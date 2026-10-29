//! YAML documents, resolved into the JSON tree `values` holds.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value as JsonValue};
use serde_saphyr::budget::{Budget, EnforcingPolicy, check_yaml_budget};
use serde_saphyr::granit_parser::{
    Event, Options as ParserOptions, Parser, ScalarStyle, ScanError, Span, Tag,
};

use crate::error::Error;

/// Deepest YAML nesting accepted. It also bounds the recursion below,
/// aliases included.
const YAML_MAX_DEPTH: usize = 128;

/// Events aliases may replay in total. One alias replays a whole anchored
/// node, so 2,000 aliases of a 2,000-item list would build four million
/// values, and a billion laughs (nine anchors, ten aliases each) asks for a
/// billion. Real documents replay a few hundred, gem metadata's shared
/// `Gem::Requirement`s included.
const YAML_MAX_REPLAYED_EVENTS: usize = 100_000;

/// Scalar bytes aliases may replay in total. The event budget alone let one
/// anchored megabyte scalar, aliased a hundred thousand times from four bytes
/// each, build a hundred gigabytes of strings.
const YAML_MAX_REPLAYED_BYTES: usize = 16 << 20;

/// A YAML node, with its plain scalars resolved (see [`parse_yaml`]).
#[derive(Clone)]
enum Yaml {
    Null,
    Bool(bool),
    /// Always within `i64` or `u64`.
    Int(i128),
    Float(f64),
    String(String),
    Sequence(Vec<Yaml>),
    Mapping(Vec<(Yaml, Yaml)>),
    /// A node under a local tag (`!ruby/object:Gem::Specification`). The tag
    /// tells duplicate mapping keys apart and is dropped from values.
    Tagged(String, Box<Yaml>),
}

/// Parse one YAML document into the JSON tree `values` holds. Gem metadata
/// is read the same way.
///
/// Plain scalars resolve by the YAML 1.2 core schema, with one change that
/// is part of the values contract: a decimal with a leading zero stays a
/// string, so a file mode `0755` reads as written rather than as 755. A plain
/// scalar is null (`~`, `null`, `Null`, `NULL`, empty), a boolean (`true`,
/// `True`, `TRUE` and the `false` spellings), an integer (decimal, `0x`,
/// `0o`, `0b`, signed), a float, or else a string, so `1_000`, `yes` and `on`
/// stay strings. An integer wider than 64 bits is kept as its digits. Quoted
/// and block scalars are strings. `!!bool`, `!!int`, `!!float` and `!!null`
/// convert their scalar or fail; other `!!` tags leave it a string. A local
/// tag (`!ruby/object:…`) is dropped and its plain scalar resolves as
/// untagged. `.inf` and `.nan` become null, as JSON has no such numbers, and
/// `<<` is an ordinary key. A mapping key that is not a string is spelled by
/// [`key_spelling`]; a duplicate key, or a second document, is an error.
///
/// The input is untrusted. serde-saphyr's budget check bounds depth and the
/// counts of events, nodes, anchors and aliases before anything is built,
/// and errors name a line and column without quoting the input.
pub(in crate::formats) fn parse_yaml(bytes: &[u8]) -> Result<JsonValue, YamlError> {
    let text = std::str::from_utf8(bytes).map_err(YamlError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let report = check_yaml_budget(text, yaml_budget(text.len()), EnforcingPolicy::AllContent)
        .map_err(YamlError::Scan)?;
    if let Some(breach) = report.breached {
        return Err(format!("YAML budget exceeded: {breach:?}").into());
    }
    let events = first_document(text)?;
    if events.is_empty() {
        return Ok(JsonValue::Null);
    }
    let mut composer = Composer {
        events: &events,
        anchors: HashMap::new(),
        replaying: 0,
        replayed: 0,
        replayed_bytes: 0,
    };
    let root = composer.node(&mut 0, 0)?;
    Ok(yaml_to_json(root))
}

/// serde-saphyr's default budget, with the depth cap above. The per-event
/// counts grow with the input, which already bounds them (every event, node,
/// anchor and alias spends input bytes), so a large lockfile still parses;
/// alias expansion is bounded by [`Composer`]. Comments are counted too, as
/// the check's parser reports them.
fn yaml_budget(input_len: usize) -> Budget {
    let mut budget = Budget::default();
    budget.max_depth = YAML_MAX_DEPTH;
    budget.max_events = budget.max_events.max(input_len.saturating_mul(2));
    budget.max_nodes = budget.max_nodes.max(input_len);
    budget.max_aliases = budget.max_aliases.max(input_len);
    budget.max_anchors = budget.max_anchors.max(input_len);
    budget.max_merge_keys = budget.max_merge_keys.max(input_len);
    budget.max_total_scalar_bytes = budget.max_total_scalar_bytes.max(input_len);
    budget.max_total_comment_bytes = budget.max_total_comment_bytes.max(input_len);
    budget.max_buffered_comment_events = budget.max_buffered_comment_events.max(input_len);
    // The replay budget bounds what aliases cost exactly; this heuristic would
    // also reject ordinary reuse of a few anchors.
    budget.enforce_alias_anchor_ratio = false;
    budget
}

/// Why [`parse_yaml`] rejected a document.
#[derive(Debug)]
pub(in crate::formats) enum YamlError {
    /// The input is not UTF-8.
    NotUtf8(std::str::Utf8Error),
    /// The scanner, or the budget check running it, rejected the input.
    Scan(ScanError),
    /// A filefacts limit or resolution rule rejected the document; the text
    /// says which and where.
    Rejected(String),
}

impl From<String> for YamlError {
    fn from(message: String) -> Self {
        Self::Rejected(message)
    }
}

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8(e) => write!(f, "input is not UTF-8: {e}"),
            Self::Scan(e) => e.fmt(f),
            Self::Rejected(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for YamlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotUtf8(e) => Some(e),
            Self::Scan(e) => Some(e),
            Self::Rejected(_) => None,
        }
    }
}

impl From<YamlError> for Error {
    /// The scanner's error, when there is one, is kept as the source so a
    /// caller can inspect it rather than parse the message.
    fn from(e: YamlError) -> Self {
        match e {
            YamlError::NotUtf8(source) => Error::malformed_caused_by("yaml", source),
            YamlError::Scan(source) => Error::malformed_caused_by("yaml", source),
            YamlError::Rejected(_) => Error::malformed("yaml", e.to_string()),
        }
    }
}

/// The node events of the stream's only document. A second document is an
/// error: the single-tree `Values` view has no place for it.
fn first_document(text: &str) -> Result<Vec<(Event<'_>, Span)>, YamlError> {
    let mut options = ParserOptions::default();
    options.emit_comments = false;
    let mut events = Vec::new();
    let mut documents = 0;
    for item in Parser::new_from_str_with_options(text, options) {
        let (event, span) = item.map_err(YamlError::Scan)?;
        match event {
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(format!(
                        "more than one YAML document at line {}",
                        span.start.line()
                    )
                    .into());
                }
            }
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            event => events.push((event, span)),
        }
    }
    Ok(events)
}

/// Builds [`Yaml`] from a document's events, replaying an anchored node's
/// events wherever an alias names it.
struct Composer<'a, 'i> {
    events: &'a [(Event<'i>, Span)],
    /// Anchor id → index of the anchored node's first event.
    anchors: HashMap<usize, usize>,
    /// Aliases being replayed right now; events read meanwhile are replays.
    replaying: usize,
    replayed: usize,
    /// Scalar bytes read while replaying.
    replayed_bytes: usize,
}

impl<'a, 'i> Composer<'a, 'i> {
    /// Consume the event at `pos`, charging it to the replay budget when an
    /// alias is being replayed. Returns its index and the event.
    fn take(&mut self, pos: &mut usize) -> Result<(usize, &'a (Event<'i>, Span)), String> {
        let at = *pos;
        let Some(entry) = self.events.get(at) else {
            return Err("unexpected end of YAML document".to_string());
        };
        *pos += 1;
        if self.replaying > 0 {
            self.replayed += 1;
            if self.replayed > YAML_MAX_REPLAYED_EVENTS {
                return Err(format!(
                    "YAML aliases expand past {YAML_MAX_REPLAYED_EVENTS} events{}",
                    location(&entry.1)
                ));
            }
            if let Event::Scalar(value, ..) = &entry.0 {
                self.replayed_bytes = self.replayed_bytes.saturating_add(value.len());
                if self.replayed_bytes > YAML_MAX_REPLAYED_BYTES {
                    return Err(format!(
                        "YAML aliases expand past {YAML_MAX_REPLAYED_BYTES} scalar bytes{}",
                        location(&entry.1)
                    ));
                }
            }
        }
        Ok((at, entry))
    }

    fn is_end(&self, pos: usize) -> bool {
        matches!(
            self.events.get(pos),
            Some((Event::SequenceEnd | Event::MappingEnd, _))
        )
    }

    /// Record an anchor where the document defines it. Replays pass the same
    /// definitions again and must not move an anchor a later one redefined.
    fn anchor(&mut self, id: usize, at: usize) {
        if id != 0 && self.replaying == 0 {
            self.anchors.insert(id, at);
        }
    }

    fn node(&mut self, pos: &mut usize, depth: usize) -> Result<Yaml, String> {
        let (at, (event, span)) = self.take(pos)?;
        let events = self.events;
        let (node, tag) = match event {
            Event::Alias(id) => {
                let Some(&start) = self.anchors.get(id) else {
                    return Err(format!("unknown YAML anchor{}", location(span)));
                };
                self.replaying += 1;
                let node = self.node(&mut start.clone(), depth);
                self.replaying -= 1;
                return node;
            }
            Event::Scalar(value, style, anchor, tag) => {
                self.anchor(*anchor, at);
                let local = local_tag(tag.as_deref());
                let core = if local.is_some() {
                    None
                } else {
                    tag.as_deref()
                };
                let scalar = resolve_scalar(value, *style, core, local.is_some())
                    .map_err(|e| format!("{e}{}", location(span)))?;
                (scalar, local)
            }
            Event::SequenceStart(_, anchor, tag) => {
                self.anchor(*anchor, at);
                let depth = deeper(depth, span)?;
                let mut items = Vec::new();
                while !self.is_end(*pos) {
                    items.push(self.node(pos, depth)?);
                }
                self.take(pos)?;
                (Yaml::Sequence(items), local_tag(tag.as_deref()))
            }
            Event::MappingStart(_, anchor, tag) => {
                self.anchor(*anchor, at);
                let depth = deeper(depth, span)?;
                let mut entries = Vec::new();
                let mut seen = HashSet::new();
                while !self.is_end(*pos) {
                    let key_span = events.get(*pos).map(|(_, span)| span);
                    let key = self.node(pos, depth)?;
                    if !seen.insert(key_identity(&key)) {
                        return Err(format!(
                            "duplicate YAML mapping key {}{}",
                            key_spelling(&key),
                            key_span.map(location).unwrap_or_default()
                        ));
                    }
                    let value = self.node(pos, depth)?;
                    entries.push((key, value));
                }
                self.take(pos)?;
                (Yaml::Mapping(entries), local_tag(tag.as_deref()))
            }
            _ => return Err(format!("unexpected YAML event{}", location(span))),
        };
        Ok(match tag {
            Some(tag) => Yaml::Tagged(tag, Box::new(node)),
            None => node,
        })
    }
}

/// The depth of a collection opened at `depth`, past the cap an error.
fn deeper(depth: usize, span: &Span) -> Result<usize, String> {
    if depth >= YAML_MAX_DEPTH {
        return Err(format!("YAML recursion limit exceeded{}", location(span)));
    }
    Ok(depth + 1)
}

fn location(span: &Span) -> String {
    format!(
        " at line {} column {}",
        span.start.line(),
        span.start.col() + 1
    )
}

/// The tag's resolved URI: `tag:yaml.org,2002:int` for `!!int`, `!foo` for a
/// local tag, `!` for the non-specific one.
fn full_tag(tag: &Tag) -> String {
    format!("{}{}", tag.handle(), tag.suffix())
}

/// A local tag, without its `!`.
fn local_tag(tag: Option<&Tag>) -> Option<String> {
    let full = full_tag(tag?);
    let rest = full.strip_prefix('!')?;
    Some(if rest.is_empty() {
        full
    } else {
        rest.to_string()
    })
}

/// Resolve one scalar. `tagged` marks a scalar under a local tag, which
/// resolves as untagged.
fn resolve_scalar(
    value: &str,
    style: ScalarStyle,
    tag: Option<&Tag>,
    tagged: bool,
) -> Result<Yaml, String> {
    if let (Some(tag), false) = (tag, tagged) {
        let invalid = |expected: &str| format!("invalid value {value:?}, expected {expected}");
        return match full_tag(tag).as_str() {
            "tag:yaml.org,2002:bool" => parse_bool(value)
                .map(Yaml::Bool)
                .ok_or_else(|| invalid("a boolean")),
            "tag:yaml.org,2002:int" => resolve_int(value).ok_or_else(|| invalid("an integer")),
            "tag:yaml.org,2002:float" => parse_f64(value)
                .map(Yaml::Float)
                .ok_or_else(|| invalid("a float")),
            "tag:yaml.org,2002:null" => parse_null(value)
                .map(|()| Yaml::Null)
                .ok_or_else(|| invalid("null")),
            _ => Ok(Yaml::String(value.to_string())),
        };
    }
    if style == ScalarStyle::Plain {
        return Ok(resolve_plain(value));
    }
    Ok(Yaml::String(value.to_string()))
}

/// Resolve an untagged plain scalar.
fn resolve_plain(value: &str) -> Yaml {
    if value.is_empty() || parse_null(value).is_some() {
        return Yaml::Null;
    }
    if let Some(b) = parse_bool(value) {
        return Yaml::Bool(b);
    }
    if let Some(int) = resolve_int(value) {
        return int;
    }
    if !digits_but_not_number(value) {
        if let Some(float) = parse_f64(value) {
            return Yaml::Float(float);
        }
    }
    Yaml::String(value.to_string())
}

/// An integer scalar. One wider than 64 bits stays its text, which JSON
/// could not hold as a number.
fn resolve_int(value: &str) -> Option<Yaml> {
    if let Some(int) = parse_unsigned_int(value, u64::from_str_radix) {
        return Some(Yaml::Int(i128::from(int)));
    }
    if let Some(int) = parse_negative_int(value, i64::from_str_radix) {
        return Some(Yaml::Int(i128::from(int)));
    }
    let wide = parse_unsigned_int(value, u128::from_str_radix).is_some()
        || parse_negative_int(value, i128::from_str_radix).is_some()
        || is_decimal_integer(value);
    wide.then(|| Yaml::String(value.to_string()))
}

/// A decimal integer of any width, as YAML 1.2's core schema reads one.
fn is_decimal_integer(value: &str) -> bool {
    let digits = value.strip_prefix(['-', '+']).unwrap_or(value);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !digits_but_not_number(value)
}

fn parse_null(value: &str) -> Option<()> {
    matches!(value, "null" | "Null" | "NULL" | "~").then_some(())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

/// A non-negative integer in any of the core schema's bases.
fn parse_unsigned_int<T>(
    value: &str,
    from_str_radix: fn(&str, u32) -> Result<T, std::num::ParseIntError>,
) -> Option<T> {
    let unpositive = value.strip_prefix('+').unwrap_or(value);
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpositive.strip_prefix(prefix) {
            if rest.starts_with(['+', '-']) {
                return None;
            }
            if let Ok(int) = from_str_radix(rest, radix) {
                return Some(int);
            }
        }
    }
    if unpositive.starts_with(['+', '-']) || digits_but_not_number(value) {
        return None;
    }
    from_str_radix(unpositive, 10).ok()
}

/// A negative integer in any of the core schema's bases.
fn parse_negative_int<T>(
    value: &str,
    from_str_radix: fn(&str, u32) -> Result<T, std::num::ParseIntError>,
) -> Option<T> {
    for (prefix, radix) in [("-0x", 16), ("-0o", 8), ("-0b", 2)] {
        if let Some(rest) = value.strip_prefix(prefix) {
            if let Ok(int) = from_str_radix(&format!("-{rest}"), radix) {
                return Some(int);
            }
        }
    }
    if digits_but_not_number(value) {
        return None;
    }
    from_str_radix(value, 10).ok()
}

/// A float, `.inf` and `.nan` spellings included.
fn parse_f64(value: &str) -> Option<f64> {
    let unpositive = match value.strip_prefix('+') {
        Some(rest) if rest.starts_with(['+', '-']) => return None,
        Some(rest) => rest,
        None => value,
    };
    if let ".inf" | ".Inf" | ".INF" = unpositive {
        return Some(f64::INFINITY);
    }
    if let "-.inf" | "-.Inf" | "-.INF" = value {
        return Some(f64::NEG_INFINITY);
    }
    if let ".nan" | ".NaN" | ".NAN" = value {
        return Some(f64::NAN);
    }
    unpositive.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// Leading zeros followed by digits, which stay a string.
fn digits_but_not_number(value: &str) -> bool {
    let value = value.strip_prefix(['-', '+']).unwrap_or(value);
    value
        .strip_prefix('0')
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn yaml_to_json(value: Yaml) -> JsonValue {
    match value {
        Yaml::Null => JsonValue::Null,
        Yaml::Bool(b) => JsonValue::Bool(b),
        Yaml::Int(i) => match u64::try_from(i) {
            Ok(u) => u.into(),
            Err(_) => i64::try_from(i).map_or(JsonValue::Null, JsonValue::from),
        },
        Yaml::Float(f) => {
            serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
        }
        Yaml::String(s) => JsonValue::String(s),
        Yaml::Sequence(seq) => JsonValue::Array(seq.into_iter().map(yaml_to_json).collect()),
        Yaml::Mapping(map) => {
            let mut obj = Map::new();
            for (k, v) in map {
                obj.insert(key_spelling(&k), yaml_to_json(v));
            }
            JsonValue::Object(obj)
        }
        Yaml::Tagged(_, value) => yaml_to_json(*value),
    }
}

/// A mapping key as a JSON object key. A string is itself; a null, boolean
/// or number is its JSON text (`null`, `true`, `31`, `1.5`), with YAML's
/// `.inf`, `-.inf` and `.nan` for the floats JSON cannot write; a collection
/// is its compact JSON. A key's tag is dropped, as a value's is.
fn key_spelling(key: &Yaml) -> String {
    match key {
        Yaml::String(s) => s.clone(),
        Yaml::Float(f) if f.is_nan() => ".nan".to_string(),
        Yaml::Float(f) if f.is_infinite() => if *f > 0.0 { ".inf" } else { "-.inf" }.to_string(),
        Yaml::Tagged(_, inner) => key_spelling(inner),
        other => yaml_to_json(other.clone()).to_string(),
    }
}

/// What makes two keys duplicates: equal values, with every NaN equal and
/// `-0.0` equal to `0.0`.
fn key_identity(key: &Yaml) -> String {
    match key {
        Yaml::Null => "~".to_string(),
        Yaml::Bool(b) => format!("b{b}"),
        Yaml::Int(i) => format!("i{i}"),
        Yaml::Float(f) if f.is_nan() => "fnan".to_string(),
        Yaml::Float(f) => format!("f{}", (f + 0.0).to_bits()),
        Yaml::String(s) => format!("s{s}"),
        Yaml::Sequence(items) => {
            let parts: Vec<String> = items.iter().map(key_identity).collect();
            format!("[{}]", parts.join("\0"))
        }
        Yaml::Mapping(entries) => {
            let parts: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("{}\0{}", key_identity(k), key_identity(v)))
                .collect();
            format!("{{{}}}", parts.join("\0"))
        }
        Yaml::Tagged(tag, value) => format!("!{tag}\0{}", key_identity(value)),
    }
}
