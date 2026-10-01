//! Extractors for structured-document formats.
//!
//! For these formats the file's content *is* the metadata. We parse and
//! hand the resulting tree straight to [`Values`] with no synthetic
//! key-namespace prefix — `fileid` already tells consumers which
//! structured format they're looking at.

use crate::metric;
use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value as JsonValue};
use serde_saphyr::budget::{Budget, EnforcingPolicy, check_yaml_budget};
use serde_saphyr::granit_parser::{
    Event, Options as ParserOptions, Parser, ScalarStyle, Span, Tag,
};

use crate::error::Error;
use crate::output::Metrics;
use crate::output::Values;

/// Generic JSON payloads are common, sometimes huge, and not always worth
/// deserializing. Named JSON formats use `extract_json` directly and are not
/// subject to this limit.
pub(crate) const GENERIC_JSON_PARSE_LIMIT_BYTES: usize = 75 * 1024;

/// Parse the bytes as JSON and populate `values` with the parsed
/// content's top-level keys (when the root is an object) or wrap the
/// non-object root under `value` (when it isn't).
pub(super) fn extract_json(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let parsed: JsonValue =
        serde_json::from_slice(bytes).map_err(|e| Error::malformed("json", e.to_string()))?;
    promote_root(parsed, values);
    Ok(())
}

/// Parse a generic `.json` document if it is below the default parse cap.
/// Oversized files stay analyzable as text/raw content, but we avoid building
/// a potentially huge `serde_json::Value` tree.
pub(super) fn extract_generic_json(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    metrics.insert(
        metric!("json.parse_limit_bytes"),
        GENERIC_JSON_PARSE_LIMIT_BYTES as f64,
    );
    if bytes.len() > GENERIC_JSON_PARSE_LIMIT_BYTES {
        values.insert("json.parse.skipped", JsonValue::Bool(true));
        values.insert(
            "json.parse.reason",
            JsonValue::String("size_limit".to_string()),
        );
        values.insert(
            "json.parse.limit_bytes",
            JsonValue::Number((GENERIC_JSON_PARSE_LIMIT_BYTES as u64).into()),
        );
        values.insert(
            "json.parse.size_bytes",
            JsonValue::Number((bytes.len() as u64).into()),
        );
        return Ok(());
    }

    metrics.insert(metric!("json.parsed_bytes"), bytes.len() as f64);
    if let Ok(parsed) = serde_json::from_slice::<JsonValue>(bytes) {
        promote_root(parsed, values);
        return Ok(());
    }
    // JSON with comments. VS Code's own workspace files (`.vscode/tasks.json`,
    // `settings.json`, `launch.json`), `tsconfig.json` and most `.eslintrc`
    // variants are JSONC by specification: `//` and `/* */` comments and
    // trailing commas are legal there, and their consumers parse them fine.
    // A strict-only parse dropped the whole value tree for every such file,
    // so a folder-open task with a trailing comma had no `tasks[*].command`
    // for any value path to read -- a gap one campaign relied on to slip a
    // hidden autorun past scanners that parse strictly. Fall back to the same
    // tolerant parser gyp uses, with JSONC comment syntax, and record that
    // the fallback was needed: a document that is not strict JSON is a fact
    // worth keeping, without losing the tree.
    match parse_jsonc(bytes) {
        Some(parsed) => {
            metrics.insert(metric!("json.parse_lenient"), 1.0);
            promote_root(parsed, values);
            Ok(())
        }
        None => Err(Error::malformed(
            "json",
            "not valid JSON or JSONC".to_string(),
        )),
    }
}

/// Parse a node-gyp build manifest (`binding.gyp`, `.gyp`, `.gypi`).
///
/// gyp is Python-literal syntax, JSON only in the common case. Real manifests
/// use trailing commas, `#` comments, and single quotes; hostile ones add
/// Python string escapes (`\xNN`, `\uNNNN`, `\U00NNNNNN`) so a byte-escaped
/// keyword like `"\x6e\x6f\x6e\x65"` reads as `"none"` only after decoding.
/// Parse as strict JSON first (fast, exact, unchanged behavior for the common
/// case), then fall back to a tolerant Python-literal parse so value paths like
/// `targets[*].sources[*]` and a concealed target `type` still resolve instead
/// of vanishing into a text/raw scan. `gyp.parse_lenient=1` marks a manifest
/// that needed the fallback — a diffable signal, since a build manifest that is
/// not even valid JSON is itself worth a second look.
pub(super) fn extract_gyp(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    metrics.insert(
        metric!("json.parse_limit_bytes"),
        GENERIC_JSON_PARSE_LIMIT_BYTES as f64,
    );
    if bytes.len() > GENERIC_JSON_PARSE_LIMIT_BYTES {
        values.insert("json.parse.skipped", JsonValue::Bool(true));
        values.insert(
            "json.parse.reason",
            JsonValue::String("size_limit".to_string()),
        );
        values.insert(
            "json.parse.limit_bytes",
            JsonValue::Number((GENERIC_JSON_PARSE_LIMIT_BYTES as u64).into()),
        );
        values.insert(
            "json.parse.size_bytes",
            JsonValue::Number((bytes.len() as u64).into()),
        );
        return Ok(());
    }
    metrics.insert(metric!("json.parsed_bytes"), bytes.len() as f64);
    if let Ok(parsed) = serde_json::from_slice::<JsonValue>(bytes) {
        promote_root(parsed, values);
        return Ok(());
    }
    match parse_gyp(bytes) {
        Some(parsed) => {
            metrics.insert(metric!("gyp.parse_lenient"), 1.0);
            promote_root(parsed, values);
            Ok(())
        }
        None => Err(Error::malformed(
            "gyp",
            "not valid JSON or gyp Python-literal syntax".to_string(),
        )),
    }
}

/// Parse the bytes as one YAML document; see [`parse_yaml`]. A stream of
/// several documents is malformed here, since the single-tree `Values` view
/// has no place for the others.
pub(super) fn extract_yaml(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let json = parse_yaml(bytes).map_err(|e| Error::malformed("yaml", e))?;
    promote_root(json, values);
    Ok(())
}

/// Parse the bytes as TOML.
pub(super) fn extract_toml(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed("toml", format!("input is not utf-8: {e}")))?;
    let parsed: toml::Value = text
        .parse()
        .map_err(|e: toml::de::Error| Error::malformed("toml", e.to_string()))?;
    let json = toml_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse the bytes as an Apple Property List (XML or binary form).
pub(super) fn extract_plist(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let cursor = std::io::Cursor::new(bytes);
    let parsed: plist::Value =
        plist::Value::from_reader(cursor).map_err(|e| Error::malformed("plist", e.to_string()))?;
    let json = plist_to_json(parsed);
    promote_root(json, values);
    Ok(())
}

/// Parse PKG-INFO / METADATA format (RFC 822-style headers).
///
/// Multi-value headers (a key repeating across lines) become a JSON
/// array. Continuation lines (starting with whitespace) append to the
/// previous header's value.
pub(super) fn extract_pkginfo(bytes: &[u8], values: &mut Values) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::malformed("pkginfo", format!("input is not utf-8: {e}")))?;
    let mut root: Map<String, JsonValue> = Map::new();
    let mut last_key: Option<String> = None;

    for line in text.lines() {
        if line.is_empty() {
            // Blank line ends the header block. Body (long description)
            // is captured under `description` for parity with PEP 314.
            break;
        }
        if line.starts_with(|c: char| c.is_whitespace()) {
            // Continuation: append to the value of `last_key`.
            if let Some(k) = &last_key {
                if let Some(existing) = root.get_mut(k) {
                    append_continuation(existing, line.trim_start());
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = JsonValue::String(value.trim().to_string());
        match root.get_mut(&key) {
            None => {
                root.insert(key.clone(), value);
            }
            Some(JsonValue::Array(arr)) => arr.push(value),
            Some(existing) => {
                let prior = std::mem::replace(existing, JsonValue::Null);
                *existing = JsonValue::Array(vec![prior, value]);
            }
        }
        last_key = Some(key);
    }

    *values = Values::from_json(JsonValue::Object(root));
    Ok(())
}

/// When the parsed root is an object, splat its entries into `values`
/// directly. When it isn't (root is an array or scalar — rare for our
/// supported formats), park it under `root` so consumers can still
/// retrieve it.
fn promote_root(json: JsonValue, values: &mut Values) {
    match json {
        JsonValue::Object(map) => {
            *values = Values::from_json(JsonValue::Object(map));
        }
        other => {
            let mut wrapper = Map::new();
            wrapper.insert("root".to_string(), other);
            *values = Values::from_json(JsonValue::Object(wrapper));
        }
    }
}

fn append_continuation(existing: &mut JsonValue, line: &str) {
    if let JsonValue::String(s) = existing {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(line);
    }
}

/// Deepest YAML nesting accepted: serde_yaml's recursion limit, kept so every
/// document that parsed before still does. It also bounds the recursion
/// below, aliases included.
const YAML_MAX_DEPTH: usize = 128;

/// serde_yaml's alias rule: a document may follow at most 100 aliases per
/// event it holds.
const YAML_ALIAS_JUMPS_PER_EVENT: usize = 100;

/// Events aliases may replay in total. serde_yaml's rule above lets one alias
/// replay a whole anchored list, so 2,000 aliases of a 2,000-item list built
/// four million values; this caps that. A billion laughs (nine anchors, ten
/// aliases each) asks for a billion. Real documents replay a few hundred, gem
/// metadata's shared `Gem::Requirement`s included.
const YAML_MAX_REPLAYED_EVENTS: usize = 100_000;

/// A YAML node as serde_yaml 0.9 resolved it into its `Value`, so documents
/// read exactly as they always have: what a rule matches as `"0755"` stays a
/// string.
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
    /// is dropped from values and kept only in the spelling of a mapping key.
    Tagged(String, Box<Yaml>),
}

/// Parse one YAML document into the JSON tree `values` holds. Gem metadata
/// is read the same way.
///
/// Scalars resolve exactly as serde_yaml 0.9 resolved them: a plain scalar is
/// null (`~`, `null`, `Null`, `NULL`, empty), a boolean (`true`, `True`,
/// `TRUE` and the `false` spellings), an integer (decimal without a leading
/// zero, `0x`, `0o`, `0b`, signed), a float, or else a string, so `0755`,
/// `1_000`, `yes` and `on` stay strings. Quoted and block scalars are strings.
/// `!!bool`, `!!int`, `!!float` and `!!null` convert their scalar or fail;
/// other `!!` tags leave it a string. A local tag (`!ruby/object:…`) is
/// dropped and its plain scalar resolves as untagged. `.inf` and `.nan` become
/// null, as JSON has no such numbers, and `<<` is an ordinary key.
///
/// Two departures, where serde_yaml lost data: an integer beyond 64 bits is
/// kept as its digits (serde_yaml rejected the document, or past 128 bits
/// made it a float), and aliases may replay at most
/// [`YAML_MAX_REPLAYED_EVENTS`] events.
///
/// The input is untrusted. serde-saphyr's budget check bounds depth and the
/// counts of events, nodes, anchors and aliases before anything is built,
/// and errors name a line and column without quoting the input.
pub(super) fn parse_yaml(bytes: &[u8]) -> Result<JsonValue, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("input is not UTF-8: {e}"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let report = check_yaml_budget(text, yaml_budget(text.len()), EnforcingPolicy::AllContent)
        .map_err(|e| e.to_string())?;
    if let Some(breach) = report.breached {
        return Err(format!("YAML budget exceeded: {breach:?}"));
    }
    let events = first_document(text)?;
    if events.is_empty() {
        return Ok(JsonValue::Null);
    }
    let mut composer = Composer {
        events: &events,
        anchors: HashMap::new(),
        jumps: 0,
        replaying: 0,
        replayed: 0,
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

/// The node events of the stream's only document. A second document is an
/// error, as it was for serde_yaml.
fn first_document(text: &str) -> Result<Vec<(Event<'_>, Span)>, String> {
    let mut options = ParserOptions::default();
    options.emit_comments = false;
    let mut events = Vec::new();
    let mut documents = 0;
    for item in Parser::new_from_str_with_options(text, options) {
        let (event, span) = item.map_err(|e| e.to_string())?;
        match event {
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(format!(
                        "more than one YAML document at line {}",
                        span.start.line()
                    ));
                }
            }
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            event => events.push((event, span)),
        }
    }
    Ok(events)
}

/// Builds [`Yaml`] from a document's events, replaying an anchored node's
/// events wherever an alias names it, as serde_yaml did.
struct Composer<'a, 'i> {
    events: &'a [(Event<'i>, Span)],
    /// Anchor id → index of the anchored node's first event.
    anchors: HashMap<usize, usize>,
    jumps: usize,
    /// Aliases being replayed right now; events read meanwhile are replays.
    replaying: usize,
    replayed: usize,
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
                self.jumps += 1;
                if self.jumps > events.len().saturating_mul(YAML_ALIAS_JUMPS_PER_EVENT) {
                    return Err(format!(
                        "YAML alias repetition limit exceeded{}",
                        location(span)
                    ));
                }
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
                            yaml_key_to_string(&key),
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

/// A local tag, which serde_yaml kept as `Value::Tagged`, without its `!`.
fn local_tag(tag: Option<&Tag>) -> Option<String> {
    let full = full_tag(tag?);
    let rest = full.strip_prefix('!')?;
    Some(if rest.is_empty() {
        full
    } else {
        rest.to_string()
    })
}

/// serde_yaml's `visit_scalar`. `tagged` marks a scalar under a local tag,
/// which resolves as untagged.
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

/// serde_yaml's `visit_untagged_scalar`.
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

/// serde_yaml's `visit_int`. An integer wider than 64 bits stays its text:
/// JSON cannot hold it, and serde_yaml either rejected the whole document or,
/// past 128 bits, read it as a float.
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

/// serde_yaml's `parse_unsigned_int`.
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

/// serde_yaml's `parse_negative_int`.
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

/// serde_yaml's `parse_f64`.
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

/// Leading zeros followed by digits, which serde_yaml kept a string.
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
                // YAML allows non-string map keys; we stringify for JSON.
                obj.insert(yaml_key_to_string(&k), yaml_to_json(v));
            }
            JsonValue::Object(obj)
        }
        Yaml::Tagged(_, value) => yaml_to_json(*value),
    }
}

/// A key's JSON spelling, as serde_yaml's `Value` displayed it.
fn yaml_key_to_string(key: &Yaml) -> String {
    match key {
        Yaml::String(s) => s.clone(),
        Yaml::Bool(b) => b.to_string(),
        Yaml::Int(i) => i.to_string(),
        Yaml::Float(f) => format_float(*f),
        Yaml::Null => "null".to_string(),
        other => emit_yaml(other),
    }
}

/// serde_yaml's float spelling: `.nan`, `.inf`, `-.inf`, else the shortest
/// round-trip form, `1e20` rather than serde_json's `1e+20`.
fn format_float(f: f64) -> String {
    if f.is_nan() {
        ".nan".to_string()
    } else if f.is_infinite() {
        if f > 0.0 { ".inf" } else { "-.inf" }.to_string()
    } else {
        serde_json::Number::from_f64(f)
            .map_or_else(String::new, |n| n.to_string().replace("e+", "e"))
    }
}

/// What makes two keys duplicates for serde_yaml: equal values, with every
/// NaN equal and `-0.0` equal to `0.0`.
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

/// A collection or tagged key written as block YAML, the way serde_yaml's
/// serializer (libyaml, unlimited width) wrote it: `[a, b]` is `- a\n- b`.
fn emit_yaml(node: &Yaml) -> String {
    let mut out = String::new();
    emit_node(node, 0, &mut out);
    out.trim().to_string()
}

/// Write `node` at the cursor; continuation lines start at `indent`.
fn emit_node(node: &Yaml, indent: usize, out: &mut String) {
    match node {
        Yaml::Sequence(items) if !items.is_empty() => {
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    newline(indent, out);
                }
                out.push_str("- ");
                emit_node(item, indent + 2, out);
            }
        }
        Yaml::Mapping(entries) if !entries.is_empty() => {
            for (n, (key, value)) in entries.iter().enumerate() {
                if n > 0 {
                    newline(indent, out);
                }
                if is_simple_key(key) {
                    emit_node(key, indent, out);
                } else {
                    out.push_str("? ");
                    emit_node(key, indent + 2, out);
                    newline(indent, out);
                }
                out.push(':');
                match value {
                    // Sequences sit at their key's indentation.
                    Yaml::Sequence(items) if !items.is_empty() => {
                        newline(indent, out);
                        emit_node(value, indent, out);
                    }
                    Yaml::Mapping(entries) if !entries.is_empty() => {
                        newline(indent + 2, out);
                        emit_node(value, indent + 2, out);
                    }
                    _ => {
                        out.push(' ');
                        emit_node(value, indent + 2, out);
                    }
                }
            }
        }
        Yaml::Sequence(_) => out.push_str("[]"),
        Yaml::Mapping(_) => out.push_str("{}"),
        Yaml::Tagged(tag, value) => {
            out.push('!');
            out.push_str(tag);
            if is_collection(value) {
                newline(indent, out);
            } else {
                out.push(' ');
            }
            emit_node(value, indent, out);
        }
        Yaml::Null => out.push_str("null"),
        Yaml::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Yaml::Int(i) => out.push_str(&i.to_string()),
        Yaml::Float(f) => out.push_str(&format_float(*f)),
        Yaml::String(s) => emit_string(s, indent, out),
    }
}

fn is_collection(node: &Yaml) -> bool {
    match node {
        Yaml::Sequence(items) => !items.is_empty(),
        Yaml::Mapping(entries) => !entries.is_empty(),
        _ => false,
    }
}

/// libyaml writes a mapping key inline unless it is a collection, spans
/// lines, or runs past 128 bytes; then it uses `? key`.
fn is_simple_key(key: &Yaml) -> bool {
    match key {
        Yaml::String(s) => s.len() <= 128 && !s.chars().any(is_break),
        Yaml::Tagged(tag, value) => match &**value {
            Yaml::String(s) => tag.len() + 1 + s.len() <= 128 && !s.chars().any(is_break),
            value => !is_collection(value),
        },
        key => !is_collection(key),
    }
}

fn newline(indent: usize, out: &mut String) {
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', indent));
}

/// A string scalar in the style libyaml picked. serde_yaml asked for a
/// literal block when the text has a newline, and for single quotes when it
/// would read back as something else (`'1'`, `'yes'` does not); libyaml then
/// fell back to quotes, and to double quotes with escapes, as the text needs.
fn emit_string(s: &str, indent: usize, out: &mut String) {
    let chars: Vec<char> = s.chars().collect();
    let special = chars.iter().any(|&c| !is_printable(c));
    let mut space_break = false;
    let mut break_space = false;
    for &[a, b] in chars.array_windows() {
        space_break |= a == ' ' && is_break(b);
        break_space |= is_break(a) && b == ' ';
    }
    let single_allowed = !special && !space_break && !break_space;
    if s.contains('\n') {
        if !special && !space_break && !s.ends_with(' ') {
            emit_literal(s, indent, out);
        } else {
            emit_double_quoted(s, out);
        }
        return;
    }
    let resolves_otherwise =
        !matches!(resolve_plain(s), Yaml::String(_)) || digits_but_not_number(s);
    if !resolves_otherwise && single_allowed && plain_allowed(&chars) {
        out.push_str(s);
    } else if single_allowed {
        out.push('\'');
        for &c in &chars {
            match c {
                '\'' => out.push_str("''"),
                c if is_break(c) => {
                    out.push(c);
                    out.extend(std::iter::repeat_n(' ', indent));
                }
                c => out.push(c),
            }
        }
        out.push('\'');
    } else {
        emit_double_quoted(s, out);
    }
}

fn emit_literal(s: &str, indent: usize, out: &mut String) {
    out.push('|');
    let body = s.trim_end_matches('\n');
    out.push_str(match s.len() - body.len() {
        0 => "-",
        1 => "",
        _ => "+",
    });
    for line in body.split('\n') {
        out.push('\n');
        if !line.is_empty() {
            out.extend(std::iter::repeat_n(' ', indent.max(2)));
            out.push_str(line);
        }
    }
    for _ in 1..s.len() - body.len() {
        out.push('\n');
    }
}

/// libyaml's test for a plain scalar in block context, given the text needs
/// no quoting for its characters.
fn plain_allowed(chars: &[char]) -> bool {
    let (Some(&first), Some(&last)) = (chars.first(), chars.last()) else {
        return false;
    };
    let starts_document =
        chars.starts_with(&['-', '-', '-']) || chars.starts_with(&['.', '.', '.']);
    if first == ' ' || last == ' ' || starts_document || chars.iter().any(|&c| is_break(c)) {
        return false;
    }
    !chars.iter().enumerate().any(|(n, &c)| {
        let followed_by_space = chars.get(n + 1).is_none_or(|&next| next == ' ');
        match n.checked_sub(1).and_then(|prev| chars.get(prev)) {
            None => {
                "#,[]{}&*!|>'\"%@`".contains(c)
                    || (matches!(c, '?' | ':' | '-') && followed_by_space)
            }
            Some(&prev) => (c == ':' && followed_by_space) || (c == '#' && prev == ' '),
        }
    })
}

/// libyaml's printable set: no control character but newline, no NEL, no
/// surrogate or byte-order mark.
fn is_printable(c: char) -> bool {
    matches!(
        c,
        '\n' | '\u{20}'..='\u{7e}' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..
    ) && c != '\u{feff}'
}

/// libyaml's (YAML 1.1) line breaks, which its emitter would not write plain.
fn is_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn emit_double_quoted(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\0' => out.push_str("\\0"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\e"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{85}' => out.push_str("\\N"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            c if is_printable(c) => out.push(c),
            c if u32::from(c) <= 0xff => out.push_str(&format!("\\x{:02X}", u32::from(c))),
            c if u32::from(c) <= 0xffff => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push_str(&format!("\\U{:08X}", u32::from(c))),
        }
    }
    out.push('"');
}

fn toml_to_json(value: toml::Value) -> JsonValue {
    use toml::Value as T;
    match value {
        T::String(s) => JsonValue::String(s),
        T::Integer(i) => JsonValue::Number(i.into()),
        T::Float(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        T::Boolean(b) => JsonValue::Bool(b),
        T::Datetime(dt) => JsonValue::String(dt.to_string()),
        T::Array(arr) => JsonValue::Array(arr.into_iter().map(toml_to_json).collect()),
        T::Table(tab) => {
            let mut obj = Map::new();
            for (k, v) in tab {
                obj.insert(k, toml_to_json(v));
            }
            JsonValue::Object(obj)
        }
    }
}

fn plist_to_json(value: plist::Value) -> JsonValue {
    use plist::Value as P;
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(d.to_xml_format()),
        P::Data(bytes) => JsonValue::String(base64_encode(&bytes)),
        // A keyed-archive object reference, which only the binary form can
        // encode. Spelled the way `plutil -convert xml1` spells it so a rule
        // written against either form of the same archive matches both.
        P::Uid(uid) => {
            let mut obj = Map::new();
            obj.insert("CF$UID".to_string(), JsonValue::Number(uid.get().into()));
            JsonValue::Object(obj)
        }
        P::Array(arr) => JsonValue::Array(arr.into_iter().map(plist_to_json).collect()),
        P::Dictionary(dict) => {
            let mut obj = Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v));
            }
            JsonValue::Object(obj)
        }
        // `plist::Value` is `#[non_exhaustive]`. Round-trip unknown
        // variants as null rather than panic.
        _ => JsonValue::Null,
    }
}

/// Minimal base64 encoder for plist `Data` blobs. We don't depend on the
/// `base64` crate for one tiny encoding path.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .zip([16, 8, 0])
            .fold(0u32, |n, (&b, shift)| n | (u32::from(b) << shift));
        // A chunk of k bytes fills k + 1 sextets; the rest are padding.
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(match ALPHABET.get(((n >> shift) & 0x3F) as usize) {
                Some(&c) if k <= chunk.len() => char::from(c),
                _ => '=',
            });
        }
    }
    out
}

/// Recursion cap for the gyp parser: deeper than any real build manifest, low
/// enough that a hostile nest cannot overflow the stack or the `Value` drop.
const MAX_GYP_DEPTH: usize = 64;

/// Tolerant parse of the Python-literal subset gyp uses, into a JSON value.
///
/// Returns `None` on anything it cannot parse, so the caller falls back exactly
/// as before — never a partial or guessed tree.
fn parse_gyp(content: &[u8]) -> Option<JsonValue> {
    parse_lenient(content, CommentStyle::Python)
}

/// Tolerant parse of JSON with comments (JSONC): `//` and `/* */` comments
/// and trailing commas, on top of strict JSON. Same parser as gyp with the
/// comment syntax swapped; single-quoted strings and hex numbers are accepted
/// as well, which only ever widens what a file can say and never changes the
/// tree of a document strict JSON already accepted (strict runs first).
///
/// Returns `None` on anything it cannot parse, so the caller reports the
/// malformed document exactly as before -- never a partial or guessed tree.
fn parse_jsonc(content: &[u8]) -> Option<JsonValue> {
    parse_lenient(content, CommentStyle::Jsonc)
}

fn parse_lenient(content: &[u8], comments: CommentStyle) -> Option<JsonValue> {
    let mut parser = GypParser {
        bytes: content,
        pos: 0,
        comments,
    };
    parser.skip_trivia();
    let value = parser.parse_value(0)?;
    parser.skip_trivia();
    // A gyp manifest is a single top-level dict/list; trailing tokens mean we
    // misparsed, so refuse rather than expose a truncated tree.
    parser.at_end().then_some(value)
}

/// Minimal recursive-descent parser for the Python-literal subset gyp uses:
/// dicts, lists, single/double-quoted strings, numbers, `true`/`false`/`null`,
/// trailing commas, `#` comments, and Python string escapes.
struct GypParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    comments: CommentStyle,
}

/// Which comment syntax the tolerant parser skips as whitespace.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommentStyle {
    /// gyp (Python literal): `#` to end of line.
    Python,
    /// JSON with comments: `//` to end of line and `/* ... */` blocks.
    Jsonc,
}

impl<'a> GypParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// The unconsumed input.
    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.pos..).unwrap_or_default()
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Skip ASCII whitespace and comments in the configured style.
    fn skip_trivia(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else if c == b'#' && self.comments == CommentStyle::Python {
                self.skip_line();
            } else if c == b'/' && self.comments == CommentStyle::Jsonc {
                match self.bytes.get(self.pos + 1) {
                    Some(b'/') => self.skip_line(),
                    Some(b'*') => {
                        self.pos += 2;
                        // An unterminated block comment swallows the rest of
                        // the document; the parse then fails at end of input
                        // exactly as strict JSON would.
                        while self.pos < self.bytes.len() {
                            if self.rest().starts_with(b"*/") {
                                self.pos += 2;
                                break;
                            }
                            self.pos += 1;
                        }
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
    }

    /// Consume through the next newline (line comment body).
    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            self.pos += 1;
            if c == b'\n' {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Option<JsonValue> {
        if depth >= MAX_GYP_DEPTH {
            return None;
        }
        self.skip_trivia();
        match self.peek()? {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'\'' | b'"' => self.parse_string().map(JsonValue::String),
            b't' | b'f' | b'n' => self.parse_ident_literal(),
            b'0'..=b'9' | b'-' | b'+' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: usize) -> Option<JsonValue> {
        self.pos += 1; // consume '{'
        let mut map = Map::new();
        loop {
            self.skip_trivia();
            match self.peek()? {
                b'}' => {
                    self.pos += 1;
                    return Some(JsonValue::Object(map));
                }
                b'\'' | b'"' => {
                    let key = self.parse_string()?;
                    self.skip_trivia();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.pos += 1; // consume ':'
                    let value = self.parse_value(depth + 1)?;
                    map.insert(key, value);
                    self.skip_trivia();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(JsonValue::Object(map));
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Option<JsonValue> {
        self.pos += 1; // consume '['
        let mut arr = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek()? {
                b']' => {
                    self.pos += 1;
                    return Some(JsonValue::Array(arr));
                }
                _ => {
                    arr.push(self.parse_value(depth + 1)?);
                    self.skip_trivia();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(JsonValue::Array(arr));
                        }
                        _ => return None,
                    }
                }
            }
        }
    }

    /// Parse a single- or double-quoted string, decoding Python/JSON escapes.
    fn parse_string(&mut self) -> Option<String> {
        let quote = self.peek()?;
        self.pos += 1; // consume opening quote
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                q if q == quote => return Some(out),
                b'\\' => {
                    let esc = self.peek()?;
                    self.pos += 1;
                    match esc {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'0' => out.push('\0'),
                        b'x' => out.push(self.parse_hex_escape(2)?),
                        b'u' => out.push(self.parse_hex_escape(4)?),
                        b'U' => out.push(self.parse_hex_escape(8)?),
                        // `\\`, `\"`, `\'`, `\/`, and any other escape: the
                        // escaped byte stands for itself (Python leaves unknown
                        // escapes literal; the leading backslash is dropped).
                        other => out.push(other as char),
                    }
                }
                // Multi-byte UTF-8: re-attach the continuation bytes of the
                // lead byte we just consumed so non-ASCII content survives.
                lead if lead >= 0x80 => {
                    let start = self.pos - 1;
                    let end = (start + utf8_width(lead)).min(self.bytes.len());
                    out.push_str(std::str::from_utf8(self.bytes.get(start..end)?).ok()?);
                    self.pos = end;
                }
                _ => out.push(c as char),
            }
        }
    }

    /// Read `digits` hex digits into a `char`. Invalid or out-of-range code
    /// points (lone surrogates, > U+10FFFF) fail the parse.
    fn parse_hex_escape(&mut self, digits: usize) -> Option<char> {
        let mut code: u32 = 0;
        for _ in 0..digits {
            let nibble = (self.peek()? as char).to_digit(16)?;
            code = code.checked_mul(16)?.checked_add(nibble)?;
            self.pos += 1;
        }
        char::from_u32(code)
    }

    fn parse_ident_literal(&mut self) -> Option<JsonValue> {
        for (word, value) in [
            ("true", JsonValue::Bool(true)),
            ("false", JsonValue::Bool(false)),
            ("null", JsonValue::Null),
        ] {
            if self.rest().starts_with(word.as_bytes()) {
                self.pos += word.len();
                return Some(value);
            }
        }
        None
    }

    fn parse_number(&mut self) -> Option<JsonValue> {
        let start = self.pos;
        if matches!(self.peek(), Some(b'-' | b'+')) {
            self.pos += 1;
        }
        // Hex integers (`0x1F`) are valid Python/gyp literals.
        if self.rest().starts_with(b"0x") || self.rest().starts_with(b"0X") {
            self.pos += 2;
            let hex_start = self.pos;
            while matches!(self.peek(), Some(c) if (c as char).is_ascii_hexdigit()) {
                self.pos += 1;
            }
            let hex = std::str::from_utf8(self.bytes.get(hex_start..self.pos)?).ok()?;
            let n = i64::from_str_radix(hex, 16).ok()?;
            let signed = if self.bytes.get(start) == Some(&b'-') {
                -n
            } else {
                n
            };
            return Some(JsonValue::Number(signed.into()));
        }
        while matches!(self.peek(), Some(c) if (c as char).is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(self.bytes.get(start..self.pos)?).ok()?;
        serde_json::from_str::<JsonValue>(text)
            .ok()
            .filter(JsonValue::is_number)
    }
}

/// Byte length of a UTF-8 sequence from its lead byte.
fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_object_is_promoted() {
        let mut v = Values::new();
        extract_json(br#"{"name":"x","version":"1.0"}"#, &mut v).unwrap();
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
        assert_eq!(v.get("version").and_then(|x| x.as_str()), Some("1.0"));
    }

    #[test]
    fn json_array_root_lands_under_root_key() {
        let mut v = Values::new();
        extract_json(b"[1,2,3]", &mut v).unwrap();
        assert!(v.get("root").and_then(|x| x.as_array()).is_some());
    }

    #[test]
    fn json_malformed_returns_error() {
        let mut v = Values::new();
        let err = extract_json(b"{ not json", &mut v).unwrap_err();
        assert!(matches!(err, Error::Malformed { format: "json", .. }));
    }

    #[test]
    fn toml_basic() {
        let mut v = Values::new();
        extract_toml(b"[package]\nname = \"x\"\n", &mut v).unwrap();
        assert_eq!(v.get("package.name").and_then(|x| x.as_str()), Some("x"));
    }

    #[test]
    fn yaml_basic() {
        let mut v = Values::new();
        extract_yaml(b"name: x\non:\n  push:\n    branches: [main]\n", &mut v).unwrap();
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
    }

    fn yaml(text: &str) -> JsonValue {
        parse_yaml(text.as_bytes()).unwrap()
    }

    /// Plain scalars resolve as serde_yaml 0.9 resolved them, so values rules
    /// match as strings (`0755`, `1_000`, `yes`) stay strings.
    #[test]
    fn yaml_plain_scalars_resolve_as_serde_yaml_did() {
        let v = yaml(
            "on: push\nwords: [yes, no, on, off, y, n]\nbools: [true, True, FALSE]\n\
             odd: [tRuE, nUlL, 0755, 007, 1_000, 1e999, +.nan]\n\
             nulls: [~, null, Null, NULL]\nempty:\nnonfinite: [.inf, -.inf, .nan, .NaN]\n\
             nums: [42, -7, 0x1F, -0x1F, 0o17, 0b101, +12, 3.5, 1e3, .5]\n\
             wide: [18446744073709551616, -9223372036854775809]\n\
             quoted: ['true', \"1\"]\nblock: |\n  0755\n",
        );
        assert_eq!(v["on"], "push");
        assert_eq!(
            v["words"],
            serde_json::json!(["yes", "no", "on", "off", "y", "n"])
        );
        assert_eq!(v["bools"], serde_json::json!([true, true, false]));
        assert_eq!(
            v["odd"],
            serde_json::json!(["tRuE", "nUlL", "0755", "007", "1_000", "1e999", "+.nan"])
        );
        assert_eq!(v["nulls"], serde_json::json!([null, null, null, null]));
        assert_eq!(v["empty"], JsonValue::Null);
        assert_eq!(v["nonfinite"], serde_json::json!([null, null, null, null]));
        assert_eq!(
            v["nums"],
            serde_json::json!([42, -7, 31, -31, 15, 5, 12, 3.5, 1000.0, 0.5])
        );
        // Wider than 64 bits: kept as digits, never a float.
        assert_eq!(
            v["wide"],
            serde_json::json!(["18446744073709551616", "-9223372036854775809"])
        );
        assert_eq!(v["quoted"], serde_json::json!(["true", "1"]));
        assert_eq!(v["block"], "0755\n");
    }

    /// `!!bool`/`!!int`/`!!float`/`!!null` convert or fail, other `!!` tags
    /// leave a string, and a local tag is dropped with its plain scalar
    /// resolved as untagged.
    #[test]
    fn yaml_tags_resolve_as_serde_yaml_did() {
        let v = yaml(
            "int: !!int \"42\"\nfloat: !!float 1\nstr: !!str 0x1F\nts: !!timestamp 2001-12-14\n\
             bin: !!binary aGVsbG8=\nlocal: !custom 12\nlocal_zero: !custom 0755\n\
             local_quoted: !custom \"12\"\nglobal: !<tag:example.com,2000:x> 7\n\
             spec: !ruby/object:Gem::Specification\n  name: x\nset: !!set {a, b}\n",
        );
        assert_eq!(v["int"], 42);
        assert_eq!(v["float"], 1.0);
        assert_eq!(v["str"], "0x1F");
        assert_eq!(v["ts"], "2001-12-14");
        assert_eq!(v["bin"], "aGVsbG8=");
        assert_eq!(v["local"], 12);
        assert_eq!(v["local_zero"], "0755");
        assert_eq!(v["local_quoted"], "12");
        assert_eq!(v["global"], "7");
        assert_eq!(v["spec"], serde_json::json!({"name": "x"}));
        assert_eq!(v["set"], serde_json::json!({"a": null, "b": null}));
        for bad in ["a: !!int abc\n", "a: !!bool yes\n", "a: !!null \"\"\n"] {
            assert!(parse_yaml(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    /// A key that is not a string keeps the spelling serde_yaml gave it.
    #[test]
    fn yaml_non_string_keys_are_spelled_by_value() {
        let v = yaml(
            "1: int\n0x1F: hex\ntrue: bool\n~: nil\n1.5: float\n1e20: exp\n.inf: inf\n\
             0755: zero\n? [a, b]\n: seq\n? {x: 1}\n: map\n? [yes, '1', [2, 3]]\n: nested\n\
             !t tagged: tag\n",
        );
        for (key, value) in [
            ("1", "int"),
            ("31", "hex"),
            ("true", "bool"),
            ("null", "nil"),
            ("1.5", "float"),
            ("1e20", "exp"),
            (".inf", "inf"),
            ("0755", "zero"),
            ("- a\n- b", "seq"),
            ("x: 1", "map"),
            ("- yes\n- '1'\n- - 2\n  - 3", "nested"),
            ("!t tagged", "tag"),
        ] {
            assert_eq!(v[key], value, "{key:?} in {v}");
        }
    }

    /// Aliases expand, and `<<` stays an ordinary key.
    #[test]
    fn yaml_anchors_aliases_and_merge_keys() {
        let v = yaml(
            "base: &b {k: 1}\ncopy: *b\nmerged:\n  <<: *b\n  j: 2\nzero: &z 0755\nagain: *z\n",
        );
        assert_eq!(v["copy"], serde_json::json!({"k": 1}));
        assert_eq!(v["merged"], serde_json::json!({"<<": {"k": 1}, "j": 2}));
        assert_eq!(v["again"], "0755");
    }

    /// A billion laughs stops at serde_yaml's alias rule, and reusing one big
    /// anchor stops at the replay budget, both quickly and without building
    /// the expansion. Three levels (1,110 replayed events) are ordinary reuse.
    #[test]
    fn yaml_alias_bombs_are_rejected_quickly() {
        let mut laughs = String::from("a0: &a0 lol\n");
        for level in 1..=9 {
            let refs = vec![format!("*a{}", level - 1); 10].join(", ");
            laughs.push_str(&format!("a{level}: &a{level} [{refs}]\n"));
        }
        let items: Vec<String> = (0..2_000).map(|i| i.to_string()).collect();
        let reuse = format!(
            "big: &big [{}]\nuses: [{}]\n",
            items.join(", "),
            vec!["*big"; 2_000].join(", ")
        );
        let start = std::time::Instant::now();
        let err = parse_yaml(laughs.as_bytes()).unwrap_err();
        assert!(err.contains("alias repetition limit"), "{err}");
        let err = parse_yaml(reuse.as_bytes()).unwrap_err();
        assert!(err.contains("aliases expand past"), "{err}");
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        let small: String = laughs.lines().take(4).map(|l| format!("{l}\n")).collect();
        assert!(parse_yaml(small.as_bytes()).is_ok());
    }

    /// Nesting is capped at serde_yaml's 128 levels, in flow and block style,
    /// through aliases too, and an absurdly deep document fails fast.
    #[test]
    fn yaml_nesting_depth_is_bounded() {
        let flow = |n: usize| format!("a: {}{}\n", "[".repeat(n), "]".repeat(n));
        let block = |n: usize| {
            let mut doc: String = (0..n)
                .map(|i| format!("{}k{i}:\n", "  ".repeat(i)))
                .collect();
            doc.push_str(&format!("{}leaf\n", "  ".repeat(n)));
            doc
        };
        // The document's own mapping is the first level.
        assert!(parse_yaml(flow(127).as_bytes()).is_ok());
        assert!(parse_yaml(flow(128).as_bytes()).is_err());
        assert!(parse_yaml(block(128).as_bytes()).is_ok());
        assert!(parse_yaml(block(129).as_bytes()).is_err());
        // 64 levels under an anchor, replayed 64 levels deep: 129 in all.
        let deep = format!(
            "a: &x {}{}\nb: {}*x{}\n",
            "[".repeat(64),
            "]".repeat(64),
            "[".repeat(64),
            "]".repeat(64)
        );
        assert!(parse_yaml(deep.as_bytes()).is_err());
        assert!(parse_yaml(b"a: &a [1, *a]\n").is_err());
        let start = std::time::Instant::now();
        assert!(parse_yaml(flow(100_000).as_bytes()).is_err());
        assert!(parse_yaml(block(5_000).as_bytes()).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
    }

    /// The per-event budgets grow with the input, so a lockfile larger than
    /// serde-saphyr's default node budget still parses.
    #[test]
    fn yaml_large_document_parses() {
        let doc: String = (0..300_000).map(|i| format!("- {i}\n")).collect();
        let v = parse_yaml(doc.as_bytes()).unwrap();
        assert_eq!(v.as_array().map(Vec::len), Some(300_000));
    }

    #[test]
    fn yaml_streams_duplicates_and_bad_bytes_are_malformed() {
        for bad in [
            &b"a: 1\n---\nb: 2\n"[..],
            b"a: 1\na: 2\n",
            b"true: 1\nTrue: 2\n",
            b"a: \xff\n",
            b"a: [1, 2\n",
        ] {
            let mut v = Values::new();
            let err = extract_yaml(bad, &mut v).unwrap_err();
            assert!(matches!(err, Error::Malformed { format: "yaml", .. }));
        }
        assert_eq!(yaml(""), JsonValue::Null);
        assert_eq!(yaml("\u{feff}a: 1\n")["a"], 1);
    }

    /// The same dictionary written as a binary plist and as an XML plist
    /// lands in `values` identically: the binary reader is chosen from the
    /// `bplist00` magic, not from anything the caller passes.
    #[test]
    fn binary_plist_matches_xml_plist() {
        let mut dict = plist::Dictionary::new();
        dict.insert("CFBundleIdentifier".into(), "com.example.dropper".into());
        dict.insert("LSUIElement".into(), true.into());
        dict.insert("Count".into(), 42.into());
        dict.insert("Ratio".into(), 0.5.into());
        dict.insert("Blob".into(), plist::Value::Data(b"Man".to_vec()));
        dict.insert(
            "Args".into(),
            plist::Value::Array(vec!["-c".into(), "curl http://x".into()]),
        );
        let root = plist::Value::Dictionary(dict);

        let mut binary = Vec::new();
        root.to_writer_binary(&mut binary).unwrap();
        assert!(binary.starts_with(b"bplist00"));
        let mut xml = Vec::new();
        root.to_writer_xml(&mut xml).unwrap();

        let mut from_binary = Values::new();
        extract_plist(&binary, &mut from_binary).unwrap();
        let mut from_xml = Values::new();
        extract_plist(&xml, &mut from_xml).unwrap();
        assert_eq!(from_binary.as_json(), from_xml.as_json());

        assert_eq!(
            from_binary.get("CFBundleIdentifier").unwrap(),
            "com.example.dropper"
        );
        assert_eq!(from_binary.get("LSUIElement").unwrap(), true);
        assert_eq!(from_binary.get("Count").unwrap(), 42);
        assert_eq!(from_binary.get("Ratio").unwrap(), 0.5);
        assert_eq!(from_binary.get("Blob").unwrap(), "TWFu");
        assert_eq!(from_binary.get("Args[1]").unwrap(), "curl http://x");
    }

    /// NSKeyedArchiver output is the common binary-only plist. Its `$class`
    /// object references decode to `CF$UID` dictionaries instead of nulls.
    #[test]
    fn binary_plist_keyed_archive_uids_are_preserved() {
        let mut class = plist::Dictionary::new();
        class.insert("$classname".into(), "NSMutableDictionary".into());
        let mut object = plist::Dictionary::new();
        object.insert("$class".into(), plist::Value::Uid(plist::Uid::new(2)));
        let mut root = plist::Dictionary::new();
        root.insert("$archiver".into(), "NSKeyedArchiver".into());
        root.insert(
            "$objects".into(),
            plist::Value::Array(vec![
                "$null".into(),
                plist::Value::Dictionary(object),
                plist::Value::Dictionary(class),
            ]),
        );
        let mut binary = Vec::new();
        plist::Value::Dictionary(root)
            .to_writer_binary(&mut binary)
            .unwrap();

        let mut values = Values::new();
        extract_plist(&binary, &mut values).unwrap();
        assert_eq!(values.get("$archiver").unwrap(), "NSKeyedArchiver");
        assert_eq!(values.get("$objects[1].$class.CF$UID").unwrap(), 2);
        assert_eq!(
            values.get("$objects[2].$classname").unwrap(),
            "NSMutableDictionary"
        );
    }

    #[test]
    fn binary_plist_truncated_is_an_error() {
        let mut dict = plist::Dictionary::new();
        dict.insert("k".into(), "v".into());
        let mut binary = Vec::new();
        plist::Value::Dictionary(dict)
            .to_writer_binary(&mut binary)
            .unwrap();
        let mut values = Values::new();
        assert!(extract_plist(&binary[..binary.len() / 2], &mut values).is_err());
        assert!(extract_plist(b"bplist00", &mut values).is_err());
    }

    #[test]
    fn pkginfo_simple() {
        let mut v = Values::new();
        let input = b"Metadata-Version: 2.1\nName: foo\nVersion: 1.2.3\n";
        extract_pkginfo(input, &mut v).unwrap();
        assert_eq!(
            v.get("metadata-version").and_then(|x| x.as_str()),
            Some("2.1")
        );
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("foo"));
    }

    #[test]
    fn pkginfo_keys_are_lowercase() {
        let mut v = Values::new();
        let input = b"Summary: Dependency confusion PoC\nAuthor-email: a@example.com\n";
        extract_pkginfo(input, &mut v).unwrap();
        assert_eq!(
            v.get("summary").and_then(|x| x.as_str()),
            Some("Dependency confusion PoC")
        );
        assert_eq!(
            v.get("author-email").and_then(|x| x.as_str()),
            Some("a@example.com")
        );
    }

    #[test]
    fn pkginfo_multi_value_becomes_array() {
        let mut v = Values::new();
        let input = b"Classifier: A\nClassifier: B\nClassifier: C\n";
        extract_pkginfo(input, &mut v).unwrap();
        let arr = v.get("classifier").and_then(|x| x.as_array()).unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn base64_encodes_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn generic_json_strict_path_leaves_no_lenient_marker() {
        let json = br#"{"version":"2.0.0","tasks":[{"command":"node ./x.js"}]}"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_generic_json(json, &mut v, &mut m).unwrap();
        assert_eq!(
            v.get("tasks[0].command").and_then(|x| x.as_str()),
            Some("node ./x.js")
        );
        assert!(m.get("json.parse_lenient").is_none());
    }

    #[test]
    fn generic_json_trailing_comma_still_yields_the_task_tree() {
        // The PolinRider tasks.json shape: a trailing comma after the last
        // task object. VS Code runs it; strict JSON rejects it, and before
        // the fallback no `tasks[*].command` value existed to match.
        let json = br#"{
          "version": "2.0.0",
          "tasks": [
            {
              "label": "eslint-check",
              "type": "shell",
              "command": "node ./public/fonts/fa-solid-300.llf",
              "hide": true,
              "runOptions": { "runOn": "folderOpen" }
            },
          ]
        }"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_generic_json(json, &mut v, &mut m).unwrap();
        assert_eq!(
            v.get("tasks[0].command").and_then(|x| x.as_str()),
            Some("node ./public/fonts/fa-solid-300.llf")
        );
        assert_eq!(
            v.get("tasks[0].runOptions.runOn").and_then(|x| x.as_str()),
            Some("folderOpen")
        );
        assert_eq!(m.get("json.parse_lenient"), Some(1.0));
    }

    #[test]
    fn generic_json_line_and_block_comments_are_trivia() {
        // A settings.json as VS Code users actually write it. A `//` inside a
        // string value must survive as content, not open a comment.
        let json = br#"{
          // Automatically saves files after a delay
          "files.autoSave": "off",
          /* hide the terminal */ "terminal.integrated.hideOnStartup": "always",
          "url": "https://example.com/a", // trailing comment
        }"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_generic_json(json, &mut v, &mut m).unwrap();
        // Dotted setting names are literal keys, so read the tree directly
        // rather than through the path-splitting `get`.
        let root = v.as_json();
        assert_eq!(root["files.autoSave"].as_str(), Some("off"));
        assert_eq!(
            root["terminal.integrated.hideOnStartup"].as_str(),
            Some("always")
        );
        assert_eq!(root["url"].as_str(), Some("https://example.com/a"));
        assert_eq!(m.get("json.parse_lenient"), Some(1.0));
    }

    #[test]
    fn generic_json_garbage_and_unterminated_comment_fail_cleanly() {
        let mut v = Values::new();
        let mut m = Metrics::new();
        assert!(extract_generic_json(b"{ this is not json }", &mut v, &mut m).is_err());
        assert!(extract_generic_json(b"{ /* open forever \"a\": 1 }", &mut v, &mut m).is_err());
        // gyp's `#` comments are not JSONC comments.
        assert!(extract_generic_json(b"{ # nope\n \"a\": 1 }", &mut v, &mut m).is_err());
        assert!(v.get("a").is_none());
    }

    #[test]
    fn gyp_plain_json_uses_the_strict_path() {
        // A conventional binding.gyp is valid JSON; it must parse without the
        // lenient fallback and land its value paths.
        let gyp = br#"{"targets":[{"target_name":"addon","sources":["addon.c"]}]}"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_gyp(gyp, &mut v, &mut m).unwrap();
        assert_eq!(
            v.get("targets[0].target_name").and_then(|x| x.as_str()),
            Some("addon")
        );
        assert!(m.get("gyp.parse_lenient").is_none());
    }

    #[test]
    fn gyp_lenient_decodes_byte_escaped_target_and_sources() {
        // The openapi-react-query-codegen wave's binding.gyp shape: trailing
        // commas, a `<(var)` target name, and a `\x`-escaped `type` that reads
        // as "none" only after decoding. Strict JSON rejects all of it.
        let gyp = br#"{
            "variables": { "var": "Frot", },
            "targets": [ {
                "target_name": "<(var)",
                "type":"\x6e\x6f\x6e\x65",
                "sources": ["dog.c"],
            } ],
        }"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_gyp(gyp, &mut v, &mut m).unwrap();
        assert_eq!(
            v.get("variables.var").and_then(|x| x.as_str()),
            Some("Frot")
        );
        assert_eq!(
            v.get("targets[0].target_name").and_then(|x| x.as_str()),
            Some("<(var)")
        );
        // The concealment is undone: type is the plaintext keyword.
        assert_eq!(
            v.get("targets[0].type").and_then(|x| x.as_str()),
            Some("none")
        );
        assert_eq!(
            v.get("targets[0].sources[0]").and_then(|x| x.as_str()),
            Some("dog.c")
        );
        assert_eq!(m.get("gyp.parse_lenient"), Some(1.0));
    }

    #[test]
    fn gyp_unicode_escape_recovers_the_command_string() {
        // \U00.. escapes reassemble a command hidden from a plaintext scan.
        let gyp =
            br#"{"targets":[{"conditions":[["\U0000006e\U0000006f\U00000064\U00000065", {}]]}]}"#;
        let mut v = Values::new();
        let mut m = Metrics::new();
        extract_gyp(gyp, &mut v, &mut m).unwrap();
        // conditions is an array of `[expr, {}]` pairs — nested arrays, which
        // the dotted `get` path can't index in one segment, so assert on the
        // JSON tree directly.
        assert_eq!(
            v.as_json()
                .pointer("/targets/0/conditions/0/0")
                .and_then(|x| x.as_str()),
            Some("node")
        );
    }

    #[test]
    fn gyp_garbage_fails_cleanly() {
        // Neither JSON nor gyp: no tree, so the caller falls through to a scan.
        let mut v = Values::new();
        let mut m = Metrics::new();
        assert!(extract_gyp(b"\x00\x01 not a manifest", &mut v, &mut m).is_err());
    }
}
