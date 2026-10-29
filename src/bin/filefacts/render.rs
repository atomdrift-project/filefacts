//! The terminal renderer: the bundle's detail in a colored, aligned layout —
//! heading pills, grouped metrics, columnar section and symbol tables.
//!
//! Every string printed passes through [`Style::fg`], [`Style::bold`] or
//! [`Style::pill`], which escape control characters: names, strings and paths
//! come from the analysed file, and a raw ESC in one would let the file drive
//! the user's terminal.

use std::borrow::Cow;
use std::path::Path;

use filefacts::{
    Arg, Errors, FileType, ParsedFile, Section, SectionFlag, Sections, Symbol, SymbolKind, Text,
    View,
};
use serde::Serialize;
use serde_json::Value;

/// How terminal output looks, decided once per run.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Style {
    /// Emit truecolor escapes.
    pub(crate) color: bool,
    /// Width of the rule under each file header, in columns.
    pub(crate) width: usize,
}

impl Style {
    /// Width when `COLUMNS` does not give one.
    const DEFAULT_WIDTH: usize = 100;

    /// The width `COLUMNS` asks for, clamped to a readable range, or
    /// [`Self::DEFAULT_WIDTH`] when it is unset or not a number.
    pub(crate) fn width_from(columns: Option<&str>) -> usize {
        columns
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_WIDTH)
            .clamp(60, 200)
    }

    fn fg(self, c: Rgb, text: &str) -> String {
        let text = escape_controls(text);
        if !self.color {
            return text.into_owned();
        }
        let Rgb(r, g, b) = c;
        format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
    }

    fn bold(self, c: Rgb, text: &str) -> String {
        let text = escape_controls(text);
        if !self.color {
            return text.into_owned();
        }
        let Rgb(r, g, b) = c;
        format!("\x1b[1;38;2;{r};{g};{b}m{text}\x1b[0m")
    }

    fn dim(self, text: &str) -> String {
        self.fg(FG_DIM, text)
    }

    fn pill(self, label: &str, bg: Rgb) -> String {
        let label = escape_controls(label);
        if !self.color {
            return format!(" {label} ");
        }
        let Rgb(r, g, b) = bg;
        format!("\x1b[1;38;2;255;255;255;48;2;{r};{g};{b}m {label} \x1b[0m")
    }

    fn heading(self, view: View, count: Option<usize>) -> String {
        let color = heading_color(view);
        let bar = self.bold(color, "▌");
        let label = self.bold(color, &view.name().to_uppercase());
        let mut out = format!("{bar} {label}");
        if let Some(n) = count {
            out.push(' ');
            out.push_str(&self.dim(&format!("({n})")));
        }
        out
    }
}

#[derive(Copy, Clone)]
struct Rgb(u8, u8, u8);

// Foreground palette — neutral, readable on dark terminal backgrounds.
const FG_TITLE: Rgb = Rgb(230, 230, 230); // bold path
const FG_LABEL: Rgb = Rgb(150, 150, 150); // metric key / column label
const FG_VALUE: Rgb = Rgb(210, 210, 210); // value text
const FG_DIM: Rgb = Rgb(110, 110, 110); // very-dim chrome
const FG_HEX: Rgb = Rgb(180, 150, 220); // hex offsets / addresses
const FG_NUM: Rgb = Rgb(180, 210, 140); // plain numbers
const FG_STR: Rgb = Rgb(220, 200, 140); // string content
const FG_FLAG_EXEC: Rgb = Rgb(255, 140, 80); // executable
const FG_FLAG_WRITE: Rgb = Rgb(255, 200, 80); // writable
const FG_FLAG_READ: Rgb = Rgb(120, 180, 140); // readable
const FG_RULE: Rgb = Rgb(60, 70, 85); // rule glyphs
const FG_ERROR: Rgb = Rgb(215, 95, 95); // error red
const FG_OK: Rgb = Rgb(95, 175, 95); // benign green
const FG_NULL: Rgb = Rgb(110, 110, 110); // null/none

/// The heading bar color of a view.
fn heading_color(view: View) -> Rgb {
    match view {
        View::Fileid => Rgb(180, 140, 100),
        View::Values => Rgb(140, 175, 215),
        View::Metrics => Rgb(140, 200, 175),
        View::Sections => Rgb(190, 160, 220),
        View::Kind(SymbolKind::Import) => Rgb(200, 145, 175),
        View::Kind(SymbolKind::Export) => Rgb(170, 200, 145),
        View::Kind(SymbolKind::Function) => Rgb(220, 170, 130),
        View::Errors => Rgb(215, 95, 95),
        _ => Rgb(160, 160, 160),
    }
}

// ─── top-level renderer ─────────────────────────────────────────────

/// `parsed` for the terminal: a header for `path`, then `view`, or every
/// bundled view when `view` is `None`.
pub(crate) fn format_terminal(
    st: Style,
    path: &Path,
    parsed: &ParsedFile<'_>,
    view: Option<View>,
) -> serde_json::Result<String> {
    let mut out = render_file_header(st, path, parsed);
    out.push('\n');
    match view {
        None => {
            for view in View::ALL.into_iter().filter(|v| v.bundled()) {
                render_section(st, &mut out, view, &render_view(st, parsed, view)?);
            }
        }
        Some(view) => {
            let rendered = render_view(st, parsed, view)?;
            out.push_str(&st.heading(view, rendered.count));
            out.push('\n');
            if rendered.body.is_empty() {
                out.push_str(&st.dim("  (empty)"));
                out.push('\n');
            } else {
                out.push_str(&rendered.body);
            }
        }
    }
    Ok(out.trim_end().to_string())
}

/// One view rendered for the terminal.
struct Rendered {
    /// Item count shown in the heading.
    count: Option<usize>,
    /// Whether the bundle shows the view as `(empty)` instead of `body`.
    empty: bool,
    body: String,
}

fn render_view(st: Style, parsed: &ParsedFile<'_>, view: View) -> serde_json::Result<Rendered> {
    let rendered = match view {
        View::Metrics => {
            let metrics = parsed.metrics();
            Rendered {
                count: (metrics.len() > 6).then_some(metrics.len()),
                empty: metrics.is_empty(),
                body: render_metrics(st, metrics),
            }
        }
        View::ArchiveMembers => {
            let members = parsed.archive_members();
            Rendered {
                count: Some(members.len()),
                empty: members.is_empty(),
                body: render_archive_members(st, members),
            }
        }
        View::Sections => {
            let sections = parsed.sections();
            Rendered {
                count: Some(sections.len()),
                empty: sections.is_empty(),
                body: render_sections(st, sections),
            }
        }
        View::Errors => {
            let errors = parsed.errors();
            Rendered {
                count: Some(errors.len()),
                empty: errors.is_empty(),
                body: render_errors(st, errors),
            }
        }
        View::Symbols | View::Kind(_) => {
            let symbols: Vec<&Symbol> = match view {
                View::Kind(kind) => parsed.symbols().iter_kind(kind).collect(),
                _ => parsed.symbols().iter().collect(),
            };
            let body = match view {
                View::Kind(SymbolKind::Import) => render_imports(st, &symbols),
                View::Kind(SymbolKind::Export) => render_exports(st, &symbols),
                View::Kind(SymbolKind::Function) => render_functions(st, &symbols),
                _ => render_symbols(st, &symbols),
            };
            Rendered {
                count: Some(symbols.len()),
                empty: symbols.is_empty(),
                body,
            }
        }
        View::Text => render_text(st, parsed.text()),
        // Serialised only as far as the preview reaches: these hold a row
        // per string in the file, and making every row a `Value` costs
        // several times the rows' own memory to show the first few dozen.
        View::Literals | View::Comments => {
            let rows = match view {
                View::Literals => parsed.literals().as_slice(),
                _ => parsed.comments().as_slice(),
            };
            let (total, shown) = preview(rows.iter(), ARRAY_PREVIEW_LIMIT)?;
            let mut body = render_values_tree(st, &Value::Array(shown));
            if total > ARRAY_PREVIEW_LIMIT {
                let more = format!("... {} more", total - ARRAY_PREVIEW_LIMIT);
                body.push_str(&format!("  {}\n", st.dim(&more)));
            }
            Rendered {
                count: Some(total),
                empty: total == 0,
                body,
            }
        }
        // Rendered as the generic tree of what the JSON holds: these views
        // are trees whose keys come from the file or the format, and the
        // renderer looks none of them up by name.
        View::Fileid | View::Identity | View::Values | View::Flow | View::References => {
            let value = serde_json::to_value(parsed.view(view))?;
            let body = match view {
                View::Fileid => render_fileid(st, &value),
                _ => render_values_tree(st, &value),
            };
            Rendered {
                count: top_level_count(&value),
                empty: is_empty_value(&value),
                body,
            }
        }
        // `View` is non-exhaustive: a view added later still renders, as
        // the generic tree of its JSON.
        _ => {
            let value = serde_json::to_value(parsed.view(view))?;
            Rendered {
                count: top_level_count(&value),
                empty: is_empty_value(&value),
                body: render_values_tree(st, &value),
            }
        }
    };
    Ok(rendered)
}

fn render_section(st: Style, out: &mut String, view: View, rendered: &Rendered) {
    out.push_str(&st.heading(view, rendered.count));
    out.push('\n');
    if rendered.empty {
        out.push_str(&st.dim("  (empty)"));
        out.push_str("\n\n");
        return;
    }
    let body = &rendered.body;
    out.push_str(body);
    if !body.ends_with("\n\n") {
        if body.ends_with('\n') {
            out.push('\n');
        } else {
            out.push_str("\n\n");
        }
    }
}

fn top_level_count(value: &Value) -> Option<usize> {
    match value {
        Value::Array(a) => Some(a.len()),
        // A count makes sense for top-level lists of items, not for a small
        // bag of fields such as fileid.
        Value::Object(o) if o.len() > 6 => Some(o.len()),
        _ => None,
    }
}

fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        // An object whose every leaf is empty reads as empty for header
        // purposes.
        Value::Object(o) => o.is_empty() || o.values().all(is_empty_value),
        _ => false,
    }
}

// ─── file header ────────────────────────────────────────────────────

/// Metrics the header reads; a test pins both to the catalog.
const FILE_SIZE: &str = "file.size";
const FILE_ENTROPY: &str = "file.entropy";

fn render_file_header(st: Style, path: &Path, parsed: &ParsedFile<'_>) -> String {
    let file_type = parsed.fileid().file_type();
    let mut out = st.bold(FG_TITLE, &path.display().to_string());
    out.push_str("  ");
    out.push_str(&st.pill(
        &format!("{file_type:?}").to_uppercase(),
        file_type_color(file_type),
    ));

    // Subtitle: size · entropy · mismatch
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "float-to-int `as` saturates (NaN is 0); file.size is a non-negative count"
    )]
    let size = parsed.metrics().get(FILE_SIZE).unwrap_or(0.0) as u64;
    let mut subtitle = vec![st.fg(FG_LABEL, &humanize_bytes(size))];
    if let Some(e) = parsed.metrics().get(FILE_ENTROPY) {
        subtitle.push(st.fg(FG_LABEL, &format!("entropy {e:.2}")));
    }
    if parsed.fileid().extension_mismatch() {
        subtitle.push(st.fg(FG_ERROR, "extension mismatch"));
    }
    out.push_str(&format!("\n  {}\n", subtitle.join(&st.dim(" · "))));
    out.push_str(&st.fg(FG_RULE, &"─".repeat(st.width)));
    out.push('\n');
    out
}

fn file_type_color(ft: FileType) -> Rgb {
    match ft {
        FileType::Pe => Rgb(115, 60, 95),
        FileType::Elf => Rgb(60, 90, 115),
        FileType::MachO => Rgb(85, 65, 110),
        FileType::Pdf => Rgb(120, 60, 60),
        FileType::Zip
        | FileType::Crx
        | FileType::Odf
        | FileType::Jar
        | FileType::Tar
        | FileType::TarGz
        | FileType::TarBz2
        | FileType::TarXz
        | FileType::TarZst => Rgb(105, 80, 50),
        FileType::JavaClass => Rgb(90, 70, 50),
        _ => Rgb(70, 75, 90),
    }
}

// ─── fileid view ────────────────────────────────────────────────────

/// The fileid bag, one aligned `key  value` row per field, sorted by key.
fn render_fileid(st: Style, value: &Value) -> String {
    let Value::Object(map) = value else {
        return render_values_tree(st, value);
    };
    let mut fields: Vec<(&String, &Value)> = map.iter().collect();
    fields.sort_by_key(|(k, _)| *k);
    let key_w = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in fields {
        let formatted = match v {
            Value::Bool(true) => st.fg(FG_FLAG_WRITE, "true"),
            Value::Bool(false) => st.dim("false"),
            Value::String(s) => st.fg(FG_VALUE, s),
            other => st.fg(FG_VALUE, &other.to_string()),
        };
        let label = st.fg(FG_LABEL, &format!("{k:<key_w$}"));
        out.push_str(&format!("  {label}  {formatted}\n"));
    }
    out
}

// ─── values view (generic nested tree) ──────────────────────────────

fn render_values_tree(st: Style, value: &Value) -> String {
    let mut out = String::new();
    render_tree_node(st, &mut out, value, 2);
    out
}

const ARRAY_PREVIEW_LIMIT: usize = 50;

fn render_tree_node(st: Style, out: &mut String, value: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            // Two passes — scalars first (aligned), then nested children.
            let (nested, scalars): (Vec<_>, Vec<_>) = map
                .iter()
                .partition(|(_, v)| matches!(v, Value::Object(_) | Value::Array(_)));
            let key_w = scalars.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (k, v) in scalars {
                let label = st.fg(FG_LABEL, &format!("{k:<key_w$}"));
                out.push_str(&format!("{pad}{label}  {}\n", format_scalar(st, v)));
            }
            for (k, v) in nested {
                // Compact short scalar-only arrays inline.
                if let Value::Array(items) = v
                    && items.len() <= 8
                    && items.iter().all(is_short_scalar)
                {
                    let inline = items
                        .iter()
                        .map(|item| format_scalar(st, item))
                        .collect::<Vec<_>>()
                        .join(&st.dim(", "));
                    out.push_str(&format!(
                        "{pad}{label}  {open}{inline}{close}\n",
                        label = st.fg(FG_LABEL, k),
                        open = st.dim("["),
                        close = st.dim("]"),
                    ));
                    continue;
                }
                out.push_str(&format!("{pad}{}\n", st.bold(FG_VALUE, k)));
                render_tree_node(st, out, v, indent + 2);
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str(&format!("{pad}{}\n", st.dim("[]")));
                return;
            }
            for (i, v) in items.iter().take(ARRAY_PREVIEW_LIMIT).enumerate() {
                let idx = st.dim(&format!("[{i}]"));
                match v {
                    Value::Object(_) | Value::Array(_) => {
                        out.push_str(&format!("{pad}{idx}\n"));
                        render_tree_node(st, out, v, indent + 2);
                    }
                    _ => out.push_str(&format!("{pad}{idx} {}\n", format_scalar(st, v))),
                }
            }
            if items.len() > ARRAY_PREVIEW_LIMIT {
                let more = format!("... {} more", items.len() - ARRAY_PREVIEW_LIMIT);
                out.push_str(&format!("{pad}{}\n", st.dim(&more)));
            }
        }
        _ => out.push_str(&format!("{pad}{}\n", format_scalar(st, value))),
    }
}

fn is_short_scalar(v: &Value) -> bool {
    match v {
        Value::String(s) => s.len() <= 24,
        Value::Number(_) | Value::Bool(_) | Value::Null => true,
        _ => false,
    }
}

fn format_scalar(st: Style, value: &Value) -> String {
    match value {
        Value::Null => st.fg(FG_NULL, "null"),
        Value::Bool(true) => st.fg(FG_FLAG_WRITE, "true"),
        Value::Bool(false) => st.dim("false"),
        Value::String(s) => st.fg(FG_VALUE, s),
        Value::Number(n) => st.fg(FG_NUM, &n.to_string()),
        other => st.fg(FG_VALUE, &other.to_string()),
    }
}

// ─── metrics view ───────────────────────────────────────────────────

fn render_metrics(st: Style, metrics: &filefacts::Metrics) -> String {
    // Group by leading prefix (`binary.foo` → group `binary`). Per-section
    // entropies (`sections[N].entropy`) collapse into a single `sections`
    // bucket to keep the metric pane readable. `iter` yields keys sorted, so
    // each group's rows are too.
    let mut groups: std::collections::BTreeMap<&str, Vec<(&str, f64)>> =
        std::collections::BTreeMap::new();
    for (k, v) in metrics.iter() {
        groups.entry(metric_group(k)).or_default().push((k, v));
    }
    let mut out = String::new();
    for (group, entries) in groups {
        out.push_str(&format!("  {}\n", st.bold(FG_VALUE, group)));
        // Drop the group prefix on each row.
        let strip_prefix = format!("{group}.");
        let rows: Vec<(&str, String)> = entries
            .iter()
            .map(|&(k, v)| {
                let label = k.strip_prefix(&strip_prefix).unwrap_or(k);
                (label, format_metric_value(st, k, v))
            })
            .collect();
        let key_w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (label, value) in rows {
            let label = st.fg(FG_LABEL, &format!("{label:<key_w$}"));
            out.push_str(&format!("    {label}  {value}\n"));
        }
    }
    out
}

/// The group a metric key is listed under: its first dotted segment, with
/// any `[N]` index dropped. A key without a dot is its own group.
fn metric_group(key: &str) -> &str {
    match key.split_once('.') {
        Some((head, _)) => head.split_once('[').map_or(head, |(stem, _)| stem),
        None => key,
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons,
    reason = "float-to-int `as` saturates (NaN is 0) and this only formats a metric for \
              display; the suffixes matched are metric-key segments, not file extensions"
)]
fn format_metric_value(st: Style, key: &str, raw: f64) -> String {
    // Heuristics by key suffix: sizes get byte-humanised, counts stay
    // integer, ratios and entropies get fixed precision.
    let text = if key.ends_with("_size") || key.ends_with("size_bytes") {
        humanize_bytes(raw as u64)
    } else if key.ends_with(".count") || key.ends_with("_count") {
        (raw as u64).to_string()
    } else if key.ends_with("_ratio")
        || key.ends_with("_pct")
        || key.ends_with("entropy")
        || key.ends_with("entropy_variance")
    {
        format!("{raw:.3}")
    } else if raw.fract() == 0.0 && raw.abs() < 1e15 {
        (raw as i64).to_string()
    } else {
        format!("{raw:.3}")
    };
    st.fg(FG_NUM, &text)
}

// ─── text view ──────────────────────────────────────────────────────

const STRING_PREVIEW_LIMIT: usize = 40;

/// The first `limit` of `rows` as JSON values, and how many rows there are.
fn preview<'r, T: Serialize + 'r>(
    rows: impl Iterator<Item = &'r T>,
    limit: usize,
) -> serde_json::Result<(usize, Vec<Value>)> {
    let mut shown = Vec::new();
    let mut total = 0;
    for row in rows {
        if total < limit {
            shown.push(serde_json::to_value(row)?);
        }
        total += 1;
    }
    Ok((total, shown))
}

/// The text view: per encoding, its run count and the first runs.
fn render_text(st: Style, text: &Text) -> Rendered {
    let categories = [
        ("ascii", text.ascii().count()),
        ("utf16le", text.utf16le().count()),
    ];
    // Summary line: ascii N · utf16le N
    let counts: Vec<String> = categories
        .iter()
        .map(|(k, n)| format!("{} {}", st.fg(FG_LABEL, k), st.fg(FG_NUM, &n.to_string())))
        .collect();
    let mut out = format!("  {}\n", counts.join(&st.dim("  ·  ")));
    for (category, total) in categories {
        if total == 0 {
            continue;
        }
        out.push_str(&format!(
            "\n  {} {}\n",
            st.bold(FG_VALUE, category),
            st.dim(&format!("({total})")),
        ));
        let rows: Vec<_> = match category {
            "ascii" => text.ascii().take(STRING_PREVIEW_LIMIT).collect(),
            _ => text.utf16le().take(STRING_PREVIEW_LIMIT).collect(),
        };
        for row in rows {
            let kind = row
                .kind
                .map(|kind| format!("  {}", st.dim(&format!("{kind:?}"))))
                .unwrap_or_default();
            out.push_str(&format!(
                "    {} {}{kind}\n",
                st.fg(FG_HEX, &format!("0x{:08x}", row.data_offset)),
                st.fg(FG_STR, &string_excerpt(&row.value, 80)),
            ));
        }
        if total > STRING_PREVIEW_LIMIT {
            let more = format!("... {} more", total - STRING_PREVIEW_LIMIT);
            out.push_str(&format!("    {}\n", st.dim(&more)));
        }
    }
    Rendered {
        count: None,
        empty: text.is_empty(),
        body: out,
    }
}

fn string_excerpt(text: &str, max: usize) -> String {
    let escaped = escape_controls(text);
    if escaped.chars().count() <= max {
        escaped.into_owned()
    } else {
        let mut s: String = escaped.chars().take(max.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

/// `text` with terminal control and bidirectional formatting characters
/// written as escapes, so file-derived text cannot drive or visually reorder
/// terminal output. Idempotent: the output holds no unsafe characters.
pub(crate) fn escape_controls(text: &str) -> Cow<'_, str> {
    let unsafe_char = |c: char| {
        c.is_control()
            || matches!(
                c,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    };
    if !text.chars().any(unsafe_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if unsafe_char(c) => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

// ─── sections view ──────────────────────────────────────────────────

const SECTIONS_PREVIEW_LIMIT: usize = 80;

/// Per-section block layout. Each section gets a name+flags+entropy header
/// line followed by its `mem` (virtual) and `disk` (file) extents, whose hex
/// and size columns share one width across every section so they stack.
fn render_sections(st: Style, sections: &Sections) -> String {
    let rows: Vec<SectionRow<'_>> = sections.iter().map(SectionRow::new).collect();
    let lo_w = rows
        .iter()
        .flat_map(|r| [r.vaddr_lo.len(), r.file_lo.len()])
        .max()
        .unwrap_or(0);
    let hi_w = rows
        .iter()
        .flat_map(|r| [r.vaddr_hi.len(), r.file_hi.len()])
        .max()
        .unwrap_or(0);
    let size_w = rows
        .iter()
        .flat_map(|r| [r.size.len(), r.file_size.len()])
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for (i, r) in rows.iter().take(SECTIONS_PREVIEW_LIMIT).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut tail = vec![format_section_flags(st, r.section)];
        if let Some(entropy) = r.section.entropy {
            tail.push(format!(
                "{} {}",
                st.fg(FG_LABEL, "entropy"),
                st.fg(FG_NUM, &format!("{entropy:.2}")),
            ));
        }
        out.push_str(&format!(
            "  {}  {}\n",
            st.bold(FG_VALUE, &r.section.name),
            tail.join(&st.dim("  ·  ")),
        ));
        let extent = |label: &str, lo: &str, hi: &str, size: &str| {
            format!(
                "    {}   {} {} {}   {}\n",
                st.fg(FG_LABEL, label),
                st.fg(FG_HEX, &format!("{lo:>lo_w$}")),
                st.dim(".."),
                st.fg(FG_HEX, &format!("{hi:>hi_w$}")),
                st.fg(FG_NUM, &format!("{size:>size_w$}")),
            )
        };
        out.push_str(&extent("mem ", &r.vaddr_lo, &r.vaddr_hi, &r.size));
        // BSS-style entries with no on-disk bytes collapse to a dim note.
        if r.section.file_size > 0 {
            out.push_str(&extent("disk", &r.file_lo, &r.file_hi, &r.file_size));
        } else {
            out.push_str(&format!(
                "    {}   {}\n",
                st.fg(FG_LABEL, "disk"),
                st.dim("(no on-disk bytes)"),
            ));
        }
    }
    if rows.len() > SECTIONS_PREVIEW_LIMIT {
        let more = format!("... {} more", rows.len() - SECTIONS_PREVIEW_LIMIT);
        out.push_str(&format!("  {}\n", st.dim(&more)));
    }
    out
}

/// A section with its extents formatted, so column widths can be measured.
struct SectionRow<'s> {
    section: &'s Section,
    vaddr_lo: String,
    vaddr_hi: String,
    size: String,
    file_lo: String,
    file_hi: String,
    file_size: String,
}

impl<'s> SectionRow<'s> {
    fn new(section: &'s Section) -> Self {
        Self {
            section,
            vaddr_lo: format_hex(section.vaddr),
            vaddr_hi: format_hex(section.vaddr.saturating_add(section.vsize)),
            size: humanize_bytes(section.vsize),
            file_lo: format_hex(section.file_offset),
            file_hi: format_hex(section.file_offset.saturating_add(section.file_size)),
            file_size: humanize_bytes(section.file_size),
        }
    }
}

fn format_hex(n: u64) -> String {
    format!("{n:#x}")
}

/// `rwx` permissions, then any other flags dimly.
fn format_section_flags(st: Style, section: &Section) -> String {
    let perms = format!(
        "{}{}{}",
        if section.has_flag(SectionFlag::Readable) {
            st.fg(FG_FLAG_READ, "r")
        } else {
            st.dim("-")
        },
        if section.is_writable() {
            st.fg(FG_FLAG_WRITE, "w")
        } else {
            st.dim("-")
        },
        if section.is_executable() {
            st.fg(FG_FLAG_EXEC, "x")
        } else {
            st.dim("-")
        },
    );
    let extras: Vec<&str> = section
        .flags
        .iter()
        .filter(|flag| {
            !matches!(
                flag,
                SectionFlag::Readable | SectionFlag::Writable | SectionFlag::Executable
            )
        })
        .map(|flag| flag.as_str())
        .collect();
    if extras.is_empty() {
        perms
    } else {
        format!("{perms}  {}", st.dim(&extras.join(",")))
    }
}

// ─── imports view ───────────────────────────────────────────────────

const IMPORTS_PREVIEW_PER_LIB: usize = 24;

/// An import row: name, file offset, ordinal.
type ImportRow<'a> = (&'a str, Option<u64>, Option<u32>);

/// The widest `0x…` rendering among `offsets`.
fn hex_width(offsets: impl Iterator<Item = Option<u64>>) -> usize {
    offsets
        .flatten()
        .map(|n| format_hex(n).len())
        .max()
        .unwrap_or(0)
}

fn render_imports(st: Style, symbols: &[&Symbol]) -> String {
    // Group by library.
    let mut by_lib: std::collections::BTreeMap<&str, Vec<ImportRow<'_>>> =
        std::collections::BTreeMap::new();
    for symbol in symbols {
        let Symbol::Import {
            name,
            library,
            offset,
            ordinal,
            ..
        } = symbol
        else {
            continue;
        };
        let lib = library.as_deref().unwrap_or("(unknown)");
        by_lib
            .entry(lib)
            .or_default()
            .push((name, *offset, *ordinal));
    }
    let mut out = String::new();
    for (lib, entries) in by_lib {
        out.push_str(&format!(
            "  {} {}\n",
            st.bold(FG_VALUE, lib),
            st.dim(&format!("({})", entries.len())),
        ));
        let show = entries.get(..IMPORTS_PREVIEW_PER_LIB).unwrap_or(&entries);
        let off_w = hex_width(show.iter().map(|(_, offset, _)| *offset));
        for (name, offset, ordinal) in show {
            let offset = offset.map(format_hex).unwrap_or_default();
            let tail = match ordinal {
                Some(o) => format!("  {}", st.dim(&format!("#{o}"))),
                None => String::new(),
            };
            out.push_str(&format!(
                "    {}  {}{tail}\n",
                st.fg(FG_HEX, &format!("{offset:>off_w$}")),
                st.fg(FG_VALUE, name),
            ));
        }
        if entries.len() > show.len() {
            let more = format!("... {} more", entries.len() - show.len());
            out.push_str(&format!("    {}\n", st.dim(&more)));
        }
    }
    out
}

// ─── exports view ───────────────────────────────────────────────────

const EXPORTS_PREVIEW_LIMIT: usize = 80;

fn render_exports(st: Style, symbols: &[&Symbol]) -> String {
    let exports: Vec<_> = symbols
        .iter()
        .filter_map(|symbol| match symbol {
            Symbol::Export {
                name,
                offset,
                ordinal,
                forward_to,
            } => Some((name.as_str(), *offset, *ordinal, forward_to.as_deref())),
            _ => None,
        })
        .collect();
    let off_w = hex_width(exports.iter().map(|(_, offset, _, _)| *offset));
    let mut out = String::new();
    for (name, offset, ordinal, forward_to) in exports.iter().take(EXPORTS_PREVIEW_LIMIT) {
        let offset = offset.map_or_else(|| "·".into(), format_hex);
        let mut tail = Vec::<String>::new();
        if let Some(o) = ordinal {
            tail.push(st.dim(&format!("#{o}")));
        }
        if let Some(f) = forward_to {
            tail.push(format!("{} {}", st.dim("→"), st.fg(FG_VALUE, f)));
        }
        let tail = if tail.is_empty() {
            String::new()
        } else {
            format!("  {}", tail.join(&st.dim(" ")))
        };
        out.push_str(&format!(
            "  {}  {}{tail}\n",
            st.fg(FG_HEX, &format!("{offset:>off_w$}")),
            st.fg(FG_VALUE, name),
        ));
    }
    if exports.len() > EXPORTS_PREVIEW_LIMIT {
        let more = format!("... {} more", exports.len() - EXPORTS_PREVIEW_LIMIT);
        out.push_str(&format!("  {}\n", st.dim(&more)));
    }
    out
}

// ─── functions view ─────────────────────────────────────────────────

const FUNCTIONS_PREVIEW_LIMIT: usize = 60;

/// Callees listed inline under a function before the rest are counted.
const CALLEES_INLINE: usize = 8;

fn render_functions(st: Style, symbols: &[&Symbol]) -> String {
    let functions: Vec<_> = symbols
        .iter()
        .filter_map(|symbol| match symbol {
            Symbol::Function {
                name,
                offset,
                complexity,
                callees,
            } => Some((name.as_str(), *offset, *complexity, callees.as_slice())),
            _ => None,
        })
        .collect();
    let off_w = hex_width(functions.iter().map(|(_, offset, _, _)| *offset));
    let mut out = String::new();
    for (name, offset, complexity, callees) in functions.iter().take(FUNCTIONS_PREVIEW_LIMIT) {
        let offset = offset.map_or_else(|| "·".into(), format_hex);
        let tail = match complexity {
            Some(c) => format!("  {}", st.fg(FG_LABEL, &format!("cx={c}"))),
            None => String::new(),
        };
        out.push_str(&format!(
            "  {}  {}{tail}\n",
            st.fg(FG_HEX, &format!("{offset:>off_w$}")),
            st.fg(FG_VALUE, name),
        ));
        if !callees.is_empty() {
            let inline = callees
                .iter()
                .take(CALLEES_INLINE)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if callees.len() > CALLEES_INLINE {
                format!(", … +{}", callees.len() - CALLEES_INLINE)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "    {} {}{}\n",
                st.dim("→"),
                st.dim(&inline),
                st.dim(&suffix),
            ));
        }
    }
    if functions.len() > FUNCTIONS_PREVIEW_LIMIT {
        let more = format!("... {} more", functions.len() - FUNCTIONS_PREVIEW_LIMIT);
        out.push_str(&format!("  {}\n", st.dim(&more)));
    }
    out
}

// ─── symbols view ───────────────────────────────────────────────────

const SYMBOL_PREVIEW_LIMIT: usize = 30;

/// Terminal rendering of the unified `Symbols` view (or any per-kind
/// filtered subset): kind, primary name/target/path, and a compact label
/// for the optional fields most rule authors care about.
fn render_symbols(st: Style, symbols: &[&Symbol]) -> String {
    let mut out = String::new();
    for symbol in symbols.iter().take(SYMBOL_PREVIEW_LIMIT) {
        let (kind, extras) = match symbol {
            Symbol::Import { library, .. } => ("import", library.clone().unwrap_or_default()),
            Symbol::Export { .. } => ("export", String::new()),
            Symbol::Function { .. } => ("function", String::new()),
            Symbol::Call { args, .. } => (
                "call",
                args.iter().map(format_arg).collect::<Vec<_>>().join(", "),
            ),
            Symbol::Member { .. } => ("member", String::new()),
            Symbol::Bind { .. } => ("bind", String::new()),
            Symbol::Identifier { .. } => ("identifier", String::new()),
            // `Symbol` is non-exhaustive: a kind added later still renders.
            _ => ("symbol", String::new()),
        };
        let spacer = if extras.is_empty() { "" } else { "  " };
        out.push_str(&format!(
            "  {} {}{spacer}{}\n",
            st.dim(&format!("{kind:>10}")),
            st.fg(FG_VALUE, symbol.name().unwrap_or("·")),
            st.dim(&extras),
        ));
    }
    if symbols.len() > SYMBOL_PREVIEW_LIMIT {
        let more = format!("... {} more", symbols.len() - SYMBOL_PREVIEW_LIMIT);
        out.push_str(&format!("    {}\n", st.dim(&more)));
    }
    out
}

/// A call argument as it would read in source: literals with their
/// value, everything else by shape.
fn format_arg(arg: &Arg) -> String {
    match arg {
        Arg::String { value } => format!("\"{}\"", string_excerpt(value, 40)),
        Arg::Template { value } => format!("`{}`", string_excerpt(value, 40)),
        Arg::Number { text, .. } => text.clone(),
        Arg::Identifier { name } => name.clone(),
        Arg::Bool { value } => value.to_string(),
        Arg::Null => "null".into(),
        Arg::Object => "{…}".into(),
        Arg::Array => "[…]".into(),
        Arg::Function => "<function>".into(),
        Arg::Call => "<call>".into(),
        // `Expression`, and any shape added later.
        _ => "<expr>".into(),
    }
}

// ─── archive members view ───────────────────────────────────────────

const ARCHIVE_MEMBERS_PREVIEW_LIMIT: usize = 50;

/// One line per member: size, path, then whatever sets it apart from a
/// plain stored file. Paths come from the archive, so control characters
/// are escaped.
fn render_archive_members(st: Style, members: &[filefacts::ArchiveMember]) -> String {
    let shown = members
        .get(..ARCHIVE_MEMBERS_PREVIEW_LIMIT)
        .unwrap_or(members);
    let sizes: Vec<String> = shown.iter().map(|m| humanize_bytes(m.size_bytes)).collect();
    let size_w = sizes.iter().map(String::len).max().unwrap_or(0);
    let mut out = String::new();
    for (m, size) in shown.iter().zip(&sizes) {
        let mut tail = Vec::<String>::new();
        if m.entry_type != filefacts::EntryType::Regular {
            tail.push(st.dim(m.entry_type.as_str()));
        }
        if let Some(method) = m.compression.method.as_deref() {
            tail.push(st.dim(method));
        }
        if m.encrypted {
            tail.push(st.fg(FG_FLAG_WRITE, "encrypted"));
        }
        if let Some(link) = m.linkname.as_deref() {
            tail.push(format!(
                "{} {}",
                st.dim("→"),
                st.fg(FG_VALUE, &string_excerpt(link, 80))
            ));
        }
        let tail = if tail.is_empty() {
            String::new()
        } else {
            format!("  {}", tail.join(&st.dim(" ")))
        };
        out.push_str(&format!(
            "  {}  {}{tail}\n",
            st.fg(FG_NUM, &format!("{size:>size_w$}")),
            st.fg(FG_VALUE, &string_excerpt(&m.path, 120)),
        ));
    }
    if members.len() > shown.len() {
        let more = format!("... {} more", members.len() - shown.len());
        out.push_str(&format!("  {}\n", st.dim(&more)));
    }
    out
}

// ─── errors view ────────────────────────────────────────────────────

fn render_errors(st: Style, errors: &Errors) -> String {
    if errors.is_empty() {
        return format!("  {}\n", st.fg(FG_OK, "✓ none"));
    }
    let mut out = String::new();
    for diagnostic in errors.iter() {
        out.push_str(&format!(
            "  {} {}  {}\n",
            st.bold(FG_ERROR, diagnostic.kind.as_str()),
            st.dim(diagnostic.stage.as_str()),
            st.fg(FG_VALUE, &diagnostic.message),
        ));
    }
    out
}

// ─── helpers ────────────────────────────────────────────────────────

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests;
