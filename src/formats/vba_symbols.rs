//! VBA symbol extraction over decompressed module source.
//!
//! Surfaces structured `Import`/`Function` records so trait authors
//! can use `type: symbol` matchers (faster, no comment/string false
//! positives, normalization-aware) instead of brittle `type: raw`
//! regexes against the module text.
//!
//! There is no Rust tree-sitter grammar for VBA worth depending on
//! (`tree-sitter-vbscript` exists but does not cover `Declare PtrSafe`,
//! the `Lib` clause, or `Alias` properly). This is a targeted regex
//! extractor that handles the high-value cases:
//!
//! - `Declare [PtrSafe] Function|Sub NAME Lib "LIB" [Alias "ALIAS"]`
//! - `CreateObject("PROGID")` / `GetObject(... , "PROGID")`
//! - `Sub NAME` / `Function NAME` declarations (incl. `Public`/`Private`)
//!
//! Pre-processing joins MS-VBA line continuations (`_` at end-of-line)
//! and strips `'` line comments and `Rem` lines so a comment between
//! tokens doesn't break a Declare match. Offsets reported in the
//! resulting symbols are relative to the *original* source bytes.
//!
//! A non-literal `Lib` clause leaves the import's `library` as `None`, and a
//! non-literal `CreateObject`/`GetObject` ProgID emits no import at all: the
//! value is built at run time, so there is no name to record. Both are the
//! strongest single obfuscation signal and feed the
//! `office.vba.declare_non_literal_count` /
//! `office.vba.createobject_non_literal_count` /
//! `office.vba.getobject_non_literal_count` metrics.

use regex::Regex;
use std::sync::LazyLock;

use crate::output::Symbol;

/// Aggregate counters from one module's symbol extraction. Folded
/// into the per-document `office.vba.*_count` metric keys by
/// [`crate::formats::vba::extract`]. Not exposed publicly — consumers read
/// the metric map.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct VbaSymbolStats {
    pub declare_count: u32,
    pub declare_non_literal_count: u32,
    pub createobject_count: u32,
    pub createobject_non_literal_count: u32,
    pub getobject_count: u32,
    pub getobject_non_literal_count: u32,
    pub trigger_handler_count: u32,
}

/// Run the four extractors over one module's source. Pushes records
/// into `symbols_out` and returns the per-module aggregate counters.
///
/// Crate-internal: VBA symbols flow out through the unified
/// [`crate::Symbols`] view populated by [`crate::formats::vba::extract`],
/// not through a public per-module function.
pub(crate) fn extract(source: &str, symbols_out: &mut crate::output::Symbols) -> VbaSymbolStats {
    let mut stats = VbaSymbolStats::default();
    if source.is_empty() {
        return stats;
    }
    let prepared = preprocess(source);
    extract_declares(&prepared, symbols_out, &mut stats);
    extract_createobject(&prepared, symbols_out, &mut stats, false);
    extract_createobject(&prepared, symbols_out, &mut stats, true);
    extract_subs_and_functions(&prepared, symbols_out, &mut stats);
    stats
}

/// Pre-processed VBA source with line-continuation joined and line
/// comments stripped, plus a per-byte mapping back to original
/// offsets.
struct Prepared {
    text: String,
    map: Vec<usize>,
}

impl Prepared {
    fn original_offset(&self, idx: usize) -> usize {
        self.map
            .get(idx)
            .or_else(|| self.map.last())
            .copied()
            .unwrap_or(0)
    }
}

/// Join `_` line-continuations and strip `'` line comments / `Rem`
/// lines. Tracks string literals so an apostrophe inside `"…'…"` is
/// preserved.
fn preprocess(source: &str) -> Prepared {
    let bytes = source.as_bytes();
    let mut text = String::with_capacity(source.len());
    let mut map = Vec::with_capacity(source.len());

    // The `\n` that ends the line holding `from`, or the end of the source.
    let line_end = |from: usize| {
        bytes
            .get(from..)
            .and_then(|rest| memchr::memchr(b'\n', rest))
            .map_or(bytes.len(), |n| from + n)
    };

    // Whether the text since the last line break holds an open `"`, so an
    // apostrophe there is string content rather than a comment.
    let mut in_string = false;
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        // VBA line continuation: `_` followed (after optional
        // whitespace) by a line terminator. Replace the joined break
        // with a single space so adjacent tokens don't merge.
        if byte == b'_' {
            let mut j = i + 1;
            while matches!(bytes.get(j), Some(b' ' | b'\t')) {
                j += 1;
            }
            if matches!(bytes.get(j), Some(b'\n' | b'\r')) {
                if bytes.get(j) == Some(&b'\r') {
                    j += 1;
                }
                if bytes.get(j) == Some(&b'\n') {
                    j += 1;
                }
                while text.ends_with(' ') || text.ends_with('\t') {
                    text.pop();
                    map.pop();
                }
                text.push(' ');
                map.push(i);
                i = j;
                continue;
            }
        }

        // Strip line-leading `Rem` comments (case-insensitive).
        let at_line_start = text.is_empty() || text.ends_with('\n');
        if at_line_start {
            if let Some(head) = bytes.get(i..i + 3) {
                let is_rem = head.eq_ignore_ascii_case(b"Rem");
                let next = bytes.get(i + 3).copied().unwrap_or(b'\n');
                if is_rem && (next == b' ' || next == b'\t' || next == b'\r' || next == b'\n') {
                    i = line_end(i);
                    continue;
                }
            }
        }

        // Strip apostrophe comments outside of string literals.
        if byte == b'\'' && !in_string {
            i = line_end(i);
            continue;
        }

        if byte.is_ascii() {
            match byte {
                b'"' => in_string = !in_string,
                b'\n' => in_string = false,
                _ => {}
            }
            text.push(byte as char);
            map.push(i);
            i += 1;
        } else {
            // Preserve the original UTF-8 sequence: a Latin-1 cast
            // (`byte as char`) would produce mojibake for non-ASCII
            // identifiers and would also misalign the per-byte offset
            // map, since one source byte would expand into two UTF-8
            // bytes in `text` while `map` only recorded one entry.
            let ch = source
                .get(i..)
                .and_then(|rest| rest.chars().next())
                .unwrap_or('\u{FFFD}');
            let ch_len = ch.len_utf8();
            text.push(ch);
            for _ in 0..ch_len {
                map.push(i);
            }
            i += ch_len;
        }
    }

    Prepared { text, map }
}

// The patterns below are constants, so compiling them cannot fail on input;
// the unit tests exercise every one.
static DECLARE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        \b Declare \s+ (?: PtrSafe \s+ )?
        (Function | Sub) \s+
        ([A-Za-z_][A-Za-z0-9_]*) \s+
        Lib \s+
        ( "[^"]*" | [^\s(]+ )
        (?: \s+ Alias \s+ "([^"]*)" )?
        "#,
    )
    .expect("constant Declare pattern compiles")
});

static CREATE_OBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)\b CreateObject \s* \( \s* ( "[^"]*" | [^,)]+ )"#)
        .expect("constant CreateObject pattern compiles")
});

static GET_OBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)\b GetObject \s* \( \s* ( "[^"]*" | [^,)]+ ) (?: \s* , \s* ( "[^"]*" | [^,)]+ ) )?"#,
    )
    .expect("constant GetObject pattern compiles")
});

static SUB_OR_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^\s*(?:Public\s+|Private\s+|Friend\s+|Static\s+){0,2}(?:Sub|Function)\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("constant Sub/Function pattern compiles")
});

fn extract_declares(
    prep: &Prepared,
    symbols_out: &mut crate::output::Symbols,
    stats: &mut VbaSymbolStats,
) {
    for cap in DECLARE.captures_iter(&prep.text) {
        stats.declare_count = stats.declare_count.saturating_add(1);

        let lib_raw = cap.get(3).map(|m| m.as_str()).unwrap_or("");
        let library = classify_lib(lib_raw);
        if library.is_none() {
            stats.declare_non_literal_count = stats.declare_non_literal_count.saturating_add(1);
        }

        // Prefer the Alias when present — that's the actual exported
        // name in the DLL. Otherwise the local declared name is the
        // import name.
        let alias = cap.get(4).map(|m| m.as_str().to_string());
        let local = cap
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let import_name = alias.unwrap_or(local);
        if import_name.is_empty() {
            continue;
        }

        let offset = cap
            .get(0)
            .map(|m| prep.original_offset(m.start()))
            .unwrap_or(0) as u64;

        symbols_out.push(Symbol::Import {
            name: import_name,
            alias: None,
            library,
            offset: Some(offset),
            ordinal: None,
        });
    }
}

/// The library a `Lib` expression names, lowercased and without a `.dll`
/// suffix; `None` when it is not a string literal (built at run time).
fn classify_lib(raw: &str) -> Option<String> {
    let library = string_literal(raw)?.to_ascii_lowercase();
    Some(library.strip_suffix(".dll").unwrap_or(&library).to_string())
}

/// The contents of a double-quoted string literal, or `None` for any other
/// expression.
fn string_literal(raw: &str) -> Option<&str> {
    raw.trim().strip_prefix('"')?.strip_suffix('"')
}

fn extract_createobject(
    prep: &Prepared,
    symbols_out: &mut crate::output::Symbols,
    stats: &mut VbaSymbolStats,
    is_get: bool,
) {
    let (re, lib_label) = if is_get {
        (&*GET_OBJECT, "com-getobject")
    } else {
        (&*CREATE_OBJECT, "com")
    };

    for cap in re.captures_iter(&prep.text) {
        // For GetObject prefer the second arg (ProgID); otherwise
        // the first arg is the moniker (path/URL).
        let (raw, second_present) = if is_get {
            match cap.get(2) {
                Some(m) => (m.as_str(), true),
                None => (cap.get(1).map(|m| m.as_str()).unwrap_or(""), false),
            }
        } else {
            (cap.get(1).map(|m| m.as_str()).unwrap_or(""), false)
        };

        if is_get {
            stats.getobject_count = stats.getobject_count.saturating_add(1);
        } else {
            stats.createobject_count = stats.createobject_count.saturating_add(1);
        }

        let literal = string_literal(raw);
        if literal.is_none() {
            if is_get {
                stats.getobject_non_literal_count =
                    stats.getobject_non_literal_count.saturating_add(1);
            } else {
                stats.createobject_non_literal_count =
                    stats.createobject_non_literal_count.saturating_add(1);
            }
        }

        // Only emit Imports for ProgID-style data: literal
        // CreateObject args, or literal *second* args of GetObject.
        // A bare GetObject moniker (`"file:..."`) is not a ProgID, and a
        // non-literal argument has no name to record (the counts above
        // carry it).
        let Some(name) = literal.filter(|_| !is_get || second_present) else {
            continue;
        };

        let offset = cap
            .get(0)
            .map(|m| prep.original_offset(m.start()))
            .unwrap_or(0) as u64;
        symbols_out.push(Symbol::Import {
            name: name.to_string(),
            alias: None,
            library: Some(lib_label.to_string()),
            offset: Some(offset),
            ordinal: None,
        });
    }
}

/// VBA trigger-handler names. Real-world malware leans on
/// `Auto_Open`, `Document_Open`, `Workbook_Open`, …; emitting them
/// as a `trigger_handler_count` aggregate lets a trait fire on
/// "any auto-execution vector" without enumerating every name.
const TRIGGER_NAMES: &[&str] = &[
    "Auto_Open",
    "AutoOpen",
    "Auto_Close",
    "AutoClose",
    "AutoExec",
    "AutoExit",
    "AutoNew",
    "Document_Open",
    "Document_New",
    "Document_Close",
    "Document_BeforeClose",
    "Document_BeforePrint",
    "Document_BeforeSave",
    "Document_ContentControlOnEnter",
    "Workbook_Open",
    "Workbook_Activate",
    "Workbook_Deactivate",
    "Workbook_BeforeClose",
    "Workbook_BeforeSave",
    "Workbook_BeforePrint",
    "Worksheet_Activate",
    "Worksheet_Calculate",
    "Worksheet_Change",
    "Worksheet_SelectionChange",
    "UserForm_Activate",
    "UserForm_Initialize",
    "UserForm_Click",
    "UserForm_Layout",
    "Chart_Activate",
    "Chart_Calculate",
    "App_NewMail",
];

pub(super) fn is_trigger_name(name: &str) -> bool {
    TRIGGER_NAMES.iter().any(|t| t.eq_ignore_ascii_case(name))
}

fn extract_subs_and_functions(
    prep: &Prepared,
    symbols_out: &mut crate::output::Symbols,
    stats: &mut VbaSymbolStats,
) {
    // Skip names whose match start lies inside a Declare match —
    // those are already emitted as imports. The spans are disjoint and in
    // source order, so the one that could hold a start is found by search.
    let declare_spans: Vec<(usize, usize)> = DECLARE
        .find_iter(&prep.text)
        .map(|m| (m.start(), m.end()))
        .collect();

    for cap in SUB_OR_FUNCTION.captures_iter(&prep.text) {
        let Some(m) = cap.get(0) else { continue };
        let before = declare_spans.partition_point(|&(start, _)| start <= m.start());
        let inside_declare = before
            .checked_sub(1)
            .and_then(|i| declare_spans.get(i))
            .is_some_and(|&(_, end)| m.start() < end);
        if inside_declare {
            continue;
        }

        let Some(name) = cap.get(1).map(|n| n.as_str().to_string()) else {
            continue;
        };
        let offset = prep.original_offset(m.start()) as u64;

        if is_trigger_name(&name) {
            stats.trigger_handler_count = stats.trigger_handler_count.saturating_add(1);
        }

        symbols_out.push(Symbol::Function {
            name,
            offset: Some(offset),
            complexity: None,
            callees: Vec::new(),
        });
    }
}

#[cfg(test)]
mod tests;
