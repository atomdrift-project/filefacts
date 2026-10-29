use super::*;
use crate::output::{SymbolKind, Symbols};

fn run(src: &str) -> (Symbols, VbaSymbolStats) {
    let mut symbols = Symbols::new();
    let stats = extract(src, &mut symbols);
    (symbols, stats)
}

fn imports(s: &Symbols) -> Vec<(&str, Option<&str>)> {
    s.iter_kind(SymbolKind::Import)
        .filter_map(|sym| match sym {
            Symbol::Import { name, library, .. } => Some((name.as_str(), library.as_deref())),
            _ => None,
        })
        .collect()
}

fn functions(s: &Symbols) -> Vec<&str> {
    s.iter_kind(SymbolKind::Function)
        .filter_map(|sym| match sym {
            Symbol::Function { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn declare_with_alias_emits_alias_as_symbol() {
    let src = r#"
        Declare PtrSafe Function vAlloc Lib "kernel32" Alias "VirtualAlloc" _
          (ByVal lpAddress As LongPtr) As LongPtr
    "#;
    let (syms, stats) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0], ("VirtualAlloc", Some("kernel32")));
    assert_eq!(stats.declare_count, 1);
    assert_eq!(stats.declare_non_literal_count, 0);
}

#[test]
fn declare_handles_case_whitespace_and_dll_suffix() {
    let src = "declare\tFunction\tLoadLibraryA\tlib \"KERNEL32.dll\"\t(s As String)\n";
    let (syms, _) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].0, "LoadLibraryA");
    assert_eq!(imps[0].1, Some("kernel32"));
}

#[test]
fn declare_with_line_continuation() {
    let src = "Declare PtrSafe Function f _\n  Lib \"urlmon\" _\n  Alias \"URLDownloadToFileA\" (a As Long)\n";
    let (syms, _) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].0, "URLDownloadToFileA");
    assert_eq!(imps[0].1, Some("urlmon"));
}

#[test]
fn declare_skips_apostrophe_comment_between_tokens() {
    let src = "Declare Function CreateProcessA _\n  ' comment that hides intent\n  Lib \"kernel32\" (a As Long)\n";
    let (syms, _) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].0, "CreateProcessA");
}

#[test]
fn declare_with_non_literal_lib_has_no_library() {
    let src = r#"Declare Function f Lib dllName Alias "VirtualProtect" () As Long"#;
    let (syms, stats) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps, [("VirtualProtect", None)]);
    assert_eq!(stats.declare_non_literal_count, 1);
}

#[test]
fn apostrophe_inside_string_literal_is_preserved() {
    let src = "x = \"it's fine\"\nDeclare Function K Lib \"kernel32\" (s As Long)\n";
    let (syms, _) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].0, "K");
}

#[test]
fn createobject_literal_progid() {
    let src = r#"Set sh = CreateObject("WScript.Shell")"#;
    let (syms, stats) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0], ("WScript.Shell", Some("com")));
    assert_eq!(stats.createobject_count, 1);
    assert_eq!(stats.createobject_non_literal_count, 0);
}

#[test]
fn createobject_non_literal_arg() {
    let src = r#"Set x = CreateObject(progName & ".Sh" & "ell")"#;
    let (syms, stats) = run(src);
    assert!(imports(&syms).is_empty(), "no name to record");
    assert_eq!(stats.createobject_count, 1);
    assert_eq!(stats.createobject_non_literal_count, 1);
}

#[test]
fn getobject_two_arg_form_yields_progid_only() {
    let src = r#"Set xl = GetObject("c:\book.xls", "Excel.Application")"#;
    let (syms, stats) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0], ("Excel.Application", Some("com-getobject")));
    assert_eq!(stats.getobject_count, 1);
}

#[test]
fn getobject_one_arg_emits_no_symbol() {
    let src = r#"Set f = GetObject("script:http://example.com/payload.sct")"#;
    let (syms, stats) = run(src);
    assert_eq!(imports(&syms).len(), 0);
    assert_eq!(stats.getobject_count, 1);
}

#[test]
fn sub_function_declarations_extracted_excluding_declare() {
    let src = "Public Sub Document_Open()\nEnd Sub\n\nPrivate Function helper(x)\nEnd Function\n\nDeclare Function notAFunction Lib \"k32\" () As Long\n";
    let (syms, stats) = run(src);
    let names = functions(&syms);
    assert!(names.contains(&"Document_Open"));
    assert!(names.contains(&"helper"));
    assert!(!names.contains(&"notAFunction"));
    assert_eq!(stats.trigger_handler_count, 1);
}

#[test]
fn trigger_handler_count_aggregates_distinct_triggers() {
    let src = "Sub Document_Open()\nEnd Sub\nSub Workbook_Open()\nEnd Sub\nSub helper()\nEnd Sub\n";
    let (_, stats) = run(src);
    assert_eq!(stats.trigger_handler_count, 2);
}

#[test]
fn rem_comment_line_is_stripped() {
    let src =
        "Rem Declare Function fake Lib \"x\" ()\nDeclare Function real Lib \"k32\" () As Long\n";
    let (syms, _) = run(src);
    let imps = imports(&syms);
    assert_eq!(imps.len(), 1);
    assert_eq!(imps[0].0, "real");
}

#[test]
fn empty_source_returns_zero_stats() {
    let (syms, stats) = run("");
    assert!(syms.is_empty());
    assert_eq!(stats.declare_count, 0);
}

/// Windows resolves `Lib` names case-insensitively, so every casing of the
/// `.dll` suffix names the same library as the bare stem.
#[test]
fn dll_suffix_is_stripped_in_any_case() {
    for lib in [
        "\"kernel32\"",
        "\"kernel32.dll\"",
        "\"KERNEL32.DLL\"",
        "\"Kernel32.Dll\"",
        "\"kernel32.dLl\"",
        "\"KeRnEl32.DlL\"",
    ] {
        assert_eq!(classify_lib(lib).as_deref(), Some("kernel32"), "{lib}");
    }
    assert_eq!(classify_lib("\"x.dll.dll\"").as_deref(), Some("x.dll"));
    assert_eq!(classify_lib("\".dll\"").as_deref(), Some(""));
    assert_eq!(classify_lib("libName"), None);
}

/// An apostrophe inside a string is content even after a doubled quote or a
/// line continuation; one after the string closes starts a comment.
#[test]
fn apostrophes_track_string_state_across_continuations() {
    let src = "x = \"it\"\"s _\n'here\" ' CreateObject(\"Hidden.Comment\")\ny = CreateObject(\"Shell.Application\")\n";
    let (syms, stats) = run(src);
    assert_eq!(imports(&syms), [("Shell.Application", Some("com"))]);
    assert_eq!(stats.createobject_count, 1);
}

/// A Sub/Function keyword inside any Declare, not just the first, is part of
/// that import, while one between two Declares is a definition.
#[test]
fn definitions_between_declares_are_kept() {
    let src = "Declare Function A Lib \"a\" ()\nSub Between()\nEnd Sub\nDeclare Sub B Lib \"b\" ()\nFunction After()\nEnd Function\n";
    let (syms, stats) = run(src);
    assert_eq!(functions(&syms), ["Between", "After"]);
    assert_eq!(stats.declare_count, 2);
}
