//! Shared tree-sitter parse cache.
//!
//! Built lazily on first source-driven extraction and shared across
//! every source-derived view of the same `ParsedFile`.
//!
//! The cache owns the [`tree_sitter::Tree`] and a borrowed reference to
//! the source bytes (as a `&str`); the tree-sitter API references the
//! source by offset, not by reference, so the `&str` lifetime is what
//! ties this cache to the parent `ParsedFile<'a>`.

use crate::error::Error;
use crate::fileid::FileType;
use crate::formats::source::langs;
use std::cell::RefCell;
use std::io::Write;

/// Tree-sitter's external scanners serialize their state into a fixed
/// 1024-byte buffer (`TREE_SITTER_SERIALIZATION_BUFFER_SIZE` in
/// `parser.c`). On overflow `ts_parser__external_scanner_serialize`
/// hits `ts_assert(length <= 1024)` and calls `abort()` — the upstream
/// build does not define `NDEBUG`, so the assertion fires in release
/// builds. We can't catch a C `abort` from Rust, so the only safe
/// option is to refuse parses that are likely to trip it.
///
/// 2 MB matches cleave's `MAX_AST_FILE_BYTES`. Files this large are
/// almost always machine-generated (protobuf descriptors, minified
/// bundles) and gain little from AST analysis anyway.
const MAX_AST_FILE_BYTES: usize = 2 * 1024 * 1024;

/// Conservative cap for grammars whose scanner has not been audited
/// for the 1024-byte overflow. New or freshly-bumped grammar crates
/// land here automatically — when an entry is missing from
/// [`scanner_audit`], we'd rather drop AST analysis on the rare
/// 64+ KB source than risk a C-level abort on the whole worker.
const UNAUDITED_GRAMMAR_CAP_BYTES: usize = 64 * 1024;

/// Size at which a parse is worth a per-call diagnostic line. Below
/// this most scanners can't have accumulated enough state to reach
/// the 1024-byte serialization boundary, so the breadcrumb would
/// only add log noise. Above it, an abort is plausible and the
/// breadcrumb names the grammar + size for the next post-mortem.
const PARSE_BREADCRUMB_THRESHOLD_BYTES: usize = 64 * 1024;

/// Budget for the **combined** Python scanner state. Layout per
/// `tree_sitter_python_external_scanner_serialize` (`scanner.c`):
///
/// ```text
/// 1 byte   inside_interpolated_string
/// 1 byte   delimiter_count (clamped to UINT8_MAX = 255)
/// N bytes  delimiters (N = clamped count)
/// 2*M B    indent stack (M = indents.size - 1, since indents[0] is
///          always 0 and the serializer's loop starts at iter = 1)
/// ```
///
/// The upstream serializer has an off-by-one: its loop guard is
/// `size < 1024`, but each iteration writes 2 bytes, so the final
/// returned size can reach 1025 (the assert is `length <= 1024`).
/// Pick 1020 as the budget to stay clear of the boundary with one
/// indent of slack.
const PYTHON_SCANNER_BUDGET_BYTES: usize = 1020;

/// Per-string-literal byte cost in the delimiter portion of the
/// scanner state.
const PYTHON_DELIMITER_BYTES: usize = 1;

/// Per-indent-level byte cost in the indent portion of the scanner
/// state.
const PYTHON_INDENT_BYTES_PER_LEVEL: usize = 2;

thread_local! {
    /// One tree-sitter parser per worker thread, reused across files.
    /// Constructing a fresh `Parser` on every call allocates internal
    /// state tables; reusing the same instance lets tree-sitter keep
    /// its scratch arenas warm across files in the same archive.
    static THREAD_PARSER: RefCell<tree_sitter::Parser> = RefCell::new(tree_sitter::Parser::new());
}

/// A cached parse for a source file.
pub(crate) struct TreeCache<'a> {
    source: &'a str,
    tree: tree_sitter::Tree,
    file_type: FileType,
}

impl<'a> TreeCache<'a> {
    /// Parse `bytes` as `file_type` source. Returns `Ok(None)` when the
    /// type isn't a supported source language; returns `Ok(None)` when
    /// the bytes aren't valid UTF-8 (source code must be); returns
    /// `Err` only when the language is supported but the parser
    /// signals an unrecoverable error (rare — tree-sitter recovers
    /// gracefully from most malformed input).
    pub(crate) fn parse(bytes: &'a [u8], file_type: FileType) -> Result<Option<Self>, Error> {
        let Some(config) = langs::config_for(file_type) else {
            return Ok(None);
        };
        let Ok(source) = std::str::from_utf8(bytes) else {
            return Ok(None);
        };
        if would_overflow_scanner_state(file_type, source) {
            tracing::warn!(
                language = config.name,
                bytes = source.len(),
                audit = ?scanner_audit(file_type),
                "skipping tree-sitter parse to avoid 1024-byte scanner-state overflow"
            );
            return Ok(None);
        }
        let language = (config.language)();
        THREAD_PARSER.with(|cell| {
            let mut parser = cell.borrow_mut();
            parser.set_language(&language).map_err(|e| {
                Error::malformed("source", format!("tree-sitter language setup failed: {e}"))
            })?;
            // Breadcrumb for sources large enough to plausibly overflow
            // the scanner. Flushed before `parse` so the line survives
            // a C-level abort and names the offending grammar.
            if source.len() >= PARSE_BREADCRUMB_THRESHOLD_BYTES {
                tracing::info!(
                    language = config.name,
                    bytes = source.len(),
                    "tree-sitter parse begin"
                );
                let _ = std::io::stderr().flush();
                let _ = std::io::stdout().flush();
            }
            let tree = parser
                .parse(source, None)
                .ok_or_else(|| Error::malformed("source", "tree-sitter parse returned None"))?;
            Ok(Some(Self {
                source,
                tree,
                file_type,
            }))
        })
    }

    pub(crate) fn source(&self) -> &str {
        self.source
    }

    pub(crate) fn tree(&self) -> &tree_sitter::Tree {
        &self.tree
    }

    pub(crate) fn file_type(&self) -> FileType {
        self.file_type
    }
}

/// Pre-check input that could overflow a tree-sitter external scanner's
/// 1024-byte serialization buffer. Returning `true` causes `parse` to
/// skip the parse rather than risk the C-level abort.
fn would_overflow_scanner_state(file_type: FileType, source: &str) -> bool {
    let audit = scanner_audit(file_type);
    if source.len() > parse_cap_bytes(audit) {
        return true;
    }
    if matches!(audit, ScannerAudit::Modeled) && matches!(file_type, FileType::Python) {
        if estimated_python_scanner_bytes(source) > PYTHON_SCANNER_BUDGET_BYTES {
            return true;
        }
    }
    false
}

/// What we've verified about a grammar's external scanner overflow
/// behavior, against the locked crate version in this workspace.
///
/// The serialization buffer is a fixed 1024 bytes (`parser.c`
/// `TREE_SITTER_SERIALIZATION_BUFFER_SIZE`). When the C scanner's
/// `serialize()` returns more than that, the tree-sitter runtime
/// aborts. The audit categorizes how each grammar handles overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScannerAudit {
    /// Scanner serializes a fixed, small amount of state regardless of
    /// input (e.g. no external scanner, or a single counter, or a
    /// `return 0`). Cannot reach the 1024-byte limit.
    Bounded,
    /// Scanner has a self-guard in `serialize()` that returns 0 when
    /// the next write would exceed the buffer. Safe at any input size.
    SelfGuarded,
    /// Scanner can overflow, but filefacts pre-models its worst-case
    /// serialized size and rejects inputs likely to trip it. Currently
    /// only Python.
    Modeled,
    /// Grammar has not been audited at the currently-locked version —
    /// or `file_type` is one this module doesn't recognize. Apply the
    /// tight [`UNAUDITED_GRAMMAR_CAP_BYTES`] cap until audited.
    Unaudited,
}

/// Audit table for the grammars wired up in [`langs::config_for`].
///
/// When bumping a `tree-sitter-*` crate, re-inspect that crate's
/// `scanner.c` (or `.cc`) and confirm the audit category still holds
/// — in particular, check whether `external_scanner_serialize` still
/// either returns a small constant size, or guards each write against
/// `TREE_SITTER_SERIALIZATION_BUFFER_SIZE`. If neither, downgrade to
/// `Unaudited` or add a model like Python's.
fn scanner_audit(file_type: FileType) -> ScannerAudit {
    use ScannerAudit::{Bounded, Modeled, SelfGuarded, Unaudited};
    match file_type {
        // No external scanner in the locked grammar crate.
        FileType::C
        | FileType::Go
        | FileType::Groovy
        | FileType::Java
        | FileType::Makefile
        | FileType::ObjectiveC
        | FileType::TypeScript
        | FileType::Zig => Bounded,

        // External scanner present, but `serialize()` returns a fixed
        // small size independent of input.
        FileType::Elixir
        | FileType::JavaScript
        | FileType::Kotlin
        | FileType::Lua
        | FileType::PowerShell
        | FileType::Rust
        | FileType::Swift => Bounded,

        // `serialize()` early-returns 0 when the next write would
        // overflow the 1024-byte buffer.
        FileType::CSharp | FileType::Php | FileType::Ruby | FileType::Scala | FileType::Shell => {
            SelfGuarded
        }

        // Can overflow; modeled in [`estimated_python_scanner_bytes`].
        FileType::Python => Modeled,

        // Perl's `serialize()` in `ts-parser-perl` writes up to
        // 255 × `sizeof(TSPQuote)` (~3 KB) without a buffer-size guard,
        // so deeply quoted input can overflow. Treat as `Unaudited`
        // for now — the 64 KB cap blocks the bulk of the risk; a
        // proper model (like Python's) would be the long-term fix.
        FileType::Perl => Unaudited,

        _ => Unaudited,
    }
}

/// Maximum source size we'll hand to the tree-sitter parser for a
/// grammar with the given audit category.
fn parse_cap_bytes(audit: ScannerAudit) -> usize {
    match audit {
        ScannerAudit::Bounded | ScannerAudit::SelfGuarded | ScannerAudit::Modeled => {
            MAX_AST_FILE_BYTES
        }
        ScannerAudit::Unaudited => UNAUDITED_GRAMMAR_CAP_BYTES,
    }
}

/// Worst-case Python scanner serialization size. Models both the
/// **indent stack** and the **delimiter stack** the scanner persists,
/// since either one alone — or the two together — can exceed the
/// 1024-byte buffer and trip `ts_parser__external_scanner_serialize`.
/// Computed without invoking the parser so it stays cheap on hostile
/// input.
///
/// Returned value is in bytes and includes the 2-byte header that
/// the serializer emits before either stack.
fn estimated_python_scanner_bytes(source: &str) -> usize {
    // 1 byte `inside_interpolated_string` + 1 byte `delimiter_count`.
    const HEADER_BYTES: usize = 2;
    let indent_levels = estimated_python_indent_stack_depth(source);
    let delim_levels = estimated_python_delimiter_depth(source);
    // The serializer's `iter = 1` start skips `indents[0]` (always 0),
    // so the persisted indent count is `indent_levels.saturating_sub(1)`.
    let indent_bytes = indent_levels.saturating_sub(1) * PYTHON_INDENT_BYTES_PER_LEVEL;
    // Delimiter count is clamped to UINT8_MAX inside the serializer.
    let delim_bytes = delim_levels.min(u8::MAX as usize) * PYTHON_DELIMITER_BYTES;
    HEADER_BYTES + delim_bytes + indent_bytes
}

/// Worst-case depth of Python's indent stack — one of the two stacks
/// the tree-sitter external scanner persists.
fn estimated_python_indent_stack_depth(source: &str) -> usize {
    let mut stack: Vec<usize> = vec![0];
    let mut max_depth: usize = 1;

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line
            .bytes()
            .take_while(|b| matches!(b, b' ' | b'\t'))
            .fold(0usize, |col, b| if b == b'\t' { col + 8 } else { col + 1 });
        while stack.last().is_some_and(|last| indent < *last) {
            stack.pop();
        }
        if stack.last().is_some_and(|last| indent > *last) {
            stack.push(indent);
            max_depth = max_depth.max(stack.len());
        }
    }
    max_depth
}

/// Worst-case depth of Python's delimiter stack — the other stack the
/// scanner persists. The scanner pushes one entry per open string
/// literal that hasn't closed yet; the only path that grows it beyond
/// a single entry is f-string interpolation, where `f"{ ... }"` may
/// itself contain another `f"..."`.
///
/// We can't parse Python here without running tree-sitter, so we use
/// the simplest correct upper bound: every `f"`, `f'`, `F"`, or `F'`
/// found in the source is a potential push. Brackets that an f-string
/// might close (`}`) are accounted for by walking the bytes and
/// tracking the maximum unmatched `f`-prefix count between the
/// surrounding `{` and `}` boundaries. Triple-quoted f-strings count
/// once each (they consume a single delimiter slot).
fn estimated_python_delimiter_depth(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut max_depth: usize = 0;
    let mut depth: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            // Skip past a hash-line comment — `f"` inside a comment is
            // not a delimiter push.
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // An `f`/`F` immediately followed by a quote opens an
            // f-string. Plain (non-f) strings never *nest*, so we
            // only need to count f-string openers.
            b'f' | b'F' => {
                let next = bytes.get(i + 1).copied().unwrap_or(0);
                if next == b'"' || next == b'\'' {
                    depth = depth.saturating_add(1);
                    max_depth = max_depth.max(depth);
                    i += 2;
                    continue;
                }
                i += 1;
            }
            // A closing brace inside interpolation drops one level of
            // f-string nesting. Worst-case heuristic: every `}` could
            // close an f-string interpolation, so decrement.
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_oversized_source() {
        let huge = "x = 1\n".repeat(MAX_AST_FILE_BYTES);
        assert!(would_overflow_scanner_state(FileType::Python, &huge));
    }

    #[test]
    fn skips_deep_python_indentation() {
        // Indent levels alone large enough to exceed the budget when
        // even a tiny delimiter stack is added on top.
        let mut source = String::new();
        for depth in 0..600 {
            source.push_str(&" ".repeat(depth * 2));
            source.push_str("if True:\n");
        }
        assert!(would_overflow_scanner_state(FileType::Python, &source));
    }

    /// Adversarial Python that pushes BOTH the indent stack and the
    /// delimiter stack hard enough that the combined serialized state
    /// exceeds the 1024-byte buffer — even though each stack on its
    /// own would stay under the upstream serializer's clamps. The
    /// pre-existing indent-only guard at 450 levels missed this
    /// scenario; the budget-based check catches it.
    #[test]
    fn skips_combined_indent_and_fstring_pressure() {
        let mut source = String::new();
        // Bury an open f-string deep enough that the delimiter stack
        // carries 255 entries when the indent stack is also large.
        for _ in 0..255 {
            source.push_str("f\"{");
        }
        for depth in 0..400 {
            source.push_str(&" ".repeat(depth + 1));
            source.push_str("if True:\n");
        }
        assert!(would_overflow_scanner_state(FileType::Python, &source));
    }

    #[test]
    fn allows_normal_python() {
        let source = "def f():\n    return 1\n";
        assert!(!would_overflow_scanner_state(FileType::Python, source));
    }

    #[test]
    fn allows_realistic_fstring_usage() {
        let source = r#"
def greet(name, count):
    return f"hello {name}, you have {count} messages, {f'~{count*2}~'} doubled"
"#;
        assert!(!would_overflow_scanner_state(FileType::Python, source));
    }

    #[test]
    fn deep_indentation_ignored_for_non_python() {
        let mut source = String::new();
        for depth in 0..600 {
            source.push_str(&" ".repeat(depth * 2));
            source.push_str("echo hi\n");
        }
        assert!(!would_overflow_scanner_state(FileType::Shell, &source));
    }

    #[test]
    fn unaudited_grammars_use_tight_cap() {
        // Perl is known-unguarded and routed to `Unaudited`. The cap
        // for unaudited grammars must be the tighter
        // `UNAUDITED_GRAMMAR_CAP_BYTES`, not the 2 MB default — a
        // 200 KB Perl source should be rejected even though the same
        // size is fine for audited grammars.
        let source = "1;\n".repeat(80_000); // ~240 KB.
        assert!(source.len() > UNAUDITED_GRAMMAR_CAP_BYTES);
        assert!(source.len() < MAX_AST_FILE_BYTES);
        assert!(would_overflow_scanner_state(FileType::Perl, &source));
        // The same source under an audited grammar with a 2 MB cap
        // passes through (Shell is `SelfGuarded`).
        assert!(!would_overflow_scanner_state(FileType::Shell, &source));
    }

    #[test]
    fn audit_lookup_covers_every_wired_grammar() {
        // Every file type that has a `LangConfig` in `langs::config_for`
        // must have an explicit audit entry — falling into the
        // `_ => Unaudited` catch-all should be deliberate, not
        // accidental. This test pins the audit table to the current
        // grammar set so a new `FileType` doesn't silently get the
        // tight cap.
        let audited: &[FileType] = &[
            FileType::C,
            FileType::CSharp,
            FileType::Elixir,
            FileType::Go,
            FileType::Groovy,
            FileType::Java,
            FileType::JavaScript,
            FileType::Kotlin,
            FileType::Lua,
            FileType::Makefile,
            FileType::ObjectiveC,
            FileType::Perl,
            FileType::Php,
            FileType::PowerShell,
            FileType::Python,
            FileType::Ruby,
            FileType::Rust,
            FileType::Scala,
            FileType::Shell,
            FileType::Swift,
            FileType::TypeScript,
            FileType::Zig,
        ];
        for ft in audited {
            // Bounded/SelfGuarded/Modeled — anything but Unaudited
            // counts as "explicit entry". Perl is the only audited
            // type that maps to Unaudited (with a comment explaining
            // why), so allow it.
            let audit = scanner_audit(*ft);
            if *ft == FileType::Perl {
                assert_eq!(audit, ScannerAudit::Unaudited);
            } else {
                assert_ne!(
                    audit,
                    ScannerAudit::Unaudited,
                    "{ft:?} fell through to Unaudited — add explicit audit entry"
                );
            }
        }
    }

    #[test]
    fn scanner_bytes_estimator_tracks_both_stacks() {
        let plain = "x = 1\n";
        let n_plain = estimated_python_scanner_bytes(plain);
        // 2-byte header + 0 delimiter + 0 indent (single line, no block).
        assert_eq!(n_plain, 2);

        let nested = "x = f\"{f\"{1}\"}\"\n";
        let n_nested = estimated_python_scanner_bytes(nested);
        // 2 header + 2 delimiters + 0 indent.
        assert_eq!(n_nested, 4);
    }
}
