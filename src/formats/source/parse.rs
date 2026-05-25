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
            return Ok(None);
        }
        let language = (config.language)();
        THREAD_PARSER.with(|cell| {
            let mut parser = cell.borrow_mut();
            parser.set_language(&language).map_err(|e| {
                Error::malformed("source", format!("tree-sitter language setup failed: {e}"))
            })?;
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
    if source.len() > MAX_AST_FILE_BYTES {
        return true;
    }
    if matches!(file_type, FileType::Python)
        && estimated_python_scanner_bytes(source) > PYTHON_SCANNER_BUDGET_BYTES
    {
        return true;
    }
    false
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
