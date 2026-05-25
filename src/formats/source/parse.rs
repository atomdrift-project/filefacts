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

/// Python's external scanner stores the indent stack roughly two bytes
/// per level. 450 levels leaves headroom below the 1024-byte buffer.
const MAX_SAFE_PYTHON_INDENT_STACK_DEPTH: usize = 450;

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
        && estimated_python_indent_stack_depth(source) > MAX_SAFE_PYTHON_INDENT_STACK_DEPTH
    {
        return true;
    }
    false
}

/// Worst-case depth of Python's indent stack — what the tree-sitter
/// external scanner serializes. Computed without parsing so it stays
/// cheap on hostile input.
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
        let mut source = String::new();
        for depth in 0..=MAX_SAFE_PYTHON_INDENT_STACK_DEPTH + 8 {
            source.push_str(&" ".repeat(depth * 2));
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
    fn deep_indentation_ignored_for_non_python() {
        let mut source = String::new();
        for depth in 0..=MAX_SAFE_PYTHON_INDENT_STACK_DEPTH + 8 {
            source.push_str(&" ".repeat(depth * 2));
            source.push_str("echo hi\n");
        }
        assert!(!would_overflow_scanner_state(FileType::Shell, &source));
    }
}
