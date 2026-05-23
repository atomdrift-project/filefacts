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
        let language = (config.language)();
        THREAD_PARSER.with(|cell| {
            let mut parser = cell.borrow_mut();
            parser.set_language(&language).map_err(|e| {
                Error::malformed("source", format!("tree-sitter language setup failed: {e}"))
            })?;
            let tree = parser.parse(source, None).ok_or_else(|| {
                Error::malformed("source", "tree-sitter parse returned None")
            })?;
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
