//! The versioned JSON contract: a parsed file's views, each under its name.
//!
//! [`ParsedFile::bundle`] serializes the default document — the
//! [`SCHEMA_VERSION`](crate::SCHEMA_VERSION), then every bundled view — and
//! [`ParsedFile::view`] one view on its own. Both serialize straight from the
//! borrowed views, so writing one never builds an intermediate
//! `serde_json::Value` tree.

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};

use crate::{ParsedFile, SymbolKind};

/// One top-level view of a parsed file. [`View::name`] is its key in the
/// bundle.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum View {
    /// [`ParsedFile::fileid`].
    Fileid,
    /// [`ParsedFile::identity`].
    Identity,
    /// [`ParsedFile::values`].
    Values,
    /// [`ParsedFile::text`].
    Text,
    /// [`ParsedFile::literals`].
    Literals,
    /// [`ParsedFile::comments`].
    Comments,
    /// [`ParsedFile::metrics`].
    Metrics,
    /// [`ParsedFile::sections`].
    Sections,
    /// [`ParsedFile::symbols`], every kind.
    Symbols,
    /// The [`ParsedFile::symbols`] of one kind.
    Kind(SymbolKind),
    /// [`ParsedFile::flow`]; `null` when unavailable.
    Flow,
    /// [`ParsedFile::references`].
    References,
    /// [`ParsedFile::archive_members`].
    ArchiveMembers,
    /// [`ParsedFile::errors`].
    Errors,
}

impl View {
    /// Every view, in bundle order.
    pub const ALL: [Self; 20] = [
        Self::Fileid,
        Self::Identity,
        Self::Values,
        Self::Text,
        Self::Literals,
        Self::Comments,
        Self::Metrics,
        Self::Sections,
        Self::Symbols,
        Self::Kind(SymbolKind::Import),
        Self::Kind(SymbolKind::Export),
        Self::Kind(SymbolKind::Function),
        Self::Kind(SymbolKind::Call),
        Self::Kind(SymbolKind::Member),
        Self::Kind(SymbolKind::Bind),
        Self::Kind(SymbolKind::Identifier),
        Self::Flow,
        Self::References,
        Self::ArchiveMembers,
        Self::Errors,
    ];

    /// The view's name: its key in the bundle.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Fileid => "fileid",
            Self::Identity => "identity",
            Self::Values => "values",
            Self::Text => "text",
            Self::Literals => "literals",
            Self::Comments => "comments",
            Self::Metrics => "metrics",
            Self::Sections => "sections",
            Self::Symbols => "symbols",
            Self::Kind(SymbolKind::Import) => "imports",
            Self::Kind(SymbolKind::Export) => "exports",
            Self::Kind(SymbolKind::Function) => "functions",
            Self::Kind(SymbolKind::Call) => "calls",
            Self::Kind(SymbolKind::Member) => "members",
            Self::Kind(SymbolKind::Bind) => "binds",
            Self::Kind(SymbolKind::Identifier) => "identifiers",
            Self::Flow => "flow",
            Self::References => "references",
            Self::ArchiveMembers => "archive_members",
            Self::Errors => "errors",
        }
    }

    /// The view named `name`, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|view| view.name() == name)
    }

    /// One line describing the view.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Fileid => "File identification.",
            Self::Identity => "Normalized identity claims.",
            Self::Values => "Structural values tree.",
            Self::Text => "Byte-scan text runs (ascii / utf16le).",
            Self::Literals => "Parser-extracted string literals.",
            Self::Comments => "Source comment bodies.",
            Self::Metrics => "Derived metrics.",
            Self::Sections => "Binary sections.",
            Self::Symbols => "Every symbol, all kinds.",
            Self::Kind(SymbolKind::Import) => "Import symbols.",
            Self::Kind(SymbolKind::Export) => "Export symbols.",
            Self::Kind(SymbolKind::Function) => "Function symbols.",
            Self::Kind(SymbolKind::Call) => "Call symbols.",
            Self::Kind(SymbolKind::Member) => "Member symbols.",
            Self::Kind(SymbolKind::Bind) => "Bind symbols.",
            Self::Kind(SymbolKind::Identifier) => "Identifier symbols.",
            Self::Flow => "Value relationships, or null when unavailable.",
            Self::References => "Packages, URLs and files the artifact references.",
            Self::ArchiveMembers => "Typed archive member index.",
            Self::Errors => "Recoverable parse errors.",
        }
    }

    /// Whether the bundle carries this view under its own key. A symbol
    /// kind's rows are already in `symbols`; flow is opt-in because building
    /// the graph is work no other view pays for.
    #[must_use]
    pub fn bundled(self) -> bool {
        !matches!(self, Self::Kind(_) | Self::Flow)
    }
}

/// The default document for a parsed file: `schema_version`, then every
/// [bundled](View::bundled) view under its [name](View::name). See
/// [`ParsedFile::bundle`].
#[derive(Debug, Clone, Copy)]
pub struct Bundle<'p, 'a>(&'p ParsedFile<'a>);

impl Serialize for Bundle<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schema_version", crate::SCHEMA_VERSION)?;
        for view in View::ALL.into_iter().filter(|view| view.bundled()) {
            map.serialize_entry(view.name(), &ViewData(self.0, view))?;
        }
        map.end()
    }
}

/// One view of a parsed file, as the bundle carries it. See
/// [`ParsedFile::view`].
#[derive(Debug, Clone, Copy)]
pub struct ViewData<'p, 'a>(&'p ParsedFile<'a>, View);

impl Serialize for ViewData<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let parsed = self.0;
        match self.1 {
            View::Fileid => parsed.fileid().serialize(serializer),
            View::Identity => parsed.identity().serialize(serializer),
            View::Values => parsed.values().serialize(serializer),
            View::Text => parsed.text().serialize(serializer),
            View::Literals => parsed.literals().serialize(serializer),
            View::Comments => parsed.comments().serialize(serializer),
            View::Metrics => parsed.metrics().serialize(serializer),
            View::Sections => parsed.sections().serialize(serializer),
            View::Symbols => parsed.symbols().serialize(serializer),
            View::Kind(kind) => serializer.collect_seq(parsed.symbols().iter_kind(kind)),
            View::Flow => parsed.flow().serialize(serializer),
            View::References => parsed.references().serialize(serializer),
            View::ArchiveMembers => parsed.archive_members().serialize(serializer),
            View::Errors => parsed.errors().serialize(serializer),
        }
    }
}

impl<'a> ParsedFile<'a> {
    /// The file's default JSON document, ready to serialize: the schema
    /// version, then every bundled view under its name.
    ///
    /// ```
    /// let parsed = filefacts::open(b"print('hi')\n");
    /// let json = serde_json::to_value(parsed.bundle()).unwrap();
    /// assert_eq!(json["schema_version"], filefacts::SCHEMA_VERSION);
    /// assert!(json["metrics"].is_object());
    /// ```
    #[must_use]
    pub fn bundle(&self) -> Bundle<'_, 'a> {
        Bundle(self)
    }

    /// One view of the file, ready to serialize exactly as
    /// [`Self::bundle`] carries it.
    #[must_use]
    pub fn view(&self, view: View) -> ViewData<'_, 'a> {
        ViewData(self, view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_view_has_a_unique_name_that_round_trips() {
        let mut names = BTreeSet::new();
        for view in View::ALL {
            assert!(names.insert(view.name()), "{} is listed twice", view.name());
            assert_eq!(View::from_name(view.name()), Some(view));
            assert!(!view.description().is_empty());
        }
        assert_eq!(View::from_name("strings"), None);
    }

    #[test]
    fn bundle_carries_every_bundled_view_and_nothing_else() {
        let parsed = hermetic(
            "example.py",
            b"import os  # fetch\nos.system('curl http://example.invalid/x')\n",
        );
        let bundle = serde_json::to_value(parsed.bundle()).unwrap();
        let keys: BTreeSet<&str> = bundle
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<&str> = std::iter::once("schema_version")
            .chain(
                View::ALL
                    .into_iter()
                    .filter(|v| v.bundled())
                    .map(View::name),
            )
            .collect();
        assert_eq!(keys, expected);
        for view in View::ALL {
            let alone = serde_json::to_value(parsed.view(view)).unwrap();
            match view {
                _ if view.bundled() => assert_eq!(bundle[view.name()], alone, "{view:?}"),
                // A kind's rows are the matching rows of `symbols`.
                View::Kind(_) => {
                    let symbols = bundle["symbols"].as_array().unwrap();
                    assert!(
                        alone
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|r| symbols.contains(r))
                    );
                }
                View::Flow => assert!(alone.is_object()),
                _ => panic!("{view:?} is neither bundled nor covered"),
            }
        }
        assert_eq!(parsed.parse_count(), 1);
    }

    fn hermetic<'a>(path: &str, bytes: &'a [u8]) -> ParsedFile<'a> {
        crate::OpenOptions::new()
            .cache(false)
            .rizin(false)
            .path(std::path::Path::new(path))
            .open(bytes)
    }

    #[test]
    fn flow_is_a_format_neutral_view() {
        let parsed = hermetic("example.py", b"send(acquire())\n");
        let value = serde_json::to_value(parsed.view(View::Flow)).unwrap();
        assert_eq!(value["producer"], "tree-sitter");
        assert_eq!(value["language"], "python");
        assert!(value["values"].as_array().is_some());
        assert_eq!(parsed.parse_count(), 1);
    }

    #[test]
    fn unavailable_binary_flow_is_null_not_an_empty_graph() {
        let parsed = hermetic("example.elf", include_bytes!("../tests/fixtures/test.elf"));
        assert!(parsed.flow().is_none());
        let value = serde_json::to_value(parsed.view(View::Flow)).unwrap();
        assert!(value.is_null());
    }
}
