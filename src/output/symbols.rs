//! Imports, exports, and locally-defined functions — three peer
//! collections that every format extractor contributes to.
//!
//! Each binary / source format has its own native vocabulary for these
//! concepts:
//!
//! - **PE** has an import table (DLL + symbol), an export table
//!   (symbol + ordinal + RVA), bound imports, and delay-load imports.
//! - **ELF** has `.dynsym` entries (undefined → import, defined →
//!   export) and `DT_NEEDED` library references.
//! - **Mach-O** has undefined/defined symbols and dyld trie exports.
//! - **Java class** files reference other classes via the constant
//!   pool and declare methods locally.
//! - **VBA** uses `Declare … Function … Lib "kernel32"` for foreign-
//!   library imports and `CreateObject("Excel.Application")` for
//!   COM-style imports; `Public Function`/`Sub` declarations are
//!   locally-defined functions.
//! - **Source code** (tree-sitter languages) carries the same idea
//!   via `import` / `require` statements and top-level definitions.
//!
//! Rather than collapsing these into a single union type, expose
//! keeps three typed collections — [`Imports`], [`Exports`],
//! [`Functions`] — each with the fields its concept actually carries.
//! When a single fact appears in two categories (e.g. a VBA `Declare`
//! is both a local function and a foreign-library import), the
//! extractor emits one entry per category so consumers don't have to
//! handle multi-category records.
//!
//! Cross-cutting "match this name regardless of kind" queries walk
//! all three via [`ParsedFile::find_symbol`](crate::ParsedFile)
//! rather than forcing every consumer to switch on a discriminator.

use serde::Serialize;

/// A foreign-symbol reference — something this file *uses* that is
/// defined elsewhere.
///
/// Examples by `source`:
/// - `"pe"` — entry from the PE import table.
/// - `"pe-bound"` / `"pe-delay"` — same table family, different
///   binding strategies.
/// - `"elf-dynsym"` — undefined symbol in `.dynsym`.
/// - `"macho"` — undefined symbol in `LC_DYSYMTAB`.
/// - `"vba-declare"` — VBA `Declare … Function NAME Lib "LIB"`.
/// - `"vba-createobject"` / `"vba-getobject"` — COM-style ProgID
///   imports; `library` is `"com"` / `"com-getobject"`.
/// - `"java-class"` — constant-pool CONSTANT_Class_info reference.
/// - `"js-require"`, `"py-import"`, … — source-language imports.
#[derive(Debug, Clone, Serialize)]
pub struct Import {
    /// Symbol name in the form the format records it (no
    /// demangling, no path normalization). For VBA Declares with an
    /// `Alias` clause, this is the alias (i.e. the exported name in
    /// the DLL), not the local VBA-side name.
    pub name: String,
    /// Library / module / pseudo-namespace the symbol is bound to,
    /// when the format records one. PE: the DLL stem ("kernel32",
    /// case-normalised to lowercase, without `.dll`). ELF:
    /// `DT_NEEDED` library when resolvable, otherwise `None`. VBA:
    /// the Lib-clause stem, or `"com"` / `"com-getobject"` for COM
    /// imports, or the sentinel `"<non-literal>"` when the Lib
    /// argument is a runtime expression rather than a string literal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// Short tag identifying the format and extraction subkind. See
    /// module-level docs for the canonical taxonomy.
    pub source: &'static str,
    /// Byte offset within the source file where this import was
    /// declared. Optional because some formats (notably ELF dynsym)
    /// don't expose a useful offset for the import-table entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// PE ordinal-only imports / dyld trie ordinals when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
}

/// A locally-defined symbol that this file makes visible to other
/// code. Distinct from a locally-defined function (which may not be
/// exported); see [`Function`].
#[derive(Debug, Clone, Serialize)]
pub struct Export {
    /// Symbol name as recorded by the format.
    pub name: String,
    /// Format / extraction-subkind tag. See module-level docs.
    pub source: &'static str,
    /// Offset within the source file (for binary formats, the RVA
    /// of the exported entry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// PE ordinal slot, dyld trie ordinal, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
}

/// A function / method / subroutine defined inside this file. Local
/// declarations regardless of export status — a PE export entry
/// pointing at function `foo` will surface as both an [`Export`]
/// (with ordinal / RVA from the export table) and a `Function`
/// (with the entry address). VBA `Public Sub` similarly surfaces in
/// both.
#[derive(Debug, Clone, Serialize)]
pub struct Function {
    /// Function name. Empty when the format records the entry by
    /// address only (rare).
    pub name: String,
    /// Format / extraction-subkind tag.
    pub source: &'static str,
    /// Entry-point offset within the source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Optional language-level kind tag — `"method"`, `"sub"`,
    /// `"function"`, `"constructor"`, `"initializer"`. `None` when
    /// the format doesn't distinguish (e.g. PE function entries
    /// from the export table).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
}

/// All [`Import`] entries the parsers found, in the order each
/// format emits them.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Imports(Vec<Import>);

/// All [`Export`] entries the parsers found.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Exports(Vec<Export>);

/// All [`Function`] entries the parsers found.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Functions(Vec<Function>);

impl Imports {
    /// Construct an empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, import: Import) {
        self.0.push(import);
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[Import] {
        &self.0
    }
    /// Iterate every recorded import.
    pub fn iter(&self) -> std::slice::Iter<'_, Import> {
        self.0.iter()
    }
    /// Number of imports recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when no imports were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Exports {
    /// Construct an empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, export: Export) {
        self.0.push(export);
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[Export] {
        &self.0
    }
    /// Iterate every recorded export.
    pub fn iter(&self) -> std::slice::Iter<'_, Export> {
        self.0.iter()
    }
    /// Number of exports recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when no exports were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Functions {
    /// Construct an empty collection.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, function: Function) {
        self.0.push(function);
    }
    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[Function] {
        &self.0
    }
    /// Iterate every recorded function.
    pub fn iter(&self) -> std::slice::Iter<'_, Function> {
        self.0.iter()
    }
    /// Number of functions recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when no functions were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Imports {
    type Item = &'a Import;
    type IntoIter = std::slice::Iter<'a, Import>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a Exports {
    type Item = &'a Export;
    type IntoIter = std::slice::Iter<'a, Export>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a Functions {
    type Item = &'a Function;
    type IntoIter = std::slice::Iter<'a, Function>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_push_and_iterate() {
        let mut imports = Imports::new();
        imports.push(Import {
            name: "CreateFileW".into(),
            library: Some("kernel32".into()),
            source: "pe",
            offset: Some(0x1234),
            ordinal: None,
        });
        imports.push(Import {
            name: "URLDownloadToFileA".into(),
            library: Some("urlmon".into()),
            source: "vba-declare",
            offset: Some(42),
            ordinal: None,
        });
        assert_eq!(imports.len(), 2);
        let names: Vec<&str> = imports.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["CreateFileW", "URLDownloadToFileA"]);
        // Source taxonomy distinguishes the binary and the VBA entry.
        let sources: Vec<&str> = imports.iter().map(|i| i.source).collect();
        assert_eq!(sources, vec!["pe", "vba-declare"]);
    }

    #[test]
    fn exports_serialize_omits_optional_fields() {
        let mut exports = Exports::new();
        exports.push(Export {
            name: "DllMain".into(),
            source: "pe",
            offset: Some(0x1000),
            ordinal: Some(1),
        });
        exports.push(Export {
            name: "_init".into(),
            source: "elf-dynsym",
            offset: None,
            ordinal: None,
        });
        let json = serde_json::to_value(&exports).unwrap();
        // First entry has every field; second elides optionals.
        let arr = json.as_array().unwrap();
        assert!(arr[0].as_object().unwrap().contains_key("ordinal"));
        assert!(!arr[1].as_object().unwrap().contains_key("ordinal"));
        assert!(!arr[1].as_object().unwrap().contains_key("offset"));
    }

    #[test]
    fn functions_kind_optional() {
        let mut funcs = Functions::new();
        funcs.push(Function {
            name: "Auto_Open".into(),
            source: "vba-public-sub",
            offset: Some(100),
            kind: Some("sub"),
        });
        funcs.push(Function {
            name: "sub_401000".into(),
            source: "pe",
            offset: Some(0x401000),
            kind: None,
        });
        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs.iter().next().unwrap().kind, Some("sub"));
        assert_eq!(funcs.iter().nth(1).unwrap().kind, None);
    }

    #[test]
    fn collections_round_trip_through_serde() {
        let mut imports = Imports::new();
        imports.push(Import {
            name: "Foo".into(),
            library: Some("bar".into()),
            source: "pe",
            offset: None,
            ordinal: None,
        });
        let json = serde_json::to_string(&imports).unwrap();
        // `#[serde(transparent)]` means the collection serializes as
        // a bare JSON array, not `{ "0": [...] }`.
        assert!(json.starts_with('['));
        assert!(json.contains("\"name\":\"Foo\""));
    }
}
