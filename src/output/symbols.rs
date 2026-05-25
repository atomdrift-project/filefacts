//! Unified symbol facts — every named entity in the artifact, tagged
//! by kind, in one flat collection.
//!
//! Each [`Symbol`] is one fact about a name in the parsed file:
//!
//! - `Import` — foreign symbol this file uses (PE import table, ELF
//!   dynsym undef, Mach-O undef, VBA `Declare`/`CreateObject`, Java
//!   class refs, source-level `import` / `require`).
//! - `Export` — locally-defined symbol this file publishes.
//! - `Function` — function / method / sub defined inside this file;
//!   carries CFG metrics (`complexity`, `basic_blocks`, `callees`, …)
//!   when rizin disassembled it.
//! - `Call` — one source-code call site with target + arg shapes.
//! - `Member` — one dotted member-access chain observed in source.
//! - `Bind` — one static name = value binding observed in source.
//! - `Identifier` — one bare-identifier appearance.
//!
//! Same family for source and binary; which kinds populate depends on
//! the file. JSON shape is flat: `{"kind": "import", ...payload}`.

use serde::{Deserialize, Serialize};

/// Shape category for a call/bind argument.
///
/// The set is closed and intentionally small — distinguishing "what
/// kind of thing is this argument" supports every rule query that
/// doesn't need the literal value; the literal-value case is served by
/// [`Symbol::Call`]`::args`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ArgShape {
    /// String literal (after un-quoting).
    String,
    /// Numeric literal.
    Number,
    /// Boolean literal.
    Bool,
    /// Null / nil / None literal.
    Null,
    /// Bare identifier reference.
    Identifier,
    /// Object / map / dict / struct literal.
    Object,
    /// Array / list / slice literal.
    Array,
    /// Function / lambda / closure literal (anonymous callable).
    Function,
    /// Template / formatted / interpolated string.
    Template,
    /// Result of another call expression.
    Call,
    /// Any expression that doesn't fit one of the above.
    Expression,
}

/// One positional argument at a call site. Tagged enum: each variant
/// carries exactly the data meaningful for its shape, so authors of
/// `type: symbol, kind: call, arg: …` rules can match on the
/// literal value directly without going through offset correlation
/// against the top-level `literals` collection.
///
/// JSON shape: `{"shape": "<lower>", ...payload}` — the value-carrying
/// variants (String, Number, Identifier, Bool, Template) have their
/// own fields; the rest (Object, Array, Function, Null, Call,
/// Expression) carry only the shape tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "lowercase")]
#[non_exhaustive]
pub enum Arg {
    /// String literal — value is the un-quoted text.
    String {
        /// Un-quoted text content.
        value: String,
    },
    /// Numeric literal — `text` is the source-written form
    /// (`"0o777"`, `"0xDEADBEEF"`, `"4444"`); `value` is the parsed
    /// integer; `radix` is how it was written (2/8/10/16). Authors
    /// distinguish `0o777` from decimal `511` via `radix`.
    Number {
        /// Source-written form (carries the prefix/separators).
        text: String,
        /// Parsed integer value.
        value: i64,
        /// Source-written radix: 2 / 8 / 10 / 16.
        radix: u32,
    },
    /// Bare identifier — value is the identifier name.
    Identifier {
        /// Identifier name.
        name: String,
    },
    /// Boolean literal — value is the parsed bool.
    Bool {
        /// Parsed boolean value.
        value: bool,
    },
    /// Template / formatted / interpolated string — value is the
    /// source text including the formatting markers (best-effort).
    Template {
        /// Source text including formatting markers (best-effort).
        value: String,
    },
    /// Null / nil / None literal.
    Null,
    /// Object / map / dict / struct literal.
    Object,
    /// Array / list / slice literal.
    Array,
    /// Function / lambda / closure literal (anonymous callable).
    Function,
    /// Result of another call expression.
    Call,
    /// Any expression that doesn't fit one of the above (computed
    /// value, parenthesised sub-expression with non-trivial shape,
    /// member access result, …).
    Expression,
}

/// One named-entity fact about a parsed artifact.
///
/// Serializes as `{"kind": "<lower_snake>", ...payload}` via
/// `#[serde(tag = "kind")]`. Each variant carries the fields that apply
/// to its kind; unused fields are elided from JSON via
/// `skip_serializing_if`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Symbol {
    /// Foreign-symbol reference — something this file *uses* that is
    /// defined elsewhere.
    Import {
        /// Symbol name in the form the format records it (no demangling,
        /// no path normalization). For VBA `Declare` with an `Alias`
        /// clause, this is the alias.
        name: String,
        /// Library / module / pseudo-namespace the symbol is bound to,
        /// when the format records one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        library: Option<String>,
        /// Short tag identifying the format and extraction subkind.
        /// Examples: `"pe"`, `"pe-bound"`, `"pe-delay"`, `"elf-dynsym"`,
        /// `"macho"`, `"vba-declare"`, `"vba-createobject"`,
        /// `"java-class"`, `"js-require"`, `"py-import"`.
        source: String,
        /// Byte offset within the source file where this import was
        /// declared. Optional because some formats (notably ELF dynsym)
        /// don't expose a useful offset for the import-table entry.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
        /// PE ordinal-only imports / dyld trie ordinals when relevant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ordinal: Option<u32>,
    },

    /// Locally-defined symbol that this file makes visible to other code.
    Export {
        /// Symbol name as recorded by the format.
        name: String,
        /// Format / extraction-subkind tag.
        source: String,
        /// Offset within the source file (for binary formats, the RVA
        /// of the exported entry).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
        /// PE ordinal slot, dyld trie ordinal, etc.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ordinal: Option<u32>,
        /// Forwarded re-export target, when this entry is a forward
        /// rather than a locally-defined symbol. PE example:
        /// `"KERNEL32.LoadLibraryA"` or `"NTDLL.#123"`. `None` for
        /// normal exports whose RVA points at the binary's own code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        forward_to: Option<String>,
    },

    /// Function / method / subroutine defined inside this file.
    ///
    /// CFG fields (`complexity`, `basic_blocks`, `edges`, `instructions`,
    /// `stack_frame`, `recursive`, `noreturn`, `is_linear`, `callees`)
    /// are populated when rizin's `aflj` analysis ran. They are absent
    /// for entries sourced from symbol tables alone (PE imports, ELF
    /// `.dynsym`, VBA declarations, etc.).
    Function {
        /// Function name. Empty when the format records by address only.
        name: String,
        /// Format / extraction-subkind tag.
        source: String,
        /// Entry-point offset within the source file.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
        /// Language-level declaration shape — `"method"`, `"sub"`,
        /// `"function"`, `"constructor"`, `"initializer"`, `"class"`.
        /// Renamed from the prior `kind` field to avoid collision with
        /// the [`Symbol`] discriminator.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decl: Option<String>,
        /// Cyclomatic complexity (McCabe).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        complexity: Option<u32>,
        /// Number of basic blocks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        basic_blocks: Option<u32>,
        /// Number of control-flow edges between basic blocks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edges: Option<u32>,
        /// Total instruction count.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        instructions: Option<u32>,
        /// Stack frame size in bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stack_frame: Option<u64>,
        /// `true` iff the function calls itself directly.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recursive: Option<bool>,
        /// `true` iff the function never returns.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        noreturn: Option<bool>,
        /// `true` iff the function has no branches (straight-line code).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_linear: Option<bool>,
        /// Names of resolved outgoing call edges (rizin). Renamed from
        /// the prior `calls` field to disambiguate from the top-level
        /// [`Symbol::Call`] kind.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        callees: Vec<String>,
    },

    /// One observed call site in source order.
    ///
    /// `target` is the dotted-static path resolved from the callee chain
    /// — `"fetch"`, `"chrome.cookies.getAll"`. `None` when the callee is
    /// computed (`obj[varName]()`, an anonymous function call, a method
    /// on a call result, …).
    ///
    /// `args` carries only the *shape* of each argument in call order.
    /// Literal values live canonically in the top-level `literals`
    /// collection; rules that need to match arg content compose by
    /// offset window (a literal whose offset falls inside the call's
    /// extent).
    Call {
        /// Static dotted path to the function being called, or `None`
        /// for dynamic targets.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        /// Per-position arguments in call order. Each [`Arg`] carries
        /// its shape plus the literal value when the shape is a
        /// literal kind (String, Number, Identifier, Bool, Template).
        /// Authors match on arg content via `arg: { kind: ..., value:
        /// ... }` in rules without needing offset correlation against
        /// the top-level `literals` collection.
        #[serde(default)]
        args: Vec<Arg>,
        /// Source / extraction-subkind tag (typically the language name
        /// for source files).
        source: String,
        /// Byte offset of the call expression's start, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
    },

    /// One dotted member-access chain observed in source code, *in any
    /// position* — called or not, read or written.
    Member {
        /// Dotted chain like `chrome.cookies.getAll` or
        /// `window.localStorage`.
        path: String,
        /// Source / extraction-subkind tag.
        source: String,
    },

    /// One static assignment/binding observed in source code.
    ///
    /// Carries the assignment target, its shape, and its lexical scope.
    /// Literal values live canonically in the top-level `literals`
    /// collection and correlate to this bind by offset window — same
    /// pattern as [`Self::Call`] args.
    Bind {
        /// Static identifier/member path being assigned: `API_URL`,
        /// `self.path`, `exports.token`.
        target: String,
        /// Lexical scope for the assignment: `"module"`, `"class"`, or
        /// `"function"`.
        scope: String,
        /// Shape of the assigned expression.
        shape: ArgShape,
        /// Source / extraction-subkind tag.
        source: String,
        /// Byte offset where the assignment target starts.
        offset: u64,
    },

    /// One bare-identifier appearance — variable name, function name,
    /// type name, macro name. Captures naming-pattern signals
    /// (`c2_server`, `BackdoorListener`) that don't appear in any other
    /// kind.
    Identifier {
        /// The identifier text.
        name: String,
        /// Source / extraction-subkind tag.
        source: String,
        /// Byte offset of the identifier, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
    },
}

/// Discriminator tag for filtering [`Symbols`] without matching on the
/// full enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// [`Symbol::Import`].
    Import,
    /// [`Symbol::Export`].
    Export,
    /// [`Symbol::Function`].
    Function,
    /// [`Symbol::Call`].
    Call,
    /// [`Symbol::Member`].
    Member,
    /// [`Symbol::Bind`].
    Bind,
    /// [`Symbol::Identifier`].
    Identifier,
}

impl Symbol {
    /// The discriminator tag for this symbol.
    pub fn kind(&self) -> SymbolKind {
        match self {
            Self::Import { .. } => SymbolKind::Import,
            Self::Export { .. } => SymbolKind::Export,
            Self::Function { .. } => SymbolKind::Function,
            Self::Call { .. } => SymbolKind::Call,
            Self::Member { .. } => SymbolKind::Member,
            Self::Bind { .. } => SymbolKind::Bind,
            Self::Identifier { .. } => SymbolKind::Identifier,
        }
    }

    /// Primary identifying name for this symbol, when one applies.
    /// Returns the dotted target for [`Self::Call`], the chain for
    /// [`Self::Member`], the assignment target for [`Self::Bind`], or
    /// the `name` field for the rest. `None` for dynamic call targets.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Import { name, .. }
            | Self::Export { name, .. }
            | Self::Function { name, .. }
            | Self::Identifier { name, .. } => Some(name.as_str()),
            Self::Call { target, .. } => target.as_deref(),
            Self::Member { path, .. } => Some(path.as_str()),
            Self::Bind { target, .. } => Some(target.as_str()),
        }
    }

    /// The extraction-subkind tag.
    pub fn source(&self) -> &str {
        match self {
            Self::Import { source, .. }
            | Self::Export { source, .. }
            | Self::Function { source, .. }
            | Self::Call { source, .. }
            | Self::Member { source, .. }
            | Self::Bind { source, .. }
            | Self::Identifier { source, .. } => source.as_str(),
        }
    }
}

/// All [`Symbol`] facts collected from a file, in extraction order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Symbols(Vec<Symbol>);

impl Symbols {
    /// Construct an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, symbol: Symbol) {
        self.0.push(symbol);
    }

    /// Borrow the underlying slice.
    pub fn as_slice(&self) -> &[Symbol] {
        &self.0
    }

    /// Iterate every recorded symbol.
    pub fn iter(&self) -> std::slice::Iter<'_, Symbol> {
        self.0.iter()
    }

    /// Iterate symbols of a specific kind (filtered view).
    pub fn iter_kind(&self, want: SymbolKind) -> impl Iterator<Item = &Symbol> {
        self.0.iter().filter(move |s| s.kind() == want)
    }

    /// Number of symbols recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no symbols were recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Symbols {
    type Item = &'a Symbol;
    type IntoIter = std::slice::Iter<'a, Symbol>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn symbol_kind_discriminator_round_trips_through_serde() {
        let s = Symbol::Import {
            name: "CreateFileW".into(),
            library: Some("kernel32".into()),
            source: "pe".into(),
            offset: Some(0x1234),
            ordinal: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"kind\":\"import\""));
        let back: Symbol = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind(), SymbolKind::Import);
        assert_eq!(back.name(), Some("CreateFileW"));
        assert_eq!(back.source(), "pe");
    }

    #[test]
    fn function_cfg_fields_round_trip() {
        let s = Symbol::Function {
            name: "_get_cpuid".into(),
            source: "rizin".into(),
            offset: Some(0x4080),
            decl: None,
            complexity: Some(7),
            basic_blocks: Some(12),
            edges: Some(18),
            instructions: Some(83),
            stack_frame: Some(48),
            recursive: Some(false),
            noreturn: Some(false),
            is_linear: Some(false),
            callees: vec!["_resolve".into(), "_lzma_crc32".into()],
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "function");
        assert_eq!(json["complexity"], 7);
        assert_eq!(json["callees"][0], "_resolve");
        let back: Symbol = serde_json::from_value(json).unwrap();
        if let Symbol::Function { callees, .. } = back {
            assert_eq!(callees, vec!["_resolve", "_lzma_crc32"]);
        } else {
            panic!("expected Function variant");
        }
    }

    #[test]
    fn function_optional_fields_elide_from_json() {
        let s = Symbol::Function {
            name: "CreateFileW".into(),
            source: "pe-import".into(),
            offset: Some(0x1000),
            decl: None,
            complexity: None,
            basic_blocks: None,
            edges: None,
            instructions: None,
            stack_frame: None,
            recursive: None,
            noreturn: None,
            is_linear: None,
            callees: Vec::new(),
        };
        let json = serde_json::to_value(&s).unwrap();
        let obj = json.as_object().unwrap();
        for key in [
            "decl",
            "complexity",
            "basic_blocks",
            "edges",
            "instructions",
            "stack_frame",
            "recursive",
            "noreturn",
            "is_linear",
            "callees",
        ] {
            assert!(!obj.contains_key(key), "expected {key} elided when absent");
        }
    }

    #[test]
    fn call_record_round_trips() {
        let s = Symbol::Call {
            target: Some("fetch".into()),
            args: vec![Arg::String {
                value: "https://example.com".into(),
            }],
            source: "javascript".into(),
            offset: Some(42),
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["kind"], "call");
        assert_eq!(json["target"], "fetch");
        assert_eq!(json["args"][0]["shape"], "string");
        assert_eq!(json["args"][0]["value"], "https://example.com");
        let back: Symbol = serde_json::from_value(json).unwrap();
        assert_eq!(back.name(), Some("fetch"));
    }

    #[test]
    fn dynamic_call_serializes_without_target() {
        let s = Symbol::Call {
            target: None,
            args: vec![Arg::Identifier {
                name: "callback".into(),
            }],
            source: "javascript".into(),
            offset: None,
        };
        let json = serde_json::to_value(&s).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("target"));
    }

    #[test]
    fn numeric_arg_carries_text_value_and_radix() {
        // chmod(file, 0o777) — the canonical example. Verifies the
        // Number variant serializes with all three fields so authors
        // can match on parsed value + source-written radix.
        let s = Symbol::Call {
            target: Some("chmod".into()),
            args: vec![
                Arg::String {
                    value: "/tmp/x".into(),
                },
                Arg::Number {
                    text: "0o777".into(),
                    value: 511,
                    radix: 8,
                },
            ],
            source: "python".into(),
            offset: Some(0),
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["args"][1]["shape"], "number");
        assert_eq!(json["args"][1]["text"], "0o777");
        assert_eq!(json["args"][1]["value"], 511);
        assert_eq!(json["args"][1]["radix"], 8);
        let back: Symbol = serde_json::from_value(json).unwrap();
        let Symbol::Call { args, .. } = back else {
            panic!("expected Call");
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0], Arg::String { ref value } if value == "/tmp/x"));
        assert!(matches!(
            args[1],
            Arg::Number {
                value: 511,
                radix: 8,
                ..
            }
        ));
    }

    #[test]
    fn collection_is_transparent_array() {
        let mut syms = Symbols::new();
        syms.push(Symbol::Import {
            name: "Foo".into(),
            library: Some("bar".into()),
            source: "pe".into(),
            offset: None,
            ordinal: None,
        });
        let json = serde_json::to_string(&syms).unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains("\"kind\":\"import\""));
    }

    #[test]
    fn iter_kind_filters() {
        let mut syms = Symbols::new();
        syms.push(Symbol::Import {
            name: "Foo".into(),
            library: None,
            source: "pe".into(),
            offset: None,
            ordinal: None,
        });
        syms.push(Symbol::Export {
            name: "Bar".into(),
            source: "pe".into(),
            offset: None,
            ordinal: None,
            forward_to: None,
        });
        syms.push(Symbol::Import {
            name: "Baz".into(),
            library: None,
            source: "pe".into(),
            offset: None,
            ordinal: None,
        });
        let imports: Vec<&str> = syms
            .iter_kind(SymbolKind::Import)
            .map(|s| s.name().unwrap())
            .collect();
        assert_eq!(imports, vec!["Foo", "Baz"]);
    }
}
