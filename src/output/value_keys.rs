//! The value-key catalog: the [`Values`](super::Values) paths that are checked
//! at compile time.
//!
//! Format extractors write `values`, and several passes read them back by
//! path: identity folds the scattered per-format fields into one view,
//! references turns manifest fields into fetchable coordinates, and some
//! extractors consult what an earlier stage emitted. With a plain string on
//! both sides, renaming a key on either side still compiles and silently
//! empties the consumer.
//!
//! [`value_key!`](crate::value_key) closes that gap the way
//! [`metric!`](crate::metric) does for metrics. It resolves a literal against
//! [`VALUE_CATALOG`] at compile time. Writers
//! ([`Values::insert_key`](super::Values::insert_key)) and readers
//! ([`Values::get_key`](super::Values::get_key)) both take the resulting
//! [`ValueKey`], so both sides are checked against the same list. A key that
//! is not declared below is a build failure at the call site.
//!
//! The catalog does not yet cover the whole `values` surface. It holds every
//! key that is read outside the module that writes it, plus the write-only
//! keys that share a typed table with one. Other write-only keys still use
//! plain strings.
//!
//! When a key's tail is data, such as an array index or a manifest field name,
//! the fixed base is cataloged, and the call site supplies the rest through
//! [`Values::get_key_at`](super::Values::get_key_at) or
//! [`Values::insert_key_at`](super::Values::insert_key_at).

use serde_json::Value as JsonValue;

use super::metric_keys::str_eq;

/// A [`Values`](super::Values) path that is known to be declared in
/// [`VALUE_CATALOG`].
///
/// The inner string is private, and outside this module the only constructor
/// is [`value_key!`](crate::value_key), so holding a `ValueKey` means the path
/// was checked at compile time. It wraps a `&'static str`, so it is `Copy` and
/// APIs take it by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueKey(&'static str);

impl ValueKey {
    /// The path as it appears in the values tree and in trait rules.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Look this key up in a JSON tree shaped like [`Values`](super::Values),
    /// using the same dot-path rules as [`Values::get`](super::Values::get).
    ///
    /// This is for a values object that has already been serialized into
    /// another fact, where there is no `Values` to call
    /// [`get_key`](super::Values::get_key) on.
    #[must_use]
    pub fn get_in(self, root: &JsonValue) -> Option<&JsonValue> {
        super::values::navigate(root, self.0)
    }
}

impl AsRef<str> for ValueKey {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl std::fmt::Display for ValueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Resolve a literal against [`VALUE_CATALOG`], or fail the build.
///
/// This is an implementation detail of [`value_key!`](crate::value_key). It is
/// public only because an exported macro can only call public items, and it
/// is not part of the supported API. `value_key!` evaluates it in a `const`
/// context, which turns an undeclared key into a compile error. Calling it
/// directly from runtime code would move that panic to runtime and lose the
/// check.
///
/// # Panics
///
/// If `name` is not in [`VALUE_CATALOG`]. Through `value_key!` this is a
/// `const` evaluation failure, reported as a build error at the offending call
/// site. That is the only way this panic is expected to happen.
#[doc(hidden)]
#[must_use]
pub const fn declared_value_key(name: &'static str) -> ValueKey {
    let mut rest = VALUE_CATALOG;
    while let [key, tail @ ..] = rest {
        if str_eq(key, name) {
            return ValueKey(name);
        }
        rest = tail;
    }
    panic!("undeclared value key: add it to VALUE_CATALOG in src/output/value_keys.rs");
}

/// Build a checked [`ValueKey`] from a literal.
///
/// ```ignore
/// values.insert_key(value_key!("pe.signatures"), signatures);
/// let first = values.get_key_at(value_key!("pe.signatures"), "[0]");
/// ```
///
/// The literal must appear in [`VALUE_CATALOG`]. If it does not, the call
/// site fails to compile.
#[macro_export]
macro_rules! value_key {
    ($name:literal) => {{
        const KEY: $crate::ValueKey = $crate::declared_value_key($name);
        KEY
    }};
}

/// Every checked value key, sorted.
///
/// Keep it sorted, with one key per line: this list is read as a diff far more
/// often than it is read as a list. Each key must be written through
/// [`value_key!`](crate::value_key) somewhere outside a test; a unit test
/// enforces that, so a key whose last writer goes away cannot stay here and
/// keep its readers compiling against nothing.
pub const VALUE_CATALOG: &[&str] = &[
    "android.allow_backup",
    "android.app_class",
    "android.app_label",
    "android.cleartext_traffic",
    "android.compile_sdk",
    "android.debuggable",
    "android.install_location",
    "android.network_security_config",
    "android.package",
    "android.shared_user_id",
    "android.signatures",
    "android.version_code",
    "android.version_name",
    "apk.arch",
    "apk.builddate",
    "apk.builder",
    "apk.commit",
    "apk.datahash",
    "apk.license",
    "apk.maintainer",
    "apk.origin",
    "apk.packager",
    "apk.pkgdesc",
    "apk.pkgname",
    "apk.pkgver",
    "apk.url",
    "archive.builder.gnames",
    "archive.builder.unames",
    "cab.signatures",
    "cargo.build_mode",
    "crate.authors",
    "crate.description",
    "crate.homepage",
    "crate.name",
    "crate.repository",
    "crate.version",
    "crx.author",
    "crx.author_email",
    "crx.description",
    "crx.extension_id",
    "crx.homepage_url",
    "crx.public_key_sha256",
    "deb.maintainer",
    "deb.package",
    "deb.summary",
    "deb.version",
    "dmg.volume.formatted_by",
    "dmg.volume.name",
    "elf.comment",
    "elf.dwarf.comp_dirs",
    "elf.dwarf.producers",
    "elf.go",
    "file.basename",
    "gem.authors",
    "gem.homepage",
    "gem.name",
    "gem.runtime_dependencies",
    "gem.summary",
    "gem.version",
    "go_manifest.kind",
    "iso.abstract_file",
    "iso.application_id",
    "iso.bibliographic_file",
    "iso.builder",
    "iso.copyright_file",
    "iso.preparer_id",
    "iso.publisher_id",
    "iso.system_id",
    "iso.udf.implementation_id",
    "iso.udf.logical_volume_id",
    "iso.udf.volume_set_id",
    "iso.volume_id",
    "iso.volume_set_id",
    "jar.manifest",
    "jar.pom",
    "lnk.tracker",
    "lnk.volume",
    "macho.build_version",
    "macho.code_signature.cdhash",
    "macho.code_signature.cms",
    "macho.code_signature.entitlements",
    "macho.code_signature.flags",
    "macho.code_signature.identifier",
    "macho.code_signature.platform",
    "macho.code_signature.team_id",
    "macho.go",
    "macho.info_plist",
    "macho.install_name",
    "macho.launchd_plist",
    "macho.source_version",
    "npm.author",
    "npm.description",
    "npm.homepage",
    "npm.maintainers",
    "npm.name",
    "npm.repository.url",
    "npm.version",
    "nupkg.authors",
    "nupkg.description",
    "nupkg.id",
    "nupkg.owners",
    "nupkg.project_url",
    "nupkg.repository_url",
    "nupkg.title",
    "nupkg.version",
    "oci.config.digest",
    "oci.manifest.digest",
    "oci.ref",
    "office.application",
    "office.category",
    "office.company",
    "office.content_status",
    "office.created",
    "office.creator",
    "office.description",
    "office.document_security",
    "office.hyperlink_base",
    "office.keywords",
    "office.last_modified_by",
    "office.last_printed",
    "office.limits",
    "office.macros",
    "office.manager",
    "office.modified",
    "office.presentation_format",
    "office.revision",
    "office.security_flag",
    "office.slide_count",
    "office.subject",
    "office.template",
    "office.title",
    "pdf.info",
    "pe.debug.pdb.path",
    "pe.go",
    "pe.image_hash",
    "pe.rich.entries",
    "pe.signatures",
    "pe.version.company",
    "pe.version.copyright",
    "pe.version.description",
    "pe.version.file_version",
    "pe.version.internal_name",
    "pe.version.original_filename",
    "pe.version.product_name",
    "pe.version.product_version",
    "pkg",
    "png.text",
    "python.author",
    "python.homepage",
    "python.license",
    "python.maintainer",
    "python.name",
    "python.requires_python",
    "python.summary",
    "python.version",
    "rar.original_name",
    "rpm.name",
    "rpm.packager",
    "rpm.scriptlets",
    "rpm.summary",
    "rpm.url",
    "rpm.vendor",
    "rpm.version",
    "rtf.info",
    "source.autoconf.name",
    "source.autoconf.version",
    "source.go.initialization_events",
    "source.payload_flow.events",
    "source.rust.modules",
    "source.wordpress.plugin_name",
    "source.wordpress.slug",
    "source.wordpress.text_domain",
    "source.wordpress.theme_name",
    "source.wordpress.version",
    "vsix.dependencies",
    "vsix.description",
    "vsix.display_name",
    "vsix.identity",
    "whl.author",
    "whl.author_email",
    "whl.distribution",
    "whl.home_page",
    "whl.maintainer",
    "whl.maintainer_email",
    "whl.summary",
    "whl.version",
    "xpi.author",
    "xpi.description",
    "xpi.homepage_url",
    "xpi.name",
    "xpi.version",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::*;

    /// An unsorted or duplicated entry means a merge went wrong.
    #[test]
    fn catalog_is_sorted_and_unique() {
        for pair in VALUE_CATALOG.windows(2) {
            assert!(
                pair[0] < pair[1],
                "VALUE_CATALOG must be sorted and free of duplicates: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// Every entry is a plain dot path with no index or wildcard. A key with a
    /// data-derived tail is cataloged at its base, and the tail is supplied at
    /// the call site.
    #[test]
    fn catalog_entries_are_plain_paths() {
        for key in VALUE_CATALOG {
            assert!(
                key.split('.').all(|seg| !seg.is_empty()
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')),
                "not a plain value path: {key}"
            );
        }
    }

    #[test]
    fn declared_resolves_to_the_literal() {
        assert_eq!(value_key!("pe.signatures").as_str(), "pe.signatures");
        assert_eq!(value_key!("pkg").to_string(), "pkg");
    }

    #[test]
    fn get_in_navigates_like_values() {
        let root = serde_json::json!({"pe": {"signatures": [{"subject": "CN=x"}]}});
        let sigs = value_key!("pe.signatures").get_in(&root);
        assert_eq!(sigs, root.pointer("/pe/signatures"));
        assert!(value_key!("pe.go").get_in(&root).is_none());
    }

    /// Modules that only consume `values`. Every `value_key!` in them is a
    /// read, whatever it is passed to.
    const READER_MODULES: &[&str] = &[
        "src/embedded_sources.rs",
        "src/formats/identity.rs",
        "src/formats/references.rs",
        "src/formats/references/",
        "src/go_package_context.rs",
        "src/package_context.rs",
    ];

    /// Functions and methods that read the key passed directly to them.
    const READ_CALLS: &[&str] = &["get_key", "get_key_at"];

    /// `ValueKey` methods that read when called on a `value_key!(…)`.
    const READ_METHODS: &[&str] = &["get_in"];

    /// Each catalog key must have at least one `value_key!` use that is not a
    /// read. Otherwise a reader can name a key that nothing produces, and the
    /// compile-time check passes against a catalog entry with no writer
    /// behind it.
    ///
    /// The scan works on tokens, not lines. Comments, doc examples, string
    /// contents and `#[cfg(test)]` / `#[test]` items are skipped, and an
    /// invocation split across lines is still found. A use counts as a read
    /// when it is in a reader module, when it is the direct argument of a read
    /// call (`values.get_key(value_key!(…))`), or when a read method is called
    /// on it. Any other use counts as a write: an argument to `insert_key` or
    /// a format helper, or an entry in a writer's key table.
    #[test]
    fn every_catalog_key_is_written_through_value_key() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for module in READER_MODULES {
            assert!(
                root.join(module).exists(),
                "READER_MODULES lists {module}, which no longer exists"
            );
        }
        let mut files = Vec::new();
        rust_files(&root.join("src"), &mut files);
        let mut written = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for file in &files {
            let rel = file
                .strip_prefix(root)
                .expect("under the crate root")
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(file).expect("readable source");
            let scan = scan::scan(&source);
            assert!(
                scan.out_of_line_test_modules.is_empty(),
                "{rel} declares out-of-line #[cfg(test)] modules {:?}; teach this scan to skip them",
                scan.out_of_line_test_modules
            );
            let reader_module = READER_MODULES.iter().any(|m| rel.starts_with(m));
            for found in scan.uses {
                seen.insert(found.key.clone());
                if !reader_module && !found.read {
                    written.insert(found.key);
                }
            }
        }
        let unused: Vec<_> = VALUE_CATALOG
            .iter()
            .filter(|k| !seen.contains(**k))
            .collect();
        assert!(
            unused.is_empty(),
            "catalog keys never used through value_key!: {unused:?}"
        );
        let unwritten: Vec<_> = VALUE_CATALOG
            .iter()
            .filter(|k| !written.contains(**k))
            .collect();
        assert!(
            unwritten.is_empty(),
            "catalog keys that are read but never written through value_key!: {unwritten:?}"
        );
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("readable source directory")
            .map(|e| e.expect("readable entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn scan_skips_comments_strings_and_test_items() {
        let source = r##"
            // value_key!("comment.line")
            /* value_key!("comment.block") /* nested */ value_key!("comment.nested") */
            /// value_key!("doc.example")
            const S: &str = "value_key!(\"in.string\")";
            const R: &str = r#"value_key!("in.raw") "quoted" "#;
            const Q: char = '"';
            const B: u8 = b'"';
            fn f<'a>(x: &'a str) -> &'a str { x }
            const ATTR: &str = "#[cfg(test)]";
            fn write(values: &mut Values) {
                values.insert_key(
                    value_key!(
                        "split.across.lines"
                    ),
                    json!(1),
                );
                put_str(values, value_key!("helper.write"), "x");
                for (k, v) in [(value_key!("table.write"), 1)] {}
                let _ = values.get_key(value_key!("direct.read"));
                let _ = values.get_key_at(value_key!("suffix.read"), "[0]");
                let _ = value_key!("method.read").get_in(&root);
                let _ = value_key!("label.only").as_str();
                let _ = r#type;
            }
            #[cfg(test)]
            mod tests {
                fn t() { values.insert_key(value_key!("test.write"), json!(1)); }
            }
            #[test]
            fn bare_test() { values.insert_key(value_key!("bare.test"), json!(1)); }
            #[cfg(test)]
            const TEST_ONLY: [ValueKey; 1] = [value_key!("test.const")];
            fn after() { put_str(values, crate::value_key!("after.test"), "y"); }
        "##;
        let scan = scan::scan(source);
        let got: Vec<(&str, bool)> = scan.uses.iter().map(|u| (u.key.as_str(), u.read)).collect();
        assert_eq!(
            got,
            [
                ("split.across.lines", false),
                ("helper.write", false),
                ("table.write", false),
                ("direct.read", true),
                ("suffix.read", true),
                ("method.read", true),
                ("label.only", false),
                ("after.test", false),
            ]
        );
        assert!(scan.out_of_line_test_modules.is_empty());
        let scan = scan::scan("#[cfg(test)]\nmod fixtures;\n");
        assert_eq!(scan.out_of_line_test_modules, ["fixtures"]);
    }

    /// A small Rust tokenizer, just enough to find `value_key!` invocations
    /// in real code and tell reads from writes.
    mod scan {
        use super::{READ_CALLS, READ_METHODS};

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum Tok {
            Ident(String),
            Str(String),
            Punct(char),
        }

        /// One `value_key!("…")` invocation.
        #[derive(Debug)]
        pub(super) struct Use {
            pub(super) key: String,
            pub(super) read: bool,
        }

        #[derive(Debug, Default)]
        pub(super) struct Scan {
            pub(super) uses: Vec<Use>,
            /// `#[cfg(test)] mod name;` declarations, whose bodies live in
            /// another file this scan would otherwise treat as production.
            pub(super) out_of_line_test_modules: Vec<String>,
        }

        pub(super) fn scan(source: &str) -> Scan {
            let toks = tokens(source);
            let mut out = Scan::default();
            // Open delimiters, each with the identifier that names the call
            // it opens (`get_key` in `values.get_key(`), if any.
            let mut stack: Vec<(char, Option<&str>)> = Vec::new();
            let mut i = 0;
            while let Some(tok) = toks.get(i) {
                if let Some(attr_len) = test_attribute(&toks, i) {
                    let start = i + attr_len;
                    let end = skip_item(&toks, start);
                    if let [Tok::Ident(kw), Tok::Ident(name), Tok::Punct(';')] =
                        toks.get(start..end).unwrap_or_default()
                        && kw == "mod"
                    {
                        out.out_of_line_test_modules.push(name.clone());
                    }
                    i = end;
                    continue;
                }
                match tok {
                    Tok::Ident(name) if name == "value_key" => {
                        if let Some((key, len)) = invocation(&toks, i) {
                            let direct_read = matches!(
                                stack.last(),
                                Some(('(', Some(callee))) if READ_CALLS.contains(callee)
                            );
                            let method_read = toks.get(i + len) == Some(&Tok::Punct('.'))
                                && matches!(
                                    toks.get(i + len + 1),
                                    Some(Tok::Ident(m)) if READ_METHODS.contains(&m.as_str())
                                );
                            out.uses.push(Use {
                                key,
                                read: direct_read || method_read,
                            });
                            i += len;
                            continue;
                        }
                    }
                    Tok::Punct(open @ ('(' | '[' | '{')) => {
                        let callee = match i.checked_sub(1).and_then(|p| toks.get(p)) {
                            Some(Tok::Ident(name)) if *open == '(' => Some(name.as_str()),
                            _ => None,
                        };
                        stack.push((*open, callee));
                    }
                    Tok::Punct(')' | ']' | '}') => {
                        stack.pop();
                    }
                    _ => {}
                }
                i += 1;
            }
            out
        }

        /// `value_key ! <open> "<key>" <close>` at `i`: the key and the
        /// number of tokens the invocation spans.
        fn invocation(toks: &[Tok], i: usize) -> Option<(String, usize)> {
            let [
                Tok::Ident(_),
                Tok::Punct('!'),
                Tok::Punct(open),
                Tok::Str(key),
                Tok::Punct(close),
            ] = toks.get(i..i + 5)?
            else {
                return None;
            };
            matches!((open, close), ('(', ')') | ('[', ']') | ('{', '}')).then(|| (key.clone(), 5))
        }

        /// Length of a `#[cfg(test)]` or `#[test]` attribute at `i`.
        fn test_attribute(toks: &[Tok], i: usize) -> Option<usize> {
            let p = |c| Tok::Punct(c);
            let id = |s: &str| Tok::Ident(s.to_string());
            let cfg_test = [
                p('#'),
                p('['),
                id("cfg"),
                p('('),
                id("test"),
                p(')'),
                p(']'),
            ];
            let test = [p('#'), p('['), id("test"), p(']')];
            let rest = toks.get(i..)?;
            if rest.starts_with(&cfg_test) {
                Some(cfg_test.len())
            } else if rest.starts_with(&test) {
                Some(test.len())
            } else {
                None
            }
        }

        /// The index just past the item that starts at `i`: through its first
        /// top-level `;` or its first top-level `{ … }` block. A closing
        /// delimiter at the top level ends the item without being consumed,
        /// since it belongs to the enclosing group (an attributed field or
        /// variant).
        fn skip_item(toks: &[Tok], mut i: usize) -> usize {
            let mut depth = 0usize;
            while let Some(tok) = toks.get(i) {
                match tok {
                    Tok::Punct('{') if depth == 0 => return matching_brace(toks, i),
                    Tok::Punct('(' | '[' | '{') => depth += 1,
                    Tok::Punct(')' | ']' | '}') if depth == 0 => return i,
                    Tok::Punct(')' | ']' | '}') => depth -= 1,
                    Tok::Punct(';') if depth == 0 => return i + 1,
                    _ => {}
                }
                i += 1;
            }
            i
        }

        /// The index just past the `}` matching the `{` at `i`.
        fn matching_brace(toks: &[Tok], mut i: usize) -> usize {
            let mut depth = 0usize;
            while let Some(tok) = toks.get(i) {
                match tok {
                    Tok::Punct('{') => depth += 1,
                    Tok::Punct('}') => {
                        depth -= 1;
                        if depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            i
        }

        fn tokens(source: &str) -> Vec<Tok> {
            let chars: Vec<char> = source.chars().collect();
            let at = |i: usize| chars.get(i).copied();
            let mut out = Vec::new();
            let mut i = 0;
            while let Some(c) = at(i) {
                match c {
                    c if c.is_whitespace() => i += 1,
                    '/' if at(i + 1) == Some('/') => {
                        while at(i).is_some_and(|c| c != '\n') {
                            i += 1;
                        }
                    }
                    '/' if at(i + 1) == Some('*') => i = block_comment_end(&chars, i),
                    '"' => {
                        let (text, end) = cooked_string(&chars, i + 1);
                        out.push(Tok::Str(text));
                        i = end;
                    }
                    '\'' => i = quote_end(&chars, i),
                    c if c == '_' || c.is_alphanumeric() => {
                        let start = i;
                        while at(i).is_some_and(|c| c == '_' || c.is_alphanumeric()) {
                            i += 1;
                        }
                        let word: String = chars.get(start..i).unwrap_or_default().iter().collect();
                        match (word.as_str(), at(i)) {
                            ("b" | "c", Some('"')) => {
                                let (text, end) = cooked_string(&chars, i + 1);
                                out.push(Tok::Str(text));
                                i = end;
                            }
                            ("b", Some('\'')) => i = quote_end(&chars, i),
                            ("r" | "br" | "cr", Some('"' | '#')) => {
                                let hashes = chars
                                    .get(i..)
                                    .unwrap_or_default()
                                    .iter()
                                    .take_while(|&&c| c == '#')
                                    .count();
                                if at(i + hashes) == Some('"') {
                                    let (text, end) = raw_string(&chars, i + hashes + 1, hashes);
                                    out.push(Tok::Str(text));
                                    i = end;
                                } else {
                                    // A raw identifier (`r#type`): the name
                                    // lexes on the next pass.
                                    i += hashes;
                                }
                            }
                            _ => out.push(Tok::Ident(word)),
                        }
                    }
                    c => {
                        out.push(Tok::Punct(c));
                        i += 1;
                    }
                }
            }
            out
        }

        /// The index just past a (possibly nested) block comment at `i`.
        fn block_comment_end(chars: &[char], mut i: usize) -> usize {
            let mut depth = 0usize;
            while let Some(&c) = chars.get(i) {
                let next = chars.get(i + 1).copied();
                if c == '/' && next == Some('*') {
                    depth += 1;
                    i += 2;
                } else if c == '*' && next == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            i
        }

        /// A `"…"` body starting at `i` (just past the opening quote): its
        /// text and the index just past the closing quote.
        fn cooked_string(chars: &[char], mut i: usize) -> (String, usize) {
            let mut text = String::new();
            while let Some(&c) = chars.get(i) {
                match c {
                    '"' => return (text, i + 1),
                    '\\' => {
                        if let Some(&escaped) = chars.get(i + 1) {
                            text.push(escaped);
                        }
                        i += 2;
                    }
                    c => {
                        text.push(c);
                        i += 1;
                    }
                }
            }
            (text, i)
        }

        /// A raw string body starting at `i`, closed by `"` and `hashes` `#`.
        fn raw_string(chars: &[char], mut i: usize, hashes: usize) -> (String, usize) {
            let mut text = String::new();
            while let Some(&c) = chars.get(i) {
                let closes = c == '"' && (1..=hashes).all(|n| chars.get(i + n) == Some(&'#'));
                if closes {
                    return (text, i + 1 + hashes);
                }
                text.push(c);
                i += 1;
            }
            (text, i)
        }

        /// The index just past a char literal at `i`, or just past the quote
        /// when it opens a lifetime or label (whose name lexes next).
        fn quote_end(chars: &[char], i: usize) -> usize {
            match chars.get(i + 1) {
                Some('\\') => {
                    // Escaped char: skip the escaped character, then run to
                    // the closing quote (`'\u{1F600}'` is longer than one).
                    let mut j = i + 3;
                    while chars.get(j).is_some_and(|&c| c != '\'') {
                        j += 1;
                    }
                    j + 1
                }
                Some(_) if chars.get(i + 2) == Some(&'\'') => i + 3,
                _ => i + 1,
            }
        }
    }
}
