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

/// Format helpers whose second argument is the key they write. They take a
/// [`ValueKey`], so the compiler already rejects a string there; the scan
/// also checks them so that loosening a signature back to `&str` cannot
/// quietly reopen the gap.
const KEY_HELPERS: &[&str] = &["put_i64", "put_str", "put_u64"];

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
    let mut written = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (rel, source) in sources() {
        let scan = scan::scan(&source);
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

/// Production code writes `values` only at checked keys, which is what
/// makes [`VALUE_CATALOG`] the complete list of paths filefacts can emit.
///
/// The scan, which skips comments, strings and test items as above,
/// rejects two shapes:
///
/// - any call to the unchecked `Values::insert`, as `values.insert(path,
///   value)` or `Values::insert(…)`. A receiver is taken for a `Values`
///   when it is named `values`, as every one in the crate is today, or
///   when the file binds the name to one earlier (`v: &mut Values`,
///   `let mut v = Values::new()`). The two arguments tell it from a set's
///   `insert`. A variable path counts too, since it is as unchecked as a
///   literal;
/// - a [`KEY_HELPERS`] call whose key is a string literal or a `format!`.
#[test]
fn values_are_written_only_through_checked_keys() {
    let mut unchecked = Vec::new();
    for (rel, source) in sources() {
        for write in scan::scan(&source).unchecked_writes {
            unchecked.push(format!("{rel}:{}: {}", write.line, write.call));
        }
    }
    assert!(
        unchecked.is_empty(),
        "values written at an unchecked path; declare the key in VALUE_CATALOG and \
             write it with insert_key / insert_key_at and value_key!:\n{}",
        unchecked.join("\n")
    );
}

/// Every production `.rs` file under `src/`, as (crate-relative path,
/// contents). The file behind a `#[cfg(test)] mod name;`, and anything under
/// that module's directory, is test code and is left out, as inline test
/// items are.
fn sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut sources = Vec::new();
    let mut test_files = BTreeSet::new();
    let mut test_dirs = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).expect("readable source");
        // A non-`mod.rs` file keeps its child modules in a directory named
        // after it; `mod.rs` and the crate roots (`lib.rs`, `main.rs`, each
        // `src/bin/*.rs`) keep them beside it.
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let parent = file.parent().expect("a file has a parent");
        let beside = matches!(stem, "mod" | "lib" | "main") || parent == root.join("src/bin");
        let module_dir = if beside {
            parent.to_path_buf()
        } else {
            parent.join(stem)
        };
        for name in scan::scan(&source).out_of_line_test_modules {
            let leaf = module_dir.join(format!("{name}.rs"));
            let nested = module_dir.join(&name).join("mod.rs");
            assert!(
                leaf.exists() || nested.exists(),
                "{} declares #[cfg(test)] mod {name}; but neither {} nor {} exists",
                file.display(),
                leaf.display(),
                nested.display()
            );
            test_files.insert(leaf);
            test_dirs.push(module_dir.join(&name));
        }
        sources.push((file, source));
    }
    sources
        .into_iter()
        .filter(|(file, _)| {
            !test_files.contains(file) && !test_dirs.iter().any(|dir| file.starts_with(dir))
        })
        .map(|(file, source)| {
            let rel = file
                .strip_prefix(root)
                .expect("under the crate root")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, source)
        })
        .collect()
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

#[test]
fn scan_finds_unchecked_writes() {
    let source = r##"
fn write(values: &mut Values, out: &mut Out, map: &mut Map) {
    // values.insert("comment", json!(1));
    let s = "values.insert(\"in.string\", v)";
    values.insert_key(value_key!("checked"), json!(1));
    values.insert_key_at(value_key!("base"), &field, json!(1));
    put_str(values, value_key!("helper"), "x");
    values.insert(FlowOrigin { value: id, bindings });
    map.insert("not.values", 1);
    values.insert("literal", json!(1));
    values
        .insert(&format!("fmt.{x}"), json!(1));
    out.values.insert(key, json!(1));
    Values::insert(&mut values, "ufcs", json!(1));
    put_str(values, "helper.literal", "x");
    put_u64(values, &format!("helper.{x}"), 1);
    put_i64(values, key, 1);
}
fn renamed(v: &mut crate::Values, set: &mut BTreeSet<String>) {
    v.insert("renamed.param", json!(1));
    let mut acc = Values::new();
    acc.insert(&key, json!(1));
    set.insert("not.values".to_string());
}
fn put_str(values: &mut Values, key: ValueKey, s: String) {}
#[cfg(test)]
mod tests {
    fn t(values: &mut Values, m: &mut Values) {
        values.insert("test.literal", json!(1));
        put_str(values, "test.helper", "x");
    }
}
fn later(m: &mut HashMap<&str, u8>) {
    m.insert("not.values", 1);
}
"##;
    let scan = scan::scan(source);
    let got: Vec<(&str, usize)> = scan
        .unchecked_writes
        .iter()
        .map(|w| (w.call.as_str(), w.line))
        .collect();
    assert_eq!(
        got,
        [
            ("values.insert", 10),
            ("values.insert", 12),
            ("values.insert", 13),
            ("Values::insert", 14),
            ("put_str", 15),
            ("put_u64", 16),
            ("v.insert", 20),
            ("acc.insert", 22),
        ]
    );
}

/// Family templates are sorted, unique and well formed, and none sits
/// below a cataloged key, where the catalog already covers it.
#[test]
fn families_are_templates_the_catalog_does_not_cover() {
    for pair in VALUE_FAMILIES.windows(2) {
        assert!(
            pair[0] < pair[1],
            "VALUE_FAMILIES must be sorted and free of duplicates: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
    for family in VALUE_FAMILIES {
        let mut placeholders = 0;
        for seg in family.split('.') {
            let mut rest = seg;
            while !rest.is_empty() {
                if let Some(open) = rest.strip_prefix('<') {
                    let (name, tail) = open.split_once('>').unwrap_or_default();
                    assert!(
                        !name.is_empty()
                            && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                        "malformed placeholder in {family}"
                    );
                    placeholders += 1;
                    rest = tail;
                } else {
                    let plain = rest.find('<').unwrap_or(rest.len());
                    let (lit, tail) = rest.split_at(plain);
                    assert!(
                        lit.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                        "not a value path template: {family}"
                    );
                    rest = tail;
                }
            }
            assert!(!seg.is_empty(), "empty segment in {family}");
        }
        assert!(
            placeholders > 0,
            "{family} is fixed; list it in VALUE_CATALOG"
        );
        let covering = VALUE_CATALOG
            .iter()
            .find(|key| family.starts_with(&format!("{key}.")));
        assert!(
            covering.is_none(),
            "{family} sits below the cataloged key {covering:?}"
        );
    }
}

/// A small Rust tokenizer, just enough to find `value_key!` invocations
/// and unchecked `values` writes in real code, and to tell reads from
/// writes.
mod scan {
    use std::collections::BTreeSet;

    use super::{KEY_HELPERS, READ_CALLS, READ_METHODS};

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

    /// A write that names its key without the catalog: a
    /// `Values::insert` call, or a key helper given a string.
    #[derive(Debug)]
    pub(super) struct UncheckedWrite {
        /// `values.insert`, `Values::insert`, or the helper's name.
        pub(super) call: String,
        /// 1-based line of the call.
        pub(super) line: usize,
    }

    #[derive(Debug, Default)]
    pub(super) struct Scan {
        pub(super) uses: Vec<Use>,
        pub(super) unchecked_writes: Vec<UncheckedWrite>,
        /// `#[cfg(test)] mod name;` declarations, whose bodies live in
        /// another file this scan would otherwise treat as production.
        pub(super) out_of_line_test_modules: Vec<String>,
    }

    pub(super) fn scan(source: &str) -> Scan {
        let (toks, lines) = tokens(source);
        let mut out = Scan::default();
        // Names a `Values` goes by, from the production code read so far.
        let mut receivers = BTreeSet::from(["values".to_string()]);
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
                Tok::Ident(_) => {
                    if let Some(name) = values_binding(&toks, i) {
                        receivers.insert(name);
                    }
                    if let Some(call) = unchecked_write(&toks, i, &receivers) {
                        out.unchecked_writes.push(UncheckedWrite {
                            call,
                            line: lines.get(i).copied().unwrap_or_default(),
                        });
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

    /// The name that the `Values` type or constructor at `i` binds:
    /// `name: &mut Values`, `name: Values`, or `name = Values::new()`,
    /// with or without a path before `Values`.
    fn values_binding(toks: &[Tok], i: usize) -> Option<String> {
        if !matches!(toks.get(i), Some(Tok::Ident(t)) if t == "Values") {
            return None;
        }
        let at = |j: usize, back: usize| j.checked_sub(back).and_then(|p| toks.get(p));
        let punct = |tok: Option<&Tok>, c: char| tok == Some(&Tok::Punct(c));
        let mut j = i;
        while punct(at(j, 1), ':')
            && punct(at(j, 2), ':')
            && matches!(at(j, 3), Some(Tok::Ident(_)))
        {
            j -= 3;
        }
        let constructor = punct(toks.get(i + 1), ':')
            && punct(toks.get(i + 2), ':')
            && matches!(toks.get(i + 3), Some(Tok::Ident(f)) if f == "new" || f == "default");
        if constructor {
            return match (at(j, 1), at(j, 2)) {
                (Some(Tok::Punct('=')), Some(Tok::Ident(name))) => Some(name.clone()),
                _ => None,
            };
        }
        if matches!(at(j, 1), Some(Tok::Ident(m)) if m == "mut") {
            j -= 1;
        }
        if punct(at(j, 1), '&') {
            j -= 1;
        }
        match (at(j, 1), at(j, 2), at(j, 3)) {
            (Some(Tok::Punct(':')), Some(Tok::Ident(name)), before) if !punct(before, ':') => {
                Some(name.clone())
            }
            _ => None,
        }
    }

    /// The unchecked write that the identifier at `i` calls, if any:
    /// `insert(path, value)` on one of the `receivers` or as
    /// `Values::insert(…)`, whatever the path, or a [`KEY_HELPERS`] call
    /// whose key is a string.
    fn unchecked_write(toks: &[Tok], i: usize, receivers: &BTreeSet<String>) -> Option<String> {
        let Tok::Ident(name) = toks.get(i)? else {
            return None;
        };
        if toks.get(i + 1) != Some(&Tok::Punct('(')) {
            return None;
        }
        let before = |n: usize| i.checked_sub(n).and_then(|p| toks.get(p));
        let ident = |tok: Option<&Tok>, want: &str| matches!(tok, Some(Tok::Ident(n)) if n == want);
        let args = call_args(toks, i + 1);
        if name == "insert" {
            let receiver = match (before(1), before(2)) {
                (Some(Tok::Punct('.')), Some(Tok::Ident(r))) if receivers.contains(r) => Some(r),
                _ => None,
            };
            // `insert(path, value)`; a set's `insert` takes one argument.
            // A turbofish in the path can only split it further.
            if let Some(receiver) = receiver
                && args.len() >= 2
            {
                return Some(format!("{receiver}.insert"));
            }
            let path = before(1) == Some(&Tok::Punct(':'))
                && before(2) == Some(&Tok::Punct(':'))
                && ident(before(3), "Values");
            return path.then(|| "Values::insert".to_string());
        }
        let call = KEY_HELPERS.contains(&name.as_str())
            && before(1) != Some(&Tok::Punct('.'))
            && !ident(before(1), "fn");
        (call && args.get(1).is_some_and(|key| is_string_path(key))).then(|| name.clone())
    }

    /// The arguments of the call whose `(` is at `open`, split at its
    /// top-level commas. A trailing comma adds no argument.
    fn call_args(toks: &[Tok], open: usize) -> Vec<&[Tok]> {
        let mut args = Vec::new();
        let mut depth = 0usize;
        let mut start = open + 1;
        for (i, tok) in toks.iter().enumerate().skip(start) {
            match tok {
                Tok::Punct('(' | '[' | '{') => depth += 1,
                Tok::Punct(')' | ']' | '}') if depth == 0 => {
                    if i > start {
                        args.push(toks.get(start..i).unwrap_or_default());
                    }
                    break;
                }
                Tok::Punct(')' | ']' | '}') => depth -= 1,
                Tok::Punct(',') if depth == 0 => {
                    args.push(toks.get(start..i).unwrap_or_default());
                    start = i + 1;
                }
                _ => {}
            }
        }
        args
    }

    /// A path written as a string: a literal or a `format!`/`concat!`,
    /// possibly borrowed.
    fn is_string_path(arg: &[Tok]) -> bool {
        let mut arg = arg;
        while let [Tok::Punct('&'), rest @ ..] = arg {
            arg = rest;
        }
        match arg {
            [Tok::Str(_), ..] => true,
            [Tok::Ident(mac), Tok::Punct('!'), ..] => mac == "format" || mac == "concat",
            _ => false,
        }
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

    /// The tokens of `source`, and the 1-based line each one starts on.
    fn tokens(source: &str) -> (Vec<Tok>, Vec<usize>) {
        let chars: Vec<char> = source.chars().collect();
        let at = |i: usize| chars.get(i).copied();
        let mut out = Vec::new();
        let mut lines = Vec::new();
        let (mut line, mut counted) = (1, 0);
        let mut i = 0;
        while let Some(c) = at(i) {
            let start = i;
            let before = out.len();
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
            if out.len() > before {
                let skipped = chars.get(counted..start).unwrap_or_default();
                line += skipped.iter().filter(|&&c| c == '\n').count();
                counted = start;
                lines.push(line);
            }
        }
        (out, lines)
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
