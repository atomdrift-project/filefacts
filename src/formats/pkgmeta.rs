//! Arch/AUR package-metadata extraction into a shared `pkg.*` value tree.
//!
//! Two source formats describe the same package and should agree field-for-field:
//!
//! * **PKGBUILD** — the bash recipe makepkg executes (`pkgver=1.0`,
//!   `source=('a' 'b')`, `sha256sums=('…')`).
//! * **.SRCINFO** — the machine-generated, normalized mirror the AUR web UI and
//!   review tooling display (`\tpkgver = 1.0`, one `\tsource = …` line each).
//!
//! Both are parsed into the same schema so a consumer can compare a PKGBUILD
//! against its sibling `.SRCINFO` and flag divergence (the review-evasion vector
//! where what builds differs from what was reviewed). Scalar fields land at
//! `pkg.<field>`; conventional multi-value fields (`source`, `*sums`, `depends`,
//! …) are always arrays at `pkg.<field>[]` so comparisons are shape-stable even
//! when only one element is present.

use serde_json::{Map, Value as JsonValue};

use crate::Values;

/// Fields that are conventionally arrays in a PKGBUILD/.SRCINFO, so we always
/// emit them as arrays (even with a single element) for stable comparison.
const ARRAY_FIELDS: &[&str] = &[
    "source",
    "depends",
    "makedepends",
    "checkdepends",
    "optdepends",
    "provides",
    "conflicts",
    "replaces",
    "arch",
    "license",
    "validpgpkeys",
    "noextract",
    "md5sums",
    "sha1sums",
    "sha224sums",
    "sha256sums",
    "sha384sums",
    "sha512sums",
    "b2sums",
];

/// Scalar fields worth comparing/surfacing.
const SCALAR_FIELDS: &[&str] = &[
    "pkgbase", "pkgname", "pkgver", "pkgrel", "epoch", "url", "pkgdesc",
];

fn is_known_field(key: &str) -> bool {
    // architecture-suffixed sums/sources (e.g. `source_x86_64`, `sha256sums_x86_64`)
    // share the base field's semantics.
    let base = key.split_once('_').map_or(key, |(b, _)| b);
    ARRAY_FIELDS.contains(&base) || SCALAR_FIELDS.contains(&key) || SCALAR_FIELDS.contains(&base)
}

fn is_array_field(key: &str) -> bool {
    let base = key.split_once('_').map_or(key, |(b, _)| b);
    ARRAY_FIELDS.contains(&base)
    // `pkgname` is scalar in a PKGBUILD but may repeat in a split-package
    // .SRCINFO; the caller decides via `force_array`.
}

/// Insert a value under `pkg.<key>`, accumulating array fields.
fn push(root: &mut Map<String, JsonValue>, key: &str, value: String) {
    if is_array_field(key) {
        match root.get_mut(key) {
            Some(JsonValue::Array(arr)) => arr.push(JsonValue::String(value)),
            _ => {
                root.insert(
                    key.to_string(),
                    JsonValue::Array(vec![JsonValue::String(value)]),
                );
            }
        }
    } else {
        // Scalar: first write wins for pkgver/pkgrel/etc.; a repeated scalar
        // (e.g. split-package pkgname) is promoted to an array so nothing is lost.
        match root.get_mut(key) {
            None => {
                root.insert(key.to_string(), JsonValue::String(value));
            }
            Some(JsonValue::Array(arr)) => arr.push(JsonValue::String(value)),
            Some(existing) => {
                let prior = std::mem::replace(existing, JsonValue::Null);
                *existing = JsonValue::Array(vec![prior, JsonValue::String(value)]);
            }
        }
    }
}

fn finalize(root: Map<String, JsonValue>, values: &mut Values) {
    // Derive a normalized scalar checksum digest from every *sums array. Hashes
    // are always literal (never `$pkgver`-expanded), so this is directly
    // comparable across a PKGBUILD and its .SRCINFO with cleave's scalar-only
    // `eq`/`ne` — the core "what builds differs from what was reviewed" signal.
    // Sorted + deduped so ordering or algorithm-list differences don't matter.
    let mut sums: Vec<String> = Vec::new();
    for (key, value) in &root {
        let base = key.split_once('_').map_or(key.as_str(), |(b, _)| b);
        if base.ends_with("sums") {
            if let JsonValue::Array(arr) = value {
                for e in arr {
                    if let JsonValue::String(s) = e {
                        let s = s.trim();
                        // SKIP is a verification opt-out, not a digest — exclude
                        // it so its presence/absence doesn't drive the compare.
                        if !s.is_empty() && !s.eq_ignore_ascii_case("SKIP") {
                            sums.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    sums.sort();
    sums.dedup();
    if !sums.is_empty() {
        values.insert("pkg.checksums", JsonValue::String(sums.join(",")));
    }
    // Insert each field under `pkg.<field>` so the subtree merges alongside the
    // generic file.* values rather than replacing the whole values object.
    for (key, value) in root {
        values.insert(&format!("pkg.{key}"), value);
    }
}

/// Strip surrounding single/double quotes from a bash word.
fn unquote(s: &str) -> &str {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Split a bash array body (`'a' "b" c`) into elements, honoring simple quoting.
fn split_array(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in body.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse a `.SRCINFO`: `key = value` lines, leading tabs, repeated keys.
pub(super) fn extract_srcinfo(bytes: &[u8], values: &mut Values) -> Result<(), crate::Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| crate::Error::malformed("srcinfo", format!("input is not utf-8: {e}")))?;
    let mut root: Map<String, JsonValue> = Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() || !is_known_field(key) {
            continue;
        }
        push(&mut root, key, value.to_string());
    }
    finalize(root, values);
    Ok(())
}

/// Parse the metadata assignments of a PKGBUILD bash recipe. Line-oriented: it
/// recognizes the conventional column-0 `key=value` / `key=(...)` forms and the
/// multi-line array body. It does not evaluate the shell (no `$pkgver`
/// expansion); raw tokens are recorded, which is what a field-vs-field
/// comparison against `.SRCINFO` needs.
pub(super) fn extract_pkgbuild(bytes: &[u8], values: &mut Values) -> Result<(), crate::Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| crate::Error::malformed("pkgbuild", format!("input is not utf-8: {e}")))?;
    let mut root: Map<String, JsonValue> = Map::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        // Field assignments are at column 0 (not indented inside a function body).
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((key, rest)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || !is_known_field(key) {
            continue;
        }
        let rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix('(') {
            // Array assignment, possibly spanning lines until the closing ')'.
            let mut body = String::new();
            if let Some((inner, _)) = after.split_once(')') {
                body.push_str(inner);
            } else {
                body.push_str(after);
                for next in lines.by_ref() {
                    if let Some((inner, _)) = next.split_once(')') {
                        body.push(' ');
                        body.push_str(inner);
                        break;
                    }
                    body.push(' ');
                    body.push_str(next);
                }
            }
            for elem in split_array(&body) {
                push(&mut root, key, elem);
            }
        } else {
            // Scalar: strip an inline comment and quotes.
            let val = rest.split_once(" #").map_or(rest, |(v, _)| v);
            let val = unquote(val);
            if !val.is_empty() {
                push(&mut root, key, val.to_string());
            }
        }
    }
    finalize(root, values);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(values: &Values, path: &str) -> String {
        values
            .get(&format!("pkg.{path}"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    #[test]
    fn pkgbuild_fields_and_checksum_digest() {
        let src = b"pkgname=foo\npkgver=1.2.3\npkgrel=1\nsource=('a.tar.gz::https://x/v$pkgver.tar.gz')\nsha256sums=('SKIP' 'deadbeef')\n";
        let mut v = Values::new();
        extract_pkgbuild(src, &mut v).unwrap();
        assert_eq!(pkg(&v, "pkgver"), "1.2.3");
        assert_eq!(pkg(&v, "pkgname"), "foo");
        // SKIP excluded; only the real hash drives the digest.
        assert_eq!(pkg(&v, "checksums"), "deadbeef");
        assert!(matches!(v.get("pkg.source"), Some(JsonValue::Array(_))));
    }

    #[test]
    fn srcinfo_matches_pkgbuild_checksum() {
        let pb = b"pkgver=1.0\nsha256sums=('aa' 'bb')\n";
        let si = b"pkgbase = x\n\tpkgver = 1.0\n\tsha256sums = bb\n\tsha256sums = aa\n";
        let mut vp = Values::new();
        let mut vs = Values::new();
        extract_pkgbuild(pb, &mut vp).unwrap();
        extract_srcinfo(si, &mut vs).unwrap();
        // Sorted+deduped digest is order-independent → equal across both forms.
        assert_eq!(pkg(&vp, "checksums"), pkg(&vs, "checksums"));
        assert_eq!(pkg(&vp, "checksums"), "aa,bb");
    }

    #[test]
    fn srcinfo_multiline_arrays() {
        let si = b"pkgbase = foo\n\tsource = one\n\tsource = two\n";
        let mut v = Values::new();
        extract_srcinfo(si, &mut v).unwrap();
        match v.get("pkg.source") {
            Some(JsonValue::Array(a)) => assert_eq!(a.len(), 2),
            other => panic!("expected array, got {other:?}"),
        }
    }
}
