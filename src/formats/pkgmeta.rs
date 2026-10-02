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
use crate::output::{Errors, Stage};
use crate::value_key;

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

/// Keys [`finalize`] derives under `pkg.`. A field of the same name in the
/// file would replace or feed the derived fact (`url_github_owner = victim`
/// passes as an architecture-suffixed `url`), so it is never read.
const DERIVED_FIELDS: &[&str] = &["checksums", "source_github_owners", "url_github_owner"];

/// The field an architecture-suffixed key extends (`source_x86_64` → `source`).
fn base_field(key: &str) -> &str {
    key.split_once('_').map_or(key, |(b, _)| b)
}

fn is_known_field(key: &str) -> bool {
    // The key becomes a `pkg.<key>` path segment, so it is held to what a bash
    // variable name allows: a dot would otherwise nest the value elsewhere.
    if key.is_empty()
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || DERIVED_FIELDS.contains(&key)
    {
        return false;
    }
    // Scalars match exactly; architecture-suffixed sums/sources/depends share
    // the base array field's semantics.
    SCALAR_FIELDS.contains(&key) || ARRAY_FIELDS.contains(&base_field(key))
}

fn is_array_field(key: &str) -> bool {
    ARRAY_FIELDS.contains(&base_field(key))
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
        if base_field(key).ends_with("sums") {
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
    // Normalized GitHub-owner projections for provenance comparison in traits.
    // The upstream `url`'s owner and every github.com source's owner are emitted
    // as neutral facts; a trait compares the url owner against the source owners
    // (`ne … match: any`) to flag `-bin` fork impersonation — a source repo under
    // a different owner than the declared upstream. Owners are path[0] after
    // `github.com/`, an unambiguous high-confidence key; a bare cross-DOMAIN
    // difference (project site vs CDN vs GitHub releases) is normal and is
    // deliberately NOT projected, so only same-host owner divergence is
    // comparable. Parsing lives here; the comparison is pure YAML.
    let url_owner = match root.get("url") {
        Some(JsonValue::String(url)) => github_owner(url),
        _ => None,
    };
    let mut source_owners: Vec<JsonValue> = Vec::new();
    for (key, value) in &root {
        if base_field(key) != "source" {
            continue;
        }
        let JsonValue::Array(arr) = value else {
            continue;
        };
        for e in arr {
            let JsonValue::String(s) = e else { continue };
            // Honor `filename::url` rename syntax — read the URL half.
            let u = s.rsplit_once("::").map_or(s.as_str(), |(_, u)| u);
            if let Some(owner) = github_owner(u) {
                let owner = JsonValue::String(owner);
                if !source_owners.contains(&owner) {
                    source_owners.push(owner);
                }
            }
        }
    }
    // Insert each field under `pkg.<field>` so the subtree merges alongside the
    // generic file.* values rather than replacing the whole values object.
    // Fields go in before the derived facts, so a derived key always holds
    // what was derived even if a field name ever reached it.
    for (key, value) in root {
        values.insert_key_at(value_key!("pkg"), &key, value);
    }
    if !sums.is_empty() {
        values.insert_key(
            value_key!("pkg.checksums"),
            JsonValue::String(sums.join(",")),
        );
    }
    if let Some(owner) = url_owner {
        values.insert_key(value_key!("pkg.url_github_owner"), JsonValue::String(owner));
    }
    if !source_owners.is_empty() {
        values.insert_key(
            value_key!("pkg.source_github_owners"),
            JsonValue::Array(source_owners),
        );
    }
}

/// The GitHub owner (first path segment after `github.com/`), lowercased.
/// Covers `https://github.com/OWNER/repo`, `git+https://…`, codeload, and
/// release-download URLs. `None` for non-github URLs or an unresolved `$var`
/// owner (which can't be compared).
fn github_owner(s: &str) -> Option<String> {
    let rest = s.split_once("github.com/")?.1;
    let owner = rest.split(['/', '#', '?']).next()?;
    if owner.is_empty() || owner.contains('$') {
        return None;
    }
    Some(owner.to_ascii_lowercase())
}

/// Strip surrounding single/double quotes from a bash word.
fn unquote(s: &str) -> &str {
    let s = s.trim();
    ['"', '\'']
        .into_iter()
        .find_map(|q| s.strip_prefix(q)?.strip_suffix(q))
        .unwrap_or(s)
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
        .map_err(|e| crate::Error::malformed_with_source("srcinfo", "input is not utf-8", e))?;
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
///
/// This layers on the shell source extraction, so a failure here is
/// recorded in `errors` rather than returned: the source facts stand.
pub(super) fn extract_pkgbuild(bytes: &[u8], values: &mut Values, errors: &mut Errors) {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(e) => {
            errors.record_malformed(
                Stage::FormatExtract,
                format!("PKGBUILD is not UTF-8; pkg.* fields not read: {e}"),
            );
            return;
        }
    };
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
        if !is_known_field(key) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run [`extract_pkgbuild`], asserting it records nothing.
    fn pkgbuild(src: &[u8], values: &mut Values) {
        let mut errors = Errors::new();
        extract_pkgbuild(src, values, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn non_utf8_pkgbuild_records_one_error() {
        let mut v = Values::new();
        let mut errors = Errors::new();
        extract_pkgbuild(b"pkgname=foo\npkgdesc=\"caf\xe9\"\n", &mut v, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        let e = &errors.as_slice()[0];
        assert_eq!(
            (e.stage, e.kind),
            (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
        );
        assert!(v.get("pkg.pkgname").is_none());
    }

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
        pkgbuild(src, &mut v);
        assert_eq!(pkg(&v, "pkgver"), "1.2.3");
        assert_eq!(pkg(&v, "pkgname"), "foo");
        // SKIP excluded; only the real hash drives the digest.
        assert_eq!(pkg(&v, "checksums"), "deadbeef");
        assert!(matches!(v.get("pkg.source"), Some(JsonValue::Array(_))));
    }

    #[test]
    fn github_owner_extraction() {
        assert_eq!(
            github_owner("https://github.com/foo/bar"),
            Some("foo".into())
        );
        assert_eq!(
            github_owner("git+https://github.com/Foo/bar.git#tag=v1"),
            Some("foo".into())
        );
        assert_eq!(
            github_owner("https://github.com/o/r/releases/download/v1/x.tar.gz"),
            Some("o".into())
        );
        // Non-github and unresolved-variable owners aren't comparable.
        assert_eq!(github_owner("https://librewolf.net/x.tar.gz"), None);
        assert_eq!(github_owner("https://github.com/$_owner/r"), None);
    }

    #[test]
    fn github_owner_projections() {
        // url owner and source owners are emitted as neutral facts; the trait
        // does the compare. Here url=foo but the source repo is attacker/payload.
        let src = b"pkgname=tool-bin\nurl=https://github.com/foo/tool\nsource=('https://github.com/attacker/payload/releases/download/v1/t.tar.gz')\nsha256sums=('SKIP')\n";
        let mut v = Values::new();
        pkgbuild(src, &mut v);
        assert_eq!(pkg(&v, "url_github_owner"), "foo");
        assert_eq!(
            v.get("pkg.source_github_owners"),
            Some(&JsonValue::Array(vec![JsonValue::String(
                "attacker".into()
            )]))
        );
    }

    #[test]
    fn srcinfo_matches_pkgbuild_checksum() {
        let pb = b"pkgver=1.0\nsha256sums=('aa' 'bb')\n";
        let si = b"pkgbase = x\n\tpkgver = 1.0\n\tsha256sums = bb\n\tsha256sums = aa\n";
        let mut vp = Values::new();
        let mut vs = Values::new();
        pkgbuild(pb, &mut vp);
        extract_srcinfo(si, &mut vs).unwrap();
        // Sorted+deduped digest is order-independent → equal across both forms.
        assert_eq!(pkg(&vp, "checksums"), pkg(&vs, "checksums"));
        assert_eq!(pkg(&vp, "checksums"), "aa,bb");
    }

    /// A file naming a derived key, or a key that only shares a known field's
    /// prefix, must not overwrite or feed the derived provenance facts.
    #[test]
    fn file_fields_cannot_overwrite_derived_facts() {
        let srcinfo = b"pkgbase = tool-bin\n\turl = https://github.com/foo/tool\n\turl_github_owner = attacker\n\tsource_github_owners = foo\n\tchecksums = forged\n\tsource = https://github.com/attacker/payload/t.tar.gz\n\tsha256sums = aa\n";
        let pkgbuild_src = b"pkgname=tool-bin\nurl=https://github.com/foo/tool\nurl_github_owner=attacker\nsource_github_owners=(foo)\nchecksums=forged\nsource=('https://github.com/attacker/payload/t.tar.gz')\nsha256sums=('aa')\n";
        let mut from_srcinfo = Values::new();
        extract_srcinfo(srcinfo, &mut from_srcinfo).unwrap();
        let mut from_pkgbuild = Values::new();
        pkgbuild(pkgbuild_src, &mut from_pkgbuild);
        for v in [&from_srcinfo, &from_pkgbuild] {
            assert_eq!(pkg(v, "url_github_owner"), "foo");
            assert_eq!(
                v.get("pkg.source_github_owners"),
                Some(&JsonValue::Array(vec![JsonValue::String(
                    "attacker".into()
                )]))
            );
            assert_eq!(pkg(v, "checksums"), "aa");
        }
    }

    /// A key becomes a path segment; a dot in it must not nest the value.
    #[test]
    fn dotted_keys_are_not_fields() {
        let si = b"pkgbase = foo\n\tsource_x.y = https://example.com/a\n\tpkgver.x = 1\n";
        let mut v = Values::new();
        extract_srcinfo(si, &mut v).unwrap();
        assert!(v.get("pkg.source_x").is_none());
        assert!(v.get("pkg.pkgver").is_none());
        assert_eq!(pkg(&v, "pkgbase"), "foo");
    }

    #[test]
    fn architecture_suffixed_arrays_are_still_fields() {
        let si =
            b"pkgbase = foo\n\tsource_x86_64 = https://example.com/a\n\tsha256sums_x86_64 = bb\n";
        let mut v = Values::new();
        extract_srcinfo(si, &mut v).unwrap();
        assert!(matches!(
            v.get("pkg.source_x86_64"),
            Some(JsonValue::Array(_))
        ));
        assert_eq!(pkg(&v, "checksums"), "bb");
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
