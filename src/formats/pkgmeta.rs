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

/// Insert a value under `pkg.<key>`, accumulating array fields.
fn push(root: &mut Map<String, JsonValue>, key: &str, value: String) {
    let value = JsonValue::String(value);
    let array = ARRAY_FIELDS.contains(&base_field(key));
    match root.get_mut(key) {
        Some(JsonValue::Array(arr)) => arr.push(value),
        // A repeated scalar (a split-package .SRCINFO's `pkgname`) is
        // promoted to an array so nothing is lost.
        Some(existing) if !array => {
            let prior = std::mem::replace(existing, JsonValue::Null);
            *existing = JsonValue::Array(vec![prior, value]);
        }
        _ => {
            let value = if array {
                JsonValue::Array(vec![value])
            } else {
                value
            };
            root.insert(key.to_string(), value);
        }
    }
}

fn finalize(root: Map<String, JsonValue>, values: &mut Values) {
    // Derive a normalized scalar checksum digest from every *sums array. Hashes
    // are always literal (never `$pkgver`-expanded), so this is directly
    // comparable across a PKGBUILD and its .SRCINFO with a scalar equality
    // rule — the core "what builds differs from what was reviewed" signal.
    // Sorted + deduped so ordering or algorithm-list differences don't matter.
    let mut sums: Vec<String> = root
        .iter()
        .filter(|(key, _)| base_field(key).ends_with("sums"))
        .filter_map(|(_, value)| value.as_array())
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(str::trim)
        // SKIP is a verification opt-out, not a digest — exclude it so its
        // presence/absence doesn't drive the compare.
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("SKIP"))
        .map(str::to_string)
        .collect();
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
    let url_owner = root
        .get("url")
        .and_then(JsonValue::as_str)
        .and_then(github_owner);
    let mut source_owners: Vec<JsonValue> = Vec::new();
    // First-seen order for the output; the set keeps a PKGBUILD listing
    // thousands of sources from deduplicating quadratically.
    let mut seen_owners = std::collections::HashSet::new();
    let sources = root
        .iter()
        .filter(|(key, _)| base_field(key) == "source")
        .filter_map(|(_, value)| value.as_array())
        .flatten()
        .filter_map(JsonValue::as_str);
    for s in sources {
        // Honor `filename::url` rename syntax — read the URL half.
        let u = s.rsplit_once("::").map_or(s, |(_, u)| u);
        if let Some(owner) = github_owner(u)
            && seen_owners.insert(owner.clone())
        {
            source_owners.push(JsonValue::String(owner));
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

/// The body of a bash array whose `(` came just before `first`: the text up
/// to the `)` bash ends it at, which is not one inside quotes, escaped, or
/// in a comment, with any further `lines` it spans joined by spaces.
fn array_body<'a>(first: &str, lines: &mut impl Iterator<Item = &'a str>) -> String {
    let mut body = String::new();
    let mut quote: Option<char> = None;
    let mut text = first;
    loop {
        let mut chars = text.chars();
        let mut word_start = true;
        while let Some(c) = chars.next() {
            match quote {
                Some(q) if c == q => quote = None,
                None if c == ')' => return body,
                None if c == '\'' || c == '"' => quote = Some(c),
                None if c == '#' && word_start => {
                    // A comment runs to the end of the line.
                    body.push(c);
                    body.push_str(chars.as_str());
                    break;
                }
                Some('\'') => {}
                _ if c == '\\' => {
                    body.push(c);
                    body.extend(chars.next());
                    word_start = false;
                    continue;
                }
                _ => {}
            }
            word_start = quote.is_none() && c.is_whitespace();
            body.push(c);
        }
        let Some(next) = lines.next() else {
            return body;
        };
        body.push(' ');
        text = next;
    }
}

/// One line of a `key = value` metadata file.
pub(super) enum InfoLine<'a> {
    /// A `#` comment, without the `#`, trimmed.
    Comment(&'a str),
    /// A `key = value` assignment, both sides trimmed.
    Field(&'a str, &'a str),
}

/// The comments and assignments of a `key = value` metadata file: a
/// `.SRCINFO`, or the `.PKGINFO` of an Arch or Alpine built package. Lines
/// are trimmed; blank lines and lines without `=` are skipped.
///
/// Every key may repeat. A reader that keeps one value for a key keeps the
/// last line's, as pacman's `.PKGINFO` reader and apk-tools both assign each
/// line over the one before; a repeatable key collects every line in order.
pub(super) fn info_lines(text: &str) -> impl Iterator<Item = InfoLine<'_>> {
    text.lines().filter_map(|line| {
        let line = line.trim();
        if let Some(comment) = line.strip_prefix('#') {
            return Some(InfoLine::Comment(comment.trim()));
        }
        let (key, value) = line.split_once('=')?;
        Some(InfoLine::Field(key.trim(), value.trim()))
    })
}

/// Parse a `.SRCINFO`: `key = value` lines, leading tabs, repeated keys.
pub(super) fn extract_srcinfo(bytes: &[u8], values: &mut Values) -> Result<(), crate::Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| crate::Error::malformed_with_source("srcinfo", "input is not utf-8", e))?;
    let mut root: Map<String, JsonValue> = Map::new();
    for line in info_lines(text) {
        let InfoLine::Field(key, value) = line else {
            continue;
        };
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
        // `key+=(…)` appends to the array, as bash does.
        let key = key.trim();
        let key = key.strip_suffix('+').unwrap_or(key);
        if !is_known_field(key) {
            continue;
        }
        let rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix('(') {
            // Array assignment, possibly spanning lines until the closing ')'.
            let body = array_body(after, &mut lines);
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
mod tests;
