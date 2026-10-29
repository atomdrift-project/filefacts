//! Alpine `.apk` package metadata.
//!
//! An Alpine package is not a plain `.tar.gz`: it is two or three gzip streams
//! concatenated -- an optional signature segment, a control segment holding
//! `.PKGINFO`, then the data segment. The generic tar walk reports compressed
//! variants by format only, so the identity is read here, the same way
//! `npm.rs` reads
//! `package/package.json`: decompress far enough to reach the metadata, walk
//! headers only, and stop. The data segment -- tens of megabytes on a real
//! package -- is never decompressed, because `.PKGINFO` always precedes it.

use super::people::{self, Person};
use std::io::Read;

use flate2::read::MultiGzDecoder;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Decompressed bytes to read before giving up on finding `.PKGINFO`. The
/// signature and control segments together are a few KB on every real package;
/// this is generous enough to absorb an unusual one and small enough that a
/// crafted control segment cannot be used to inflate a scan.
const CONTROL_SCAN_LIMIT: u64 = 4 * 1024 * 1024;

/// tar block size.
const BLOCK: usize = 512;

/// Read a NUL-padded fixed-width tar header field.
fn cstr_field(field: &[u8]) -> &str {
    let text = field.split(|&b| b == 0).next().unwrap_or_default();
    std::str::from_utf8(text).unwrap_or("").trim()
}

/// Read a tar octal size field. Malformed fields read as zero, which advances
/// the walk one block at a time rather than trusting a bogus length.
fn octal_field(field: &[u8]) -> usize {
    let text = cstr_field(field);
    usize::from_str_radix(text.trim(), 8).unwrap_or(0)
}

pub(super) fn extract(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("apk".into()),
    );

    // Decompress a bounded prefix and walk the tar headers directly rather
    // than handing the stream to `tar::Archive`. The segments are separate
    // gzip streams whose tars may or may not carry terminating blocks, and a
    // tar reader stops at the first terminator it sees -- which on a signed
    // package is the end of the signature segment, before `.PKGINFO` is
    // reached. Walking blocks is indifferent to where one segment stops and
    // the next begins.
    //
    // Unlike `bounded::inflate_capped`, what inflated before a gzip error is
    // kept: the data segment past the control segment may be damaged without
    // touching `.PKGINFO`.
    let mut buf = Vec::new();
    if let Err(e) = MultiGzDecoder::new(bytes)
        .take(CONTROL_SCAN_LIMIT)
        .read_to_end(&mut buf)
    {
        tracing::debug!(
            target: "filefacts::apk_alpine",
            stage = "gunzip",
            inflated = buf.len(),
            error = %e,
            "gzip segments stopped inflating"
        );
        if buf.is_empty() {
            return;
        }
    }

    let mut pkginfo: Option<String> = None;
    let mut signing_keys: Vec<String> = Vec::new();
    let mut off = 0usize;
    // A header needs at least one byte after it to be worth reading.
    while let Some((block, rest)) = buf
        .get(off..)
        .filter(|tail| tail.len() > BLOCK)
        .and_then(<[u8]>::split_first_chunk::<BLOCK>)
    {
        let name = cstr_field(&block[..100]);
        if name.is_empty() {
            // Terminator or padding between segments; step over it.
            off += BLOCK;
            continue;
        }
        let size = octal_field(&block[124..136]);
        let body = off + BLOCK;
        let name = name.trim_start_matches("./");
        if name.starts_with(".SIGN.") {
            signing_keys.push(name.to_string());
        } else if name == ".PKGINFO" {
            let text = rest.get(..size).unwrap_or(rest);
            pkginfo = Some(String::from_utf8_lossy(text).into_owned());
            // `.PKGINFO` is the last thing worth reading; the data segment
            // follows and must not be walked.
            break;
        }
        // Saturating: an eleven-digit octal size rounds up past `usize::MAX`
        // on 32-bit targets.
        off = body.saturating_add(size.div_ceil(BLOCK).saturating_mul(BLOCK));
    }

    if !signing_keys.is_empty() {
        values.insert_key(
            value_key!("apk.signing_keys"),
            JsonValue::Array(signing_keys.into_iter().map(JsonValue::String).collect()),
        );
    }
    metrics.insert(
        metric!("apk.signed"),
        f64::from(u8::from(values.get("apk.signing_keys").is_some())),
    );

    let Some(text) = pkginfo else {
        return;
    };

    // `.PKGINFO` is `key = value` lines. `depend` and `provides` repeat, so
    // they collect into arrays; everything else is last-wins like the rest of
    // the package readers.
    let mut depends: Vec<JsonValue> = Vec::new();
    let mut provides: Vec<JsonValue> = Vec::new();
    let mut fields = JsonMap::new();
    for line in text.lines() {
        let line = line.trim();
        // The leading comment names the build tool -- `# Generated by melange`
        // or `abuild`. That is the closest thing a package has to a producer,
        // and it distinguishes a distro build from one made on a workstation.
        if let Some(rest) = line.strip_prefix("# Generated by ") {
            values.insert_key(
                value_key!("apk.builder"),
                JsonValue::String(rest.trim().to_string()),
            );
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() {
            continue;
        }
        match key {
            "depend" => depends.push(JsonValue::String(value.to_string())),
            "provides" => provides.push(JsonValue::String(value.to_string())),
            _ => {
                fields.insert(key.to_string(), JsonValue::String(value.to_string()));
            }
        }
    }

    for (key, out) in [
        ("pkgname", value_key!("apk.name")),
        ("pkgver", value_key!("apk.version")),
        ("pkgdesc", value_key!("apk.description")),
        ("url", value_key!("apk.homepage")),
        ("license", value_key!("apk.license")),
        ("arch", value_key!("apk.arch")),
        ("origin", value_key!("apk.origin")),
        ("commit", value_key!("apk.commit")),
        ("datahash", value_key!("apk.datahash")),
        ("builddate", value_key!("apk.builddate")),
    ] {
        if let Some(v) = fields.get(key) {
            values.insert_key(out, v.clone());
        }
    }
    // Both are `"Name <email>"` people.
    for (key, out) in [
        ("maintainer", value_key!("apk.maintainers")),
        ("packager", value_key!("apk.packagers")),
    ] {
        let person = fields
            .get(key)
            .and_then(JsonValue::as_str)
            .map(Person::parse);
        people::put(values, out, person);
    }
    if !depends.is_empty() {
        metrics.insert(metric!("apk.dependency_count"), depends.len() as f64);
        values.insert_key(value_key!("apk.dependencies"), JsonValue::Array(depends));
    }
    if !provides.is_empty() {
        values.insert_key(value_key!("apk.provides"), JsonValue::Array(provides));
    }
    if let Some(size) = fields.get("size").and_then(|v| v.as_str())
        && let Ok(n) = size.parse::<f64>()
    {
        metrics.insert(metric!("apk.installed_size"), n);
    }
    // A package whose `origin` differs from its `pkgname` is a subpackage of
    // another build; when they match it is the primary artifact. Stated as a
    // fact because a package claiming an origin it does not belong to is how a
    // typosquat borrows a real project's provenance.
    if let (Some(name), Some(origin)) = (fields.get("pkgname"), fields.get("origin")) {
        metrics.insert(
            metric!("apk.subpackage"),
            f64::from(u8::from(name != origin)),
        );
    }
}

#[cfg(test)]
mod tests;
