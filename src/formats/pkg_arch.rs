//! Arch Linux built-package metadata: the `.PKGINFO` member of a
//! `.pkg.tar.{zst,xz,gz}`.
//!
//! The generic tar walk lists only uncompressed tars, so a compressed package
//! would otherwise carry no package facts at all. This decompresses far enough
//! to reach `.PKGINFO` and lands its fields in the same `pkg.*` tree, under the
//! same names, that `pkgmeta` gives a PKGBUILD or `.SRCINFO`: `depend` lines
//! become `pkg.depends[]`, and so on. One reader of that tree then serves all
//! three forms, so a built package and its recipe compare field for field.

use std::io::Read;

use serde_json::{Map, Value as JsonValue};

use crate::output::Values;
use crate::value_key;

/// Decompressed bytes read before giving up on `.PKGINFO`. makepkg archives
/// the dot-files (`.BUILDINFO`, `.MTREE`, `.PKGINFO`) ahead of the package
/// tree, so the metadata sits in the first few hundred KiB of every real
/// package; a crafted one cannot make this inflate the whole payload.
const METADATA_SCAN_LIMIT: u64 = 4 * 1024 * 1024;

/// Largest `.PKGINFO` read.
const MAX_PKGINFO_BYTES: u64 = 1024 * 1024;

/// `.PKGINFO` keys and the `pkg.*` field each lands in. Repeatable keys
/// become arrays, as their PKGBUILD counterparts are.
const FIELDS: &[(&str, &str, bool)] = &[
    ("pkgname", "pkgname", false),
    ("pkgbase", "pkgbase", false),
    ("pkgdesc", "pkgdesc", false),
    ("url", "url", false),
    ("builddate", "builddate", false),
    ("packager", "packager", false),
    ("size", "size", false),
    ("arch", "arch", true),
    ("license", "license", true),
    ("group", "groups", true),
    ("replaces", "replaces", true),
    ("conflict", "conflicts", true),
    ("provides", "provides", true),
    ("backup", "backup", true),
    ("depend", "depends", true),
    ("optdepend", "optdepends", true),
    ("makedepend", "makedepends", true),
    ("checkdepend", "checkdepends", true),
];

pub(super) fn extract(bytes: &[u8], values: &mut Values) {
    let Some(text) = pkginfo(bytes) else {
        return;
    };
    let mut root = Map::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key.starts_with('#') {
            continue;
        }
        if key == "pkgver" {
            // `.PKGINFO` carries `[epoch:]pkgver-pkgrel` in one field; a
            // PKGBUILD has three, so split to match.
            let (version, release) = value.rsplit_once('-').unwrap_or((value, ""));
            let (epoch, version) = version.split_once(':').unwrap_or(("", version));
            for (field, part) in [("epoch", epoch), ("pkgver", version), ("pkgrel", release)] {
                if !part.is_empty() {
                    root.insert(field.into(), JsonValue::String(part.into()));
                }
            }
            continue;
        }
        let Some(&(_, field, repeated)) = FIELDS.iter().find(|(name, _, _)| *name == key) else {
            continue;
        };
        let value = JsonValue::String(value.to_string());
        if repeated {
            if let JsonValue::Array(list) = root
                .entry(field)
                .or_insert_with(|| JsonValue::Array(Vec::new()))
            {
                list.push(value);
            }
        } else {
            root.entry(field).or_insert(value);
        }
    }
    for (field, value) in root {
        values.insert_key_at(value_key!("pkg"), &field, value);
    }
}

/// The text of the package's `.PKGINFO` member, decompressing only as far
/// as [`METADATA_SCAN_LIMIT`].
fn pkginfo(bytes: &[u8]) -> Option<String> {
    let reader: Box<dyn Read + '_> = if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let decoder = super::bounded::zstd_decoder(bytes)
            .inspect_err(|error| log_abandoned("zstd", error))
            .ok()?;
        Box::new(decoder)
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Box::new(super::bounded::xz_decoder(bytes))
    } else {
        Box::new(bytes)
    };
    let mut archive = tar::Archive::new(reader.take(METADATA_SCAN_LIMIT));
    let entries = archive
        .entries()
        .inspect_err(|error| log_abandoned("tar", error))
        .ok()?;
    for entry in entries {
        let entry = entry
            .inspect_err(|error| log_abandoned("tar", error))
            .ok()?;
        let is_pkginfo = entry
            .path()
            .is_ok_and(|path| path.as_os_str() == ".PKGINFO" || path.as_os_str() == "./.PKGINFO");
        if !is_pkginfo {
            continue;
        }
        if entry.size() > MAX_PKGINFO_BYTES {
            tracing::debug!(
                target: "filefacts::pkg_arch",
                format = "pkg-arch",
                stage = "pkginfo",
                len = entry.size(),
                "`.PKGINFO` is over its size cap; package metadata skipped"
            );
            return None;
        }
        let mut text = Vec::new();
        entry
            .take(MAX_PKGINFO_BYTES)
            .read_to_end(&mut text)
            .inspect_err(|error| log_abandoned("pkginfo", error))
            .ok()?;
        return Some(String::from_utf8_lossy(&text).into_owned());
    }
    tracing::debug!(
        target: "filefacts::pkg_arch",
        format = "pkg-arch",
        stage = "tar",
        len = METADATA_SCAN_LIMIT,
        "no `.PKGINFO` within the metadata scan window"
    );
    None
}

fn log_abandoned(stage: &str, error: &std::io::Error) {
    tracing::debug!(
        target: "filefacts::pkg_arch",
        format = "pkg-arch",
        stage,
        %error,
        "package metadata read abandoned"
    );
}

#[cfg(test)]
mod tests;
