//! PHP archive (phar) extractor, for the native phar format.
//!
//! A native phar is a PHP stub ending in `__HALT_COMPILER();`, a manifest, the
//! members' contents back to back in manifest order, and an optional signature
//! trailer ending in `GBMB`. PHP runs the stub; a `phar://` stream serves the
//! members, each of which is code in its own right. The members are listed as
//! [`ArchiveMember`]s for a caller to slice (and inflate) and analyze on their
//! own, and so is the stub, under the `.phar/stub.php` name the tar- and
//! zip-based phar formats give it. Those two formats are ordinary tar and zip
//! archives and go through their own extractors.
//!
//! The structure is parsed by [`crate::fileid::phar`], which identification
//! shares; this publishes it and checks the signature's digest.
//!
//! The global and per-member metadata are PHP-serialized, and PHP unserializes
//! them whenever the archive is opened through `phar://` — even by a call as
//! innocent as `file_exists`. Serialized objects there are the phar
//! deserialization attack, so their class names are reported.

use std::borrow::Cow;

use md5::Md5;
use serde_json::{Value as JsonValue, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, member_value};
use super::bounded::{Limits, MAX_ARCHIVE_MEMBERS};
use crate::error::Error;
use crate::fileid::phar::{Algorithm, Trailer, parse};
use crate::metric;
use crate::output::{ArchiveCompression, ArchiveMember, EntryType, Metrics, Values};
use crate::value_key;

/// The name the tar- and zip-based phar formats store the stub under.
const STUB_NAME: &str = ".phar/stub.php";

/// Member flag: the content is raw deflate.
const ENTRY_DEFLATE: u32 = 0x0000_1000;

/// Member flag: the content is bzip2.
const ENTRY_BZIP2: u32 = 0x0000_2000;

/// Serialized class names listed per archive, at most.
const MAX_METADATA_CLASSES: usize = 64;

/// The shared aggregates a phar reports over its members, the stub included.
const AGGS: &[Agg] = &[
    Agg::MemberCount,
    Agg::FileCount,
    Agg::UncompressedSize(Scope::All),
    Agg::CompressedSize,
    Agg::CompressionRatio,
    Agg::Methods { always: true },
    Agg::MaxFilenameLength,
    Agg::PathTraversal(Scope::All),
    Agg::NameTricks,
    Agg::Executables,
    Agg::Scripts,
    Agg::NestedArchives,
    Agg::DuplicateMembers,
    Agg::ZipBombRatio(Scope::All),
    Agg::MtimeRange,
];

/// The published signature: its algorithm, its digest, and whether the digest
/// matches the signed bytes. `valid` is absent for an OpenSSL signature,
/// which needs the archive's public key to check.
fn signature(data: &[u8], trailer: &Trailer) -> JsonValue {
    let digest = data.get(trailer.start..trailer.end).unwrap_or_default();
    let signed = data.get(..trailer.start).unwrap_or_default();
    let valid = match trailer.algorithm {
        Algorithm::Md5 => Some(Md5::digest(signed).as_slice() == digest),
        Algorithm::Sha1 => Some(Sha1::digest(signed).as_slice() == digest),
        Algorithm::Sha256 => Some(Sha256::digest(signed).as_slice() == digest),
        Algorithm::Sha512 => Some(Sha512::digest(signed).as_slice() == digest),
        Algorithm::OpenSsl | Algorithm::OpenSslSha256 | Algorithm::OpenSslSha512 => None,
    };
    let mut value = serde_json::Map::new();
    value.insert("algorithm".into(), trailer.algorithm.as_str().into());
    value.insert("digest".into(), super::common::hex_encode(digest).into());
    if let Some(valid) = valid {
        value.insert("valid".into(), valid.into());
    }
    JsonValue::Object(value)
}

/// The class names of the objects a PHP-serialized value holds: every
/// `O:<len>:"<class>"` (and custom-serialized `C:`), in order of first
/// appearance, with the total object count.
fn serialized_classes(serialized: &[u8], classes: &mut Vec<String>) -> u64 {
    let mut count = 0;
    let mut rest = serialized;
    while let Some(at) = memchr::memchr2(b'O', b'C', rest) {
        let candidate = rest.get(at..).unwrap_or_default();
        rest = candidate.get(1..).unwrap_or_default();
        let Some(name) = class_name(candidate) else {
            continue;
        };
        count += 1;
        if classes.len() < MAX_METADATA_CLASSES && !classes.iter().any(|c| c == &name) {
            classes.push(name.into_owned());
        }
    }
    count
}

/// The class name of the serialized object at the start of `s`, which opens
/// `O:` or `C:`, if it is one.
fn class_name(s: &[u8]) -> Option<Cow<'_, str>> {
    let s = s
        .get(2..)
        .filter(|_| matches!(s, [b'O' | b'C', b':', ..]))?;
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    let len: usize = std::str::from_utf8(s.get(..digits)?).ok()?.parse().ok()?;
    let name = s.get(digits..)?.strip_prefix(b":\"")?.get(..len)?;
    s.get(digits + 2 + len).filter(|&&b| b == b'"')?;
    let valid = !name.is_empty()
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'\\' || b >= 0x80);
    valid.then(|| String::from_utf8_lossy(name))
}

fn method(flags: u32) -> &'static str {
    if flags & ENTRY_DEFLATE != 0 {
        "deflate"
    } else if flags & ENTRY_BZIP2 != 0 {
        "bzip2"
    } else {
        "stored"
    }
}

pub(super) fn extract(
    data: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let phar = parse(data, MAX_ARCHIVE_MEMBERS)?;
    values.insert_key(
        value_key!("archive.format.kind"),
        JsonValue::String("phar".into()),
    );
    values.insert_key(
        value_key!("phar.api_version"),
        JsonValue::String(phar.api_version.clone()),
    );
    if !phar.alias.is_empty() {
        values.insert_key(
            value_key!("phar.alias"),
            JsonValue::String(String::from_utf8_lossy(phar.alias).into_owned()),
        );
    }
    metrics.insert(metric!("phar.stub_size"), phar.stub_size as f64);
    metrics.insert(metric!("phar.manifest_size"), f64::from(phar.manifest_size));

    let mut stats = ArchiveStats::new(AGGS);
    let mut listed = Vec::with_capacity(phar.entries.len() + 1);
    let mut past_end = 0u64;
    let mut list = |member: ArchiveMember, extra: Option<(&str, JsonValue)>| {
        stats.observe(&member, &Reading::of(&member));
        let mut value = member_value(&member);
        if let Some((key, extra)) = extra {
            value.insert(key.into(), extra);
        }
        listed.push(JsonValue::Object(value));
        // A member whose bytes run past the end of the file cannot be sliced.
        let end = member.offsets.data.unwrap_or(0).saturating_add(
            member
                .compression
                .compressed_size
                .unwrap_or(member.size_bytes),
        );
        if end <= data.len() as u64 {
            archive_members.push(member);
        } else {
            past_end += 1;
        }
    };

    let stub = phar.stub_size as u64;
    let mut stub_member = ArchiveMember::new(STUB_NAME.to_string(), stub, EntryType::Regular);
    stub_member.compression = ArchiveCompression::new(Some(stub), Some("stored".into()));
    stub_member.offsets.data = Some(0);
    list(stub_member, None);

    let mut classes = Vec::new();
    let mut object_count = serialized_classes(phar.metadata, &mut classes);
    let mut metadata_size = phar.metadata.len() as u64;
    for entry in &phar.entries {
        object_count += serialized_classes(entry.metadata, &mut classes);
        metadata_size += entry.metadata.len() as u64;
        let mut member = ArchiveMember {
            mtime_unix: Some(i64::from(entry.mtime)),
            crc32: Some(entry.crc32),
            compression: ArchiveCompression::new(
                Some(u64::from(entry.compressed_size)),
                Some(method(entry.flags).to_string()),
            ),
            ..ArchiveMember::new(
                String::from_utf8_lossy(entry.name).into_owned(),
                u64::from(entry.size),
                EntryType::Regular,
            )
        };
        member.offsets.data = Some(entry.offset);
        let mode = (entry.flags & 0o777 != 0).then(|| json!(entry.flags & 0o777));
        list(member, mode.map(|m| ("mode", m)));
    }

    let mut limits = Limits::default();
    if phar.unlisted > 0 {
        limits.push(
            "member-cap",
            format!(
                "listed {MAX_ARCHIVE_MEMBERS} of {} members",
                MAX_ARCHIVE_MEMBERS as u64 + phar.unlisted
            ),
        );
    }
    if past_end > 0 {
        limits.push(
            "truncated",
            format!("{past_end} members run past the end of the file"),
        );
    }
    limits.emit(values, value_key!("phar.limits"));

    values.insert_key(value_key!("archive.members"), JsonValue::Array(listed));
    stats.emit(values, metrics);
    values.insert_key(
        value_key!("archive.format.entry_types"),
        JsonValue::Array(vec![JsonValue::String("regular".into())]),
    );
    metrics.insert(
        metric!("archive.format.regular_count"),
        stats.member_count() as f64,
    );

    metrics.insert(metric!("phar.metadata_size"), metadata_size as f64);
    metrics.insert(metric!("phar.metadata_object_count"), object_count as f64);
    if !classes.is_empty() {
        values.insert_key(
            value_key!("phar.metadata_classes"),
            JsonValue::Array(classes.into_iter().map(JsonValue::String).collect()),
        );
    }
    if let Some(trailer) = &phar.signature {
        values.insert_key(value_key!("phar.signature"), signature(data, trailer));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
