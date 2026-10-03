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
//! The layout follows `ext/phar/phar.c`: the stub ends at the first
//! `__HALT_COMPILER();`, every integer is little-endian, and the manifest is
//! at most 100 MB.
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

use super::archive_stats::{Agg, ArchiveStats, Reading, Scope, Shape, member_value};
use super::bounded::{MAX_ARCHIVE_MEMBERS, push_limit};
use crate::bytes;
use crate::error::Error;
use crate::metric;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};
use crate::value_key;

/// What ends the stub. PHP's phar reader looks for exactly this spelling.
const HALT_TOKEN: &[u8] = b"__HALT_COMPILER();";

/// The name the tar- and zip-based phar formats store the stub under.
const STUB_NAME: &str = ".phar/stub.php";

/// The largest manifest PHP will read.
const MAX_MANIFEST_SIZE: u32 = 100 << 20;

/// The trailer magic every signed phar ends with.
const SIGNATURE_MAGIC: &[u8; 4] = b"GBMB";

/// Global flag: the archive carries a signature trailer.
const FLAG_SIGNATURE: u32 = 0x0001_0000;

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

/// A parsed native phar: everything but the members' contents.
pub(crate) struct Phar<'a> {
    /// Where the stub ends and the manifest's length field starts.
    stub_size: usize,
    /// The manifest's declared length, not counting its length field.
    manifest_size: u32,
    /// `major.minor.release`.
    api_version: String,
    alias: &'a [u8],
    /// The global metadata, PHP-serialized.
    metadata: &'a [u8],
    entries: Vec<Entry<'a>>,
    /// Entries past [`MAX_ARCHIVE_MEMBERS`], counted but not parsed into the list.
    unlisted: u64,
    signature: Option<Signature>,
}

/// One manifest entry.
struct Entry<'a> {
    name: &'a [u8],
    size: u32,
    mtime: u32,
    compressed_size: u32,
    crc32: u32,
    flags: u32,
    metadata: &'a [u8],
    /// Where the content starts, from the start of the file.
    offset: u64,
}

/// The signature trailer.
struct Signature {
    algorithm: &'static str,
    digest: Vec<u8>,
    /// Whether the digest matches the signed bytes; `None` for an OpenSSL
    /// signature, which needs the archive's public key to check.
    valid: Option<bool>,
}

/// Whether `data` is a native phar, by a parse of its manifest. Cheap for
/// most input: it needs a trailing `GBMB` (every signed phar), or a PHP or
/// shebang opening (the usual stub of an unsigned one), before it searches.
pub(crate) fn is_phar(data: &[u8]) -> bool {
    let signed = data.ends_with(SIGNATURE_MAGIC);
    let head = data.trim_ascii_start();
    let php_stub = head.starts_with(b"<?") || head.starts_with(b"#!");
    (signed || php_stub) && parse(data).is_ok()
}

/// Parse the stub boundary, manifest and signature of a native phar.
pub(crate) fn parse(data: &[u8]) -> Result<Phar<'_>, Error> {
    let halt = memchr::memmem::find(data, HALT_TOKEN)
        .ok_or_else(|| Error::malformed("phar", "no __HALT_COMPILER(); stub end"))?;
    let stub_size = stub_end(data, halt + HALT_TOKEN.len());

    let manifest_size = bytes::u32_le(data, stub_size)
        .ok_or_else(|| Error::malformed("phar", "truncated manifest length"))?;
    if manifest_size > MAX_MANIFEST_SIZE {
        return Err(Error::malformed("phar", "manifest larger than 100 MB"));
    }
    let manifest_start = stub_size + 4;
    let data_offset = manifest_start + manifest_size as usize;
    let manifest = data
        .get(manifest_start..data_offset)
        .ok_or_else(|| Error::malformed("phar", "manifest extends past end of file"))?;

    let mut r = bytes::Reader::new(manifest);
    let count = r.u32_le().ok_or_else(|| truncated("member count"))?;
    let [hi, lo] = r.array::<2>().ok_or_else(|| truncated("API version"))?;
    if hi >> 4 != 1 {
        return Err(Error::malformed("phar", "unsupported manifest API version"));
    }
    let api_version = format!("{}.{}.{}", hi >> 4, hi & 0xf, lo >> 4);
    let flags = r.u32_le().ok_or_else(|| truncated("global flags"))?;
    let alias = length_prefixed(&mut r).ok_or_else(|| truncated("alias"))?;
    let metadata = length_prefixed(&mut r).ok_or_else(|| truncated("metadata"))?;

    let mut entries = Vec::new();
    let mut offset = data_offset as u64;
    for _ in 0..count {
        let name = length_prefixed(&mut r).ok_or_else(|| truncated("member name"))?;
        if name.is_empty() {
            return Err(Error::malformed("phar", "member with an empty name"));
        }
        let (Some(size), Some(mtime), Some(compressed_size), Some(crc32), Some(entry_flags)) =
            (r.u32_le(), r.u32_le(), r.u32_le(), r.u32_le(), r.u32_le())
        else {
            return Err(truncated("member entry"));
        };
        let entry_metadata = length_prefixed(&mut r).ok_or_else(|| truncated("member metadata"))?;
        if entries.len() < MAX_ARCHIVE_MEMBERS {
            entries.push(Entry {
                name,
                size,
                mtime,
                compressed_size,
                crc32,
                flags: entry_flags,
                metadata: entry_metadata,
                offset,
            });
        }
        offset = offset.saturating_add(u64::from(compressed_size));
    }

    let signature = if flags & FLAG_SIGNATURE != 0 {
        Some(signature(data)?)
    } else {
        None
    };

    Ok(Phar {
        stub_size,
        manifest_size,
        api_version,
        alias,
        metadata,
        unlisted: u64::from(count).saturating_sub(entries.len() as u64),
        entries,
        signature,
    })
}

/// A `u32` length and that many bytes.
fn length_prefixed<'a>(r: &mut bytes::Reader<'a>) -> Option<&'a [u8]> {
    let len = r.u32_le()?;
    r.bytes(bytes::sat_usize(len))
}

fn truncated(what: &str) -> Error {
    Error::malformed("phar", format!("manifest truncated in the {what}"))
}

/// Where the stub ends, `after_token` being the byte after
/// `__HALT_COMPILER();`. As `phar.c` reads it: a following ` ?>` (or `\n?>`)
/// belongs to the stub, and so does one newline after that.
fn stub_end(data: &[u8], after_token: usize) -> usize {
    let rest = data.get(after_token..).unwrap_or_default();
    let mut end = after_token;
    if let [b' ' | b'\n', b'?', b'>', tail @ ..] = rest {
        end += 3;
        end += match tail {
            [b'\r', b'\n', ..] => 2,
            [b'\n', ..] => 1,
            _ => 0,
        };
    }
    end
}

/// Read the signature trailer: `<signature><flags u32>GBMB`, with an OpenSSL
/// signature's length between the two. The signed bytes are everything before
/// the signature.
fn signature(data: &[u8]) -> Result<Signature, Error> {
    let bad = |detail: &str| Error::malformed("phar", format!("signature trailer {detail}"));
    if !data.ends_with(SIGNATURE_MAGIC) {
        return Err(bad("missing its GBMB magic"));
    }
    let flags_at = data.len().checked_sub(8).ok_or_else(|| bad("truncated"))?;
    let kind = bytes::u32_le(data, flags_at).ok_or_else(|| bad("truncated"))?;
    let (algorithm, digest_len, openssl) = match kind {
        0x01 => ("md5", 16, false),
        0x02 => ("sha1", 20, false),
        0x03 => ("sha256", 32, false),
        0x04 => ("sha512", 64, false),
        0x10 => ("openssl", 0, true),
        0x11 => ("openssl_sha256", 0, true),
        0x12 => ("openssl_sha512", 0, true),
        _ => return Err(bad("names an unknown algorithm")),
    };
    let (start, end) = if openssl {
        let len_at = flags_at.checked_sub(4).ok_or_else(|| bad("truncated"))?;
        let len = bytes::u32_le(data, len_at).ok_or_else(|| bad("truncated"))? as usize;
        (
            len_at.checked_sub(len).ok_or_else(|| bad("truncated"))?,
            len_at,
        )
    } else {
        (
            flags_at
                .checked_sub(digest_len)
                .ok_or_else(|| bad("truncated"))?,
            flags_at,
        )
    };
    let digest = data.get(start..end).ok_or_else(|| bad("truncated"))?;
    let signed = data.get(..start).unwrap_or_default();
    let valid = match algorithm {
        "md5" => Some(Md5::digest(signed).as_slice() == digest),
        "sha1" => Some(Sha1::digest(signed).as_slice() == digest),
        "sha256" => Some(Sha256::digest(signed).as_slice() == digest),
        "sha512" => Some(Sha512::digest(signed).as_slice() == digest),
        _ => None,
    };
    Ok(Signature {
        algorithm,
        digest: digest.to_vec(),
        valid,
    })
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
    let phar = parse(data)?;
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
        let mut value = member_value(&member, Shape::FULL);
        if let Some((key, extra)) = extra {
            value.insert(key.into(), extra);
        }
        listed.push(JsonValue::Object(value));
        // A member whose bytes run past the end of the file cannot be sliced.
        let end = member.offsets.data.unwrap_or(0).saturating_add(
            member
                .compression
                .as_ref()
                .and_then(|c| c.compressed_size)
                .unwrap_or(member.size_bytes),
        );
        if end <= data.len() as u64 {
            archive_members.push(member);
        } else {
            past_end += 1;
        }
    };

    let stub = phar.stub_size as u64;
    list(
        ArchiveMember {
            path: STUB_NAME.to_string(),
            size_bytes: stub,
            entry_type: Some("regular".to_string()),
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: Some(ArchiveCompression {
                compressed_size: Some(stub),
                method: Some("stored".to_string()),
            }),
            ownership: None,
            offsets: ArchiveOffsets {
                header: None,
                data: Some(0),
                central_header: None,
            },
        },
        None,
    );

    let mut classes = Vec::new();
    let mut object_count = serialized_classes(phar.metadata, &mut classes);
    let mut metadata_size = phar.metadata.len() as u64;
    for entry in &phar.entries {
        object_count += serialized_classes(entry.metadata, &mut classes);
        metadata_size += entry.metadata.len() as u64;
        let member = ArchiveMember {
            path: String::from_utf8_lossy(entry.name).into_owned(),
            size_bytes: u64::from(entry.size),
            entry_type: Some("regular".to_string()),
            mtime_unix: Some(i64::from(entry.mtime)),
            linkname: None,
            host_os: None,
            crc32: Some(entry.crc32),
            encrypted: false,
            compression: Some(ArchiveCompression {
                compressed_size: Some(u64::from(entry.compressed_size)),
                method: Some(method(entry.flags).to_string()),
            }),
            ownership: None,
            offsets: ArchiveOffsets {
                header: None,
                data: Some(entry.offset),
                central_header: None,
            },
        };
        let mode = (entry.flags & 0o777 != 0).then(|| json!(entry.flags & 0o777));
        list(member, mode.map(|m| ("mode", m)));
    }

    if phar.unlisted > 0 {
        push_limit(
            values,
            value_key!("phar.limits"),
            "member-cap",
            format!(
                "listed {MAX_ARCHIVE_MEMBERS} of {} members",
                MAX_ARCHIVE_MEMBERS as u64 + phar.unlisted
            ),
        );
    }
    if past_end > 0 {
        push_limit(
            values,
            value_key!("phar.limits"),
            "truncated",
            format!("{past_end} members run past the end of the file"),
        );
    }

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
    if let Some(signature) = phar.signature {
        let mut value = serde_json::Map::new();
        value.insert("algorithm".into(), signature.algorithm.into());
        value.insert(
            "digest".into(),
            super::common::hex_encode(&signature.digest).into(),
        );
        if let Some(valid) = signature.valid {
            value.insert("valid".into(), valid.into());
        }
        values.insert_key(value_key!("phar.signature"), JsonValue::Object(value));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
