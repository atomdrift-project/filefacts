//! ZIP archive-index extractor.
//!
//! Reads the central directory only — never decompresses entries. The
//! output is the full member listing, the archive comment, and a few
//! per-entry forensic fields drawn from the central-directory header.
//!
//! Decompression and recursion are the caller's responsibility:
//! `expose` describes what's *in* the archive, not what each member
//! *contains*.

// JAR signing manifests have format-defined uppercase names
// (`META-INF/*.SF`, `*.RSA`). The case-sensitive comparison is required.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::io::Cursor;

use serde_json::{Map as JsonMap, Value as JsonValue};
use zip::{CompressionMethod, ZipArchive};

use crate::error::Error;
use crate::output::{Metrics, Values};

pub(super) fn extract(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| Error::malformed("zip", e.to_string()))?;

    values.insert("archive.format", JsonValue::String("zip".into()));

    if !archive.comment().is_empty() {
        let comment = String::from_utf8_lossy(archive.comment()).into_owned();
        values.insert("archive.comment", JsonValue::String(comment));
    }

    let mut members: Vec<JsonValue> = Vec::with_capacity(archive.len());
    let mut compression_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut entry_type_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut total_compressed: u64 = 0;
    let mut total_uncompressed: u64 = 0;
    let mut mtimes: Vec<i64> = Vec::new();
    let mut setuid = 0u64;
    let mut setgid = 0u64;
    let mut sticky = 0u64;
    let mut world_writable = 0u64;
    let mut symlinks = 0u64;
    let mut encrypted_count = 0u64;

    for i in 0..archive.len() {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| Error::malformed("zip", format!("entry {i}: {e}")))?;

        let mut obj = JsonMap::new();
        obj.insert("path".into(), JsonValue::String(entry.name().to_string()));
        obj.insert(
            "size_bytes".into(),
            JsonValue::Number(entry.size().into()),
        );
        obj.insert(
            "compressed_size".into(),
            JsonValue::Number(entry.compressed_size().into()),
        );
        let method = compression_method_name(entry.compression());
        obj.insert(
            "compression_method".into(),
            JsonValue::String(method.into()),
        );
        if entry.encrypted() {
            obj.insert("encrypted".into(), JsonValue::Bool(true));
            encrypted_count += 1;
        }

        if let Some(t) = entry.last_modified().and_then(crate::scan::zip_datetime_to_unix) {
            obj.insert("mtime_unix".into(), JsonValue::Number(t.into()));
            mtimes.push(t);
        }

        if let Some(mode) = entry.unix_mode() {
            obj.insert("mode_octal".into(), JsonValue::Number(u64::from(mode).into()));
            if mode & 0o4000 != 0 {
                setuid += 1;
            }
            if mode & 0o2000 != 0 {
                setgid += 1;
            }
            if mode & 0o1000 != 0 {
                sticky += 1;
            }
            if mode & 0o002 != 0 {
                world_writable += 1;
            }
        }

        let entry_type = if entry.is_dir() {
            "directory"
        } else if entry
            .unix_mode()
            .is_some_and(|m| m & 0o170_000 == 0o120_000)
        {
            symlinks += 1;
            "symlink"
        } else {
            "regular"
        };
        obj.insert("entry_type".into(), JsonValue::String(entry_type.into()));

        total_compressed += entry.compressed_size();
        total_uncompressed += entry.size();
        *compression_counts.entry(method.into()).or_insert(0) += 1;
        *entry_type_counts.entry(entry_type.into()).or_insert(0) += 1;

        members.push(JsonValue::Object(obj));
    }

    values.insert("archive.members", JsonValue::Array(members));

    let methods: Vec<JsonValue> = compression_counts
        .keys()
        .map(|k| JsonValue::String(k.clone()))
        .collect();
    values.insert("archive.compression.methods", JsonValue::Array(methods));

    let entry_types: Vec<JsonValue> = entry_type_counts
        .keys()
        .map(|k| JsonValue::String(k.clone()))
        .collect();
    values.insert("archive.format.entry_types", JsonValue::Array(entry_types));

    // Aggregate metrics. Counts/ratios/spreads go here; verbatim values
    // (the lists above) live in `values`.
    metrics.insert("archive.member_count", archive.len() as f64);
    if total_uncompressed > 0 {
        metrics.insert(
            "archive.compression.ratio",
            total_compressed as f64 / total_uncompressed as f64,
        );
    }
    for (m, c) in &compression_counts {
        metrics.insert(format!("archive.compression.method_counts.{m}"), *c as f64);
    }
    for (t, c) in &entry_type_counts {
        metrics.insert(format!("archive.format.{}_count", t.replace('-', "_")), *c as f64);
    }
    metrics.insert("archive.security.setuid_count", setuid as f64);
    metrics.insert("archive.security.setgid_count", setgid as f64);
    metrics.insert("archive.security.sticky_count", sticky as f64);
    metrics.insert("archive.security.world_writable_count", world_writable as f64);
    metrics.insert("archive.security.symlink_count", symlinks as f64);
    metrics.insert("archive.security.encrypted_count", encrypted_count as f64);

    if !mtimes.is_empty() {
        let min = *mtimes.iter().min().unwrap_or(&0);
        let max = *mtimes.iter().max().unwrap_or(&0);
        values.insert("archive.timing.mtime_min", JsonValue::Number(min.into()));
        values.insert("archive.timing.mtime_max", JsonValue::Number(max.into()));
        metrics.insert(
            "archive.timing.mtime_spread_seconds",
            (max - min) as f64,
        );
        let unique: std::collections::BTreeSet<i64> = mtimes.iter().copied().collect();
        metrics.insert("archive.timing.mtime_unique_count", unique.len() as f64);
    }

    // Mozilla / JAR signing-pipeline detection: existence of the
    // signature-chain files in `META-INF/` is a benign-build attestation
    // (not a cryptographic verification). Emit the structural marker; the
    // consumer decides what to do with it.
    let signed_marker = members_includes(&archive, "META-INF/cose.manifest")
        && members_includes(&archive, "META-INF/cose.sig");
    if signed_marker {
        values.insert(
            "archive.signing.mozilla_extension_shape",
            JsonValue::Bool(true),
        );
    }

    // Also report `archive.signing.jar_signed_shape` when META-INF/*.SF
    // and META-INF/*.RSA both exist.
    let jar_signed_shape = archive_names(&archive)
        .any(|n| n.starts_with("META-INF/") && n.ends_with(".SF"))
        && archive_names(&archive)
            .any(|n| n.starts_with("META-INF/") && (n.ends_with(".RSA") || n.ends_with(".DSA")));
    if jar_signed_shape {
        values.insert(
            "archive.signing.jar_signed_shape",
            JsonValue::Bool(true),
        );
    }

    Ok(())
}

fn archive_names<R: std::io::Read + std::io::Seek>(
    archive: &ZipArchive<R>,
) -> impl Iterator<Item = &str> {
    archive.file_names()
}

fn members_includes<R: std::io::Read + std::io::Seek>(
    archive: &ZipArchive<R>,
    needle: &str,
) -> bool {
    archive.file_names().any(|n| n == needle)
}

fn compression_method_name(method: CompressionMethod) -> &'static str {
    match method {
        CompressionMethod::Stored => "stored",
        CompressionMethod::Deflated => "deflate",
        CompressionMethod::Bzip2 => "bzip2",
        CompressionMethod::Zstd => "zstd",
        CompressionMethod::Lzma => "lzma",
        CompressionMethod::Xz => "xz",
        CompressionMethod::Aes => "aes",
        _ => "other",
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;

    #[test]
    fn compression_names_are_stable() {
        assert_eq!(compression_method_name(CompressionMethod::Stored), "stored");
        assert_eq!(compression_method_name(CompressionMethod::Deflated), "deflate");
    }
}
