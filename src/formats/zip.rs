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

    values.insert("archive.format.kind", JsonValue::String("zip".into()));

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
    use crate::output::{Metrics, Values};
    use std::io::Cursor;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let _ = extract(bytes, &mut v, &mut m);
        (v, m)
    }

    /// Build an in-memory zip with the given members. Each tuple:
    /// `(path, body, compression_method, last_modified_unix)`.
    fn build_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            for (path, body, method) in entries {
                let opts = SimpleFileOptions::default()
                    .compression_method(*method)
                    .unix_permissions(0o644);
                w.start_file(*path, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn compression_names_are_stable() {
        assert_eq!(compression_method_name(CompressionMethod::Stored), "stored");
        assert_eq!(compression_method_name(CompressionMethod::Deflated), "deflate");
    }

    #[test]
    fn surfaces_member_listing_and_per_member_fields() {
        let z = build_zip(&[
            ("file.txt", b"hello world", CompressionMethod::Stored),
            ("nested/file.bin", b"\x00\x01\x02\x03", CompressionMethod::Deflated),
        ]);
        let (v, m) = run(&z);
        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert_eq!(members.len(), 2);
        let m0 = members[0].as_object().unwrap();
        assert_eq!(m0["path"].as_str(), Some("file.txt"));
        assert_eq!(m0["compression_method"].as_str(), Some("stored"));
        assert_eq!(m0["entry_type"].as_str(), Some("regular"));
        assert_eq!(m.get("archive.member_count"), Some(2.0));
    }

    #[test]
    fn format_kind_set_to_zip() {
        let z = build_zip(&[("a", b"x", CompressionMethod::Stored)]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.format.kind").and_then(|x| x.as_str()),
            Some("zip")
        );
    }

    #[test]
    fn compression_methods_array_unique() {
        let z = build_zip(&[
            ("a", b"x", CompressionMethod::Stored),
            ("b", b"y", CompressionMethod::Stored),
            ("c", b"z", CompressionMethod::Deflated),
        ]);
        let (v, _) = run(&z);
        let methods = v
            .get("archive.compression.methods")
            .and_then(|x| x.as_array())
            .unwrap();
        let names: Vec<&str> = methods.iter().filter_map(|x| x.as_str()).collect();
        // BTreeMap iteration order is alphabetical: deflate, stored.
        assert_eq!(names, vec!["deflate", "stored"]);
    }

    #[test]
    fn compression_ratio_present_when_uncompressed_nonzero() {
        let z = build_zip(&[(
            "big.txt",
            &b"abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij".repeat(20),
            CompressionMethod::Deflated,
        )]);
        let (_, m) = run(&z);
        let r = m.get("archive.compression.ratio").unwrap();
        assert!(r > 0.0 && r < 1.0, "expected ratio in (0,1), got {r}");
    }

    #[test]
    fn jar_signed_shape_detected() {
        let z = build_zip(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", CompressionMethod::Stored),
            ("META-INF/CERT.SF", b"sigfile", CompressionMethod::Stored),
            ("META-INF/CERT.RSA", b"\x00\x01", CompressionMethod::Stored),
            ("Main.class", b"\xca\xfe\xba\xbe", CompressionMethod::Stored),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.signing.jar_signed_shape").and_then(|x| x.as_bool()),
            Some(true)
        );
        // mozilla-extension shape needs cose.manifest + cose.sig; not set here.
        assert!(v.get("archive.signing.mozilla_extension_shape").is_none());
    }

    #[test]
    fn mozilla_extension_shape_detected() {
        let z = build_zip(&[
            ("META-INF/cose.manifest", b"mozcose", CompressionMethod::Stored),
            ("META-INF/cose.sig", b"\xde\xad", CompressionMethod::Stored),
            ("manifest.json", b"{}", CompressionMethod::Stored),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.signing.mozilla_extension_shape")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn empty_zip_emits_empty_member_list() {
        let z = build_zip(&[]);
        let (v, m) = run(&z);
        let members = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
        assert!(members.is_empty());
        assert_eq!(m.get("archive.member_count"), Some(0.0));
    }

    #[test]
    fn non_zip_input_rejected_silently() {
        // Bytes that don't start with PK\x03\x04 — extract returns Err
        // (which expose's dispatcher swallows). Values left empty.
        let (v, _) = run(b"not a zip");
        assert!(v.get("archive.members").is_none());
    }

    #[test]
    fn aggregate_method_counts_per_compression() {
        let z = build_zip(&[
            ("a", b"x", CompressionMethod::Stored),
            ("b", b"y", CompressionMethod::Deflated),
            ("c", b"z", CompressionMethod::Deflated),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.compression.method_counts.stored"), Some(1.0));
        assert_eq!(m.get("archive.compression.method_counts.deflate"), Some(2.0));
    }

    #[test]
    fn truncated_zip_doesnt_crash() {
        // Take a valid zip and chop most of it off.
        let z = build_zip(&[("a", b"hello", CompressionMethod::Stored)]);
        let truncated = &z[..z.len() / 2];
        let (_, _) = run(truncated);
        // No assertions — we only care that it didn't panic.
    }
}
