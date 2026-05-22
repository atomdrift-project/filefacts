//! ZIP archive-index extractor.
//!
//! Reads the central directory only — never decompresses entries. The
//! output is the full member listing, the archive comment, and a few
//! per-entry forensic fields drawn from the central-directory header.
//!
//! Decompression and recursion are the caller's responsibility:
//! `filefacts` describes what's *in* the archive, not what each member
//! *contains*.

// JAR signing manifests have format-defined uppercase names
// (`META-INF/*.SF`, `*.RSA`). The case-sensitive comparison is required.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::io::Cursor;

use serde_json::{Map as JsonMap, Value as JsonValue};
use zip::{CompressionMethod, ZipArchive};

use crate::error::Error;
use crate::output::{Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| Error::malformed("zip", e.to_string()))?;

    values.insert("archive.format.kind", JsonValue::String("zip".into()));

    let has_comment = !archive.comment().is_empty();
    if has_comment {
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

    // Aggregates ported from cleave's ArchiveMetrics. Counted from the
    // central-directory walk; never reads compressed entry bodies.
    let mut file_count: u64 = 0;
    let mut directory_count: u64 = 0;
    let mut max_filename_length: u64 = 0;
    let mut hidden_file_count: u64 = 0;
    let mut path_traversal_count: u64 = 0;
    // ZIP's central-directory walker doesn't read symlink targets
    // (their content lives in the compressed body). `symlink_escape_count`
    // for ZIPs always reports 0 here; tar.rs computes it from the
    // header-resident linkname directly.
    let symlink_escape_count: u64 = 0;
    let mut executable_count: u64 = 0;
    let mut script_count: u64 = 0;
    let mut unicode_filename_count: u64 = 0;
    let mut homoglyph_filename_count: u64 = 0;
    let mut double_extension_count: u64 = 0;
    let mut rtlo_filename_count: u64 = 0;
    let mut nested_archive_count: u64 = 0;
    let mut misplaced_executable_count: u64 = 0;
    let mut zip_bomb_ratio: f64 = 0.0;
    let mut extra_field_size: u64 = 0;
    let mut uses_zip64 = false;

    for i in 0..archive.len() {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| Error::malformed("zip", format!("entry {i}: {e}")))?;

        let name = entry.name().to_string();
        let mut obj = JsonMap::new();
        obj.insert("path".into(), JsonValue::String(name.clone()));
        obj.insert("size_bytes".into(), JsonValue::Number(entry.size().into()));
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

        if let Some(t) = entry
            .last_modified()
            .and_then(crate::scan::zip_datetime_to_unix)
        {
            obj.insert("mtime_unix".into(), JsonValue::Number(t.into()));
            mtimes.push(t);
        }

        if let Some(mode) = entry.unix_mode() {
            obj.insert(
                "mode_octal".into(),
                JsonValue::Number(u64::from(mode).into()),
            );
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

        let uncompressed = entry.size();
        let compressed = entry.compressed_size();
        total_compressed += compressed;
        total_uncompressed += uncompressed;
        *compression_counts.entry(method.into()).or_insert(0) += 1;
        *entry_type_counts.entry(entry_type.into()).or_insert(0) += 1;

        if entry.is_dir() {
            directory_count += 1;
        } else {
            file_count += 1;

            // Per-file compression ratio worst case (zip bomb signal).
            if uncompressed > 0 && compressed > 0 {
                let r = uncompressed as f64 / compressed as f64;
                if r > zip_bomb_ratio {
                    zip_bomb_ratio = r;
                }
            }
        }

        if name.len() as u64 > max_filename_length {
            max_filename_length = name.len() as u64;
        }

        // Filename classification — mirrors cleave's archive aggregates.
        let classification = classify_filename(&name);
        if classification.is_hidden {
            hidden_file_count += 1;
        }
        if classification.has_path_traversal {
            path_traversal_count += 1;
        }
        if classification.is_unicode {
            unicode_filename_count += 1;
        }
        if classification.has_homoglyph {
            homoglyph_filename_count += 1;
        }
        if classification.has_double_extension {
            double_extension_count += 1;
        }
        if classification.has_rtlo {
            rtlo_filename_count += 1;
        }
        if !entry.is_dir() {
            if classification.is_nested_archive {
                nested_archive_count += 1;
            }
            if classification.is_script {
                script_count += 1;
            }
            // Executable: extension OR (unix mode with any exec bit set on a
            // regular file). Symlinks and directories don't count.
            let exec_by_mode = entry
                .unix_mode()
                .is_some_and(|m| m & 0o170_000 != 0o120_000 && m & 0o111 != 0);
            if classification.is_executable || exec_by_mode {
                executable_count += 1;
                if classification.is_misplaced_executable {
                    misplaced_executable_count += 1;
                }
            }
        }

        // Symlink target captured from the central-directory extra field is
        // not exposed by the `zip` crate's high-level API; falling back to
        // entry-name-side path-traversal detection covers the common case.
        // (`tar.rs` has the linkname in the header and can detect escapes
        // exactly.)

        if let Some(extra) = entry.extra_data() {
            extra_field_size += extra.len() as u64;
            if extra_field_has_zip64(extra) {
                uses_zip64 = true;
            }
        }
        // Sentinel sizes in the central directory also indicate Zip64 usage.
        if compressed == 0xFFFF_FFFF || uncompressed == 0xFFFF_FFFF {
            uses_zip64 = true;
        }

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
    // `archive.file_count` and `archive.directory_count` mirror cleave's
    // historical struct field names that traits still reference.
    metrics.insert("archive.file_count", file_count as f64);
    metrics.insert("archive.directory_count", directory_count as f64);
    metrics.insert("archive.total_uncompressed", total_uncompressed as f64);
    metrics.insert("archive.total_compressed", total_compressed as f64);
    if total_uncompressed > 0 {
        let ratio = total_compressed as f64 / total_uncompressed as f64;
        metrics.insert("archive.compression.ratio", ratio);
    }
    for (m, c) in &compression_counts {
        metrics.insert(format!("archive.compression.method_counts.{m}"), *c as f64);
    }
    for (t, c) in &entry_type_counts {
        metrics.insert(
            format!("archive.format.{}_count", t.replace('-', "_")),
            *c as f64,
        );
    }
    metrics.insert("archive.security.setuid_count", setuid as f64);
    metrics.insert("archive.security.setgid_count", setgid as f64);
    metrics.insert("archive.security.sticky_count", sticky as f64);
    metrics.insert(
        "archive.security.world_writable_count",
        world_writable as f64,
    );
    metrics.insert("archive.security.symlink_count", symlinks as f64);
    metrics.insert("archive.security.encrypted_count", encrypted_count as f64);

    // Filename / content aggregates ported from cleave's ArchiveMetrics.
    metrics.insert("archive.max_filename_length", max_filename_length as f64);
    metrics.insert("archive.hidden_file_count", hidden_file_count as f64);
    metrics.insert("archive.path_traversal_count", path_traversal_count as f64);
    metrics.insert("archive.symlink_escape_count", symlink_escape_count as f64);
    metrics.insert("archive.executable_count", executable_count as f64);
    metrics.insert("archive.script_count", script_count as f64);
    metrics.insert(
        "archive.unicode_filename_count",
        unicode_filename_count as f64,
    );
    metrics.insert(
        "archive.homoglyph_filename_count",
        homoglyph_filename_count as f64,
    );
    metrics.insert(
        "archive.double_extension_count",
        double_extension_count as f64,
    );
    metrics.insert("archive.rtlo_filename_count", rtlo_filename_count as f64);
    metrics.insert("archive.nested_archive_count", nested_archive_count as f64);
    metrics.insert(
        "archive.misplaced_executable_count",
        misplaced_executable_count as f64,
    );
    if zip_bomb_ratio > 0.0 {
        metrics.insert("archive.zip_bomb_ratio", zip_bomb_ratio);
    }
    metrics.insert("archive.extra_field_size", extra_field_size as f64);
    if uses_zip64 {
        metrics.insert("archive.uses_zip64", 1.0);
    }
    if has_comment {
        metrics.insert("archive.has_comment", 1.0);
    }

    if !mtimes.is_empty() {
        let min = *mtimes.iter().min().unwrap_or(&0);
        let max = *mtimes.iter().max().unwrap_or(&0);
        values.insert("archive.timing.mtime_min", JsonValue::Number(min.into()));
        values.insert("archive.timing.mtime_max", JsonValue::Number(max.into()));
        metrics.insert("archive.timing.mtime_spread_seconds", (max - min) as f64);
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
        values.insert("archive.signing.jar_signed_shape", JsonValue::Bool(true));
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

/// Classification flags for a single archive entry path, derived from
/// the name alone. Cleave's `ArchiveMetrics` aggregates roll these up
/// across the archive; filefacts computes them once per member.
#[derive(Default)]
pub(super) struct FilenameClass {
    pub(super) is_hidden: bool,
    pub(super) has_path_traversal: bool,
    pub(super) is_unicode: bool,
    pub(super) has_homoglyph: bool,
    pub(super) has_double_extension: bool,
    pub(super) has_rtlo: bool,
    pub(super) is_executable: bool,
    pub(super) is_script: bool,
    pub(super) is_nested_archive: bool,
    pub(super) is_misplaced_executable: bool,
}

/// Classify a member path. Read-only; the same rules apply to ZIP and
/// TAR entries (both call this helper).
pub(super) fn classify_filename(path: &str) -> FilenameClass {
    let mut c = FilenameClass::default();

    // Hidden: any path component starts with `.` (excluding `.`/`..`).
    c.is_hidden = path
        .split('/')
        .any(|p| p.starts_with('.') && p != "." && p != "..");

    // Path traversal: any `..` component, or absolute path (leading `/`
    // or Windows drive letter).
    c.has_path_traversal = path.split('/').any(|p| p == "..")
        || path.starts_with('/')
        || path
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
            && path[1..].starts_with(":\\");

    // Non-ASCII content anywhere in the path.
    c.is_unicode = path.chars().any(|ch| !ch.is_ascii());

    // Homoglyphs: Cyrillic / Greek look-alikes for ASCII Latin letters.
    // Small curated set — generic Unicode security is out of scope.
    c.has_homoglyph = path.chars().any(is_homoglyph_char);

    // Right-to-left override and related bidi-format control chars.
    c.has_rtlo = path.chars().any(|ch| {
        matches!(
            ch as u32,
            0x202A..=0x202E | 0x2066..=0x2069
        )
    });

    // Filename basename for extension checks.
    let basename = path.rsplit('/').next().unwrap_or(path);
    let lower = basename.to_ascii_lowercase();

    // Double extension: `something.<inner>.<outer>` where outer is
    // executable and inner is a benign-looking document/text suffix.
    if let Some((stem, outer)) = lower.rsplit_once('.') {
        if is_executable_extension(outer) {
            if let Some((_, inner)) = stem.rsplit_once('.') {
                const SAFE_LOOKING: &[&str] = &[
                    "txt", "pdf", "doc", "docx", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "csv",
                    "xls", "xlsx", "rtf",
                ];
                if SAFE_LOOKING.contains(&inner) {
                    c.has_double_extension = true;
                }
            }
        }
    }

    let extension = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    c.is_executable = is_executable_extension(extension);
    c.is_script = is_script_extension(extension);
    c.is_nested_archive = is_archive_extension(extension);

    if c.is_executable {
        // Heuristic: PE executables should live in /bin or Windows
        // system dirs; .so/.dylib in /lib*. Anything else is "misplaced".
        let is_unix_lib = matches!(extension, "so" | "dylib");
        let is_pe = matches!(extension, "exe" | "dll" | "sys" | "scr");
        let in_bin = path.starts_with("bin/")
            || path.starts_with("usr/bin/")
            || path.starts_with("sbin/")
            || path.starts_with("usr/sbin/")
            || path.starts_with("usr/local/bin/");
        let in_lib = path.starts_with("lib/")
            || path.starts_with("lib64/")
            || path.starts_with("usr/lib/")
            || path.starts_with("usr/lib64/")
            || path.starts_with("usr/local/lib/");
        if is_unix_lib && !in_lib {
            c.is_misplaced_executable = true;
        } else if is_pe && !path.to_ascii_lowercase().contains("bin/") {
            // PE binaries inside an archive that don't sit under any
            // `bin/`-like prefix are the canonical lure shape.
            c.is_misplaced_executable = true;
        } else if matches!(extension, "bin" | "elf") && !in_bin {
            c.is_misplaced_executable = true;
        }
    }

    c
}

fn is_executable_extension(ext: &str) -> bool {
    matches!(
        ext,
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "cpl"
            | "msi"
            | "so"
            | "dylib"
            | "bin"
            | "elf"
            | "out"
            | "app"
    )
}

fn is_script_extension(ext: &str) -> bool {
    matches!(
        ext,
        "sh" | "bash"
            | "zsh"
            | "ksh"
            | "csh"
            | "fish"
            | "py"
            | "pyc"
            | "pyo"
            | "pl"
            | "pm"
            | "rb"
            | "js"
            | "mjs"
            | "cjs"
            | "ps1"
            | "psm1"
            | "psd1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "wsf"
            | "wsh"
            | "lua"
            | "php"
    )
}

fn is_archive_extension(ext: &str) -> bool {
    matches!(
        ext,
        "zip"
            | "jar"
            | "war"
            | "ear"
            | "apk"
            | "ipa"
            | "xpi"
            | "crx"
            | "nupkg"
            | "tar"
            | "gz"
            | "tgz"
            | "bz2"
            | "tbz2"
            | "xz"
            | "txz"
            | "zst"
            | "tzst"
            | "7z"
            | "rar"
            | "cab"
            | "iso"
            | "deb"
            | "rpm"
            | "msi"
            | "pkg"
    )
}

/// Returns true for characters commonly used in homoglyph attacks
/// (Cyrillic and Greek glyphs that visually mimic ASCII Latin letters).
fn is_homoglyph_char(ch: char) -> bool {
    matches!(
        ch,
        // Cyrillic look-alikes for a/c/e/o/p/x/у (and uppercase).
        'а' | 'с' | 'е' | 'о' | 'р' | 'х' | 'у' | 'А' | 'В' | 'С' | 'Е' | 'Н'
            | 'К' | 'М' | 'О' | 'Р' | 'Т' | 'Х'
        // Greek look-alikes.
            | 'Α' | 'Β' | 'Ε' | 'Ζ' | 'Η' | 'Ι' | 'Κ' | 'Μ' | 'Ν' | 'Ο'
            | 'Ρ' | 'Τ' | 'Υ' | 'Χ'
            | 'ο' | 'ν'
    )
}

/// Scan a raw central-directory extra-field blob for the Zip64
/// extended-information field (tag `0x0001`). Returns true on first
/// match. Format: `[u16 tag][u16 size][size bytes]` repeating.
fn extra_field_has_zip64(extra: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let tag = u16::from_le_bytes([extra[i], extra[i + 1]]);
        let size = u16::from_le_bytes([extra[i + 2], extra[i + 3]]) as usize;
        if tag == 0x0001 {
            return true;
        }
        let Some(next) = i.checked_add(4).and_then(|n| n.checked_add(size)) else {
            break;
        };
        i = next;
    }
    false
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
        assert_eq!(
            compression_method_name(CompressionMethod::Deflated),
            "deflate"
        );
    }

    #[test]
    fn surfaces_member_listing_and_per_member_fields() {
        let z = build_zip(&[
            ("file.txt", b"hello world", CompressionMethod::Stored),
            (
                "nested/file.bin",
                b"\x00\x01\x02\x03",
                CompressionMethod::Deflated,
            ),
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
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\n",
                CompressionMethod::Stored,
            ),
            ("META-INF/CERT.SF", b"sigfile", CompressionMethod::Stored),
            ("META-INF/CERT.RSA", b"\x00\x01", CompressionMethod::Stored),
            ("Main.class", b"\xca\xfe\xba\xbe", CompressionMethod::Stored),
        ]);
        let (v, _) = run(&z);
        assert_eq!(
            v.get("archive.signing.jar_signed_shape")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
        // mozilla-extension shape needs cose.manifest + cose.sig; not set here.
        assert!(v.get("archive.signing.mozilla_extension_shape").is_none());
    }

    #[test]
    fn mozilla_extension_shape_detected() {
        let z = build_zip(&[
            (
                "META-INF/cose.manifest",
                b"mozcose",
                CompressionMethod::Stored,
            ),
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
        // (which filefacts' dispatcher swallows). Values left empty.
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
        assert_eq!(
            m.get("archive.compression.method_counts.deflate"),
            Some(2.0)
        );
    }

    #[test]
    fn truncated_zip_doesnt_crash() {
        // Take a valid zip and chop most of it off.
        let z = build_zip(&[("a", b"hello", CompressionMethod::Stored)]);
        let truncated = &z[..z.len() / 2];
        let (_, _) = run(truncated);
        // No assertions — we only care that it didn't panic.
    }

    // ---- Ported `ArchiveMetrics` aggregates ----

    #[test]
    fn file_and_directory_counts_track_member_kinds() {
        // ZipWriter::add_directory creates a real directory entry.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(0o644);
            w.add_directory("dir/", opts).unwrap();
            w.start_file("dir/a", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("dir/b", opts).unwrap();
            w.write_all(b"y").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.file_count"), Some(2.0));
        assert_eq!(m.get("archive.directory_count"), Some(1.0));
    }

    #[test]
    fn totals_and_compression_ratio() {
        let z = build_zip(&[
            ("a", b"abcdefghij", CompressionMethod::Stored),
            ("b", b"klmnop", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.total_uncompressed"), Some(16.0));
        assert!(m.get("archive.total_compressed").unwrap() >= 16.0);
        // Canonical nested namespace only — flat `archive.compression_ratio`
        // alias retired.
        assert!(m.get("archive.compression.ratio").is_some());
    }

    #[test]
    fn hidden_file_count_includes_dotfiles_anywhere_in_path() {
        let z = build_zip(&[
            (".hidden", b"x", CompressionMethod::Stored),
            ("normal", b"x", CompressionMethod::Stored),
            ("nested/.dot/file", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.hidden_file_count"), Some(2.0));
    }

    #[test]
    fn path_traversal_count_flags_dotdot_components() {
        let z = build_zip(&[
            ("../escape", b"x", CompressionMethod::Stored),
            ("ok/file", b"x", CompressionMethod::Stored),
            ("/absolute", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.path_traversal_count"), Some(2.0));
    }

    #[test]
    fn script_and_executable_counts() {
        let z = build_zip(&[
            ("run.sh", b"#!/bin/sh\n", CompressionMethod::Stored),
            ("setup.py", b"x", CompressionMethod::Stored),
            ("payload.exe", b"x", CompressionMethod::Stored),
            ("readme.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.script_count"), Some(2.0));
        assert_eq!(m.get("archive.executable_count"), Some(1.0));
    }

    #[test]
    fn unicode_and_rtlo_filename_flags() {
        // U+202E is RIGHT-TO-LEFT OVERRIDE; payload.exe rendered as fxe.daolyap.
        let rtlo_name = "payload\u{202e}fdp.exe";
        let z = build_zip(&[
            ("résumé.pdf", b"x", CompressionMethod::Stored),
            (rtlo_name, b"x", CompressionMethod::Stored),
            ("ascii.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.unicode_filename_count"), Some(2.0));
        assert_eq!(m.get("archive.rtlo_filename_count"), Some(1.0));
    }

    #[test]
    fn double_extension_flag() {
        let z = build_zip(&[
            ("invoice.pdf.exe", b"x", CompressionMethod::Stored),
            ("photo.jpg.scr", b"x", CompressionMethod::Stored),
            ("ok.tar.gz", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        // pdf+exe and jpg+scr both match; tar+gz doesn't (gz isn't executable).
        assert_eq!(m.get("archive.double_extension_count"), Some(2.0));
    }

    #[test]
    fn nested_archive_count() {
        let z = build_zip(&[
            ("inner.zip", b"PK\x05\x06", CompressionMethod::Stored),
            ("payload.tar.gz", b"x", CompressionMethod::Stored),
            ("readme.txt", b"x", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.nested_archive_count"), Some(2.0));
    }

    #[test]
    fn has_comment_flag_when_archive_has_global_comment() {
        // Build a zip with a comment.
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.set_raw_comment(b"hello world".to_vec().into_boxed_slice());
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            w.start_file("a", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());
        assert_eq!(m.get("archive.has_comment"), Some(1.0));
    }

    /// Canonical key list emitted by the ZIP extractor. The test fails
    /// loudly when filefacts stops emitting any of these keys for a
    /// realistic archive — protects traits referencing them from
    /// silent disappearance.
    #[test]
    fn full_archive_key_set_emitted_for_realistic_zip() {
        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut w = ZipWriter::new(&mut buf);
            w.set_raw_comment(b"build comment".to_vec().into_boxed_slice());
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644)
                .last_modified_time(zip::DateTime::default());
            w.add_directory("dir/", opts).unwrap();
            w.start_file("dir/a.txt", opts).unwrap();
            w.write_all(b"hello world").unwrap();
            w.start_file("dir/script.sh", opts.unix_permissions(0o755))
                .unwrap();
            w.write_all(b"#!/bin/sh\n").unwrap();
            w.start_file("payload.exe", opts).unwrap();
            w.write_all(b"\x4d\x5a").unwrap();
            w.finish().unwrap();
        }
        let (_, m) = run(&buf.into_inner());

        // Every key listed here must remain present — adding new keys is fine;
        // dropping one is a breaking change requiring a trait/comment update.
        for key in [
            "archive.member_count",
            "archive.file_count",
            "archive.directory_count",
            "archive.total_uncompressed",
            "archive.total_compressed",
            "archive.compression.ratio",
            "archive.max_filename_length",
            "archive.hidden_file_count",
            "archive.path_traversal_count",
            "archive.symlink_escape_count",
            "archive.executable_count",
            "archive.script_count",
            "archive.unicode_filename_count",
            "archive.homoglyph_filename_count",
            "archive.double_extension_count",
            "archive.rtlo_filename_count",
            "archive.nested_archive_count",
            "archive.misplaced_executable_count",
            "archive.extra_field_size",
            "archive.security.setuid_count",
            "archive.security.setgid_count",
            "archive.security.sticky_count",
            "archive.security.world_writable_count",
            "archive.security.symlink_count",
            "archive.security.encrypted_count",
            "archive.has_comment",
        ] {
            assert!(
                m.get(key).is_some(),
                "missing required archive metric key: {key}"
            );
        }
    }

    #[test]
    fn max_filename_length_tracks_longest_entry() {
        let long = "a".repeat(120);
        let z = build_zip(&[
            ("short", b"x", CompressionMethod::Stored),
            (long.as_str(), b"y", CompressionMethod::Stored),
        ]);
        let (_, m) = run(&z);
        assert_eq!(m.get("archive.max_filename_length"), Some(120.0));
    }
}
