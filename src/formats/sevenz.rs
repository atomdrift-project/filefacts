//! 7z archive-header extractor.
//!
//! The 7z format keeps its member table in the next-header section. Reading it
//! gives consumers paths, sizes, timestamps, compression chains, and payload
//! encryption without touching member contents. Header-encrypted archives
//! cannot disclose a member table without a password and return a normal
//! malformed-format error, just as an unreadable ZIP central directory does.

use std::io::Cursor;

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::error::Error;
use crate::metric;
use crate::output::{ArchiveCompression, ArchiveMember, ArchiveOffsets, Metrics, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> Result<(), Error> {
    let password = sevenz_rust::Password::empty();
    let archive = sevenz_rust::Archive::read(
        &mut Cursor::new(bytes),
        bytes.len() as u64,
        password.as_ref(),
    )
    .map_err(|err| Error::malformed("7z", err.to_string()))?;

    values.insert("archive.format.kind", JsonValue::String("7z".into()));

    let folder_methods: Vec<Vec<&'static str>> = archive
        .folders
        .iter()
        .map(|folder| {
            folder
                .coders
                .iter()
                .map(|coder| method_name(coder.decompression_method_id()))
                .collect()
        })
        .collect();

    let mut members = Vec::with_capacity(archive.files.len());
    let mut total_size = 0u64;
    let mut total_compressed = 0u64;
    let mut file_count = 0u64;
    let mut directory_count = 0u64;
    let mut executable_count = 0u64;
    let mut script_count = 0u64;
    let mut nested_archive_count = 0u64;
    let mut traversal_count = 0u64;
    let mut encrypted_count = 0u64;

    for (index, entry) in archive.files.iter().enumerate() {
        let path = entry.name().replace('\\', "/");
        let folder_index = archive
            .stream_map
            .file_folder_index
            .get(index)
            .copied()
            .flatten();
        let methods = folder_index
            .and_then(|folder| folder_methods.get(folder))
            .cloned()
            .unwrap_or_default();
        let encrypted = methods.contains(&"aes256sha256");
        let method = (!methods.is_empty()).then(|| methods.join("+"));
        let compressed_size = entry.has_stream().then_some(entry.compressed_size);
        let mtime_unix = entry
            .has_last_modified_date
            .then(|| entry.last_modified_date().to_unix_time());
        let entry_type = if entry.is_directory() {
            "directory"
        } else if entry.is_anti_item() {
            "anti-item"
        } else {
            "regular"
        };

        let mut member = JsonMap::new();
        member.insert("path".into(), JsonValue::String(path.clone()));
        member.insert("size_bytes".into(), JsonValue::Number(entry.size.into()));
        member.insert("entry_type".into(), JsonValue::String(entry_type.into()));
        if let Some(size) = compressed_size {
            member.insert("compressed_size".into(), JsonValue::Number(size.into()));
        }
        if let Some(method) = method.as_deref() {
            member.insert(
                "compression_method".into(),
                JsonValue::String(method.into()),
            );
        }
        if encrypted {
            member.insert("encrypted".into(), JsonValue::Bool(true));
            encrypted_count += 1;
        }
        if let Some(mtime) = mtime_unix {
            member.insert("mtime_unix".into(), JsonValue::Number(mtime.into()));
        }
        if entry.has_crc {
            member.insert("crc32".into(), JsonValue::Number(entry.crc.into()));
        }

        total_size = total_size.saturating_add(entry.size);
        total_compressed = total_compressed.saturating_add(compressed_size.unwrap_or(0));
        if entry.is_directory() {
            directory_count += 1;
        } else {
            file_count += 1;
            let class = super::zip::classify_filename(&path);
            executable_count += u64::from(class.is_executable);
            script_count += u64::from(class.is_script);
            nested_archive_count += u64::from(class.is_nested_archive);
            traversal_count += u64::from(class.has_path_traversal);
        }

        archive_members.push(ArchiveMember {
            path,
            size_bytes: entry.size,
            entry_type: Some(entry_type.into()),
            mtime_unix,
            linkname: None,
            host_os: None,
            crc32: entry.has_crc.then_some(entry.crc as u32),
            encrypted,
            compression: (compressed_size.is_some() || method.is_some()).then_some(
                ArchiveCompression {
                    compressed_size,
                    method,
                },
            ),
            ownership: None,
            offsets: ArchiveOffsets::default(),
        });
        members.push(JsonValue::Object(member));
    }

    values.insert("archive.members", JsonValue::Array(members));
    metrics.insert(metric!("archive.member_count"), archive.files.len() as f64);
    metrics.insert(metric!("archive.file_count"), file_count as f64);
    metrics.insert(metric!("archive.directory_count"), directory_count as f64);
    metrics.insert(metric!("archive.uncompressed_size"), total_size as f64);
    metrics.insert(metric!("archive.compressed_size"), total_compressed as f64);
    metrics.insert(metric!("archive.executable_count"), executable_count as f64);
    metrics.insert(metric!("archive.script_count"), script_count as f64);
    metrics.insert(
        metric!("archive.nested_archive_count"),
        nested_archive_count as f64,
    );
    metrics.insert(
        metric!("archive.path_traversal_count"),
        traversal_count as f64,
    );
    // 7z carries its encryption in the coder chain rather than a per-entry
    // flag, so this had no ZIP-shaped counterpart and was simply never
    // emitted: every rule gated on `archive.security.encrypted_count` was
    // unreachable for 7z, including the password-protected sideload bundles
    // that are the format's most common malicious shape.
    metrics.insert(
        metric!("archive.security.encrypted_count"),
        encrypted_count as f64,
    );
    Ok(())
}

fn method_name(id: &[u8]) -> &'static str {
    use sevenz_rust::SevenZMethod as Method;

    match id {
        Method::ID_COPY => "stored",
        Method::ID_LZMA => "lzma",
        Method::ID_LZMA2 => "lzma2",
        Method::ID_ZSTD => "zstd",
        Method::ID_DEFLATE => "deflated",
        Method::ID_DEFLATE64 => "deflate64",
        Method::ID_BZIP2 => "bzip2",
        Method::ID_AES256SHA256 => "aes256sha256",
        Method::ID_BCJ_X86 => "bcj-x86",
        Method::ID_BCJ_PPC => "bcj-ppc",
        Method::ID_BCJ_IA64 => "bcj-ia64",
        Method::ID_BCJ_ARM => "bcj-arm",
        Method::ID_BCJ_ARM_THUMB => "bcj-arm-thumb",
        Method::ID_BCJ_SPARC => "bcj-sparc",
        Method::ID_DELTA => "delta",
        Method::ID_BCJ2 => "bcj2",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::extract;
    use crate::output::{Metrics, Values};

    #[test]
    fn header_walk_emits_members_without_reading_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("drop");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Setup.exe"), b"not an executable").unwrap();
        let archive_path = temp.path().join("payload.7z");

        let mut writer = sevenz_rust::SevenZWriter::create(&archive_path).unwrap();
        writer.push_source_path(&source, |_| true).unwrap();
        writer.finish().unwrap();

        let bytes = fs::read(archive_path).unwrap();
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed_members = Vec::new();
        extract(&bytes, &mut values, &mut metrics, &mut typed_members).unwrap();

        let members = values.get("archive.members").unwrap().as_array().unwrap();
        let setup = members
            .iter()
            .find(|member| {
                member["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("Setup.exe"))
            })
            .unwrap();
        assert_eq!(setup["size_bytes"].as_u64(), Some(17));
        assert_eq!(setup["entry_type"].as_str(), Some("regular"));
        assert_eq!(
            values
                .get("archive.format.kind")
                .and_then(serde_json::Value::as_str),
            Some("7z")
        );
        assert_eq!(metrics.get("archive.file_count"), Some(1.0));
        // Emitted even when nothing is encrypted: a rule gated on `min: 1`
        // and the ML feature both need absence to be a reported zero rather
        // than a missing key.
        assert_eq!(metrics.get("archive.security.encrypted_count"), Some(0.0));
        assert_eq!(typed_members.len(), members.len());
    }

    /// The shape the malicious bundles use: AES-encrypted payload streams with
    /// the header left in the clear, so the member table still reads without a
    /// password. 7z expresses that through the folder's coder chain rather than
    /// a per-entry flag, which is why it needs its own count.
    #[test]
    fn aes_payload_streams_are_counted_as_encrypted() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("drop");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Setup.exe"), b"not an executable").unwrap();
        let archive_path = temp.path().join("payload.7z");

        let mut writer = sevenz_rust::SevenZWriter::create(&archive_path).unwrap();
        writer.set_content_methods(vec![
            sevenz_rust::AesEncoderOptions::new(sevenz_rust::Password::from("hunter2")).into(),
            sevenz_rust::SevenZMethod::LZMA2.into(),
        ]);
        writer.push_source_path(&source, |_| true).unwrap();
        writer.finish().unwrap();

        let bytes = fs::read(archive_path).unwrap();
        let mut values = Values::default();
        let mut metrics = Metrics::default();
        let mut typed_members = Vec::new();
        extract(&bytes, &mut values, &mut metrics, &mut typed_members).unwrap();

        assert_eq!(metrics.get("archive.security.encrypted_count"), Some(1.0));
        assert!(typed_members.iter().all(|member| member.encrypted));
    }
}
