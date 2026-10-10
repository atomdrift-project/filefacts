//! PyTorch ZIP carrier convention, without loading a model or trusting code.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// Bytes the `zip` crate may read while recognizing a carrier, per input
/// byte, on top of a fixed 1 MiB. Opening a well-formed archive and reading
/// the two small members reads well under two passes over it, but the crate
/// rescans the file for every failing end-of-central-directory candidate, so
/// one packed with them would otherwise take quadratic time to refuse.
const READS_PER_BYTE: u64 = 4;

/// A reader that fails once `left` bytes have been read.
struct Budgeted<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Budgeted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 && !buf.is_empty() {
            return Err(io::Error::other("read budget exhausted"));
        }
        let max = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(buf.get_mut(..max).unwrap_or_default())?;
        self.left = self.left.saturating_sub(n as u64);
        Ok(n)
    }
}

impl<R: Seek> Seek for Budgeted<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub(super) fn recognized(data: &[u8]) -> bool {
    let reader = Budgeted {
        inner: Cursor::new(data),
        left: (data.len() as u64)
            .saturating_mul(READS_PER_BYTE)
            .saturating_add(1 << 20),
    };
    let Ok(mut archive) = zip::ZipArchive::new(reader) else {
        return false;
    };
    if archive.is_empty() || archive.len() > 100_000 {
        return false;
    }
    let Some(first) = archive.file_names().next() else {
        return false;
    };
    let Some((root, _)) = first.split_once('/') else {
        return false;
    };
    if root.is_empty() || root == "." || root == ".." {
        return false;
    }
    let prefix = format!("{root}/");
    if !archive.file_names().all(|name| {
        name.starts_with(&prefix)
            && !name.contains('\\')
            && !name.split('/').any(|part| part == "." || part == "..")
    }) {
        return false;
    }
    let version_name = format!("{prefix}version");
    let data_name = format!("{prefix}data.pkl");
    let version = {
        let Ok(entry) = archive.by_name(&version_name) else {
            return false;
        };
        if entry.is_dir() || entry.size() > 16 {
            return false;
        }
        // The declared size is the archive's claim; a deflated member that
        // declares 16 bytes can inflate to gigabytes. Read one byte past it.
        let mut bytes = Vec::new();
        if entry.take(17).read_to_end(&mut bytes).is_err() || bytes.len() > 16 {
            return false;
        }
        bytes
    };
    let Ok(version) = std::str::from_utf8(&version) else {
        return false;
    };
    // Bound known carrier versions. Unknown future conventions retain the
    // existing mismatch signal until their format has been reviewed.
    let version = version.trim_ascii();
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !version.parse::<u32>().is_ok_and(|v| (1..=10).contains(&v)) {
        return false;
    }
    let Ok(mut entry) = archive.by_name(&data_name) else {
        return false;
    };
    let mut header = [0; 2];
    !entry.is_dir()
        && entry.read_exact(&mut header).is_ok()
        && header[0] == 0x80
        && (2..=5).contains(&header[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fileid::{self, FileType};
    use std::io::Write;
    use std::path::Path;

    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in files {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn canonical_torchscript_fixture_keeps_zip_type_without_suffix_mismatch() {
        let data = include_bytes!("testdata/tiny-torchscript.pt");
        assert!(recognized(data));
        for name in ["model.pt", "model.pth", "model.ckpt", "MODEL.PT"] {
            let detected = fileid::detect(Path::new(name), data).unwrap();
            assert_eq!(detected.file_type, FileType::Zip);
            assert!(!detected.extension_mismatch());
        }
        assert!(
            fileid::detect(Path::new("model.py"), data)
                .unwrap()
                .extension_mismatch()
        );
    }

    #[test]
    fn serialization_framing_does_not_exempt_arbitrary_or_malformed_zip() {
        for files in [
            vec![("model/data.pkl", &b"\x80\x02}."[..])],
            vec![("model/version", &b"3\n"[..])],
            vec![
                ("model/version", &b"3\n"[..]),
                ("other/data.pkl", &b"\x80\x02}."[..]),
            ],
            vec![
                ("model/version", &b"three"[..]),
                ("model/data.pkl", &b"\x80\x02}."[..]),
            ],
            vec![
                ("model/version", &b"11"[..]),
                ("model/data.pkl", &b"\x80\x02}."[..]),
            ],
            vec![
                ("model/version", &b"3\n"[..]),
                ("model/data.pkl", &b"MZprogram"[..]),
            ],
            vec![
                ("model/version", &b"3\n"[..]),
                ("model/data.pkl", &b"\x80\x06}."[..]),
            ],
            vec![
                ("model/version", &b"3\n"[..]),
                ("model/data.pkl", &b"\x80\x02}."[..]),
                ("model/../payload", &b"code"[..]),
            ],
        ] {
            let data = archive(&files);
            assert!(!recognized(&data));
            assert!(
                fileid::detect(Path::new("model.pt"), &data)
                    .unwrap()
                    .extension_mismatch()
            );
        }
        let data = archive(&[("model/version", b"3\n"), ("model/data.pkl", b"\x80\x02}.")]);
        assert!(recognized(&data));
        assert!(!recognized(&data[..data.len() - 12]));
    }

    #[test]
    fn executable_members_receive_no_trust_from_the_carrier_convention() {
        let data = archive(&[
            ("model/version", b"3\n"),
            ("model/data.pkl", b"\x80\x02}."),
            ("model/code/evil.py", b"import os; os.system('payload')"),
        ]);
        assert!(recognized(&data));
        // Recognition preserves archive classification and child extraction;
        // it only describes the suffix's established serialization convention.
        assert_eq!(
            fileid::detect(Path::new("model.pt"), &data)
                .unwrap()
                .file_type,
            FileType::Zip
        );
    }

    #[test]
    fn torchscript_debug_pickle_suffix_dispatches_to_pickle_without_executing_it() {
        let data = include_bytes!("testdata/tiny-torchscript.debug_pkl");
        let detected = fileid::detect(Path::new("__torch__.py.debug_pkl"), data).unwrap();
        assert_eq!(detected.file_type, FileType::Pickle);
        assert!(!detected.extension_mismatch());
        // This adds a serialization suffix; it grants no exception to a
        // body whose magic says it is an executable or another format.
        let executable = include_bytes!("testdata/tiny-torchscript.pt");
        let detected = fileid::detect(Path::new("code.debug_pkl"), executable).unwrap();
        assert_eq!(detected.file_type, FileType::Zip);
        assert!(detected.extension_mismatch());
    }

    /// A `version` member that declares two bytes but inflates to megabytes
    /// is refused rather than read whole: the declared size is only the
    /// archive's claim.
    #[test]
    fn version_member_inflating_past_its_declared_size_is_refused() {
        let mut version = b"3".to_vec();
        version.resize(1 << 20, b' ');
        let mut data = archive(&[
            ("model/version", &version),
            ("model/data.pkl", b"\x80\x02}."),
        ]);
        // Rewrite the declared uncompressed size in the local header (+22)
        // and the central-directory record (+24) of `model/version`.
        let declared = (1_u32 << 20).to_le_bytes();
        let mut at = 0;
        let mut patched = 0;
        while let Some(off) = data[at..].windows(4).position(|w| w == declared) {
            let pos = at + off;
            data[pos..pos + 4].copy_from_slice(&2_u32.to_le_bytes());
            patched += 1;
            at = pos + 4;
        }
        assert_eq!(patched, 2);
        assert!(!recognized(&data));
    }

    /// End-of-central-directory candidates that each fail made the `zip`
    /// crate rescan the file once per candidate; recognition is now bounded.
    #[test]
    fn failing_end_record_candidates_are_refused_promptly() {
        let mut record = [0_u8; 22];
        record[..4].copy_from_slice(b"PK\x05\x06");
        record[8..10].copy_from_slice(&1_u16.to_le_bytes());
        record[10..12].copy_from_slice(&1_u16.to_le_bytes());
        let data = record.repeat((512 << 10) / record.len());
        let start = std::time::Instant::now();
        assert!(!recognized(&data));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
}
