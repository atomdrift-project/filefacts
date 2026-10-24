//! Go proxy distribution ZIPs, identified without inflating member contents.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// Bound failed end-of-directory searches as well as successful reads. The ZIP
/// reader otherwise rescans its input for every false EOCD signature.
struct Budgeted<'a> {
    inner: Cursor<&'a [u8]>,
    left: usize,
}

impl Read for Budgeted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 && !buf.is_empty() {
            return Err(io::Error::other("ZIP probe read budget exhausted"));
        }
        let max = buf.len().min(self.left);
        let n = self.inner.read(buf.get_mut(..max).unwrap_or_default())?;
        self.left -= n;
        Ok(n)
    }
}

impl Seek for Budgeted<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Recognize the distribution convention, not whether Go would accept every
/// byte of this package. Older modules need not have a go.mod or a .go file.
/// https://go.dev/ref/mod#zip-files
pub(super) fn recognized(data: &[u8]) -> bool {
    // Most ZIPs cannot be modules. Check the first local name before opening
    // the central directory; member sizes are deliberately not used here, as
    // Go's streaming writer leaves them in data descriptors instead.
    let Some(name_len) = crate::bytes::u16_le(data, 26).map(usize::from) else {
        return false;
    };
    let Some(name) = data
        .get(30..30 + name_len)
        .and_then(|b| std::str::from_utf8(b).ok())
    else {
        return false;
    };
    let Some(prefix) = module_prefix(name) else {
        return false;
    };
    let reader = Budgeted {
        inner: Cursor::new(data),
        left: data.len().saturating_mul(4).saturating_add(1 << 20),
    };
    let Ok(archive) = zip::ZipArchive::new(reader) else {
        return false;
    };
    let mut has_file = false;
    for name in archive.file_names() {
        let Some(relative) = name.strip_prefix(prefix) else {
            return false;
        };
        if name.contains('\\')
            || relative
                .trim_end_matches('/')
                .split('/')
                .any(|p| p == "." || p == ".." || (p.is_empty() && !relative.is_empty()))
        {
            return false;
        }
        has_file |= !relative.is_empty() && !name.ends_with('/');
    }
    has_file
}

fn module_prefix(name: &str) -> Option<&str> {
    let (module, after) = name.split_once('@')?;
    let (version, _) = after.split_once('/')?;
    let host = module.split('/').next()?;
    // Downloadable module paths have a DNS-shaped first element; Go's !x
    // URL escaping is not used in archive member names (uppercase is literal).
    if !host.contains('.')
        || host.starts_with(['.', '-'])
        || !host
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-".contains(&c))
        || !module.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
        })
        || !canonical_version(version)
    {
        return None;
    }
    name.get(..module.len() + version.len() + 2)
}

fn canonical_version(version: &str) -> bool {
    let Some(version) = version.strip_prefix('v') else {
        return false;
    };
    let version = version.strip_suffix("+incompatible").unwrap_or(version);
    let (core, pre) = version
        .split_once('-')
        .map_or((version, None), |(a, b)| (a, Some(b)));
    let mut parts = core.split('.');
    if !(0..3).all(|_| parts.next().is_some_and(number)) || parts.next().is_some() {
        return false;
    }
    pre.is_none_or(|pre| {
        pre.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && (!part.bytes().all(|c| c.is_ascii_digit()) || number(part))
        })
    })
}

fn number(part: &str) -> bool {
    !part.is_empty()
        && (part.len() == 1 || !part.starts_with('0'))
        && part.bytes().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArchiveFormat, FileId, FileType};
    use std::io::Write;
    use std::path::Path;
    use zip::write::SimpleFileOptions;

    fn module_zip(names: &[&str]) -> Vec<u8> {
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in names {
            zip.start_file(*name, options).unwrap();
            zip.write_all(b"package hello\n").unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn go_module_downloads_have_a_stable_type_without_a_filename() {
        for prefix in [
            "example.com/hello@v1.2.3",
            "github.com/BurntSushi/toml@v1.4.0",
            "tailscale.com@v1.102.3",
            "example.com/lib/v2@v2.0.0-rc.1",
            "example.com/lib@v4.4.0+incompatible",
            "example.com/lib@v0.0.0-20260528132821-f66b8cdce5b3",
        ] {
            {
                // README alone also covers legacy releases with no go.mod.
                let data = module_zip(&[&format!("{prefix}/README.md")]);
                for filename in ["v1.2.3.zip", "download", "deadbeef", "archive.jar"] {
                    let id = FileId::from_path_and_bytes(Path::new(filename), &data);
                    assert_eq!(id.file_type(), FileType::GoModule, "{prefix}: {filename}");
                    if filename.ends_with(".zip") {
                        assert!(!id.extension_mismatch());
                    }
                }
                let parsed = crate::OpenOptions::new().cache(false).open(&data);
                assert_eq!(parsed.fileid().file_type(), FileType::GoModule);
                assert_eq!(parsed.archive_members().len(), 1);
                assert!(parsed.errors().is_empty());
                assert_eq!(
                    FileType::GoModule.archive_format(),
                    Some(ArchiveFormat::Zip)
                );
                let encoded = serde_json::to_string(&FileType::GoModule).unwrap();
                assert_eq!(encoded, "\"go_module\"");
                assert_eq!(
                    serde_json::from_str::<FileType>(&encoded).unwrap(),
                    FileType::GoModule
                );
            }
        }
    }

    #[test]
    fn go_writer_data_descriptors_are_detected_from_the_central_directory() {
        // Produced by Go archive/zip, with zero sizes in local headers.
        let data = include_bytes!("testdata/go-module-stream.zip");
        assert_eq!(&data[18..26], &[0; 8]);
        assert!(recognized(data));
        assert_eq!(FileId::from_bytes(data).file_type(), FileType::GoModule);
        assert!(!recognized(&data[..data.len() / 2]));
    }

    #[test]
    fn incidental_go_files_and_mixed_roots_are_not_modules() {
        for names in [
            vec!["go.mod", "hello.go"],
            vec!["repo-main/go.mod", "repo-main/hello.go"],
            vec!["example.com/hello@v1.2.3/go.mod", "other/payload"],
            vec![
                "example.com/hello@v1.2.3/go.mod",
                "example.com/hello@v1.2.4/x.go",
            ],
            vec!["example.com/hello@v1.2.3/../escape"],
            vec!["example.com/hello@v1.2.3/a//b"],
            vec!["example.com/hello@v1.2.3/a\\b"],
            vec!["example.com/hello@latest/go.mod"],
            vec!["example.com/hello@v01.2.3/go.mod"],
            vec!["example.com/hello@v1.2.3+meta/go.mod"],
            vec!["backup/hello@v1.2.3/go.mod"],
            vec!["../example.com/hello@v1.2.3/go.mod"],
        ] {
            assert!(!recognized(&module_zip(&names)), "{names:?}");
        }
        // Marker text in a stored nested ZIP must not identify its wrapper.
        let inner = module_zip(&["example.com/hello@v1.2.3/go.mod"]);
        let mut outer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        outer
            .start_file("payload.zip", SimpleFileOptions::default())
            .unwrap();
        outer.write_all(&inner).unwrap();
        assert!(!recognized(&outer.finish().unwrap().into_inner()));
        assert!(!recognized(b"PK\x03\x04example.com/hello@v1.2.3/go.mod"));
    }
}
