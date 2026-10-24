//! Bounded manifest probes for source-package archives. A nested dependency's
//! manifest cannot name its enclosing archive: only a root or one wrapper counts.
// Published member names are case-sensitive format markers.
#![allow(clippy::case_sensitive_file_extension_comparisons)]
use std::io::Read;

use super::FileType;

pub(super) const MANIFEST_LIMIT: u64 = 128 * 1024;

fn manifest_name(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix("./").unwrap_or(path);
    if path.contains('\\') {
        return None;
    }
    let (root, name) = path.split_once('/').unwrap_or(("", path));
    if name.contains('/') || matches!(root, "." | "..") {
        return None;
    }
    Some((root, name))
}

fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case(key) {
            return None;
        }
        let value = value.split(" #").next()?.trim();
        Some(
            value
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
                .or_else(|| value.strip_prefix('"').and_then(|v| v.strip_suffix('"')))
                .unwrap_or(value),
        )
    })
}

fn version(value: &str) -> bool {
    value.starts_with(|c: char| c.is_ascii_digit() || c == 'v')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c))
}

fn crate_manifest(root: &str, body: &str) -> Option<FileType> {
    let doc: toml::Value = toml::from_str(body).ok()?;
    let package = doc.get("package")?;
    let name = package.get("name")?.as_str()?;
    let version = package.get("version")?.as_str()?;
    (root == format!("{name}-{version}") && !name.is_empty() && !version.is_empty())
        .then_some(FileType::Crate)
}

/// The manifest's own identity must fit its archive root. Fixed manifest names
/// alone are insufficient: empty templates and documentation are common.
fn manifest(path: &str, body: &[u8]) -> Option<FileType> {
    let (root, name) = manifest_name(path)?;
    let text = std::str::from_utf8(body).ok()?;
    match name {
        "Cargo.toml" if !root.is_empty() => crate_manifest(root, text),
        "composer.json" => {
            let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
            let (vendor, package) = doc.get("name")?.as_str()?.split_once('/')?;
            let part = |s: &str| {
                !s.is_empty()
                    && s.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c)
                    })
            };
            (part(vendor) && part(package)).then_some(FileType::Composer)
        }
        "pubspec.yaml" => {
            let name = field(text, "name")?;
            (!name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                && version(field(text, "version")?))
            .then_some(FileType::Pub)
        }
        "DESCRIPTION" if !root.is_empty() => (field(text, "Package")? == root
            && version(field(text, "Version")?)
            && field(text, "Title").is_some()
            && field(text, "Description").is_some())
        .then_some(FileType::Cran),
        "META.json" if !root.is_empty() => {
            let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
            let name = doc.get("name")?.as_str()?;
            let release = doc.get("version")?;
            let release = release
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| release.to_string());
            (!name.is_empty()
                && root == format!("{name}-{release}")
                && version(&release)
                && doc.get("meta-spec")?.is_object())
            .then_some(FileType::Cpan)
        }
        "META.yml" if !root.is_empty() => (root.starts_with(&format!("{}-", field(text, "name")?))
            && version(field(text, "version")?)
            && field(text, "meta-spec").is_some())
        .then_some(FileType::Cpan),
        name if name.ends_with(".cabal") && !root.is_empty() => {
            let package = field(text, "name")?;
            let release = field(text, "version")?;
            (name.strip_suffix(".cabal")? == package
                && root == format!("{package}-{release}")
                && version(release))
            .then_some(FileType::Hackage)
        }
        _ => None,
    }
}

pub(super) fn is_manifest(path: &str) -> bool {
    manifest_name(path).is_some_and(|(_, name)| {
        matches!(
            name,
            "Cargo.toml" | "pubspec.yaml" | "DESCRIPTION" | "META.json" | "META.yml"
        ) || name.ends_with(".cabal")
    })
}

#[derive(Default)]
pub(super) struct TarProbe {
    candidate: Option<(String, FileType)>,
    pub_hint: bool,
    hex_version: bool,
    hex_checksum: bool,
    hex_metadata: bool,
    hex_contents: bool,
}

impl TarProbe {
    /// Inspect only small manifests or short format signatures. `tar` skips the
    /// rest under its caller's existing total decompression budget.
    pub(super) fn observe(&mut self, path: &str, entry: impl Read, size: u64) {
        self.pub_hint |= path.ends_with(".dart") || path == "lib";
        let hex_limit = match path {
            "VERSION" => Some(8),
            "CHECKSUM" => Some(128),
            "metadata.config" => Some(MANIFEST_LIMIT),
            "contents.tar.gz" => Some(2),
            _ => None,
        };
        if !is_manifest(path) && hex_limit.is_none() {
            return;
        }
        let limit = hex_limit.unwrap_or(MANIFEST_LIMIT);
        if size > limit && path != "contents.tar.gz" {
            return;
        }
        let mut body = Vec::new();
        if entry.take(limit + 1).read_to_end(&mut body).is_err() || body.len() as u64 > limit {
            // contents.tar.gz needs only its gzip signature, not its body.
            if path != "contents.tar.gz" {
                return;
            }
        }
        match path {
            "VERSION" => self.hex_version = body.trim_ascii() == b"3",
            "CHECKSUM" => {
                self.hex_checksum = body.trim_ascii().len() == 64
                    && body.trim_ascii().iter().all(u8::is_ascii_hexdigit)
            }
            "metadata.config" => {
                self.hex_metadata = memchr::memmem::find(&body, b"<<\"name\">>").is_some()
                    && memchr::memmem::find(&body, b"<<\"version\">>").is_some()
            }
            "contents.tar.gz" => self.hex_contents = body.starts_with(b"\x1f\x8b"),
            _ => {
                if let Some(kind) = manifest(path, &body)
                    && let Some((root, _)) = manifest_name(path)
                    && self
                        .candidate
                        .as_ref()
                        .is_none_or(|(old, _)| !old.is_empty())
                {
                    self.candidate = Some((root.to_owned(), kind));
                }
            }
        }
    }

    pub(super) fn hex(&self) -> bool {
        self.hex_version && self.hex_checksum && self.hex_metadata && self.hex_contents
    }

    pub(super) fn extended_walk(&self) -> bool {
        self.pub_hint
    }

    pub(super) fn finish(self, root: Option<&str>) -> Option<FileType> {
        self.candidate.and_then(|(prefix, kind)| {
            (prefix.is_empty() || root == Some(prefix.as_str())).then_some(kind)
        })
    }
}

/// Composer distributions are commonly GitHub ZIPs, including streaming ZIPs.
/// Use the central directory and inflate only the root manifest, with a hard cap.
pub(super) fn composer_zip(data: &[u8]) -> bool {
    // Avoid opening every arbitrary ZIP unless a local name at least mentions
    // composer.json. This is a hint only; the central directory is authoritative.
    if memchr::memmem::find(data, b"composer.json").is_none() {
        return false;
    }
    let Ok(mut archive) = super::zip_probe::open(data) else {
        return false;
    };
    let candidate = archive
        .file_names()
        .find(|name| manifest_name(name).is_some_and(|(_, base)| base == "composer.json"))
        .map(str::to_owned);
    let Some(name) = candidate else {
        return false;
    };
    let Some((root, _)) = manifest_name(&name) else {
        return false;
    };
    let prefix = if root.is_empty() {
        String::new()
    } else {
        format!("{root}/")
    };
    if !prefix.is_empty()
        && !archive
            .file_names()
            .all(|name| name == root || name.starts_with(&prefix))
    {
        return false;
    }
    let Ok(entry) = archive.by_name(&name) else {
        return false;
    };
    if entry.is_dir() || entry.size() > MANIFEST_LIMIT {
        return false;
    }
    let mut body = Vec::new();
    entry
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut body)
        .is_ok()
        && body.len() as u64 <= MANIFEST_LIMIT
        && manifest(&name, &body) == Some(FileType::Composer)
}

#[cfg(test)]
mod tests {
    use crate::{ArchiveFormat, FileId, FileType};
    use std::io::{Cursor, Write};
    use std::path::Path;

    fn tar(members: &[(&str, &[u8])], gzip: bool) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in members {
            let mut header = tar::Header::new_ustar();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *body).unwrap();
        }
        let data = builder.into_inner().unwrap();
        if !gzip {
            return data;
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&data).unwrap();
        encoder.finish().unwrap()
    }

    fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in members {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn identifies(bytes: &[u8], kind: FileType) {
        for path in ["download", "deadbeef", "artifact.tar.gz", "archive.zip"] {
            let id = FileId::from_path_and_bytes(Path::new(path), bytes);
            assert_eq!(id.file_type(), kind, "{path}");
        }
        let parsed = crate::OpenOptions::new().cache(false).open(bytes);
        assert_eq!(parsed.fileid().file_type(), kind);
        assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
        // These fields feed container fallback models independently of the
        // ecosystem-specific label.
        let container = kind.archive_format().unwrap();
        assert_eq!(
            parsed
                .values()
                .get("archive.container.archive")
                .and_then(serde_json::Value::as_str),
            Some(container.label())
        );
        let label = serde_json::to_string(&kind).unwrap();
        assert_eq!(serde_json::from_str::<FileType>(&label).unwrap(), kind);
    }

    #[test]
    fn source_package_types_survive_renamed_downloads() {
        let cases: Vec<(FileType, Vec<u8>)> = vec![
            (FileType::Crate, tar(&[("demo-1.2.3/Cargo.toml", b"[package]\nname='demo'\nversion='1.2.3'\n")], true)),
            (FileType::Pub, tar(&[("lib/demo.dart", b"library demo;"), ("pubspec.yaml", b"name: demo\nversion: '1.2.3'\nenvironment:\n  sdk: ^3.4.0\n")], true)),
            (FileType::Cran, tar(&[("demo/DESCRIPTION", b"Package: demo\nVersion: 1.2.3\nTitle: Example\nDescription: Example package.\n")], true)),
            (FileType::Cpan, tar(&[("Demo-1.23/META.json", br#"{"name":"Demo","version":"1.23","meta-spec":{"version":2}}"#)], true)),
            (FileType::Cpan, tar(&[("Demo-1.23/META.yml", b"---\nname: Demo\nversion: '1.23'\nmeta-spec:\n  version: '1.4'\n")], true)),
            (FileType::Hackage, tar(&[("demo-0.1.2.3/demo.cabal", b"Name: demo\nVersion: 0.1.2.3\nCabal-Version: >=1.10\n")], true)),
            (FileType::Hex, tar(&[("VERSION", b"3"), ("CHECKSUM", &[b'A';64]), ("metadata.config", b"{<<\"name\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.2.3\">>}."), ("contents.tar.gz", b"\x1f\x8b\x08\0")], false)),
            (FileType::Composer, zip(&[("demo-main/composer.json", br#"{"name":"vendor/demo","require":{"php":">=8.0"}}"#), ("demo-main/src/Demo.php", b"<?php echo 1;")])),
            (FileType::Composer, zip(&[("composer.json", br#"{"name":"vendor/demo"}"#), ("src/Demo.php", b"<?php echo 1;")])),
        ];
        for (kind, bytes) in cases {
            identifies(&bytes, kind);
        }
    }

    #[test]
    fn incidental_manifests_do_not_name_the_outer_archive() {
        for members in [
            vec![(
                "repo/docs/demo/Cargo.toml",
                &b"[package]\nname='demo'\nversion='1.2.3'\n"[..],
            )],
            vec![(
                "repo/Cargo.toml",
                &b"[package]\nname='demo'\nversion='1.2.3'\n"[..],
            )],
            vec![(
                "repo/sub/pubspec.yaml",
                &b"name: demo\nversion: 1.2.3\n"[..],
            )],
            vec![(
                "demo/DESCRIPTION",
                &b"Package: other\nVersion: 1.0\nTitle: x\nDescription: y\n"[..],
            )],
            vec![(
                "Demo-1.0/META.json",
                &br#"{"name":"Demo","version":"1.0"}"#[..],
            )],
            vec![("demo-1.0/demo.cabal", &b"name: other\nversion: 1.0\n"[..])],
            vec![
                ("VERSION", &b"3"[..]),
                ("CHECKSUM", &b"bad"[..]),
                ("metadata.config", &b"x"[..]),
                ("contents.tar.gz", &b"x"[..]),
            ],
            vec![
                (
                    "demo-1.2.3/Cargo.toml",
                    &b"[package]\nname='demo'\nversion='1.2.3'\n"[..],
                ),
                ("unrelated/payload", &b"x"[..]),
            ],
        ] {
            assert_eq!(
                FileId::from_bytes(&tar(&members, true)).file_type(),
                FileType::TarGz,
                "{members:?}"
            );
        }
        for members in [
            vec![(
                "repo/vendor/lib/composer.json",
                &br#"{"name":"vendor/lib"}"#[..],
            )],
            vec![("repo/composer.json", &b"{}"[..])],
            vec![
                ("repo/composer.json", &br#"{"name":"vendor/lib"}"#[..]),
                ("other/file", &b"x"[..]),
            ],
            vec![("repo/composer.json", &b"{broken"[..])],
        ] {
            assert_eq!(
                FileId::from_bytes(&zip(&members)).file_type(),
                FileType::Zip
            );
        }
        assert_eq!(
            FileType::Composer.archive_format(),
            Some(ArchiveFormat::Zip)
        );
    }

    #[test]
    fn rootless_pub_manifest_may_follow_many_source_files() {
        let names: Vec<String> = (0..100).map(|i| format!("lib/source{i}.dart")).collect();
        let mut members: Vec<_> = names
            .iter()
            .map(|s| (s.as_str(), &b"library demo;"[..]))
            .collect();
        members.push(("README.md", b"documentation"));
        members.push(("pubspec.yaml", b"name: demo\nversion: 1.2.3\n"));
        identifies(&tar(&members, true), FileType::Pub);
    }

    #[test]
    fn oversized_manifests_remain_generic() {
        let mut oversized = b"name: demo\nversion: 1.2.3\n# ".to_vec();
        oversized.resize(super::MANIFEST_LIMIT as usize + 1, b'a');
        assert_eq!(
            FileId::from_bytes(&tar(&[("pubspec.yaml", &oversized)], true)).file_type(),
            FileType::TarGz
        );
        assert_eq!(
            FileId::from_bytes(&zip(&[("composer.json", &oversized)])).file_type(),
            FileType::Zip
        );
    }
}
