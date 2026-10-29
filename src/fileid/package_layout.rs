//! What a package archive's member names and manifests make it.
//!
//! One standard decides every tar layout. Member names a format defines
//! settle it where the format puts them: the first member (`gpkg-1`,
//! `.SIGN.*`, `+MANIFEST`, `props.plist`) or the archive root (`.PKGINFO`
//! with `.MTREE`, `metadata.gz` with `data.tar.gz`, an OCI layout). An
//! ecosystem manifest settles it only when its own identity names the one
//! directory every member sits under (`<name>-<version>/` for a crate or an
//! sdist), or the archive has no root directory at all; npm fixes its root
//! as `package/`, so its manifest settles the layout when it checks out there:
//! a nested dependency's manifest cannot name its enclosing archive, and a
//! manifest's fixed name alone is no identity, since empty templates and
//! documentation carry it too.
use std::io::Read;

use super::{FileType, Sniff, zip_probe};

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

/// A Python sdist's Core Metadata: `Name` and `Version`, and a root named
/// for them. The root spells the name as the build tool normalized it, so the
/// two are compared with PEP 503 normalization.
fn sdist_manifest(root: &str, text: &str) -> Option<FileType> {
    field(text, "Metadata-Version")?;
    let name = field(text, "Name")?;
    let release = field(text, "Version")?;
    let stem = root.strip_suffix(release)?.strip_suffix('-')?;
    let normalized = |s: &str| {
        s.split(['-', '_', '.'])
            .filter(|part| !part.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
    };
    (!name.is_empty() && version(release) && normalized(stem) == normalized(name))
        .then_some(FileType::PythonSdist)
}

/// The manifest's own identity must fit its archive root.
fn manifest(path: &str, body: &[u8]) -> Option<FileType> {
    let (root, name) = manifest_name(path)?;
    let text = std::str::from_utf8(body).ok()?;
    match name {
        "Cargo.toml" if !root.is_empty() => crate_manifest(root, text),
        // npm packs every package under `package/`.
        "package.json" if root == "package" => {
            let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
            let named = |key| doc.get(key).and_then(serde_json::Value::as_str);
            (named("name").is_some_and(|n| !n.is_empty()) && named("version").is_some())
                .then_some(FileType::Npm)
        }
        "PKG-INFO" if !root.is_empty() => sdist_manifest(root, text),
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
        name if !root.is_empty() && name.strip_suffix(".cabal").is_some() => {
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

fn is_manifest(path: &str) -> bool {
    manifest_name(path).is_some_and(|(_, name)| {
        matches!(
            name,
            "Cargo.toml"
                | "package.json"
                | "PKG-INFO"
                | "pubspec.yaml"
                | "DESCRIPTION"
                | "META.json"
                | "META.yml"
        ) || name
            .rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && ext == "cabal")
    })
}

/// Members a tar is read through for a container image's markers; a `docker
/// save` bundle writes `manifest.json` after its layers.
const DEEP_MEMBERS: usize = 512;

/// Members read before a tar with several top-level entries is settled.
/// Every first-member and root marker sits within them.
const SHALLOW_MEMBERS: usize = 8;

/// The top-level directory a tar's members share.
enum Root {
    /// No member observed yet.
    Unseen,
    /// Every member so far sits under this one.
    One(String),
    /// Members sit under more than one.
    Many,
}

/// A tar's members, observed one at a time, and the package layout they
/// name. See the module documentation for the standard every marker meets.
pub(super) struct TarProbe {
    /// Members observed, not counting metadata headers and AppleDouble
    /// sidecars.
    members: usize,
    /// The top-level directory the members so far share.
    root: Root,
    /// The first ecosystem manifest whose identity checked out, with the
    /// root it names (empty for a rootless archive).
    candidate: Option<(String, FileType)>,
    pkginfo: bool,
    arch_meta: bool,
    gem_metadata: bool,
    gem_data: bool,
    oci_layout: bool,
    oci_index: bool,
    docker_manifest: bool,
    docker_layers: bool,
    /// Dart sources, so a rootless pub package may name itself late.
    pub_hint: bool,
    hex_version: bool,
    hex_checksum: bool,
    hex_metadata: bool,
    hex_contents: bool,
}

impl TarProbe {
    pub(super) fn new() -> Self {
        Self {
            members: 0,
            root: Root::Unseen,
            candidate: None,
            pkginfo: false,
            arch_meta: false,
            gem_metadata: false,
            gem_data: false,
            oci_layout: false,
            oci_index: false,
            docker_manifest: false,
            docker_layers: false,
            pub_hint: false,
            hex_version: false,
            hex_checksum: false,
            hex_metadata: false,
            hex_contents: false,
        }
    }

    /// Members observed so far.
    pub(super) fn members(&self) -> usize {
        self.members
    }

    /// Observe the member at `path` (`./` and a trailing `/` already
    /// trimmed). Returns the layout once a format-defined marker settles it.
    /// Only small manifests and short signatures are read from `entry`; `tar`
    /// skips the rest under its caller's decompression budget.
    pub(super) fn observe(
        &mut self,
        path: &str,
        is_file: bool,
        entry: impl Read,
        size: u64,
    ) -> Option<FileType> {
        let (top, rest) = path.split_once('/').unwrap_or((path, ""));
        let base = path.rsplit('/').next().unwrap_or(path);
        // macOS AppleDouble sidecars that `tar` smuggles in are not members.
        if base.starts_with("._") || path.is_empty() {
            return None;
        }
        self.members += 1;
        if self.members == 1 {
            let first = if base == "gpkg-1" && rest == "gpkg-1" {
                Some(FileType::GentooBinpkg)
            } else if path.starts_with(".SIGN.") {
                Some(FileType::ApkAlpine)
            } else if matches!(path, "+COMPACT_MANIFEST" | "+MANIFEST") {
                Some(FileType::PkgFreebsd)
            } else if path == "props.plist" {
                Some(FileType::Xbps)
            } else {
                None
            };
            if first.is_some() {
                return first;
            }
        }
        match path {
            ".PKGINFO" => self.pkginfo = true,
            ".MTREE" | ".BUILDINFO" => self.arch_meta = true,
            "metadata.gz" => self.gem_metadata = true,
            "data.tar.gz" => self.gem_data = true,
            "oci-layout" => self.oci_layout = true,
            "index.json" => self.oci_index = true,
            "manifest.json" => self.docker_manifest = true,
            "repositories" => self.docker_layers = true,
            _ if path.ends_with("/layer.tar") || path.starts_with("blobs/") => {
                self.docker_layers = true;
            }
            _ => {}
        }
        if self.pkginfo && self.arch_meta {
            return Some(FileType::PkgArch);
        }
        if self.gem_metadata && self.gem_data {
            return Some(FileType::Gem);
        }
        if (self.oci_layout && self.oci_index) || (self.docker_manifest && self.docker_layers) {
            return Some(FileType::OciImage);
        }
        match &self.root {
            Root::Unseen => self.root = Root::One(top.to_owned()),
            Root::One(r) if r != top => self.root = Root::Many,
            _ => {}
        }
        if is_file {
            self.read_manifest(path, entry, size);
            // npm's root is fixed by the format, so its manifest settles the
            // layout as soon as it checks out under that one root.
            if matches!(&self.root, Root::One(r) if r == "package")
                && self
                    .candidate
                    .as_ref()
                    .is_some_and(|(_, kind)| *kind == FileType::Npm)
            {
                return Some(FileType::Npm);
            }
            if self.hex_version && self.hex_checksum && self.hex_metadata && self.hex_contents {
                return Some(FileType::Hex);
            }
        }
        None
    }

    fn read_manifest(&mut self, path: &str, entry: impl Read, size: u64) {
        self.pub_hint |=
            path == "lib" || path.rsplit_once('.').is_some_and(|(_, ext)| ext == "dart");
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
                    && body.trim_ascii().iter().all(u8::is_ascii_hexdigit);
            }
            "metadata.config" => {
                self.hex_metadata = memchr::memmem::find(&body, b"<<\"name\">>").is_some()
                    && memchr::memmem::find(&body, b"<<\"version\">>").is_some();
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

    /// How many members to read before settling. A single-root package may
    /// name itself last, so it is read to the end of the caller's byte
    /// budget; `deep` reads on for container-image markers, which only a
    /// plain tar carries.
    pub(super) fn cap(&self, deep: bool) -> usize {
        if deep {
            DEEP_MEMBERS
        } else if !matches!(self.root, Root::Many) || self.pub_hint {
            usize::MAX
        } else {
            SHALLOW_MEMBERS
        }
    }

    /// The layout once every member read has been observed: the manifest
    /// candidate when its root is the archive's one root (or it has none),
    /// else a plain tar.
    pub(super) fn finish(self) -> FileType {
        self.candidate
            .and_then(|(prefix, kind)| {
                (prefix.is_empty() || matches!(&self.root, Root::One(r) if *r == prefix))
                    .then_some(kind)
            })
            .unwrap_or(FileType::Tar)
    }
}

/// Composer distributions are commonly GitHub ZIPs, including streaming ZIPs.
/// Use the central directory and inflate only the root manifest, with a hard
/// cap. Callers ask only when a local name mentions `composer.json`.
pub(super) fn composer_zip(sniff: &Sniff<'_>) -> bool {
    let Some(mut archive) = sniff.zip() else {
        return false;
    };
    let candidate = zip_probe::names(&archive)
        .find(|name| manifest_name(name).is_some_and(|(_, base)| base == "composer.json"))
        .map(std::borrow::Cow::into_owned);
    let Some(name) = candidate else {
        return false;
    };
    let Some((root, _)) = manifest_name(&name) else {
        return false;
    };
    if !root.is_empty()
        && !zip_probe::names(&archive).all(|name| {
            name == root
                || name
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
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
mod tests;
