//! Content-based detection: magic bytes, shebangs, and structural markers.
//!
//! Uses a first-byte jump table to avoid sequential if-chains. Most files are
//! identified by examining only the first 4-20 bytes.

use std::{io::Read, path::Path};

use super::{DetectionSource, FileType};

/// LNK shell link CLSID header (20 bytes).
const LNK_MAGIC: &[u8] = &[
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];

/// Detect file type from content. Returns the type and how it was detected.
pub(crate) fn detect_from_content(path: &Path, data: &[u8]) -> Option<(FileType, DetectionSource)> {
    if data.len() < 2 {
        return None;
    }

    if looks_like_udif_dmg(data) {
        return Some((FileType::Dmg, DetectionSource::Magic));
    }

    // ── First-byte jump table ────────────────────────────────────────
    // Dispatch on data[0] to avoid evaluating 30+ conditions sequentially.
    // Each arm only checks formats that start with that byte.
    let result = match data[0] {
        0x00 => {
            // AppleDouble (`._<name>`) resource forks: 00 05 16 07.
            // macOS routinely smuggles these into tarballs alongside real
            // files. Their bodies are binary metadata blobs (xattrs, finder
            // info, resource forks), not the file types their extension
            // claims. Return Unknown so cleave's `is_program()` skip kicks
            // in — otherwise `._foo.php` gets analyzed as PHP, the binary
            // body trips entropy/obfuscation traits, and a benign Composer
            // tarball lights up at suspicious.
            if data.len() >= 4 && data[1] == 0x05 && data[2] == 0x16 && data[3] == 0x07 {
                Some((FileType::Unknown, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x7F => {
            // ELF: 7F 45 4C 46
            if data.len() >= 4 && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
                Some((FileType::Elf, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'M' => {
            // PE: MZ, or Cabinet: MSCF
            if data[1] == b'Z' {
                Some((FileType::Pe, DetectionSource::Magic))
            } else if data.len() >= 4 && data[1] == b'S' && data[2] == b'C' && data[3] == b'F' {
                Some((FileType::Cab, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'P' => {
            // ZIP/JAR/OOXML: PK
            if data[1] == b'K' {
                Some(classify_pk(path, data))
            } else {
                None
            }
        }
        0xCA => {
            // Java class and Mach-O fat both start with CAFEBABE.
            // Java's bytes 6..8 are the class-file `major_version`
            // (45 = Java 1.1, 52 = Java 8, 65 = Java 21 — well over
            // a decade of headroom in 45..=70). Mach-O fat's bytes
            // 4..8 are `nfat_arch` (BE u32), realistically ≤ 12.
            //
            // Either signal alone misfires on random or hostile bytes
            // shaped like CAFEBABE: a junk file whose `major_version`
            // lands at 0x01F4 (500) fails the Java check, then the
            // Mach-O parser tries to slice with a several-billion
            // offset. Combine both checks so we only call it Mach-O
            // when nfat_arch is plausible AND the Java major isn't.
            if data.len() >= 8 && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE {
                let major = u16::from_be_bytes([data[6], data[7]]);
                let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if (45..=70).contains(&major) || nfat_arch > 16 {
                    Some((FileType::JavaClass, DetectionSource::Magic))
                } else {
                    Some((FileType::MachO, DetectionSource::Magic))
                }
            } else {
                None
            }
        }
        0xFE => {
            // Mach-O: FEEDFACE (32-bit) or FEEDFACF (64-bit)
            if data.len() >= 4
                && data[1] == 0xED
                && data[2] == 0xFA
                && (data[3] == 0xCE || data[3] == 0xCF)
            {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCE => {
            // Mach-O 32-bit swapped: CEFAEDFE
            if data.len() >= 4 && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCF => {
            // Mach-O 64-bit swapped: CFFAEDFE
            if data.len() >= 4 && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xBE => {
            // Mach-O fat swapped: BEBAFECA
            if data.len() >= 4 && data[1] == 0xBA && data[2] == 0xFE && data[3] == 0xCA {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xFF => {
            // JPEG: FF D8 FF
            if data.len() >= 3 && data[1] == 0xD8 && data[2] == 0xFF {
                Some((FileType::Jpeg, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x89 => {
            // PNG: 89 50 4E 47 0D 0A 1A 0A
            if data.starts_with(b"\x89PNG\r\n\x1a\n") {
                Some((FileType::Png, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xD0 => {
            // OLE2/CFBF: D0 CF 11 E0 A1 B1 1A E1
            if data.len() >= 8
                && data[1] == 0xCF
                && data[2] == 0x11
                && data[3] == 0xE0
                && data[4] == 0xA1
                && data[5] == 0xB1
                && data[6] == 0x1A
                && data[7] == 0xE1
            {
                Some((FileType::OleDoc, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x4C => {
            // LNK: 4C 00 00 00 01 14 02 00 ...
            if data.len() >= LNK_MAGIC.len() && data.starts_with(LNK_MAGIC) {
                Some((FileType::Lnk, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'R' => {
            // RAR: Rar!
            if data.starts_with(b"Rar!") {
                Some((FileType::Rar, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'F' => {
            // Compiled AppleScript: Fasd
            if data.starts_with(b"Fasd") {
                Some((FileType::AppleScript, DetectionSource::Magic))
            } else if data.len() >= 12 && data.starts_with(b"FOR1") && &data[8..12] == b"BEAM" {
                // Erlang/Elixir BEAM bytecode: IFF container `FOR1` <u32 size> `BEAM`.
                Some((FileType::Beam, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'I' => {
            // Compiled HTML Help: ITSF
            if data.starts_with(b"ITSF") {
                Some((FileType::Chm, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'{' => {
            // RTF: {\rtf
            if data.starts_with(b"{\\rtf") {
                Some((FileType::Rtf, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'%' => {
            // PDF: %PDF-
            if data.starts_with(b"%PDF-") {
                Some((FileType::Pdf, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x80 => {
            // Python pickle (protocol 2+). The 0x80 prefix is shared with many binary
            // formats, so we require a pickle-associated extension to avoid false positives.
            if (2..=5).contains(&data[1]) {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase);
                if matches!(
                    ext.as_deref(),
                    Some("pkl" | "pickle" | "joblib" | "pt" | "pth")
                ) {
                    Some((FileType::Pickle, DetectionSource::Magic))
                } else {
                    None
                }
            } else {
                None
            }
        }
        b'b' => {
            // Binary Plist: bplist
            if data.starts_with(b"bplist") {
                Some((FileType::Plist, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'!' => {
            // Debian package: !<arch>
            if data.starts_with(b"!<arch>") {
                Some((FileType::Deb, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'x' => {
            // XAR (macOS PKG): xar!
            if data.starts_with(b"xar!") {
                Some((FileType::PkgMacos, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'C' => {
            // Chrome extension: Cr24
            if data.starts_with(b"Cr24") {
                Some((FileType::Crx, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xED => {
            // RPM: ED AB EE DB
            if data.len() >= 4 && data[1] == 0xAB && data[2] == 0xEE && data[3] == 0xDB {
                Some((FileType::Rpm, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x1F => {
            // Gzip: 1F 8B — could wrap a tar or be a single compressed file.
            // Use extension to tell them apart; unknown extension → plain gz.
            if data[1] == 0x8B {
                // `.apk` + gzip magic is an Alpine Linux package (a
                // gzip-concatenated tar), distinct from the Android `.apk`
                // (a zip — handled by `classify_pk`). The two never share
                // magic, so container magic alone disambiguates them.
                let ft = if path_ends_with_ci(path, b".apk") {
                    FileType::ApkAlpine
                } else if path_ends_with_ci(path, b".crate") {
                    // Cargo-specific extension; always a `<name>-<ver>/` gzip tar.
                    FileType::Crate
                } else if path_ends_with_ci(path, b".tar.gz") || path_ends_with_ci(path, b".tgz") {
                    // npm publishes gzip tarballs with everything under a
                    // `package/` prefix; that marker — not the generic
                    // extension — is what identifies an npm package.
                    if gzip_tar_is_npm(data) {
                        FileType::Npm
                    } else {
                        FileType::TarGz
                    }
                } else {
                    FileType::Gz
                };
                Some((ft, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xFD => {
            // XZ: FD 37 7A 58
            if data.starts_with(b"\xfd7zX") {
                let ft = if path_ends_with_ci(path, b".tar.xz") || path_ends_with_ci(path, b".txz")
                {
                    FileType::TarXz
                } else {
                    FileType::Xz
                };
                Some((ft, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'B' => {
            // Bzip2: BZh
            if data.starts_with(b"BZh") {
                let ft = if path_ends_with_ci(path, b".tar.bz2")
                    || path_ends_with_ci(path, b".tbz2")
                    || path_ends_with_ci(path, b".tbz")
                {
                    FileType::TarBz2
                } else {
                    FileType::Bz2
                };
                Some((ft, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'7' => {
            // 7z: 37 7A BC AF 27 1C
            if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
                Some((FileType::SevenZ, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x28 => {
            // Zstandard: 28 B5 2F FD
            if data.len() >= 4 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
                // FreeBSD (`.pkg`, `+MANIFEST` marker) and Arch
                // (`.pkg.tar.zst`, `.PKGINFO` marker) are both zstd tars,
                // disambiguated by their leading manifest member.
                let ft = if is_freebsd_pkg_zstd(path, data) {
                    FileType::PkgFreebsd
                } else if path_ends_with_ci(path, b".pkg.tar.zst") {
                    if zstd_tar_has_pkginfo(data) {
                        FileType::PkgArch
                    } else {
                        FileType::TarZst
                    }
                } else if path_ends_with_ci(path, b".tar.zst")
                    || path_ends_with_ci(path, b".tzst")
                    || path_ends_with_ci(path, b".xbps")
                {
                    FileType::TarZst
                } else {
                    FileType::Zst
                };
                Some((ft, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'#' => {
            // Shebang: #!
            if data[1] == b'!' {
                detect_shebang(data)
            } else {
                None
            }
        }
        b'<' => {
            // PHP opening tag: <?php
            if data.starts_with(b"<?php") {
                Some((FileType::Php, DetectionSource::Magic))
            } else if let Some(r) = detect_xml_plist(data) {
                Some(r)
            } else {
                // Generic XML: <?xml prolog or well-known root elements.
                detect_xml(data)
            }
        }
        _ => None,
    };

    if result.is_some() {
        return result;
    }

    // ── Fallback checks (rare paths) ─────────────────────────────────
    // These are guarded by cheap pre-checks to avoid unnecessary work.

    // Python bytecode (3.5+): XX 0D 0D 0A — first byte varies by version
    if data.len() >= 4 && data[1] == 0x0D && data[2] == 0x0D && data[3] == 0x0A {
        return Some((FileType::PythonBytecode, DetectionSource::Magic));
    }

    // Tampered PE: only scan if there's an 'M' in the first 64 bytes
    if memchr::memchr(b'M', &data[1..data.len().min(64)]).is_some() {
        if let Some(ft) = detect_tampered_pe(data) {
            return Some((ft, DetectionSource::Magic));
        }
    }

    // XML Plist not starting with '<' — only check if first bytes suggest XML-ish content
    // (whitespace or BOM before a '<' tag)
    if data[0] != b'<' && memchr::memchr(b'<', &data[..data.len().min(64)]).is_some() {
        if let Some(r) = detect_xml_plist(data) {
            return Some(r);
        }
    }

    if looks_like_github_actions_workflow(path, data) {
        return Some((FileType::GithubActions, DetectionSource::Heuristic));
    }

    // Manifest files — only check if there's a filename component
    if path.file_name().is_some() {
        if let Some(ft) = detect_manifest(path, data) {
            return Some((ft, DetectionSource::Filename));
        }
    }

    None
}

fn looks_like_udif_dmg(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    let trailer = &data[data.len() - 512..];
    if !trailer.starts_with(b"koly") {
        return false;
    }

    let version = u32::from_be_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let header_size = u32::from_be_bytes([trailer[8], trailer[9], trailer[10], trailer[11]]);
    version >= 4 && header_size == 512
}

/// Case-insensitive suffix match on path bytes (no allocation).
fn path_ends_with_ci(path: &Path, suffix: &[u8]) -> bool {
    let s = path.to_string_lossy();
    let bytes = s.as_bytes();
    if bytes.len() < suffix.len() {
        return false;
    }
    bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn is_freebsd_pkg_zstd(path: &Path, data: &[u8]) -> bool {
    if !path_ends_with_ci(path, b".pkg") {
        return false;
    }
    let Ok(mut decoder) = zstd::stream::read::Decoder::new(data) else {
        return false;
    };
    let mut prefix = [0u8; 32];
    let Ok(n) = decoder.read(&mut prefix) else {
        return false;
    };
    prefix[..n].starts_with(b"+COMPACT_MANIFEST") || prefix[..n].starts_with(b"+MANIFEST")
}

/// Peek a gzip tar's leading members (header names only) to decide whether the
/// layout is an npm package: every entry under a `package/` prefix, with a
/// `package/package.json` present. Bails on the first non-`package/` entry, so
/// a non-npm gzip tar costs one header. Bounded to the first 16 members.
fn gzip_tar_is_npm(data: &[u8]) -> bool {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(data));
    let Ok(entries) = archive.entries() else {
        return false;
    };
    for entry in entries.take(24) {
        let Ok(entry) = entry else { return false };
        // Tar metadata headers (pax/GNU long-name) aren't real members.
        if matches!(
            entry.header().entry_type(),
            tar::EntryType::XGlobalHeader
                | tar::EntryType::XHeader
                | tar::EntryType::GNULongName
                | tar::EntryType::GNULongLink
        ) {
            continue;
        }
        let Ok(path) = entry.path() else { continue };
        let path = path.to_string_lossy();
        let trimmed = path.trim_end_matches('/');
        // Skip macOS AppleDouble sidecars (`._name`) that `tar` smuggles in
        // alongside real files — they're not part of the npm layout.
        let basename = trimmed.rsplit('/').next().unwrap_or(trimmed);
        if basename.starts_with("._") {
            continue;
        }
        // The directory entry arrives as `package` (trailing slash stripped);
        // files under it as `package/<...>`. The first real entry outside that
        // tree means this isn't an npm package.
        if trimmed != "package" && !trimmed.starts_with("package/") {
            return false;
        }
        if trimmed == "package/package.json" {
            return true;
        }
    }
    false
}

/// Peek a zstd tar's leading members for the Arch package marker `.PKGINFO`
/// (its first member). Bounded to the first 8 members.
fn zstd_tar_has_pkginfo(data: &[u8]) -> bool {
    let Ok(decoder) = zstd::stream::read::Decoder::new(data) else {
        return false;
    };
    let mut archive = tar::Archive::new(decoder);
    let Ok(entries) = archive.entries() else {
        return false;
    };
    for entry in entries.take(8) {
        let Ok(entry) = entry else { return false };
        if entry.path().is_ok_and(|p| p.as_os_str() == ".PKGINFO") {
            return true;
        }
    }
    false
}

fn looks_like_github_actions_workflow(path: &Path, data: &[u8]) -> bool {
    if !(path_ends_with_ci(path, b".yml") || path_ends_with_ci(path, b".yaml")) {
        return false;
    }

    let Ok(text) = std::str::from_utf8(&data[..data.len().min(16 * 1024)]) else {
        return false;
    };

    let mut has_on = false;
    let mut has_jobs = false;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("---") || line.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }

        let Some((key, _)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim_matches(|c| c == '\'' || c == '"' || c == ' ');
        match key {
            "on" => has_on = true,
            "jobs" => has_jobs = true,
            _ => {}
        }
        if has_on && has_jobs {
            return true;
        }
    }

    false
}

/// Classify PK (ZIP) archives into JAR, OOXML, or generic Archive.
///
/// ZIP-based formats share the same magic bytes, so disambiguation requires
/// the file extension or scanning for format-specific entries in the ZIP.
fn classify_pk(path: &Path, data: &[u8]) -> (FileType, DetectionSource) {
    // Lowercase extension once for all checks
    let ext_lower = lowercase_ext(path);
    let ext = ext_lower.as_deref().unwrap_or("");

    if matches!(ext, "jar" | "war" | "ear") {
        return (FileType::Jar, DetectionSource::Magic);
    }

    if ext == "xpi" {
        return (FileType::Xpi, DetectionSource::Magic);
    }

    if ext == "whl" {
        return (FileType::Whl, DetectionSource::Magic);
    }

    // `.apk` + zip magic is an Android application package. Alpine's `.apk` is
    // a gzip tar, resolved in the gzip branch — the two never share magic.
    if ext == "apk" {
        return (FileType::ApkAndroid, DetectionSource::Magic);
    }

    // Zip-based package ecosystems, disambiguated from a generic zip by their
    // unambiguous extension (each ships its identity manifest inside).
    if ext == "conda" {
        return (FileType::Conda, DetectionSource::Magic);
    }
    if ext == "egg" {
        return (FileType::Egg, DetectionSource::Magic);
    }
    if ext == "nupkg" {
        return (FileType::Nupkg, DetectionSource::Magic);
    }
    if ext == "ipa" {
        return (FileType::Ipa, DetectionSource::Magic);
    }
    if ext == "vsix" {
        return (FileType::Vsix, DetectionSource::Magic);
    }

    if matches!(
        ext,
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "dotm" | "xltx" | "xltm"
    ) {
        return (FileType::Ooxml, DetectionSource::Magic);
    }

    // OpenDocument Format by extension
    if matches!(
        ext,
        "odt"
            | "ods"
            | "odp"
            | "odg"
            | "odf"
            | "ott"
            | "ots"
            | "otp"
            | "odm"
            | "oth"
            | "otg"
            | "odb"
            | "odc"
            | "odi"
    ) {
        return (FileType::Odf, DetectionSource::Magic);
    }

    // OOXML by content (scan for [Content_Types].xml) — but not for archive containers
    let is_archive_opc = matches!(
        ext,
        "zip"
            | "jar"
            | "war"
            | "ear"
            | "vsix"
            | "nupkg"
            | "xpi"
            | "whl"
            | "epub"
            | "apk"
            | "ipa"
            | "aar"
            | "egg"
            | "phar"
            | "pyz"
            | "conda"
            | "msix"
            | "appx"
            | "msixbundle"
            | "appxbundle"
            | "aab"
            | "apks"
            | "xapk"
            | "cbz"
    );
    if !is_archive_opc && memchr::memmem::find(data, b"[Content_Types].xml").is_some() {
        return (FileType::Ooxml, DetectionSource::Magic);
    }

    // ODF by content — first ZIP entry is an uncompressed "mimetype" file
    // containing "application/vnd.oasis.opendocument."
    if memchr::memmem::find(data, b"application/vnd.oasis.opendocument.").is_some() {
        return (FileType::Odf, DetectionSource::Magic);
    }

    (FileType::Zip, DetectionSource::Magic)
}

/// Lowercase extension into a stack buffer. Returns None if no extension or too long.
fn lowercase_ext(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?;
    if ext.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf[..ext.len()].copy_from_slice(ext.as_bytes());
    buf[..ext.len()].make_ascii_lowercase();
    // Input was valid UTF-8 ASCII, lowering preserves that.
    let Ok(ext) = std::str::from_utf8(&buf[..ext.len()]) else {
        return None;
    };
    Some(ext.to_string())
}

/// Detect a generic XML document by `<?xml` prolog or well-known root elements.
///
/// Called only when the file starts with `<` and is NOT a plist/PHP/HTML document.
/// Plist is checked first (separate function), and HTML is distinguished from
/// generic XML by the `looks_like_html` content heuristic that runs later.
fn detect_xml(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    // Standard XML prolog
    if data.starts_with(b"<?xml") {
        return Some((FileType::Xml, DetectionSource::Magic));
    }

    // MSBuild projects often omit the prolog and start with `<Project `
    // Matching the xmlns confirms it's real MSBuild (not some other <Project>).
    if data.starts_with(b"<Project ") || data.starts_with(b"<Project\t") {
        let head = &data[..data.len().min(512)];
        if memchr::memmem::find(head, b"schemas.microsoft.com/developer/msbuild").is_some() {
            return Some((FileType::Xml, DetectionSource::Magic));
        }
    }

    // Other common extensionless XML roots. Each is narrow enough to avoid
    // colliding with HTML — HTML would match `looks_like_html` heuristic after
    // this returns None.
    for prefix in [
        &b"<svg "[..],
        &b"<svg>"[..],
        &b"<rss "[..],
        &b"<feed "[..],
        &b"<RDF "[..],
        &b"<configuration>"[..],
        &b"<configuration "[..],
        &b"<manifest "[..],
        &b"<Configuration "[..],
    ] {
        if data.starts_with(prefix) {
            return Some((FileType::Xml, DetectionSource::Magic));
        }
    }

    None
}

/// Detect XML Plist markers in the first 256 bytes.
fn detect_xml_plist(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    let head = &data[..data.len().min(256)];
    if memchr::memmem::find(head, b"<plist").is_some()
        || memchr::memmem::find(head, b"<!DOCTYPE plist").is_some()
    {
        Some((FileType::Plist, DetectionSource::Magic))
    } else {
        None
    }
}

/// Detect shebang-based file types.
///
/// Extracts the interpreter name from the first line and dispatches via a
/// match on the path segment after the last '/'.
fn detect_shebang(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    // Extract first line (up to 128 bytes)
    let limit = data.len().min(128);
    let first_line_end = memchr::memchr(b'\n', &data[..limit]).unwrap_or(limit);
    let line = &data[2..first_line_end]; // skip "#!"

    // Handle "#!/usr/bin/env <interpreter>" — find the interpreter name
    // Handle "#!/path/to/interpreter" — use last path component
    let interp = if line.starts_with(b"/usr/bin/env ") || line.starts_with(b"/usr/bin/env\t") {
        // Skip "/usr/bin/env " and any extra whitespace
        let rest = &line[13..];
        let start = rest
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(0);
        &rest[start..]
    } else {
        // Find last '/' and take everything after it
        let slash_pos = memchr::memrchr(b'/', line).map_or(0, |p| p + 1);
        &line[slash_pos..]
    };

    // Take just the interpreter basename (stop at space, tab, or NUL for flags like "python3 -u")
    let end = interp
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == 0)
        .unwrap_or(interp.len());
    let name = &interp[..end];

    // Match interpreter name
    match name {
        b"sh" | b"bash" | b"zsh" | b"dash" | b"ash" | b"ksh" | b"fish" | b"tcsh" | b"csh"
        | b"atf-sh" => Some((FileType::Shell, DetectionSource::Shebang)),
        // debian/rules and friends: `#!/usr/bin/make -f`. Without this the
        // content heuristics mis-type make scripts as source code.
        b"make" | b"gmake" => Some((FileType::Makefile, DetectionSource::Shebang)),
        b"python" | b"python2" | b"python3" => Some((FileType::Python, DetectionSource::Shebang)),
        b"node" | b"nodejs" | b"deno" | b"bun" => {
            Some((FileType::JavaScript, DetectionSource::Shebang))
        }
        b"ruby" => Some((FileType::Ruby, DetectionSource::Shebang)),
        b"perl" | b"perl5" => Some((FileType::Perl, DetectionSource::Shebang)),
        b"php" | b"php8" | b"php7" => Some((FileType::Php, DetectionSource::Shebang)),
        b"lua" | b"luajit" => Some((FileType::Lua, DetectionSource::Shebang)),
        _ => None,
    }
}

/// Detect tampered PE: MZ within first 64 bytes with valid PE\0\0 signature.
fn detect_tampered_pe(data: &[u8]) -> Option<FileType> {
    let search_limit = data.len().min(64);
    if search_limit < 3 {
        return None;
    }
    // Use memchr to find 'M' bytes instead of scanning byte-by-byte
    let mut pos = 1; // skip position 0 (already checked by MZ branch)
    while let Some(offset) = memchr::memchr(b'M', &data[pos..search_limit.saturating_sub(1)]) {
        let i = pos + offset;
        if data.get(i + 1) == Some(&b'Z') {
            let pe_data = &data[i..];
            if pe_data.len() >= 0x40 {
                let e_lfanew = u32::from_le_bytes([
                    pe_data[0x3C],
                    pe_data[0x3D],
                    pe_data[0x3E],
                    pe_data[0x3F],
                ]) as usize;
                if e_lfanew + 4 <= pe_data.len() && pe_data[e_lfanew..e_lfanew + 4] == *b"PE\0\0" {
                    return Some(FileType::Pe);
                }
            }
        }
        pos = i + 1;
    }
    None
}

/// Detect manifest file types that require content inspection.
fn detect_manifest(path: &Path, data: &[u8]) -> Option<FileType> {
    let file_name = path.file_name()?.to_str()?;

    // Stack-allocated lowercase (manifest names are short)
    let mut buf = [0u8; 32];
    let len = file_name.len().min(buf.len());
    buf[..len].copy_from_slice(&file_name.as_bytes()[..len]);
    buf[..len].make_ascii_lowercase();
    let name = std::str::from_utf8(&buf[..len]).unwrap_or("");

    match name {
        "package.json" => Some(FileType::PackageJson),
        "package-lock.json" => Some(FileType::PackageLockJson),
        "go.mod" => Some(FileType::GoMod),
        "go.sum" => Some(FileType::GoSum),
        "requirements.txt" => Some(FileType::RequirementsTxt),
        "poetry.lock" => Some(FileType::PoetryLock),
        "pipfile.lock" => Some(FileType::PipfileLock),
        "gemfile.lock" => Some(FileType::GemfileLock),
        "composer.lock" => Some(FileType::ComposerLock),
        "yarn.lock" => Some(FileType::YarnLock),
        "pnpm-lock.yaml" => Some(FileType::PnpmLock),
        "manifest.json" => {
            // Chrome extension: manifest_version + at least one Chrome-specific key
            if memchr::memmem::find(data, b"\"manifest_version\"").is_some()
                && (memchr::memmem::find(data, b"\"permissions\"").is_some()
                    || memchr::memmem::find(data, b"\"content_scripts\"").is_some()
                    || memchr::memmem::find(data, b"\"background\"").is_some()
                    || memchr::memmem::find(data, b"\"host_permissions\"").is_some())
            {
                Some(FileType::ChromeManifest)
            } else {
                None
            }
        }
        "extension.vsixmanifest" => Some(FileType::VsixManifest),
        ".pkginfo" | ".buildinfo" | ".mtree" => Some(FileType::Text),
        "pkg-info" | "metadata" => Some(FileType::PkgInfo),
        "action.yml" | "action.yaml" => Some(FileType::GithubActions),
        _ => {
            if name.ends_with(".vsixmanifest") {
                Some(FileType::VsixManifest)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn elf_magic() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        let (ft, src) = detect_from_content(Path::new("a.out"), data).unwrap();
        assert_eq!(ft, FileType::Elf);
        assert_eq!(src, DetectionSource::Magic);
    }

    #[test]
    fn pe_magic() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        let (ft, _) = detect_from_content(Path::new("app.exe"), data).unwrap();
        assert_eq!(ft, FileType::Pe);
    }

    #[test]
    fn macho_64() {
        let data = [0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
        let (ft, _) = detect_from_content(Path::new("binary"), &data).unwrap();
        assert_eq!(ft, FileType::MachO);
    }

    #[test]
    fn java_class_vs_macho_fat() {
        let java = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 52];
        let (ft, _) = detect_from_content(Path::new("Main.class"), &java).unwrap();
        assert_eq!(ft, FileType::JavaClass);

        let macho = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        let (ft, _) = detect_from_content(Path::new("universal"), &macho).unwrap();
        assert_eq!(ft, FileType::MachO);
    }

    /// Junk file shaped like CAFEBABE whose `major_version` falls
    /// outside the Java range AND whose `nfat_arch` is implausibly
    /// large. Pre-fix, this classified as Mach-O and the fat parser
    /// then sliced with a multi-gigabyte start offset → panic. We now
    /// treat it as a Java class so the lenient class parser handles
    /// it (and bails cleanly when the body doesn't match).
    #[test]
    fn cafebabe_with_implausible_nfat_arch_falls_back_to_java() {
        // bytes[4..8] = 0x4D 0x11 0xAB 0xD4 — nfat_arch ≈ 1.29 billion
        // and major_version = 0xABD4 (44_000), both outside their
        // respective sane ranges.
        let junk = [0xCA, 0xFE, 0xBA, 0xBE, 0x4D, 0x11, 0xAB, 0xD4];
        let (ft, _) = detect_from_content(Path::new("anon.class"), &junk).unwrap();
        assert_eq!(ft, FileType::JavaClass);
    }

    #[test]
    fn shebang_bash() {
        let data = b"#!/bin/bash\necho hello\n";
        let (ft, src) = detect_from_content(Path::new("script"), data).unwrap();
        assert_eq!(ft, FileType::Shell);
        assert_eq!(src, DetectionSource::Shebang);
    }

    #[test]
    fn shebang_python() {
        let data = b"#!/usr/bin/env python3\nimport sys\n";
        let (ft, src) = detect_from_content(Path::new("tool"), data).unwrap();
        assert_eq!(ft, FileType::Python);
        assert_eq!(src, DetectionSource::Shebang);
    }

    #[test]
    fn shebang_env_with_flags() {
        let data = b"#!/usr/bin/env python3 -u\nimport sys\n";
        let (ft, _) = detect_from_content(Path::new("tool"), data).unwrap();
        assert_eq!(ft, FileType::Python);
    }

    #[test]
    fn shebang_direct_path() {
        let data = b"#!/usr/local/bin/perl\nuse strict;\n";
        let (ft, _) = detect_from_content(Path::new("script"), data).unwrap();
        assert_eq!(ft, FileType::Perl);
    }

    #[test]
    fn shebang_node() {
        let data = b"#!/usr/bin/env node\nconsole.log('hi');\n";
        let (ft, _) = detect_from_content(Path::new("script"), data).unwrap();
        assert_eq!(ft, FileType::JavaScript);
    }

    #[test]
    fn png_magic() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let (ft, _) = detect_from_content(Path::new("image.png"), data).unwrap();
        assert_eq!(ft, FileType::Png);
    }

    #[test]
    fn jpeg_magic() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let (ft, _) = detect_from_content(Path::new("photo.jpg"), &data).unwrap();
        assert_eq!(ft, FileType::Jpeg);
    }

    #[test]
    fn ole2_magic() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0; 100]);
        let (ft, _) = detect_from_content(Path::new("doc.doc"), &data).unwrap();
        assert_eq!(ft, FileType::OleDoc);
    }

    #[test]
    fn plist_xml() {
        let data = b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC>";
        let (ft, _) = detect_from_content(Path::new("Info.plist"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
    }

    #[test]
    fn plist_binary() {
        let data = b"bplist00\x00\x00\x00\x00";
        let (ft, _) = detect_from_content(Path::new("prefs"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
    }

    #[test]
    fn rar_archive() {
        let data = b"Rar!\x1a\x07\x01\x00";
        let (ft, _) = detect_from_content(Path::new("archive.rar"), data).unwrap();
        assert_eq!(ft, FileType::Rar);
    }

    #[test]
    fn gzip_plain() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("data.gz"), &data).unwrap();
        assert_eq!(ft, FileType::Gz);
    }

    #[test]
    fn gzip_tar() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("data.tar.gz"), &data).unwrap();
        assert_eq!(ft, FileType::TarGz);
    }

    #[test]
    fn zip_archive() {
        let data = b"PK\x03\x04some content here";
        let (ft, _) = detect_from_content(Path::new("data.zip"), data).unwrap();
        assert_eq!(ft, FileType::Zip);
    }

    #[test]
    fn jar_detected_as_jar() {
        let data = b"PK\x03\x04jar content here";
        let (ft, _) = detect_from_content(Path::new("lib.jar"), data).unwrap();
        assert_eq!(ft, FileType::Jar);
    }

    #[test]
    fn apk_android_is_zip() {
        // `.apk` + ZIP magic → Android package (never the Alpine gzip form).
        let data = b"PK\x03\x04android apk content";
        let (ft, _) = detect_from_content(Path::new("app.apk"), data).unwrap();
        assert_eq!(ft, FileType::ApkAndroid);
    }

    #[test]
    fn apk_alpine_is_gzip_tar() {
        // `.apk` + gzip magic → Alpine package, disambiguated from Android by
        // container magic alone (no member peek).
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("musl-1.2.4.apk"), &data).unwrap();
        assert_eq!(ft, FileType::ApkAlpine);
    }

    #[test]
    fn macos_pkg_is_xar() {
        let data = b"xar!\x00\x1c\x00\x01";
        let (ft, _) = detect_from_content(Path::new("installer.pkg"), data).unwrap();
        assert_eq!(ft, FileType::PkgMacos);
    }

    #[test]
    fn ooxml_by_extension() {
        let data = b"PK\x03\x04some office content";
        let (ft, _) = detect_from_content(Path::new("report.docx"), data).unwrap();
        assert_eq!(ft, FileType::Ooxml);
    }

    #[test]
    fn ooxml_by_content_types() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"[Content_Types].xml");
        let (ft, _) = detect_from_content(Path::new("report.txt"), &data).unwrap();
        assert_eq!(ft, FileType::Ooxml);
    }

    #[test]
    fn php_opening_tag() {
        let data = b"<?php\necho 'hello';\n";
        let (ft, _) = detect_from_content(Path::new("page"), data).unwrap();
        assert_eq!(ft, FileType::Php);
    }

    #[test]
    fn tampered_pe() {
        let mut data = vec![0x00; 256];
        data[5] = b'M';
        data[6] = b'Z';
        let e_lfanew: u32 = 0x80;
        data[5 + 0x3C] = (e_lfanew & 0xFF) as u8;
        data[5 + 0x3D] = 0;
        data[5 + 0x3E] = 0;
        data[5 + 0x3F] = 0;
        let pe_sig_offset = 5 + e_lfanew as usize;
        if pe_sig_offset + 4 <= data.len() {
            data[pe_sig_offset] = b'P';
            data[pe_sig_offset + 1] = b'E';
            data[pe_sig_offset + 2] = 0;
            data[pe_sig_offset + 3] = 0;
        }
        let (ft, _) = detect_from_content(Path::new("suspicious"), &data).unwrap();
        assert_eq!(ft, FileType::Pe);
    }

    #[test]
    fn chrome_manifest() {
        let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
        let (ft, _) = detect_from_content(Path::new("manifest.json"), data).unwrap();
        assert_eq!(ft, FileType::ChromeManifest);
    }

    #[test]
    fn lnk_magic() {
        let mut data = LNK_MAGIC.to_vec();
        data.extend_from_slice(&[0; 100]);
        let (ft, _) = detect_from_content(Path::new("shortcut.lnk"), &data).unwrap();
        assert_eq!(ft, FileType::Lnk);
    }

    #[test]
    fn python_bytecode() {
        let data = [0x42, 0x0D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let (ft, _) = detect_from_content(Path::new("module.pyc"), &data).unwrap();
        assert_eq!(ft, FileType::PythonBytecode);
    }

    #[test]
    fn beam_bytecode() {
        // IFF container: `FOR1` <u32 size> `BEAM`
        let data = *b"FOR1\x00\x00\x40\x08BEAMAtU8";
        let (ft, src) = detect_from_content(Path::new("gb_trees.beam"), &data).unwrap();
        assert_eq!(ft, FileType::Beam);
        assert_eq!(src, DetectionSource::Magic);
    }

    #[test]
    fn for1_without_beam_is_not_beam() {
        // `FOR1` IFF header for a non-BEAM form (e.g. AIFF would be `FORM`) must not match.
        let data = *b"FOR1\x00\x00\x00\x08AIFFxxxx";
        assert!(detect_from_content(Path::new("x"), &data).is_none());
    }

    #[test]
    fn zstd_archive() {
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        let (ft, _) = detect_from_content(Path::new("data.zst"), &data).unwrap();
        assert_eq!(ft, FileType::Zst);
    }

    #[test]
    fn freebsd_pkg_zstd_archive() {
        let data = zstd::encode_all(&b"+COMPACT_MANIFEST\0payload"[..], 3).unwrap();
        let (ft, _) = detect_from_content(Path::new("BerkeleyGW-4.0_2.pkg"), &data).unwrap();
        assert_eq!(ft, FileType::PkgFreebsd);
    }

    #[test]
    fn crate_is_gzip_tar() {
        // `.crate` is cargo-specific; gzip magic + extension suffices.
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("serde-1.0.0.crate"), &data).unwrap();
        assert_eq!(ft, FileType::Crate);
    }

    #[test]
    fn npm_tgz_detected_by_package_prefix() {
        // npm tarballs put everything under `package/`; build a real gzip tar
        // so the marker peek runs.
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            // macOS `tar` smuggles an AppleDouble `._package` sidecar in as the
            // first entry; the peek must skip it rather than bail.
            let mut sidecar = tar::Header::new_ustar();
            sidecar.set_path("._package").unwrap();
            sidecar.set_size(0);
            sidecar.set_cksum();
            b.append(&sidecar, std::io::empty()).unwrap();
            // Real `tar` emits the `package/` directory entry first; the peek
            // must tolerate it (its path arrives without the trailing slash).
            let mut dir = tar::Header::new_ustar();
            dir.set_path("package/").unwrap();
            dir.set_size(0);
            dir.set_entry_type(tar::EntryType::Directory);
            dir.set_cksum();
            b.append(&dir, std::io::empty()).unwrap();
            let body = br#"{"name":"demo","version":"1.0.0"}"#;
            let mut h = tar::Header::new_ustar();
            h.set_path("package/package.json").unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
            b.finish().unwrap();
        }
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("demo-1.0.0.tgz"), &gz).unwrap();
        assert_eq!(ft, FileType::Npm);

        // A `.tgz` without the `package/` layout stays a generic gzip tar.
        let plain = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"not a tar").unwrap();
            e.finish().unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("blob.tgz"), &plain).unwrap();
        assert_eq!(ft, FileType::TarGz);
    }

    #[test]
    fn arch_pkg_detected_by_pkginfo() {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            let body = b"pkgname = demo\n";
            let mut h = tar::Header::new_ustar();
            h.set_path(".PKGINFO").unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
            b.finish().unwrap();
        }
        let zst = zstd::encode_all(&tar[..], 3).unwrap();
        let (ft, _) =
            detect_from_content(Path::new("demo-1.0-1-x86_64.pkg.tar.zst"), &zst).unwrap();
        assert_eq!(ft, FileType::PkgArch);
    }

    #[test]
    fn zip_package_ecosystems_by_extension() {
        for (name, expected) in [
            ("pkg.conda", FileType::Conda),
            ("lib.egg", FileType::Egg),
            ("Newtonsoft.Json.nupkg", FileType::Nupkg),
            ("App.ipa", FileType::Ipa),
            ("ext.vsix", FileType::Vsix),
        ] {
            let data = b"PK\x03\x04zip body";
            let (ft, _) = detect_from_content(Path::new(name), data).unwrap();
            assert_eq!(ft, expected, "{name}");
        }
    }

    #[test]
    fn sevenz_archive() {
        let data = b"7z\xBC\xAF\x27\x1C\x00\x00";
        let (ft, _) = detect_from_content(Path::new("data.7z"), data).unwrap();
        assert_eq!(ft, FileType::SevenZ);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(detect_from_content(Path::new("x"), b"x").is_none());
    }
}
