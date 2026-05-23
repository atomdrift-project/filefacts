//! Extension and filename-based detection.

use std::path::Path;

use super::FileType;

/// Detect file type from path (filename match first, then extension).
pub(crate) fn detect_from_path(path: &Path) -> Option<FileType> {
    // Filename matches (manifests, well-known names)
    if let Some(ft) = detect_from_filename(path) {
        return Some(ft);
    }

    // GitHub Actions workflow files
    let path_str = path.to_string_lossy();
    if path_str.contains(".github/workflows/") || path_str.contains(".github\\workflows\\") {
        let p = path_str.as_bytes();
        if ends_with_ci(p, b".yml") || ends_with_ci(p, b".yaml") {
            return Some(FileType::GithubActions);
        }
    }

    // systemd service drop-ins: *.service.d/*.conf
    if (path_str.contains(".service.d/") || path_str.contains(".service.d\\"))
        && ends_with_ci(path_str.as_bytes(), b".conf")
    {
        return Some(FileType::SystemdService);
    }

    // Archive multi-part extensions (check before single extension)
    let p = path_str.as_bytes();
    if ends_with_ci(p, b".pkg.tar.zst") {
        return Some(FileType::TarZst);
    }
    if ends_with_ci(p, b".pkg.tar.xz") {
        return Some(FileType::TarXz);
    }
    if ends_with_ci(p, b".pkg.tar.gz") {
        return Some(FileType::TarGz);
    }
    if ends_with_ci(p, b".tar.gz") || ends_with_ci(p, b".tgz") || ends_with_ci(p, b".crate") {
        return Some(FileType::TarGz);
    }
    if ends_with_ci(p, b".tar.bz2") || ends_with_ci(p, b".tbz2") || ends_with_ci(p, b".tbz") {
        return Some(FileType::TarBz2);
    }
    if ends_with_ci(p, b".tar.xz") || ends_with_ci(p, b".txz") {
        return Some(FileType::TarXz);
    }
    if ends_with_ci(p, b".tar.zst") || ends_with_ci(p, b".tzst") || ends_with_ci(p, b".xbps") {
        return Some(FileType::TarZst);
    }
    if ends_with_ci(p, b".tar") || ends_with_ci(p, b".gem") {
        return Some(FileType::Tar);
    }

    // JAR/WAR/EAR by extension
    if ends_with_ci(p, b".jar") || ends_with_ci(p, b".war") || ends_with_ci(p, b".ear") {
        return Some(FileType::Jar);
    }

    // Single extension
    detect_from_extension(path)
}

/// Returns true if the path matched via filename (not extension).
pub(crate) fn is_filename_match(path: &Path) -> bool {
    detect_from_filename(path).is_some() || {
        let s = path.to_string_lossy();
        (s.contains(".github/workflows/") || s.contains(".github\\workflows\\"))
            && (ends_with_ci(s.as_bytes(), b".yml") || ends_with_ci(s.as_bytes(), b".yaml"))
    }
}

/// Returns true if the path has a data/config extension that should not be
/// sent through content heuristics.
pub(crate) fn is_data_format(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };

    // Use a small stack buffer to lowercase without allocation
    let mut buf = [0u8; 16];
    if ext.len() >= buf.len() {
        return false;
    }
    buf[..ext.len()].copy_from_slice(ext.as_bytes());
    buf[..ext.len()].make_ascii_lowercase();
    // Input was valid UTF-8; ASCII lowering preserves that invariant.
    let Ok(ext_lower) = std::str::from_utf8(&buf[..ext.len()]) else {
        return false;
    };

    matches!(
        ext_lower,
        "yaml"
            | "yml"
            | "json"
            | "toml"
            | "ini"
            | "cfg"
            | "conf"
            | "properties"
            | "txt"
            | "text"
            | "md"
            | "markdown"
            | "rst"
            | "adoc"
            | "csv"
            | "tsv"
            | "log"
            | "svg"
            | "xml"
            | "service"
            | "erl"
            | "hrl"
            | "elv"
            | "nu"
            | "fish"
    )
}

/// Detect from well-known filenames.
fn detect_from_filename(path: &Path) -> Option<FileType> {
    let name = path.file_name()?.to_str()?;

    if name.eq_ignore_ascii_case("package.json") {
        return Some(FileType::PackageJson);
    }
    if name.eq_ignore_ascii_case("package-lock.json") {
        return Some(FileType::PackageLockJson);
    }
    if name.eq_ignore_ascii_case("composer.json") {
        return Some(FileType::ComposerJson);
    }
    if name.eq_ignore_ascii_case("cargo.toml") {
        return Some(FileType::CargoToml);
    }
    if name.eq_ignore_ascii_case("pyproject.toml") {
        return Some(FileType::PyProjectToml);
    }
    if name.eq_ignore_ascii_case("pkg-info") || name.eq_ignore_ascii_case("metadata") {
        return Some(FileType::PkgInfo);
    }
    if name.eq_ignore_ascii_case("meta.json") || name.eq_ignore_ascii_case("metadata.json") {
        return Some(FileType::PkgInfo);
    }
    if name.eq_ignore_ascii_case("extension.vsixmanifest")
        || name
            .get(name.len().saturating_sub(13)..)
            .is_some_and(|s| s.eq_ignore_ascii_case(".vsixmanifest"))
    {
        return Some(FileType::VsixManifest);
    }
    if name.eq_ignore_ascii_case("action.yml") || name.eq_ignore_ascii_case("action.yaml") {
        return Some(FileType::GithubActions);
    }
    if name == "Dockerfile" || name.starts_with("Dockerfile.") || name.starts_with("dockerfile.") {
        return Some(FileType::Dockerfile);
    }
    if name == "Containerfile" || name.starts_with("Containerfile.") {
        return Some(FileType::Dockerfile);
    }
    if name.starts_with("Makefile") || name.starts_with("GNUmakefile") {
        return Some(FileType::Makefile);
    }
    if name.eq_ignore_ascii_case("LICENSE") || name.eq_ignore_ascii_case("COPYING") {
        return Some(FileType::Text);
    }

    None
}

/// Detect from single file extension.
fn detect_from_extension(path: &Path) -> Option<FileType> {
    let ext = path.extension()?.to_str()?;

    // Stack-allocated lowercase (no allocation for extensions < 16 chars)
    let mut buf = [0u8; 16];
    if ext.len() >= buf.len() {
        return None;
    }
    buf[..ext.len()].copy_from_slice(ext.as_bytes());
    buf[..ext.len()].make_ascii_lowercase();
    // Input was valid UTF-8; ASCII lowering preserves that invariant.
    let Ok(ext_lower) = std::str::from_utf8(&buf[..ext.len()]) else {
        return None;
    };

    match ext_lower {
        "sh" | "bash" | "ksh" | "zsh" | "csh" | "tcsh" | "dash" => Some(FileType::Shell),
        "py" | "pth" => Some(FileType::Python),
        "js" | "mjs" | "cjs" | "jsx" => Some(FileType::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(FileType::TypeScript),
        "go" => Some(FileType::Go),
        "rs" => Some(FileType::Rust),
        "java" => Some(FileType::Java),
        "class" => Some(FileType::JavaClass),
        "pyc" => Some(FileType::PythonBytecode),
        "rb" | "rbs" => Some(FileType::Ruby),
        "php" => Some(FileType::Php),
        "pl" | "pm" | "t" => Some(FileType::Perl),
        "ps1" | "psm1" | "psd1" => Some(FileType::PowerShell),
        "kt" | "kts" => Some(FileType::Kotlin),
        "bat" | "cmd" => Some(FileType::Batch),
        "vbs" | "vbe" | "wsf" | "wsc" => Some(FileType::Vbs),
        "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" | "hxx" | "hh" | "pas" | "dpr" | "asm" | "s"
        | "nasm" => Some(FileType::C),
        "lua" => Some(FileType::Lua),
        "cs" => Some(FileType::CSharp),
        "swift" => Some(FileType::Swift),
        "m" | "mm" => Some(FileType::ObjectiveC),
        "groovy" | "gradle" => Some(FileType::Groovy),
        "scala" | "sc" => Some(FileType::Scala),
        "zig" => Some(FileType::Zig),
        "ex" | "exs" => Some(FileType::Elixir),
        "scpt" | "applescript" => Some(FileType::AppleScript),
        "service" => Some(FileType::SystemdService),
        "desktop" => Some(FileType::DesktopEntry),
        "xml" | "csproj" | "vbproj" | "fsproj" | "proj" | "props" | "targets" | "vcxproj"
        | "xaml" | "config" | "settings" | "svg" => Some(FileType::Xml),
        "plist" | "resx" => Some(FileType::Plist),
        "rtf" => Some(FileType::Rtf),
        "doc" | "msi" | "msp" | "msg" | "dot" | "ppt" | "xls" | "xlt" => Some(FileType::OleDoc),
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "dotm" | "xltx" | "xltm" => {
            Some(FileType::Ooxml)
        }
        "odt" | "ods" | "odp" | "odg" | "odf" | "ott" | "ots" | "otp" => Some(FileType::Odf),
        "lnk" => Some(FileType::Lnk),
        "pdf" => Some(FileType::Pdf),
        "jpg" | "jpeg" => Some(FileType::Jpeg),
        "png" => Some(FileType::Png),
        "pkl" | "pickle" | "joblib" => Some(FileType::Pickle),
        "zip" | "apk" | "ipa" | "xpi" | "epub" | "nupkg" | "vsix" | "aar" | "egg" | "whl"
        | "phar" => Some(FileType::Zip),
        "7z" => Some(FileType::SevenZ),
        "rar" => Some(FileType::Rar),
        "deb" => Some(FileType::Deb),
        "rpm" => Some(FileType::Rpm),
        "crx" => Some(FileType::Crx),
        "pkg" => Some(FileType::Pkg),
        "cab" => Some(FileType::Cab),
        "chm" => Some(FileType::Chm),
        "gz" => Some(FileType::Gz),
        "bz2" => Some(FileType::Bz2),
        "xz" => Some(FileType::Xz),
        "zst" => Some(FileType::Zst),
        "html" | "htm" => Some(FileType::Html),
        "md" | "markdown" => Some(FileType::Markdown),
        "mk" | "mak" => Some(FileType::Makefile),
        "dockerfile" | "containerfile" => Some(FileType::Dockerfile),
        "txt" | "text" | "b64" | "base64" => Some(FileType::Text),
        // Opaque binary "data" extensions that commonly carry encrypted/XOR'd payloads
        // (PlugX's Canon.dat, Cobalt Strike profiles, shellcode drops).
        "dat" | "bin" | "payload" | "raw" => Some(FileType::Data),
        _ => None,
    }
}

/// Case-insensitive suffix check on raw bytes (no allocation).
fn ends_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn python_extension() {
        assert_eq!(
            detect_from_path(Path::new("script.py")),
            Some(FileType::Python)
        );
        assert_eq!(
            detect_from_path(Path::new("site-package.pth")),
            Some(FileType::Python)
        );
    }

    #[test]
    fn shell_extensions() {
        for ext in &["sh", "bash", "zsh", "ksh"] {
            let path = format!("script.{ext}");
            assert_eq!(
                detect_from_path(Path::new(&path)),
                Some(FileType::Shell),
                "failed for .{ext}"
            );
        }
    }

    #[test]
    fn package_json() {
        assert_eq!(
            detect_from_path(Path::new("/foo/bar/package.json")),
            Some(FileType::PackageJson)
        );
    }

    #[test]
    fn package_lock_json() {
        assert_eq!(
            detect_from_path(Path::new("/foo/bar/package-lock.json")),
            Some(FileType::PackageLockJson)
        );
    }

    #[test]
    fn github_actions_workflow() {
        assert_eq!(
            detect_from_path(Path::new(".github/workflows/ci.yml")),
            Some(FileType::GithubActions)
        );
    }

    #[test]
    fn systemd_service_extension() {
        assert_eq!(
            detect_from_path(Path::new("persistence.service")),
            Some(FileType::SystemdService)
        );
    }

    #[test]
    fn systemd_service_drop_in() {
        assert_eq!(
            detect_from_path(Path::new("/etc/systemd/system/ssh.service.d/override.conf")),
            Some(FileType::SystemdService)
        );
    }

    #[test]
    fn tar_gz() {
        assert_eq!(
            detect_from_path(Path::new("data.tar.gz")),
            Some(FileType::TarGz)
        );
        assert_eq!(
            detect_from_path(Path::new("data.tgz")),
            Some(FileType::TarGz)
        );
        assert_eq!(
            detect_from_path(Path::new("data.tar.bz2")),
            Some(FileType::TarBz2)
        );
        assert_eq!(
            detect_from_path(Path::new("data.tar.xz")),
            Some(FileType::TarXz)
        );
        assert_eq!(
            detect_from_path(Path::new("data.tar.zst")),
            Some(FileType::TarZst)
        );
        assert_eq!(detect_from_path(Path::new("data.tar")), Some(FileType::Tar));
        assert_eq!(detect_from_path(Path::new("data.rar")), Some(FileType::Rar));
        assert_eq!(
            detect_from_path(Path::new("data.7z")),
            Some(FileType::SevenZ)
        );
        assert_eq!(
            detect_from_path(Path::new("package.deb")),
            Some(FileType::Deb)
        );
        assert_eq!(
            detect_from_path(Path::new("package.rpm")),
            Some(FileType::Rpm)
        );
    }

    #[test]
    fn jar_extension() {
        assert_eq!(detect_from_path(Path::new("lib.jar")), Some(FileType::Jar));
    }

    #[test]
    fn unknown_extension() {
        assert_eq!(detect_from_path(Path::new("file.xyz")), None);
    }

    #[test]
    fn data_formats_blocked() {
        assert!(is_data_format(Path::new("config.yaml")));
        assert!(is_data_format(Path::new("data.json")));
        assert!(is_data_format(Path::new("evil.service")));
        assert!(is_data_format(Path::new("notes.txt")));
        assert!(!is_data_format(Path::new("script.py")));
        assert!(!is_data_format(Path::new("binary")));
    }

    #[test]
    fn case_insensitive_extension() {
        assert_eq!(
            detect_from_path(Path::new("script.PY")),
            Some(FileType::Python)
        );
    }

    #[test]
    fn filename_match_flag() {
        assert!(is_filename_match(Path::new("package.json")));
        assert!(!is_filename_match(Path::new("script.py")));
        assert!(is_filename_match(Path::new(".github/workflows/ci.yml")));
    }

    #[test]
    fn ooxml_extensions() {
        assert_eq!(
            detect_from_path(Path::new("report.docx")),
            Some(FileType::Ooxml)
        );
        assert_eq!(
            detect_from_path(Path::new("sheet.xlsx")),
            Some(FileType::Ooxml)
        );
    }

    #[test]
    fn erlang_returns_none() {
        assert_eq!(detect_from_path(Path::new("app.erl")), None);
    }
}
