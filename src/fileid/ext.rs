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
    if ends_with_ci(p, b".crate") {
        return Some(FileType::Crate);
    }
    if ends_with_ci(p, b".tar.gz") || ends_with_ci(p, b".tgz") {
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
    if ends_with_ci(p, b".gem") {
        return Some(FileType::Gem);
    }
    if ends_with_ci(p, b".tar") {
        return Some(FileType::Tar);
    }

    // Versioned ELF shared libraries, e.g. libssl.so.3 or libc.so.6.
    if has_versioned_so_suffix(&path_str) {
        return Some(FileType::Elf);
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
    if name.eq_ignore_ascii_case("binding.gyp") {
        return Some(FileType::Gyp);
    }
    if name.eq_ignore_ascii_case("cargo.toml") {
        return Some(FileType::CargoToml);
    }
    if name.eq_ignore_ascii_case("pyproject.toml") {
        return Some(FileType::PyProjectToml);
    }
    if name.eq_ignore_ascii_case(".pkginfo")
        || name.eq_ignore_ascii_case(".buildinfo")
        || name.eq_ignore_ascii_case(".mtree")
    {
        return Some(FileType::Text);
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
    // Meson build files. Their own DSL (not source code); classify as a build
    // file so source/AST traits (e.g. JavaScript obfuscation) do not run on them.
    if name.eq_ignore_ascii_case("meson.build")
        || name.eq_ignore_ascii_case("meson.options")
        || name.eq_ignore_ascii_case("meson_options.txt")
    {
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
        "sh" | "bash" | "ksh" | "zsh" | "csh" | "tcsh" | "dash" | "fish" | "command" => {
            Some(FileType::Shell)
        }
        "py" | "pyw" | "pyi" | "pth" => Some(FileType::Python),
        "js" | "mjs" | "cjs" | "jsx" | "jse" => Some(FileType::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(FileType::TypeScript),
        // CSS and preprocessor stylesheets. There is no dedicated stylesheet
        // analyzer, and their C-like braces/`;`/`//` syntax otherwise scores as
        // JavaScript under content heuristics — which fires JS AST rules
        // (arithmetic-density obfuscation, string-concat) on benign layout math
        // like `margin: $a - $b`. Treat them as plain text: still scanned for
        // strings/URLs/secrets, but never parsed as a JS AST.
        "css" | "scss" | "sass" | "less" | "styl" | "pcss" | "postcss" => Some(FileType::Text),
        // Vim script. No dedicated analyzer, and its ubiquitous `let ` bindings
        // otherwise score as JavaScript under content heuristics — which fires
        // JS rules on syntax databases like filetype.vim (a catalog of sensitive
        // path patterns: .aws/credentials, /etc/hosts, ...). Treat as plain text.
        "vim" => Some(FileType::Text),
        // Lisp family. No dedicated analyzer; parenthesized arithmetic like
        // `(- a b)` otherwise scores as JavaScript and fires JS obfuscation
        // rules on e.g. the GCL ANSI test suite. Treat as plain text.
        "lsp" | "lisp" | "el" | "cl" | "scm" => Some(FileType::Text),
        // OCaml family. No dedicated analyzer; `let`-heavy implementations
        // otherwise score as JavaScript and `.mli` `val` declarations score
        // as Kotlin under weak content heuristics. Treat as plain text.
        "ml" | "mli" | "mll" | "mly" | "mld" | "eliom" | "eliomi" => Some(FileType::Text),
        // SQL dumps/scripts. No dedicated analyzer; large dumps of long INSERT
        // statements otherwise content-score as Batch and fire batch
        // line/token-bloat obfuscation rules. Treat as plain text.
        "sql" | "ddl" | "dml" => Some(FileType::Text),
        // Smali (Android/Dalvik bytecode disassembly). No dedicated analyzer;
        // its dense arithmetic/array literals otherwise score as JavaScript and
        // fire JS arithmetic-obfuscation rules (e.g. jadx test .smali fixtures).
        "smali" => Some(FileType::Text),
        // Unified-diff patches. No dedicated analyzer; their `-`/`+` line
        // prefixes otherwise content-score as JavaScript, and the removed-line
        // `-` markers parse as subtraction operators — tripping
        // js-arithmetic-array-init on benign kernel/source patch sets. Text.
        "patch" | "diff" => Some(FileType::Text),
        // TypeScript compiler test baselines (annotated code fixtures, not
        // executable JS): x.types / x.symbols / x.baseline.
        "types" | "symbols" | "baseline" => Some(FileType::Text),
        "go" => Some(FileType::Go),
        "rs" => Some(FileType::Rust),
        "java" => Some(FileType::Java),
        "class" => Some(FileType::JavaClass),
        "pyc" | "pyo" => Some(FileType::PythonBytecode),
        "beam" => Some(FileType::Beam),
        "rb" | "rbs" | "gemspec" => Some(FileType::Ruby),
        "php" | "php3" | "php4" | "php5" | "php7" | "phtml" => Some(FileType::Php),
        "pl" | "pm" | "t" => Some(FileType::Perl),
        "ps1" | "psm1" | "psd1" => Some(FileType::PowerShell),
        "kt" | "kts" => Some(FileType::Kotlin),
        "bat" | "cmd" => Some(FileType::Batch),
        "jcl" => Some(FileType::Jcl),
        "vbs" | "vbe" | "wsf" | "wsc" | "wsh" => Some(FileType::Vbs),
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
        "clj" | "cljs" | "cljc" | "cljr" | "edn" | "bb" => Some(FileType::Clojure),
        "scpt" | "applescript" => Some(FileType::AppleScript),
        "service" => Some(FileType::SystemdService),
        "desktop" => Some(FileType::DesktopEntry),
        "xml" | "csproj" | "vbproj" | "fsproj" | "proj" | "props" | "targets" | "vcxproj"
        | "xaml" | "config" | "settings" | "svg" | "nuspec" | "wsdl" | "xsd" | "xsl" | "xslt" => {
            Some(FileType::Xml)
        }
        "json" => Some(FileType::Json),
        "gyp" | "gypi" => Some(FileType::Gyp),
        "plist" | "resx" => Some(FileType::Plist),
        "rtf" => Some(FileType::Rtf),
        "doc" | "msi" | "msp" | "msg" | "dot" | "ppt" | "pps" | "pot" | "ppa" | "xls" | "xlt"
        | "xla" => Some(FileType::OleDoc),
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "dotm" | "xltx" | "xltm"
        | "xlam" | "ppam" | "potx" | "potm" | "ppsx" | "ppsm" | "sldx" | "sldm" => {
            Some(FileType::Ooxml)
        }
        "odt" | "ods" | "odp" | "odg" | "odf" | "ott" | "ots" | "otp" | "odm" | "oth" | "otg"
        | "odb" | "odc" | "odi" => Some(FileType::Odf),
        "exe" | "dll" | "sys" | "scr" | "cpl" | "ocx" | "drv" | "efi" | "pyd" => Some(FileType::Pe),
        "so" | "elf" | "ko" => Some(FileType::Elf),
        "dylib" | "bundle" => Some(FileType::MachO),
        "lnk" => Some(FileType::Lnk),
        "pdf" => Some(FileType::Pdf),
        "jpg" | "jpeg" | "jpe" | "jfif" => Some(FileType::Jpeg),
        "png" => Some(FileType::Png),
        "pkl" | "pickle" | "joblib" => Some(FileType::Pickle),
        // Zip-based package ecosystems with unambiguous extensions get their
        // own type (the magic branch agrees when `PK` is present; this keeps
        // the extension fallback consistent so it isn't flagged a mismatch).
        "ipa" => Some(FileType::Ipa),
        "nupkg" => Some(FileType::Nupkg),
        "vsix" => Some(FileType::Vsix),
        "egg" => Some(FileType::Egg),
        "conda" => Some(FileType::Conda),
        "zip" | "apk" | "epub" | "aar" | "phar" | "pyz" | "msix" | "appx" | "msixbundle"
        | "appxbundle" | "aab" | "apks" | "xapk" | "cbz" => Some(FileType::Zip),
        "xpi" => Some(FileType::Xpi),
        "whl" => Some(FileType::Whl),
        "7z" | "cb7" => Some(FileType::SevenZ),
        "rar" | "cbr" => Some(FileType::Rar),
        "deb" | "udeb" => Some(FileType::Deb),
        "rpm" | "srpm" => Some(FileType::Rpm),
        "crx" => Some(FileType::Crx),
        "pkg" => Some(FileType::PkgMacos),
        "cab" | "msu" => Some(FileType::Cab),
        "chm" => Some(FileType::Chm),
        "asar" => Some(FileType::Asar),
        "gz" => Some(FileType::Gz),
        "bz2" => Some(FileType::Bz2),
        "xz" => Some(FileType::Xz),
        "zst" => Some(FileType::Zst),
        "html" | "htm" => Some(FileType::Html),
        // R Markdown / Quarto / Sweave are markdown documents with embedded
        // code chunks — classify as Markdown so they aren't analysed as source
        // code (their YAML frontmatter and code chunks otherwise trip
        // polyglot/obfuscation matchers).
        "md" | "markdown" | "rmd" | "qmd" | "rnw" => Some(FileType::Markdown),
        "mk" | "mak" => Some(FileType::Makefile),
        "dockerfile" | "containerfile" => Some(FileType::Dockerfile),
        "txt" | "text" | "b64" | "base64" => Some(FileType::Text),
        // Opaque binary "data" extensions that commonly carry encrypted/XOR'd payloads
        // (PlugX's Canon.dat, Cobalt Strike profiles, shellcode drops).
        "dat" | "bin" | "payload" | "raw" => Some(FileType::Data),
        _ => None,
    }
}

fn has_versioned_so_suffix(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let bytes = name.as_bytes();
    let Some(pos) = bytes
        .windows(4)
        .rposition(|window| window.eq_ignore_ascii_case(b".so."))
    else {
        return false;
    };
    let suffix = &bytes[pos + 4..];
    !suffix.is_empty()
        && suffix.iter().any(u8::is_ascii_digit)
        && suffix.iter().all(|b| b.is_ascii_digit() || *b == b'.')
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
            detect_from_path(Path::new("windowed.pyw")),
            Some(FileType::Python)
        );
        assert_eq!(
            detect_from_path(Path::new("types.pyi")),
            Some(FileType::Python)
        );
        assert_eq!(
            detect_from_path(Path::new("site-package.pth")),
            Some(FileType::Python)
        );
    }

    #[test]
    fn compiled_python_extensions() {
        assert_eq!(
            detect_from_path(Path::new("module.pyc")),
            Some(FileType::PythonBytecode)
        );
        assert_eq!(
            detect_from_path(Path::new("module.pyo")),
            Some(FileType::PythonBytecode)
        );
        assert_eq!(detect_from_path(Path::new("app.pyz")), Some(FileType::Zip));
    }

    #[test]
    fn shell_extensions() {
        for ext in &["sh", "bash", "zsh", "ksh", "fish", "command"] {
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
    fn native_binary_extensions() {
        assert_eq!(detect_from_path(Path::new("app.exe")), Some(FileType::Pe));
        assert_eq!(
            detect_from_path(Path::new("native.pyd")),
            Some(FileType::Pe)
        );
        assert_eq!(
            detect_from_path(Path::new("libfoo.so")),
            Some(FileType::Elf)
        );
        assert_eq!(
            detect_from_path(Path::new("module.ko")),
            Some(FileType::Elf)
        );
        assert_eq!(
            detect_from_path(Path::new("/usr/lib/libssl.so.3")),
            Some(FileType::Elf)
        );
        assert_eq!(
            detect_from_path(Path::new("/usr/lib/libc.so.6.1")),
            Some(FileType::Elf)
        );
        assert_eq!(
            detect_from_path(Path::new("libfoo.dylib")),
            Some(FileType::MachO)
        );
        assert_eq!(
            detect_from_path(Path::new("Plugin.bundle")),
            Some(FileType::MachO)
        );
        assert_eq!(detect_from_path(Path::new("note.so.old")), None);
    }

    #[test]
    fn package_archive_aliases() {
        for name in [
            "app.msix",
            "app.appx",
            "bundle.msixbundle",
            "bundle.appxbundle",
            "android.aab",
            "split.apks",
            "bundle.xapk",
            "comic.cbz",
        ] {
            assert_eq!(
                detect_from_path(Path::new(name)),
                Some(FileType::Zip),
                "failed for {name}"
            );
        }
    }

    #[test]
    fn archive_family_aliases() {
        assert_eq!(
            detect_from_path(Path::new("installer.msu")),
            Some(FileType::Cab)
        );
        assert_eq!(
            detect_from_path(Path::new("package.udeb")),
            Some(FileType::Deb)
        );
        assert_eq!(
            detect_from_path(Path::new("source.srpm")),
            Some(FileType::Rpm)
        );
        assert_eq!(
            detect_from_path(Path::new("comic.cbr")),
            Some(FileType::Rar)
        );
        assert_eq!(
            detect_from_path(Path::new("comic.cb7")),
            Some(FileType::SevenZ)
        );
    }

    #[test]
    fn odf_alias_extensions() {
        for name in [
            "text.odm",
            "web.oth",
            "drawing.otg",
            "database.odb",
            "chart.odc",
            "image.odi",
        ] {
            assert_eq!(
                detect_from_path(Path::new(name)),
                Some(FileType::Odf),
                "failed for {name}"
            );
        }
    }

    #[test]
    fn office_alias_extensions() {
        for name in ["show.pps", "template.pot", "addin.ppa", "addin.xla"] {
            assert_eq!(
                detect_from_path(Path::new(name)),
                Some(FileType::OleDoc),
                "failed for {name}"
            );
        }
        for name in [
            "addin.xlam",
            "addin.ppam",
            "template.potx",
            "template.potm",
            "show.ppsx",
            "show.ppsm",
            "slide.sldx",
            "slide.sldm",
        ] {
            assert_eq!(
                detect_from_path(Path::new(name)),
                Some(FileType::Ooxml),
                "failed for {name}"
            );
        }
    }

    #[test]
    fn image_alias_extensions() {
        assert_eq!(
            detect_from_path(Path::new("photo.jpe")),
            Some(FileType::Jpeg)
        );
        assert_eq!(
            detect_from_path(Path::new("photo.jfif")),
            Some(FileType::Jpeg)
        );
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
    fn source_alias_extensions() {
        assert_eq!(
            detect_from_path(Path::new("payload.jse")),
            Some(FileType::JavaScript)
        );
        assert_eq!(
            detect_from_path(Path::new("plugin.gemspec")),
            Some(FileType::Ruby)
        );
        assert_eq!(
            detect_from_path(Path::new("shell.phtml")),
            Some(FileType::Php)
        );
        assert_eq!(
            detect_from_path(Path::new("shell.php5")),
            Some(FileType::Php)
        );
        assert_eq!(
            detect_from_path(Path::new("settings.wsh")),
            Some(FileType::Vbs)
        );
        assert_eq!(
            detect_from_path(Path::new("package.nuspec")),
            Some(FileType::Xml)
        );
        assert_eq!(
            detect_from_path(Path::new("schema.xsd")),
            Some(FileType::Xml)
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

    #[test]
    fn stylesheets_are_text_not_javascript() {
        // Stylesheets must not be parsed as JS — their `$a - $b` layout math
        // otherwise trips JS arithmetic/obfuscation AST rules.
        for name in [
            "theme.scss",
            "layout/_sidebar.scss",
            "vars.sass",
            "mixins.less",
            "site.css",
            "app.styl",
        ] {
            assert_eq!(
                detect_from_path(Path::new(name)),
                Some(FileType::Text),
                "{name} should be Text, not JavaScript"
            );
        }
    }

    #[test]
    fn ocaml_extensions_are_text_not_javascript_or_kotlin() {
        for name in [
            "scheduler_bench.ml",
            "duneboot.mli",
            "lexer.mll",
            "parser.mly",
            "manual.mld",
            "page.eliom",
            "page.eliomi",
        ] {
            assert_eq!(
                detect_from_path(Path::new(name)),
                Some(FileType::Text),
                "{name} should be Text, not JavaScript or Kotlin"
            );
        }
    }
}
