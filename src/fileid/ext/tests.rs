use super::*;

#[test]
fn autorun_config_carriers_are_typed() {
    // `.code-workspace` is JSONC with a possible folder-open `tasks` block.
    assert_eq!(
        detect_from_path(Path::new("api.code-workspace")),
        Some(FileType::Json)
    );
    // Run-control dotfiles have no `Path::extension`; match by name.
    for name in [".npmrc", "sub/.NPMRC", ".yarnrc"] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::Text),
            "{name}"
        );
    }
    // `.yarnrc.yml` keeps its YAML extension typing.
    assert_eq!(
        detect_from_path(Path::new(".yarnrc.yml")),
        Some(FileType::Yaml)
    );
}

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
    for ext in &[
        "sh", "bash", "zsh", "ksh", "fish", "command", "ebuild", "eclass",
    ] {
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
fn registry_json_suffix_beats_generic_json() {
    assert_eq!(
        detect_from_path(Path::new("/tmp/left-pad@1.3.0.registry.json")),
        Some(FileType::Registry)
    );
    // A plain .json is still generic, not a registry document.
    assert_eq!(
        detect_from_path(Path::new("/tmp/data.json")),
        Some(FileType::Json)
    );
}

#[test]
fn reg_extension_is_a_registry_export() {
    assert_eq!(
        detect_from_path(Path::new("C:\\Temp\\settings.REG")),
        Some(FileType::Reg)
    );
    // `.registry.json` is package metadata, never a registry export.
    assert_eq!(
        detect_from_path(Path::new("left-pad@1.3.0.registry.json")),
        Some(FileType::Registry)
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

/// A provenance or lifecycle suffix hides the real extension. Source-shaped
/// inner types resolve through it; binaries and archives do not, because
/// their magic bytes are better evidence than a renamed path.
#[test]
fn wrapper_suffix_reveals_inner_source_extension() {
    assert_eq!(
        detect_from_path(Path::new("configure-backdoor.c.fragment")),
        Some(FileType::C)
    );
    assert_eq!(
        detect_from_path(Path::new("wp-includes-vars.php.sample")),
        Some(FileType::Php)
    );
    assert_eq!(
        detect_from_path(Path::new("loader.js.bak")),
        Some(FileType::JavaScript)
    );
    // Not source-shaped: content detection decides these.
    assert_eq!(detect_from_path(Path::new("payload.zip.sample")), None);
    assert_eq!(detect_from_path(Path::new("libc.so.disabled")), None);
    // No inner extension to reveal.
    assert_eq!(detect_from_path(Path::new("evidence.fragment")), None);
    // A wrapper suffix is stripped only once.
    assert_eq!(detect_from_path(Path::new("x.py.bak.old")), None);
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
    assert!(is_data_format(Path::new("package/parse.ts.map")));
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
        detect_from_path(Path::new("windows.foundation.idl")),
        Some(FileType::C)
    );
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

#[test]
fn patel_extension_is_text_not_shell() {
    // Iosevka's PatEL glyph source (`.ptl`) must not parse as Shell — its
    // `$$include`/`$`-macro heads otherwise trip shell command-execution
    // and obfuscated-command traits on font-outline source.
    for name in ["gsub-ligation.ptl", "packages/font-otl/src/gsub-cv-ss.ptl"] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::Text),
            "{name} should be Text, not Shell"
        );
    }
}

#[test]
fn yara_rule_extension_is_yara_not_source_language() {
    // A rule corpus is a list of quoted malware strings. Typed as a source
    // language it runs that language's traits over its own detection
    // patterns, so the rules fire on the rules.
    for name in [
        "apt_cryptominer.yar",
        "rules/Multi_Cryptominer_Xmrig.yara",
        "THIRD_PARTY/IcedID.YARA",
    ] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::Yara),
            "{name} should be Yara, not PHP/Kotlin/Python/Shell"
        );
    }
}

#[test]
fn mysqltest_scripts_are_text() {
    for name in [
        "mariadb-11.8.6/mysql-test/main/gis-rtree.test",
        "mariadb-11.8.6/mysql-test/include/mix1.inc",
        "storage/columnstore/columnstore/mysql-test/columnstore/basic/r/ctype_cmp_char1_latin1_swedish_ci.result",
        "mysql-test/suite/innodb/t/instant_alter_bugs.test",
    ] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::Text),
            "{name} should be Text, not a content-sniffed language"
        );
    }
    // Outside a mysql-test tree the generic extensions are left alone.
    assert_ne!(
        detect_from_path(Path::new("sqlite/test/select1.test")),
        Some(FileType::Text)
    );
    assert_ne!(
        detect_from_path(Path::new("mysql-test/lib/My/Platform.pm")),
        Some(FileType::Text)
    );
}

#[test]
fn protobuf_schema_extension_is_text_not_kotlin() {
    assert_eq!(
        detect_from_path(Path::new("c2.proto")),
        Some(FileType::Text),
        "protobuf schemas use package/message syntax but are not Kotlin"
    );
}

#[test]
fn license_files_are_text_not_source() {
    // License/copying files (incl. license-name suffixes) are plain text —
    // otherwise their prose content-sniffs to a programming language.
    for name in [
        "LICENSE",
        "licence",
        "LICENSE.txt",
        "LICENSE.GPLv3",
        "LICENSE.LGPLv3",
        "COPYING",
        "COPYING.LESSER",
        "LICENSE-MIT",
    ] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::Text),
            "{name} should be Text"
        );
    }
    // A source file merely starting with "license" keeps its code type.
    assert_eq!(
        detect_from_path(Path::new("license-checker.js")),
        Some(FileType::JavaScript),
        "license-checker.js must stay JavaScript"
    );
}

/// Checksums and signatures published beside a release name the artifact
/// first. Every multi-part rule above matches a suffix, so the archive
/// or library name in the middle never wins over the sidecar's own
/// extension.
#[test]
fn release_sidecars_keep_their_own_type() {
    for name in [
        "jdk-21.tar.gz.sig",
        "zlib-1.3.tar.zst.asc",
        "rails-7.0.4.gem.sig",
        "app.jar.asc",
        "libssl.so.3.sig",
        "SHA256SUMS.SIGN",
    ] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::PgpSignature),
            "{name}"
        );
    }
    for name in [
        "jdk-21.tar.gz.sha256sum",
        "zlib-1.3.tar.zst.SHA512SUM",
        "src.tar.sha1sum",
        "app.jar.md5sum",
        "libssl.so.3.sha256",
    ] {
        assert_eq!(
            detect_from_path(Path::new(name)),
            Some(FileType::Text),
            "{name}"
        );
    }
}

#[test]
fn odf_extensions_are_shared_with_the_zip_classifier() {
    for ext in ["odt", "ODS", "otp", "odi"] {
        let name = format!("report.{ext}");
        assert_eq!(
            detect_from_path(Path::new(&name)),
            Some(FileType::Odf),
            "{name}"
        );
    }
    assert!(!is_odf_extension("docx"));
}

#[test]
fn lowercase_ext_fits_the_stack_buffer() {
    let ext = |name: &str| lowercase_ext(Path::new(name)).map(|e| e.to_string());
    assert_eq!(ext("Setup.EXE").as_deref(), Some("exe"));
    assert_eq!(
        ext("x.ABCDEFGHIJKLMNOP").as_deref(),
        Some("abcdefghijklmnop")
    );
    assert_eq!(ext("x.abcdefghijklmnopq"), None);
    assert_eq!(ext("Makefile"), None);
    assert_eq!(ext(".npmrc"), None);
}
