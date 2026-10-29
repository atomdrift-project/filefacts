//! Release sidecars, named formats, unmatched input and the narrow APIs.

use super::*;

// ── Skip / non-match ─────────────────────────────────────────────

#[test]
fn unknown_binary_returns_none() {
    // `.bin` classifies as `Data` (see ext.rs), so an unregistered
    // extension and unrecognised magic exercise the "truly unknown" path.
    let got = detect(Path::new("data.blob"), b"\x00\x00\x00\x00");
    assert!(
        got.is_none(),
        "expected None for unknown content, got {got:?}"
    );
}

#[test]
fn magic_less_types_survive_a_wrapper_suffix() {
    // A quarantined or backed-up config has no signature in its bytes, so
    // the extension under the wrapper is the only evidence there is, and
    // unknown is not analyzed.
    let yaml = b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n";
    let json = b"{\n  \"name\": \"x\"\n}\n";
    assert_detect("deploy.yaml.quarantine", yaml, FileType::Yaml);
    assert_detect("cfg.yaml.bak", yaml, FileType::Yaml);
    assert_detect("package.json.bak", json, FileType::Json);
    assert_detect("index.js.bak", b"const a = 1;\n", FileType::JavaScript);
    // Binaries and archives are NOT typed from a name under a wrapper —
    // their magic is authoritative, so a renamed payload cannot claim a
    // type its bytes do not support.
    assert!(
        detect_path(Path::new("note.so.old")).is_none(),
        "a binary must not be typed from its name under a wrapper"
    );
    assert!(detect_path(Path::new("app.tar.gz.bak")).is_none());
}

#[test]
fn version_suffix_is_not_an_unknown_extension() {
    // Registry artifacts are stored as `<name>@<semver>` with no suffix.
    // `Path::extension` splits on the last dot and reports "0"/"25", which
    // was being read as an unrecognized extension — making every ordinary
    // npm/crate/gem tarball an `archive_as_unknown` masquerade signal.
    let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03";
    for name in [
        "keyvault-keys@4.8.0",
        "cranelift-native@0.118.0",
        "react-redux@7.1.25",
        "jsonpointer@v0.21.1",
        "python3.11",
    ] {
        let det = detect(Path::new(name), gz).unwrap();
        assert!(
            !det.extension_mismatch(),
            "{name} reported an extension mismatch on a version suffix"
        );
    }
    // A named extension still counts, in both directions.
    assert!(
        !detect(Path::new("pkg-1.2.3.tgz"), gz)
            .unwrap()
            .extension_mismatch()
    );
    assert!(
        detect(Path::new("photo.png"), gz)
            .unwrap()
            .extension_mismatch(),
        "a real extension disagreeing with content is still a mismatch"
    );
}

// ── Release sidecars, images and packages named by their suffix ───

/// A SquashFS superblock: `hsqs` magic, then the 4.0 header fields.
fn squashfs_superblock() -> Vec<u8> {
    let mut v = b"hsqs".to_vec();
    // inodes, mkfs_time, block_size, fragments, compression, block_log,
    // flags, ids, s_major(4), s_minor(0).
    v.extend_from_slice(&10u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&131_072u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    for field in [1u16, 17, 0, 0, 4, 0] {
        v.extend_from_slice(&field.to_le_bytes());
    }
    v.resize(256, 0);
    v
}

#[test]
fn snap_is_squashfs_named_by_extension() {
    // binwalk-ng_5.snap — a SquashFS image. The magic gives the filesystem;
    // only the extension says it is a Snap package.
    assert_detect("binwalk-ng_5.snap", &squashfs_superblock(), FileType::Snap);
    assert_detect(
        "firmware.squashfs",
        &squashfs_superblock(),
        FileType::SquashFs,
    );
    // Big-endian superblocks are the same filesystem.
    let mut be = squashfs_superblock();
    be[..4].copy_from_slice(b"sqsh");
    assert_detect("rootfs.bin", &be, FileType::SquashFs);
}

#[test]
fn snap_extension_without_readable_body() {
    // With no readable body, the extension still names the package.
    assert_detect("binwalk-ng_5.snap", b"", FileType::Snap);
    assert_eq!(
        detect_path(Path::new("binwalk-ng_5.snap"))
            .unwrap()
            .file_type,
        FileType::Snap
    );
}

#[test]
fn snap_text_snapshot_is_not_a_squashfs_archive() {
    let snapshot = b"// Jest Snapshot v1, https://goo.gl/fbAQLP\n\nexports[`cover 1`] = `\n\"<div class=\"wp-block-cover\">Cover</div>\"\n`;\n";
    for name in [
        "transforms.native.js.snap",
        "output.snap",
        "output.squashfs",
    ] {
        let detection = detect(Path::new(name), snapshot).unwrap();
        assert_eq!(
            detection.file_type,
            FileType::JavaScript,
            "{name}: {detection:?}"
        );
        assert!(detection.extension_mismatch(), "{name}: {detection:?}");
    }
    // Binary bodies without the filesystem signature also must not enter
    // the SquashFS extractor solely because of their name.
    assert_detect("opaque.snap", &[0, 1, 2, 3].repeat(64), FileType::Data);
}

#[test]
fn flatpak_is_extension_only() {
    // Beekeeper-Studio-5.9.3-aarch64.flatpak — an OSTree static delta in
    // GVariant framing, with no magic at a fixed offset to key on.
    assert_ext("Beekeeper-Studio-5.9.3-aarch64.flatpak", FileType::Flatpak);
}

#[test]
fn pgp_signature_armored_and_by_extension() {
    // OpenJDK21U-testimage_x64_mac_hotspot_21.0.12_8.tar.gz.sig — the `.sig`
    // suffix follows a `.tar.gz`, so it must beat the archive fallbacks.
    assert_ext(
        "OpenJDK21U-testimage_x64_mac_hotspot_21.0.12_8.tar.gz.sig",
        FileType::PgpSignature,
    );
    assert_detect(
        "release.asc",
        b"-----BEGIN PGP SIGNATURE-----\n\niQIzBAAB\n",
        FileType::PgpSignature,
    );
}

#[test]
fn certificate_signature_is_distinct_from_openpgp() {
    let data = include_bytes!("../../../tests/data/certificate-signature.sig");
    for name in ["libwidevinecdm.dylib.sig", "framework.SIGN", "renamed"] {
        let det = detect(Path::new(name), data).unwrap();
        assert_eq!(det.file_type, FileType::CertificateSignature, "{name}");
        assert_eq!(det.source, DetectionSource::Magic);
        assert!(!det.extension_mismatch(), "{name}");
    }
    assert_eq!(
        detect_content(data).unwrap().file_type,
        FileType::CertificateSignature
    );
    let mut flag_one = data.to_vec();
    *flag_one.last_mut().unwrap() = 1;
    assert_detect("framework.sig", &flag_one, FileType::CertificateSignature);
    // A certificate prefix cannot hide another body or malformed framing.
    for damaged in [
        &data[..data.len() - 1],
        &[data.as_slice(), b"payload"].concat(),
        &data[..64],
    ] {
        assert_ne!(
            detect_content(damaged).map(|d| d.file_type),
            Some(FileType::CertificateSignature)
        );
    }
    let mut bad_certificate = data.to_vec();
    bad_certificate[4] = 0x31;
    assert_ne!(
        detect_content(&bad_certificate).map(|d| d.file_type),
        Some(FileType::CertificateSignature)
    );
    // The convention applies to binary signature extensions, not ASCII armor.
    assert!(
        detect(Path::new("release.asc"), data)
            .unwrap()
            .extension_mismatch()
    );
}

#[test]
fn checksum_manifest_is_text() {
    // libdenort-x86_64-pc-windows-msvc.zip.sha256sum — the `.zip` in the
    // middle of the name must not win.
    assert_ext(
        "libdenort-x86_64-pc-windows-msvc.zip.sha256sum",
        FileType::Text,
    );
    assert_ext("SHASUMS256.txt", FileType::Text);
}

#[test]
fn generic_yaml_is_typed() {
    // hle.yaml / config.yaml / gpqa.yaml from HuggingFace model repos.
    assert_ext("hle.yaml", FileType::Yaml);
    assert_ext("config.yml", FileType::Yaml);
}

#[test]
fn yaml_dialects_are_not_extension_mismatches() {
    // A workflow is YAML: refining `.yml` to GithubActions is agreement
    // about one file, not a masquerade.
    let data = b"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
    let det = detect(Path::new("ci.yml"), data).unwrap();
    assert_eq!(det.file_type, FileType::GithubActions);
    assert!(!det.extension_mismatch());
    let det = detect(Path::new("pnpm-lock.yaml"), b"lockfileVersion: 9\n").unwrap();
    assert!(!det.extension_mismatch());
}

#[test]
fn new_types_round_trip_through_labels() {
    for ft in [
        FileType::Yaml,
        FileType::Snap,
        FileType::Flatpak,
        FileType::SquashFs,
        FileType::PgpSignature,
    ] {
        assert_eq!(FileType::from_label(ft.label()), Some(ft), "{ft:?}");
    }
}

#[test]
fn yaml_not_misclassified() {
    // A plain YAML config is Yaml — not the language whose keywords its
    // values happen to contain, and not unknown either. `on: push` is
    // deliberately workflow-shaped: the GitHub Actions refinement needs a
    // `jobs:` key too, so this must stay generic.
    let det = detect(Path::new("config.yaml"), b"name: test\non: push\n").unwrap();
    assert_eq!(det.file_type, FileType::Yaml);
    assert!(!det.extension_mismatch());
}

#[test]
fn json_data_detects_as_generic_json() {
    let det = detect(Path::new("data.json"), b"{\"key\": \"value\"}").unwrap();
    assert_eq!(det.file_type, FileType::Json);
    assert!(det.file_type.is_program());
}

#[test]
fn txt_detects_as_text() {
    assert_detect("notes.txt", b"some text here", FileType::Text);
}

#[test]
fn source_map_sidecars_detect_as_data() {
    assert_ext("package/parse.ts.map", FileType::Data);
    assert_ext("bundle.map", FileType::Data);
}

#[test]
fn m4_macro_detects_as_text() {
    assert_detect(
        "build-to-host.m4",
        b"AC_DEFUN([gl_BUILD_TO_HOST], [AC_SUBST([$1])])\n",
        FileType::Text,
    );
}

#[test]
fn raw_lzma_extension_detects_as_lzma() {
    assert_detect(
        "fixture.lzma",
        b"\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff",
        FileType::Lzma,
    );
}

#[test]
fn asar_detects_as_archive() {
    assert_detect(
        "app.asar",
        b"\x04\x00\x00\x00\x20\x00\x00\x00\x1c\x00\x00\x00\x18\x00\x00\x00{\"files\":{}}",
        FileType::Asar,
    );
    assert!(FileType::Asar.is_archive());
}

// ── API: detect_content / detect_path ────────────────────────────

#[test]
fn detect_content_only() {
    let det = detect_content(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();
    assert_eq!(det.file_type, FileType::Png);
}

#[test]
fn detect_path_only() {
    let det = detect_path(Path::new("app.js")).unwrap();
    assert_eq!(det.file_type, FileType::JavaScript);
}

// ── Filename-detected types inside temp directories ──────────────

/// Filename-detected types (package.json, Cargo.toml, etc.) must be
/// recognized when the file sits inside a temp directory, which is how
/// the HTTP upload handlers preserve the original name.
#[test]
fn license_in_temp_dir_detected_as_text() {
    let data = include_bytes!("../testdata/LICENSE");
    let det = detect(Path::new("/tmp/fn-list/LICENSE"), data).unwrap();
    assert_eq!(det.file_type, FileType::Text);
    assert_eq!(det.source, DetectionSource::Filename);
}

#[test]
fn extensionless_project_configuration_gets_text_fallback() {
    for (name, data) in [
        (".babelrc", b"{\"presets\": [\"example\"]}\n".as_slice()),
        (".eslintrc", b"{\"extends\": \"example\"}\n".as_slice()),
        (".eslintignore", b"build/\nnode_modules/\n".as_slice()),
        (
            ".editorconfig",
            b"root = true\n[*]\nindent_size = 2\n".as_slice(),
        ),
    ] {
        let detection = detect(Path::new(name), data).expect("config should be identified");
        assert_ne!(detection.file_type, FileType::Unknown, "{name}");
        assert!(
            matches!(detection.file_type, FileType::Text | FileType::Json),
            "{name}"
        );
    }
    let elf = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";
    assert!(detect(Path::new(".babelrc"), elf).is_none_or(|d| d.file_type != FileType::Text));
}

#[test]
fn gcc_specs_section_identifies_extensionless_text() {
    assert_detect(
        "sysroot/lib/specs",
        b"*self_spec:\n-wrapper /bin/sh,%R/wrap.sh\n",
        FileType::Text,
    );
    assert_detect(
        "specs",
        b"*link:\n%{!static:--dynamic-linker /lib/ld.so}\n",
        FileType::Text,
    );
    let prose = detect(Path::new("specs"), b"project specifications\n");
    assert!(prose.is_none() || prose.unwrap().file_type != FileType::Text);
    let binary = detect(Path::new("specs"), b"\x7fELF\x02\x01\x01\0*self_spec:\n");
    assert!(binary.is_none() || binary.unwrap().file_type != FileType::Text);
}
