use super::*;
use crate::output::{Metrics, Values};

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let _ = extract(bytes, &mut v, &mut m, &mut Errors::new());
    (v, m)
}

/// A file with the OLE2 signature that `cfb` cannot open used to come
/// back as an empty, error-free document.
#[test]
fn unopenable_compound_file_is_reported() {
    let mut bytes = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
    bytes.resize(1024, 0xAB);
    let mut errors = Errors::new();
    let result = extract(&bytes, &mut Values::new(), &mut Metrics::new(), &mut errors);
    assert!(result.is_err(), "malformed compound file must not pass");

    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("x.doc"))
        .open(&bytes);
    assert!(
        parsed
            .errors()
            .iter()
            .any(|e| e.stage == Stage::Ole2Parse && e.message.contains("ole2")),
        "{:?}",
        parsed.errors()
    );
}

/// End the longest run of consecutive FAT entries early, so the stream
/// stored there (the only multi-sector one) claims more bytes than its
/// sector chain holds.
fn cut_stream_chain(bytes: &mut [u8]) {
    let sector = 1usize << u16::from_le_bytes([bytes[0x1E], bytes[0x1F]]);
    let fat_sector = u32::from_le_bytes(bytes[0x4C..0x50].try_into().unwrap()) as usize;
    let fat = (fat_sector + 1) * sector;
    let entry = |b: &[u8], k: usize| u32::from_le_bytes(b[fat + 4 * k..][..4].try_into().unwrap());
    let start = (0..sector / 4 - 3)
        .find(|&i| (0..3).all(|k| entry(bytes, i + k) == (i + k + 1) as u32))
        .expect("multi-sector stream chain");
    let at = fat + 4 * (start + 1);
    bytes[at..at + 4].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
}

/// A listed stream whose sector chain ends early is recorded, not treated
/// as absent.
#[test]
fn unreadable_stream_is_recorded() {
    let body = vec![0x5A; 64 * 1024];
    let mut bytes = build_cfb(&[("/WordDocument", &body)]);
    cut_stream_chain(&mut bytes);
    let mut errors = Errors::new();
    let mut v = Values::new();
    extract(&bytes, &mut v, &mut Metrics::new(), &mut errors).unwrap();
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("doc"));
    assert!(
        errors
            .iter()
            .any(|e| e.message.contains("WordDocument") && e.stage == Stage::Ole2Parse),
        "{errors:?}"
    );
}

/// Build a tiny in-memory CFB with the given stream paths and
/// optional bodies. Creates parent storages on demand — the
/// `cfb` crate requires every storage to exist before a stream
/// inside it can be created.
fn build_cfb(streams: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut cfb = cfb::CompoundFile::create(&mut buf).unwrap();
        for (path, body) in streams {
            // Walk every "/foo/bar/" prefix and create the storage
            // if it doesn't yet exist.
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if parts.len() > 1 {
                let mut accum = String::new();
                for part in &parts[..parts.len() - 1] {
                    accum.push('/');
                    accum.push_str(part);
                    if !cfb.exists(&accum) {
                        cfb.create_storage(&accum).unwrap();
                    }
                }
            }
            let mut stream = cfb.create_stream(path).unwrap();
            stream.write_all(body).unwrap();
        }
    }
    buf.into_inner()
}

#[test]
fn detects_word_document() {
    let cfb = build_cfb(&[("/WordDocument", b"fake-word-body")]);
    let (v, m) = run(&cfb);
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("doc"));
    let streams = v.get("office.streams").and_then(|x| x.as_array()).unwrap();
    assert!(streams.iter().any(|s| s.as_str() == Some("/WordDocument")));
    assert!(m.get("office.stream_count").unwrap() >= 1.0);
}

#[test]
fn detects_excel_workbook() {
    let cfb = build_cfb(&[("/Workbook", b"fake-xl-body")]);
    let (v, _) = run(&cfb);
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("xls"));
}

#[test]
fn detects_powerpoint_document() {
    let cfb = build_cfb(&[("/PowerPoint Document", b"fake-ppt-body")]);
    let (v, _) = run(&cfb);
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("ppt"));
}

#[test]
fn unrecognised_streams_fall_back_to_ole2() {
    let cfb = build_cfb(&[("/RandomStream", b"junk")]);
    let (v, _) = run(&cfb);
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("ole2"));
}

#[test]
fn detects_macros_in_vba_storage() {
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/Macros/VBA/Module1", b"Sub Auto_Open\nEnd Sub"),
    ]);
    let (v, m) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"macros"));
    assert!(m.get("office.macro_count").unwrap() >= 1.0);
}

#[test]
fn detects_encryption_info_stream() {
    let cfb = build_cfb(&[
        ("/EncryptionInfo", b"\x04\x00\x04\x00encrypted-info-blob"),
        ("/EncryptedPackage", b"ciphertext"),
    ]);
    let (v, _) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"encryption"));
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Attachment property stream: 8-byte header + one 16-byte entry per
/// (tag, u32 value).
fn attach_props(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut out = vec![0u8; 8];
    for (tag, value) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&6u32.to_le_bytes()); // flags
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    out
}

#[test]
fn describes_msg_attachments() {
    let long = utf16("Re comprobante.Tutela.XHTML");
    let mime = utf16("text/html");
    let short = utf16("image001.png");
    let cid = utf16("image001.png@01D0");
    let hidden = attach_props(&[(0x3705_0003, 1), (0x7FFE_000B, 1)]);
    let a0 = "/__attach_version1.0_#00000000";
    let a1 = "/__attach_version1.0_#00000001";
    let a2 = "/__attach_version1.0_#00000002";
    let cfb = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("subject")),
        (&format!("{a0}/__substg1.0_37010102"), b"<svg/>"),
        (&format!("{a0}/__substg1.0_3707001F"), &long),
        (&format!("{a0}/__substg1.0_370E001F"), &mime),
        (&format!("{a1}/__substg1.0_37010102"), b"\x89PNG...."),
        (&format!("{a1}/__substg1.0_3704001F"), &short),
        (&format!("{a1}/__substg1.0_3712001F"), &cid),
        (&format!("{a1}/__properties_version1.0"), &hidden),
        (
            &format!("{a2}/__substg1.0_3701000D/__substg1.0_0037001F"),
            &utf16("inner"),
        ),
        (
            &format!("{a2}/__substg1.0_3001001F"),
            &utf16("Fwd: invoice"),
        ),
    ]);
    let (v, m) = run(&cfb);
    assert_eq!(v.get("office.kind").and_then(|x| x.as_str()), Some("msg"));
    assert_eq!(m.get("office.msg.attachment_count"), Some(3.0));

    let list = v
        .get("office.msg.attachments")
        .and_then(|x| x.as_array())
        .expect("attachments listed");
    let by_name = |name: &str| {
        list.iter()
            .find(|a| a.get("filename").and_then(|f| f.as_str()) == Some(name))
            .unwrap_or_else(|| panic!("no attachment named {name}: {list:?}"))
    };

    let svg = by_name("Re comprobante.Tutela.XHTML");
    assert_eq!(svg.get("extension").and_then(|x| x.as_str()), Some("xhtml"));
    assert_eq!(svg.get("mime").and_then(|x| x.as_str()), Some("text/html"));
    assert_eq!(svg.get("size").and_then(serde_json::Value::as_u64), Some(6));
    assert!(svg.get("hidden").is_none());

    let png = by_name("image001.png");
    assert_eq!(png.get("extension").and_then(|x| x.as_str()), Some("png"));
    assert_eq!(
        png.get("content_id").and_then(|x| x.as_str()),
        Some("image001.png@01D0")
    );
    assert_eq!(png.get("method").and_then(|x| x.as_str()), Some("by_value"));
    assert_eq!(png.get("hidden"), Some(&serde_json::Value::Bool(true)));

    let msg = by_name("Fwd: invoice");
    assert!(msg.get("extension").is_none());
    assert!(msg.get("size").is_none());
    assert_eq!(
        msg.get("method").and_then(|x| x.as_str()),
        Some("embedded_message")
    );
}

#[test]
fn msg_without_attachments_reports_zero() {
    let cfb = build_cfb(&[("/__substg1.0_0037001F", &utf16("hello"))]);
    let (v, m) = run(&cfb);
    assert_eq!(m.get("office.msg.attachment_count"), Some(0.0));
    assert!(v.get("office.msg.attachments").is_none());
}

#[test]
fn attachment_extension_rules() {
    assert_eq!(attachment_extension("a.PDF").as_deref(), Some("pdf"));
    assert_eq!(attachment_extension("x.tar.gz").as_deref(), Some("gz"));
    assert_eq!(
        attachment_extension("C:\\t\\run.lnk").as_deref(),
        Some("lnk")
    );
    assert_eq!(attachment_extension(".htaccess"), None);
    assert_eq!(attachment_extension("noext"), None);
    assert_eq!(attachment_extension("trailing."), None);
    assert_eq!(attachment_extension("a.b c"), None);
}

#[test]
fn detects_ole10native_objects() {
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/ObjectPool/_1234567890/\u{1}Ole10Native", b"native-obj"),
    ]);
    let (v, _) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"ole_objects"));
}

#[test]
fn non_cfb_input_silent() {
    let (v, _) = run(b"not even close to OLE2 bytes");
    assert!(v.get("office.kind").is_none());
    assert!(v.get("office.streams").is_none());
}

#[test]
fn empty_input_silent() {
    let (v, _) = run(&[]);
    assert!(v.get("office.kind").is_none());
}

#[test]
fn streams_listed_in_walk_order() {
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/SummaryInformation", b"y"),
        ("/1Table", b"z"),
    ]);
    let (v, _) = run(&cfb);
    let streams = v.get("office.streams").and_then(|x| x.as_array()).unwrap();
    let paths: Vec<&str> = streams.iter().filter_map(|x| x.as_str()).collect();
    // Just check membership — the cfb crate's walk order isn't
    // part of the contract.
    assert!(paths.iter().any(|p| *p == "/WordDocument"));
    assert!(paths.iter().any(|p| *p == "/SummaryInformation"));
    assert!(paths.iter().any(|p| *p == "/1Table"));
}

/// Build a SummaryInformation stream containing the listed
/// (PID, VT_LPSTR string) pairs. Used to exercise the
/// property-set parser end-to-end through `extract`.
fn build_summary_info(props: &[(u32, &str)]) -> Vec<u8> {
    // Header (48 bytes total): 28-byte main header + 16-byte
    // section header. The section data starts at offset 48 (= 28
    // + 16-byte FMTID + 4-byte section offset, with `offset = 48`).
    let mut out = Vec::new();
    // Main header.
    out.extend_from_slice(&0xFFFE_u16.to_le_bytes()); // ByteOrder
    out.extend_from_slice(&0x0000_u16.to_le_bytes()); // Version
    out.extend_from_slice(&[0u8; 4]); // OS
    out.extend_from_slice(&[0u8; 16]); // CLSID
    out.extend_from_slice(&1u32.to_le_bytes()); // section count
    // Section header: 16-byte FMTID + 4-byte offset.
    out.extend_from_slice(&[0u8; 16]); // FMTID
    out.extend_from_slice(&48u32.to_le_bytes()); // section starts at byte 48

    // Build the property-name table first to compute the entry
    // table size.
    let n = props.len() as u32;
    let entry_table_size = 8 + (n as usize) * 8; // size + count + entries

    // Reserve a slot for the section header (size + count).
    let mut section_body: Vec<u8> = Vec::new();
    section_body.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    section_body.extend_from_slice(&n.to_le_bytes()); // num props

    // Entry table — PID + offset-from-section-start.
    let mut values_blob: Vec<u8> = Vec::new();
    for (pid, _) in props {
        let offset_in_section = entry_table_size + values_blob.len();
        section_body.extend_from_slice(&pid.to_le_bytes());
        section_body.extend_from_slice(&(offset_in_section as u32).to_le_bytes());
        // Add the value to the blob: VT_LPSTR (0x001E), u32 byte
        // length, NUL-terminated bytes, then pad to 4-byte align.
        let s = props.iter().find(|(p, _)| *p == *pid).unwrap().1;
        let mut s_bytes = s.as_bytes().to_vec();
        s_bytes.push(0);
        let len = s_bytes.len() as u32;
        values_blob.extend_from_slice(&0x0000_001E_u32.to_le_bytes());
        values_blob.extend_from_slice(&len.to_le_bytes());
        values_blob.extend_from_slice(&s_bytes);
        while !values_blob.len().is_multiple_of(4) {
            values_blob.push(0);
        }
    }

    section_body.extend_from_slice(&values_blob);
    // Fill in the actual section size.
    let total_size = section_body.len() as u32;
    section_body[0..4].copy_from_slice(&total_size.to_le_bytes());

    out.extend_from_slice(&section_body);
    out
}

#[test]
fn surfaces_office_properties_from_summary_information() {
    let summary = build_summary_info(&[
        (0x02, "Quarterly Report"),
        (0x04, "Alice"),
        (0x08, "Bob"),
        (0x12, "Microsoft Word"),
    ]);
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/\x05SummaryInformation", &summary),
    ]);
    let (v, _) = run(&cfb);
    assert_eq!(
        v.get("office.title").and_then(|x| x.as_str()),
        Some("Quarterly Report")
    );
    assert_eq!(
        v.get("office.creator").and_then(|x| x.as_str()),
        Some("Alice")
    );
    assert_eq!(
        v.get("office.last_modified_by").and_then(|x| x.as_str()),
        Some("Bob")
    );
    assert_eq!(
        v.get("office.application").and_then(|x| x.as_str()),
        Some("Microsoft Word")
    );
}

/// Build a property-set stream containing a mix of VT_LPSTR and
/// VT_I4 properties. Mirror of `build_summary_info` but supports
/// both types so we can exercise DocumentSummaryInformation
/// counts (slide_count, security_flag).
enum PropValue {
    Lpstr(&'static str),
    I4(i32),
}

fn build_property_set(props: &[(u32, PropValue)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFFFE_u16.to_le_bytes());
    out.extend_from_slice(&0x0000_u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&48u32.to_le_bytes());

    let n = props.len() as u32;
    let entry_table_size = 8 + (n as usize) * 8;
    let mut section_body: Vec<u8> = Vec::new();
    section_body.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    section_body.extend_from_slice(&n.to_le_bytes());

    let mut values_blob: Vec<u8> = Vec::new();
    for (pid, val) in props {
        let offset_in_section = entry_table_size + values_blob.len();
        section_body.extend_from_slice(&pid.to_le_bytes());
        section_body.extend_from_slice(&(offset_in_section as u32).to_le_bytes());
        match val {
            PropValue::Lpstr(s) => {
                let mut s_bytes = s.as_bytes().to_vec();
                s_bytes.push(0);
                let len = s_bytes.len() as u32;
                values_blob.extend_from_slice(&0x0000_001E_u32.to_le_bytes());
                values_blob.extend_from_slice(&len.to_le_bytes());
                values_blob.extend_from_slice(&s_bytes);
            }
            PropValue::I4(v) => {
                values_blob.extend_from_slice(&0x0000_0003_u32.to_le_bytes());
                values_blob.extend_from_slice(&v.to_le_bytes());
            }
        }
        while !values_blob.len().is_multiple_of(4) {
            values_blob.push(0);
        }
    }
    section_body.extend_from_slice(&values_blob);
    let total_size = section_body.len() as u32;
    section_body[0..4].copy_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&section_body);
    out
}

#[test]
fn merges_document_summary_information_into_office_properties() {
    let summary = build_summary_info(&[(0x02, "Quarterly Report"), (0x04, "Alice")]);
    let dsi = build_property_set(&[
        (0x10, PropValue::Lpstr("Eve")),      // manager
        (0x11, PropValue::Lpstr("Acme Inc")), // company
        (0x09, PropValue::I4(42)),            // slide_count
        (0x13, PropValue::I4(1)),             // security_flag
    ]);
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/\x05SummaryInformation", &summary),
        ("/\x05DocumentSummaryInformation", &dsi),
    ]);
    let (v, _) = run(&cfb);
    // From SummaryInformation:
    assert_eq!(
        v.get("office.title").and_then(|x| x.as_str()),
        Some("Quarterly Report")
    );
    assert_eq!(
        v.get("office.creator").and_then(|x| x.as_str()),
        Some("Alice")
    );
    // From DocumentSummaryInformation:
    assert_eq!(
        v.get("office.manager").and_then(|x| x.as_str()),
        Some("Eve")
    );
    assert_eq!(
        v.get("office.company").and_then(|x| x.as_str()),
        Some("Acme Inc")
    );
    assert_eq!(
        v.get("office.slide_count").and_then(|x| x.as_i64()),
        Some(42)
    );
    assert_eq!(
        v.get("office.security_flag").and_then(|x| x.as_i64()),
        Some(1)
    );
}

#[test]
fn document_summary_alone_still_populates_office_properties() {
    // No SummaryInformation present — DSI fields should still land in office.*.
    let dsi = build_property_set(&[
        (0x11, PropValue::Lpstr("Acme Inc")),
        (0x1A, PropValue::Lpstr("https://intranet.acme/docs")),
    ]);
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/\x05DocumentSummaryInformation", &dsi),
    ]);
    let (v, _) = run(&cfb);
    assert_eq!(
        v.get("office.company").and_then(|x| x.as_str()),
        Some("Acme Inc")
    );
    assert_eq!(
        v.get("office.hyperlink_base").and_then(|x| x.as_str()),
        Some("https://intranet.acme/docs")
    );
}

#[test]
fn flags_equation_editor_clsid_on_storage() {
    // CVE-2017-11882 — Equation Editor 3.0 CLSID.
    // Bytes are the canonical little-endian on-disk form.
    let equation_clsid = uuid::Uuid::parse_str("0002ce02-0000-0000-c000-000000000046").unwrap();
    // Build a CFB with a storage that has the dangerous CLSID set.
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    {
        let mut cfb = cfb::CompoundFile::create(&mut buf).unwrap();
        cfb.create_storage("/EQUATION").unwrap();
        cfb.set_storage_clsid("/EQUATION", equation_clsid).unwrap();
        let mut s = cfb.create_stream("/WordDocument").unwrap();
        std::io::Write::write_all(&mut s, b"x").unwrap();
    }
    let bytes = buf.into_inner();
    let (v, m) = run(&bytes);

    let dangerous = v
        .get("office.dangerous_clsids")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(dangerous.len(), 1);
    assert_eq!(
        dangerous[0]["clsid"].as_str(),
        Some("0002ce02-0000-0000-c000-000000000046")
    );
    assert!(
        dangerous[0]["name"]
            .as_str()
            .unwrap()
            .contains("Equation Editor")
    );
    assert_eq!(dangerous[0]["storage"].as_str(), Some("/EQUATION"));
    assert_eq!(m.get("office.dangerous_clsid_count"), Some(1.0));

    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"dangerous_clsid"));
}

#[test]
fn benign_clsids_dont_trigger_dangerous_list() {
    let benign_clsid = uuid::Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    {
        let mut cfb = cfb::CompoundFile::create(&mut buf).unwrap();
        cfb.create_storage("/random").unwrap();
        cfb.set_storage_clsid("/random", benign_clsid).unwrap();
        let mut s = cfb.create_stream("/WordDocument").unwrap();
        std::io::Write::write_all(&mut s, b"x").unwrap();
    }
    let (v, _) = run(&buf.into_inner());
    assert!(v.get("office.dangerous_clsids").is_none());
}

#[test]
fn lookup_dangerous_clsid_known_entries() {
    assert!(lookup_dangerous_clsid("0002ce02-0000-0000-c000-000000000046").is_some());
    assert!(lookup_dangerous_clsid("f20da720-c02f-11ce-927b-0800095ae340").is_some());
    assert!(lookup_dangerous_clsid("996bf5e0-8044-4650-adeb-0b013914e99c").is_some());
    assert!(lookup_dangerous_clsid("00000000-0000-0000-0000-000000000000").is_none());
}

/// Build a minimal CompObj stream body — 28-byte header followed
/// by AnsiUserType + (optional) ProgID. ClipboardFormat slot is
/// left as a 4-byte zero marker.
fn build_compobj_body(user_type: &str, prog_id: Option<&str>) -> Vec<u8> {
    let mut body = vec![0u8; 28];
    // AnsiUserType
    let mut ut = user_type.as_bytes().to_vec();
    ut.push(0);
    body.extend_from_slice(&(ut.len() as u32).to_le_bytes());
    body.extend_from_slice(&ut);
    // ClipboardFormat: zero marker → no string follows.
    body.extend_from_slice(&0u32.to_le_bytes());
    // ProgID (Reserved3)
    if let Some(pid) = prog_id {
        let mut p = pid.as_bytes().to_vec();
        p.push(0);
        body.extend_from_slice(&(p.len() as u32).to_le_bytes());
        body.extend_from_slice(&p);
    }
    body
}

#[test]
fn surfaces_compobj_prog_id_for_extension_mismatch() {
    // .doc file whose CompObj actually claims to be Excel — the
    // CVE-2017-0199 / T1036.005 shape.
    let body = build_compobj_body("Microsoft Excel Worksheet", Some("Excel.Sheet.8"));
    let cfb = build_cfb(&[("/WordDocument", b"x"), ("/\x01CompObj", &body)]);
    let (v, _) = run(&cfb);
    let co = v.get("office.compobj").and_then(|x| x.as_object()).unwrap();
    assert_eq!(
        co.get("app_version").and_then(|x| x.as_str()),
        Some("Excel.Sheet.8")
    );
    assert_eq!(
        co.get("prog_id").and_then(|x| x.as_str()),
        Some("Excel.Sheet.8")
    );
    assert_eq!(
        co.get("user_type").and_then(|x| x.as_str()),
        Some("Microsoft Excel Worksheet")
    );
}

#[test]
fn compobj_parser_handles_missing_prog_id() {
    // Documents without a ProgID still surface the user_type.
    let body = build_compobj_body("Microsoft Word Document", None);
    let cfb = build_cfb(&[("/WordDocument", b"x"), ("/\x01CompObj", &body)]);
    let (v, _) = run(&cfb);
    let co = v.get("office.compobj").and_then(|x| x.as_object()).unwrap();
    assert_eq!(
        co.get("user_type").and_then(|x| x.as_str()),
        Some("Microsoft Word Document")
    );
    assert!(co.get("app_version").is_none());
}

#[test]
fn compobj_parser_rejects_truncated_stream() {
    // Just the 4-byte header — too short to carry any strings.
    let cfb = build_cfb(&[("/WordDocument", b"x"), ("/\x01CompObj", &[0u8; 4])]);
    let (v, _) = run(&cfb);
    // No office.compobj emitted when the stream can't be parsed.
    assert!(v.get("office.compobj").is_none());
}

#[test]
fn iso8601_format_matches_known_unix_timestamp() {
    // 2024-01-15T08:00:00Z = 1_705_305_600
    assert_eq!(format_iso8601_utc(1_705_305_600), "2024-01-15T08:00:00Z");
    // 1970-01-01T00:00:00Z = 0
    assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
}

#[test]
fn macro_count_reflects_multiple_vba_storages() {
    // Real macro-enabled docs sometimes have nested VBA storages.
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/Macros/VBA/Module1", b""),
        ("/Macros/VBA/Module2", b""),
        ("/Macros/VBA/_VBA_PROJECT", b""),
    ]);
    let (_, m) = run(&cfb);
    // Each /VBA storage entry counts; the exact tally depends on
    // how `cfb::CompoundFile::walk` materializes parent storages,
    // so we just assert a non-trivial count.
    assert!(m.get("office.macro_count").unwrap() >= 1.0);
}
#[test]
fn detects_object_pool_as_ole_objects() {
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/ObjectPool/_123/Contents", b"obj"),
    ]);
    let (v, _) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"ole_objects"));
    assert!(names.contains(&"object_pool"));
}

#[test]
fn detects_summary_information_security_encryption() {
    let summary = build_property_set(&[(0x13, PropValue::I4(1))]);
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/\x05SummaryInformation", &summary),
    ]);
    let (v, _) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"encryption"));
    assert_eq!(
        v.get("office.document_security").and_then(|x| x.as_i64()),
        Some(1)
    );
}

#[test]
fn detects_word_document_encryption_flag() {
    let mut word = vec![0u8; 12];
    word[10..12].copy_from_slice(&0x0100_u16.to_le_bytes());
    let cfb = build_cfb(&[("/WordDocument", &word)]);
    let (v, _) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"encryption"));
}

#[test]
fn detects_encrypted_summary_stream() {
    let cfb = build_cfb(&[
        ("/WordDocument", b"x"),
        ("/EncryptedSummary", b"ciphertext"),
    ]);
    let (v, _) = run(&cfb);
    let features = v.get("office.features").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"encryption"));
}

#[test]
fn lookup_dangerous_clsid_expanded_entries() {
    assert_eq!(
        lookup_dangerous_clsid("d27cdb6e-ae6d-11cf-96b8-444553540000"),
        Some("Shockwave Flash")
    );
    assert_eq!(
        lookup_dangerous_clsid("00021700-0000-0000-c000-000000000046"),
        Some("Equation Editor")
    );
    assert_eq!(
        lookup_dangerous_clsid("79eac9d0-baf9-11ce-8c82-00aa004ba90b"),
        Some("StdHlink")
    );
}

/// The `office.features[]` array as owned strings.
fn feature_list(v: &Values) -> Vec<String> {
    v.get("office.features")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// A BIFF workbook stream: BOF, then one BOUNDSHEET per sheet, then one
/// DEFINEDNAME per entry. Mirrors what Excel writes closely enough for
/// the extractor, which never decodes cell data.
fn workbook(sheets: &[(u8, u8, &str)], builtin_names: &[u8]) -> Vec<u8> {
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0];
    for (kind, vis, name) in sheets {
        let body_len = 8 + name.len();
        d.extend_from_slice(&[0x85, 0x00]);
        d.extend_from_slice(&(body_len as u16).to_le_bytes());
        d.extend_from_slice(&[0, 0, 0, 0, *vis, *kind]);
        d.push(name.len() as u8);
        d.push(0); // compressed string
        d.extend_from_slice(name.as_bytes());
    }
    for idx in builtin_names {
        d.extend_from_slice(&[0x18, 0x00, 0x10, 0x00]);
        d.extend_from_slice(&[0x20, 0x00, 0, 1]);
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        d.extend_from_slice(&[0, *idx]);
    }
    d
}

#[test]
fn xlm_macro_workbook_reports_its_sheets_and_auto_open() {
    // The whole emission path, not just the record walk: an Excel 4.0
    // macro sheet beside an ordinary one, named Auto_Open.
    let wb = workbook(&[(0, 0, "Sheet1"), (SHEET_XLM, 0, "rRQxz")], &[1]);
    let cfb = build_cfb(&[("/Workbook", &wb)]);
    let (v, m) = run(&cfb);

    assert_eq!(m.get("office.sheet_count"), Some(2.0));
    assert_eq!(m.get("office.xlm_sheet_count"), Some(1.0));
    assert_eq!(m.get("office.name_count"), Some(1.0));
    assert_eq!(m.get("office.hidden_sheet_count"), None);

    let features = feature_list(&v);
    let features: Vec<&str> = features.iter().map(String::as_str).collect();
    assert!(features.contains(&"xlm_macros"), "{features:?}");
    assert!(features.contains(&"auto_open"), "{features:?}");
    assert!(!features.contains(&"veryhidden_sheets"), "{features:?}");

    let sheets = v
        .get("office.sheet_names")
        .and_then(|x| x.as_array())
        .unwrap();
    let sheets: Vec<&str> = sheets.iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(sheets, vec!["Sheet1", "rRQxz"]);
    assert_eq!(v.get("office.names").unwrap()[0], "auto_open");
}

#[test]
fn ordinary_workbook_reports_no_macro_surface() {
    // The negative case that keeps the XLM traits off every spreadsheet.
    let wb = workbook(&[(0, 0, "Sheet1"), (0, 0, "Sheet2")], &[6]);
    let cfb = build_cfb(&[("/Workbook", &wb)]);
    let (v, m) = run(&cfb);

    assert_eq!(m.get("office.sheet_count"), Some(2.0));
    assert_eq!(m.get("office.xlm_sheet_count"), None);
    let features = feature_list(&v);
    let features: Vec<&str> = features.iter().map(String::as_str).collect();
    assert!(!features.contains(&"xlm_macros"), "{features:?}");
    assert!(!features.contains(&"auto_open"), "{features:?}");
    // Built-in 6 is Print_Area, and it is named, not numbered.
    assert_eq!(v.get("office.names").unwrap()[0], "print_area");
}

#[test]
fn very_hidden_sheet_is_reported_separately_from_hidden() {
    let wb = workbook(&[(0, 0, "Sheet1"), (SHEET_XLM, 2, "x")], &[]);
    let cfb = build_cfb(&[("/Workbook", &wb)]);
    let (v, m) = run(&cfb);
    assert_eq!(m.get("office.hidden_sheet_count"), Some(1.0));
    let features = feature_list(&v);
    let features: Vec<&str> = features.iter().map(String::as_str).collect();
    assert!(features.contains(&"veryhidden_sheets"), "{features:?}");
}

#[test]
fn encrypted_workbook_emits_no_sheet_inventory() {
    // Every field after FILEPASS is ciphertext. Reading one would invent
    // sheets, and a stray byte would announce a macro sheet.
    let mut wb = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0];
    wb.extend_from_slice(&[0x2F, 0x00, 0x02, 0x00, 0x01, 0x00]);
    wb.extend_from_slice(&workbook(&[(SHEET_XLM, 0, "x")], &[1])[8..]);
    let cfb = build_cfb(&[("/Workbook", &wb)]);
    let (v, m) = run(&cfb);
    assert_eq!(m.get("office.sheet_count"), None);
    assert_eq!(m.get("office.xlm_sheet_count"), None);
    assert!(v.get("office.sheet_names").is_none());
}

#[test]
fn vba_project_storage_counts_as_macros() {
    // Excel writes the project as `/_VBA_PROJECT`. Matching only `/vba`
    // missed it, because the underscore sits between the separator and
    // the name -- so a macro-bearing workbook reported none.
    let cfb = build_cfb(&[("/Book", b"x"), ("/_VBA_PROJECT/dir", b"y")]);
    let (v, m) = run(&cfb);
    assert!(m.get("office.macro_count").unwrap_or(0.0) >= 1.0);
    let features = feature_list(&v);
    let features: Vec<&str> = features.iter().map(String::as_str).collect();
    assert!(features.contains(&"macros"), "{features:?}");
}

#[test]
fn boundsheets_reads_sheet_kind_and_visibility() {
    // BOF, then two BOUNDSHEET records: a visible worksheet and a very
    // hidden Excel 4.0 macro sheet -- the XLM maldoc shape.
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0, 0, 0, 0];
    for (kind, vis) in [(0u8, 0u8), (1u8, 2u8)] {
        d.extend_from_slice(&[0x85, 0x00, 0x08, 0x00]);
        d.extend_from_slice(&[0, 0, 0, 0]); // lbPlyPos
        d.extend_from_slice(&[vis, kind]); // grbit: lo visibility, hi kind
        d.extend_from_slice(&[0, 0]); // cch + grbitChr
    }
    let sheets = boundsheets(&d);
    assert_eq!(sheets.len(), 2);
    assert_eq!((sheets[0].kind, sheets[0].visibility), (0, 0));
    assert_eq!((sheets[1].kind, sheets[1].visibility), (SHEET_XLM, 2));
}

#[test]
fn boundsheets_reports_ordinary_hidden_apart_from_very_hidden() {
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0, 0, 0, 0];
    for vis in [0u8, 1, 2] {
        d.extend_from_slice(&[0x85, 0x00, 0x08, 0x00]);
        d.extend_from_slice(&[0, 0, 0, 0, vis, 0, 0, 0]);
    }
    let sheets = boundsheets(&d);
    assert_eq!(sheets.iter().filter(|s| s.visibility != 0).count(), 2);
    assert_eq!(
        sheets
            .iter()
            .filter(|s| s.visibility == SHEET_VERY_HIDDEN)
            .count(),
        1
    );
}

#[test]
fn defined_names_read_builtin_indices() {
    // BOF (BIFF8), then Auto_Open and Auto_Close as built-in names.
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0];
    for idx in [1u8, 2] {
        // Auto_Open, Auto_Close
        d.extend_from_slice(&[0x18, 0x00, 0x10, 0x00]);
        d.extend_from_slice(&[0x20, 0x00]); // grbit: fBuiltin
        d.extend_from_slice(&[0, 1]); // chKey, cch = 1
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // cce..lengths
        d.extend_from_slice(&[0, idx]); // name flags, builtin index
    }
    assert_eq!(defined_names(&d), vec!["auto_open", "auto_close"]);
}

#[test]
fn defined_names_read_the_text_form_too() {
    // A named range is text, not a builtin index; reading its first byte
    // as an index would turn an ordinary name into a phantom Auto_Open.
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0];
    d.extend_from_slice(&[0x18, 0x00, 0x14, 0x00]);
    d.extend_from_slice(&[0x00, 0x00]); // grbit: not builtin
    d.extend_from_slice(&[0, 5]); // chKey, cch = 5
    d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    d.extend_from_slice(&[0]); // compressed string
    d.extend_from_slice(b"Total");
    assert_eq!(defined_names(&d), vec!["total"]);
    assert!(defined_names(b"not biff").is_empty());
}

#[test]
fn defined_names_read_biff5_without_the_encoding_byte() {
    // BIFF5 has no string-flags byte, so the name starts one earlier.
    // Reading it at the BIFF8 offset loses the first character.
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x05, 0, 0];
    d.extend_from_slice(&[0x18, 0x00, 0x17, 0x00]);
    d.extend_from_slice(&[0x00, 0x00, 0, 9]);
    d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    d.extend_from_slice(b"Auto_Open");
    assert_eq!(defined_names(&d), vec!["auto_open"]);
}

#[test]
fn boundsheets_read_the_sheet_name() {
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0];
    d.extend_from_slice(&[0x85, 0x00, 0x0D, 0x00]);
    d.extend_from_slice(&[0, 0, 0, 0]); // lbPlyPos
    d.extend_from_slice(&[0, 1]); // grbit: visible XLM macro sheet
    d.extend_from_slice(&[5, 0]); // cch, compressed
    d.extend_from_slice(b"rRQxz");
    assert_eq!(boundsheets(&d)[0].name, "rRQxz");
}

#[test]
fn encrypted_workbooks_are_not_read() {
    // FILEPASS ahead of the sheet table: every payload after it is
    // ciphertext, and reading one would invent a sheet.
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0];
    d.extend_from_slice(&[0x2F, 0x00, 0x02, 0x00, 0x01, 0x00]);
    assert!(biff_encrypted(&d));
    assert!(!biff_encrypted(&[0x09, 0x08, 0x04, 0x00, 0x00, 0x06, 0, 0]));
}

#[test]
fn boundsheets_requires_a_biff_stream() {
    // Without the leading BOF this is not a workbook, and walking it would
    // invent sheets out of arbitrary bytes.
    assert!(boundsheets(b"not a biff stream at all").is_empty());
    assert!(boundsheets(&[]).is_empty());
}

#[test]
fn boundsheets_ignores_the_record_id_inside_cell_data() {
    // 0x0085 occurs constantly as ordinary data. A record walk steps over
    // it; a byte scan would report a sheet here.
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0, 0, 0, 0];
    d.extend_from_slice(&[0xFD, 0x00, 0x0A, 0x00]); // some record, 10 bytes
    d.extend_from_slice(&[0x85, 0x00, 0x08, 0x00, 0, 0, 0, 0, 2, 1]); // payload
    assert!(boundsheets(&d).is_empty());
}

#[test]
fn boundsheets_stops_at_a_truncated_record() {
    let mut d = vec![0x09, 0x08, 0x04, 0x00, 0, 0, 0, 0];
    d.extend_from_slice(&[0x85, 0x00, 0xFF, 0x00]); // claims 255 bytes, has none
    assert!(boundsheets(&d).is_empty());
}
