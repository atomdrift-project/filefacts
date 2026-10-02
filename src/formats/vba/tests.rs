use super::*;

#[test]
fn a_unicode_stream_name_survives_where_the_mbcs_one_is_mangled() {
    // `Módulo1` in UTF-16LE. The MBCS twin of this field is code-page
    // bytes, so the lossy UTF-8 read of it cannot round-trip the accent.
    let wide: Vec<u8> = "M\u{f3}dulo1"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(
        read_utf16_string(&wide, 0, wide.len()).as_deref(),
        Some("M\u{f3}dulo1")
    );
}

#[test]
fn a_malformed_unicode_stream_name_is_rejected_rather_than_guessed() {
    let wide: Vec<u8> = "Mod1".encode_utf16().flat_map(u16::to_le_bytes).collect();
    // Truncated: the declared length runs past the end of the stream.
    assert_eq!(read_utf16_string(&wide, 0, wide.len() + 2), None);
    // A length that cannot be whole UTF-16 code units.
    assert_eq!(read_utf16_string(&wide, 0, 3), None);
    // An unpaired surrogate.
    assert_eq!(read_utf16_string(&[0x00, 0xD8], 0, 2), None);
    // NUL padding alone carries no name.
    assert_eq!(read_utf16_string(&[0, 0, 0, 0], 0, 4), None);
    // An offset past the end does not panic.
    assert_eq!(read_utf16_string(&wide, wide.len() + 9, 2), None);
}

#[test]
fn decompress_empty_input_yields_empty_output() {
    assert!(decompress_vba(&[]).unwrap().is_empty());
}

#[test]
fn decompress_rejects_wrong_signature() {
    // First byte must be 0x01.
    let err = decompress_vba(&[0xFF, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecompressError::BadSignature);
}

#[test]
fn decompress_uncompressed_chunk_roundtrip() {
    // Signature, header with high bit clear (uncompressed),
    // followed by 5 literal bytes. The decompressor reads up to
    // 4096 bytes after the header for uncompressed chunks.
    let mut input = vec![0x01u8];
    input.extend_from_slice(&0x0002_u16.to_le_bytes()); // chunk_size 2+3=5, uncompressed
    input.extend_from_slice(b"hello");
    let out = decompress_vba(&input).unwrap();
    assert!(out.starts_with(b"hello"));
}

#[test]
fn max_bit_count_matches_spec_steps() {
    // MAX(4, CeilingLog2(DecompressedCurrent - DecompressedChunkStart)),
    // capped at 12 (MS-OVBA 2.4.1.3.19.1). It grows with the position;
    // it used to shrink, which decoded every copy token wrongly.
    assert_eq!(max_bit_count(0), 4);
    assert_eq!(max_bit_count(4), 4);
    assert_eq!(max_bit_count(16), 4);
    assert_eq!(max_bit_count(17), 5);
    assert_eq!(max_bit_count(32), 5);
    assert_eq!(max_bit_count(33), 6);
    assert_eq!(max_bit_count(0x800), 11);
    assert_eq!(max_bit_count(0x1000), 12);
    // Capped, and never spins on a huge input.
    assert_eq!(max_bit_count(usize::MAX), 12);
}

/// A dir stream shaped like a real one: the PROJECTVERSION quirk, one
/// reference, then the modules.
fn realistic_dir_stream() -> Vec<u8> {
    let mut d = Vec::new();
    let rec = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
    };
    rec(&mut d, 0x0001, &1u32.to_le_bytes()); // SysKind
    rec(&mut d, 0x0002, &0x0409u32.to_le_bytes()); // Lcid
    rec(&mut d, 0x0003, &0x04e4u16.to_le_bytes()); // CodePage
    rec(&mut d, 0x0004, b"Project"); // Name
    // PROJECTVERSION: Size is Reserved and reads 4, the payload is 6.
    d.extend_from_slice(&0x0009u16.to_le_bytes());
    d.extend_from_slice(&4u32.to_le_bytes());
    d.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // A registered reference, whose layout the generic walk cannot follow.
    rec(&mut d, 0x0016, b"stdole");
    rec(
        &mut d,
        0x000D,
        b"*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#stdole2.tlb#OLE",
    );
    d.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // PROJECTMODULES + PROJECTCOOKIE, then one module.
    d.extend_from_slice(&0x000Fu16.to_le_bytes());
    d.extend_from_slice(&2u32.to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&0x0013u16.to_le_bytes());
    d.extend_from_slice(&2u32.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    rec(&mut d, 0x0019, b"ThisDocument"); // MODULENAME
    rec(&mut d, 0x001A, b"ThisDocument"); // MODULESTREAMNAME
    rec(&mut d, 0x0031, &0x2Au32.to_le_bytes()); // MODULEOFFSET
    rec(&mut d, 0x0022, &[]); // MODULETYPE: class
    rec(&mut d, 0x002B, &[]); // MODULETERMINATOR
    d
}

#[test]
fn modules_are_found_past_the_version_quirk_and_the_references() {
    // Walking from byte zero by id/size reaches no module on a real file:
    // PROJECTVERSION lies about its length and the references have their
    // own layouts. Anchoring on PROJECTMODULES steps over both.
    let infos = parse_dir_stream(&realistic_dir_stream()).modules;
    assert_eq!(infos.len(), 1, "expected one module");
    assert_eq!(infos[0].name, "ThisDocument");
    assert_eq!(infos[0].stream_name, "ThisDocument");
    assert_eq!(infos[0].offset, 0x2A);
}

#[test]
fn a_non_ascii_module_name_comes_from_the_unicode_record() {
    // `Módulo1` in code-page bytes is not UTF-8, so reading the MBCS
    // record gives `M<replacement>dulo1` and the stream lookup misses.
    // MS-OVBA writes the same name in UTF-16 right after it.
    let mut d = Vec::new();
    d.extend_from_slice(&0x000Fu16.to_le_bytes());
    d.extend_from_slice(&2u32.to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    let rec = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
    };
    rec(&mut d, 0x0019, b"M\xf3dulo1"); // MODULENAME, cp1252
    rec(&mut d, 0x001A, b"M\xf3dulo1"); // MODULESTREAMNAME, cp1252
    let wide: Vec<u8> = "Módulo1"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    rec(&mut d, 0x0032, &wide); // the Unicode variant
    rec(&mut d, 0x0031, &4u32.to_le_bytes());
    rec(&mut d, 0x002B, &[]);

    let infos = parse_dir_stream(&d).modules;
    assert_eq!(infos.len(), 1);
    assert_eq!(
        infos[0].stream_name, "Módulo1",
        "stream name must come from the UTF-16 record"
    );
}

#[test]
fn dir_stream_parser_handles_empty_input() {
    let infos = parse_dir_stream(&[]).modules;
    assert!(infos.is_empty());
}

#[test]
fn decompress_compressed_chunk_pure_literals() {
    // Compressed chunk with only literal tokens. MS-OVBA encodes
    // chunk_size as `stored + 3` where the stored value is the
    // 12 low bits of the chunk header. chunk_size *includes* the
    // 2-byte chunk header, so a body of (flag + 8 literals) = 9
    // bytes needs chunk_size = 11, encoded as stored=8.
    let mut input = vec![0x01u8];
    let header = 0x8000u16 | 0x0008u16;
    input.extend_from_slice(&header.to_le_bytes());
    input.push(0x00); // flag byte — all literals
    input.extend_from_slice(b"abcdefgh");
    let out = decompress_vba(&input).unwrap();
    assert_eq!(&out, b"abcdefgh");
}

#[test]
fn decompress_compressed_chunk_with_back_reference() {
    // Literal "ABCD" (4 bytes) followed by a copy-token that
    // copies 3 bytes from offset 4 — yielding "ABCDABC".
    // Body: flag(1) + 4 literals + token(2) = 7 bytes.
    // chunk_size = 7 + 2 (header) = 9 → stored = 6.
    let mut input = vec![0x01u8];
    let header = 0x8000u16 | 0x0006u16;
    input.extend_from_slice(&header.to_le_bytes());
    // Flag byte: bits 0..3 are the four literals (=0), bit 4 is
    // the token (=1). High bits unused.
    input.push(0b0001_0000);
    input.extend_from_slice(b"ABCD");
    // Token at decompressed_pos=4, where BitCount is 4: the offset
    // occupies the top 4 bits and the length the low 12. Want length=3,
    // offset=4 -> length_field=0, offset_field=3 -> (3 << 12) | 0.
    let token = 0x3000u16;
    input.extend_from_slice(&token.to_le_bytes());
    let out = decompress_vba(&input).unwrap();
    assert_eq!(&out, b"ABCDABC");
}

#[test]
fn decompress_handles_truncated_chunk_header() {
    // Signature plus a single byte — chunk header needs 2 bytes,
    // so the loop should exit cleanly.
    let input = vec![0x01u8, 0xAB];
    let out = decompress_vba(&input).unwrap();
    assert!(out.is_empty());
}

#[test]
fn dir_stream_parser_handles_multiple_modules() {
    let mut d = Vec::new();
    // Helper to push a record.
    let push_record = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
    };
    push_record(&mut d, 0x0019, b"Module1");
    push_record(&mut d, 0x001A, b"Stream1");
    push_record(&mut d, 0x0031, &10u32.to_le_bytes());
    push_record(&mut d, 0x0021, &[]); // procedural
    push_record(&mut d, 0x002B, &[]); // terminator
    push_record(&mut d, 0x0019, b"ClassMod");
    push_record(&mut d, 0x001A, b"ClassStream");
    push_record(&mut d, 0x0031, &20u32.to_le_bytes());
    push_record(&mut d, 0x0022, &[]); // class
    push_record(&mut d, 0x002B, &[]);
    let infos = parse_dir_stream(&d).modules;
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].name, "Module1");
    assert_eq!(infos[0].stream_name, "Stream1");
    assert_eq!(infos[0].offset, 10);
    assert!(matches!(infos[0].module_type, VbaModuleType::Standard));
    assert_eq!(infos[1].name, "ClassMod");
    assert_eq!(infos[1].offset, 20);
    assert!(matches!(infos[1].module_type, VbaModuleType::Class));
}

#[test]
fn dir_stream_parser_stops_at_terminator() {
    let mut d = Vec::new();
    // First module then a MODULETERMINATOR_PROJECT (0x000F) —
    // parser should stop, not pick up further records.
    d.extend_from_slice(&0x0019_u16.to_le_bytes());
    d.extend_from_slice(&3u32.to_le_bytes());
    d.extend_from_slice(b"Foo");
    d.extend_from_slice(&0x002B_u16.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0x000F_u16.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    // Ghost module past the terminator — shouldn't be parsed.
    d.extend_from_slice(&0x0019_u16.to_le_bytes());
    d.extend_from_slice(&5u32.to_le_bytes());
    d.extend_from_slice(b"Ghost");
    let infos = parse_dir_stream(&d).modules;
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].name, "Foo");
}

#[test]
fn dir_stream_parser_handles_truncated_record_size() {
    // Record claims a size that runs past the stream end —
    // parser must not panic.
    let mut d = Vec::new();
    d.extend_from_slice(&0x0019_u16.to_le_bytes());
    d.extend_from_slice(&1000u32.to_le_bytes()); // claims 1000 bytes of name
    d.extend_from_slice(b"shortbody"); // but only 9 are actually present
    let dir = parse_dir_stream(&d); // must not panic
    assert!(dir.truncated, "a record past the end is a truncated stream");
}

#[test]
fn ascii_string_handles_null_terminator() {
    // Trailing NULs (common in fixed-width stream slots) are
    // trimmed.
    let data = b"hello\0\0\0";
    assert_eq!(read_ascii_string(data, 0, 8), "hello");
}

#[test]
fn ascii_string_bounds_checked() {
    // Out-of-bounds request returns an empty string instead of
    // panicking.
    assert_eq!(read_ascii_string(b"abc", 5, 2), "");
    assert_eq!(read_ascii_string(b"abc", 0, 100), "");
}

#[test]
fn dir_stream_parser_extracts_single_module() {
    // Minimal dir stream with one MODULENAME + MODULESTREAMNAME +
    // MODULEOFFSET + MODULETERMINATOR record sequence.
    let mut d = Vec::new();
    // MODULENAME(0x0019) size=3 "Foo"
    d.extend_from_slice(&0x0019_u16.to_le_bytes());
    d.extend_from_slice(&3u32.to_le_bytes());
    d.extend_from_slice(b"Foo");
    // MODULESTREAMNAME(0x001A) size=3 "Bar"
    d.extend_from_slice(&0x001A_u16.to_le_bytes());
    d.extend_from_slice(&3u32.to_le_bytes());
    d.extend_from_slice(b"Bar");
    // MODULEOFFSET(0x0031) size=4 offset=42
    d.extend_from_slice(&0x0031_u16.to_le_bytes());
    d.extend_from_slice(&4u32.to_le_bytes());
    d.extend_from_slice(&42u32.to_le_bytes());
    // MODULETERMINATOR(0x002B) size=0
    d.extend_from_slice(&0x002B_u16.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());

    let infos = parse_dir_stream(&d).modules;
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].name, "Foo");
    assert_eq!(infos[0].stream_name, "Bar");
    assert_eq!(infos[0].offset, 42);
}

/// Wrap raw bytes as a single uncompressed MS-OVBA chunk so the
/// decompressor round-trips them verbatim (`raw` must be ≤ 4096).
fn ovba_store(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01u8];
    out.extend_from_slice(&0u16.to_le_bytes()); // header, high bit clear → uncompressed
    out.extend_from_slice(raw);
    out
}

#[test]
fn ooxml_vbaproject_member_is_decompressed() {
    use std::io::{Cursor, Write};

    // dir stream describing one standard module "Module1" whose
    // source lives in the "Module1" stream at offset 0.
    let mut dir = Vec::new();
    let push = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
    };
    push(&mut dir, 0x0019, b"Module1"); // MODULENAME
    push(&mut dir, 0x001A, b"Module1"); // MODULESTREAMNAME
    push(&mut dir, 0x0031, &0u32.to_le_bytes()); // MODULEOFFSET = 0
    push(&mut dir, 0x0021, &[]); // procedural
    push(&mut dir, 0x002B, &[]); // terminator

    let source =
        b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  Shell \"calc.exe\"\r\nEnd Sub\r\n";

    // vbaProject.bin is a standalone CFBF with a /VBA storage.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
        comp.create_storage("/VBA").unwrap();
        {
            let mut s = comp.create_stream("/VBA/dir").unwrap();
            s.write_all(&ovba_store(&dir)).unwrap();
        }
        {
            let mut s = comp.create_stream("/VBA/Module1").unwrap();
            s.write_all(&ovba_store(source)).unwrap();
        }
    }
    let vba_bin = buf.into_inner();

    // Wrap it in an OOXML-style zip under word/vbaProject.bin.
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    zw.start_file(
        "word/vbaProject.bin",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zw.write_all(&vba_bin).unwrap();
    let zip_bytes = zw.finish().unwrap().into_inner();

    let mut zip = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    let mut symbols = crate::output::Symbols::new();
    let mut errors = Errors::new();
    extract_from_zip(
        &mut zip,
        &mut values,
        &mut metrics,
        &mut symbols,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    let modules = values
        .get("office.vba.modules")
        .and_then(|v| v.as_array())
        .expect("office.vba.modules populated from OOXML vbaProject.bin");
    assert_eq!(modules.len(), 1);
    let src = modules[0]
        .get("source")
        .and_then(|v| v.as_str())
        .expect("module source present");
    assert!(src.contains("AutoOpen"), "decompressed source: {src}");
    assert!(src.contains("Shell"));
    assert_eq!(metrics.get("office.vba.module_count"), Some(1.0));
}

/// A dir stream with PROJECTMODULES and one module record per
/// `(name, offset)`, every module standard.
fn dir_for(modules: &[(&str, u32)]) -> Vec<u8> {
    let mut d = Vec::new();
    let rec = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
    };
    d.extend_from_slice(&0x000Fu16.to_le_bytes());
    d.extend_from_slice(&2u32.to_le_bytes());
    d.extend_from_slice(&(modules.len() as u16).to_le_bytes());
    for (name, offset) in modules {
        rec(&mut d, 0x0019, name.as_bytes());
        rec(&mut d, 0x001A, name.as_bytes());
        rec(&mut d, 0x0031, &offset.to_le_bytes());
        rec(&mut d, 0x0021, &[]);
        rec(&mut d, 0x002B, &[]);
    }
    d
}

fn compound_file(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
        comp.create_storage("/VBA").unwrap();
        for (path, body) in streams {
            comp.create_stream(path).unwrap().write_all(body).unwrap();
        }
    }
    buf.into_inner()
}

fn run_ole(bytes: &[u8]) -> (Values, Errors) {
    let mut values = Values::new();
    let mut errors = Errors::new();
    extract(
        bytes,
        &mut values,
        &mut Metrics::new(),
        &mut crate::output::Symbols::new(),
        &mut errors,
    );
    (values, errors)
}

fn module_names(values: &Values) -> Vec<String> {
    values
        .get("office.vba.modules")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("name").and_then(JsonValue::as_str))
        .map(str::to_string)
        .collect()
}

#[test]
fn a_document_without_a_vba_project_records_nothing() {
    let bytes = compound_file(&[("/VBA/NotADir", b"x".to_vec())]);
    let (values, errors) = run_ole(&bytes);
    assert!(errors.is_empty(), "{errors:?}");
    assert!(values.get("office.vba").is_none());
    assert!(values.get("office.limits").is_none());
}

#[test]
fn a_dir_stream_that_does_not_decompress_is_recorded() {
    let mut dir = ovba_store(&dir_for(&[("Module1", 0)]));
    dir[0] = 0x00;
    let bytes = compound_file(&[
        ("/VBA/dir", dir),
        ("/VBA/Module1", ovba_store(b"Sub A()\r\nEnd Sub\r\n")),
    ]);
    let (values, errors) = run_ole(&bytes);
    assert!(module_names(&values).is_empty());
    assert_eq!(errors.len(), 1, "{errors:?}");
    let e = errors.iter().next().unwrap();
    assert_eq!(e.stage, Stage::Ole2Parse);
    assert!(e.message.contains("dir stream"), "{}", e.message);
    assert!(e.message.contains("signature"), "{}", e.message);
}

#[test]
fn a_truncated_dir_stream_is_recorded_and_the_modules_before_it_survive() {
    let mut raw = dir_for(&[("Module1", 0)]);
    // A second MODULENAME claiming far more bytes than remain.
    raw.extend_from_slice(&0x0019u16.to_le_bytes());
    raw.extend_from_slice(&5000u32.to_le_bytes());
    raw.extend_from_slice(b"Ghost");
    let bytes = compound_file(&[
        ("/VBA/dir", ovba_store(&raw)),
        ("/VBA/Module1", ovba_store(b"Sub A()\r\nEnd Sub\r\n")),
    ]);
    let (values, errors) = run_ole(&bytes);
    assert_eq!(module_names(&values), ["Module1"]);
    // One report for the truncation, none for the phantom module it left.
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors
            .iter()
            .all(|e| e.message.contains("runs past the end")),
        "{errors:?}"
    );
}

#[test]
fn unreadable_modules_are_recorded_and_the_readable_ones_kept() {
    let mut bad = ovba_store(b"Sub B()\r\nEnd Sub\r\n");
    bad[0] = 0x07;
    let dir = dir_for(&[
        ("Good", 0),
        ("Missing", 0),
        ("BadSignature", 0),
        ("PastTheEnd", 0x4000),
    ]);
    let bytes = compound_file(&[
        ("/VBA/dir", ovba_store(&dir)),
        ("/VBA/Good", ovba_store(b"Sub A()\r\nEnd Sub\r\n")),
        ("/VBA/BadSignature", bad),
        ("/VBA/PastTheEnd", ovba_store(b"Sub C()\r\nEnd Sub\r\n")),
    ]);
    let (values, errors) = run_ole(&bytes);
    assert_eq!(module_names(&values), ["Good"]);
    let messages: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
    assert_eq!(messages.len(), 3, "{messages:?}");
    assert!(messages[0].contains("\"Missing\""), "{messages:?}");
    assert!(messages[1].contains("\"BadSignature\""), "{messages:?}");
    assert!(messages[1].contains("signature"), "{messages:?}");
    assert!(messages[2].contains("\"PastTheEnd\""), "{messages:?}");
    assert!(messages[2].contains("past the end"), "{messages:?}");
    assert!(errors.iter().all(|e| e.stage == Stage::Ole2Parse));
}

/// A module whose source decompresses past the cap is a coverage limit:
/// it lands in `office.limits`, after any limit already there, and
/// `errors` stays empty.
#[test]
fn the_decompression_cap_is_a_limit_not_an_error() {
    // Each chunk is one copy token of 4098 bytes.
    let mut source = vec![0x01u8];
    for _ in 0..(MAX_DECOMPRESSED_SIZE / 4098 + 2) {
        source.extend_from_slice(&(0x8000u16 | 0x3000 | 2).to_le_bytes());
        source.push(0x01);
        source.extend_from_slice(&0x0FFFu16.to_le_bytes());
    }
    let bytes = compound_file(&[
        (
            "/VBA/dir",
            ovba_store(&dir_for(&[("Big", 0), ("Small", 0)])),
        ),
        ("/VBA/Big", source),
        ("/VBA/Small", ovba_store(b"Sub A()\r\nEnd Sub\r\n")),
    ]);
    let mut values = Values::new();
    values.insert(
        "office.limits",
        serde_json::json!([{ "stage": "part-scan", "reason": "earlier" }]),
    );
    let mut errors = Errors::new();
    extract(
        &bytes,
        &mut values,
        &mut Metrics::new(),
        &mut crate::output::Symbols::new(),
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(module_names(&values), ["Small"]);
    let limits = values
        .get("office.limits")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(limits.len(), 2, "{limits:?}");
    assert_eq!(limits[0]["stage"], "part-scan");
    assert_eq!(limits[1]["stage"], "vba-decompress-cap");
}

/// A `vbaProject.bin` that is not a compound file is reported under the
/// OOXML stage, named by its part.
#[test]
fn an_ooxml_project_that_does_not_open_is_recorded() {
    use std::io::Write;
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    zw.start_file(
        "word/vbaProject.bin",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zw.write_all(b"not a compound file").unwrap();
    let zip_bytes = zw.finish().unwrap().into_inner();
    let mut zip = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    let mut values = Values::new();
    let mut errors = Errors::new();
    extract_from_zip(
        &mut zip,
        &mut values,
        &mut Metrics::new(),
        &mut crate::output::Symbols::new(),
        &mut errors,
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    let e = errors.iter().next().unwrap();
    assert_eq!(e.stage, Stage::OoxmlParse);
    assert!(
        e.message.starts_with("word/vbaProject.bin: "),
        "{}",
        e.message
    );
    assert!(values.get("office.vba").is_none());
}
