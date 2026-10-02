use super::{
    LARGE_RIZIN_INPUT, MAX_PLIST_DEPTH, NativeFormat, RizinDecision, RizinProfile, XorScan,
    basename, cfb_entry_path, decide_rizin, extract_text_strings, format_guid, has_xor_intent,
    hex_encode, plist_to_json, read_uleb128, section_entropy, stem,
};
use crate::output::Strings;
use serde_json::Value as JsonValue;

fn transparent_profile(format: NativeFormat) -> RizinProfile {
    RizinProfile {
        format,
        size: 64 << 20,
        function_count: 0,
        section_count: 8,
        stripped: Some(false),
        go_function_metadata: false,
        string_count: 10_000,
        string_bytes: 4 << 20,
        code_entropy: Some(6.2),
        overall_entropy: 6.5,
    }
}

#[test]
fn rizin_policy_is_consistent_across_native_formats() {
    for format in [NativeFormat::Elf, NativeFormat::MachO, NativeFormat::Pe] {
        assert!(matches!(
            decide_rizin(transparent_profile(format)),
            RizinDecision::Skip("static facts show a transparent binary")
        ));

        let mut no_strings = transparent_profile(format);
        no_strings.string_count = 0;
        no_strings.string_bytes = 0;
        assert!(matches!(
            decide_rizin(no_strings),
            RizinDecision::Analyze("printable strings are sparse")
        ));

        let mut packed_code = transparent_profile(format);
        packed_code.code_entropy = Some(7.3);
        assert!(matches!(
            decide_rizin(packed_code),
            RizinDecision::Analyze("executable code has high entropy")
        ));
    }
}

#[test]
fn static_function_inventory_wins_over_expensive_signals() {
    for format in [NativeFormat::Elf, NativeFormat::MachO, NativeFormat::Pe] {
        let mut profile = transparent_profile(format);
        profile.function_count = 1;
        profile.stripped = Some(true);
        profile.string_count = 0;
        profile.string_bytes = 0;
        profile.code_entropy = Some(8.0);
        assert!(matches!(
            decide_rizin(profile),
            RizinDecision::Skip("static function inventory available")
        ));
    }
}

#[test]
fn go_without_typed_functions_is_admitted_on_every_platform() {
    for format in [NativeFormat::Elf, NativeFormat::MachO, NativeFormat::Pe] {
        let mut profile = transparent_profile(format);
        profile.go_function_metadata = true;
        profile.stripped = Some(true);
        profile.string_count = 0;
        profile.string_bytes = 0;
        profile.code_entropy = Some(8.0);
        assert!(matches!(
            decide_rizin(profile),
            RizinDecision::Analyze("Go function inventory needs recovery")
        ));

        profile.function_count = 1;
        assert!(matches!(
            decide_rizin(profile),
            RizinDecision::Skip("typed Go function inventory available")
        ));
    }
}

#[test]
fn stripped_size_budget_has_an_explicit_boundary() {
    for format in [NativeFormat::Elf, NativeFormat::MachO] {
        let mut profile = transparent_profile(format);
        profile.stripped = Some(true);
        profile.size = LARGE_RIZIN_INPUT;
        assert!(matches!(
            decide_rizin(profile),
            RizinDecision::Analyze("stripped binary within deep-analysis budget")
        ));

        profile.size += 1;
        assert!(matches!(
            decide_rizin(profile),
            RizinDecision::Skip("static facts show a transparent binary")
        ));
    }
}

#[test]
fn string_density_and_count_are_both_admission_signals() {
    let mut profile = transparent_profile(NativeFormat::Elf);
    profile.string_count = 64;
    profile.string_bytes = profile.size / 1024;
    assert!(!decide_rizin(profile).runs());

    profile.string_bytes -= 1;
    assert!(matches!(
        decide_rizin(profile),
        RizinDecision::Analyze("printable strings are sparse")
    ));

    profile.string_bytes = profile.size;
    profile.string_count = 63;
    assert!(matches!(
        decide_rizin(profile),
        RizinDecision::Analyze("printable strings are sparse")
    ));
}

#[test]
fn pe_exceptions_are_narrow_and_explicit() {
    let mut malformed = transparent_profile(NativeFormat::Pe);
    malformed.section_count = 0;
    assert!(matches!(
        decide_rizin(malformed),
        RizinDecision::Analyze("PE section table needs recovery")
    ));

    let mut importless = transparent_profile(NativeFormat::Pe);
    importless.size = 5 * 1024 * 1024;
    assert!(matches!(
        decide_rizin(importless),
        RizinDecision::Analyze("small importless PE")
    ));

    importless.size += 1;
    assert!(!decide_rizin(importless).runs());
}

#[test]
fn failing_workerd_macho_is_recognized_as_transparent() {
    let profile = RizinProfile {
        format: NativeFormat::MachO,
        size: 119_799_896,
        function_count: 0,
        section_count: 20,
        stripped: Some(false),
        go_function_metadata: false,
        string_count: 330_028,
        string_bytes: 40 << 20,
        code_entropy: Some(6.39),
        overall_entropy: 6.70,
    };
    assert!(matches!(
        decide_rizin(profile),
        RizinDecision::Skip("static facts show a transparent binary")
    ));
}

#[test]
fn xor_intent_detects_operator_and_keyword() {
    // bitwise-XOR operator (C/JS/Python/…)
    assert!(has_xor_intent(b"for (i=0;i<n;i++) out[i] = buf[i] ^ key;"));
    // `xor` keyword, any case (xor / VBScript Xor / PowerShell -bxor)
    assert!(has_xor_intent(b"result = a xor b"));
    assert!(has_xor_intent(b"$d = $b -bxor 0x42"));
    assert!(has_xor_intent(b"value = data.XOR(key)"));
}

#[test]
fn xor_intent_absent_in_benign_source() {
    // A plain comment / coordinate string of the kind that previously
    // mis-decoded into speculative "XOR payload" false positives.
    assert!(!has_xor_intent(
        b"// Build data=\"Name:v1,v2;...\" from series"
    ));
    assert!(!has_xor_intent(
        b"10504 1900 10802 2169 L 11697 1363 C 11971"
    ));
    assert!(!has_xor_intent(b"const greeting = `hello ${name}`;"));
    assert!(!has_xor_intent(b""));
}

#[test]
fn hex_encode_known_vectors() {
    assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    assert_eq!(hex_encode(&[]), "");
}

#[test]
fn section_entropy_clamps_to_the_file() {
    let bytes: Vec<u8> = (0..=255u8).collect();
    assert_eq!(section_entropy(&bytes, 0, 256), 8.0);
    // A section running past EOF is measured over the bytes that exist.
    assert_eq!(section_entropy(&bytes, 128, u64::MAX), 7.0);
    assert_eq!(section_entropy(&bytes, 0, 0), 0.0);
    assert_eq!(section_entropy(&bytes, 256, 16), 0.0);
    assert_eq!(section_entropy(&bytes, u64::MAX, 16), 0.0);
}

#[test]
fn format_guid_byteswaps_the_first_three_fields() {
    // On disk the first three fields are little-endian, the rest bytes.
    let sequential: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
    assert_eq!(
        format_guid(&sequential),
        "04030201-0605-0807-090a-0b0c0d0e0f10"
    );
    assert_eq!(
        format_guid(&[0u8; 16]),
        "00000000-0000-0000-0000-000000000000"
    );
    // A .NET MVID that ikdasm prints as {3C2F06E5-115F-41C1-9886-1F7748FBEF06}.
    let mvid = [
        0xe5, 0x06, 0x2f, 0x3c, 0x5f, 0x11, 0xc1, 0x41, 0x98, 0x86, 0x1f, 0x77, 0x48, 0xfb, 0xef,
        0x06,
    ];
    assert_eq!(format_guid(&mvid), "3c2f06e5-115f-41c1-9886-1f7748fbef06");
}

#[test]
fn uleb128_advances_past_the_value() {
    let bytes = [0xE5, 0x8E, 0x26, 0x05];
    let mut off = 0;
    assert_eq!(read_uleb128(&bytes, &mut off), Some(624_485));
    assert_eq!(off, 3);
    assert_eq!(read_uleb128(&bytes, &mut off), Some(5));
    assert_eq!(read_uleb128(&bytes, &mut off), None);
    // Ten bytes is the longest a 64-bit value can take.
    let mut max = [0xff; 10];
    max[9] = 0x01;
    assert_eq!(read_uleb128(&max, &mut 0), Some(u64::MAX));
    assert_eq!(read_uleb128(&[0xff; 11], &mut 0), None);
}

#[test]
fn plist_to_json_stops_at_the_depth_cap() {
    let mut nested = plist::Value::String("leaf".into());
    for _ in 0..=MAX_PLIST_DEPTH {
        nested = plist::Value::Array(vec![nested]);
    }
    let mut json = &plist_to_json(nested, 0);
    let mut levels = 0;
    while let Some(inner) = json.as_array().and_then(|a| a.first()) {
        json = inner;
        levels += 1;
    }
    assert_eq!(levels, usize::from(MAX_PLIST_DEPTH) + 1);
    assert_eq!(*json, JsonValue::Null);
}

#[test]
fn basename_unix_path() {
    assert_eq!(basename("/tmp/foo/bar.exe"), "bar.exe");
}

#[test]
fn basename_windows_path() {
    assert_eq!(basename("C:\\Users\\bob\\stealer.exe"), "stealer.exe");
}

#[test]
fn basename_mixed_separators() {
    // Windows forward-slash convention.
    assert_eq!(basename("C:/Users\\bob/run.exe"), "run.exe");
}

#[test]
fn basename_no_separator() {
    assert_eq!(basename("foo.exe"), "foo.exe");
}

#[test]
fn basename_trailing_separator_returns_empty() {
    // Pure mechanical behavior: the segment after the last separator is "".
    // Callers should normalize trailing separators before calling.
    assert_eq!(basename("foo/"), "");
}

#[test]
fn stem_simple() {
    assert_eq!(stem("update.exe"), "update");
}

#[test]
fn stem_strips_only_last_extension() {
    // Python pathlib semantics: stem of "foo.tar.gz" is "foo.tar".
    assert_eq!(stem("foo.tar.gz"), "foo.tar");
}

#[test]
fn stem_no_extension() {
    assert_eq!(stem("Makefile"), "Makefile");
}

#[test]
fn stem_leading_dot_is_not_extension() {
    // .gitignore is a hidden file, not "extension only".
    assert_eq!(stem(".gitignore"), ".gitignore");
    // ..foo has stem ..foo for the same reason.
    assert_eq!(stem("..foo"), "..foo");
}

#[test]
fn stem_dotfile_with_extension() {
    // .config.json: leading-dot prefix preserved, .json stripped.
    assert_eq!(stem(".config.json"), ".config");
}

#[test]
fn stem_empty_string() {
    assert_eq!(stem(""), "");
}

/// A stream nested inside a storage must render `/`-separated on every
/// host. `cfb` joins path components with the platform separator, so on
/// Windows this walk yields `/VBA\dir` — which silently defeated every
/// `/vba/`-style match in the OLE and VBA extractors, and put a
/// backslash into the published `office.streams` paths.
#[test]
fn cfb_entry_paths_are_slash_separated_on_every_host() {
    use std::io::Cursor;

    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
        comp.create_storage("/VBA").unwrap();
        comp.create_stream("/VBA/dir").unwrap();
    }
    let comp = cfb::CompoundFile::open(buf).unwrap();
    let paths: Vec<String> = comp.walk().map(|e| cfb_entry_path(&e)).collect();

    assert!(
        paths.iter().any(|p| p == "/VBA/dir"),
        "nested entry should normalise to /VBA/dir, got {paths:?}"
    );
    assert!(
        paths.iter().all(|p| !p.contains('\\')),
        "no host separator should survive: {paths:?}"
    );
}

#[test]
fn malformed_utf16_bom_utf8_payload_preserves_string_offsets() {
    let bytes = b"\xff\xfe@echo off\r\npowershell -command Invoke-WebRequest\r\n\0";
    let mut strings = Strings::new();

    extract_text_strings(bytes, &mut strings, XorScan::No);

    let command = strings
        .text
        .ascii()
        .find(|s| s.value.contains("Invoke-WebRequest"))
        .expect("malformed BOM wrapper must expose its text");
    assert_eq!(command.data_offset, 13);
}

#[test]
fn malformed_utf16_bom_batch_reaches_the_public_text_view() {
    let bytes = b"\xff\xfe@echo off\r\npowershell -command Invoke-WebRequest\r\n\0";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("dropper.bat"))
        .open(bytes);

    assert!(
        parsed
            .text()
            .ascii()
            .any(|s| s.value.contains("Invoke-WebRequest")),
        "source fallback must retain malformed BOM-wrapped batch text"
    );
}
