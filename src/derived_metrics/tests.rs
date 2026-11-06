use super::*;
use crate::output::Section;

#[test]
fn forged_section_sizes_do_not_overflow_the_code_data_ratio() {
    // Two sections each claiming nearly `u64::MAX` bytes: the code and
    // data sums must not overflow.
    let section = |name: &str, flag: SectionFlag| Section {
        name: name.into(),
        vaddr: 0,
        vsize: 0,
        file_offset: 0,
        file_size: u64::MAX - 1,
        flags: vec![flag],
        flags_raw: None,
        entropy: Some(1.0),
    };
    let sections = Sections::from_iter([
        section("a", SectionFlag::Executable),
        section("b", SectionFlag::Data),
    ]);
    let mut metrics = Metrics::new();
    emit_binary_aggregates(&sections, &output::Strings::new(), b"x", &mut metrics);
    assert_eq!(
        metrics.lookup(&metric!("binary.code_to_data_ratio")),
        Some(0.5)
    );
}

/// Compiler and loader artifacts must not count as a public API.
///
/// Any C++ binary built with exceptions exports Itanium-ABI RTTI, and every
/// Mach-O executable exports its image header. A stub with no real exports
/// reaches four on those alone, which is enough to satisfy an
/// `exports.api_count >= 4` suppression and silence the obfuscation rules
/// that would otherwise describe it.
#[test]
fn rtti_and_image_header_are_not_api_exports() {
    for artifact in [
        "__ZTISt9exception",
        "_ZTSSt11logic_error",
        "__ZTVN10__cxxabiv117__class_type_infoE",
        "__ZTTSt13basic_fstream",
        "_mh_execute_header",
        "mh_execute_header",
    ] {
        assert!(!is_api_export(artifact), "{artifact} should not count");
    }
}

#[test]
fn ordinary_symbols_are_api_exports() {
    for real in ["_main", "curl_easy_init", "_SSL_connect", "ZLibDecompress"] {
        assert!(is_api_export(real), "{real} should count");
    }
}

#[test]
fn string_length_stddev_is_the_population_stddev() {
    let mut strings = output::Strings::new();
    for (i, len) in [2usize, 4, 4, 4, 5, 5, 7, 9].into_iter().enumerate() {
        strings
            .literals
            .push(crate::output::Literal::new("x".repeat(len), i as u64 * 16));
    }
    let mut metrics = Metrics::new();
    emit_binary_aggregates(&Sections::default(), &strings, b"", &mut metrics);
    assert_eq!(metrics.get("binary.avg_string_length"), Some(5.0));
    assert_eq!(metrics.get("binary.string_length_stddev"), Some(2.0));
}

/// `binary.high_entropy_string_count` counts strings shaped like keys,
/// digests and encoded blobs, and not prose or names.
#[test]
fn high_entropy_strings_are_keys_digests_and_blobs() {
    let mut strings = output::Strings::new();
    for (i, s) in [
        // An access-key-shaped token.
        "AKIAZ7QX4M2PLRWB9TKD",
        // A SHA-1 digest.
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        // A base64 blob of random bytes.
        "q3Zt9vX2LkP0mWbN8rJc5YhG1sFdA7eUo4TiK6wRzEx=",
        // Prose and identifiers are not.
        "The quick brown fox jumps over the lazy dog",
        "initializeComponentRegistry",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE",
        "deadbeefdeadbeefdeadbeef",
    ]
    .into_iter()
    .enumerate()
    {
        strings
            .literals
            .push(crate::output::Literal::new(s, i as u64 * 64));
    }
    let mut metrics = Metrics::new();
    emit_binary_aggregates(&Sections::default(), &strings, b"", &mut metrics);
    assert_eq!(metrics.get("binary.high_entropy_string_count"), Some(3.0));
}

/// A section the format marks as data is not code, even in an executable
/// segment, for every code metric alike.
#[test]
fn code_size_and_code_entropy_agree_on_what_is_code() {
    let section = |name: &str, flags: Vec<SectionFlag>, size: u64| Section {
        name: name.into(),
        vaddr: 0,
        vsize: 0,
        file_offset: 0,
        file_size: size,
        flags,
        flags_raw: None,
        entropy: Some(5.0),
    };
    let sections = Sections::from_iter([
        section(
            "__text",
            vec![SectionFlag::Executable, SectionFlag::Code],
            100,
        ),
        section(
            "__const",
            vec![SectionFlag::Executable, SectionFlag::Data],
            50,
        ),
    ]);
    let mut metrics = Metrics::new();
    emit_section_metrics(&sections, &mut metrics);
    emit_binary_aggregates(&sections, &output::Strings::new(), &[0; 200], &mut metrics);
    assert_eq!(metrics.get("sections.code_size"), Some(100.0));
    assert_eq!(
        metrics.get("binary.code_to_data_ratio"),
        Some(100.0 / 150.0)
    );
}
