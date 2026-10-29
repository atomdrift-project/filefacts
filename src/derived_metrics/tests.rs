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
        metrics.get_key(&metric!("binary.code_to_data_ratio")),
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
