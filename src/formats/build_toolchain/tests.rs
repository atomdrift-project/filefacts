use super::*;

#[test]
fn recognizes_ubuntu_gcc_banner() {
    let (fam, ver) = recognize_comment("GCC: (Ubuntu 14.2.0-1ubuntu1) 14.2.0").unwrap();
    assert!(matches!(fam, Family::Gcc));
    assert_eq!(ver, "14.2.0");
}

#[test]
fn recognizes_alpine_clang_banner() {
    let (fam, ver) = recognize_comment("Alpine clang version 19.1.4").unwrap();
    assert!(matches!(fam, Family::Clang));
    assert_eq!(ver, "19.1.4");
}

#[test]
fn recognizes_apple_clang_banner() {
    let (fam, ver) = recognize_comment("Apple clang version 15.0.0 (clang-1500.0.40.1)").unwrap();
    assert!(matches!(fam, Family::AppleClang));
    assert_eq!(ver, "15.0.0");
}

#[test]
fn recognizes_rustc_banner() {
    let (fam, ver) = recognize_comment("rustc version 1.78.0 (9b00956e5 2024-04-29)").unwrap();
    assert!(matches!(fam, Family::Rustc));
    assert_eq!(ver, "1.78.0");
}

/// Every `.rodata*` header may cover the same bytes; the scan stops once
/// the sections it read add up to the file, instead of re-reading them
/// per header. Disjoint sections are all read.
#[test]
fn rodata_scan_is_charged_against_the_file_length() {
    let section = |off: u64, size: u64| crate::output::Section {
        name: ".rodata".into(),
        vaddr: 0,
        vsize: size,
        file_offset: off,
        file_size: size,
        flags: Vec::new(),
        flags_raw: None,
        entropy: None,
    };
    let mut bytes = vec![b'x'; 1000];
    bytes[600..613].copy_from_slice(b"rustc 1.80.0 ");
    let mut sections: Vec<_> = (0..5000).map(|_| section(0, 500)).collect();
    sections.push(section(500, 500));
    assert_eq!(scan_rust_rodata(&sections, &bytes), None);
    let disjoint = [section(0, 500), section(500, 500)];
    assert_eq!(
        scan_rust_rodata(&disjoint, &bytes).as_deref(),
        Some("1.80.0")
    );
}

#[test]
fn ignores_unknown_banner() {
    assert!(recognize_comment("some other text").is_none());
}

/// A Go ELF's toolchain version is the one the build-info decoder read,
/// without its `go` prefix; there is no second parser to disagree.
#[test]
fn go_version_comes_from_the_decoded_build_info() {
    let section = |name: &str| crate::output::Section {
        name: name.into(),
        vaddr: 0,
        vsize: 0,
        file_offset: 0,
        file_size: 0,
        flags: Vec::new(),
        flags_raw: None,
        entropy: None,
    };
    let mut values = Values::new();
    values.insert_key(
        value_key!("elf.go"),
        serde_json::json!({"version": "go1.21.5"}),
    );
    from_elf(&mut values, &[section(".note.go.buildid")], &[]);
    assert_eq!(
        values.get("build.toolchain.compiler"),
        Some(&serde_json::json!("go"))
    );
    assert_eq!(
        values.get("build.toolchain.version"),
        Some(&serde_json::json!("1.21.5"))
    );
}
