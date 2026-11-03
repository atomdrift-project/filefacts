use super::extract;
use crate::output::{Metrics, Symbol, Symbols};

fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> Vec<u8> {
    let mut b = vec![0u8; 0x130];
    b[..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    b[0x40..0x42].copy_from_slice(b"NE");
    put16(&mut b, 0x40 + 0x1c, 1); // one segment
    put16(&mut b, 0x40 + 0x1e, 1); // one module
    put16(&mut b, 0x40 + 0x22, 0x40);
    put16(&mut b, 0x40 + 0x28, 0x48);
    put16(&mut b, 0x40 + 0x2a, 0x4a);
    put16(&mut b, 0x40 + 0x32, 4);
    b[0x40 + 0x36] = 2; // Windows
    put16(&mut b, 0x80, 0x10); // segment at 0x100
    put16(&mut b, 0x82, 4);
    put16(&mut b, 0x84, 0x100); // relocation data present
    put16(&mut b, 0x88, 0); // module name offset
    b[0x8a..0x8f].copy_from_slice(b"\x04USER");
    b[0x8f..0x97].copy_from_slice(b"\x07ByNameX");
    put16(&mut b, 0x104, 3);
    for (index, (kind, target)) in [(1u8, 10u16), (1, 999), (2, 5)].into_iter().enumerate() {
        let at = 0x106 + 8 * index;
        b[at] = 3; // far pointer
        b[at + 1] = kind;
        put16(&mut b, at + 2, 0);
        put16(&mut b, at + 4, 1); // first module reference
        put16(&mut b, at + 6, target);
    }
    b
}

#[test]
fn resolves_known_ordinals_and_retains_unknown_and_named_imports() {
    let mut symbols = Symbols::new();
    extract(&fixture(), &mut symbols, &mut Metrics::default()).unwrap();
    assert!(symbols.iter().any(|s| matches!(s, Symbol::Import { name, library: Some(lib), ordinal: Some(10), .. } if name == "SetTimer" && lib == "user")));
    assert!(symbols.iter().any(
        |s| matches!(s, Symbol::Import { name, ordinal: Some(999), .. } if name == "ordinal_999")
    ));
    assert!(
        symbols
            .iter()
            .any(|s| matches!(s, Symbol::Import { name, ordinal: None, .. } if name == "ByNameX"))
    );
}

#[test]
fn normal_filefacts_pipeline_exposes_imports() {
    let bytes = fixture();
    let parsed = crate::OpenOptions::new().open(&bytes);
    assert_eq!(parsed.fileid().file_type(), crate::FileType::Ne);
    let extracted = parsed.run_pipeline();
    assert!(extracted.symbols.iter().any(
        |s| matches!(s, Symbol::Import { name, ordinal: Some(10), .. } if name == "SetTimer")
    ));
}

#[test]
fn does_not_apply_windows_ordinal_names_to_other_ne_targets() {
    let mut bytes = fixture();
    bytes[0x40 + 0x36] = 1;
    let mut symbols = Symbols::new();
    extract(&bytes, &mut symbols, &mut Metrics::default()).unwrap();
    assert!(symbols.iter().any(
        |s| matches!(s, Symbol::Import { name, ordinal: Some(10), .. } if name == "ordinal_10")
    ));
}

#[test]
fn resolves_additional_ordinals_only_for_their_defining_module() {
    assert_eq!(
        super::ordinal_name("kernel", 59),
        Some("WriteProfileString")
    );
    assert_eq!(super::ordinal_name("kernel", 166), Some("WinExec"));
    assert_eq!(super::ordinal_name("user", 141), Some("SetClipboardData"));
    assert_eq!(super::ordinal_name("shell", 5), Some("RegSetValue"));
    assert_eq!(super::ordinal_name("other", 59), None);
    assert_ne!(super::ordinal_name("user", 5), Some("RegSetValue"));
}

#[test]
fn rejects_truncated_and_out_of_range_tables_without_partial_symbols() {
    let mut cases = Vec::new();
    let mut bad = fixture();
    bad.truncate(0x10b);
    cases.push(bad);
    let mut bad = fixture();
    put16(&mut bad, 0x106 + 4, 2); // invalid module index
    cases.push(bad);
    let mut bad = fixture();
    put16(&mut bad, 0x40 + 0x32, 31); // unsupported alignment
    cases.push(bad);
    for bytes in cases {
        let mut symbols = Symbols::new();
        assert!(extract(&bytes, &mut symbols, &mut Metrics::default()).is_err());
        assert!(symbols.is_empty());
    }
}
