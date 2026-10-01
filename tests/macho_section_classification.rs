//! Original executable-constants specimen and malformed/virtual section cases.
#![allow(
    clippy::indexing_slicing,
    reason = "helpers index a fixed, trusted fixture at known offsets"
)]
use sha2::{Digest, Sha256};
const FAT: &[u8] = include_bytes!("../testdata/macho/lcg_xor_executable_constants.macho");
fn open(b: &[u8]) -> filefacts::ParsedFile<'_> {
    filefacts::cache::set_caching_enabled(false);
    filefacts::open(b).unwrap()
}
fn thin() -> &'static [u8] {
    &FAT[0x4000..0x4000 + 48560]
}
fn word(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn header(b: &[u8], name: &str) -> (usize, usize) {
    let mut p = 32;
    for _ in 0..word(b, 16) {
        if word(b, p) == 0x19 {
            for i in 0..word(b, p + 64) as usize {
                let h = p + 72 + i * 80;
                if b[h..h + 16].split(|c| *c == 0).next().unwrap() == name.as_bytes() {
                    return (p, h);
                }
            }
        }
        p += word(b, p + 4) as usize;
    }
    panic!("section {name}")
}
fn entropy(b: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for c in b {
        counts[*c as usize] += 1;
    }
    counts
        .iter()
        .filter(|n| **n > 0)
        .map(|n| {
            let p = *n as f64 / b.len() as f64;
            -p * p.log2()
        })
        .sum()
}
#[test]
fn code_entropy_excludes_executable_constants_and_uses_real_file_spans() {
    let _disable = filefacts::rizin::scoped_disable_current_thread();
    assert_eq!(
        format!("{:x}", Sha256::digest(FAT)),
        "a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1"
    );
    for b in [FAT, thin(), &FAT[65536..65536 + 85776]] {
        let p = open(b);
        let secs = p.sections();
        let constants = secs.iter().find(|s| s.name == "__TEXT,__const").unwrap();
        assert!(constants.is_executable());
        assert!(!constants.is_code());
        assert!(constants.flags.iter().any(|f| f == "data"));
        assert!(constants.entropy.unwrap() > 7.5);
        let code: Vec<_> = secs
            .iter()
            .filter(|s| {
                matches!(
                    s.name.as_str(),
                    "__TEXT,__text" | "__TEXT,__stubs" | "__TEXT,__stub_helper"
                )
            })
            .collect();
        assert_eq!(code.len(), 3);
        let mut weighted = 0.;
        let mut size = 0;
        for s in &code {
            assert!(s.is_code());
            let bytes = &b[s.file_offset as usize..(s.file_offset + s.file_size) as usize];
            let h = entropy(bytes);
            assert!((h - s.entropy.unwrap()).abs() < 1e-9);
            weighted += h * s.file_size as f64;
            size += s.file_size;
        }
        let fact = p.metrics().fact("binary.code_entropy").unwrap();
        assert!((fact.value - weighted / size as f64).abs() < 1e-9);
        assert_eq!(
            fact.spans
                .iter()
                .map(|s| (s.offset, s.len))
                .collect::<Vec<_>>(),
            code.iter()
                .map(|s| (s.file_offset, s.file_size))
                .collect::<Vec<_>>()
        );
        assert!(
            p.metrics()
                .fact("binary.data_entropy")
                .unwrap()
                .spans
                .iter()
                .any(|s| s.offset == constants.file_offset && s.len == constants.file_size)
        );
        assert_eq!(p.parse_count(), 1);
    }
}
#[test]
fn fat_sections_are_rebased_once_without_changing_entropy() {
    let _disable = filefacts::rizin::scoped_disable_current_thread();
    let fat = open(FAT);
    let t = open(thin());
    assert_eq!(fat.sections().len(), t.sections().len());
    for (f, s) in fat.sections().iter().zip(t.sections().iter()) {
        assert_eq!(f.name, s.name);
        assert_eq!(f.file_offset, s.file_offset + 0x4000);
        assert_eq!(f.file_size, s.file_size);
        assert_eq!(f.entropy, s.entropy);
    }
}
#[test]
fn instruction_attributes_and_stub_type_work_without_conventional_names() {
    let _disable = filefacts::rizin::scoped_disable_current_thread();
    for flags in [0x80000000u32, 0x400, 8] {
        let mut b = thin().to_vec();
        let (_, h) = header(&b, "__const");
        b[h..h + 16].fill(0);
        b[h..h + 9].copy_from_slice(b"__renamed");
        b[h + 64..h + 68].copy_from_slice(&flags.to_le_bytes());
        let p = open(&b);
        let s = p
            .sections()
            .iter()
            .find(|s| s.name == "__TEXT,__renamed")
            .unwrap();
        assert!(s.is_code());
    }
}
#[test]
fn instruction_attributes_do_not_override_non_executable_segment_permissions() {
    let _disable = filefacts::rizin::scoped_disable_current_thread();
    let mut b = thin().to_vec();
    let (seg, _) = header(&b, "__text");
    b[seg + 60..seg + 64].copy_from_slice(&1u32.to_le_bytes());
    let p = open(&b);
    let s = p
        .sections()
        .iter()
        .find(|s| s.name == "__TEXT,__text")
        .unwrap();
    assert!(s.flags.iter().any(|f| f == "code"));
    assert!(!s.is_executable());
    assert!(!s.is_code());
}
#[test]
fn zero_fill_sections_have_no_file_bytes_entropy_or_rebased_offset() {
    let _disable = filefacts::rizin::scoped_disable_current_thread();
    for flags in [1u32, 0xc, 0x12] {
        for fat in [false, true] {
            let mut b = if fat { FAT.to_vec() } else { thin().to_vec() };
            let base = if fat { 0x4000 } else { 0 };
            let (_, h) = header(&b[base..], "__const");
            let h = h + base;
            b[h + 64..h + 68].copy_from_slice(&flags.to_le_bytes());
            b[h + 48..h + 52].fill(0);
            let p = open(&b);
            let s = p
                .sections()
                .iter()
                .find(|s| s.name == "__TEXT,__const")
                .unwrap();
            assert!(s.vsize > 0);
            assert_eq!(s.file_size, 0, "type {flags:x}, fat={fat}");
            assert_eq!(s.file_offset, 0);
            assert_eq!(s.entropy, None);
            assert!(
                !p.metrics()
                    .fact("binary.data_entropy")
                    .unwrap()
                    .spans
                    .iter()
                    .any(|s| s.offset == 0 || s.offset == 0x4000)
            );
        }
    }
}
#[test]
fn pe_and_elf_execute_flags_keep_their_existing_meaning() {
    let _disable = filefacts::rizin::scoped_disable_current_thread();
    let p = open(thin());
    let mut s = p.sections().iter().next().unwrap().clone();
    for flags in [
        vec!["executable"],
        vec!["executable", "code"],
        vec!["execinstr", "alloc"],
    ] {
        s.flags = flags.iter().map(|s| s.to_string()).collect();
        assert!(s.is_executable());
        assert!(s.is_code());
    }
    s.flags = vec!["executable".into(), "data".into()];
    assert!(s.is_executable());
    assert!(!s.is_code());
}
