//! Original executable-constants specimen and malformed/virtual section cases.
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "helpers index and offset into a fixed, trusted fixture at known positions"
)]
mod common;

// The section views under test come from the static parse alone.
use common::open;
use filefacts::SectionFlag;
use sha2::{Digest, Sha256};
/// The specimen, stored zstd-compressed (see `testdata/README.md`).
static FAT: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    zstd::decode_all(
        &include_bytes!("../testdata/macho/lcg_xor_executable_constants.macho.zst")[..],
    )
    .expect("fixture decompresses")
});
fn thin() -> &'static [u8] {
    &FAT[0x4000..0x4000 + 48560]
}
/// The slice a parse of the whole file describes at its top level, and where
/// it starts: this machine's, so the x86-64 slice or the arm64 one.
fn primary() -> (usize, &'static [u8]) {
    let at = open(&FAT)
        .slice_symbols()
        .primary()
        .expect("a primary slice") as usize;
    let len = if at == 0x4000 { 48560 } else { 85776 };
    (at, &FAT[at..at + len])
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
    assert_eq!(
        format!("{:x}", Sha256::digest(&*FAT)),
        "a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1"
    );
    for b in [FAT.as_slice(), thin(), &FAT[65536..65536 + 85776]] {
        let p = open(b);
        let secs = p.sections();
        let constants = secs.iter().find(|s| s.name == "__TEXT,__const").unwrap();
        assert!(constants.is_executable());
        assert!(!constants.is_code());
        assert!(constants.has_flag(SectionFlag::Data));
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
    let fat = open(&FAT);
    let (at, slice) = primary();
    let t = open(slice);
    assert_eq!(fat.sections().len(), t.sections().len());
    for (f, s) in fat.sections().iter().zip(t.sections().iter()) {
        assert_eq!(f.name, s.name);
        assert_eq!(f.file_offset, s.file_offset + at as u64);
        assert_eq!(f.file_size, s.file_size);
        assert_eq!(f.entropy, s.entropy);
    }
}
/// One parse of a universal file reads what each of its slices imports and
/// exports: the primary slice's among the file's symbols, the other slice's
/// beside them, and each the rows a parse of that slice alone gives. The
/// primary is the slice this machine runs. A thin file has no other slices.
#[test]
fn one_parse_reads_every_slices_imports_and_exports() {
    use filefacts::{Symbol, SymbolKind, Symbols};
    let linked = |symbols: &Symbols| -> Vec<Symbol> {
        let keep = |s: &&Symbol| matches!(s.kind(), SymbolKind::Import | SymbolKind::Export);
        symbols.iter().filter(keep).cloned().collect()
    };
    let (x86_64, arm64) = ((0x4000, thin()), (65536, &FAT[65536..65536 + 85776]));
    let (host, other) = if cfg!(target_arch = "aarch64") {
        (arm64, x86_64)
    } else {
        (x86_64, arm64)
    };
    let fat = open(&FAT);
    assert_eq!(fat.slice_symbols().primary(), Some(host.0));
    assert_eq!(primary().0 as u64, host.0);
    let alone = linked(open(host.1).symbols());
    assert!(alone.iter().any(|s| s.kind() == SymbolKind::Import));
    assert_eq!(linked(fat.symbols()), alone);

    let others: Vec<_> = fat.slice_symbols().others().collect();
    assert_eq!(others.len(), 1);
    assert_eq!(others[0].0, other.0);
    let alone = linked(open(other.1).symbols());
    assert!(alone.iter().any(|s| s.kind() == SymbolKind::Import));
    assert_eq!(linked(others[0].1), alone);
    assert!(
        others[0].1.iter_kind(SymbolKind::Function).next().is_none(),
        "only imports and exports are kept for a slice that is not primary"
    );
    assert_eq!(fat.parse_count(), 1);

    let thin = open(thin());
    assert_eq!(thin.slice_symbols().primary(), None);
    assert_eq!(thin.slice_symbols().others().count(), 0);
}
#[test]
fn instruction_attributes_and_stub_type_work_without_conventional_names() {
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
    let mut b = thin().to_vec();
    let (seg, _) = header(&b, "__text");
    b[seg + 60..seg + 64].copy_from_slice(&1u32.to_le_bytes());
    let p = open(&b);
    let s = p
        .sections()
        .iter()
        .find(|s| s.name == "__TEXT,__text")
        .unwrap();
    assert!(s.has_flag(SectionFlag::Code));
    assert!(!s.is_executable());
    assert!(!s.is_code());
}
#[test]
fn zero_fill_sections_have_no_file_bytes_entropy_or_rebased_offset() {
    for flags in [1u32, 0xc, 0x12] {
        for fat in [false, true] {
            let mut b = if fat { FAT.to_vec() } else { thin().to_vec() };
            let base = if fat { primary().0 } else { 0 };
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
                    .any(|s| s.offset == 0 || s.offset == base as u64)
            );
        }
    }
}
#[test]
fn pe_and_elf_execute_flags_keep_their_existing_meaning() {
    let p = open(thin());
    let mut s = p.sections().iter().next().unwrap().clone();
    for flags in [
        vec![SectionFlag::Executable],
        vec![SectionFlag::Executable, SectionFlag::Code],
        vec![SectionFlag::Executable, SectionFlag::Alloc],
    ] {
        s.flags = flags;
        assert!(s.is_executable());
        assert!(s.is_code());
    }
    s.flags = vec![SectionFlag::Executable, SectionFlag::Data];
    assert!(s.is_executable());
    assert!(!s.is_code());
}
