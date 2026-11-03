use super::*;
use crate::output::SymbolKind;

/// One pclntab layout: its magic's low byte, byte order and pointer size.
#[derive(Clone, Copy, Debug)]
struct Layout {
    magic: u8,
    big_endian: bool,
    pointer: usize,
}

impl Layout {
    fn version(self) -> Version {
        match self.magic {
            0xfb => Version::Go12,
            0xfa => Version::Go116,
            _ => Version::Go118,
        }
    }

    fn field(self) -> usize {
        match self.version() {
            Version::Go118 => 4,
            Version::Go12 | Version::Go116 => self.pointer,
        }
    }
}

const LAYOUTS: [Layout; 8] = [
    Layout {
        magic: 0xfb,
        big_endian: false,
        pointer: 8,
    },
    Layout {
        magic: 0xfb,
        big_endian: true,
        pointer: 4,
    },
    Layout {
        magic: 0xfa,
        big_endian: false,
        pointer: 8,
    },
    Layout {
        magic: 0xfa,
        big_endian: true,
        pointer: 8,
    },
    Layout {
        magic: 0xf0,
        big_endian: false,
        pointer: 8,
    },
    Layout {
        magic: 0xf1,
        big_endian: false,
        pointer: 8,
    },
    Layout {
        magic: 0xf1,
        big_endian: true,
        pointer: 8,
    },
    Layout {
        magic: 0xf1,
        big_endian: false,
        pointer: 4,
    },
];

const GO120: Layout = Layout {
    magic: 0xf1,
    big_endian: false,
    pointer: 8,
};

fn set(table: &mut [u8], at: usize, value: u64, width: usize, big_endian: bool) {
    let bytes = value.to_be_bytes();
    let mut field = bytes[8 - width..].to_vec();
    if !big_endian {
        field.reverse();
    }
    table[at..at + width].copy_from_slice(&field);
}

fn put(table: &mut Vec<u8>, value: u64, width: usize, big_endian: bool) {
    let at = table.len();
    table.resize(at + width, 0);
    set(table, at, value, width, big_endian);
}

const TEXT: u64 = 0x40_1000;

/// A pclntab naming `functions` (name, entry address) and closing at `end`,
/// laid out as Go's linker writes `layout`. The 1.18+ header's text word
/// holds a bogus value: readers must take the text start from the image.
fn build(layout: Layout, functions: &[(&str, u64)], end: u64) -> Vec<u8> {
    let (pointer, field, big_endian) = (layout.pointer, layout.field(), layout.big_endian);
    let version = layout.version();
    let entry = |address: u64| match version {
        Version::Go118 => address - TEXT,
        Version::Go12 | Version::Go116 => address,
    };
    let mut table = Vec::new();
    put(
        &mut table,
        0xffff_ff00 | u64::from(layout.magic),
        4,
        big_endian,
    );
    table.extend([0, 0, 1, pointer as u8]);
    let words = table.len();
    table.resize(
        words
            + pointer
                * match version {
                    Version::Go12 => 1,
                    Version::Go116 => 7,
                    Version::Go118 => 8,
                },
        0,
    );
    let functab_len = (2 * functions.len() + 1) * field;
    // Go 1.2's functab follows the header; later layouts put names first.
    let mut functab = table.len();
    if version == Version::Go12 {
        table.resize(functab + functab_len, 0);
    }
    let names = table.len();
    let mut name_offsets = Vec::new();
    for (name, _) in functions {
        let base = if version == Version::Go12 { 0 } else { names };
        name_offsets.push((table.len() - base) as u64);
        table.extend(name.as_bytes());
        table.push(0);
    }
    if version != Version::Go12 {
        functab = table.len();
        table.resize(functab + functab_len, 0);
    }
    let records_base = if version == Version::Go12 { 0 } else { functab };
    for (index, (&(_, address), name_offset)) in functions.iter().zip(name_offsets).enumerate() {
        let record = table.len();
        put(&mut table, entry(address), field, big_endian);
        put(&mut table, name_offset, 4, big_endian);
        let slot = functab + index * 2 * field;
        set(&mut table, slot, entry(address), field, big_endian);
        set(
            &mut table,
            slot + field,
            (record - records_base) as u64,
            field,
            big_endian,
        );
    }
    set(
        &mut table,
        functab + 2 * functions.len() * field,
        entry(end),
        field,
        big_endian,
    );
    let header = [
        functions.len() as u64,
        0,
        0xdead_beef,
        names as u64,
        0,
        0,
        0,
        functab as u64,
    ];
    let header: &[u64] = match version {
        Version::Go12 => &header[..1],
        Version::Go116 => &[header[0], 0, header[3], 0, 0, 0, header[7]],
        Version::Go118 => &header,
    };
    for (index, &word) in header.iter().enumerate() {
        set(
            &mut table,
            words + index * pointer,
            word,
            pointer,
            big_endian,
        );
    }
    table
}

const FUNCTIONS: [(&str, u64); 3] = [
    ("runtime.main", TEXT),
    ("main.main", TEXT + 0x40),
    ("example.com/pkg.(*T).Method[...]", TEXT + 0x100),
];
const END: u64 = TEXT + 0x180;

/// Code exactly spanned by [`FUNCTIONS`].
fn code() -> Code {
    Code::of([(TEXT, END - TEXT)]).unwrap()
}

fn read_all(table: &[u8], code: Code) -> Vec<(String, u64)> {
    entries(functions(table, code, TEXT).expect("the table reads"))
}

/// Each function's name and entry; none carries rizin's metrics.
fn entries(functions: Vec<Symbol>) -> Vec<(String, u64)> {
    functions
        .into_iter()
        .map(|symbol| match symbol {
            Symbol::Function {
                name,
                offset,
                complexity,
                callees,
            } => {
                assert_eq!(complexity, None);
                assert!(callees.is_empty());
                (name, offset.unwrap())
            }
            other => panic!("not a function: {other:?}"),
        })
        .collect()
}

#[test]
fn every_layout_and_byte_order_reads_names_and_entry_addresses() {
    let want: Vec<(String, u64)> = FUNCTIONS
        .iter()
        .map(|&(name, address)| (name.to_owned(), address))
        .collect();
    for layout in LAYOUTS {
        let table = build(layout, &FUNCTIONS, END);
        assert_eq!(read_all(&table, code()), want, "{layout:?}");
    }
}

#[test]
fn go118_entries_count_from_the_image_text_not_the_header_word() {
    // The header's text word reads 0xdeadbeef; Go 1.27 writes zero there.
    let table = build(GO120, &FUNCTIONS, END);
    assert_eq!(
        read_all(&table, code())[1],
        ("main.main".to_owned(), TEXT + 0x40)
    );
    // Read against another text start, every entry moves with it.
    let moved = Code::of([(TEXT + 0x1000, END - TEXT)]).unwrap();
    let shifted = entries(functions(&table, moved, TEXT + 0x1000).unwrap());
    assert_eq!(shifted[0].1, TEXT + 0x1000);
}

#[test]
fn a_table_covering_little_of_the_code_is_a_decoy() {
    // A real Go text section is nearly all functions. A tiny table grafted
    // onto a payload, to keep rizin out, spans a sliver of its code.
    let table = build(GO120, &FUNCTIONS, END);
    let payload = Code::of([(TEXT, 0x10_0000)]).unwrap();
    assert_eq!(
        read(&table, payload, TEXT).unwrap_err(),
        "functions cover too little of the executable code"
    );
    // Half is enough: Go code shares the section with cgo's C objects.
    let half = Code::of([(TEXT, 2 * (END - TEXT))]).unwrap();
    assert!(functions(&table, half, TEXT).is_some());
}

#[test]
fn functions_outside_the_code_are_refused() {
    let table = build(GO120, &FUNCTIONS, END);
    let short = Code::of([(TEXT, END - TEXT - 1)]).unwrap();
    assert_eq!(
        read(&table, short, TEXT).unwrap_err(),
        "functions lie outside the executable code"
    );
    let later = Code::of([(TEXT + 1, END - TEXT)]).unwrap();
    assert_eq!(
        read(&table, later, TEXT).unwrap_err(),
        "functions lie outside the executable code"
    );
}

#[test]
fn entries_out_of_order_are_refused() {
    let shuffled = [FUNCTIONS[1], FUNCTIONS[0], FUNCTIONS[2]];
    for layout in LAYOUTS {
        let table = build(layout, &shuffled, END);
        assert_eq!(
            read(&table, code(), TEXT).unwrap_err(),
            "functab entries out of order",
            "{layout:?}"
        );
    }
    // An end before the last entry is out of order too.
    let table = build(GO120, &FUNCTIONS, TEXT + 0x80);
    assert_eq!(
        read(&table, code(), TEXT).unwrap_err(),
        "functab end precedes its last entry"
    );
}

/// A [`GO120`] table's header word `index`.
fn word(table: &[u8], index: usize) -> usize {
    u64::from_le_bytes(table[8 + index * 8..16 + index * 8].try_into().unwrap()) as usize
}

/// The offsets of a [`GO120`] table's `_func` records, in functab order.
fn records(table: &[u8]) -> Vec<usize> {
    let functab = word(table, 7);
    (0..word(table, 0))
        .map(|index| {
            let at = functab + index * 8 + 4;
            functab + u32::from_le_bytes(table[at..at + 4].try_into().unwrap()) as usize
        })
        .collect()
}

#[test]
fn a_record_that_disagrees_with_the_functab_is_refused() {
    let mut table = build(GO120, &FUNCTIONS, END);
    let record = records(&table)[0];
    table[record] ^= 0x10;
    assert_eq!(
        read(&table, code(), TEXT).unwrap_err(),
        "function record disagrees with the functab"
    );
}

#[test]
fn a_name_out_of_bounds_or_negative_is_refused() {
    let table = build(GO120, &FUNCTIONS, END);
    let record = records(&table)[0];
    for offset in [u32::MAX, i32::MAX as u32, table.len() as u32] {
        let mut forged = table.clone();
        forged[record + 4..record + 8].copy_from_slice(&offset.to_le_bytes());
        assert!(
            read(&forged, code(), TEXT).is_err(),
            "name offset {offset:#x}"
        );
    }
}

#[test]
fn a_forged_function_count_is_refused() {
    for count in [0, u64::from(u32::MAX), (MAX_FUNCTIONS + 1) as u64] {
        let mut table = build(GO120, &FUNCTIONS, END);
        table[8..16].copy_from_slice(&count.to_le_bytes());
        assert!(read(&table, code(), TEXT).is_err(), "count {count}");
    }
}

#[test]
fn names_past_their_budget_are_refused() {
    // Honest names are disjoint slices of the funcname table, so copying
    // them costs at most the table's size. A forged table can aim every
    // record at one long name and multiply the copy.
    let named: Vec<(&str, u64)> = (0..64).map(|i| ("f", TEXT + i * 0x10)).collect();
    let code = Code::of([(TEXT, 64 * 0x10)]).unwrap();
    let mut table = build(GO120, &named, TEXT + 64 * 0x10);
    assert!(read(&table, code, TEXT).is_ok());
    let long = table.len() - word(&table, 3);
    table.extend([b'x'; 400]);
    table.push(0);
    for record in records(&table) {
        table[record + 4..record + 8].copy_from_slice(&(long as u32).to_le_bytes());
    }
    assert_eq!(
        read(&table, code, TEXT).unwrap_err(),
        "function names exceed the table"
    );
}

#[test]
fn every_truncation_is_refused_without_panicking() {
    for layout in LAYOUTS {
        let table = build(layout, &FUNCTIONS, END);
        for len in 0..table.len() {
            // A cut through the trailing name can still parse whole when the
            // name is the last thing; it may not read any other way.
            if let Ok(read) = read(&table[..len], code(), TEXT) {
                assert_eq!(read.len(), FUNCTIONS.len(), "{layout:?} cut at {len}");
            }
        }
    }
}

#[test]
fn find_skips_stray_magics_and_finds_the_table() {
    let table = build(GO120, &FUNCTIONS, END);
    let mut region = vec![0x90; 37];
    // Stray magics: one without the header's zero padding, one with a
    // plausible prefix and nothing behind it.
    region.extend([0xf1, 0xff, 0xff, 0xff, 1, 0, 1, 8]);
    region.extend([0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8, 0xff, 0xff]);
    region.extend(&table);
    region.extend([0x90; 11]);
    let found = find(&region, code(), TEXT).expect("the table is found");
    assert_eq!(found.len(), FUNCTIONS.len());
    assert!(find(&region[..60], code(), TEXT).is_none());
}

#[test]
fn code_spans_its_executable_ranges() {
    assert_eq!(Code::of([]), None);
    assert_eq!(Code::of([(0x1000, 0)]), None);
    let code = Code::of([(0x3000, 0x100), (0x1000, 0x200)]).unwrap();
    assert_eq!(
        code,
        Code {
            start: 0x1000,
            end: 0x3100,
            bytes: 0x300
        }
    );
    assert!(code.mostly_covered_by(0x180));
    assert!(!code.mostly_covered_by(0x17f));
}

// ------------------------------------------------------------------
// Real Go binaries: their inventory comes from the pclntab and binform's
// recovery never starts.
// ------------------------------------------------------------------

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let compressed = std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"));
    zstd::decode_all(compressed.as_slice()).expect("fixture decompresses")
}

/// Function names, with binform's recovery shown not to have run.
fn go_inventory(bytes: &[u8]) -> Vec<String> {
    let parsed = crate::OpenOptions::new().cache(false).open(bytes);
    assert!(parsed.metrics().get("binary.avg_complexity").is_none());
    parsed
        .symbols()
        .iter_kind(SymbolKind::Function)
        .filter_map(|symbol| symbol.name().map(str::to_owned))
        .collect()
}

#[test]
fn a_stripped_go_elf_reads_its_functions_from_the_pclntab() {
    let names = go_inventory(&fixture("go-pclntab-names.zst"));
    assert_eq!(names.len(), 2078);
    const PKG: &str = "example.com/atomdrift/filefacts-fixture/deliberately/long/module/path/internal/sealedpayload";
    for want in [
        format!("{PKG}.OpenSealedPayload"),
        format!("{PKG}.ReportLength"),
        "main.main".to_owned(),
        "runtime.main".to_owned(),
    ] {
        assert!(names.contains(&want), "{want} missing");
    }
    // Generic instantiations keep their type-shape names.
    assert!(
        names
            .iter()
            .any(|n| n.starts_with(&format!("{PKG}.mustValue[")) && n.contains('{'))
    );
}

#[test]
fn a_stripped_go_pe_finds_its_pclntab_in_rdata() {
    // Go's PE linker writes no `.gopclntab` section.
    let bytes = fixture("go-pe-no-exports.exe.zst");
    let names = go_inventory(&bytes);
    assert_eq!(names.len(), 1415);
    assert!(names.iter().any(|n| n == "main.main"));
    let parsed = crate::OpenOptions::new().cache(false).open(&bytes);
    assert_eq!(parsed.symbols().iter_kind(SymbolKind::Export).count(), 0);
}

#[test]
fn a_stripped_go_macho_reads_its_functions_from_the_pclntab() {
    let names = go_inventory(&fixture("go-macho-arm64.zst"));
    assert_eq!(names.len(), 1435);
    assert!(names.iter().any(|n| n == "main.main"));
}
