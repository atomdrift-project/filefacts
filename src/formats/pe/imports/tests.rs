use super::*;
use crate::formats::goblin_safe;
use crate::formats::pe::tests::read_fixture;

#[test]
fn delay_import_vas_resolve_against_the_full_image_base() {
    // RvaBased descriptors pass through untouched.
    assert_eq!(delay_import_rva(0x2000, true, 0x1_4000_0000), 0x2000);
    // Legacy VA-based descriptor in a PE32 image.
    assert_eq!(delay_import_rva(0x0040_2000, false, 0x0040_0000), 0x2000);
    // A PE32+ base is above every 32-bit VA. Truncating it to its low
    // half (0x4000_0000) would turn this forged VA into RVA 0x2000.
    assert_eq!(delay_import_rva(0x4000_2000, false, 0x1_4000_0000), 0);
}

/// `test.exe` (PE32+) with `descriptors` delay-load descriptors that all
/// share one name table of `entries` ordinal imports.
fn pe_with_shared_delay_imports(descriptors: usize, entries: usize) -> Vec<u8> {
    let put = |bytes: &mut Vec<u8>, at: usize, value: u32| {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_offset + 4;
    let sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_optional = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap());
    let optional = coff + 20;
    let last = optional + size_of_optional as usize + (sections - 1) * 40;
    let va = u32::from_le_bytes(bytes[last + 12..last + 16].try_into().unwrap());
    let pointer = u32::from_le_bytes(bytes[last + 20..last + 24].try_into().unwrap()) as usize;

    let dll_at = (descriptors + 1) * 32;
    let int_at = dll_at + 8;
    let size = int_at + (entries + 1) * 8;
    bytes.resize(pointer + size, 0);
    bytes[pointer..pointer + size].fill(0);
    put(&mut bytes, last + 8, size as u32); // virtual_size
    put(&mut bytes, last + 16, size as u32); // size_of_raw_data
    bytes[pointer + dll_at..pointer + dll_at + 6].copy_from_slice(b"a.dll\0");
    for i in 0..entries {
        let at = pointer + int_at + i * 8;
        bytes[at..at + 8].copy_from_slice(&0x8000_0000_0000_0001_u64.to_le_bytes());
    }
    for i in 0..descriptors {
        let at = pointer + i * 32;
        put(&mut bytes, at, 1); // RvaBased
        put(&mut bytes, at + 4, va + dll_at as u32);
        put(&mut bytes, at + 16, va + int_at as u32);
    }
    // Data directory 13 is the delay-import table; PE32+ puts the array at +112.
    let slot = optional + 112 + 13 * 8;
    put(&mut bytes, slot, va);
    put(&mut bytes, slot + 4, ((descriptors + 1) * 32) as u32);
    bytes
}

/// Descriptors sharing one name table multiply into symbols; the total is
/// capped, not just each table.
#[test]
fn delay_imports_are_capped_across_descriptors() {
    let small = pe_with_shared_delay_imports(3, 5);
    let prepared = goblin_safe::prepare_pe(&small);
    let pe = goblin_safe::parse_pe(&prepared).ok().expect("parses");
    let (mut values, mut metrics, mut symbols) =
        (Values::new(), Metrics::new(), crate::Symbols::new());
    delay_imports(&pe, &small, &mut values, &mut metrics, &mut symbols);
    assert_eq!(symbols.len(), 15);
    assert_eq!(metrics.get("pe.delay_import_count"), Some(15.0));

    // 128 descriptors x 4096 entries would be half a million symbols.
    let big = pe_with_shared_delay_imports(128, 4096);
    let prepared = goblin_safe::prepare_pe(&big);
    let pe = goblin_safe::parse_pe(&prepared).ok().expect("parses");
    let (mut values, mut metrics, mut symbols) =
        (Values::new(), Metrics::new(), crate::Symbols::new());
    delay_imports(&pe, &big, &mut values, &mut metrics, &mut symbols);
    assert_eq!(symbols.len(), 16 * 1024);
    assert_eq!(metrics.get("pe.delay_import_count"), Some(16.0 * 1024.0));
}

/// An import as goblin synthesizes it: by name, or by ordinal as
/// `ORDINAL n`.
fn import<'a>(dll: &'a str, name: Option<&'a str>, ordinal: u16) -> Import<'a> {
    Import {
        name: name.map_or_else(|| format!("ORDINAL {ordinal}").into(), Into::into),
        dll,
        ordinal,
        offset: 0,
        rva: 0,
        size: 0,
    }
}

/// The imphash pefile and VirusTotal compute. The joined string below is
/// derived from pefile's `get_imphash` and its `ordlookup` tables, not from
/// this code: `ws2_32.dll` ordinals 3 and 115 are `closesocket` and
/// `WSAStartup`, and `wsock32.dll` 16 is `recv`;
/// `oleaut32.dll` 2 is `SysAllocString`, while 1 is not in its table; any
/// other library, and any ordinal missing from a table, reads `ord<n>`. Only
/// a final `.dll`/`.ocx`/`.sys` is stripped, and the library and function
/// are lowercased. Its MD5 was computed independently.
#[test]
fn imphash_matches_pefile() {
    let imports = [
        import("KERNEL32.dll", Some("GetProcAddress"), 0x2b5),
        import("WS2_32.dll", None, 3),
        import("WS2_32.dll", None, 115),
        import("WS2_32.dll", None, 400),
        import("WSOCK32.dll", None, 16),
        import("OLEAUT32.dll", None, 2),
        import("OLEAUT32.dll", None, 1),
        import("MSVCRT.dll", None, 7),
        import("foo.ocx.DLL", None, 2),
        import("USER32", Some("MessageBoxA"), 0),
    ];
    // kernel32.getprocaddress,ws2_32.closesocket,ws2_32.wsastartup,
    // ws2_32.ord400,wsock32.recv,oleaut32.sysallocstring,oleaut32.ord1,
    // msvcrt.ord7,foo.ocx.ord2,user32.messageboxa
    assert_eq!(
        imphash(&imports).as_deref(),
        Some("5003190901ffd22d77db9eea33178aa1")
    );
    assert_eq!(imphash(&[]), None);
}

/// A function genuinely named like goblin's ordinal placeholder, but with a
/// different ordinal, is hashed by its name.
#[test]
fn only_goblins_own_ordinal_names_read_as_ordinals() {
    assert!(by_ordinal(&import("a.dll", None, 9)));
    assert!(!by_ordinal(&import("a.dll", Some("ORDINAL 9"), 10)));
    assert!(!by_ordinal(&import("a.dll", Some("ORDINAL"), 0)));
}

/// The tables are sorted for the binary search, ordinals unique.
#[test]
fn ordinal_tables_are_sorted() {
    for table in [ordinals::WS2_32, ordinals::WSOCK32, ordinals::OLEAUT32] {
        assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
    }
    assert_eq!(ordinal_name("ws2_32.dll", 500), "WEP");
    assert_eq!(
        ordinal_name("oleaut32.dll", 443),
        "UnRegisterTypeLibForUser"
    );
    assert_eq!(ordinal_name("kernel32.dll", 1), "ord1");
}
