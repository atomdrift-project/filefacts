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
        // The address table the loader binds, here the name table itself.
        put(&mut bytes, at + 12, va + int_at as u32);
        put(&mut bytes, at + 16, va + int_at as u32);
    }
    // Data directory 13 is the delay-import table; PE32+ puts the array at +112.
    let slot = optional + 112 + 13 * 8;
    put(&mut bytes, slot, va);
    put(&mut bytes, slot + 4, ((descriptors + 1) * 32) as u32);
    bytes
}

/// Descriptors sharing one name table multiply into symbols; the total is
/// capped, not just each table, in the descriptor facts and in the symbols.
#[test]
fn delay_imports_are_capped_across_descriptors() {
    let views = |bytes: &[u8]| {
        let prepared = goblin_safe::prepare_pe(bytes);
        let pe = goblin_safe::parse_pe(&prepared).ok().expect("parses");
        let layout = binform::parse(bytes).expect("binform reads it");
        let (mut values, mut metrics, mut symbols) =
            (Values::new(), Metrics::new(), crate::Symbols::new());
        delay_imports(&pe, bytes, &mut values, &mut metrics);
        imports(
            &layout,
            pe.image_base,
            pe.header.coff_header.machine,
            false,
            &mut values,
            &mut metrics,
            &mut symbols,
        );
        let delayed = symbols
            .iter()
            .filter(|s| matches!(s, crate::Symbol::Import { library: Some(l), .. } if l == "a"))
            .count();
        (delayed, metrics.get("pe.delay_import_count"))
    };
    assert_eq!(views(&pe_with_shared_delay_imports(3, 5)), (15, Some(15.0)));
    // 128 descriptors x 4096 entries would be half a million symbols.
    assert_eq!(
        views(&pe_with_shared_delay_imports(128, 4096)),
        (16 * 1024, Some(16.0 * 1024.0))
    );
}

/// An import as binform reads it: by name, or by ordinal.
fn import(dll: &str, name: Option<&str>, ordinal: u16) -> binform::Import {
    binform::Import {
        name: name.map_or_else(|| format!("Ordinal_{ordinal}"), Into::into),
        library: Some(dll.into()),
        ordinal: name.is_none().then_some(ordinal),
        slot: None,
        delayed: false,
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
        imphash(&imports.iter().collect::<Vec<_>>()).as_deref(),
        Some("5003190901ffd22d77db9eea33178aa1")
    );
    assert_eq!(imphash(&[]), None);
}

/// A function genuinely named like an ordinal placeholder is hashed by its
/// name: only an import the table marks by ordinal reads as one.
#[test]
fn only_imports_by_ordinal_hash_as_ordinals() {
    let named = binform::Import {
        ordinal: None,
        ..import("a.dll", Some("ORDINAL 9"), 0)
    };
    assert_eq!(
        imphash(&[&named]),
        imphash(&[&import("a.dll", Some("ordinal 9"), 0)])
    );
    assert_ne!(imphash(&[&named]), imphash(&[&import("a.dll", None, 9)]));
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

/// The naming-only tables are sorted too, and name what the DLLs export
/// there (msi's as Wine's `msi.spec` numbers them); the imphash still takes
/// pefile's tables alone, so it keeps matching pefile and VirusTotal.
#[test]
fn naming_tables_name_imports_but_not_the_imphash() {
    for table in [
        ordinal_names::MSI,
        ordinal_names::COMCTL32,
        ordinal_names::CABINET,
        ordinal_names::MFC42,
        ordinal_names::MFC42U,
        ordinal_names::COREDLL,
        ordinal_names::COREDLL_X86,
        ordinal_names::COREDLL_ARM,
        ordinal_names::COREDLL_MIPS,
        ordinal_names::COREDLL_SH,
        ordinal_names::COMMCTRL,
    ] {
        assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
    }
    assert_eq!(
        known_ordinal("msi.dll", 141, None),
        Some("MsiSetInternalUI")
    );
    assert_eq!(
        known_ordinal("msi.dll", 281, None),
        Some("MsiSetExternalUIRecord")
    );
    assert_eq!(
        known_ordinal("comctl32.dll", 17, None),
        Some("InitCommonControls")
    );
    assert_eq!(
        known_ordinal("mfc42.dll", 6375, None),
        Some("?WinHelpA@CWinApp@@UAEXKI@Z")
    );
    // comctl32 6.0 renumbered what 5.82 exported at 18 to 20.
    assert_eq!(known_ordinal("comctl32.dll", 21, None), None);
    assert_eq!(known_ordinal("ws2_32.dll", 500, None), Some("WEP"));
    assert_eq!(ordinal_name("msi.dll", 141), "ord141");
}

/// Windows CE's coredll numbers most exports alike on every CPU, but not
/// all: those it does not are named only when the PE's CPU is known.
#[test]
fn windows_ce_ordinals_follow_the_cpu() {
    assert_eq!(
        known_ordinal("coredll.dll", 2, None),
        Some("InitializeCriticalSection")
    );
    assert_eq!(
        known_ordinal("commctrl.dll", 2, None),
        Some("InitCommonControlsEx")
    );
    assert_eq!(known_ordinal("coredll.dll", 10, None), None);
    let arm = Cpu::of_machine(0x01c2);
    assert_eq!(arm, Some(Cpu::Arm));
    assert_eq!(
        known_ordinal("coredll.dll", 10, arm),
        Some("InterlockedIncrement")
    );
    assert_eq!(
        known_ordinal("coredll.dll", 10, Cpu::of_machine(0x014c)),
        Some("Int_HeapAlloc")
    );
    assert_eq!(Cpu::of_machine(0x8664), None);
}
