use super::*;

/// Build one DWORD-aligned VS_VERSIONINFO block (`wType=1`, text) with a key,
/// an optional value, and pre-built child bytes — mirroring the real layout
/// so the walker is exercised against genuine alignment/length rules.
fn version_block(key: &str, value: Option<&str>, children: &[u8]) -> Vec<u8> {
    let utf16z = |s: &str| -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let value_units = value.map_or(0, |v| v.encode_utf16().count() + 1);
    let mut b = Vec::new();
    b.extend_from_slice(&0u16.to_le_bytes()); // wLength (patched below)
    b.extend_from_slice(&(value_units as u16).to_le_bytes()); // wValueLength (WCHARs)
    b.extend_from_slice(&1u16.to_le_bytes()); // wType = text
    b.extend_from_slice(&utf16z(key));
    while b.len() % 4 != 0 {
        b.push(0);
    }
    if let Some(v) = value {
        b.extend_from_slice(&utf16z(v));
    }
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b.extend_from_slice(children);
    let len = b.len() as u16;
    b[0..2].copy_from_slice(&len.to_le_bytes());
    b
}

fn partial_version_pe() -> Vec<u8> {
    let string = version_block("ProductName", Some("Disk Manager Tool"), &[]);
    let table = version_block("040904b0", None, &string);
    let root = version_block(
        "VS_VERSION_INFO",
        None,
        &version_block("StringFileInfo", None, &table),
    );
    let mut pe = vec![0; 0x1000];
    pe[..2].copy_from_slice(b"MZ");
    let w = |b: &mut [u8], o, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let d = |b: &mut [u8], o, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    d(&mut pe, 0x3c, 0x80);
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    w(&mut pe, 0x86, 1);
    w(&mut pe, 0x94, 0xe0);
    w(&mut pe, 0x98, 0x10b);
    d(&mut pe, 0x98 + 92, 16);
    d(&mut pe, 0x98 + 112, 0x1000);
    d(&mut pe, 0x98 + 116, 22 * 1024 * 1024);
    d(&mut pe, 0x178 + 12, 0x1000);
    d(&mut pe, 0x178 + 16, 0xc00);
    d(&mut pe, 0x178 + 20, 0x400);
    for (dir, id, target) in [
        (0usize, 16u32, 0x80000020u32),
        (0x20, 1, 0x80000040),
        (0x40, 1033, 0x60),
    ] {
        w(&mut pe, 0x400 + dir + 14, 1);
        d(&mut pe, 0x400 + dir + 16, id);
        d(&mut pe, 0x400 + dir + 20, target);
    }
    d(&mut pe, 0x460, 0x1100);
    d(&mut pe, 0x464, root.len() as u32);
    pe[0x500..0x500 + root.len()].copy_from_slice(&root);
    pe
}
/// The one section [`partial_version_pe`] lays out: RVA 0x1000, file offset
/// 0x400. Unnamed, so recovery can only reach it through the directory.
fn partial_section() -> SectionTable {
    SectionTable {
        virtual_address: 0x1000,
        virtual_size: 0xc00,
        size_of_raw_data: 0xc00,
        pointer_to_raw_data: 0x400,
        ..SectionTable::default()
    }
}

/// The resource directory `pe`'s header slot declares.
fn declared_resources(pe: &[u8]) -> DataDirectory {
    let word = |at: usize| {
        pe.get(at..at + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    DataDirectory {
        virtual_address: word(0x98 + 112),
        size: word(0x98 + 116),
    }
}

/// Run [`extract`] over `pe` as [`partial_version_pe`] lays it out.
fn read(pe: &[u8]) -> Values {
    read_with(pe, &[partial_section()], Some(declared_resources(pe)))
}

fn read_with(pe: &[u8], sections: &[SectionTable], resources: Option<DataDirectory>) -> Values {
    let mut values = Values::new();
    extract(
        sections,
        Some(0x200),
        resources,
        pe,
        &mut values,
        &mut Metrics::new(),
    );
    values
}

fn product_name(values: &Values) -> Option<&str> {
    values
        .get("pe.version.product_name")
        .and_then(JsonValue::as_str)
}

#[test]
fn resource_recovery_is_bounded_and_structural() {
    let pe = partial_version_pe();
    assert_eq!(product_name(&read(&pe)), Some("Disk Manager Tool"));
    assert!(
        read(&pe)
            .get("pe.version.product_name_offset")
            .and_then(JsonValue::as_u64)
            .unwrap()
            >= 0x500
    );
    // A forged directory never leads the walk anywhere: no leaves.
    let leaves = |pe: &[u8]| {
        version_leaves(
            &[partial_section()],
            Some(0x200),
            declared_resources(pe),
            pe,
        )
    };
    assert_eq!(leaves(&pe).len(), 1);
    for (off, data) in [
        (0x410, 10u32),
        (0x414, 0x80000000),
        (0x460, 0xfffffff0),
        (0x464, 0x10001),
    ] {
        let mut invalid = pe.clone();
        invalid[off..off + 4].copy_from_slice(&data.to_le_bytes());
        assert!(leaves(&invalid).is_empty(), "offset {off:x}");
    }
    for length in [0, 64, 256, 1024, 1280] {
        assert!(product_name(&read(&pe[..length])).is_none());
    }
}

/// Hand-crafted resources: the directory entry, the directory itself, or a
/// `String` header is damaged while the strings stay readable. The value is
/// recovered from the resource region, at the offset of its text.
#[test]
fn version_strings_recovered_past_damaged_structure() {
    let pe = partial_version_pe();
    let expected = read(&pe)
        .get("pe.version.product_name_offset")
        .and_then(JsonValue::as_u64);

    // Directory leaf points nowhere; the directory range still maps.
    let mut broken_directory = pe.clone();
    broken_directory[0x460..0x464].copy_from_slice(&0xfffffff0u32.to_le_bytes());
    let values = read(&broken_directory);
    assert_eq!(product_name(&values), Some("Disk Manager Tool"));
    assert_eq!(
        values
            .get("pe.version.product_name_offset")
            .and_then(JsonValue::as_u64),
        expected
    );

    // No resource directory at all: the `.rsrc` section is searched.
    let mut rsrc = partial_section();
    rsrc.name = *b".rsrc\0\0\0";
    assert_eq!(
        product_name(&read_with(&pe, &[rsrc], None)),
        Some("Disk Manager Tool")
    );
    // Nothing names the resources: nothing to search.
    assert!(product_name(&read_with(&pe, &[partial_section()], None)).is_none());

    // `wValueLength` overruns the block, so the walker skips the string.
    let mut damaged = pe.clone();
    let key: Vec<u8> = "ProductName"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let at = memchr::memmem::find(&damaged, &key).unwrap();
    damaged[at - 4..at - 2].copy_from_slice(&65535u16.to_le_bytes());
    assert_eq!(product_name(&read(&damaged)), Some("Disk Manager Tool"));
}

/// The value is aligned from the start of its `String` entry: an entry that
/// starts two bytes past a DWORD boundary must not lose its first character.
#[test]
fn recovered_value_alignment_is_entry_relative() {
    let mut info = VersionInfo::default();
    // Key + NUL is 24 bytes, so the value sits at entry + 6 + 24 = entry + 30,
    // aligned up to entry + 32 regardless of where the entry starts.
    let mut blob = vec![0u8; 2];
    blob.extend(
        "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    let entry = blob.len();
    blob.extend_from_slice(&[0xff; 6]); // damaged wLength/wValueLength/wType
    blob.extend(
        "OriginalFilename\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    while !(blob.len() - entry).is_multiple_of(4) {
        blob.push(0);
    }
    blob.extend(
        "WinRT.Runtime.dll\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    assert_eq!(entry % 4, 2);
    assert!(recover_from_region(
        &blob,
        (0, blob.len()),
        false,
        &mut info
    ));
    assert_eq!(info.string("OriginalFilename"), Some("WinRT.Runtime.dll"));
}

/// Every `StringFileInfo` key reaches `pe.version.*` with its offset, the
/// same through either parse: one table, one walk.
#[test]
fn every_string_key_is_read() {
    let strings: Vec<u8> = STRING_FIELDS
        .iter()
        .flat_map(|(key, ..)| version_block(key, Some(key), &[]))
        .collect();
    let table = version_block("040904b0", None, &strings);
    let root = version_block(
        "VS_VERSION_INFO",
        None,
        &version_block("StringFileInfo", None, &table),
    );
    let values = walked(&root);
    for (key, value_key, offset_key) in STRING_FIELDS {
        assert_eq!(values.lookup(value_key), Some(&JsonValue::from(key)));
        assert!(values.lookup(offset_key).is_some(), "{key}");
    }
}

/// The values and offsets one walk of `blob`, rooted at offset 0, reads.
fn walked(blob: &[u8]) -> Values {
    let mut info = VersionInfo::default();
    let mut budget = MAX_VERSION_NODES;
    walk_version_block(blob, 0, blob.len(), 0, &mut budget, &mut info);
    let mut values = Values::new();
    info.emit(&mut values, &mut Metrics::new());
    values
}

#[test]
fn version_value_offsets_anchor_at_the_string() {
    let string = version_block("CompanyName", Some("ACME Corp"), &[]);
    let table = version_block("040904b0", None, &string);
    let sfi = version_block("StringFileInfo", None, &table);
    let root = version_block("VS_VERSION_INFO", None, &sfi);

    let values = walked(&root);

    // The companion offset must point exactly at the UTF-16LE value bytes.
    let want: Vec<u8> = "ACME Corp"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let expect = root
        .windows(want.len())
        .position(|w| w == want.as_slice())
        .map(|p| p as u64);
    assert!(expect.is_some(), "fixture must contain the value");
    assert_eq!(
        values
            .get("pe.version.company_offset")
            .and_then(JsonValue::as_u64),
        expect,
    );
    // Unknown keys (StringFileInfo/StringTable/langID) emit no companion.
    assert!(values.get("pe.version.040904b0_offset").is_none());
}

#[test]
fn version_walker_tolerates_garbage() {
    // Truncated and zero-length blocks must not panic or loop.
    walked(&[]);
    walked(&[0u8; 8]);
    let mut sig: Vec<u8> = "VS_VERSION_INFO"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    sig.truncate(10); // cut mid-key
    walked(&sig);
}

/// Blocks the walker visits for `blob`, rooted at offset 0.
fn blocks_visited(blob: &[u8]) -> usize {
    let mut budget = MAX_VERSION_NODES;
    walk_version_block(
        blob,
        0,
        blob.len(),
        0,
        &mut budget,
        &mut VersionInfo::default(),
    );
    MAX_VERSION_NODES - budget
}

/// An empty-keyed, value-less block header claiming `w_length` bytes.
fn bare_header(w_length: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0..2].copy_from_slice(&w_length.to_le_bytes());
    h[4..6].copy_from_slice(&1u16.to_le_bytes()); // wType = text
    h
}

#[test]
fn version_walker_clamps_children_to_their_parent() {
    // Each unit is a 16-byte block A whose only child B claims 0xFFFF
    // bytes, so B's "children" are every later unit. Unclamped, each A is
    // re-walked under every earlier B -- work combinatorial in the unit
    // count. Clamped to A, each B is a leaf: one root plus two per unit.
    const UNITS: usize = 100;
    let mut units = Vec::new();
    for _ in 0..UNITS {
        units.extend_from_slice(&bare_header(16));
        units.extend_from_slice(&bare_header(0xFFFF));
    }
    let root = version_block("VS_VERSION_INFO", None, &units);
    assert_eq!(blocks_visited(&root), 1 + 2 * UNITS);
}

#[test]
fn version_walker_stops_at_the_node_budget() {
    // Well-nested but implausibly dense: the root's 64 KiB holds ~8k
    // empty children, past the per-walk budget.
    let children: Vec<u8> = (0..8000).flat_map(|_| bare_header(8)).collect();
    let root = version_block("VS_VERSION_INFO", None, &children);
    assert_eq!(blocks_visited(&root), MAX_VERSION_NODES);
}

#[test]
fn os_label_known() {
    assert_eq!(file_os_label(0x0004_0004), "windows_nt_windows32");
    assert_eq!(file_os_label(0xdead_beef), "unknown");
}

#[test]
fn type_label_known() {
    assert_eq!(file_type_label(1), "app");
    assert_eq!(file_type_label(2), "dll");
    assert_eq!(file_type_label(99), "unknown");
}

#[test]
fn flags_decompose() {
    let f = file_flags(0x01 | 0x04 | 0x20);
    assert!(f.contains(&"debug".to_string()));
    assert!(f.contains(&"patched".to_string()));
    assert!(f.contains(&"special_build".to_string()));
    assert_eq!(f.len(), 3);
}

#[test]
fn flags_empty_when_zero() {
    assert!(file_flags(0).is_empty());
}

#[test]
fn flags_decompose_full_set() {
    let f = file_flags(0x3F);
    assert_eq!(
        f,
        vec![
            "debug",
            "pre_release",
            "patched",
            "private_build",
            "info_inferred",
            "special_build"
        ]
    );
}

#[test]
fn os_label_covers_canonical_values() {
    // From wintrust.h. The composite encodings pair an OS family
    // (high word) with a host environment (low word).
    assert_eq!(file_os_label(0x0001_0000), "dos");
    assert_eq!(file_os_label(0x0002_0000), "os216");
    assert_eq!(file_os_label(0x0003_0000), "os232");
    assert_eq!(file_os_label(0x0004_0000), "windows_nt");
    assert_eq!(file_os_label(0x0001_0001), "dos_windows16");
    assert_eq!(file_os_label(0x0001_0004), "dos_windows32");
    assert_eq!(file_os_label(0x0004_0004), "windows_nt_windows32");
    assert_eq!(file_os_label(0xdead_beef), "unknown");
}

#[test]
fn type_label_covers_drv_and_font() {
    assert_eq!(file_type_label(3), "drv");
    assert_eq!(file_type_label(4), "font");
    assert_eq!(file_type_label(5), "vxd");
    assert_eq!(file_type_label(7), "static_lib");
}

#[test]
fn type_label_unknown_falls_back() {
    assert_eq!(file_type_label(0), "unknown");
    assert_eq!(file_type_label(8), "unknown");
    assert_eq!(file_type_label(u32::MAX), "unknown");
}

#[test]
fn identity_scores_below_length_guard() {
    assert!(identity_scores("short").is_none());
    assert!(identity_scores("Acme Corp Tools").is_none()); // 15 chars
}

#[test]
fn identity_scores_clean_name_low_symbol_ratio() {
    // Legitimate identity: letters + spaces, symbol ratio ~0.
    let (ratio, entropy) =
        identity_scores("Microsoft CorporationWindows Operating System").unwrap();
    assert!(ratio < 0.05, "clean name symbol ratio {ratio}");
    assert!(entropy > 3.0);
}

#[test]
fn identity_scores_scrambled_high_symbol_ratio() {
    // Crypter-scrambled VERSIONINFO: symbol/digit dense, fires the metric.
    let (ratio, entropy) = identity_scores("5:EB6>G8HB<57C5II=J47I>5FF@F6664<<CCI;I8:").unwrap();
    assert!(ratio >= 0.4, "scrambled symbol ratio {ratio}");
    assert!(entropy >= 3.5, "scrambled entropy {entropy}");
}

#[test]
fn identity_scores_repeated_padding_excluded_by_entropy() {
    // Degenerate numeric padding: high symbol ratio but near-zero entropy,
    // so the ANDed composite (which also needs the entropy floor) rejects it.
    let (ratio, entropy) = identity_scores("00000000000000000000").unwrap();
    assert!(ratio >= 0.4);
    assert!(entropy < 1.0, "padding entropy {entropy}");
}

/// Every InternalName/OriginalFilename pair observed across the PE corpus
/// in `supplychain-attack-data`. The first four are the benign shapes a
/// strict inequality would have flagged; the last is the generated one.
#[test]
fn module_names_fold_to_related_forms() {
    for (internal, original) in [
        ("d3dcompiler_47.dll", "d3dcompiler_47.dll"),
        ("DTWpfInstaller.exe", "DTWpfInstaller.exe"),
        ("WebBrowserPassView", "WebBrowserPassView.exe"),
        ("ClassicShellSetup", "ClassicShellSetup.exe"),
    ] {
        let a = fold_module_name(internal).unwrap();
        let b = fold_module_name(original).unwrap();
        assert!(
            a.contains(&b) || b.contains(&a),
            "{internal} / {original} folded to {a} / {b}"
        );
    }
}

#[test]
fn generated_module_names_stay_unrelated() {
    let a = fold_module_name("Didride Cutuse").unwrap();
    let b = fold_module_name("Thin.dll").unwrap();
    assert!(!a.contains(&b) && !b.contains(&a), "{a} / {b}");
}

#[test]
fn fold_module_name_normalises_separators_and_case() {
    assert_eq!(fold_module_name("Foo-Bar_Baz.DLL").unwrap(), "foobarbaz");
    // A dotted version is not an extension: keep the digits.
    assert_eq!(fold_module_name("libssl.1.1").unwrap(), "libssl11");
}

#[test]
fn fold_module_name_rejects_too_short_to_compare() {
    assert!(fold_module_name("a.dll").is_none());
    assert!(fold_module_name("  ").is_none());
}

/// The root block's `VS_FIXEDFILEINFO` is read by the same walk as the
/// strings.
#[test]
fn fixed_file_info_is_read_from_the_root() {
    let mut fixed = [0u8; FIXED_FILE_INFO_LEN];
    for (at, value) in [
        (0, FIXED_FILE_INFO_SIGNATURE),
        (24, 0x3f),
        (28, 0x02),
        (32, 0x0004_0004),
        (36, 3),
        (40, 6),
    ] {
        fixed[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut root = version_block("VS_VERSION_INFO", None, &[]);
    // A binary value (`wType` 0) of the structure's size, after the key.
    root[2..4].copy_from_slice(&(FIXED_FILE_INFO_LEN as u16).to_le_bytes());
    root[4..6].copy_from_slice(&0u16.to_le_bytes());
    root.extend_from_slice(&fixed);
    let len = root.len() as u16;
    root[0..2].copy_from_slice(&len.to_le_bytes());
    let values = walked(&root);
    assert_eq!(
        values.get("pe.version.os").and_then(JsonValue::as_str),
        Some("windows_nt_windows32")
    );
    assert_eq!(
        values.get("pe.version.type").and_then(JsonValue::as_str),
        Some("drv")
    );
    assert_eq!(
        values.get("pe.version.subtype").and_then(JsonValue::as_str),
        Some("network")
    );
    assert_eq!(
        values.get("pe.version.flags"),
        Some(&serde_json::json!(["pre_release"]))
    );
    // Without its signature the structure is not read.
    let signature = root.len() - FIXED_FILE_INFO_LEN;
    root[signature] ^= 0xff;
    assert!(walked(&root).get("pe.version.os").is_none());
}

/// A `String` with an intact header and no value (`wValueLength` 0) is
/// empty: recovery must not read the next entry's header and key as its
/// text (EldoS RawDisk's `Comments` came out as "D\u{12}\u{1}CompanyName").
#[test]
fn empty_string_is_not_recovered_from_next_entry() {
    let strings = [
        version_block("Comments", None, &[]),
        version_block("CompanyName", Some("EldoS Corporation"), &[]),
    ]
    .concat();
    let table = version_block("040904b0", None, &strings);
    let root = version_block(
        "VS_VERSION_INFO",
        None,
        &version_block("StringFileInfo", None, &table),
    );
    let mut info = VersionInfo::default();
    assert!(recover_from_region(&root, (0, root.len()), true, &mut info));
    assert_eq!(info.string("CompanyName"), Some("EldoS Corporation"));
    assert_eq!(info.string("Comments"), None);
}
