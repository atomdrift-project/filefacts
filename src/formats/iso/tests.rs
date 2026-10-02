use super::*;

/// One ISO 9660 directory record.
fn dir_record(name: &[u8], lba: u32, size: u32, flags: u8) -> Vec<u8> {
    let len = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    let mut rec = vec![0u8; len];
    rec[0] = len as u8;
    rec[2..6].copy_from_slice(&lba.to_le_bytes());
    rec[6..10].copy_from_slice(&lba.to_be_bytes());
    rec[10..14].copy_from_slice(&size.to_le_bytes());
    rec[14..18].copy_from_slice(&size.to_be_bytes());
    rec[25] = flags;
    rec[32] = name.len() as u8;
    rec[33..33 + name.len()].copy_from_slice(name);
    rec
}

/// A 20-sector image whose root holds one file, `SETUP.EXE`, with
/// `trailing` appended past the declared volume.
fn one_file_image(trailing: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 20 * SECTOR];
    let pvd = &mut image[16 * SECTOR..17 * SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..84].copy_from_slice(&20u32.to_le_bytes());
    pvd[128..130].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    pvd[156..190].copy_from_slice(&dir_record(&[0], 18, SECTOR as u32, 2));
    pvd[881] = 1;
    let terminator = &mut image[17 * SECTOR..18 * SECTOR];
    terminator[0] = 255;
    terminator[1..6].copy_from_slice(b"CD001");
    let mut root = dir_record(&[0], 18, SECTOR as u32, 2);
    root.extend(dir_record(&[1], 18, SECTOR as u32, 2));
    root.extend(dir_record(b"SETUP.EXE;1", 19, 5, 0));
    image[18 * SECTOR..18 * SECTOR + root.len()].copy_from_slice(&root);
    image[19 * SECTOR..19 * SECTOR + 5].copy_from_slice(b"MZ...");
    image.extend_from_slice(trailing);
    image
}

/// The tree's files feed the shared `archive.*` aggregates; a carved
/// region is listed as a member but its synthetic name says nothing.
#[test]
fn archive_aggregates_cover_files_not_carved_regions() {
    let image = one_file_image(&[0x41; 4096]);
    let (mut values, mut metrics, mut members) = (Values::new(), Metrics::new(), Vec::new());
    extract(&image, &mut values, &mut metrics, &mut members).unwrap();

    let listed = values
        .get("archive.members")
        .and_then(JsonValue::as_array)
        .unwrap();
    let kinds: Vec<_> = listed.iter().map(|m| m["entry_type"].as_str()).collect();
    assert_eq!(kinds, [Some("regular"), Some("trailing")]);
    assert_eq!(listed[0]["path"], "SETUP.EXE");
    assert_eq!(listed[0]["data_offset"], 19 * SECTOR as u64);
    assert_eq!(listed.len(), members.len());

    assert_eq!(metrics.get("archive.member_count"), Some(2.0));
    assert_eq!(metrics.get("archive.file_count"), Some(1.0));
    assert_eq!(metrics.get("archive.uncompressed_size"), Some(5.0));
    // `.iso-unclaimed/trailing.bin` is neither hidden nor an executable.
    assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
    assert_eq!(metrics.get("archive.misplaced_executable_count"), Some(1.0));
    assert_eq!(metrics.get("archive.hidden_file_count"), Some(0.0));
    assert_eq!(metrics.get("archive.format.trailing_count"), Some(1.0));
}

/// Build a system area (16 * 2048 bytes) carrying an MBR whose single
/// entry starts at `start_lba` and spans `sectors` 512-byte LBAs.
fn system_area_with_partition(start_lba: u32, sectors: u32) -> Vec<u8> {
    let mut area = vec![0u8; SYSTEM_AREA_SECTORS * SECTOR];
    let e = 446;
    area[e + 4] = 0xEE; // GPT protective
    area[e + 8..e + 12].copy_from_slice(&start_lba.to_le_bytes());
    area[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
    area[510] = 0x55;
    area[511] = 0xAA;
    area
}

#[test]
fn hybrid_partition_claims_bytes_past_the_iso_volume() {
    // Redox's desktop livedisk: ISO 9660 declares 21 sectors (43,008
    // bytes) while the file is 604 MB, with one 0xEE entry covering the
    // whole image. Those bytes are claimed by the partition table, so
    // none of them is "unclaimed" — without this the entire operating
    // system is reported as one `trailing` member and every data-file
    // rule runs over it as an opaque blob.
    let total = 4 * 1024 * 1024usize;
    let mut bytes = system_area_with_partition(1, (total / 512) as u32 - 1);
    bytes.resize(total, 0xAB);
    let ranges = partition_claimed_ranges(&bytes);
    assert_eq!(
        ranges,
        vec![(512, total as u64)],
        "partition must claim to EOF"
    );
}

#[test]
fn payload_appended_past_the_last_partition_is_still_trailing() {
    // The exemption must not become a blanket one: bytes beyond where the
    // partition table stops are still unaccounted for.
    let part_end = 1024 * 1024usize;
    let total = part_end + 64 * 1024;
    let mut bytes = system_area_with_partition(1, (part_end / 512) as u32 - 1);
    bytes.resize(total, 0xCD);
    let ranges = partition_claimed_ranges(&bytes);
    let claimed_end = ranges.iter().map(|(_, e)| *e).max().unwrap_or(0);
    assert_eq!(claimed_end, part_end as u64);
    assert!(
        (total as u64) > claimed_end,
        "bytes past the partition remain unaccounted and are reported as trailing"
    );
}

#[test]
fn plain_image_without_a_boot_signature_claims_nothing() {
    let bytes = vec![0u8; SYSTEM_AREA_SECTORS * SECTOR + 4096];
    assert!(partition_claimed_ranges(&bytes).is_empty());
}

fn entry(namespace: Namespace, path: &str, lba: u32, size: u32, flags: u8) -> Entry {
    Entry {
        namespace,
        path: path.to_string(),
        alt_name: None,
        lba,
        size,
        flags,
        recorded: None,
        depth: 1,
        contiguous: true,
        ext_attr_sectors: 0,
        mode: None,
        uid: None,
        gid: None,
        symlink: None,
    }
}

#[test]
fn subdirectory_in_both_namespaces_is_not_tree_only() {
    // Each namespace writes its own directory records, so `/READ` and
    // `/Read` sit at different extents even though they are the same
    // directory. Only a file's extent is shared across trees.
    let entries = vec![
        entry(Namespace::Iso9660, "/READ", 20, 2048, 0x02),
        entry(Namespace::Iso9660, "/READ/READ.TXT", 33, 19, 0),
        entry(Namespace::Joliet, "/Read", 24, 2048, 0x02),
        entry(Namespace::Joliet, "/Read/read.txt", 33, 19, 0),
    ];
    let mut anomalies = Vec::new();
    let files = merge_namespaces(entries, &mut anomalies);
    assert!(
        !anomalies.contains(&"tree-only-file"),
        "directories must not count: {anomalies:?}"
    );
    assert_eq!(files.iter().filter(|f| !f.is_dir).count(), 1);
}

#[test]
fn file_in_one_namespace_is_still_tree_only() {
    let entries = vec![
        entry(Namespace::Iso9660, "/README.TXT", 33, 19, 0),
        entry(Namespace::Joliet, "/ReadMe.txt", 33, 19, 0),
        entry(Namespace::Joliet, "/invoice.exe", 34, 4096, 0),
    ];
    let mut anomalies = Vec::new();
    merge_namespaces(entries, &mut anomalies);
    assert!(anomalies.contains(&"tree-only-file"));
}

#[test]
fn joliet_levels_recognised() {
    assert_eq!(joliet_level(b"%/@"), Some(1));
    assert_eq!(joliet_level(b"%/C"), Some(2));
    assert_eq!(joliet_level(b"%/E"), Some(3));
    assert_eq!(joliet_level(b""), None);
    assert_eq!(joliet_level(b"%/X"), None);
}

#[test]
fn version_suffix_stripped_from_names() {
    assert_eq!(decode_name(b"SETUP.EXE;1", false), "SETUP.EXE");
    assert_eq!(decode_name(b"README.;1", false), "README");
    // A semicolon that isn't a version marker stays put.
    assert_eq!(decode_name(b"a;b", false), "a;b");
}

#[test]
fn joliet_names_decode_from_ucs2be() {
    let name: Vec<u8> = "hi.exe".encode_utf16().flat_map(u16::to_be_bytes).collect();
    assert_eq!(decode_name(&name, true), "hi.exe");
}

#[test]
fn dec_datetime_sentinel_is_not_a_date() {
    assert!(IsoTime::parse_dec(Some(b"0000000000000000\x00")).is_none());
    let t = IsoTime::parse_dec(Some(b"2026032317321065\x08")).unwrap();
    // 2026-03-23 17:32:10 at +02:00 == 15:32:10 UTC.
    assert_eq!(t.gmt_offset_minutes, 120);
    assert_eq!(t.unix, 1_774_279_930);
}

#[test]
fn binary_datetime_rebases_from_1900() {
    let t = IsoTime::parse_bin(Some(&[126, 3, 23, 17, 30, 20, 8])).unwrap();
    assert_eq!(t.gmt_offset_minutes, 120);
    assert_eq!(t.unix, 1_774_279_820);
}

#[test]
fn builder_matched_before_the_banner_it_embeds() {
    let mut pvd = empty_pvd();
    // genisoimage carries the mkisofs banner for compatibility.
    pvd.application_id =
        b"GENISOIMAGE ISO 9660/HFS FILESYSTEM CREATOR (C) 1993 E.YOUNGDALE".to_vec();
    assert_eq!(
        detect_builder(&pvd),
        Some(("genisoimage", "application_id"))
    );
    pvd.application_id = b"MKISOFS ISO 9660/HFS FILESYSTEM BUILDER".to_vec();
    assert_eq!(detect_builder(&pvd), Some(("mkisofs", "application_id")));
    pvd.application_id = Vec::new();
    assert_eq!(detect_builder(&pvd), None);
}

#[test]
fn mangled_short_name_is_not_divergence() {
    let same = [
        ("iso9660", "INSTALL0".to_string()),
        ("joliet", "Installer_v1836_x64.exe".to_string()),
    ];
    assert!(!divergent_names(&same));
    let different = [
        ("iso9660", "README".to_string()),
        ("joliet", "invoice.exe".to_string()),
    ];
    assert!(divergent_names(&different));
}

/// A directory record pointing back at its own extent makes the tree
/// cyclic. The walk visits each extent once and terminates.
#[test]
fn cyclic_directory_is_walked_once() {
    let root_lba = 1_u32;
    let mut rec = vec![0u8; 34];
    rec[0] = 34; // record length
    rec[2..6].copy_from_slice(&root_lba.to_le_bytes());
    rec[10..14].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    rec[25] = 0x02; // directory
    rec[32] = 1; // name length
    rec[33] = b'D';
    let mut bytes = vec![0u8; 2 * SECTOR];
    bytes[SECTOR..SECTOR + rec.len()].copy_from_slice(&rec);

    let mut walk = Walk::new();
    walk.run(&bytes, root_lba, SECTOR as u32, Namespace::Iso9660);
    assert_eq!(walk.dirs_walked, 1);
    assert_eq!(walk.visited.len(), 1);
    let paths: Vec<&str> = walk.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["/D"]);
    assert!(!walk.truncated);
}

#[test]
fn symlink_components_reassemble() {
    // flags=0, len=3, "etc"; flags=0, len=6, "passwd"
    let mut out = String::new();
    decode_symlink(b"\x00\x00\x03etc\x00\x06passwd", &mut out);
    assert_eq!(out, "etc/passwd");
    let mut root = String::new();
    decode_symlink(b"\x00\x08\x00\x00\x03etc", &mut root);
    assert_eq!(root, "/etc");
}

fn susp_record(signature: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(4 + payload.len());
    record.extend_from_slice(&signature);
    record.push((4 + payload.len()) as u8);
    record.push(1); // SUSP entry version
    record.extend_from_slice(payload);
    record
}

fn both32(value: u32) -> Vec<u8> {
    let mut encoded = value.to_le_bytes().to_vec();
    encoded.extend_from_slice(&value.to_be_bytes());
    encoded
}

fn test_entry() -> Entry {
    Entry {
        namespace: Namespace::Iso9660,
        path: "/LIBSYS.SO;1".into(),
        alt_name: None,
        lba: 0,
        size: 0,
        flags: 0,
        recorded: None,
        depth: 0,
        contiguous: true,
        ext_attr_sectors: 0,
        mode: None,
        uid: None,
        gid: None,
        symlink: None,
    }
}

#[test]
fn susp_payload_starts_after_four_byte_header() {
    let mut system_use = susp_record(*b"NM", b"\0libsys.so.7");

    let mut px = both32(0o100755);
    px.extend(both32(1)); // link count
    px.extend(both32(1000)); // uid
    px.extend(both32(100)); // gid
    system_use.extend(susp_record(*b"PX", &px));

    // SL entry flags, followed by the `usr` and `lib` components.
    system_use.extend(susp_record(*b"SL", b"\0\0\x03usr\0\x03lib"));

    let mut walk = Walk::new();
    let mut entry = test_entry();
    walk.parse_susp(&[], &system_use, &mut entry, "/lib", 0);

    assert_eq!(entry.path, "/lib/libsys.so.7");
    assert_eq!(entry.alt_name.as_deref(), Some("libsys.so.7"));
    assert_eq!(entry.mode, Some(0o100755));
    assert_eq!(entry.uid, Some(1000));
    assert_eq!(entry.gid, Some(100));
    assert_eq!(entry.symlink.as_deref(), Some("usr/lib"));
}

#[test]
fn susp_ce_continuation_uses_unshifted_payload() {
    let continuation = susp_record(*b"NM", b"\0continued-name");
    let mut image = vec![0_u8; SECTOR + continuation.len()];
    image[SECTOR..].copy_from_slice(&continuation);

    let mut ce = both32(1); // continuation block
    ce.extend(both32(0)); // offset within block
    ce.extend(both32(continuation.len() as u32));

    let mut walk = Walk::new();
    let mut entry = test_entry();
    walk.parse_susp(&image, &susp_record(*b"CE", &ce), &mut entry, "", 0);

    assert_eq!(entry.path, "/continued-name");
}

fn empty_pvd() -> Pvd {
    Pvd {
        system_id: Vec::new(),
        volume_id: Vec::new(),
        volume_set_id: Vec::new(),
        publisher_id: Vec::new(),
        preparer_id: Vec::new(),
        application_id: Vec::new(),
        copyright_file: Vec::new(),
        abstract_file: Vec::new(),
        bibliographic_file: Vec::new(),
        escape: Vec::new(),
        volume_space_sectors: 0,
        volume_set_size: 0,
        volume_sequence_number: 0,
        logical_block_size: 2048,
        path_table_size: 0,
        path_table_lba: [0, 0],
        file_structure_version: 1,
        root_lba: 0,
        root_len: 0,
        created: None,
        modified: None,
        expires: None,
        effective: None,
        application_use_nonzero: 0,
    }
}
