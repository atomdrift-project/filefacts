use super::*;

#[test]
fn dstring_decodes_both_charsets() {
    // Latin-1: marker 8, "AB", used length 3.
    let mut latin = vec![0_u8; 8];
    latin[0] = 8;
    latin[1] = b'A';
    latin[2] = b'B';
    latin[7] = 3;
    assert_eq!(dstring(Some(&latin)).as_deref(), Some("AB"));

    // UCS-2BE: marker 16, "AB", used length 5.
    let mut ucs = vec![0_u8; 8];
    ucs[0] = 16;
    ucs[1..5].copy_from_slice(&[0, b'A', 0, b'B']);
    ucs[7] = 5;
    assert_eq!(dstring(Some(&ucs)).as_deref(), Some("AB"));
}

#[test]
fn revision_reads_as_bcd() {
    let mut ent = vec![0_u8; 32];
    ent[24] = 0x60;
    ent[25] = 0x02;
    assert_eq!(domain_revision(Some(&ent)).as_deref(), Some("2.60"));
    assert_eq!(domain_revision(Some(&[0_u8; 32])), None);
}

#[test]
fn permissions_fold_to_posix() {
    // owner rwx, group r-x, other r--
    let perms = (0b00111 << 10) | (0b00101 << 5) | 0b00100;
    assert_eq!(udf_permissions_to_mode(perms), 0o754);
}

#[test]
fn file_identifiers_reject_a_non_fid_run() {
    assert!(parse_fids(&[0_u8; 64]).is_empty());
}

/// Write a directory File Entry at `block` whose contents are the
/// `len`-byte extent at `data_block`.
fn directory_entry(bytes: &mut [u8], block: usize, data_block: u32, len: u32) {
    let fe = &mut bytes[block * SECTOR..(block + 1) * SECTOR];
    fe[0..2].copy_from_slice(&tag::FILE_ENTRY.to_le_bytes());
    fe[27] = 4; // directory
    fe[56..64].copy_from_slice(&u64::from(len).to_le_bytes());
    fe[172..176].copy_from_slice(&8_u32.to_le_bytes()); // one short_ad
    fe[176..180].copy_from_slice(&len.to_le_bytes());
    fe[180..184].copy_from_slice(&data_block.to_le_bytes());
}

/// Every directory lists every other: `k` directories of `k`
/// subdirectory identifiers each. Dedup at pop queued all `k * k` of
/// them (with 65,536 identifiers per directory and 8,192 directories,
/// hundreds of millions); dedup at queue time queues each once.
#[test]
fn directories_naming_each_other_are_queued_once() {
    let k = 400_usize;
    let record_len = 40_usize; // 38 + a 2-byte name, padded to 4
    let data_block = k + 1;
    let data_len = k * record_len;
    let mut bytes = vec![0_u8; (data_block + data_len.div_ceil(SECTOR) + 1) * SECTOR];
    for block in 0..=k {
        directory_entry(&mut bytes, block, data_block as u32, data_len as u32);
    }
    for i in 0..k {
        let at = data_block * SECTOR + i * record_len;
        let fid = &mut bytes[at..at + record_len];
        fid[0..2].copy_from_slice(&tag::FILE_IDENTIFIER.to_le_bytes());
        fid[18] = 0x02; // directory
        fid[19] = 2;
        fid[24..28].copy_from_slice(&((i + 1) as u32).to_le_bytes());
        fid[38] = 8;
        fid[39] = b'd';
    }
    let vol = Volume {
        bytes: &bytes,
        partition_start: 0,
        block_size: SECTOR as u32,
    };
    let mut walk = TreeWalk::new(&vol);
    walk.run(0);
    assert_eq!(walk.dirs_queued, k);
    assert_eq!(walk.dir_count, k as u64 + 1);
    assert!(!walk.truncated);
    // Only the root's `k` one-byte names became paths: identifiers
    // naming an already-visited directory build none.
    assert_eq!(MAX_PATH_BYTES - walk.path_budget, k);
}

/// The same directories, walked under spent budgets: the directory-byte
/// budget stops the walk before every ICB re-parses the shared extent,
/// and the path budget stops it before its paths outgrow the cap.
#[test]
fn walk_stops_at_dir_and_path_budgets() {
    let k = 64_usize;
    let record_len = 40_usize;
    let data_block = k + 1;
    let data_len = k * record_len;
    let mut bytes = vec![0_u8; (data_block + data_len.div_ceil(SECTOR) + 1) * SECTOR];
    for block in 0..=k {
        directory_entry(&mut bytes, block, data_block as u32, data_len as u32);
    }
    for i in 0..k {
        let at = data_block * SECTOR + i * record_len;
        let fid = &mut bytes[at..at + record_len];
        fid[0..2].copy_from_slice(&tag::FILE_IDENTIFIER.to_le_bytes());
        fid[18] = 0x02;
        fid[19] = 2;
        fid[24..28].copy_from_slice(&((i + 1) as u32).to_le_bytes());
        fid[38] = 8;
        fid[39] = b'd';
    }
    let vol = Volume {
        bytes: &bytes,
        partition_start: 0,
        block_size: SECTOR as u32,
    };

    let mut walk = TreeWalk::new(&vol);
    walk.dir_budget = 3 * data_len;
    walk.run(0);
    assert!(walk.truncated);
    assert_eq!(walk.dir_count, 4);

    let mut walk = TreeWalk::new(&vol);
    walk.path_budget = 10;
    walk.run(0);
    assert!(walk.truncated);
    assert_eq!(walk.dirs_queued, 10);
    assert_eq!(walk.path_budget, 0);
}

#[test]
fn walks_partition_relative_udf_file_extents() {
    // Different lengths and block numbers catch accidentally interchanged
    // allocation-descriptor fields. Exercise both short_ad and long_ad,
    // extended attributes before the AD, and a nonzero partition base.
    for ad_type in [0_u16, 1] {
        let mut bytes = vec![0_u8; 5 * SECTOR];
        let name = b"\x08payload.dll";
        let record_len = (38 + name.len()).div_ceil(4) * 4;
        for (sector, file_type, length, data_block, ea_len) in [
            (1, 4_u8, record_len as u64, 1_u32, 24_usize),
            (3, 5_u8, 4_u64, 3_u32, 0_usize),
        ] {
            let fe = &mut bytes[sector * SECTOR..(sector + 1) * SECTOR];
            fe[0..2].copy_from_slice(&tag::FILE_ENTRY.to_le_bytes());
            fe[27] = file_type;
            fe[34..36].copy_from_slice(&ad_type.to_le_bytes());
            fe[56..64].copy_from_slice(&length.to_le_bytes());
            fe[168..172].copy_from_slice(&(ea_len as u32).to_le_bytes());
            let ad_len = if ad_type == 0 { 8_u32 } else { 16_u32 };
            fe[172..176].copy_from_slice(&ad_len.to_le_bytes());
            let ad = 176 + ea_len;
            fe[ad..ad + 4].copy_from_slice(&(length as u32).to_le_bytes());
            fe[ad + 4..ad + 8].copy_from_slice(&data_block.to_le_bytes());
        }
        let fid = &mut bytes[2 * SECTOR..3 * SECTOR];
        fid[0..2].copy_from_slice(&tag::FILE_IDENTIFIER.to_le_bytes());
        fid[16..18].copy_from_slice(&1_u16.to_le_bytes());
        fid[19] = name.len() as u8;
        fid[20..24].copy_from_slice(&(SECTOR as u32).to_le_bytes());
        fid[24..28].copy_from_slice(&2_u32.to_le_bytes());
        fid[38..38 + name.len()].copy_from_slice(name);
        bytes[4 * SECTOR..4 * SECTOR + 4].copy_from_slice(b"MZ!!");
        let vol = Volume {
            bytes: &bytes,
            partition_start: 1,
            block_size: SECTOR as u32,
        };
        let mut walk = TreeWalk::new(&vol);
        walk.run(0);
        assert_eq!(walk.file_count, 1);
        assert_eq!(walk.members.len(), 1);
        let member = &walk.members[0];
        assert_eq!(member.path, "payload.dll");
        assert_eq!(member.size_bytes, 4);
        assert_eq!(member.offsets.data, Some((4 * SECTOR) as u64));
        assert!(!walk.truncated);
    }
}
