use super::*;

/// Assemble a minimal single-partition UDIF image: `[data fork][xml][koly]`.
/// `fork` is stored as one `raw` chunk; the plist names one `blkx` member.
fn build_dmg(name: &str, fork: &[u8]) -> Vec<u8> {
    let sectors = fork.len().div_ceil(512) as u64;

    // mish: header + one raw chunk + a terminator chunk.
    let mut mish = vec![0u8; 204];
    mish[0..4].copy_from_slice(b"mish");
    mish[4..8].copy_from_slice(&1u32.to_be_bytes()); // version
    mish[8..16].copy_from_slice(&0u64.to_be_bytes()); // base sector
    mish[16..24].copy_from_slice(&sectors.to_be_bytes());
    mish[200..204].copy_from_slice(&2u32.to_be_bytes()); // chunk count
    let push_chunk = |m: &mut Vec<u8>, et: u32, sec: u64, cnt: u64, coff: u64, clen: u64| {
        let mut c = vec![0u8; 40];
        c[0..4].copy_from_slice(&et.to_be_bytes());
        c[8..16].copy_from_slice(&sec.to_be_bytes());
        c[16..24].copy_from_slice(&cnt.to_be_bytes());
        c[24..32].copy_from_slice(&coff.to_be_bytes());
        c[32..40].copy_from_slice(&clen.to_be_bytes());
        m.extend_from_slice(&c);
    };
    push_chunk(&mut mish, 0x0000_0001, 0, sectors, 0, fork.len() as u64);
    push_chunk(&mut mish, 0xffff_ffff, sectors, 0, fork.len() as u64, 0);

    // resource-fork → blkx → [ { Name, Data } ]
    let mut entry = plist::Dictionary::new();
    entry.insert("Name".into(), plist::Value::String(name.into()));
    entry.insert("Data".into(), plist::Value::Data(mish));
    let mut rf = plist::Dictionary::new();
    rf.insert(
        "blkx".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(entry)]),
    );
    let mut root = plist::Dictionary::new();
    root.insert("resource-fork".into(), plist::Value::Dictionary(rf));
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(root)).unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(fork);
    let xml_offset = out.len() as u64;
    out.extend_from_slice(&xml);

    let mut koly = vec![0u8; KOLY_LEN];
    koly[0..4].copy_from_slice(b"koly");
    koly[4..8].copy_from_slice(&4u32.to_be_bytes()); // version
    koly[8..12].copy_from_slice(&512u32.to_be_bytes()); // header size
    koly[24..32].copy_from_slice(&0u64.to_be_bytes()); // data fork offset
    koly[32..40].copy_from_slice(&(fork.len() as u64).to_be_bytes());
    koly[216..224].copy_from_slice(&xml_offset.to_be_bytes());
    koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    koly[488..492].copy_from_slice(&1u32.to_be_bytes()); // image variant
    koly[492..500].copy_from_slice(&sectors.to_be_bytes());
    out.extend_from_slice(&koly);
    out
}

/// A 2048-byte partition carrying an HFS+ volume header at +1024.
fn hfs_fork(file_count: u32, folder_count: u32, create: u32, modify: u32) -> Vec<u8> {
    let mut fork = vec![0u8; 2048];
    let vh = &mut fork[1024..];
    vh[0..2].copy_from_slice(b"H+");
    vh[8..12].copy_from_slice(b"10.0"); // lastMountedVersion
    vh[16..20].copy_from_slice(&create.to_be_bytes());
    vh[20..24].copy_from_slice(&modify.to_be_bytes());
    vh[32..36].copy_from_slice(&file_count.to_be_bytes());
    vh[36..40].copy_from_slice(&folder_count.to_be_bytes());
    vh[40..44].copy_from_slice(&4096u32.to_be_bytes()); // block size
    fork
}

fn run(bytes: &[u8]) -> (Values, Metrics, Vec<ArchiveMember>) {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut members = Vec::new();
    extract(bytes, &mut v, &mut m, &mut members).unwrap();
    (v, m, members)
}

#[test]
fn container_facts_for_raw_hfs_image() {
    let dmg = build_dmg("disk image (Apple_HFS : 4)", &hfs_fork(42, 7, 0, 0));
    let (v, m, members) = run(&dmg);

    assert_eq!(v.get("dmg.format").and_then(|x| x.as_str()), Some("UDIF"));
    assert_eq!(v.get("dmg.udif_version").and_then(|x| x.as_u64()), Some(4));
    // No compressor used → uncompressed format label.
    assert_eq!(
        v.get("dmg.udif_format").and_then(|x| x.as_str()),
        Some("UDRO")
    );
    assert_eq!(
        v.get("dmg.filesystem").and_then(|x| x.as_str()),
        Some("HFS+")
    );
    assert_eq!(m.get("dmg.partition_count"), Some(1.0));
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].entry_type, EntryType::Partition);
}

#[test]
fn hfs_volume_facts_from_raw_chunk() {
    // create 4h ahead of modify → +14400s timezone skew (local vs GMT).
    let create = MAC_EPOCH_OFFSET as u32 + 14_400;
    let modify = MAC_EPOCH_OFFSET as u32;
    let dmg = build_dmg(
        "disk image (Apple_HFS : 4)",
        &hfs_fork(42, 7, create, modify),
    );
    let (v, m, _) = run(&dmg);

    assert_eq!(m.get("dmg.volume.file_count"), Some(42.0));
    assert_eq!(m.get("dmg.volume.folder_count"), Some(7.0));
    assert_eq!(m.get("dmg.volume.block_size"), Some(4096.0));
    assert_eq!(m.get("dmg.volume.timezone_skew_seconds"), Some(14_400.0));
    assert_eq!(
        v.get("dmg.volume.modified_unix").and_then(|x| x.as_i64()),
        Some(0)
    );
    assert_eq!(
        v.get("dmg.volume.last_mounted_version")
            .and_then(|x| x.as_str()),
        Some("10.0")
    );
}

#[test]
fn zlib_chunk_is_decompressed_for_volume_facts() {
    use std::io::Write;
    let fork = hfs_fork(3, 1, 0, 0);
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&fork).unwrap();
    let zlib = enc.finish().unwrap();

    // Build a DMG whose single chunk is zlib instead of raw.
    let sectors = (fork.len() / 512) as u64;
    let mut mish = vec![0u8; 204];
    mish[0..4].copy_from_slice(b"mish");
    mish[16..24].copy_from_slice(&sectors.to_be_bytes());
    mish[200..204].copy_from_slice(&1u32.to_be_bytes());
    let mut c = vec![0u8; 40];
    c[0..4].copy_from_slice(&0x8000_0005u32.to_be_bytes()); // zlib
    c[16..24].copy_from_slice(&sectors.to_be_bytes());
    c[32..40].copy_from_slice(&(zlib.len() as u64).to_be_bytes());
    mish.extend_from_slice(&c);

    let mut entry = plist::Dictionary::new();
    entry.insert(
        "Name".into(),
        plist::Value::String("disk image (Apple_HFS : 4)".into()),
    );
    entry.insert("Data".into(), plist::Value::Data(mish));
    let mut rf = plist::Dictionary::new();
    rf.insert(
        "blkx".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(entry)]),
    );
    let mut root = plist::Dictionary::new();
    root.insert("resource-fork".into(), plist::Value::Dictionary(rf));
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(root)).unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(&zlib);
    let xml_offset = out.len() as u64;
    out.extend_from_slice(&xml);
    let mut koly = vec![0u8; KOLY_LEN];
    koly[0..4].copy_from_slice(b"koly");
    koly[4..8].copy_from_slice(&4u32.to_be_bytes());
    koly[32..40].copy_from_slice(&(zlib.len() as u64).to_be_bytes());
    koly[216..224].copy_from_slice(&xml_offset.to_be_bytes());
    koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    koly[492..500].copy_from_slice(&sectors.to_be_bytes());
    out.extend_from_slice(&koly);

    let (v, m, _) = run(&out);
    assert_eq!(
        v.get("dmg.udif_format").and_then(|x| x.as_str()),
        Some("UDZO")
    );
    assert_eq!(m.get("dmg.volume.file_count"), Some(3.0));
}

/// Partitions are archive members: listed under `archive.members` and
/// summed by the shared aggregates.
#[test]
fn partitions_are_published_as_archive_members() {
    let dmg = build_dmg("disk image (Apple_HFS : 4)", &hfs_fork(1, 1, 0, 0));
    let (v, m, members) = run(&dmg);
    let listed = v.get("archive.members").and_then(|x| x.as_array()).unwrap();
    assert_eq!(listed.len(), members.len());
    assert_eq!(listed[0]["entry_type"], "partition");
    assert_eq!(listed[0]["compression_method"], "raw");
    assert_eq!(listed[0]["host_os"], "macintosh");
    assert_eq!(m.get("archive.member_count"), Some(1.0));
    assert_eq!(m.get("archive.uncompressed_size"), Some(2048.0));
    assert_eq!(m.get("archive.compression.method_counts.raw"), Some(1.0));
    // A partition label is not a file name.
    assert!(m.get("archive.executable_count").is_none());
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn zlib_chunk(sector_number: u64, sector_count: u64, comp_length: u64) -> Chunk {
    Chunk {
        entry_type: 0x8000_0005,
        sector_number,
        sector_count,
        comp_offset: 0,
        comp_length,
    }
}

fn koly_at_zero() -> Koly {
    Koly {
        version: 4,
        data_fork_offset: 0,
        data_fork_length: 0,
        xml_offset: 0,
        xml_length: 0,
        image_variant: 1,
        sector_count: 0,
    }
}

/// Thousands of descriptors naming one zlib blob share one inflate budget,
/// and each decodes at most its own sector run, rather than each inflating
/// the whole window.
#[test]
fn overlapping_zlib_chunks_share_one_inflate_budget() {
    let blob = zlib(&vec![0_u8; MAX_VOL_PREFIX]);
    let half = (MAX_VOL_PREFIX as u64 / SECTOR) / 2;
    let part = Partition {
        name: String::new(),
        sector_count: half * 2,
        data_offset: 0,
        chunks: (0..10_000)
            .map(|_| zlib_chunk(0, half, blob.len() as u64))
            .collect(),
    };
    let (_, inflated) = reconstruct_prefix(&blob, &koly_at_zero(), &part, MAX_VOL_PREFIX).unwrap();
    assert_eq!(inflated, MAX_PREFIX_INFLATE);
}

/// A chunk writes no more than its declared sector run.
#[test]
fn zlib_chunk_output_is_capped_at_its_sector_count() {
    let blob = zlib(&vec![0xAB_u8; 8 * SECTOR as usize]);
    let part = Partition {
        name: String::new(),
        sector_count: 8,
        data_offset: 0,
        chunks: vec![zlib_chunk(0, 1, blob.len() as u64)],
    };
    let (buf, inflated) =
        reconstruct_prefix(&blob, &koly_at_zero(), &part, 8 * SECTOR as usize).unwrap();
    assert_eq!(inflated, SECTOR as usize);
    assert!(buf[..SECTOR as usize].iter().all(|&b| b == 0xAB));
    assert!(buf[SECTOR as usize..].iter().all(|&b| b == 0));
}

/// One chunk pointing outside the image leaves the others intact.
#[test]
fn bad_chunk_loses_only_its_own_sectors() {
    let blob = zlib(&[0xCD_u8; SECTOR as usize]);
    let mut bad = zlib_chunk(1, 1, 64);
    bad.comp_offset = u64::MAX - 8;
    let part = Partition {
        name: String::new(),
        sector_count: 2,
        data_offset: 0,
        chunks: vec![zlib_chunk(0, 1, blob.len() as u64), bad],
    };
    let (buf, _) = reconstruct_prefix(&blob, &koly_at_zero(), &part, 2 * SECTOR as usize).unwrap();
    assert!(buf[..SECTOR as usize].iter().all(|&b| b == 0xCD));
}

/// Descriptors that each re-handle the window while one sector stays
/// unwritten do not multiply the work by the descriptor count: zlib streams
/// that inflate to nothing still consume their source, and raw or zero runs
/// rewrite sectors already written. The walk stops at the work budget,
/// before a last chunk that would finish the window.
#[test]
fn chunks_that_never_finish_the_window_share_one_work_budget() {
    // A zlib stream of empty stored blocks: 64 KiB consumed, nothing out.
    let mut bytes = vec![0x78, 0x01];
    for _ in 0..(64 << 10) / 5 {
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
    }
    let stalled = bytes.len() as u64;
    let finisher = zlib(&[0xAB; SECTOR as usize]);
    let finisher_at = bytes.len() as u64;
    bytes.extend_from_slice(&finisher);
    let raw_at = bytes.len() as u64;
    bytes.extend_from_slice(&[0xAB; SECTOR as usize]);

    let window = MAX_VOL_PREFIX as u64 / SECTOR;
    let rounds = MAX_PREFIX_WORK / (64 << 10) + 8;
    for (entry_type, finish_type, finish_at, finish_len) in [
        (0x8000_0005, 0x8000_0005, finisher_at, finisher.len() as u64),
        (0x0000_0001, 0x0000_0001, raw_at, SECTOR),
        (0x0000_0000, 0x0000_0001, raw_at, SECTOR),
    ] {
        let mut chunks: Vec<Chunk> = (0..rounds)
            .map(|_| Chunk {
                entry_type,
                sector_number: 0,
                sector_count: window - 1,
                comp_offset: 0,
                comp_length: stalled,
            })
            .collect();
        chunks.push(Chunk {
            entry_type: finish_type,
            sector_number: window - 1,
            sector_count: 1,
            comp_offset: finish_at,
            comp_length: finish_len,
        });
        let part = Partition {
            name: String::new(),
            sector_count: window,
            data_offset: 0,
            chunks,
        };
        let (buf, _) = reconstruct_prefix(&bytes, &koly_at_zero(), &part, MAX_VOL_PREFIX).unwrap();
        let last = &buf[MAX_VOL_PREFIX - SECTOR as usize..];
        assert!(
            last.iter().all(|&b| b == 0),
            "entry type {entry_type:#x}: the walk ran past its work budget"
        );
    }
}

#[test]
fn non_dmg_bytes_error() {
    let mut v = Values::new();
    let mut m = Metrics::new();
    let mut members = Vec::new();
    assert!(extract(b"not a dmg at all", &mut v, &mut m, &mut members).is_err());
}

/// The resource-fork plist is attacker bytes: a binary plist whose shared
/// references expand exponentially is refused instead of expanded.
#[test]
fn blkx_plist_reference_expansion_is_refused() {
    let xml = crate::formats::plist_guard::reference_dag(8);
    let koly = Koly {
        xml_length: xml.len() as u64,
        ..koly_at_zero()
    };
    assert!(parse_blkx(&xml, &koly).is_empty());
}
