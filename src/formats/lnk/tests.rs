use super::*;

fn header_bytes(link_flags: u32, file_attrs: u32, show_command: u32) -> Vec<u8> {
    let mut h = vec![0u8; 76];
    h[..4].copy_from_slice(&0x0000_004Cu32.to_le_bytes());
    // CLSID (16 bytes from offset 4) — exact value doesn't matter for our parse
    h[4] = 0x01;
    h[5] = 0x14;
    h[6] = 0x02;
    h[7] = 0x00;
    h[20..24].copy_from_slice(&link_flags.to_le_bytes());
    h[24..28].copy_from_slice(&file_attrs.to_le_bytes());
    h[52..56].copy_from_slice(&0x1234u32.to_le_bytes());
    h[60..64].copy_from_slice(&show_command.to_le_bytes());
    h
}

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    extract(bytes, &mut v, &mut s, &mut m).unwrap();
    (v, m)
}

#[test]
fn rejects_non_lnk() {
    let (v, _) = run(b"not an lnk");
    assert!(v.get("lnk.header").is_none());
}

#[test]
fn surfaces_header_flags() {
    let lnk = header_bytes(FLAG_HAS_LINK_TARGET_ID_LIST | FLAG_IS_UNICODE, 0x0020, 3);
    let (v, _) = run(&lnk);
    let header = v.get("lnk.header").and_then(|x| x.as_object()).unwrap();
    assert_eq!(
        header.get("show_command").and_then(|x| x.as_str()),
        Some("maximized")
    );
    let flags = header.get("flags").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = flags.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"has_link_target_id_list"));
    assert!(names.contains(&"is_unicode"));
    let attrs = header
        .get("file_attributes")
        .and_then(|x| x.as_array())
        .unwrap();
    let attr_names: Vec<&str> = attrs.iter().filter_map(|x| x.as_str()).collect();
    assert!(attr_names.contains(&"archive"));
}

#[test]
fn extracts_relative_path_unicode() {
    // Header sets HAS_RELATIVE_PATH + IS_UNICODE; no IDList/LinkInfo so the
    // string sits at offset 76 directly.
    let path = "..\\target.exe";
    let mut lnk = header_bytes(FLAG_HAS_RELATIVE_PATH | FLAG_IS_UNICODE, 0, 1);
    let chars: Vec<u16> = path.encode_utf16().collect();
    lnk.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for w in &chars {
        lnk.extend_from_slice(&w.to_le_bytes());
    }
    let (v, _) = run(&lnk);
    assert_eq!(
        v.get("lnk.relative_path").and_then(|x| x.as_str()),
        Some(path)
    );
}

#[test]
fn stringdata_carries_body_offset() {
    // Header is 76 bytes; with no IDList/LinkInfo the StringData starts
    // there, so the body sits 2 bytes later past the length prefix.
    let path = "..\\target.exe";
    let mut lnk = header_bytes(FLAG_HAS_RELATIVE_PATH | FLAG_IS_UNICODE, 0, 1);
    let chars: Vec<u16> = path.encode_utf16().collect();
    lnk.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for w in &chars {
        lnk.extend_from_slice(&w.to_le_bytes());
    }
    let (v, _) = run(&lnk);
    assert_eq!(
        v.get("lnk.relative_path_offset").and_then(|x| x.as_u64()),
        Some(78)
    );
    assert_eq!(
        &lnk[78..78 + chars.len() * 2],
        &lnk[78..],
        "offset must index the body bytes"
    );
}

#[test]
fn icon_environment_block_carries_its_offset() {
    // IconEnvironmentDataBlock: u32 size, u32 signature, ANSI target
    // at +8 (260 bytes), Unicode target at +268 (520 bytes). The
    // Unicode copy wins, so the anchor must point at +268.
    let mut lnk = header_bytes(0, 0, 1);
    let block_start = lnk.len();
    let mut block = vec![0u8; 788];
    block[0..4].copy_from_slice(&788u32.to_le_bytes());
    block[4..8].copy_from_slice(&EXTRA_ICON_ENVIRONMENT_DATA.to_le_bytes());
    let target = "%ProgramFiles%\\app\\app.exe";
    for (i, unit) in target.encode_utf16().enumerate() {
        block[268 + i * 2..268 + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    lnk.extend_from_slice(&block);
    lnk.extend_from_slice(&[0u8; 4]); // terminal block

    let (v, _) = run(&lnk);
    assert_eq!(
        v.get("lnk.icon_environment_target")
            .and_then(|x| x.as_str()),
        Some(target)
    );
    assert_eq!(
        v.get("lnk.icon_environment_target_offset")
            .and_then(|x| x.as_u64()),
        Some((block_start + 268) as u64)
    );
}

#[test]
fn extracts_tracker_block() {
    // Build a minimal header + TrackerData ExtraData block.
    let mut lnk = header_bytes(0, 0, 1);
    // TrackerDataBlock: u32 block_size, u32 signature, u32 length,
    // u32 version, ansi machine_id[16], guid volume[16], guid file[16]
    let mut block = Vec::new();
    block.extend_from_slice(&(96u32).to_le_bytes()); // block_size (rounded for our layout)
    block.extend_from_slice(&EXTRA_TRACKER_DATA.to_le_bytes());
    block.extend_from_slice(&0u32.to_le_bytes()); // length
    block.extend_from_slice(&0u32.to_le_bytes()); // version
    let mut machine = b"build-host-01\0\0\0".to_vec();
    machine.resize(16, 0);
    block.extend_from_slice(&machine);
    // Volume Droid GUID
    block.extend_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ]);
    // File Droid GUID (last 6 bytes encode the MAC)
    block.extend_from_slice(&[
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77,
    ]);
    // Block was declared as 96 bytes total; pad if needed.
    while block.len() < 96 {
        block.push(0);
    }
    // Final zero u32 terminates ExtraData.
    lnk.extend_from_slice(&block);
    lnk.extend_from_slice(&0u32.to_le_bytes());

    let (v, _) = run(&lnk);
    let tracker = v.get("lnk.tracker").and_then(|x| x.as_object()).unwrap();
    assert_eq!(
        tracker.get("machine_id").and_then(|x| x.as_str()),
        Some("build-host-01")
    );
    let mac = tracker.get("mac_address").and_then(|x| x.as_str()).unwrap();
    assert_eq!(mac, "22:33:44:55:66:77");
    let blocks = v.get("lnk.blocks").and_then(|x| x.as_array()).unwrap();
    let names: Vec<&str> = blocks.iter().filter_map(|x| x.as_str()).collect();
    assert!(names.contains(&"tracker"));

    // Identity reads the tracker's machine name back. It once asked for a
    // `machine_name` field that this extractor never writes, so the claim
    // was silently empty on every shortcut. It is reported once, as
    // `machine_id`; a `lnk_machine_name` duplicate was dropped.
    let id = super::super::identity::derive(crate::FileType::Lnk, &lnk, &v);
    assert_eq!(
        id.unique_ids.get("machine_id").map(String::as_str),
        Some("build-host-01")
    );
    assert!(!id.unique_ids.contains_key("lnk_machine_name"));
    assert_eq!(
        id.unique_ids.get("mac_address").map(String::as_str),
        Some("22:33:44:55:66:77")
    );
}

#[test]
fn empty_input_is_silent() {
    let (v, _) = run(&[]);
    assert!(v.get("lnk.header").is_none());
}

#[test]
fn truncated_header_doesnt_crash() {
    // Right header size field but file is shorter than the declared
    // header — should silently bail rather than panic.
    let mut h = vec![0u8; 40];
    h[..4].copy_from_slice(&0x0000_004Cu32.to_le_bytes());
    let (v, _) = run(&h);
    assert!(v.get("lnk.header").is_none());
}

#[test]
fn wrong_header_size_rejected() {
    // Header size != 0x4C → not a valid SHLLINK header.
    let mut h = vec![0u8; 76];
    h[..4].copy_from_slice(&0x0000_0040u32.to_le_bytes());
    let (v, _) = run(&h);
    assert!(v.get("lnk.header").is_none());
}

#[test]
fn file_size_metric_surfaces() {
    let lnk = header_bytes(0, 0, 1);
    let (_, m) = run(&lnk);
    // file_size at offset 52 == 0x1234.
    assert_eq!(m.get("lnk.file_size"), Some(f64::from(0x1234)));
}

#[test]
fn show_command_defaults_for_unknown_value() {
    // Show command of 999 is not 1/3/7 → should fall back without panic.
    let lnk = header_bytes(0, 0, 999);
    let (v, _) = run(&lnk);
    let header = v.get("lnk.header").and_then(|x| x.as_object()).unwrap();
    // show_command may be absent or have a sane fallback; just assert no panic.
    let _ = header.get("show_command");
}

#[test]
fn derive_mac_handles_short_guid() {
    assert!(derive_mac("not-a-guid").is_none());
    assert!(derive_mac("aaaaaaaa-bbbb-cccc-dddd-zz").is_none());
}

#[test]
fn derive_mac_extracts_six_bytes() {
    let mac = derive_mac("00000000-0000-0000-0000-aabbccddeeff").unwrap();
    assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
}

/// Build a minimal LinkInfo block (no Unicode optional fields,
/// VolumeIDAndLocalBasePath set) of the form:
///
/// [header 0x1C bytes][VolumeID][LocalBasePath ASCIIZ][CommonPathSuffix ASCIIZ]
fn build_link_info_with_local_path(
    drive_type: u32,
    serial: u32,
    label: &str,
    local: &str,
    suffix: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    // Header: 7 u32 fields, 0x1C bytes total. We fill offsets in
    // after constructing payload positions.
    out.extend_from_slice(&[0u8; 0x1C]);

    // VolumeID block at offset 0x1C.
    let volume_offset = out.len() as u32;
    let mut vol = Vec::new();
    vol.extend_from_slice(&[0u8; 4]); // size placeholder
    vol.extend_from_slice(&drive_type.to_le_bytes());
    vol.extend_from_slice(&serial.to_le_bytes());
    vol.extend_from_slice(&(0x10u32).to_le_bytes()); // VolumeLabelOffset
    vol.extend_from_slice(label.as_bytes());
    vol.push(0);
    let vol_size = vol.len() as u32;
    vol[0..4].copy_from_slice(&vol_size.to_le_bytes());
    out.extend_from_slice(&vol);

    // LocalBasePath.
    let local_offset = out.len() as u32;
    out.extend_from_slice(local.as_bytes());
    out.push(0);

    // CommonPathSuffix.
    let suffix_offset = out.len() as u32;
    out.extend_from_slice(suffix.as_bytes());
    out.push(0);

    let total_size = out.len() as u32;
    out[0..4].copy_from_slice(&total_size.to_le_bytes());
    out[4..8].copy_from_slice(&0x1Cu32.to_le_bytes()); // HeaderSize
    out[8..12].copy_from_slice(&0x1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    out[12..16].copy_from_slice(&volume_offset.to_le_bytes());
    out[16..20].copy_from_slice(&local_offset.to_le_bytes());
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // no network link
    out[24..28].copy_from_slice(&suffix_offset.to_le_bytes());
    out
}

#[test]
fn link_info_yields_volume_and_target_path() {
    let mut lnk = header_bytes(FLAG_HAS_LINK_INFO, 0x20, 1);
    let info = build_link_info_with_local_path(
        3, // fixed drive
        0xDEAD_BEEF,
        "System",
        "C:\\Windows\\System32\\notepad.exe",
        "",
    );
    lnk.extend_from_slice(&info);
    let (v, _) = run(&lnk);
    let vol = v.get("lnk.volume").and_then(|x| x.as_object()).unwrap();
    assert_eq!(
        vol.get("drive_type").and_then(|x| x.as_str()),
        Some("fixed")
    );
    assert_eq!(
        vol.get("serial").and_then(|x| x.as_u64()),
        Some(0xDEAD_BEEF)
    );
    assert_eq!(vol.get("name").and_then(|x| x.as_str()), Some("System"));
    assert_eq!(
        v.get("lnk.target_path").and_then(|x| x.as_str()),
        Some("C:\\Windows\\System32\\notepad.exe")
    );
    // The anchor must index the LocalBasePath bytes in the file.
    let at = v
        .get("lnk.target_path_offset")
        .and_then(|x| x.as_u64())
        .unwrap() as usize;
    assert!(
        lnk[at..].starts_with(b"C:\\Windows\\System32\\notepad.exe\0"),
        "offset {at} does not index the base path"
    );
}

#[test]
fn link_info_with_path_suffix_concatenates() {
    let mut lnk = header_bytes(FLAG_HAS_LINK_INFO, 0x20, 1);
    let info =
        build_link_info_with_local_path(3, 0, "", "C:\\Users\\victim", "\\Desktop\\target.exe");
    lnk.extend_from_slice(&info);
    let (v, _) = run(&lnk);
    assert_eq!(
        v.get("lnk.target_path").and_then(|x| x.as_str()),
        Some("C:\\Users\\victim\\Desktop\\target.exe")
    );
}

#[test]
fn id_list_walk_recovers_drive_root_when_no_link_info() {
    // Header has IDList flag set but no LinkInfo. Build a single
    // drive-root ItemID (class 0x2F, content "C:\\\0").
    let mut lnk = header_bytes(FLAG_HAS_LINK_TARGET_ID_LIST, 0, 1);

    // First, the IDList size (u16). We'll fill it in after.
    let id_list_start = lnk.len();
    lnk.extend_from_slice(&[0u8; 2]);

    // ItemID #1: drive root C:\
    let item1: Vec<u8> = {
        let mut b = vec![0x2Fu8]; // class
        b.extend_from_slice(b"C:\\\0");
        b
    };
    let item1_size = (2 + item1.len()) as u16;
    lnk.extend_from_slice(&item1_size.to_le_bytes());
    lnk.extend_from_slice(&item1);

    // Terminator (u16 0).
    lnk.extend_from_slice(&[0u8, 0u8]);
    let id_list_size = (lnk.len() - id_list_start - 2) as u16;
    lnk[id_list_start..id_list_start + 2].copy_from_slice(&id_list_size.to_le_bytes());

    let (v, _) = run(&lnk);
    let target = v.get("lnk.target_path").and_then(|x| x.as_str()).unwrap();
    assert!(target.starts_with("C:"), "got: {target}");
    // With no named component the anchor falls back to the drive root.
    let at = v
        .get("lnk.target_path_offset")
        .and_then(|x| x.as_u64())
        .unwrap() as usize;
    assert!(
        lnk[at..].starts_with(b"C:\\\0"),
        "offset {at} does not index the drive root"
    );
}

#[test]
fn link_info_too_short_is_silent() {
    // FLAG_HAS_LINK_INFO set but the LinkInfo size field
    // declares less than the 0x1C header.
    let mut lnk = header_bytes(FLAG_HAS_LINK_INFO, 0, 1);
    lnk.extend_from_slice(&8u32.to_le_bytes()); // size = 8 (truncated)
    lnk.extend_from_slice(&[0u8; 4]);
    let (v, _) = run(&lnk);
    assert!(v.get("lnk.volume").is_none());
    assert!(v.get("lnk.target_path").is_none());
}

#[test]
fn drive_type_name_maps_known_values() {
    assert_eq!(drive_type_name(3), "fixed");
    assert_eq!(drive_type_name(4), "remote");
    assert_eq!(drive_type_name(5), "cdrom");
    assert_eq!(drive_type_name(99), "unknown");
}

/// Build an LNK with a `HasArguments` StringData payload whose
/// UTF-16LE content is the requested string.
fn lnk_with_arguments(args: &str) -> Vec<u8> {
    let mut lnk = header_bytes(FLAG_HAS_ARGUMENTS | FLAG_IS_UNICODE, 0, 1);
    let chars: Vec<u16> = args.encode_utf16().collect();
    lnk.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for w in &chars {
        lnk.extend_from_slice(&w.to_le_bytes());
    }
    lnk
}

#[test]
fn argument_whitespace_metrics_fire_on_padded_args() {
    // 60 leading spaces + "powershell.exe -enc AAAA".
    let mut args = " ".repeat(60);
    args.push_str("powershell.exe -enc AAAA");
    let (_, m) = run(&lnk_with_arguments(&args));
    assert_eq!(m.get("lnk.arguments_leading_spaces"), Some(60.0));
    assert_eq!(m.get("lnk.arguments_max_whitespace_run"), Some(60.0));
    assert!(m.get("lnk.arguments_whitespace_count").unwrap() >= 60.0);
}

#[test]
fn argument_whitespace_metrics_quiet_on_normal_args() {
    let (_, m) = run(&lnk_with_arguments("/c notepad.exe"));
    assert!(m.get("lnk.arguments_max_whitespace_run").unwrap() < 50.0);
    assert_eq!(m.get("lnk.arguments_leading_tabs"), Some(0.0));
}

#[test]
fn argument_whitespace_metrics_count_leading_tabs() {
    let args = format!("{}cmd.exe", "\t".repeat(55));
    let (_, m) = run(&lnk_with_arguments(&args));
    assert_eq!(m.get("lnk.arguments_leading_tabs"), Some(55.0));
    assert_eq!(m.get("lnk.arguments_max_whitespace_run"), Some(55.0));
}
