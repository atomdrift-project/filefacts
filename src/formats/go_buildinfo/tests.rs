use super::*;

#[test]
fn pclntab_magic_recognizes_known_versions() {
    // Go 1.18 (LE) and Go 1.20 (BE) headers, with a plausible tail.
    assert!(has_pclntab_magic(&[0xf0, 0xff, 0xff, 0xff, 0, 0, 1, 8]));
    assert!(has_pclntab_magic(&[0xff, 0xff, 0xff, 0xf1, 0, 0, 1, 8]));
    // Go 1.2 / 1.16 little-endian.
    assert!(has_pclntab_magic(&[0xfb, 0xff, 0xff, 0xff]));
    assert!(has_pclntab_magic(&[0xfa, 0xff, 0xff, 0xff]));
}

#[test]
fn pclntab_magic_rejects_decoys_and_short_input() {
    // A section named like pclntab but without a real magic must NOT pass —
    // otherwise a decoy could downgrade analysis and hide functions.
    assert!(!has_pclntab_magic(b"not a pclntab"));
    assert!(!has_pclntab_magic(&[0x00, 0x00, 0x00, 0x00]));
    assert!(!has_pclntab_magic(&[0xf0, 0xff, 0xff])); // too short
    assert!(!has_pclntab_magic(&[])); // empty
}

#[test]
fn uvarint_decodes_small_values() {
    // 0x96 0x01 → 150. Standard Go uvarint test vector.
    let mut buf = vec![0x96, 0x01];
    buf.extend([b's'; 150]);
    buf.push(0xaa);
    let (s, rest) = read_uvarint_string(&buf).unwrap();
    assert_eq!(s, &[b's'; 150][..]);
    assert_eq!(rest, &[0xaa]);
    // A length past the buffer is no string.
    assert_eq!(read_uvarint_string(&buf[..100]), None);
}

#[test]
fn modinfo_parses_minimal_record_set() {
    let mut out = Map::new();
    parse_modinfo(
        b"path\texample.com/main\nmod\texample.com/main\tv1.0.0\t\ndep\texample.com/util\tv0.1.0\th1:xyz=\nbuild\t-tags=foo\nbuild\tvcs=git\nbuild\tvcs.modified=true\n",
        &mut out,
    );
    assert_eq!(out["path"], JsonValue::String("example.com/main".into()));
    let deps = out["deps"].as_array().unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0]["path"], "example.com/util");
    assert_eq!(out["build_settings"]["-tags"], "foo");
    assert_eq!(out["vcs"]["system"], "git");
    assert_eq!(out["vcs"]["modified"], "true");
}

#[test]
fn classifies_dependency_provenance() {
    let mut out = Map::new();
    parse_modinfo(
        b"path\texample.com/main\n\
          dep\tfmt\t(devel)\t\n\
          dep\tgithub.com/foo/bar\tv1.2.3\th1:aaa=\n\
          dep\texample.com/old\tv1.0.0\th1:bbb=\n\
          =>\texample.com/new\tv2.0.0\th1:ccc=\n",
        &mut out,
    );
    // fmt = std, github.com/foo/bar = thirdparty, example.com/old is
    // replaced (followed by a `=>` target), the `=>` itself not counted.
    assert_eq!(out["deps_std"], JsonValue::from(1u32));
    assert_eq!(out["deps_thirdparty"], JsonValue::from(1u32));
    assert_eq!(out["deps_replaced"], JsonValue::from(1u32));
    assert_eq!(out["deps_vendored"], JsonValue::from(0u32));
}

#[test]
fn build_id_from_rodata_marker() {
    let rodata = b"....Go build ID: \"abc123/def456\"....";
    let id = build_id(None, Some(rodata), b"");
    assert_eq!(id.as_deref(), Some("abc123/def456"));
}

#[test]
fn build_id_from_elf_note() {
    // namesz=4 ("Go\0\0"), descsz=7 ("id12345"), type=4.
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&7u32.to_le_bytes());
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(b"Go\0\0");
    note.extend_from_slice(b"id12345");
    assert_eq!(parse_elf_buildid_note(&note).as_deref(), Some("id12345"));
}

#[test]
fn old_format_pointer_resolving_near_usize_max_is_ignored() {
    // A PT_LOAD whose `p_offset` sits near `u64::MAX` resolves the
    // version pointer to an offset where `hdr_off + 2 * ptr_size` would
    // overflow (a panic under overflow checks).
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(&[8, 0]); // ptr_size, pointer-format flags
    blob.resize(32, 0);
    let resolve = |_: u64| Some(usize::MAX - 4);
    let mut values = Values::new();
    detect(
        &blob,
        &mut values,
        crate::value_key!("elf.go"),
        Some(&resolve),
        &GoSections {
            buildinfo: Some(&blob),
            ..GoSections::default()
        },
    );
    assert!(values.get("elf.go").is_none());
}

#[test]
fn build_id_note_with_overflowing_name_size_is_ignored() {
    let mut note = Vec::new();
    note.extend_from_slice(&u32::MAX.to_le_bytes()); // namesz
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(b"Go\0\0abcd");
    assert_eq!(parse_elf_buildid_note(&note), None);
}

/// Each `dep` line becomes a JSON object hundreds of times its size, so
/// the list stops at [`MAX_DEPS`].
#[test]
fn modinfo_dependency_list_is_capped() {
    let blob = "dep\tA\n".repeat(MAX_DEPS + 10);
    let mut out = Map::new();
    parse_modinfo(blob.as_bytes(), &mut out);
    assert_eq!(out["deps"].as_array().unwrap().len(), MAX_DEPS);
}

#[test]
fn go_root_from_pclntab_runtime_path() {
    let pclntab = b"\x00\x00/usr/local/go/src/runtime/proc.go\x00";
    assert_eq!(scan_go_root(pclntab).as_deref(), Some("/usr/local/go"));
}

#[test]
fn main_root_is_common_dir_of_developer_paths() {
    let pclntab =
        b"/home/dev/project/main.go\x00\x00/home/dev/project/pkg/util.go\x00\x00/usr/local/go/src/runtime/proc.go\x00";
    let root = scan_go_main_root(pclntab, Some("/usr/local/go"));
    assert_eq!(root.as_deref(), Some("/home/dev/project"));
}

/// A Go 1.18+ inline blob: header, then the version and modinfo strings.
fn inline_blob(version: &str, modinfo: &str) -> Vec<u8> {
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(&[8, 0x2]); // ptr_size, inline-string flag
    blob.resize(HEADER_LEN, 0);
    for s in [version, modinfo] {
        blob.push(u8::try_from(s.len()).unwrap()); // one-byte uvarint
        blob.extend_from_slice(s.as_bytes());
    }
    blob
}

fn go_value(region: Option<&[u8]>, file: &[u8]) -> Option<JsonValue> {
    let mut values = Values::new();
    let sections = GoSections {
        buildinfo: region,
        ..GoSections::default()
    };
    detect(
        file,
        &mut values,
        crate::value_key!("elf.go"),
        None,
        &sections,
    );
    values.get("elf.go").cloned()
}

/// Only a magic at a 16-byte offset within the build-info region is the
/// binary's own: one at any other offset, or anywhere outside the region (an
/// embedded payload's blob, a decoy string), says nothing about the host.
#[test]
fn build_info_is_read_only_at_an_aligned_offset_of_its_region() {
    let blob = inline_blob("go1.22.1", "path\texample.com/app\n");
    let mut region = vec![0u8; 16];
    region.extend_from_slice(&blob);
    let go = go_value(Some(&region), &region).expect("aligned blob decodes");
    assert_eq!(go["version"], "go1.22.1");
    assert_eq!(go["path"], "example.com/app");

    let mut unaligned = vec![0u8; 3];
    unaligned.extend_from_slice(&blob);
    assert_eq!(go_value(Some(&unaligned), &unaligned), None);

    // The whole file holds an aligned blob, but the region does not.
    let mut file = vec![0u8; 64];
    file.extend_from_slice(&blob);
    assert_eq!(go_value(Some(&file[..64]), &file), None);
    assert_eq!(go_value(None, &file), None);
}

/// A misaligned decoy ahead of the real blob does not hide it.
#[test]
fn decoy_magic_before_the_blob_is_skipped() {
    let mut region = vec![0u8; 5];
    region.extend_from_slice(&inline_blob("go0.0.0", ""));
    region.resize(48, 0);
    region.extend_from_slice(&inline_blob("go1.21.5", ""));
    let go = go_value(Some(&region), &region).expect("aligned blob decodes");
    assert_eq!(go["version"], "go1.21.5");
}

/// The pre-1.18 layout stores pointers in the target's byte order; a
/// non-zero flags byte marks a big-endian target.
#[test]
fn pointer_layout_follows_the_target_byte_order() {
    let mut file = MAGIC.to_vec();
    file.extend_from_slice(&[4, 1]); // 4-byte pointers, big-endian
    file.extend_from_slice(&0x40u32.to_be_bytes()); // version string header
    file.extend_from_slice(&0u32.to_be_bytes()); // no modinfo
    file.resize(0x40, 0);
    file.extend_from_slice(&0x50u32.to_be_bytes()); // data pointer
    file.extend_from_slice(&8u32.to_be_bytes()); // length
    file.resize(0x50, 0);
    file.extend_from_slice(b"go1.10.3");
    // Identity mapping: virtual addresses are file offsets.
    let resolve = |va: u64| usize::try_from(va).ok();
    let mut values = Values::new();
    let sections = GoSections {
        buildinfo: Some(&file),
        ..GoSections::default()
    };
    detect(
        &file,
        &mut values,
        crate::value_key!("elf.go"),
        Some(&resolve),
        &sections,
    );
    assert_eq!(values.get("elf.go").unwrap()["version"], "go1.10.3");
}
