#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use super::*;
use crate::formats::embedded::{EmbeddedKind, scan};

/// A 256-byte buffer with a DOS header: enough for marker scanning.
fn pe_stub() -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    buf[..2].copy_from_slice(b"MZ");
    buf
}

/// A minimal valid PE32 image at `offset`.
fn make_synthetic_pe(buf: &mut Vec<u8>, offset: usize) {
    if buf.len() < offset + 4096 {
        buf.resize(offset + 4096, 0);
    }
    buf[offset..offset + 2].copy_from_slice(b"MZ");
    buf[offset + 0x3C..offset + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = offset + 0x80;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
    buf[pe + 20..pe + 22].copy_from_slice(&0x00E0u16.to_le_bytes());
    buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf[pe + 80..pe + 84].copy_from_slice(&4096u32.to_le_bytes());
    let section = pe + 24 + 0xE0;
    buf[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
    buf[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
}

fn image(offset: usize, size: usize, format: Option<&'static str>) -> EmbeddedBinary {
    EmbeddedBinary {
        offset,
        kind: EmbeddedKind::Pe32,
        size,
        encoding: None,
        format,
    }
}

fn kind(data: &[u8], embedded: &[EmbeddedBinary]) -> Option<&'static str> {
    detect(data, embedded).map(|(kind, _)| kind)
}

#[test]
fn nsis_needs_its_header_and_a_string() {
    let mut data = pe_stub();
    data.extend_from_slice(NSIS_DEADBEEF);
    assert_eq!(kind(&data, &[]), None);
    data.extend_from_slice(b"NSIS Error");
    assert_eq!(detect(&data, &[]), Some(("nsis", Some(256))));
}

#[test]
fn inno_marker() {
    let mut data = pe_stub();
    data.extend_from_slice(INNO_MARKER);
    assert_eq!(detect(&data, &[]), Some(("inno", Some(256))));
}

#[test]
fn inno_takes_precedence_over_a_weak_nsis_marker() {
    let mut data = pe_stub();
    data.extend_from_slice(INNO_MARKER);
    data.extend_from_slice(NSIS_DEADBEEF);
    assert_eq!(kind(&data, &[]), Some("inno"));
}

#[test]
fn markers_inside_an_embedded_image_are_the_childs() {
    let mut data = vec![0u8; 1024];
    data[..2].copy_from_slice(b"MZ");
    data[512..514].copy_from_slice(b"MZ");
    data[576..576 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    assert_eq!(kind(&data, &[image(512, 512, Some("inno"))]), None);

    let mut nsis = vec![0u8; 1024];
    nsis[..2].copy_from_slice(b"MZ");
    nsis[576..580].copy_from_slice(NSIS_DEADBEEF);
    nsis[608..618].copy_from_slice(b"NSIS Error");
    assert_eq!(kind(&nsis, &[image(512, 512, Some("nsis"))]), None);
}

#[test]
fn a_root_marker_still_counts_beside_a_nested_one() {
    let mut data = vec![0u8; 1024];
    data[..2].copy_from_slice(b"MZ");
    data[256..256 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    data[576..576 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    assert_eq!(
        detect(&data, &[image(512, 512, Some("inno"))]),
        Some(("inno", Some(256)))
    );
}

#[test]
fn the_scanners_span_keeps_a_nested_installer_off_the_host() {
    let mut data = vec![0u8; 8192];
    data[..2].copy_from_slice(b"MZ");
    make_synthetic_pe(&mut data, 512);
    data[1536..1536 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    let embedded = scan(&data);
    assert!(
        embedded
            .iter()
            .any(|e| e.offset == 512 && e.format == Some("inno"))
    );
    assert_eq!(kind(&data, &embedded), None);
}

#[test]
fn nuitka_needs_its_runtime_and_payload_outside_embedded_images() {
    let mut data = pe_stub();
    data.extend_from_slice(b"NUITKA_ONEFILE_PARENT\0");
    let payload = data.len();
    data.extend_from_slice(NUITKA_PAYLOAD);
    data.extend_from_slice(b"compressed records");
    assert_eq!(detect(&data, &[]), Some(("nuitka", Some(payload))));
    let len = data.len();
    assert_eq!(kind(&data, &[image(payload, len - payload, None)]), None);
    assert_eq!(kind(b"MZNUITKA_ONEFILE_PARENT", &[]), None);
}

#[test]
fn iexpress_needs_its_resources_and_a_bounded_cabinet() {
    let mut data = b"MZ".to_vec();
    for name in ["CABINET", "RUNPROGRAM"] {
        data.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    }
    let start = data.len();
    let mut cab = [0_u8; 64];
    cab[..4].copy_from_slice(b"MSCF");
    cab[8..12].copy_from_slice(&64_u32.to_le_bytes());
    cab[16..20].copy_from_slice(&44_u32.to_le_bytes());
    cab[24..30].copy_from_slice(&[3, 1, 1, 0, 1, 0]);
    data.extend(cab);
    assert_eq!(detect(&data, &[]), Some(("iexpress", Some(start))));
    assert_eq!(kind(&data[..start + 48], &[]), None);
    let mut version_only = b"MZ Microsoft wextract.pdb".to_vec();
    version_only.extend(cab);
    assert_eq!(kind(&version_only, &[]), None);
    data[start + 28] = 0;
    assert_eq!(kind(&data, &[]), None);
}

#[test]
fn nothing_in_benign_or_empty_data() {
    assert_eq!(
        kind(b"a normal binary without installer markers", &[]),
        None
    );
    assert_eq!(kind(&[], &[]), None);
}

#[test]
fn emits_the_kind_and_marker() {
    let mut data = pe_stub();
    data.extend_from_slice(INNO_MARKER);
    let mut values = Values::new();
    emit(&data, &[], &mut values);
    assert_eq!(
        values.get("binary.installer.kind"),
        Some(&JsonValue::from("inno"))
    );
    assert_eq!(
        values.get("binary.installer.marker_offset"),
        Some(&JsonValue::from(256))
    );
}

#[test]
fn pyinstaller_reports_the_cookie_python_version() {
    for (encoded, version) in [(311u32, "3.11"), (27, "2.7"), (39, "3.9")] {
        let mut data = pe_stub();
        data.extend_from_slice(PYINSTALLER_COOKIE);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&encoded.to_be_bytes());
        let mut values = Values::new();
        emit(&data, &[], &mut values);
        assert_eq!(
            values.get("binary.installer.python_version"),
            Some(&JsonValue::from(version))
        );
    }
    let mut data = pe_stub();
    data.extend_from_slice(PYINSTALLER_COOKIE);
    data.extend_from_slice(&[0xff; 16]);
    let mut values = Values::new();
    emit(&data, &[], &mut values);
    assert_eq!(values.get("binary.installer.python_version"), None);
}
