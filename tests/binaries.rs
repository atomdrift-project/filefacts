//! End-to-end tests of executables: typed views and overlays of the PE,
//! ELF and Mach-O fixtures.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::float_cmp,
    reason = "fixtures build binary layouts from literals and compare exact expected values"
)]

mod common;

use common::{import_names, open};
use filefacts::FileType;

// Embedded rather than read at run time, so the tests do not depend on the
// working directory.
const PE_FIXTURE: &[u8] = include_bytes!("fixtures/test.exe");

const ELF_FIXTURE: &[u8] = include_bytes!("fixtures/test.elf");

const MACHO_FIXTURE: &[u8] = include_bytes!("fixtures/test.macho");

#[test]
fn binary_typed_fact_views_are_not_mirrored_in_values() {
    let parsed = open(PE_FIXTURE);

    assert!(
        !import_names(&parsed).is_empty(),
        "imports should populate the unified Symbols view"
    );
    assert!(
        !parsed.sections().is_empty(),
        "sections typed view should be populated"
    );

    let values = parsed.values();
    for path in [
        "imports",
        "exports",
        "functions",
        "sections",
        "strings",
        "ast",
        "errors",
    ] {
        assert!(
            values.get(path).is_none(),
            "{path} must live only in its typed filefacts view"
        );
    }
    assert_eq!(parsed.parse_count(), 1);
}

/// Deterministic high-entropy filler standing in for an appended payload.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// `binary.overlay_size`/`binary.overlay_entropy` for `bytes`, asserting
/// the entropy span starts exactly where the overlay does.
fn overlay_of(bytes: &[u8]) -> Option<(u64, u64)> {
    let parsed = open(bytes);
    let metrics = parsed.metrics();
    let size = metrics.get("binary.overlay_size")? as u64;
    assert_eq!(metrics.get("binary.has_overlay"), Some(1.0));
    let entropy = metrics
        .fact("binary.overlay_entropy")
        .expect("overlay entropy");
    let [span] = entropy.spans.as_slice() else {
        panic!("one overlay span, got {:?}", entropy.spans);
    };
    assert_eq!(span.len, size);
    Some((span.offset, size))
}

/// Mach-O's last segment is `__LINKEDIT`, which has no sections but holds
/// the symbol tables, dyld info and code signature through EOF. It is
/// part of the image, not an overlay.
#[test]
fn macho_linkedit_is_not_an_overlay() {
    assert_eq!(overlay_of(MACHO_FIXTURE), None);
}

/// Bytes appended past `__LINKEDIT` are still a real overlay.
#[test]
fn macho_bytes_past_linkedit_are_an_overlay() {
    let mut bytes = MACHO_FIXTURE.to_vec();
    let image_len = bytes.len() as u64;
    bytes.extend(pseudo_random(4096));
    assert_eq!(overlay_of(&bytes), Some((image_len, 4096)));
    let parsed = open(&bytes);
    assert!(parsed.metrics().get("binary.overlay_entropy").unwrap() > 7.0);
}

/// A universal binary: the overlay is measured in whole-file offsets past
/// the last slice's image, not against the slice-relative section offsets.
#[test]
fn fat_macho_overlay_is_past_the_last_slice() {
    let slice = MACHO_FIXTURE;
    let slice_offset = 0x1000_u32;
    let mut bytes = Vec::new();
    bytes.extend(0xCAFE_BABE_u32.to_be_bytes());
    bytes.extend(1_u32.to_be_bytes()); // nfat_arch
    bytes.extend(0x0100_0007_u32.to_be_bytes()); // CPU_TYPE_X86_64
    bytes.extend(3_u32.to_be_bytes()); // CPU_SUBTYPE_X86_64_ALL
    bytes.extend(slice_offset.to_be_bytes());
    bytes.extend((slice.len() as u32).to_be_bytes());
    bytes.extend(12_u32.to_be_bytes()); // align 2^12
    bytes.resize(slice_offset as usize, 0);
    bytes.extend(slice);
    assert_eq!(open(&bytes).fileid().file_type(), FileType::MachO);
    assert_eq!(overlay_of(&bytes), None);

    let image_len = bytes.len() as u64;
    bytes.extend(pseudo_random(1000));
    assert_eq!(overlay_of(&bytes), Some((image_len, 1000)));
}

/// The ELF section-header table sits after every section, at EOF; it is
/// part of the image, not an overlay. The fixture carries 220 genuinely
/// appended bytes past its table (e_shoff 21264 + 26 * 64 = 22928): only
/// those are the overlay, and further appended bytes extend it.
#[test]
fn elf_overlay_starts_after_section_header_table() {
    let mut bytes = ELF_FIXTURE.to_vec();
    assert_eq!(bytes.len(), 22928 + 220);
    assert_eq!(overlay_of(&bytes), Some((22928, 220)));
    bytes.extend(pseudo_random(2048));
    assert_eq!(overlay_of(&bytes), Some((22928, 220 + 2048)));
}
