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

const LNK_FIXTURE: &[u8] = include_bytes!("fixtures/lnk/powershell_hidden.lnk");

/// Every executable type surfaces the unified `sections.*`, `imports.*`,
/// `exports.*` and `dependencies.*` counts, the names that replaced the
/// format-scoped `pe.import_count` / `elf.import_count` aliases.
const CANONICAL_COUNTS: [&str; 7] = [
    "sections.count",
    "sections.executable_count",
    "sections.writable_count",
    "sections.executable_writable_count",
    "sections.code_size",
    "sections.name_entropy",
    "sections.nonstandard_count",
];

/// Metrics the retired aliases once carried; none may come back.
const RETIRED_ALIASES: [&str; 29] = [
    "binary.section_count",
    "binary.import_count",
    "binary.export_count",
    "binary.dependency_count",
    "binary.wx_section_count",
    "binary.has_signature",
    "binary.signed",
    "binary.has_executable_stack",
    "binary.has_malformed_structure",
    "binary.aliased_exports",
    "binary.function_count",
    "binary.rizin_function_count",
    "binary.signed_with_individual_cert",
    "pe.import_count",
    "pe.export_count",
    "pe.imported_library_count",
    "elf.import_count",
    "elf.export_count",
    "elf.section_count",
    "elf.needed_count",
    "macho.import_count",
    "macho.export_count",
    "macho.library_count",
    "imports.total",
    "functions.total",
    "archive.compression_ratio",
    "archive.symlink_count",
    "archive.encrypted_count",
    "chm.itsf_lcid",
];

fn assert_metrics(parsed: &filefacts::ParsedFile<'_>, keys: &[&str]) {
    let metrics = parsed.metrics();
    let missing: Vec<_> = keys.iter().filter(|k| metrics.get(k).is_none()).collect();
    assert!(missing.is_empty(), "missing metrics: {missing:?}");
}

#[test]
fn executables_emit_canonical_section_metrics() {
    for (name, bytes, file_type) in [
        ("pe", PE_FIXTURE, FileType::Pe),
        ("elf", ELF_FIXTURE, FileType::Elf),
        ("macho", MACHO_FIXTURE, FileType::MachO),
    ] {
        let parsed = open(bytes);
        assert_eq!(parsed.fileid().file_type(), file_type, "{name}");
        assert_metrics(&parsed, &CANONICAL_COUNTS);
        assert_metrics(&parsed, &["imports.count", "dependencies.count"]);
        if file_type != FileType::Pe {
            assert_metrics(&parsed, &["exports.count"]);
        }
        assert!(parsed.metrics().get("sections.count") > Some(0.0), "{name}");
        assert!(!parsed.sections().is_empty(), "{name}");
        assert!(!import_names(&parsed).is_empty(), "{name} imports");
    }
}

#[test]
fn retired_aliases_are_not_emitted() {
    for (name, bytes) in [
        ("pe", PE_FIXTURE),
        ("elf", ELF_FIXTURE),
        ("macho", MACHO_FIXTURE),
    ] {
        let parsed = open(bytes);
        for retired in RETIRED_ALIASES {
            assert!(
                parsed.metrics().get(retired).is_none(),
                "retired alias {retired} re-emitted for {name}"
            );
        }
    }
}

#[test]
fn format_specific_metrics_are_emitted() {
    assert_metrics(
        &open(ELF_FIXTURE),
        &["elf.bits", "elf.little_endian", "elf.program_header_count"],
    );
    assert_metrics(&open(MACHO_FIXTURE), &["macho.load_command_count"]);
}

/// A healthy executable records no parse errors; the metric is absent.
#[test]
fn healthy_pe_has_no_parse_errors() {
    let parsed = open(PE_FIXTURE);
    assert_eq!(
        parsed.metrics().get("parse.error_count").unwrap_or(0.0),
        0.0
    );
}

/// The LNK extractor surfaces the argument-whitespace metrics (the
/// CVE-2025-9491 signal) whenever the shortcut has an arguments field.
#[test]
fn lnk_emits_argument_whitespace_metrics() {
    let parsed = open(LNK_FIXTURE);
    assert_eq!(parsed.fileid().file_type(), FileType::Lnk);
    assert_metrics(
        &parsed,
        &[
            "lnk.arguments_leading_spaces",
            "lnk.arguments_leading_tabs",
            "lnk.arguments_whitespace_count",
            "lnk.arguments_max_whitespace_run",
        ],
    );
}
