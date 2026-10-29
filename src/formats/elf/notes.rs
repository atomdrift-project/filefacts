//! ELF notes: the GNU build-id, ABI tag and properties, FDO package
//! metadata, and whether each loaded note is still reachable through a note
//! program header.

use goblin::elf::Elf;
use goblin::elf::header;
use goblin::elf::note::{Note, NoteIterator};
use serde_json::Value as JsonValue;

use super::RangeCover;
use crate::formats::common::bytes_at::{u32_le, u64_le};
use crate::formats::common::{hex_encode, put_str};
use crate::formats::goblin_safe;
use crate::metric;
use crate::output::{Errors, Metrics, Values};
use crate::value_key;

/// `.note.package` (`n_type = 0xCAFE1A7E`, vendor `"FDO"`) — FDO
/// Package Metadata. The descriptor is a JSON document with a fixed
/// schema (<https://systemd.io/COREDUMP_PACKAGE_METADATA/>): `name`,
/// `version`, `type` (`rpm`/`deb`/`apk`/…), `cpe`, `url`, `vcs`.
/// Strongest distro/package attestation any binary format offers —
/// Wolfi, Chainguard, Fedora 36+, recent systemd builds emit it.
/// Surfaced as the `elf.package` subtree with the JSON keys verbatim
/// (so trait authors write `elf.package.type == "apk"`).
pub(super) fn package(notes: &[Note<'_>], values: &mut Values) {
    for note in notes {
        if note.n_type != 0xCAFE_1A7E {
            continue;
        }
        // Trim trailing NULs — the section may pad up to 4 bytes.
        let Some(desc) = note.desc.split(|&b| b == 0).next() else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(desc) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<JsonValue>(text) else {
            continue;
        };
        if json.is_null() {
            continue;
        }
        values.insert_key(value_key!("elf.package"), json);
        return;
    }
}

/// `.note.ABI-tag` (`NT_GNU_ABI_TAG = 1`) — declares the minimum
/// kernel version the binary expects. The descriptor is four 32-bit
/// words: ABI (0 = Linux), major, minor, patch.
pub(super) fn abi_tag(notes: &[Note<'_>], values: &mut Values) {
    for note in notes {
        if note.name == "GNU" && note.n_type == 1 && note.desc.len() >= 16 {
            let words: [u32; 4] = [0, 1, 2, 3].map(|i| u32_le(note.desc, i * 4).unwrap_or(0));
            let os = match words[0] {
                0 => "linux",
                1 => "hurd",
                2 => "solaris",
                3 => "freebsd",
                4 => "netbsd",
                5 => "syllable",
                _ => "unknown",
            };
            let mut obj = serde_json::Map::new();
            obj.insert("os".into(), JsonValue::String(os.to_string()));
            obj.insert(
                "min_kernel".into(),
                JsonValue::String(format!("{}.{}.{}", words[1], words[2], words[3])),
            );
            values.insert_key(value_key!("elf.abi"), JsonValue::Object(obj));
            return;
        }
    }
}

/// `.note.gnu.property` (`NT_GNU_PROPERTY_TYPE_0 = 5`) — modern
/// hardening / ISA feature requirements. Names are
/// machine-dispatched because GNU's property numbering reuses
/// `0xc000_0000+` for both x86 (`X86_ISA_1_*`) and AArch64
/// (`AARCH64_FEATURE_*`). When we see an AArch64 PAUTH property
/// we also emit `elf.pauth_scheme` with the `platform:version`
/// pair that identifies the key-generation scheme.
pub(super) fn gnu_property(
    elf: &Elf<'_>,
    notes: &[Note<'_>],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let is_aarch64 = elf.header.e_machine == header::EM_AARCH64;
    for note in notes {
        if note.name != "GNU" || note.n_type != 5 {
            continue;
        }
        // Each property is `pr_type (u32) | pr_datasz (u32) | data | pad`
        // 8-byte aligned. Walk and collect names of known property types.
        let mut props = Vec::new();
        let mut off = 0;
        while off + 8 <= note.desc.len() {
            let pr_type = u32_le(note.desc, off).unwrap_or(0);
            let pr_datasz = u32_le(note.desc, off + 4).unwrap_or(0) as usize;
            let data_start = off + 8;
            let data_end = data_start.saturating_add(pr_datasz);
            if data_end > note.desc.len() {
                break;
            }
            if let Some(name) = gnu_property_name(pr_type, is_aarch64) {
                let mut entry = serde_json::Map::new();
                entry.insert("type".into(), JsonValue::String(name.to_string()));
                if pr_datasz == 4 {
                    let v = u32_le(note.desc, data_start).unwrap_or(0);
                    entry.insert("value".into(), JsonValue::String(format!("0x{v:x}")));
                    if is_aarch64 && pr_type == 0xC000_0000 {
                        // AARCH64_FEATURE_1_AND — bit-decomposed
                        // features that link-time enforcement
                        // requires (BTI / PAC / GCS).
                        let mut feats = Vec::new();
                        if v & 0x1 != 0 {
                            feats.push("bti");
                            metrics.insert(metric!("elf.has_aarch64_bti"), 1.0);
                        }
                        if v & 0x2 != 0 {
                            feats.push("pac");
                            metrics.insert(metric!("elf.has_aarch64_pac"), 1.0);
                        }
                        if v & 0x4 != 0 {
                            feats.push("gcs");
                        }
                        if !feats.is_empty() {
                            entry.insert(
                                "features".into(),
                                JsonValue::Array(
                                    feats
                                        .into_iter()
                                        .map(|s| JsonValue::String(s.into()))
                                        .collect(),
                                ),
                            );
                        }
                    } else if !is_aarch64 && pr_type == 0xC000_0002 {
                        // GNU_PROPERTY_X86_FEATURE_1_AND — Intel CET
                        // requirements stamped by the linker. bit 0 =
                        // IBT (Indirect Branch Tracking, shadow CFI),
                        // bit 1 = SHSTK (shadow stack).
                        if v & 0x1 != 0 {
                            metrics.insert(metric!("elf.has_cet_ibt"), 1.0);
                        }
                        if v & 0x2 != 0 {
                            metrics.insert(metric!("elf.has_cet_shstk"), 1.0);
                        }
                    } else if !is_aarch64 && pr_type == 0xC000_0001 {
                        // GNU_PROPERTY_X86_ISA_1_NEEDED — floor ISA
                        // level (v1/v2/v3/v4). Surface as a string so
                        // traits can match on the name.
                        let level = match v {
                            1 => Some("x86-64-v1"),
                            2 => Some("x86-64-v2"),
                            4 => Some("x86-64-v3"),
                            8 => Some("x86-64-v4"),
                            _ => None,
                        };
                        if let Some(s) = level {
                            put_str(values, value_key!("elf.x86_isa_level"), s);
                        }
                    }
                } else if is_aarch64 && pr_type == 0xC000_0001 && pr_datasz == 16 {
                    // AARCH64_FEATURE_PAUTH — 16 bytes, two u64
                    // words identifying the key-generation scheme.
                    let platform = u64_le(note.desc, data_start).unwrap_or(0);
                    let version = u64_le(note.desc, data_start + 8).unwrap_or(0);
                    let scheme = format!("{}:{}", pauth_platform_name(platform), version);
                    entry.insert(
                        "platform".into(),
                        JsonValue::String(pauth_platform_name(platform).into()),
                    );
                    entry.insert("version".into(), JsonValue::Number(version.into()));
                    put_str(values, value_key!("elf.pauth_scheme"), scheme);
                }
                props.push(JsonValue::Object(entry));
            }
            // 8-byte align
            off = (data_end + 7) & !7;
        }
        if !props.is_empty() {
            values.insert_key(value_key!("elf.gnu_property"), JsonValue::Array(props));
        }
        return;
    }
}

/// Map a GNU property type ID to its canonical name. AArch64
/// reuses the `0xC000_0000+` range for `AARCH64_FEATURE_*`, so the
/// dispatch keys off `elf.machine` to pick the right family.
pub(super) fn gnu_property_name(pr_type: u32, is_aarch64: bool) -> Option<&'static str> {
    match pr_type {
        0x0000_0001 => Some("stack_size"),
        0x0000_0002 => Some("no_copy_on_protected"),
        0xC000_0000 if is_aarch64 => Some("aarch64_feature_1_and"),
        0xC000_0001 if is_aarch64 => Some("aarch64_feature_pauth"),
        0xC000_0000 => Some("x86_isa_1_used"),
        0xC000_0001 => Some("x86_isa_1_needed"),
        0xC000_0002 => Some("x86_feature_1_and"),
        0xC000_0003 => Some("x86_feature_2_used"),
        0xC000_0004 => Some("x86_feature_2_needed"),
        0xC000_0005 => Some("x86_isa_1_and"),
        _ => None,
    }
}

/// Recognized PAUTH platforms (from `linux/include/uapi/asm-generic/aarch64-pauth.h`
/// and binutils `elfnn-aarch64.c`). `0` is the invalid/unspecified
/// platform; LLVM uses `0x10000002` for its default scheme.
pub(super) fn pauth_platform_name(platform: u64) -> &'static str {
    match platform {
        0 => "invalid",
        1 => "linux",
        0x1000_0002 => "llvm",
        _ => "unknown",
    }
}

pub(super) fn build_id(
    elf: &Elf<'_>,
    bytes: &[u8],
    segment_notes: &[Note<'_>],
    values: &mut Values,
    metrics: &mut Metrics,
    errors_out: &mut Errors,
) {
    // GNU build-id lives in a SHT_NOTE section named `.note.gnu.build-id`
    // (or `.gnu.build.attributes` in newer binutils), with a matching
    // PT_NOTE program header. Read it from the *section table* first: a
    // note-cavity infector flips that PT_NOTE program header to PT_LOAD
    // but leaves the section — and the ID — byte-identical, so a
    // segment-only walk (`iter_note_headers`) wrongly reports the ID as
    // gone and destroys the "identity retained, execution redirected"
    // evidence. Sections survive the repurposing; fall back to segments
    // only for stripped binaries that carry no section headers.
    let section_notes = drain(
        elf.iter_note_sections(bytes, None),
        &mut bytes.len(),
        errors_out,
    );
    let desc = gnu_build_id_desc(&section_notes).or_else(|| gnu_build_id_desc(segment_notes));
    if let Some(desc) = desc {
        put_str(values, value_key!("elf.build_id"), hex_encode(desc));
        metrics.insert(metric!("elf.has_build_id"), 1.0);
        metrics.insert(metric!("elf.build_id_length"), desc.len() as f64);
    }
}

/// First GNU build-id (`n_type == NT_GNU_BUILD_ID`, owner `GNU`) among
/// `notes`, or `None`.
fn gnu_build_id_desc<'a>(notes: &[Note<'a>]) -> Option<&'a [u8]> {
    notes
        .iter()
        .find(|note| note.name == "GNU" && note.n_type == 3)
        .map(|note| note.desc)
}

/// Every note a lazy goblin note walk yields, drained through `goblin_safe`.
/// Notes goblin rejects are skipped; `None` (no note segments or sections)
/// yields none.
///
/// Each note is charged its header, name and descriptor against `budget`
/// bytes, and the walk stops once one no longer fits. Note segments and
/// sections are file-controlled ranges that may all cover the same bytes:
/// 65535 `PT_NOTE` headers over one 1 MiB run of 12-byte notes is 5.7 billion
/// notes, and one long-named note re-read per header is `headers × run`
/// bytes. Honest note ranges are disjoint, so the file length is budget
/// enough for all of them.
pub(super) fn drain<'a>(
    notes: Option<NoteIterator<'a>>,
    budget: &mut usize,
    errors_out: &mut Errors,
) -> Vec<Note<'a>> {
    let walk = notes.into_iter().flatten().flatten().take_while(|note| {
        let size = 12usize
            .saturating_add(note.name.len())
            .saturating_add(note.desc.len());
        let Some(left) = budget.checked_sub(size) else {
            return false;
        };
        *budget = left;
        true
    });
    goblin_safe::drain_or_record(walk, errors_out, crate::Stage::ElfParse)
}

/// Flag `SHT_NOTE` sections whose bytes are not covered by any note
/// program header (`PT_NOTE` or `PT_GNU_PROPERTY`). Linkers emit every
/// note with a matching program header, so an uncovered note section is
/// the note-cavity tell: an infector flipped the note's program header
/// to an executable `PT_LOAD` and left the note — its GNU build-id
/// included — intact in the section table. This is the positive
/// "identity retained, execution redirected" signal that pairs with the
/// entry / segment changes.
///
/// Two metrics: `elf.uncovered_note_count` counts every orphaned
/// note section; `elf.build_id_uncovered` fires when the
/// orphaned note is specifically the GNU build-id — the identity
/// fingerprint present on disk yet invisible to the kernel / coredump /
/// debuginfod path that reads it through the program headers. Only
/// meaningful when the file has program headers (ET_EXEC / ET_DYN);
/// relocatable objects legitimately have none.
pub(super) fn segment_coverage(
    elf: &Elf<'_>,
    bytes: &[u8],
    metrics: &mut Metrics,
    errors_out: &mut Errors,
) {
    use goblin::elf::program_header::{PT_GNU_PROPERTY, PT_NOTE};
    use goblin::elf::section_header::SHT_NOTE;
    if elf.program_headers.is_empty() {
        return;
    }
    let note_ranges = RangeCover::new(
        elf.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_NOTE || ph.p_type == PT_GNU_PROPERTY)
            .map(|ph| (ph.p_offset, ph.p_offset.saturating_add(ph.p_filesz)))
            .collect(),
    );
    let ctx = goblin::container::Ctx::new(
        if elf.is_64 {
            goblin::container::Container::Big
        } else {
            goblin::container::Container::Little
        },
        if elf.little_endian {
            goblin::container::Endian::Little
        } else {
            goblin::container::Endian::Big
        },
    );
    // One note budget across every section re-read below.
    let mut note_budget = bytes.len();
    // SHF_ALLOC = 0x2. Only *loaded* notes are expected to have a note
    // program header — the loader reads them from memory. Non-allocated
    // notes (`.note.stapsdt` SystemTap probes, `.note.gnu.gold-version`,
    // packaging notes) legitimately have no PT_NOTE, so gating on
    // SHF_ALLOC keeps a benign static binary from tripping this.
    const SHF_ALLOC: u64 = 0x2;
    let mut uncovered = 0u64;
    let mut build_id_orphaned = false;
    for sh in &elf.section_headers {
        if sh.sh_type != SHT_NOTE || sh.sh_size == 0 || sh.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        let start = sh.sh_offset;
        let end = sh.sh_offset.saturating_add(sh.sh_size);
        if note_ranges.contains(start, end) {
            continue;
        }
        uncovered += 1;
        if build_id_orphaned {
            continue;
        }
        // Is the orphaned note the GNU build-id? Read back this section's
        // own notes, so the check is independent of ordering and names.
        let offset = crate::bytes::sat_usize(start);
        let walk = goblin::elf::note::NoteIterator {
            iters: vec![goblin::elf::note::NoteDataIterator {
                data: bytes,
                offset,
                size: offset.saturating_add(crate::bytes::sat_usize(sh.sh_size)),
                ctx: (crate::bytes::sat_usize(sh.sh_addralign), ctx),
            }],
            index: 0,
        };
        let notes = drain(Some(walk), &mut note_budget, errors_out);
        build_id_orphaned = gnu_build_id_desc(&notes).is_some();
    }
    if uncovered > 0 {
        metrics.insert(metric!("elf.uncovered_note_count"), uncovered as f64);
    }
    if build_id_orphaned {
        metrics.insert(metric!("elf.build_id_uncovered"), 1.0);
    }
}
