//! The export table and the code shapes at its entry points.

use std::collections::HashMap;

use goblin::pe::PE;
use goblin::pe::export::Reexport;
use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};

use super::layout::{file_backed_size, rva_to_file_offset};
use crate::formats::common::put_i64;
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// `IMAGE_SCN_MEM_EXECUTE`.
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

pub(super) fn exports(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    let mut forwarded_count: u32 = 0;
    for exp in &pe.exports {
        let Some(name) = exp.name else { continue };
        // PE forwarded exports come in two shapes (per
        // `IMAGE_EXPORT_DIRECTORY` §6.3.1): `DLL.symbol` and
        // `DLL.#ordinal`. Both are serialised back into a single
        // string so consumers don't have to switch on a
        // discriminator. When the entry is a normal export
        // (RVA points at this binary's own code/data), `forward_to`
        // stays `None`.
        let forward_to = match exp.reexport {
            Some(Reexport::DLLName { export, lib }) => Some(format!("{lib}.{export}")),
            Some(Reexport::DLLOrdinal { ordinal, lib }) => Some(format!("{lib}.#{ordinal}")),
            None => None,
        };
        forwarded_count = forwarded_count.saturating_add(u32::from(forward_to.is_some()));
        // The RVA, not the file offset: it is what `dumpbin /exports`, IDA,
        // Ghidra and the PE specification key exports by.
        symbols_out.push(crate::Symbol::Export {
            name: name.to_string(),
            offset: Some(exp.rva as u64),
            ordinal: None,
            forward_to,
        });
    }
    // Export count flows through cross-format `exports.count`.
    if forwarded_count > 0 {
        metrics.insert(
            metric!("pe.forwarded_export_count"),
            f64::from(forwarded_count),
        );
    }
    // Export-directory timestamp lives inside IMAGE_EXPORT_DIRECTORY
    // and is distinct from the COFF header's `pe.timestamp`. Supply-
    // chain tampering sometimes rewrites one without touching the
    // other, so emit it independently. Zero is a sentinel meaning
    // "unset" — linkers can elect to leave it untouched.
    if let Some(export_data) = &pe.export_data {
        let ts = export_data.export_directory_table.time_date_stamp;
        if ts != 0 {
            put_i64(values, value_key!("pe.export_timestamp"), i64::from(ts));
            metrics.insert(metric!("pe.export_timestamp"), f64::from(ts));
        }
    }
    entry_code_shapes(pe, bytes, metrics);
}

/// One decoding pass over the code at every export's entry, for two shapes:
///
/// - `pe.aliased_export_count` — exports whose first instruction lands on
///   the same place: a direct jump or call to a shared target, or the same
///   entry RVA. Proxy and hijack DLLs alias hundreds of exports onto one stub.
/// - `pe.exports_max_shared_early_call_count` — the most named,
///   non-forwarded exports in executable sections whose first straight-line
///   instructions make the same direct call. This reports a code shape; it
///   does not establish invocation or the callee's behavior.
fn entry_code_shapes(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    if pe.exports.is_empty() {
        return;
    }
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let bitness = match opt.standard_fields.magic {
        MAGIC_32 => 32,
        MAGIC_64 => 64,
        _ => return,
    };
    let alignment = Some(opt.windows_fields.file_alignment);
    let mut first_targets: HashMap<u64, u32> = HashMap::new();
    let mut early_calls: HashMap<u64, u32> = HashMap::new();
    for export in &pe.exports {
        let Ok(rva) = u32::try_from(export.rva) else {
            continue;
        };
        let Some(offset) = rva_to_file_offset(pe, rva) else {
            continue;
        };
        let ip = u64::from(rva);
        // An x86 instruction is at most 15 bytes, so 16 hold the first whole.
        if let Some(code) = bytes.get(offset..offset.saturating_add(16))
            && let Some(first) = Decoder::with_ip(bitness, code, ip, DecoderOptions::NONE)
                .iter()
                .next()
        {
            let target = match first.mnemonic() {
                Mnemonic::Jmp | Mnemonic::Call if first.near_branch_target() != 0 => {
                    first.near_branch_target()
                }
                _ => ip,
            };
            *first_targets.entry(target).or_default() += 1;
        }

        if export.name.is_none() || export.reexport.is_some() {
            continue;
        }
        // The same first-match rule as the RVA mapper, including its
        // loader-aligned raw extent: overlapping section headers must not
        // let an executable section bless bytes mapped from another section.
        let Some(section) = pe.sections.iter().find(|s| {
            rva.checked_sub(s.virtual_address)
                .is_some_and(|delta| u64::from(delta) < file_backed_size(s, alignment))
        }) else {
            continue;
        };
        if section.characteristics & SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let available =
            file_backed_size(section, alignment) - u64::from(rva - section.virtual_address);
        let end = offset
            .saturating_add(usize::try_from(available.min(64)).unwrap_or(0))
            .min(bytes.len());
        let Some(code) = bytes.get(offset..end) else {
            continue;
        };
        for target in early_direct_calls(code, ip, bitness) {
            *early_calls.entry(target).or_default() += 1;
        }
    }
    let aliased: u32 = first_targets.values().filter(|&&c| c > 1).sum();
    if aliased > 0 {
        metrics.insert(metric!("pe.aliased_export_count"), f64::from(aliased));
    }
    if let Some(&max) = early_calls.values().max().filter(|&&n| n >= 2) {
        metrics.insert(
            metric!("pe.exports_max_shared_early_call_count"),
            f64::from(max),
        );
    }
}

/// The distinct direct call targets in the first twelve straight-line
/// instructions of `code`.
fn early_direct_calls(code: &[u8], rva: u64, bitness: u32) -> Vec<u64> {
    let mut targets = Vec::new();
    let decoder = Decoder::with_ip(bitness, code, rva, DecoderOptions::NONE);
    for ins in decoder.into_iter().take(12) {
        if ins.is_invalid() {
            break;
        }
        match ins.flow_control() {
            FlowControl::Call => {
                if matches!(
                    ins.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    let target = ins.near_branch_target();
                    if !targets.contains(&target) {
                        targets.push(target);
                    }
                }
            }
            FlowControl::Next => {}
            // A branch, return, exception or indirect call ends the straight
            // line; do not claim calls beyond it are on this entry path.
            _ => break,
        }
    }
    targets
}

#[cfg(test)]
mod tests;
