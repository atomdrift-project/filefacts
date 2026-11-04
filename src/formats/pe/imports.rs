//! The import directory, its imphash, bound imports, and delay-load imports.

use goblin::pe::PE;
use goblin::pe::optional_header::MAGIC_64;
use serde_json::Value as JsonValue;

use super::layout::rva_to_file_offset;
use super::{ordinal_names, ordinals};
use crate::formats::common::bytes_at::{u16_le, u32_le, u64_le};
use crate::formats::common::{hex_encode, put_str};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

pub(super) fn imports(
    layout: &binform::Binary<'_>,
    image_base: u64,
    machine: u16,
    table_skipped: bool,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    // binform reads the import table and then the delay-load table, one
    // entry per slot, the DLL name as the binary spells it. The library lands
    // in the typed view as its lowercase stem (no `.dll` / `.ocx` / `.sys`),
    // so consumers match `library == "kernel32"` without case or extension
    // juggling. An import table too large to walk (see
    // `goblin_safe::prepare_pe`) contributes nothing, as it never did.
    let cpu = Cpu::of_machine(machine);
    let mut libraries = std::collections::BTreeSet::new();
    let mut table = Vec::new();
    let mut delayed = 0_u64;
    for imp in &layout.imports {
        if imp.delayed {
            // Descriptors may share one name table; real binaries delay-load
            // tens to hundreds of functions.
            if delayed >= MAX_DELAY_IMPORTS {
                continue;
            }
            delayed += 1;
        } else if table_skipped {
            continue;
        } else {
            libraries.insert(imp.library.as_deref().unwrap_or(""));
            table.push(imp);
        }
        let dll = imp.library.as_deref().unwrap_or("").to_ascii_lowercase();
        // An import by ordinal from a DLL whose ordinals are known goes by
        // the name the DLL exports there; `ordinal` keeps the number.
        let name = match imp.ordinal {
            Some(ordinal) => known_ordinal(&dll, ordinal, cpu)
                .map_or_else(|| format!("ORDINAL {ordinal}"), str::to_owned),
            None => imp.name.clone(),
        };
        symbols_out.push(crate::Symbol::Import {
            name,
            alias: None,
            library: Some(strip_lib_ext(&dll).to_string()),
            // The RVA of the slot the loader fills.
            offset: imp.slot.map(|slot| slot.wrapping_sub(image_base)),
            ordinal: imp.ordinal.map(u32::from),
        });
    }
    // DLL dependencies (the libraries imports are bound to) flow through the
    // cross-format `dependencies.count`; the symbol total is `imports.count`.
    metrics.insert(metric!("dependencies.count"), libraries.len() as f64);

    if let Some(hash) = imphash(&table) {
        put_str(values, value_key!("pe.hashes.imphash"), hash);
    }
}

/// The most delay-load imports counted, and taken into the symbol view,
/// across every descriptor. Descriptors may all share one name table, so
/// a few kilobytes can claim half a million symbols; real binaries
/// delay-load tens to hundreds of functions.
const MAX_DELAY_IMPORTS: u64 = 16 * 1024;

/// The *imphash* as pefile and VirusTotal compute it: the MD5 of the
/// comma-joined, lowercased `library.function` list in import-table order,
/// each library stripped of a `.dll` / `.ocx` / `.sys` extension. An import
/// by ordinal is named from pefile's tables for `ws2_32.dll`, `wsock32.dll`
/// and `oleaut32.dll`, and as `ord<n>` otherwise. `None` for an empty import
/// table.
///
/// The hash was popularised by Mandiant and remains the standard
/// per-import-table fingerprint for malware-family clustering; it only
/// clusters with other tools' output when it is computed the same way.
fn imphash(imports: &[&binform::Import]) -> Option<String> {
    use md5::{Digest, Md5};

    if imports.is_empty() {
        return None;
    }
    let parts: Vec<String> = imports
        .iter()
        .map(|imp| {
            let dll = imp.library.as_deref().unwrap_or("").to_ascii_lowercase();
            let function = match imp.ordinal {
                Some(ordinal) => ordinal_name(&dll, ordinal),
                None => imp.name.clone(),
            };
            format!("{}.{}", strip_lib_ext(&dll), function.to_ascii_lowercase())
        })
        .collect();
    Some(hex_encode(&Md5::digest(parts.join(",").as_bytes())))
}

/// pefile's `ordlookup.ordLookup(dll, ordinal, make_name=True)` for a
/// lowercased `dll`: its three tables only, so the imphash matches pefile's.
fn ordinal_name(dll: &str, ordinal: u16) -> String {
    pefile_ordinal(dll, ordinal).map_or_else(|| format!("ord{ordinal}"), str::to_owned)
}

/// The name pefile's `ordlookup` gives `dll`'s (lowercase, with its
/// extension) export at `ordinal`.
fn pefile_ordinal(dll: &str, ordinal: u16) -> Option<&'static str> {
    lookup(
        match dll {
            "ws2_32.dll" => ordinals::WS2_32,
            "wsock32.dll" => ordinals::WSOCK32,
            "oleaut32.dll" => ordinals::OLEAUT32,
            _ => &[],
        },
        ordinal,
    )
}

/// The name `dll` (lowercase, with its extension) exports at `ordinal`, for
/// the DLLs whose ordinals are stable across Windows releases: pefile's, and
/// those programs import by ordinal from `ordinal_names.rs`. For naming
/// imports; the imphash takes pefile's alone.
pub(in crate::formats) fn known_ordinal(
    dll: &str,
    ordinal: u16,
    cpu: Option<Cpu>,
) -> Option<&'static str> {
    // Windows CE's coredll numbers some exports differently per CPU: those
    // ordinals are named only when the CPU is known.
    let per_cpu = match (dll, cpu) {
        ("coredll.dll", Some(Cpu::X86)) => ordinal_names::COREDLL_X86,
        ("coredll.dll", Some(Cpu::Arm)) => ordinal_names::COREDLL_ARM,
        ("coredll.dll", Some(Cpu::Mips)) => ordinal_names::COREDLL_MIPS,
        ("coredll.dll", Some(Cpu::SuperH)) => ordinal_names::COREDLL_SH,
        _ => &[],
    };
    pefile_ordinal(dll, ordinal)
        .or_else(|| lookup(per_cpu, ordinal))
        .or_else(|| {
            lookup(
                match dll {
                    "msi.dll" => ordinal_names::MSI,
                    "comctl32.dll" => ordinal_names::COMCTL32,
                    "cabinet.dll" => ordinal_names::CABINET,
                    "mfc42.dll" => ordinal_names::MFC42,
                    "mfc42u.dll" => ordinal_names::MFC42U,
                    "coredll.dll" => ordinal_names::COREDLL,
                    "commctrl.dll" => ordinal_names::COMMCTRL,
                    _ => &[],
                },
                ordinal,
            )
        })
}

/// The CPU families whose DLLs number exports differently: Windows CE's
/// coredll, built for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::formats) enum Cpu {
    X86,
    Arm,
    Mips,
    SuperH,
}

impl Cpu {
    /// The family of a PE's COFF `Machine`.
    pub(in crate::formats) fn of_machine(machine: u16) -> Option<Self> {
        match machine {
            0x014c => Some(Self::X86),
            // ARM, Thumb (Windows CE's ARMV4I).
            0x01c0 | 0x01c2 => Some(Self::Arm),
            // R4000, WCEMIPSV2, MIPS16, MIPSFPU, MIPSFPU16.
            0x0166 | 0x0169 | 0x0266 | 0x0366 | 0x0466 => Some(Self::Mips),
            // SH3, SH3DSP, SH3E, SH4.
            0x01a2..=0x01a4 | 0x01a6 => Some(Self::SuperH),
            _ => None,
        }
    }
}

/// `table`'s name for `ordinal`; the table is sorted by ordinal.
fn lookup(table: &'static [(u16, &'static str)], ordinal: u16) -> Option<&'static str> {
    table
        .binary_search_by_key(&ordinal, |&(n, _)| n)
        .ok()
        .and_then(|i| table.get(i))
        .map(|&(_, name)| name)
}

/// `lib` without one trailing `.dll`, `.ocx` or `.sys`, the extensions the
/// imphash definition strips. Anything else is preserved verbatim.
fn strip_lib_ext(lib: &str) -> &str {
    [".dll", ".ocx", ".sys"]
        .into_iter()
        .find_map(|ext| lib.strip_suffix(ext))
        .unwrap_or(lib)
}

/// Parse the `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` table (data
/// directory index 11). Unlike every other data directory entry, the
/// `VirtualAddress` here is a **file offset**, not an RVA — the table
/// lives in the headers between the data directories and the section
/// table. Each `IMAGE_BOUND_IMPORT_DESCRIPTOR` is 8 bytes; an all-zero
/// descriptor terminates the list, and module-name offsets are
/// relative to the start of the bound-import table.
///
/// The loader rebinds on any mismatch, so modern toolchains rarely emit the
/// table and finding one is itself a build-pipeline fingerprint. goblin does
/// not parse it, so the walk here is self-contained and bounds-checked.
///
/// Emits to values:
/// - `pe.bound_imports[]` — array of `{name, time_date_stamp,
///   forwarder_ref_count}` objects, capped at 64 entries.
///
/// Emits to metrics:
/// - `pe.bound_import_count` — number of descriptors recovered.
/// - `pe.bound_imports_fingerprint` — CRC-32 of the canonical-sorted
///   set. Useful for "binaries linked on the same host within seconds
///   get the same fingerprint" clustering.
pub(super) fn bound_imports(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_bound_import_table() else {
        return;
    };
    let table_off = dd.virtual_address as usize;
    let table_size = dd.size as usize;
    if table_size == 0 || table_off >= bytes.len() {
        return;
    }
    let end = table_off.saturating_add(table_size).min(bytes.len());
    let Some(table) = bytes.get(table_off..end) else {
        return;
    };

    struct Desc {
        name: String,
        time_date_stamp: u32,
        forwarder_ref_count: u32,
    }
    let mut out: Vec<Desc> = Vec::new();
    let mut cursor = 0_usize;
    while out.len() < 64 {
        // A descriptor is 8 bytes; a short tail ends the table.
        let (Some(time_date), Some(name_off), Some(forwarder_count)) = (
            u32_le(table, cursor),
            u16_le(table, cursor.saturating_add(4)),
            u16_le(table, cursor.saturating_add(6)),
        ) else {
            break;
        };
        let name_off = usize::from(name_off);
        let forwarder_count = u32::from(forwarder_count);

        // All-zero descriptor terminates the list.
        if time_date == 0 && name_off == 0 && forwarder_count == 0 {
            break;
        }
        if let Some(tail) = table.get(name_off..table.len().min(name_off + 256)) {
            let name = tail.split(|b| *b == 0).next().unwrap_or_default();
            if let Ok(name) = std::str::from_utf8(name)
                && !name.is_empty()
            {
                out.push(Desc {
                    name: name.to_string(),
                    time_date_stamp: time_date,
                    forwarder_ref_count: forwarder_count,
                });
            }
        }
        cursor = cursor.saturating_add(8 + (forwarder_count as usize).saturating_mul(8));
    }
    if out.is_empty() {
        return;
    }

    let modules: Vec<JsonValue> = out
        .iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "time_date_stamp": d.time_date_stamp,
                "forwarder_ref_count": d.forwarder_ref_count,
            })
        })
        .collect();
    values.insert_key(value_key!("pe.bound_imports"), JsonValue::Array(modules));

    metrics.insert(metric!("pe.bound_import_count"), out.len() as f64);
    // CRC-32 fingerprint over the canonical-sorted set so the
    // linker's emission order doesn't change clustering.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    let mut hasher = crc32fast::Hasher::new();
    for d in &out {
        hasher.update(d.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(&d.time_date_stamp.to_le_bytes());
        hasher.update(&d.forwarder_ref_count.to_le_bytes());
    }
    metrics.insert(
        metric!("pe.bound_imports_fingerprint"),
        f64::from(hasher.finalize()),
    );
}

/// IMAGE_DELAYLOAD_DESCRIPTOR table walker. Delay-load imports are
/// resolved on first call rather than at process startup, so they
/// don't appear in the regular IAT / Import Directory — pefile sees
/// them via `DIRECTORY_ENTRY_DELAY_IMPORT`. They are forensically
/// important: evasive malware moves anti-analysis APIs
/// (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
/// `VirtualProtect` for code-patching, network primitives) into the
/// delay-load table so a static IAT scan misses them.
///
/// Emits `pe.delay_imports[]` (one descriptor per DLL with timestamp,
/// rva_based flag, and import count). The imports themselves reach the
/// typed [`crate::Symbols`] view from binform's table, with the rest (see
/// [`imports`]).
pub(super) fn delay_imports(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_delay_import_descriptor() else {
        return;
    };
    if dd.virtual_address == 0 || dd.size == 0 {
        return;
    }
    let Some(table_off) = rva_to_file_offset(pe, dd.virtual_address) else {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "delay-imports",
            rva = dd.virtual_address,
            "delay-import directory maps to no file bytes"
        );
        return;
    };
    let is_64 = opt.standard_fields.magic == MAGIC_64;
    let ptr_size = if is_64 { 8 } else { 4 };
    let image_base = opt.windows_fields.image_base;
    const DESC_SIZE: usize = 32; // IMAGE_DELAYLOAD_DESCRIPTOR is 8 DWORDs
    const MAX_DESCRIPTORS: usize = 128;
    const MAX_FUNCTIONS_PER_DLL: usize = 4096;

    let mut entries_out: Vec<JsonValue> = Vec::new();
    let mut total_imports = 0_u64;
    let mut cursor = table_off;
    let mut desc_idx = 0;
    while desc_idx < MAX_DESCRIPTORS && total_imports < MAX_DELAY_IMPORTS {
        let Some(desc) = bytes.get(cursor..cursor.saturating_add(DESC_SIZE)) else {
            break;
        };
        let field = |at: usize| u32_le(desc, at).unwrap_or(0);
        let attrs = field(0);
        let name_va = field(4);
        // ModuleHandle (8) and the IAT (12) are runtime state.
        let int_va = field(16);
        // BoundIAT (20) and UnloadIAT (24) are runtime caches too.
        let timestamp = field(28);
        cursor += DESC_SIZE;
        desc_idx += 1;

        if attrs == 0 && name_va == 0 && int_va == 0 {
            break; // all-zero descriptor terminates the list
        }
        // Attributes bit 0 (`RvaBased`) tells us whether `name`/`iat`/`int`
        // are RVAs (modern linkers) or absolute VAs (VC6-era linkers).
        let rva_based = attrs & 1 != 0;
        let to_rva = |v: u32| delay_import_rva(v, rva_based, image_base);

        let dll = rva_to_file_offset(pe, to_rva(name_va))
            .map(|off| cstring_at(bytes, off))
            .unwrap_or_default();
        if dll.is_empty() {
            continue;
        }
        // Count the Import Name Table's pointer-sized entries, up to the
        // zero that ends it.
        let mut function_count = 0_u64;
        if let Some(mut int_off) = rva_to_file_offset(pe, to_rva(int_va)) {
            let budget = MAX_DELAY_IMPORTS - total_imports;
            for _ in 0..MAX_FUNCTIONS_PER_DLL.min(crate::bytes::sat_usize(budget)) {
                let entry = if is_64 {
                    u64_le(bytes, int_off)
                } else {
                    u32_le(bytes, int_off).map(u64::from)
                };
                let Some(entry) = entry else {
                    break;
                };
                int_off += ptr_size;
                if entry == 0 {
                    break;
                }
                function_count += 1;
            }
        }
        total_imports = total_imports.saturating_add(function_count);

        entries_out.push(serde_json::json!({
            "dll": dll,
            "rva_based": rva_based,
            "time_date_stamp": timestamp,
            "import_count": function_count,
        }));
    }

    if !entries_out.is_empty() {
        values.insert_key(
            value_key!("pe.delay_imports"),
            JsonValue::Array(entries_out),
        );
        metrics.insert(metric!("pe.delay_import_count"), total_imports as f64);
    }
}

/// Resolve a delay-load descriptor field to an RVA. `RvaBased` descriptors
/// already hold RVAs; the older ones hold VAs, which only fit the 32-bit
/// field under a PE32 image base. Subtracting in 64 bits keeps a PE32+ base
/// from being truncated to a low half that a forged VA can then match.
fn delay_import_rva(value: u32, rva_based: bool, image_base: u64) -> u32 {
    if rva_based {
        return value;
    }
    // The difference never exceeds `value`, so it always fits.
    u32::try_from(u64::from(value).saturating_sub(image_base)).unwrap_or(0)
}

/// The NUL-terminated string at file offset `off`, capped at 512 bytes, or
/// empty when it is not UTF-8 (DLL and function names are ASCII by spec).
fn cstring_at(bytes: &[u8], off: usize) -> String {
    let cap = bytes.len().min(off.saturating_add(512));
    let Some(tail) = bytes.get(off..cap) else {
        return String::new();
    };
    let name = tail.split(|&b| b == 0).next().unwrap_or_default();
    std::str::from_utf8(name).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests;
