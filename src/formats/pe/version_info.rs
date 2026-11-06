//! VS_VERSIONINFO resource extractor.
//!
//! The `.rsrc` section of a PE carries a `VS_VERSIONINFO` structure
//! (type `RT_VERSION`, ID 16) populated by the linker from the
//! source-tree's `.rc` file. The forensically relevant content lives
//! in two children:
//!
//! - **`VS_FIXEDFILEINFO`** — packed version numbers, flags, target OS
//!   class, file type / subtype, date.
//! - **`StringFileInfo` → `StringTable` → `String`** — the per-locale
//!   name/value pairs every analyst recognises: `CompanyName`,
//!   `ProductName`, `OriginalFilename`, `FileVersion`,
//!   `LegalCopyright`, …
//!
//! One bounded walk of the resource directory finds the `RT_VERSION`
//! leaves, and one walk of each leaf's block tree reads both children: the
//! strings flatten to snake_case `pe.version.*` leaves (`pe.version.company`,
//! `pe.version.file_version`, …), each with the file offset of its value,
//! and `VS_FIXEDFILEINFO` decomposes into `pe.version.{os,type,subtype,flags}`
//! with format-conventional names — flag bits as a sorted string array, OS
//! class as a stable label. The same walk serves an image goblin parsed and
//! one it could not, given a section table.

use crate::metric;
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::resource::{IMAGE_RESOURCE_DATA_IS_DIRECTORY, RT_VERSION};
use goblin::pe::section_table::SectionTable;
use serde_json::Value as JsonValue;

use super::layout::section_rva_to_file_offset;
use crate::bytes::{u16_le, u32_le};
use crate::formats::common::{put_str, put_u64};
use crate::output::{Metrics, ValueKey, Values};
use crate::scan::entropy;
use crate::value_key;

/// Read the `RT_VERSION` resources under the resource directory `resources`
/// into `pe.version.*`, resolving RVAs through `sections`. Returns whether
/// there was a `VS_VERSIONINFO` resource.
pub(super) fn extract(
    sections: &[SectionTable],
    file_alignment: Option<u32>,
    resources: DataDirectory,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> bool {
    let mut info = VersionInfo::default();
    let mut found = false;
    for (off, len) in version_leaves(sections, file_alignment, resources, bytes) {
        let end = off.saturating_add(len);
        let (key, _) = read_utf16_key(bytes, off.saturating_add(6), end);
        if key != "VS_VERSION_INFO" {
            continue;
        }
        found = true;
        let mut budget = MAX_VERSION_NODES;
        walk_version_block(bytes, off, end, 0, &mut budget, &mut info);
    }
    info.emit(values, metrics);
    found
}

/// `StringFileInfo` keys and the `pe.version.*` leaves their value and its
/// file offset land at: snake_case, no `_name` filler when unambiguous, no
/// `Legal` prefix on copyright and trademarks.
const STRING_FIELDS: [(&str, ValueKey, ValueKey); 12] = [
    (
        "Comments",
        value_key!("pe.version.comments"),
        value_key!("pe.version.comments_offset"),
    ),
    (
        "CompanyName",
        value_key!("pe.version.company"),
        value_key!("pe.version.company_offset"),
    ),
    (
        "FileDescription",
        value_key!("pe.version.description"),
        value_key!("pe.version.description_offset"),
    ),
    (
        "FileVersion",
        value_key!("pe.version.file_version"),
        value_key!("pe.version.file_version_offset"),
    ),
    (
        "InternalName",
        value_key!("pe.version.internal_name"),
        value_key!("pe.version.internal_name_offset"),
    ),
    (
        "LegalCopyright",
        value_key!("pe.version.copyright"),
        value_key!("pe.version.copyright_offset"),
    ),
    (
        "LegalTrademarks",
        value_key!("pe.version.trademarks"),
        value_key!("pe.version.trademarks_offset"),
    ),
    (
        "OriginalFilename",
        value_key!("pe.version.original_filename"),
        value_key!("pe.version.original_filename_offset"),
    ),
    (
        "PrivateBuild",
        value_key!("pe.version.private_build"),
        value_key!("pe.version.private_build_offset"),
    ),
    (
        "ProductName",
        value_key!("pe.version.product_name"),
        value_key!("pe.version.product_name_offset"),
    ),
    (
        "ProductVersion",
        value_key!("pe.version.product_version"),
        value_key!("pe.version.product_version_offset"),
    ),
    (
        "SpecialBuild",
        value_key!("pe.version.special_build"),
        value_key!("pe.version.special_build_offset"),
    ),
];

/// What the block walk read: each known string's value and the file offset
/// of its value, by its index in [`STRING_FIELDS`], and the fixed info. The
/// first string table to name a key wins.
#[derive(Default)]
struct VersionInfo {
    strings: [Option<(String, usize)>; STRING_FIELDS.len()],
    fixed: Option<FixedFileInfo>,
}

/// The `VS_FIXEDFILEINFO` fields `pe.version.*` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedFileInfo {
    file_flags_mask: u32,
    file_flags: u32,
    file_os: u32,
    file_type: u32,
    file_subtype: u32,
}

/// `VS_FIXEDFILEINFO.dwSignature`.
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xfeef_04bd;
/// `sizeof(VS_FIXEDFILEINFO)`.
const FIXED_FILE_INFO_LEN: usize = 52;

impl FixedFileInfo {
    /// The structure at `off`, when it carries its signature.
    fn read(bytes: &[u8], off: usize) -> Option<Self> {
        let field = |at: usize| u32_le(bytes, off.checked_add(at)?);
        (field(0)? == FIXED_FILE_INFO_SIGNATURE).then_some(())?;
        Some(Self {
            file_flags_mask: field(24)?,
            file_flags: field(28)?,
            file_os: field(32)?,
            file_type: field(36)?,
            file_subtype: field(40)?,
        })
    }
}

impl VersionInfo {
    /// The value of the string `key` names, when the walk read one.
    fn string(&self, key: &str) -> Option<&str> {
        let index = STRING_FIELDS.iter().position(|(name, ..)| *name == key)?;
        let (value, _) = self.strings.get(index)?.as_ref()?;
        Some(value)
    }

    fn emit(&self, values: &mut Values, metrics: &mut Metrics) {
        if let Some(fixed) = self.fixed {
            fixed_file_info(&fixed, values);
        }
        for ((_, value_key, offset_key), string) in STRING_FIELDS.iter().zip(&self.strings) {
            if let Some((value, offset)) = string {
                put_str(values, *value_key, value.as_str());
                put_u64(values, *offset_key, *offset as u64);
            }
        }
        identity_metrics(self, metrics);
    }
}

/// Maximum VS_VERSIONINFO tree depth honoured while indexing value offsets.
/// Real resources are 4 levels (root → StringFileInfo → StringTable → String);
/// the cap bounds recursion (stack) depth only. Total work is bounded by
/// clamping each child to its parent and by [`MAX_VERSION_NODES`].
const MAX_VERSION_DEPTH: u8 = 8;

/// Maximum blocks visited in one VS_VERSIONINFO walk. A real resource holds
/// about a dozen strings per locale; this leaves room for many locales while
/// capping the work a forged blob can demand.
const MAX_VERSION_NODES: usize = 4096;

/// Read a UTF-16LE NUL-terminated key at `pos`, returning `(key, offset just
/// past the terminator)`. Bounded by `end`.
fn read_utf16_key(bytes: &[u8], pos: usize, end: usize) -> (String, usize) {
    let window = bytes.get(pos..end.min(bytes.len())).unwrap_or_default();
    let key = crate::bytes::utf16_until_nul(window);
    // Step over the terminator when the window holds one.
    let consumed = (key.len() + 2).min(window.len() & !1);
    (
        crate::bytes::utf16_lossy(key, crate::bytes::Endian::Little),
        pos + consumed,
    )
}

/// Round `n` up to the next 4-byte boundary (VS_VERSIONINFO blocks are
/// DWORD-aligned).
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Walk one length-prefixed VS_VERSIONINFO block at `off` (a file offset into
/// `bytes`): `{u16 wLength, u16 wValueLength, u16 wType, WCHAR szKey[], pad,
/// Value, pad, Children}`. Reads the root's `VS_FIXEDFILEINFO` and every
/// `String` block whose key is in [`STRING_FIELDS`] into `info`, then
/// recurses into children. Fully bounds- and depth-checked: this parses
/// untrusted resource bytes.
///
/// `limit` is the parent's end: a block claiming to run past it is clamped
/// there, so sibling subtrees cannot overlap and no byte is walked twice.
/// `budget` counts down the blocks the whole walk may still visit.
fn walk_version_block(
    bytes: &[u8],
    off: usize,
    limit: usize,
    depth: u8,
    budget: &mut usize,
    info: &mut VersionInfo,
) {
    if depth >= MAX_VERSION_DEPTH || *budget == 0 || off.saturating_add(6) > limit {
        return;
    }
    *budget -= 1;
    let Some(&[l0, l1, v0, v1, t0, t1]) = bytes.get(off..).and_then(<[u8]>::first_chunk::<6>)
    else {
        return;
    };
    let w_length = usize::from(u16::from_le_bytes([l0, l1]));
    let w_value_length = usize::from(u16::from_le_bytes([v0, v1]));
    let w_type = u16::from_le_bytes([t0, t1]);
    let block_end = off.saturating_add(w_length).min(limit);
    if w_length < 6 || block_end <= off {
        return; // zero/short length — stop rather than loop
    }

    let (key, key_end) = read_utf16_key(bytes, off + 6, block_end);
    let value_off = align4(key_end);
    // Text values count WCHARs; binary values count bytes.
    let value_bytes = if w_type == 1 {
        w_value_length * 2
    } else {
        w_value_length
    };
    let value = value_off
        .checked_add(value_bytes)
        .filter(|&end| end <= block_end)
        .and_then(|end| bytes.get(value_off..end));

    if depth == 0 && value_bytes >= FIXED_FILE_INFO_LEN && value.is_some() {
        info.fixed = info.fixed.or_else(|| FixedFileInfo::read(bytes, value_off));
    }
    if w_type == 1
        && let Some(index) = STRING_FIELDS.iter().position(|(name, ..)| *name == key)
        && let Some(slot) = info.strings.get_mut(index)
        && slot.is_none()
        && let Some(data) = value.filter(|data| data.len() >= 2)
    {
        let text = crate::bytes::utf16_lossy(
            crate::bytes::utf16_until_nul(data),
            crate::bytes::Endian::Little,
        );
        *slot = Some((text, value_off));
    }

    // Children follow the value, DWORD-aligned, up to this block's end.
    let mut child = align4(value_off.saturating_add(value_bytes));
    while child.saturating_add(6) <= block_end {
        let Some(child_len) = u16_le(bytes, child) else {
            break;
        };
        let child_len = usize::from(child_len);
        if child_len < 6 {
            break;
        }
        walk_version_block(bytes, child, block_end, depth + 1, budget, info);
        child = align4(child.saturating_add(child_len));
    }
}

/// Emit randomness/non-linguisticness metrics over the human-readable identity
/// fields (CompanyName + ProductName + FileDescription). Crypter stubs routinely
/// XOR/shift the VERSIONINFO string table, leaving garbage that no legitimate
/// vendor field carries. A charset trait only catches scrambles that land on
/// symbol bytes; these metrics also catch alphanumeric-range scrambles and are
/// harder to evade than a fixed character class.
///
/// - `pe.version.identity_entropy` — Shannon bits/char over the concatenated
///   identity fields. Length-guarded: emitted only when the concatenation is at
///   least 16 chars, below which the estimate is too noisy to threshold.
/// - `pe.version.identity_symbol_ratio` — fraction of chars that are neither
///   letters (incl. non-ASCII letters, so CJK/transliterated names score low)
///   nor whitespace. Real names are letters + spaces; scrambles interleave
///   digits and punctuation.
///
/// The two are meant to be ANDed in a composite: high entropy alone FPs on long
/// non-English names, high symbol ratio alone FPs on version-laden product
/// names; together they isolate scrambled identity.
fn identity_metrics(info: &VersionInfo, metrics: &mut Metrics) {
    let mut identity = String::new();
    for field in ["CompanyName", "ProductName", "FileDescription"]
        .into_iter()
        .filter_map(|key| info.string(key))
    {
        identity.push_str(field.trim());
    }

    if let Some((symbol_ratio, entropy)) = identity_scores(&identity) {
        metrics.insert(metric!("pe.version.identity_symbol_ratio"), symbol_ratio);
        metrics.insert(metric!("pe.version.identity_entropy"), entropy);
    }

    module_name_consistency(info, metrics);
}

/// `InternalName` and `OriginalFilename` name the same module, so a linker sets
/// them from the same source: they come out identical (`d3dcompiler_47.dll` /
/// `d3dcompiler_47.dll`) or one is the other's stem (`WebBrowserPassView` /
/// `WebBrowserPassView.exe`). Builder kits that synthesise a vendor identity
/// fill the two fields independently and leave them unrelated.
///
/// The comparison is deliberately loose. Traits can already express a strict
/// `ne:` between two value paths, and a strict test is useless here: it fires
/// on every stem pair, which is most of the benign population. Folding the
/// extension, case and separators away and then accepting *containment* leaves
/// only the genuinely unrelated case.
///
/// Emitted as 0 or 1 whenever both fields are present, so a consumer can
/// distinguish "checked and consistent" from "not checked".
fn module_name_consistency(info: &VersionInfo, metrics: &mut Metrics) {
    let (Some(internal), Some(original)) = (
        info.string("InternalName").and_then(fold_module_name),
        info.string("OriginalFilename").and_then(fold_module_name),
    ) else {
        return;
    };

    let related = internal.contains(&original) || original.contains(&internal);
    metrics.insert(
        metric!("consistency.internal_name_original_filename_mismatch"),
        if related { 0.0 } else { 1.0 },
    );
}

/// Fold a module name to its comparable core: drop one trailing extension,
/// lowercase, and keep only alphanumerics so spaces, `_`, `-` and `.` cannot
/// make two spellings of one name look different.
///
/// `None` below three characters, where containment stops being evidence of
/// anything — a two-letter stem is a substring of far too much.
fn fold_module_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let stem = match trimmed.rsplit_once('.') {
        // The extension must contain a letter. Without that, a trailing
        // version component is eaten as one -- `libssl.1.1` folds to
        // `libssl1`, quietly making two different modules look related.
        Some((base, ext))
            if !base.is_empty()
                && (1..=5).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
                && ext.chars().any(|c| c.is_ascii_alphabetic()) =>
        {
            base
        }
        _ => trimmed,
    };

    let folded: String = stem
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();

    (folded.chars().count() >= 3).then_some(folded)
}

/// Symbol/digit ratio and Shannon byte-entropy of the concatenated identity
/// text. `None` below the 16-char length guard, where the estimate is too noisy
/// to threshold.
fn identity_scores(identity: &str) -> Option<(f64, f64)> {
    let total = identity.chars().count();
    if total < 16 {
        return None;
    }

    let nonlinguistic = identity
        .chars()
        .filter(|c| !c.is_alphabetic() && !c.is_whitespace())
        .count();
    let symbol_ratio = nonlinguistic as f64 / total as f64;

    let entropy = entropy::shannon(identity.as_bytes());

    Some((symbol_ratio, entropy))
}

fn fixed_file_info(fixed: &FixedFileInfo, values: &mut Values) {
    // VS_FIXEDFILEINFO numeric file/product versions are dropped: in
    // practice they duplicate the string-table FileVersion /
    // ProductVersion that already lives on `pe.version.{file_version,
    // product_version}`. The fixed-info OS class / file type / flags
    // are unique to the binary header and stay.
    put_str(
        values,
        value_key!("pe.version.os"),
        file_os_label(fixed.file_os),
    );
    put_str(
        values,
        value_key!("pe.version.type"),
        file_type_label(fixed.file_type),
    );
    if fixed.file_type == 3 || fixed.file_type == 4 {
        // DRV (3) and FONT (4) types carry a subtype; for everything
        // else the field is `VFT2_UNKNOWN` and not worth surfacing.
        put_str(
            values,
            value_key!("pe.version.subtype"),
            file_subtype_label(fixed.file_type, fixed.file_subtype),
        );
    }
    let flags = file_flags(fixed.file_flags & fixed.file_flags_mask);
    if !flags.is_empty() {
        values.insert_key(
            value_key!("pe.version.flags"),
            JsonValue::Array(flags.into_iter().map(JsonValue::String).collect()),
        );
    }
}

fn file_os_label(file_os: u32) -> &'static str {
    // From verrsrc.h `VOS_*`. The standard combinations only —
    // exotic OS+platform combos collapse to "unknown".
    match file_os {
        0x0001_0000 => "dos",
        0x0002_0000 => "os216",
        0x0003_0000 => "os232",
        0x0004_0000 => "windows_nt",
        0x0001_0001 => "dos_windows16",
        0x0001_0004 => "dos_windows32",
        0x0002_0002 => "os216_pm16",
        0x0003_0003 => "os232_pm32",
        0x0004_0004 => "windows_nt_windows32",
        _ => "unknown",
    }
}

fn file_type_label(file_type: u32) -> &'static str {
    // From verrsrc.h `VFT_*`.
    match file_type {
        0x0000_0001 => "app",
        0x0000_0002 => "dll",
        0x0000_0003 => "drv",
        0x0000_0004 => "font",
        0x0000_0005 => "vxd",
        0x0000_0007 => "static_lib",
        _ => "unknown",
    }
}

fn file_subtype_label(file_type: u32, subtype: u32) -> &'static str {
    if file_type == 3 {
        // VFT_DRV subtypes
        match subtype {
            0x0000_0001 => "printer",
            0x0000_0002 => "keyboard",
            0x0000_0003 => "language",
            0x0000_0004 => "display",
            0x0000_0005 => "mouse",
            0x0000_0006 => "network",
            0x0000_0007 => "system",
            0x0000_0008 => "installable",
            0x0000_0009 => "sound",
            0x0000_000a => "comm",
            0x0000_000b => "input_method",
            0x0000_000c => "versioned_printer",
            _ => "unknown",
        }
    } else if file_type == 4 {
        // VFT_FONT subtypes
        match subtype {
            0x0000_0001 => "raster",
            0x0000_0002 => "vector",
            0x0000_0003 => "truetype",
            _ => "unknown",
        }
    } else {
        "unknown"
    }
}

fn file_flags(flags: u32) -> Vec<String> {
    // From verrsrc.h `VS_FF_*`.
    [
        (0x01, "debug"),
        (0x02, "pre_release"),
        (0x04, "patched"),
        (0x08, "private_build"),
        (0x10, "info_inferred"),
        (0x20, "special_build"),
    ]
    .into_iter()
    .filter(|&(bit, _)| flags & bit != 0)
    .map(|(_, name)| name.to_owned())
    .collect()
}

/// The `RT_VERSION` leaves of the resource directory `resources`, as
/// `(file offset, length)`, resolving RVAs through `sections`. Walks only
/// the type → name → language levels under type 16, bounded in entries,
/// leaves and the directory bytes it reads, and never the payload of any
/// other resource: a large `RT_RCDATA` must not hide a small version
/// resource. An empty list for a directory that is malformed anywhere on
/// the way.
fn version_leaves(
    sections: &[SectionTable],
    file_alignment: Option<u32>,
    resources: DataDirectory,
    bytes: &[u8],
) -> Vec<(usize, usize)> {
    /// Directory bytes the walk reads, and entries it visits.
    const MAX_DIRECTORY_BYTES: usize = 1024 * 1024;
    const MAX_ENTRIES: usize = 4096;
    /// Leaves taken, and the largest one: real version resources are a few
    /// KiB, and a `wLength` caps a block at 64 KiB.
    const MAX_LEAVES: usize = 16;
    const MAX_LEAF_LEN: usize = 65536;
    let offset = |rva: u32, len: usize| -> Option<usize> {
        let off = section_rva_to_file_offset(sections, file_alignment, rva)?;
        bytes.get(off..off.checked_add(len)?)?;
        Some(off)
    };
    let root = resources.virtual_address;
    let declared = crate::bytes::sat_usize(resources.size).min(MAX_DIRECTORY_BYTES);
    let entry_offset = |relative: usize, len: usize| -> Option<usize> {
        if relative.checked_add(len)? > declared {
            return None;
        }
        offset(root.checked_add(u32::try_from(relative).ok()?)?, len)
    };
    let walk = || -> Option<Vec<(usize, usize)>> {
        let mut todo = vec![(0usize, 0u8)];
        let mut budget = MAX_ENTRIES;
        let mut leaves = Vec::new();
        while let Some((relative, depth)) = todo.pop() {
            let dir = entry_offset(relative, 16)?;
            let n = usize::from(u16_le(bytes, dir + 12)?)
                .checked_add(usize::from(u16_le(bytes, dir + 14)?))?;
            budget = budget.checked_sub(n)?;
            for i in 0..n {
                let e = entry_offset(relative.checked_add(16 + i * 8)?, 8)?;
                if depth == 0 && u32_le(bytes, e)? != u32::from(RT_VERSION) {
                    continue;
                }
                let target = u32_le(bytes, e + 4)?;
                let next = crate::bytes::sat_usize(target & !IMAGE_RESOURCE_DATA_IS_DIRECTORY);
                let is_directory = target & IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0;
                if depth < 2 && is_directory {
                    todo.push((next, depth + 1));
                } else if depth == 2 && !is_directory {
                    let data = entry_offset(next, 16)?;
                    let len = crate::bytes::sat_usize(u32_le(bytes, data + 4)?);
                    if !(6..=MAX_LEAF_LEN).contains(&len) || leaves.len() >= MAX_LEAVES {
                        return None;
                    }
                    leaves.push((offset(u32_le(bytes, data)?, len)?, len));
                } else {
                    return None;
                }
            }
        }
        Some(leaves)
    };
    walk().unwrap_or_else(|| {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "version-info",
            rva = root,
            "resource directory malformed on the way to RT_VERSION"
        );
        Vec::new()
    })
}

#[cfg(test)]
mod tests;
