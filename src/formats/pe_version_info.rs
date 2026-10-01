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
//! Goblin parses the whole resource tree for us and exposes typed
//! accessors. We flatten the strings into snake_case `pe.version.*`
//! leaves (`pe.version.company`, `pe.version.file_version`, …) and
//! decompose the `VS_FIXEDFILEINFO` into `pe.version.{os,type,subtype,flags}`
//! with format-conventional names — flag bits as a sorted string array,
//! OS class as a stable label.

use crate::metric;
use goblin::pe::resource::{StringFileInfo, VersionInfo, VsFixedFileInfo};
use serde_json::Value as JsonValue;

use crate::formats::common::bytes_at::u16_le;
use crate::formats::common::{put_str, put_u64};
use crate::output::{Metrics, ValueKey, Values};
use crate::value_key;

pub(super) fn extract(
    info: &VersionInfo<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    if let Some(ref fixed) = info.fixed_info {
        if fixed.is_valid() {
            fixed_file_info(fixed, values);
        }
    }
    string_table(&info.string_info, values);
    // goblin decodes the string-table values but hides their file offsets, so
    // walk the raw VS_VERSIONINFO blob ourselves to anchor `pe.version.*`
    // `value` matches in the hex view.
    emit_value_offsets(bytes, values);
    identity_metrics(&info.string_info, metrics);
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

/// Map a VS_VERSIONINFO `String` key to the `_offset` companion of the
/// `pe.version.*` leaf the value-tree uses (must match [`string_table`]), so
/// the emitted offset lines up with the value path a trait queries.
fn version_offset_key(key: &str) -> Option<ValueKey> {
    Some(match key {
        "Comments" => value_key!("pe.version.comments_offset"),
        "CompanyName" => value_key!("pe.version.company_offset"),
        "FileDescription" => value_key!("pe.version.description_offset"),
        "FileVersion" => value_key!("pe.version.file_version_offset"),
        "InternalName" => value_key!("pe.version.internal_name_offset"),
        "LegalCopyright" => value_key!("pe.version.copyright_offset"),
        "LegalTrademarks" => value_key!("pe.version.trademarks_offset"),
        "OriginalFilename" => value_key!("pe.version.original_filename_offset"),
        "PrivateBuild" => value_key!("pe.version.private_build_offset"),
        "ProductName" => value_key!("pe.version.product_name_offset"),
        "ProductVersion" => value_key!("pe.version.product_version_offset"),
        "SpecialBuild" => value_key!("pe.version.special_build_offset"),
        _ => return None,
    })
}

/// Read a UTF-16LE NUL-terminated key at `pos`, returning `(key, offset just
/// past the terminator)`. Bounded by `end`.
fn read_utf16_key(bytes: &[u8], pos: usize, end: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = pos;
    while i + 2 <= end {
        let Some(u) = u16_le(bytes, i) else {
            break;
        };
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

/// Round `n` up to the next 4-byte boundary (VS_VERSIONINFO blocks are
/// DWORD-aligned).
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Walk one length-prefixed VS_VERSIONINFO block at `off` (a file offset into
/// `bytes`): `{u16 wLength, u16 wValueLength, u16 wType, WCHAR szKey[], pad,
/// Value, pad, Children}`. Records `pe.version.<leaf>_offset` for `String`
/// blocks whose key is recognised, then recurses into children. Fully bounds-
/// and depth-checked: this parses untrusted resource bytes.
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
    values: &mut Values,
) {
    if depth >= MAX_VERSION_DEPTH || *budget == 0 || off + 6 > limit {
        return;
    }
    *budget -= 1;
    let Some(&[l0, l1, v0, v1, t0, t1]) = bytes.get(off..).and_then(<[u8]>::first_chunk::<6>)
    else {
        return;
    };
    let w_length = u16::from_le_bytes([l0, l1]) as usize;
    let w_value_length = u16::from_le_bytes([v0, v1]) as usize;
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

    if let Some(offset_key) = version_offset_key(&key)
        && value_off < block_end
    {
        put_u64(values, offset_key, value_off as u64);
    }

    // Children follow the value, DWORD-aligned, up to this block's end.
    let mut child = align4(value_off.saturating_add(value_bytes));
    while child + 6 <= block_end {
        let Some(child_len) = u16_le(bytes, child) else {
            break;
        };
        let child_len = child_len as usize;
        if child_len < 6 {
            break;
        }
        walk_version_block(bytes, child, block_end, depth + 1, budget, values);
        child = align4(child.saturating_add(child_len));
    }
}

/// Locate the VS_VERSIONINFO blob by its `"VS_VERSION_INFO"` key (6 bytes into
/// the root block) and walk it, recording each string value's byte offset.
fn emit_value_offsets(bytes: &[u8], values: &mut Values) {
    let sig: Vec<u8> = "VS_VERSION_INFO"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let Some(key_pos) = memchr::memmem::find(bytes, &sig) else {
        return;
    };
    let root = key_pos.saturating_sub(6);
    let mut budget = MAX_VERSION_NODES;
    walk_version_block(bytes, root, bytes.len(), 0, &mut budget, values);
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
fn identity_metrics(strings: &StringFileInfo<'_>, metrics: &mut Metrics) {
    let mut identity = String::new();
    for field in [
        strings.company_name(),
        strings.product_name(),
        strings.file_description(),
    ]
    .into_iter()
    .flatten()
    {
        identity.push_str(field.trim());
    }

    if let Some((symbol_ratio, entropy)) = identity_scores(&identity) {
        metrics.insert(metric!("pe.version.identity_symbol_ratio"), symbol_ratio);
        metrics.insert(metric!("pe.version.identity_entropy"), entropy);
    }

    module_name_consistency(strings, metrics);
}

/// `InternalName` and `OriginalFilename` name the same module, so a linker sets
/// them from the same source: they come out identical (`d3dcompiler_47.dll` /
/// `d3dcompiler_47.dll`) or one is the other's stem (`WebBrowserPassView` /
/// `WebBrowserPassView.exe`). Builder kits that synthesise a vendor identity
/// fill the two fields independently and leave them unrelated — the 2021
/// `coa`/`rc` npm loader declared `InternalName "Didride Cutuse"` against
/// `OriginalFilename "Thin.dll"`.
///
/// The comparison is deliberately loose. Traits can already express a strict
/// `ne:` between two value paths, and a strict test is useless here: it fires
/// on every stem pair, which is most of the benign population. Folding the
/// extension, case and separators away and then accepting *containment* leaves
/// only the genuinely unrelated case.
///
/// Emitted as 0 or 1 whenever both fields are present, so a consumer can
/// distinguish "checked and consistent" from "not checked".
fn module_name_consistency(strings: &StringFileInfo<'_>, metrics: &mut Metrics) {
    let (Some(internal), Some(original)) = (strings.internal_name(), strings.original_filename())
    else {
        return;
    };
    let (Some(internal), Some(original)) =
        (fold_module_name(&internal), fold_module_name(&original))
    else {
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

    let mut freq = [0u32; 256];
    let byte_total = identity.len() as f64;
    for b in identity.bytes() {
        if let Some(slot) = freq.get_mut(usize::from(b)) {
            *slot += 1;
        }
    }
    let entropy = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / byte_total;
            -p * p.log2()
        })
        .sum();

    Some((symbol_ratio, entropy))
}

fn fixed_file_info(fixed: &VsFixedFileInfo, values: &mut Values) {
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

fn string_table(strings: &StringFileInfo<'_>, values: &mut Values) {
    // VS_VERSIONINFO StringFileInfo entries flatten to `pe.version.*`
    // with snake_case keys (no `_name` filler when unambiguous, no
    // `Legal` prefix on copyright/trademarks). The Win32 SDK key
    // names are documented as canonical PascalCase (CompanyName etc.);
    // we honour the *concepts* but keep the path style consistent with
    // the rest of filefacts.
    if let Some(v) = strings.company_name() {
        put_str(values, value_key!("pe.version.company"), v);
    }
    if let Some(v) = strings.file_description() {
        put_str(values, value_key!("pe.version.description"), v);
    }
    if let Some(v) = strings.file_version() {
        put_str(values, value_key!("pe.version.file_version"), v);
    }
    if let Some(v) = strings.internal_name() {
        put_str(values, value_key!("pe.version.internal_name"), v);
    }
    if let Some(v) = strings.legal_copyright() {
        put_str(values, value_key!("pe.version.copyright"), v);
    }
    if let Some(v) = strings.legal_trademarks() {
        put_str(values, value_key!("pe.version.trademarks"), v);
    }
    if let Some(v) = strings.original_filename() {
        put_str(values, value_key!("pe.version.original_filename"), v);
    }
    if let Some(v) = strings.product_name() {
        put_str(values, value_key!("pe.version.product_name"), v);
    }
    if let Some(v) = strings.product_version() {
        put_str(values, value_key!("pe.version.product_version"), v);
    }
    if let Some(v) = strings.comments() {
        put_str(values, value_key!("pe.version.comments"), v);
    }
    if let Some(v) = strings.private_build() {
        put_str(values, value_key!("pe.version.private_build"), v);
    }
    if let Some(v) = strings.special_build() {
        put_str(values, value_key!("pe.version.special_build"), v);
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
    let mut out = Vec::new();
    if flags & 0x01 != 0 {
        out.push("debug".to_string());
    }
    if flags & 0x02 != 0 {
        out.push("pre_release".to_string());
    }
    if flags & 0x04 != 0 {
        out.push("patched".to_string());
    }
    if flags & 0x08 != 0 {
        out.push("private_build".to_string());
    }
    if flags & 0x10 != 0 {
        out.push("info_inferred".to_string());
    }
    if flags & 0x20 != 0 {
        out.push("special_build".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one DWORD-aligned VS_VERSIONINFO block (`wType=1`, text) with a key,
    /// an optional value, and pre-built child bytes — mirroring the real layout
    /// so the walker is exercised against genuine alignment/length rules.
    fn version_block(key: &str, value: Option<&str>, children: &[u8]) -> Vec<u8> {
        let utf16z = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        let value_units = value.map_or(0, |v| v.encode_utf16().count() + 1);
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_le_bytes()); // wLength (patched below)
        b.extend_from_slice(&(value_units as u16).to_le_bytes()); // wValueLength (WCHARs)
        b.extend_from_slice(&1u16.to_le_bytes()); // wType = text
        b.extend_from_slice(&utf16z(key));
        while b.len() % 4 != 0 {
            b.push(0);
        }
        if let Some(v) = value {
            b.extend_from_slice(&utf16z(v));
        }
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b.extend_from_slice(children);
        let len = b.len() as u16;
        b[0..2].copy_from_slice(&len.to_le_bytes());
        b
    }

    #[test]
    fn version_value_offsets_anchor_at_the_string() {
        let string = version_block("CompanyName", Some("ACME Corp"), &[]);
        let table = version_block("040904b0", None, &string);
        let sfi = version_block("StringFileInfo", None, &table);
        let root = version_block("VS_VERSION_INFO", None, &sfi);

        let mut values = Values::new();
        emit_value_offsets(&root, &mut values);

        // The companion offset must point exactly at the UTF-16LE value bytes.
        let want: Vec<u8> = "ACME Corp"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let expect = root
            .windows(want.len())
            .position(|w| w == want.as_slice())
            .map(|p| p as u64);
        assert!(expect.is_some(), "fixture must contain the value");
        assert_eq!(
            values
                .get("pe.version.company_offset")
                .and_then(JsonValue::as_u64),
            expect,
        );
        // Unknown keys (StringFileInfo/StringTable/langID) emit no companion.
        assert!(values.get("pe.version.040904b0_offset").is_none());
    }

    #[test]
    fn version_walker_tolerates_garbage() {
        // No signature, truncated, and zero-length blocks must not panic or loop.
        let mut v = Values::new();
        emit_value_offsets(&[], &mut v);
        emit_value_offsets(&[0u8; 8], &mut v);
        let mut sig: Vec<u8> = "VS_VERSION_INFO"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        sig.truncate(10); // cut mid-key
        emit_value_offsets(&sig, &mut v);
    }

    /// Blocks the walker visits for `blob`, rooted at offset 0.
    fn blocks_visited(blob: &[u8]) -> usize {
        let mut budget = MAX_VERSION_NODES;
        walk_version_block(blob, 0, blob.len(), 0, &mut budget, &mut Values::new());
        MAX_VERSION_NODES - budget
    }

    /// An empty-keyed, value-less block header claiming `w_length` bytes.
    fn bare_header(w_length: u16) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[0..2].copy_from_slice(&w_length.to_le_bytes());
        h[4..6].copy_from_slice(&1u16.to_le_bytes()); // wType = text
        h
    }

    #[test]
    fn version_walker_clamps_children_to_their_parent() {
        // Each unit is a 16-byte block A whose only child B claims 0xFFFF
        // bytes, so B's "children" are every later unit. Unclamped, each A is
        // re-walked under every earlier B -- work combinatorial in the unit
        // count. Clamped to A, each B is a leaf: one root plus two per unit.
        const UNITS: usize = 100;
        let mut units = Vec::new();
        for _ in 0..UNITS {
            units.extend_from_slice(&bare_header(16));
            units.extend_from_slice(&bare_header(0xFFFF));
        }
        let root = version_block("VS_VERSION_INFO", None, &units);
        assert_eq!(blocks_visited(&root), 1 + 2 * UNITS);
    }

    #[test]
    fn version_walker_stops_at_the_node_budget() {
        // Well-nested but implausibly dense: the root's 64 KiB holds ~8k
        // empty children, past the per-walk budget.
        let children: Vec<u8> = (0..8000).flat_map(|_| bare_header(8)).collect();
        let root = version_block("VS_VERSION_INFO", None, &children);
        assert_eq!(blocks_visited(&root), MAX_VERSION_NODES);
    }

    #[test]
    fn os_label_known() {
        assert_eq!(file_os_label(0x0004_0004), "windows_nt_windows32");
        assert_eq!(file_os_label(0xdead_beef), "unknown");
    }

    #[test]
    fn type_label_known() {
        assert_eq!(file_type_label(1), "app");
        assert_eq!(file_type_label(2), "dll");
        assert_eq!(file_type_label(99), "unknown");
    }

    #[test]
    fn flags_decompose() {
        let f = file_flags(0x01 | 0x04 | 0x20);
        assert!(f.contains(&"debug".to_string()));
        assert!(f.contains(&"patched".to_string()));
        assert!(f.contains(&"special_build".to_string()));
        assert_eq!(f.len(), 3);
    }

    #[test]
    fn flags_empty_when_zero() {
        assert!(file_flags(0).is_empty());
    }

    #[test]
    fn flags_decompose_full_set() {
        let f = file_flags(0x3F);
        assert_eq!(
            f,
            vec![
                "debug",
                "pre_release",
                "patched",
                "private_build",
                "info_inferred",
                "special_build"
            ]
        );
    }

    #[test]
    fn os_label_covers_canonical_values() {
        // From wintrust.h. The composite encodings pair an OS family
        // (high word) with a host environment (low word).
        assert_eq!(file_os_label(0x0001_0000), "dos");
        assert_eq!(file_os_label(0x0002_0000), "os216");
        assert_eq!(file_os_label(0x0003_0000), "os232");
        assert_eq!(file_os_label(0x0004_0000), "windows_nt");
        assert_eq!(file_os_label(0x0001_0001), "dos_windows16");
        assert_eq!(file_os_label(0x0001_0004), "dos_windows32");
        assert_eq!(file_os_label(0x0004_0004), "windows_nt_windows32");
        assert_eq!(file_os_label(0xdead_beef), "unknown");
    }

    #[test]
    fn type_label_covers_drv_and_font() {
        assert_eq!(file_type_label(3), "drv");
        assert_eq!(file_type_label(4), "font");
        assert_eq!(file_type_label(5), "vxd");
        assert_eq!(file_type_label(7), "static_lib");
    }

    #[test]
    fn type_label_unknown_falls_back() {
        assert_eq!(file_type_label(0), "unknown");
        assert_eq!(file_type_label(8), "unknown");
        assert_eq!(file_type_label(u32::MAX), "unknown");
    }

    #[test]
    fn identity_scores_below_length_guard() {
        assert!(identity_scores("short").is_none());
        assert!(identity_scores("Acme Corp Tools").is_none()); // 15 chars
    }

    #[test]
    fn identity_scores_clean_name_low_symbol_ratio() {
        // Legitimate identity: letters + spaces, symbol ratio ~0.
        let (ratio, entropy) =
            identity_scores("Microsoft CorporationWindows Operating System").unwrap();
        assert!(ratio < 0.05, "clean name symbol ratio {ratio}");
        assert!(entropy > 3.0);
    }

    #[test]
    fn identity_scores_scrambled_high_symbol_ratio() {
        // Crypter-scrambled VERSIONINFO: symbol/digit dense, fires the metric.
        let (ratio, entropy) =
            identity_scores("5:EB6>G8HB<57C5II=J47I>5FF@F6664<<CCI;I8:").unwrap();
        assert!(ratio >= 0.4, "scrambled symbol ratio {ratio}");
        assert!(entropy >= 3.5, "scrambled entropy {entropy}");
    }

    #[test]
    fn identity_scores_repeated_padding_excluded_by_entropy() {
        // Degenerate numeric padding: high symbol ratio but near-zero entropy,
        // so the ANDed composite (which also needs the entropy floor) rejects it.
        let (ratio, entropy) = identity_scores("00000000000000000000").unwrap();
        assert!(ratio >= 0.4);
        assert!(entropy < 1.0, "padding entropy {entropy}");
    }

    /// Every InternalName/OriginalFilename pair observed across the PE corpus
    /// in `supplychain-attack-data`. The first four are the benign shapes a
    /// strict inequality would have flagged; the last is the generated one.
    #[test]
    fn module_names_fold_to_related_forms() {
        for (internal, original) in [
            ("d3dcompiler_47.dll", "d3dcompiler_47.dll"),
            ("DTWpfInstaller.exe", "DTWpfInstaller.exe"),
            ("WebBrowserPassView", "WebBrowserPassView.exe"),
            ("ClassicShellSetup", "ClassicShellSetup.exe"),
        ] {
            let a = fold_module_name(internal).unwrap();
            let b = fold_module_name(original).unwrap();
            assert!(
                a.contains(&b) || b.contains(&a),
                "{internal} / {original} folded to {a} / {b}"
            );
        }
    }

    #[test]
    fn generated_module_names_stay_unrelated() {
        let a = fold_module_name("Didride Cutuse").unwrap();
        let b = fold_module_name("Thin.dll").unwrap();
        assert!(!a.contains(&b) && !b.contains(&a), "{a} / {b}");
    }

    #[test]
    fn fold_module_name_normalises_separators_and_case() {
        assert_eq!(fold_module_name("Foo-Bar_Baz.DLL").unwrap(), "foobarbaz");
        // A dotted version is not an extension: keep the digits.
        assert_eq!(fold_module_name("libssl.1.1").unwrap(), "libssl11");
    }

    #[test]
    fn fold_module_name_rejects_too_short_to_compare() {
        assert!(fold_module_name("a.dll").is_none());
        assert!(fold_module_name("  ").is_none());
    }
}
