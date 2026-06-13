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
//! accessors. We pull the strings into `pe.version_info.strings.<Key>`
//! and decompose the `VS_FIXEDFILEINFO` into `pe.version_info.fixed.*`
//! with format-conventional names — file_version as `"a.b.c.d"`,
//! flag bits as a sorted string array, OS class as a stable label.

use goblin::pe::resource::{StringFileInfo, VersionInfo, VsFixedFileInfo};
use serde_json::Value as JsonValue;

use crate::formats::common::{put_str, put_u64};
use crate::output::{Metrics, Values};

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
/// the cap bounds stack use on a hostile/looping blob.
const MAX_VERSION_DEPTH: u8 = 8;

/// Map a VS_VERSIONINFO `String` key to the `pe.version.*` leaf the value-tree
/// uses (must match [`string_table`]), so the emitted `<leaf>_offset` companion
/// lines up with the value path a trait queries.
fn version_key_leaf(key: &str) -> Option<&'static str> {
    Some(match key {
        "Comments" => "comments",
        "CompanyName" => "company",
        "FileDescription" => "description",
        "FileVersion" => "file_version",
        "InternalName" => "internal_name",
        "LegalCopyright" => "copyright",
        "LegalTrademarks" => "trademarks",
        "OriginalFilename" => "original_filename",
        "PrivateBuild" => "private_build",
        "ProductName" => "product_name",
        "ProductVersion" => "product_version",
        "SpecialBuild" => "special_build",
        _ => return None,
    })
}

/// Read a UTF-16LE NUL-terminated key at `pos`, returning `(key, offset just
/// past the terminator)`. Bounded by `end`.
fn read_utf16_key(bytes: &[u8], pos: usize, end: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = pos;
    while i + 2 <= end {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
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
fn walk_version_block(bytes: &[u8], off: usize, depth: u8, values: &mut Values) {
    if depth >= MAX_VERSION_DEPTH || off + 6 > bytes.len() {
        return;
    }
    let w_length = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
    let w_value_length = u16::from_le_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
    let w_type = u16::from_le_bytes([bytes[off + 4], bytes[off + 5]]);
    let block_end = off.saturating_add(w_length).min(bytes.len());
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

    if let Some(leaf) = version_key_leaf(&key)
        && value_off < block_end
    {
        put_u64(
            values,
            &format!("pe.version.{leaf}_offset"),
            value_off as u64,
        );
    }

    // Children follow the value, DWORD-aligned, up to this block's end.
    let mut child = align4(value_off.saturating_add(value_bytes));
    while child + 6 <= block_end {
        let child_len = u16::from_le_bytes([bytes[child], bytes[child + 1]]) as usize;
        if child_len < 6 {
            break;
        }
        walk_version_block(bytes, child, depth + 1, values);
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
    walk_version_block(bytes, root, 0, values);
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
        metrics.insert("pe.version.identity_symbol_ratio", symbol_ratio);
        metrics.insert("pe.version.identity_entropy", entropy);
    }
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
        freq[b as usize] += 1;
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
    put_str(values, "pe.version.os", file_os_label(fixed.file_os));
    put_str(values, "pe.version.type", file_type_label(fixed.file_type));
    if fixed.file_type == 3 || fixed.file_type == 4 {
        // DRV (3) and FONT (4) types carry a subtype; for everything
        // else the field is `VFT2_UNKNOWN` and not worth surfacing.
        put_str(
            values,
            "pe.version.subtype",
            file_subtype_label(fixed.file_type, fixed.file_subtype),
        );
    }
    let flags = file_flags(fixed.file_flags & fixed.file_flags_mask);
    if !flags.is_empty() {
        values.insert(
            "pe.version.flags",
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
        put_str(values, "pe.version.company", v);
    }
    if let Some(v) = strings.file_description() {
        put_str(values, "pe.version.description", v);
    }
    if let Some(v) = strings.file_version() {
        put_str(values, "pe.version.file_version", v);
    }
    if let Some(v) = strings.internal_name() {
        put_str(values, "pe.version.internal_name", v);
    }
    if let Some(v) = strings.legal_copyright() {
        put_str(values, "pe.version.copyright", v);
    }
    if let Some(v) = strings.legal_trademarks() {
        put_str(values, "pe.version.trademarks", v);
    }
    if let Some(v) = strings.original_filename() {
        put_str(values, "pe.version.original_filename", v);
    }
    if let Some(v) = strings.product_name() {
        put_str(values, "pe.version.product_name", v);
    }
    if let Some(v) = strings.product_version() {
        put_str(values, "pe.version.product_version", v);
    }
    if let Some(v) = strings.comments() {
        put_str(values, "pe.version.comments", v);
    }
    if let Some(v) = strings.private_build() {
        put_str(values, "pe.version.private_build", v);
    }
    if let Some(v) = strings.special_build() {
        put_str(values, "pe.version.special_build", v);
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
}
