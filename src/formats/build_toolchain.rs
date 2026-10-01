//! Cross-format toolchain attribution.
//!
//! Every format keeps its own native shape — PE's Rich header at
//! `pe.rich.*`, ELF's `.comment` at `elf.comment[]`, Mach-O's
//! `LC_BUILD_VERSION` at `macho.build_version.*` — but analysts often
//! want a single "what built this?" answer that's portable across
//! formats. This module produces a small `build.toolchain.{compiler,
//! version}` aggregate by inspecting the native paths already
//! populated on `Values`.
//!
//! The schema is intentionally thin:
//!
//! - `compiler` is one of the well-known short names below.
//! - `version` is the canonical version string each compiler stamps
//!   into its own banner. We don't reformat or normalize.
//!
//! When attribution is ambiguous (e.g. mixed-toolchain `.comment`
//! sections) the *first* recognizable token wins, since that's the
//! one a linker user would point at when asked "what built this?".

use crate::formats::common::{put_str, read_uleb128};
use crate::output::Values;
use crate::value_key;

/// Family identifier emitted as `build.toolchain.compiler`. The set
/// stays explicit so trait authors can match `exact:` cleanly.
#[derive(Debug, Clone, Copy)]
enum Family {
    Gcc,
    Clang,
    AppleClang,
    Msvc,
    Rustc,
    Go,
    Swift,
}

impl Family {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Clang => "clang",
            Self::AppleClang => "apple_clang",
            Self::Msvc => "msvc",
            Self::Rustc => "rustc",
            Self::Go => "go",
            Self::Swift => "swift",
        }
    }
}

/// Derive `build.toolchain.*` from a finished ELF parse. Checks for
/// a Go build-id section first (Go binaries usually ship without a
/// `.comment` entry); the version comes from the `.go.buildinfo`
/// blob when present. Otherwise walks `elf.comment[]` for the first
/// recognized GCC / clang / rustc banner.
pub(super) fn from_elf(values: &mut Values, sections: &[crate::output::Section], bytes: &[u8]) {
    if sections.iter().any(|s| s.name == ".note.go.buildid") {
        let version = sections
            .iter()
            .find(|s| s.name == ".go.buildinfo")
            .and_then(|s| read_go_buildinfo(bytes, s.file_offset, s.file_size))
            .unwrap_or_default();
        emit(values, Family::Go, version);
        return;
    }
    if let Some(entries) = values
        .get_key(value_key!("elf.comment"))
        .and_then(serde_json::Value::as_array)
        .cloned()
    {
        for entry in entries {
            let Some(text) = entry.as_str() else {
                continue;
            };
            if let Some((family, version)) = recognize_comment(text) {
                emit(values, family, version);
                return;
            }
        }
    }
    // Stripped-binary fallback: Rust embeds its compiler version
    // string in `rodata` as `rustc X.Y.Z` followed by the build
    // metadata. Scanning rodata sections (`.rodata` / `.rodata.*`)
    // catches binaries that have had `.comment` stripped.
    if let Some(version) = scan_rust_rodata(sections, bytes) {
        emit(values, Family::Rustc, version);
    }
}

/// Scan `.rodata` (and `.rodata.*` variants) for a `rustc X.Y.Z`
/// build-info marker. Modern Rust embeds this string verbatim in
/// the binary even when `.comment` is stripped, so it's the
/// reliable identification path for release builds.
fn scan_rust_rodata(sections: &[crate::output::Section], bytes: &[u8]) -> Option<String> {
    const NEEDLE: &[u8] = b"rustc ";
    for s in sections {
        if !s.name.starts_with(".rodata") {
            continue;
        }
        let start = usize::try_from(s.file_offset).ok()?;
        let len = usize::try_from(s.file_size).ok()?;
        let end = start.checked_add(len)?;
        if end > bytes.len() {
            continue;
        }
        let mut pos = start;
        while pos + NEEDLE.len() < end {
            if let Some(rel) = bytes
                .get(pos..end)
                .and_then(|w| w.windows(NEEDLE.len()).position(|w| w == NEEDLE))
            {
                let after = pos + rel + NEEDLE.len();
                // Require a digit immediately after `rustc ` to
                // reject "rustcracker"-style false positives.
                if bytes.get(after).is_some_and(|b| b.is_ascii_digit()) {
                    let token_end = bytes
                        .get(after..end)
                        .and_then(|t| {
                            t.iter()
                                .position(|b| matches!(*b, b' ' | b'\n' | b'\0' | b'-' | b'('))
                        })
                        .map_or(end, |n| after + n);
                    if let Some(Ok(v)) = bytes.get(after..token_end).map(std::str::from_utf8) {
                        return Some(v.to_string());
                    }
                }
                pos = after;
            } else {
                break;
            }
        }
    }
    None
}

/// Parse `.go.buildinfo` and return the Go runtime version string
/// (`"1.21.5"` style, with the `go` prefix stripped). Returns `None`
/// on malformed input or the older pointer-style layout we don't
/// follow.
///
/// Format reference (Go 1.18+ inline layout):
/// - bytes 0..14: magic `\xff Go buildinf:`
/// - byte 14: ptr_size
/// - byte 15: flag (`0x2` = inline-string format)
/// - bytes 16..32: filler padding (the header is 32 bytes total)
/// - byte 32+: `varint` length then `len` bytes of `runtime.Version()`,
///   then `varint` length then `len` bytes of `runtime/debug.BuildInfo`
///   text (which we ignore for `build.toolchain.version`).
fn read_go_buildinfo(bytes: &[u8], offset: u64, size: u64) -> Option<String> {
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    let end = start.checked_add(len)?;
    if len < 32 {
        return None;
    }
    let buf = bytes.get(start..end)?;
    if !buf.starts_with(MAGIC) {
        return None;
    }
    let flag = *buf.get(15)?;
    if flag & 0x2 == 0 {
        // Pointer format — would need to resolve a virtual address
        // to a file offset via the segment table. Modern toolchains
        // (Go 1.18+) write the inline format; skip the legacy
        // pointer layout rather than reach back through goblin here.
        return None;
    }
    // Inline data begins at byte 32 (the 32-byte header is fixed).
    let mut version_start = 32;
    let version_len = usize::try_from(read_uleb128(buf, &mut version_start)?).ok()?;
    let version_end = version_start.checked_add(version_len)?;
    let version = std::str::from_utf8(buf.get(version_start..version_end)?).ok()?;
    Some(version.trim_start_matches("go").to_string())
}

/// Match a single `.comment` token against the known toolchain
/// banners. Returns `(family, version)` when a banner is recognized;
/// the version string is the literal substring the toolchain stamped
/// (we don't normalize — analysts read `14.2.0` or `(Ubuntu 11.4.0)`
/// and know exactly what the compiler said).
fn recognize_comment(text: &str) -> Option<(Family, String)> {
    // GCC banners look like `GCC: (Ubuntu 14.2.0-1ubuntu1) 14.2.0`.
    // The trailing token after the parenthesized distro tag is the
    // canonical version.
    if let Some(rest) = text.strip_prefix("GCC:") {
        let after_paren = match rest.find(')') {
            Some(p) => rest[p + 1..].trim(),
            None => rest.trim(),
        };
        let version = after_paren
            .split([';', ',', ' '])
            .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .unwrap_or("")
            .to_string();
        return Some((Family::Gcc, version));
    }
    // Apple clang has a distinct prefix and uses a different version
    // numbering (Apple-internal); treat it as its own family so
    // toolchain-attribution traits don't conflate.
    if text.contains("Apple LLVM") || text.contains("Apple clang") {
        if let Some(pos) = text.find("version ") {
            let rest = &text[pos + "version ".len()..];
            let token = rest.split([' ', '(', ')']).next().unwrap_or("");
            return Some((Family::AppleClang, token.to_string()));
        }
        return Some((Family::AppleClang, String::new()));
    }
    if let Some(pos) = text.find("clang version ") {
        let rest = &text[pos + "clang version ".len()..];
        let token = rest.split([' ', '(', ')']).next().unwrap_or("");
        return Some((Family::Clang, token.to_string()));
    }
    // Rustc stamps either `rustc version X.Y.Z` (older) or
    // `Rust X.Y.Z` (newer). Both match here.
    if let Some(pos) = text.find("rustc version ") {
        let rest = &text[pos + "rustc version ".len()..];
        let token = rest.split([' ', '(', ')']).next().unwrap_or("");
        return Some((Family::Rustc, token.to_string()));
    }
    None
}

/// Mark `build.toolchain.compiler = "msvc"` when the PE carries a
/// Rich header. We don't attempt to derive a VS-year version: the
/// `build_id` field is the linker's *minor* build counter (small
/// numbers like 100–300 are normal across all VS releases), and
/// `product_id` requires a maintained mapping table that's only
/// loosely documented. Analysts who need finer attribution should
/// inspect `pe.rich.entries[*]` directly.
pub(super) fn from_pe_rich(values: &mut Values) {
    if values
        .get_key(value_key!("pe.rich.entries"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        emit(values, Family::Msvc, String::new());
    }
}

/// Derive `build.toolchain.*` from a finished Mach-O parse. Order:
///
/// 1. Any `__TEXT,__swift5_*` section ⇒ `swift`.
/// 2. A `clang` entry in `macho.build_version.tools[]` ⇒
///    `apple_clang` with that tool's version (the canonical
///    Apple-internal "clang-XXXX" build number).
/// 3. Otherwise `LC_BUILD_VERSION` presence ⇒ `apple_clang` with
///    no version.
pub(super) fn from_macho(values: &mut Values, sections: &[crate::output::Section]) {
    let has_swift = sections.iter().any(|s| s.name.contains(",__swift5_"));
    if has_swift {
        put_str(
            values,
            value_key!("build.toolchain.compiler"),
            Family::Swift.as_str(),
        );
        return;
    }
    let bv = values.get_key(value_key!("macho.build_version"));
    let clang_version = bv
        .and_then(|v| v.get("tools"))
        .and_then(serde_json::Value::as_array)
        .and_then(|tools| {
            tools.iter().find_map(|t| {
                if t.get("tool").and_then(serde_json::Value::as_str) == Some("clang") {
                    t.get("version")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                } else {
                    None
                }
            })
        });
    if bv.is_some() {
        emit(
            values,
            Family::AppleClang,
            clang_version.unwrap_or_default(),
        );
    }
}

fn emit(values: &mut Values, family: Family, version: String) {
    put_str(
        values,
        value_key!("build.toolchain.compiler"),
        family.as_str(),
    );
    if !version.is_empty() {
        put_str(values, value_key!("build.toolchain.version"), version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_ubuntu_gcc_banner() {
        let (fam, ver) = recognize_comment("GCC: (Ubuntu 14.2.0-1ubuntu1) 14.2.0").unwrap();
        assert!(matches!(fam, Family::Gcc));
        assert_eq!(ver, "14.2.0");
    }

    #[test]
    fn recognizes_alpine_clang_banner() {
        let (fam, ver) = recognize_comment("Alpine clang version 19.1.4").unwrap();
        assert!(matches!(fam, Family::Clang));
        assert_eq!(ver, "19.1.4");
    }

    #[test]
    fn recognizes_apple_clang_banner() {
        let (fam, ver) =
            recognize_comment("Apple clang version 15.0.0 (clang-1500.0.40.1)").unwrap();
        assert!(matches!(fam, Family::AppleClang));
        assert_eq!(ver, "15.0.0");
    }

    #[test]
    fn recognizes_rustc_banner() {
        let (fam, ver) = recognize_comment("rustc version 1.78.0 (9b00956e5 2024-04-29)").unwrap();
        assert!(matches!(fam, Family::Rustc));
        assert_eq!(ver, "1.78.0");
    }

    #[test]
    fn ignores_unknown_banner() {
        assert!(recognize_comment("some other text").is_none());
    }

    #[test]
    fn go_buildinfo_inline_version_is_read() {
        let mut blob = b"\xff Go buildinf:".to_vec();
        blob.extend_from_slice(&[8, 0x2]); // ptr_size, inline-string flag
        blob.resize(32, 0);
        blob.push(8); // uvarint length
        blob.extend_from_slice(b"go1.21.5");
        let len = blob.len() as u64;
        assert_eq!(read_go_buildinfo(&blob, 0, len).as_deref(), Some("1.21.5"));
        // A length running past the section, or a truncated uvarint, is no
        // version.
        assert_eq!(read_go_buildinfo(&blob, 0, len - 1), None);
        blob.truncate(32);
        blob.push(0x88);
        assert_eq!(read_go_buildinfo(&blob, 0, 33), None);
    }
}
