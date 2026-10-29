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

use crate::formats::common::put_str;
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
/// `.comment` entry), taking the version from the `elf.go` build info the
/// Go decoder already emitted. Otherwise walks `elf.comment[]` for the first
/// recognized GCC / clang / rustc banner.
pub(super) fn from_elf(values: &mut Values, sections: &[crate::output::Section], bytes: &[u8]) {
    if sections.iter().any(|s| s.name == ".note.go.buildid") {
        let version = values
            .get_key(value_key!("elf.go"))
            .and_then(|go| go.get("version"))
            .and_then(serde_json::Value::as_str)
            .map(|v| v.trim_start_matches("go").to_string())
            .unwrap_or_default();
        emit(values, Family::Go, version);
        return;
    }
    let banner = values
        .get_key(value_key!("elf.comment"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .find_map(recognize_comment);
    if let Some((family, version)) = banner {
        emit(values, family, version);
        return;
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
///
/// Section ranges are file-controlled and need not be disjoint, so every
/// `.rodata*` header may cover the same megabytes: the scan is charged
/// against the file length, as `elf::sections` charges entropy. Honest
/// sections are disjoint slices of the file and never run out.
fn scan_rust_rodata(sections: &[crate::output::Section], bytes: &[u8]) -> Option<String> {
    const NEEDLE: &[u8] = b"rustc ";
    let mut budget = bytes.len();
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
        budget = budget.checked_sub(len)?;
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
mod tests;
