//! Go build-info extraction.
//!
//! Every Go-compiled binary (Linux ELF, macOS Mach-O, Windows PE)
//! embeds the metadata for `runtime/debug.BuildInfo` in a fixed
//! magic-prefixed blob that lives in a section named
//! `.go.buildinfo` (ELF) / `__DATA,__go_buildinfo` (Mach-O), or near the
//! start of the first writable data segment or section when there is no
//! such section (stripped ELF, PE). The blob layout has been stable since
//! Go 1.13, and is the cleanest way to recover:
//!
//! - the compiler version (`go1.21.5`),
//! - the main-module import path,
//! - the full transitive dependency list with versions + checksums,
//! - the build flags (`-buildmode`, `-tags`, `CGO_ENABLED`, …),
//! - the VCS revision/time, and whether the working tree had
//!   uncommitted changes when the binary was built (`vcs.modified`).
//!
//! This is one of the highest-yield forensic surfaces on a Go
//! malware sample: Go binaries are typically stripped, so symbol
//! tables tell you nothing, but the build-info blob is required at
//! runtime by `debug.ReadBuildInfo` and survives intact.
//!
//! ## Format
//!
//! ```text
//!     +0   14 bytes  "\xff Go buildinf:"                  (magic)
//!     +14  1 byte    pointer-size              (4 or 8)
//!     +15  1 byte    flags     (bit 1 = strings inline; else non-zero = big-endian)
//!     +16  …         two pointers (pre-1.18), or padding to +32
//!     +32  …         inline payload (1.18+)
//! ```
//!
//! The blob starts 16-byte aligned within its region, and only there is
//! it looked for, as Go's own `debug/buildinfo` does: the first magic
//! string anywhere in the file may belong to an embedded payload or a
//! decoy, and must not make the host "Go".
//!
//! When `flags & 0x2` is set (Go 1.18+) the payload is two
//! varint-length-prefixed strings: the version string, then the
//! `modinfo` blob. Older binaries store two pointers to Go string
//! headers instead, which the caller's VA→offset resolver follows.
//!
//! The `modinfo` blob itself is plain UTF-8: one record per line,
//! tab-separated fields, prefixed with a 16-byte sentinel pair the
//! runtime uses to find the blob in memory. We strip the sentinels
//! and parse the records.

use serde_json::{Map, Value as JsonValue};

use crate::formats::common::bytes_at::u32_le;
use crate::formats::common::read_uleb128;
use crate::output::{ValueKey, Values};

const MAGIC: &[u8] = b"\xff Go buildinf:";

/// The blob's alignment within its region and its fixed header size, as Go's
/// linker writes them and `debug/buildinfo` reads them.
const ALIGN: usize = 16;
const HEADER_LEN: usize = 32;

/// `dep` / `=>` records kept from one modinfo blob. Real binaries list a
/// few hundred (Kubernetes about a thousand); each six-byte `dep\tA` line
/// becomes a JSON object of several hundred bytes, so an unbounded list
/// turns a modinfo blob into a hundredfold allocation.
const MAX_DEPS: usize = 16_384;

/// The byte ranges the caller's format parser resolves for [`detect`]: where
/// the build-info blob may live, and the attribution sections the Go
/// build-id / GoRoot / developer source root are recovered from, none of
/// which live in the blob.
#[derive(Default)]
pub(super) struct GoSections<'a> {
    /// Where Go's `debug/buildinfo` looks for the blob: the dedicated
    /// section, else the format's first writable data segment or section.
    pub buildinfo: Option<&'a [u8]>,
    /// ELF `.note.go.buildid` note bytes (None for Mach-O / PE).
    pub buildid_note: Option<&'a [u8]>,
    /// `.gopclntab` / `__gopclntab` section bytes.
    pub pclntab: Option<&'a [u8]>,
    /// Read-only data section bytes (`.rodata` / `__const` / `.rdata`),
    /// scanned for the `Go build ID: "…"` linker marker as a fallback.
    pub rodata: Option<&'a [u8]>,
}

/// Go `pclntab` header magics across releases, little- and big-endian.
/// Go 1.2/1.16/1.18/1.20 use `0xfffffffb/fa/f0/f1`; the table is laid out in
/// target byte order, so both orientations are accepted (LE covers
/// amd64/arm64/386/arm; BE covers s390x/mips/ppc64).
const PCLNTAB_MAGICS: [[u8; 4]; 8] = [
    [0xfb, 0xff, 0xff, 0xff],
    [0xfa, 0xff, 0xff, 0xff],
    [0xf0, 0xff, 0xff, 0xff],
    [0xf1, 0xff, 0xff, 0xff],
    [0xff, 0xff, 0xff, 0xfb],
    [0xff, 0xff, 0xff, 0xfa],
    [0xff, 0xff, 0xff, 0xf0],
    [0xff, 0xff, 0xff, 0xf1],
];

/// True when `data` begins with a recognized Go pclntab magic — proof the
/// section is a genuine Go function table, not a same-named decoy. Used by the
/// admission controller to skip Rizin entirely: Go's pclntab already provides a
/// complete function inventory. Validating the magic, not just the section name,
/// stops a hand-added empty `.gopclntab`/`__gopclntab` from making a stripped
/// payload look like a Go binary and suppressing deep recovery.
pub(super) fn has_pclntab_magic(data: &[u8]) -> bool {
    data.get(..4)
        .and_then(|m| <[u8; 4]>::try_from(m).ok())
        .is_some_and(|magic| PCLNTAB_MAGICS.contains(&magic))
}

/// The PE section Go's `debug/buildinfo` searches: the first one with an
/// address and a size whose characteristics, alignment aside, are exactly
/// initialized, readable, writable data.
pub(super) fn pe_region<'a>(pe: &goblin::pe::PE<'_>, bytes: &'a [u8]) -> Option<&'a [u8]> {
    const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;
    const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x60_0000;
    const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const DATA: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    let section = pe.sections.iter().find(|s| {
        s.virtual_address != 0
            && s.size_of_raw_data != 0
            && s.characteristics & !IMAGE_SCN_ALIGN_32BYTES == DATA
    })?;
    let start = crate::bytes::sat_usize(section.pointer_to_raw_data);
    let end = start.saturating_add(crate::bytes::sat_usize(section.size_of_raw_data));
    bytes.get(start..end.min(bytes.len()))
}

/// Decode the build-info blob in `sections.buildinfo` into one object at
/// `key` (`pe.go`, `elf.go` or `macho.go`), keeping Go data attached to the
/// format that hosted it.
///
/// `resolve_va` maps a virtual address to an offset in `bytes`. The pre-1.18
/// layout stores pointers to the version and modinfo strings rather than the
/// strings, so without a resolver that layout yields nothing.
pub(super) fn detect(
    bytes: &[u8],
    values: &mut Values,
    key: ValueKey,
    resolve_va: Option<&dyn Fn(u64) -> Option<usize>>,
    sections: &GoSections<'_>,
) {
    // The blob: from the first magic at a 16-byte offset into the region.
    let Some((header, payload)) = sections.buildinfo.and_then(|region| {
        let at = memchr::memmem::find_iter(region, MAGIC).find(|at| at % ALIGN == 0)?;
        region.get(at..)?.split_first_chunk::<HEADER_LEN>()
    }) else {
        return;
    };
    let ptr_size = usize::from(header[14]);
    let flags = header[15];

    let mut obj = Map::new();
    if flags & 0x2 != 0 {
        let Some((version, rest)) = read_uvarint_string(payload) else {
            tracing::debug!(
                target: "filefacts::go_buildinfo",
                stage = "inline",
                format = key.as_str(),
                "Go build-info version string is truncated"
            );
            return;
        };
        let modinfo_bytes = read_uvarint_string(rest).map_or(&[][..], |(s, _)| s);
        if let Ok(s) = std::str::from_utf8(version) {
            obj.insert("version".into(), JsonValue::String(s.to_string()));
        }
        parse_modinfo(modinfo_bytes, &mut obj);
    } else if let Some(resolve) = resolve_va {
        // Pre-1.18: two pointers at +16, each to a Go string header
        // (`{ data ptr; int len }`) in the data segment.
        let big_endian = flags != 0;
        if !decode_old_format(bytes, header, ptr_size, big_endian, resolve, &mut obj) {
            tracing::debug!(
                target: "filefacts::go_buildinfo",
                stage = "pointers",
                format = key.as_str(),
                ptr_size,
                "Go build-info pointers do not resolve to a version string"
            );
            return;
        }
    } else {
        tracing::debug!(
            target: "filefacts::go_buildinfo",
            stage = "pointers",
            format = key.as_str(),
            "pre-1.18 Go build info needs a VA resolver this format lacks"
        );
        return;
    }

    // Attribution facts that live outside the build-info blob.
    if let Some(id) = build_id(sections.buildid_note, sections.rodata, bytes) {
        obj.insert("build_id".into(), JsonValue::String(id));
    }
    if let Some(pclntab) = sections.pclntab {
        let go_root = scan_go_root(pclntab);
        if let Some(main_root) = scan_go_main_root(pclntab, go_root.as_deref()) {
            obj.insert("main_root".into(), JsonValue::String(main_root));
        }
        if let Some(root) = go_root {
            obj.insert("go_root".into(), JsonValue::String(root));
        }
    }

    if obj.is_empty() {
        return;
    }
    values.insert_key(key, JsonValue::Object(obj));
}

/// Recover the Go build id. Prefers the ELF `.note.go.buildid` note;
/// otherwise scans the read-only data section (and a bounded prefix of
/// the file) for the linker's `Go build ID: "…"` marker.
fn build_id(buildid_note: Option<&[u8]>, rodata: Option<&[u8]>, bytes: &[u8]) -> Option<String> {
    if let Some(note) = buildid_note
        && let Some(id) = parse_elf_buildid_note(note)
    {
        return Some(id);
    }
    let needle = b"Go build ID: \"";
    let scan_in = |hay: &[u8]| -> Option<String> {
        let pos = memchr::memmem::find(hay, needle)?;
        let after = hay.get(pos + needle.len()..)?;
        let end = after.iter().take(256).position(|&b| b == b'"')?;
        let id = std::str::from_utf8(after.get(..end)?).ok()?;
        (!id.is_empty()).then(|| id.to_string())
    };
    if let Some(ro) = rodata
        && let Some(id) = scan_in(ro)
    {
        return Some(id);
    }
    scan_in(bytes.get(..4 * 1024 * 1024).unwrap_or(bytes))
}

/// Parse an ELF `.note.go.buildid` note (namesz/descsz/type header,
/// 4-byte-padded name then desc); the desc is the ASCII build id.
fn parse_elf_buildid_note(note: &[u8]) -> Option<String> {
    if note.len() < 16 {
        return None;
    }
    let namesz = crate::bytes::sat_usize(u32_le(note, 0)?);
    let descsz = crate::bytes::sat_usize(u32_le(note, 4)?);
    let desc_off = namesz.checked_add(3)?.checked_add(12)? & !3;
    let desc_end = desc_off.checked_add(descsz)?;
    let desc = note.get(desc_off..desc_end)?.split(|&b| b == 0).next()?;
    let s = std::str::from_utf8(desc).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Scan the pclntab for the canonical `/src/runtime/` source path and
/// walk back to the GoRoot install prefix.
fn scan_go_root(pclntab: &[u8]) -> Option<String> {
    let pos = memchr::memmem::find(pclntab, b"/src/runtime/")?;
    let mut start = pos;
    let lo = pos.saturating_sub(256);
    while start > lo && pclntab.get(start - 1).copied().is_some_and(is_path_byte) {
        start -= 1;
    }
    if start == pos {
        return None;
    }
    let s = std::str::from_utf8(pclntab.get(start..pos)?).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Recover the developer source-tree root: the longest common directory
/// prefix of absolute `*.go` paths in the pclntab that are neither under
/// GoRoot nor in the module cache. Empty under `-trimpath`.
fn scan_go_main_root(pclntab: &[u8], go_root: Option<&str>) -> Option<String> {
    const MAX_CANDIDATES: usize = 4096;
    let mut candidates: Vec<&str> = Vec::new();
    for rel in memchr::memmem::Finder::new(b".go\0").find_iter(pclntab) {
        if candidates.len() >= MAX_CANDIDATES {
            break;
        }
        // Walk back from the `.go` match to the start of the path.
        let mut start = rel;
        let lo = rel.saturating_sub(512);
        while start > lo {
            let Some(&b) = pclntab.get(start - 1) else {
                break;
            };
            if !is_path_byte(b) && b != b'/' {
                break;
            }
            start -= 1;
        }
        // Only absolute paths identify a developer tree; relative module
        // paths (emitted under -trimpath) don't.
        if start == rel || pclntab.get(start) != Some(&b'/') {
            continue;
        }
        let Some(Ok(s)) = pclntab.get(start..rel + 3).map(std::str::from_utf8) else {
            continue;
        };
        if go_root.is_some_and(|r| s.starts_with(r))
            || s.contains("/pkg/mod/")
            || s.contains("/src/runtime/")
        {
            continue;
        }
        candidates.push(s);
    }
    if candidates.is_empty() {
        return None;
    }
    let prefix = longest_common_dir_prefix(&candidates)?;
    (!prefix.is_empty() && prefix != "/").then_some(prefix)
}

fn longest_common_dir_prefix(paths: &[&str]) -> Option<String> {
    let (first, rest) = paths.split_first()?;
    let mut max = first.len();
    for &p in rest {
        let common = first
            .as_bytes()
            .iter()
            .zip(p.as_bytes())
            .take_while(|(a, b)| a == b)
            .count();
        max = max.min(common);
        if max == 0 {
            return None;
        }
    }
    let cut = first[..max].rfind('/')?;
    Some(if cut == 0 {
        "/".to_string()
    } else {
        first[..cut].to_string()
    })
}

fn is_path_byte(b: u8) -> bool {
    matches!(b, b'/' | b'.' | b'-' | b'_' | b'+' | b':') || b.is_ascii_alphanumeric()
}

/// Decode the pre-1.18 pointer layout whose header is `header`. Returns
/// `true` when at least the Go version string was recovered. The resolver
/// maps a VA to an offset in `bytes`; the rest is two indirections (pointer →
/// string header → string body).
fn decode_old_format(
    bytes: &[u8],
    header: &[u8; HEADER_LEN],
    ptr_size: usize,
    big_endian: bool,
    resolve_va: &dyn Fn(u64) -> Option<usize>,
    out: &mut Map<String, JsonValue>,
) -> bool {
    if ptr_size != 4 && ptr_size != 8 {
        return false;
    }
    // Both pointers fit the 32-byte header at the widest pointer size.
    let v_ptr = read_uint(header, 16, ptr_size, big_endian);
    let m_ptr = read_uint(header, 16 + ptr_size, ptr_size, big_endian);

    let mut got_version = false;
    if let Some(version) = read_go_string(bytes, v_ptr, ptr_size, big_endian, resolve_va) {
        if let Ok(s) = std::str::from_utf8(&version) {
            out.insert("version".into(), JsonValue::String(s.to_string()));
            got_version = true;
        }
    }
    if let Some(modinfo) = read_go_string(bytes, m_ptr, ptr_size, big_endian, resolve_va) {
        parse_modinfo(&modinfo, out);
    }
    got_version
}

/// Follow a Go `string` header at VA `header_va`. Layout:
/// `{ data: pointer; len: int }`. Returns the string body bytes.
fn read_go_string(
    bytes: &[u8],
    header_va: u64,
    ptr_size: usize,
    big_endian: bool,
    resolve_va: &dyn Fn(u64) -> Option<usize>,
) -> Option<Vec<u8>> {
    let hdr_off = resolve_va(header_va)?;
    if hdr_off.checked_add(2 * ptr_size)? > bytes.len() {
        return None;
    }
    let data_va = read_uint(bytes, hdr_off, ptr_size, big_endian);
    let len = read_uint(bytes, hdr_off + ptr_size, ptr_size, big_endian);
    // A forged length must not allocate gigabytes; real modinfo blobs are a
    // few KiB, far under 4 MiB.
    let len = usize::try_from(len).ok()?.min(4 * 1024 * 1024);
    if len == 0 {
        return Some(Vec::new());
    }
    let data_off = resolve_va(data_va)?;
    let end = data_off.checked_add(len)?;
    Some(bytes.get(data_off..end)?.to_vec())
}

/// Unsigned read of a `width`-byte (4 or 8) target pointer or `int`; 0 past
/// the end of `bytes`, which resolves to nothing.
fn read_uint(bytes: &[u8], off: usize, width: usize, big_endian: bool) -> u64 {
    let Some(field) = off.checked_add(width).and_then(|end| bytes.get(off..end)) else {
        return 0;
    };
    let fold = |acc: u64, b: &u8| (acc << 8) | u64::from(*b);
    if big_endian {
        field.iter().fold(0, fold)
    } else {
        field.iter().rev().fold(0, fold)
    }
}

/// Parse the modinfo text and fold its records into `out`. Records
/// are tab-separated; the leading byte sequence written by the Go
/// runtime to mark the blob in memory is stripped first.
fn parse_modinfo(blob: &[u8], out: &mut Map<String, JsonValue>) {
    // Trim the 16-byte sentinels the runtime brackets the modinfo
    // with. Locating the first ASCII `path\t` line is more
    // forgiving than reproducing the exact sentinel bytes.
    let start = memchr::memmem::find(blob, b"path\t").unwrap_or(0);
    let end = blob
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(blob.len(), |p| p + 1);
    let text = std::str::from_utf8(blob.get(start..end).unwrap_or(&[]))
        .unwrap_or("")
        .trim_end_matches('\n');
    if text.is_empty() {
        return;
    }
    let mut deps: Vec<JsonValue> = Vec::new();
    let mut build = Map::new();
    let mut vcs = Map::new();
    for line in text.lines() {
        let mut parts = line.splitn(4, '\t');
        let Some(tag) = parts.next() else { continue };
        match tag {
            "path" => {
                if let Some(p) = parts.next() {
                    out.insert("path".into(), JsonValue::String(p.to_string()));
                }
            }
            "mod" => {
                let mut m = Map::new();
                if let Some(p) = parts.next() {
                    m.insert("path".into(), JsonValue::String(p.to_string()));
                }
                if let Some(v) = parts.next() {
                    m.insert("version".into(), JsonValue::String(v.to_string()));
                }
                if let Some(s) = parts.next() {
                    if !s.is_empty() {
                        m.insert("sum".into(), JsonValue::String(s.to_string()));
                    }
                }
                out.insert("module".into(), JsonValue::Object(m));
            }
            "dep" | "=>" if deps.len() < MAX_DEPS => {
                // Both `dep\t…` and `=>\t…` (replace directive
                // target) flow into the same dependency list.
                let mut d = Map::new();
                if let Some(p) = parts.next() {
                    d.insert("path".into(), JsonValue::String(p.to_string()));
                }
                if let Some(v) = parts.next() {
                    d.insert("version".into(), JsonValue::String(v.to_string()));
                }
                if let Some(s) = parts.next() {
                    if !s.is_empty() {
                        d.insert("sum".into(), JsonValue::String(s.to_string()));
                    }
                }
                if tag == "=>" {
                    d.insert("kind".into(), JsonValue::String("replace".into()));
                }
                deps.push(JsonValue::Object(d));
            }
            "build" => {
                // `build\t<key>=<value>` or `build\t<flag>` (boolean).
                let Some(kv) = parts.next() else { continue };
                let (k, v) = match kv.split_once('=') {
                    Some((k, v)) => (k.to_string(), JsonValue::String(v.to_string())),
                    None => (kv.to_string(), JsonValue::Bool(true)),
                };
                // VCS-related entries get pulled out into their own
                // sub-object so consumers don't have to grep through
                // build settings to find the revision.
                if let Some(stripped) = k.strip_prefix("vcs.") {
                    vcs.insert(stripped.to_string(), v);
                } else if k == "vcs" {
                    vcs.insert("system".into(), v);
                } else {
                    build.insert(k, v);
                }
            }
            _ => {}
        }
    }
    if !deps.is_empty() {
        let (std, thirdparty, replaced, vendored) = classify_deps(&deps);
        out.insert("deps_std".into(), JsonValue::from(std));
        out.insert("deps_thirdparty".into(), JsonValue::from(thirdparty));
        out.insert("deps_replaced".into(), JsonValue::from(replaced));
        out.insert("deps_vendored".into(), JsonValue::from(vendored));
        out.insert("deps".into(), JsonValue::Array(deps));
    }
    if !build.is_empty() {
        out.insert("build_settings".into(), JsonValue::Object(build));
    }
    if !vcs.is_empty() {
        out.insert("vcs".into(), JsonValue::Object(vcs));
    }
}

/// Tally dependency provenance. A `=>` (replace-directive target) entry
/// immediately follows the dep it replaces, so a dep with a trailing
/// replace entry is counted as `replaced`; the replace entry itself is
/// not counted as its own dependency. Mirrors the buildinfo dep model.
fn classify_deps(deps: &[JsonValue]) -> (u32, u32, u32, u32) {
    let (mut std, mut thirdparty, mut replaced, mut vendored) = (0u32, 0u32, 0u32, 0u32);
    let is_replace = |d: &JsonValue| d.get("kind").and_then(|k| k.as_str()) == Some("replace");
    for (i, dep) in deps.iter().enumerate() {
        if is_replace(dep) {
            continue; // replacement target — accounted for by its base dep
        }
        let path = dep.get("path").and_then(|p| p.as_str()).unwrap_or("");
        if deps.get(i + 1).is_some_and(is_replace) {
            replaced += 1;
        } else if path.contains("/vendor/") {
            vendored += 1;
        } else if path
            .split('/')
            .next()
            .is_some_and(|first| !first.is_empty() && !first.contains('.'))
        {
            // A stdlib path has no dot in its first segment; third-party
            // module paths are domain-rooted (`github.com/…`).
            std += 1;
        } else {
            thirdparty += 1;
        }
    }
    (std, thirdparty, replaced, vendored)
}

/// Decode an unsigned varint (Go's `encoding/binary.Uvarint`) and
/// return the trailing string of that length plus the rest of the
/// payload after it. The string is *not* validated as UTF-8 — caller
/// decides whether to lossy-decode or skip.
fn read_uvarint_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut start = 0;
    let len = usize::try_from(read_uleb128(buf, &mut start)?).ok()?;
    let end = start.checked_add(len)?;
    Some((buf.get(start..end)?, buf.get(end..)?))
}

#[cfg(test)]
mod tests;
