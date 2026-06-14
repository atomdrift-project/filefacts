//! Go build-info extraction.
//!
//! Every Go-compiled binary (Linux ELF, macOS Mach-O, Windows PE)
//! embeds the metadata for `runtime/debug.BuildInfo` in a fixed
//! magic-prefixed blob that lives in a section named
//! `.go.buildinfo` (ELF) / `__DATA,__go_buildinfo` (Mach-O) /
//! `.go.buildinfo` (PE). The blob layout has been stable since
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
//!     +15  1 byte    flags                     (bit 1 = strings inline)
//!     +16  …         payload
//! ```
//!
//! When `flags & 0x2` is set (Go 1.18+) the payload is two
//! varint-length-prefixed strings: the version string, then the
//! `modinfo` blob. Older binaries use pointers into the data
//! segment instead — those are not parsed here; the version string
//! still recovers because the modinfo plain-text is searchable.
//!
//! The `modinfo` blob itself is plain UTF-8: one record per line,
//! tab-separated fields, prefixed with a 16-byte sentinel pair the
//! runtime uses to find the blob in memory. We strip the sentinels
//! and parse the records.

use serde_json::{Map, Value as JsonValue};

use crate::output::Values;

const MAGIC: &[u8] = b"\xff Go buildinf:";

/// Scan the file for Go's build-info magic and, when present,
/// populate `<key_prefix>.go.*` with the decoded metadata. The
/// key prefix is the format's namespace (`"elf"`, `"macho"`,
/// `"pe"`) — keeps Go data attached to the format that hosted it.
///
/// `resolve_va` is an optional virtual-address resolver. The old
/// (Go <1.18) format encodes the version + modinfo strings as
/// pointers into the binary's load segments; resolving them needs
/// the format's program-header table. Callers that can map a VA to
/// a file offset (the ELF extractor walks `PT_LOAD`) pass a
/// closure; those that can't pass `None` and we silently skip the
/// old-format decode.
/// Attribution sections the caller resolves (via its format parser) and
/// hands to [`detect`] so the Go build-id / GoRoot / developer source
/// root can be recovered. None of these live in the build-info blob.
#[derive(Default)]
pub(super) struct GoSections<'a> {
    /// ELF `.note.go.buildid` note bytes (None for Mach-O / PE).
    pub buildid_note: Option<&'a [u8]>,
    /// `.gopclntab` / `__gopclntab` section bytes.
    pub pclntab: Option<&'a [u8]>,
    /// Read-only data section bytes (`.rodata` / `__const` / `.rdata`),
    /// scanned for the `Go build ID: "…"` linker marker as a fallback.
    pub rodata: Option<&'a [u8]>,
}

pub(super) fn detect(
    bytes: &[u8],
    values: &mut Values,
    key_prefix: &str,
    resolve_va: Option<&dyn Fn(u64) -> Option<usize>>,
    sections: &GoSections<'_>,
) {
    let Some(start) = find_bytes(bytes, MAGIC) else {
        return;
    };
    if start + 32 > bytes.len() {
        return;
    }
    let ptr_size = bytes[start + 14] as usize;
    let flags = bytes[start + 15];
    let inline = flags & 0x2 != 0;

    let key = format!("{key_prefix}.go");
    let mut obj = Map::new();
    if inline {
        // Payload starts at a 32-byte alignment from the magic.
        let payload = &bytes[start + 32..];
        let Some((version, rest)) = read_uvarint_string(payload) else {
            return;
        };
        let modinfo_bytes = read_uvarint_string(rest).map_or(&[][..], |(s, _)| s);
        if let Ok(s) = std::str::from_utf8(version) {
            obj.insert("version".into(), JsonValue::String(s.to_string()));
        }
        parse_modinfo(modinfo_bytes, &mut obj);
    } else if let Some(resolve) = resolve_va {
        // Old (Go <1.18) format: two VA pointers follow the header
        // at +16. Each one points to a Go string-header struct
        // (`{ data ptr; int len }`) sitting in the data segment.
        if !decode_old_format(bytes, start, ptr_size, resolve, &mut obj) {
            return;
        }
    } else {
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
    values.insert(&key, JsonValue::Object(obj));
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
        let pos = find_bytes(hay, needle)?;
        let after = &hay[pos + needle.len()..];
        let end = after.iter().take(256).position(|&b| b == b'"')?;
        let id = std::str::from_utf8(&after[..end]).ok()?;
        (!id.is_empty()).then(|| id.to_string())
    };
    if let Some(ro) = rodata
        && let Some(id) = scan_in(ro)
    {
        return Some(id);
    }
    scan_in(&bytes[..bytes.len().min(4 * 1024 * 1024)])
}

/// Parse an ELF `.note.go.buildid` note (namesz/descsz/type header,
/// 4-byte-padded name then desc); the desc is the ASCII build id.
fn parse_elf_buildid_note(note: &[u8]) -> Option<String> {
    if note.len() < 16 {
        return None;
    }
    let namesz = u32::from_le_bytes(note[..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(note[4..8].try_into().ok()?) as usize;
    let desc_off = 12 + ((namesz + 3) & !3);
    let desc_end = desc_off.checked_add(descsz)?;
    let desc = note.get(desc_off..desc_end)?.split(|&b| b == 0).next()?;
    let s = std::str::from_utf8(desc).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Scan the pclntab for the canonical `/src/runtime/` source path and
/// walk back to the GoRoot install prefix.
fn scan_go_root(pclntab: &[u8]) -> Option<String> {
    let pos = find_bytes(pclntab, b"/src/runtime/")?;
    let mut start = pos;
    let lo = pos.saturating_sub(256);
    while start > lo && is_path_byte(pclntab[start - 1]) {
        start -= 1;
    }
    if start == pos {
        return None;
    }
    let s = std::str::from_utf8(&pclntab[start..pos]).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Recover the developer source-tree root: the longest common directory
/// prefix of absolute `*.go` paths in the pclntab that are neither under
/// GoRoot nor in the module cache. Empty under `-trimpath`.
fn scan_go_main_root(pclntab: &[u8], go_root: Option<&str>) -> Option<String> {
    const MAX_CANDIDATES: usize = 4096;
    let mut candidates: Vec<&str> = Vec::new();
    let mut from = 0;
    while candidates.len() < MAX_CANDIDATES {
        let Some(rel0) = find_bytes(&pclntab[from..], b".go\0") else {
            break;
        };
        let rel = from + rel0;
        from = rel + 4;
        let mut start = rel;
        let lo = rel.saturating_sub(512);
        while start > lo {
            let b = pclntab[start - 1];
            if !is_path_byte(b) && b != b'/' {
                break;
            }
            start -= 1;
        }
        if start == rel || pclntab[start] != b'/' {
            continue;
        }
        let Ok(s) = std::str::from_utf8(&pclntab[start..rel + 3]) else {
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
    let first = paths.first()?;
    let mut max = first.len();
    for &p in &paths[1..] {
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

/// Decode the legacy pointer-based build-info layout. Returns
/// `true` when at least the Go version string was recovered. The
/// resolver maps a VA to a file offset; the rest is just two
/// indirections (pointer → string header → string body).
fn decode_old_format(
    bytes: &[u8],
    start: usize,
    ptr_size: usize,
    resolve_va: &dyn Fn(u64) -> Option<usize>,
    out: &mut Map<String, JsonValue>,
) -> bool {
    if ptr_size != 4 && ptr_size != 8 {
        return false;
    }
    if start + 16 + 2 * ptr_size > bytes.len() {
        return false;
    }
    let v_ptr = read_uint_le(bytes, start + 16, ptr_size);
    let m_ptr = read_uint_le(bytes, start + 16 + ptr_size, ptr_size);

    let mut got_version = false;
    if let Some(version) = read_go_string(bytes, v_ptr, ptr_size, resolve_va) {
        if let Ok(s) = std::str::from_utf8(&version) {
            out.insert("version".into(), JsonValue::String(s.to_string()));
            got_version = true;
        }
    }
    if let Some(modinfo) = read_go_string(bytes, m_ptr, ptr_size, resolve_va) {
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
    resolve_va: &dyn Fn(u64) -> Option<usize>,
) -> Option<Vec<u8>> {
    let hdr_off = resolve_va(header_va)?;
    if hdr_off + 2 * ptr_size > bytes.len() {
        return None;
    }
    let data_va = read_uint_le(bytes, hdr_off, ptr_size);
    let len = read_uint_le(bytes, hdr_off + ptr_size, ptr_size);
    // Sanity-cap on length so a malformed pointer can't have us
    // allocate gigabytes. 4 MiB is far above any real Go modinfo
    // (kube-diag's was 1.3 KiB).
    let len = usize::try_from(len).ok()?.min(4 * 1024 * 1024);
    if len == 0 {
        return Some(Vec::new());
    }
    let data_off = resolve_va(data_va)?;
    let end = data_off.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some(bytes[data_off..end].to_vec())
}

/// Little-endian unsigned read of `width` bytes (4 or 8). Go
/// binaries are little-endian on every mainstream architecture
/// (the loader hasn't shipped a big-endian build target in
/// years), so we don't carry an endian parameter — the few
/// `mips`/`s390x` BE binaries are rare enough to defer.
fn read_uint_le(bytes: &[u8], off: usize, width: usize) -> u64 {
    let mut v: u64 = 0;
    for i in 0..width {
        if off + i >= bytes.len() {
            return v;
        }
        v |= u64::from(bytes[off + i]) << (8 * i);
    }
    v
}

/// Parse the modinfo text and fold its records into `out`. Records
/// are tab-separated; the leading byte sequence written by the Go
/// runtime to mark the blob in memory is stripped first.
fn parse_modinfo(blob: &[u8], out: &mut Map<String, JsonValue>) {
    // Trim the 16-byte sentinels the runtime brackets the modinfo
    // with. Locating the first ASCII `path\t` line is more
    // forgiving than reproducing the exact sentinel bytes.
    let start = find_bytes(blob, b"path\t").unwrap_or(0);
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
            "dep" | "=>" => {
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
        } else if is_stdlib_path(path) {
            std += 1;
        } else {
            thirdparty += 1;
        }
    }
    (std, thirdparty, replaced, vendored)
}

/// A Go stdlib package path has no dot in its first segment (third-party
/// module paths are domain-rooted: `github.com/…`, `golang.org/x/…`).
fn is_stdlib_path(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("");
    !first.is_empty() && !first.contains('.')
}

/// Decode an unsigned varint (Go's `encoding/binary.Uvarint`) and
/// return the trailing string of that length plus the rest of the
/// payload after it. The string is *not* validated as UTF-8 — caller
/// decides whether to lossy-decode or skip.
fn read_uvarint_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, after_len) = decode_uvarint(buf)?;
    let len = usize::try_from(len).ok()?;
    if len > after_len.len() {
        return None;
    }
    let (s, rest) = after_len.split_at(len);
    Some((s, rest))
}

fn decode_uvarint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if shift > 63 {
            return None;
        }
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, &buf[i + 1..]));
        }
        shift += 7;
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarint_decodes_small_values() {
        // 0x96 0x01 → 150. Standard Go uvarint test vector.
        let (v, rest) = decode_uvarint(&[0x96, 0x01, 0xaa]).unwrap();
        assert_eq!(v, 150);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn modinfo_parses_minimal_record_set() {
        let mut out = Map::new();
        parse_modinfo(
            b"path\texample.com/main\nmod\texample.com/main\tv1.0.0\t\ndep\texample.com/util\tv0.1.0\th1:xyz=\nbuild\t-tags=foo\nbuild\tvcs=git\nbuild\tvcs.modified=true\n",
            &mut out,
        );
        assert_eq!(out["path"], JsonValue::String("example.com/main".into()));
        let deps = out["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0]["path"], "example.com/util");
        assert_eq!(out["build_settings"]["-tags"], "foo");
        assert_eq!(out["vcs"]["system"], "git");
        assert_eq!(out["vcs"]["modified"], "true");
    }

    #[test]
    fn classifies_dependency_provenance() {
        let mut out = Map::new();
        parse_modinfo(
            b"path\texample.com/main\n\
              dep\tfmt\t(devel)\t\n\
              dep\tgithub.com/foo/bar\tv1.2.3\th1:aaa=\n\
              dep\texample.com/old\tv1.0.0\th1:bbb=\n\
              =>\texample.com/new\tv2.0.0\th1:ccc=\n",
            &mut out,
        );
        // fmt = std, github.com/foo/bar = thirdparty, example.com/old is
        // replaced (followed by a `=>` target), the `=>` itself not counted.
        assert_eq!(out["deps_std"], JsonValue::from(1u32));
        assert_eq!(out["deps_thirdparty"], JsonValue::from(1u32));
        assert_eq!(out["deps_replaced"], JsonValue::from(1u32));
        assert_eq!(out["deps_vendored"], JsonValue::from(0u32));
    }

    #[test]
    fn build_id_from_rodata_marker() {
        let rodata = b"....Go build ID: \"abc123/def456\"....";
        let id = build_id(None, Some(rodata), b"");
        assert_eq!(id.as_deref(), Some("abc123/def456"));
    }

    #[test]
    fn build_id_from_elf_note() {
        // namesz=4 ("Go\0\0"), descsz=7 ("id12345"), type=4.
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&7u32.to_le_bytes());
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(b"Go\0\0");
        note.extend_from_slice(b"id12345");
        assert_eq!(parse_elf_buildid_note(&note).as_deref(), Some("id12345"));
    }

    #[test]
    fn go_root_from_pclntab_runtime_path() {
        let pclntab = b"\x00\x00/usr/local/go/src/runtime/proc.go\x00";
        assert_eq!(scan_go_root(pclntab).as_deref(), Some("/usr/local/go"));
    }

    #[test]
    fn main_root_is_common_dir_of_developer_paths() {
        let pclntab =
            b"/home/dev/project/main.go\x00\x00/home/dev/project/pkg/util.go\x00\x00/usr/local/go/src/runtime/proc.go\x00";
        let root = scan_go_main_root(pclntab, Some("/usr/local/go"));
        assert_eq!(root.as_deref(), Some("/home/dev/project"));
    }
}
