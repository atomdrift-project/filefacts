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
pub(super) fn detect(bytes: &[u8], values: &mut Values, key_prefix: &str) {
    let Some(start) = find_bytes(bytes, MAGIC) else {
        return;
    };
    if start + 32 > bytes.len() {
        return;
    }
    let flags = bytes[start + 15];
    let inline = flags & 0x2 != 0;
    if !inline {
        // Old (Go <1.18) format uses VA pointers into the data
        // segment; resolving them needs the program header table
        // and is not worth the complexity here. The plain-text
        // `modinfo` still leaks via the strings view.
        return;
    }
    // Payload starts at a 32-byte alignment from the magic.
    let payload = &bytes[start + 32..];
    let (version, rest) = match read_uvarint_string(payload) {
        Some(v) => v,
        None => return,
    };
    let modinfo_bytes = read_uvarint_string(rest).map_or(&[][..], |(s, _)| s);

    let key = format!("{key_prefix}.go");
    let mut obj = Map::new();
    if let Ok(s) = std::str::from_utf8(version) {
        obj.insert("version".into(), JsonValue::String(s.to_string()));
    }
    parse_modinfo(modinfo_bytes, &mut obj);
    values.insert(&key, JsonValue::Object(obj));
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
        out.insert("deps".into(), JsonValue::Array(deps));
    }
    if !build.is_empty() {
        out.insert("build_settings".into(), JsonValue::Object(build));
    }
    if !vcs.is_empty() {
        out.insert("vcs".into(), JsonValue::Object(vcs));
    }
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
}
