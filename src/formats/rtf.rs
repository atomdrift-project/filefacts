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

use crate::formats::common::{
    XorScan, append_decoded_strings, extract_binary_strings, hex_nibble, put_str,
};
use crate::output::{Metrics, Strings, Values};
use crate::value_key;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    // Canonical RTF starts with a versioned header. A tightly gated malformed
    // object form is accepted below; other inputs remain generic.
    if !bytes.starts_with(b"{\\rtf") && !crate::fileid::looks_like_obfuscated_rtf(bytes) {
        return;
    }

    // Header control words sit at the top of the document, before
    // the first group. Scan the first 128 bytes which is plenty.
    let head = bytes.get(..128).unwrap_or(bytes);
    if let Some(version) = parse_numeric_control(head, b"\\rtf") {
        put_str(values, value_key!("rtf.version"), version);
    }
    if let Some(cs) = parse_charset(head) {
        put_str(values, value_key!("rtf.charset"), cs);
    }
    if let Some(cp) = parse_numeric_control(head, b"\\ansicpg") {
        put_str(values, value_key!("rtf.codepage"), cp);
    }
    if let Some(lang) = parse_numeric_control(head, b"\\deflang") {
        put_str(values, value_key!("rtf.deflang"), lang);
    }

    info_group(bytes, values);
    fields(bytes, values);
    objects(bytes, values, strings, metrics);
    features(bytes, values);
    shape(bytes, values, metrics);
}

/// Return the numeric tail of a control word (`\rtf1` → `"1"`,
/// `\ansicpg1252` → `"1252"`). Negative numbers (`-1`) supported.
fn parse_numeric_control(bytes: &[u8], cw: &[u8]) -> Option<String> {
    let pos = memchr::memmem::find(bytes, cw)?;
    let tail = bytes.get(pos + cw.len()..)?;
    let number = tail.get(..param_len(tail))?;
    // A bare `-` is not a number.
    if !number.last().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(number).ok().map(str::to_string)
}

/// Length of the optional signed numeric parameter at the front of
/// `bytes`: a `-`, then digits. A bare `-` counts, so callers that need
/// digits check for them.
fn param_len(bytes: &[u8]) -> usize {
    let sign = usize::from(bytes.first() == Some(&b'-'));
    let digits = bytes
        .iter()
        .skip(sign)
        .take_while(|b| b.is_ascii_digit())
        .count();
    sign + digits
}

/// Split the control word at the front of `bytes` (just past its
/// backslash) into its letters and what follows its optional numeric
/// parameter.
fn split_control_word(bytes: &[u8]) -> (&[u8], &[u8]) {
    let letters = bytes.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    let (word, rest) = bytes.split_at_checked(letters).unwrap_or((bytes, &[]));
    (word, rest.get(param_len(rest)..).unwrap_or_default())
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
        if let Some(pos) = memchr::memmem::find(bytes, cw) {
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
    let Some(inner) = bytes.get(info_start + 1..group_end) else {
        return;
    };

    let mut info = serde_json::Map::new();
    // Iterate nested groups inside `\info`.
    let mut i = 0;
    while let Some(rel) = inner
        .get(i..)
        .and_then(|rest| rest.iter().position(|&b| b == b'{'))
    {
        let child_start = i + rel;
        let child_end = match_group_end(inner, child_start);
        let child = inner.get(child_start + 1..child_end).unwrap_or_default();
        // First control word is the key.
        if let Some(word) = child.strip_prefix(b"\\") {
            let (key, after) = split_control_word(word);
            let key = std::str::from_utf8(key).ok().map(str::to_lowercase);
            if let Some(k) = key {
                // Skip past the control word's trailing delimiter.
                let raw = after.strip_prefix(b" ").unwrap_or(after);
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
        values.insert_key(value_key!("rtf.info"), JsonValue::Object(info));
    }
}

/// Decode an RTF text run: drop control words/symbols and unescape
/// the common `\\`, `\{`, `\}` sequences. Hex escapes (`\\'XX`) are
/// rendered as the literal byte. Caller already trimmed the leading
/// control word.
fn decode_text(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((&b, after)) = rest.split_first() {
        rest = match (b, after) {
            (b'\\', [next @ (b'\\' | b'{' | b'}'), tail @ ..]) => {
                out.push(*next);
                tail
            }
            (b'\\', [b'\'', tail @ ..]) => {
                // Hex escape `\'XX`.
                if let [hi, lo, hex_tail @ ..] = tail
                    && let (Some(h), Some(l)) = (hex_nibble(*hi), hex_nibble(*lo))
                {
                    out.push((h << 4) | l);
                    hex_tail
                } else {
                    tail
                }
            }
            (b'\\', [b'~' | b'-' | b'_', tail @ ..]) => {
                out.push(b' ');
                tail
            }
            (b'\\', [next, ..]) if next.is_ascii_alphabetic() => {
                // Generic control word — skip the letters
                // and its optional numeric parameter.
                let (_, tail) = split_control_word(after);
                tail.strip_prefix(b" ").unwrap_or(tail)
            }
            (b'\\', _) => after.get(1..).unwrap_or_default(),
            (b'{' | b'}', _) => after,
            _ => {
                out.push(b);
                after
            }
        };
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
    while let Some(rel) = find_from(bytes, pos, b"\\fldinst") {
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
        while let Some(&b) = bytes.get(end) {
            match b {
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
        let body = decode_text(bytes.get(cursor..end).unwrap_or_default());
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
        values.insert_key(value_key!("rtf.fields"), JsonValue::Array(entries));
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
    while let Some(rel) = find_from(bytes, pos, b"\\objclass") {
        let abs = pos + rel;
        let mut cursor = abs + 9;
        if bytes.get(cursor) == Some(&b' ') {
            cursor += 1;
        }
        let name = bytes
            .get(cursor..)
            .unwrap_or_default()
            .split(|b| matches!(b, b'}' | b'{' | b'\\'))
            .next()
            .unwrap_or_default();
        if let Ok(class) = std::str::from_utf8(name) {
            let trimmed = class.trim();
            if !trimmed.is_empty() {
                entries.push(json!({"class": trimmed}));
            }
        }
        pos = (cursor + name.len()).max(abs + 9);
    }
    entries.extend(objdata_objects(bytes, strings, metrics));
    if !entries.is_empty() {
        values.insert_key(value_key!("rtf.objects"), JsonValue::Array(entries));
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
    while let Some(rel) = find_from(bytes, pos, b"\\objdata") {
        if count >= MAX_BLOBS as u64 {
            tracing::debug!(
                target: "filefacts::rtf",
                stage = "objdata",
                cap = MAX_BLOBS,
                offset = pos + rel,
                "objdata blobs past the cap not decoded"
            );
            break;
        }
        let start = pos + rel + 8;
        let decoded = decode_hex_run(bytes.get(start..).unwrap_or_default(), MAX_HEX, MAX_DECODED);
        pos = start;
        if decoded.is_empty() {
            continue;
        }
        count += 1;
        decoded_total += decoded.len() as u64;
        // The payload's own strings, recovered from behind the hex. This is
        // as much the point of decoding as the OLE1 header: an `\objdata`
        // blob need not hold an OLE object at all, and a command line hex
        // encoded there only exists once the digits are paired up. The same
        // is true of an embedded compound file: whatever it holds is
        // invisible until the blob is decoded.
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

    let u32_at = |off: usize| crate::bytes::u32_le(data, off).map(|v| v as usize);
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
        let is_pe = crate::bytes::u32_le(native, 0x3c)
            .and_then(|off| native.get(off as usize..))
            .is_some_and(|nt| nt.starts_with(b"PE\0\0"));
        return Some(if is_pe { "pe" } else { "mz-dos" });
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
        values.insert_key(
            value_key!("rtf.features"),
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
    while let Some(rel) = find_from(bytes, pos, cw) {
        let abs = pos + rel;
        let after = bytes.get(abs + cw.len()).copied().unwrap_or(b' ');
        if !after.is_ascii_alphabetic() {
            return true;
        }
        pos = abs + cw.len();
    }
    false
}

/// Position of the first `needle` in `bytes` at or after `pos`, relative
/// to `pos`.
fn find_from(bytes: &[u8], pos: usize, needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(bytes.get(pos..)?, needle)
}

/// Structural fingerprint counts. Cheap byte-level scans the
/// generator can't easily fake.
fn shape(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let mut control_words = 0_usize;
    let mut braces_open = 0_usize;
    let mut braces_close = 0_usize;
    let mut depth = 0_i32;
    let mut max_depth = 0_i32;
    let mut rest = bytes;
    while let Some((&b, after)) = rest.split_first() {
        rest = match b {
            b'\\' if after.first().is_some_and(u8::is_ascii_alphabetic) => {
                // A control word is letters, an optional parameter, then a
                // delimiter. Encrypted bytes after a stub header are full of
                // `\` + letter pairs; counting those made a payload look as
                // dense as a document and the sparse-body check never fired.
                let (_, tail) = split_control_word(after);
                let delimited = tail.first().is_none_or(|b| {
                    matches!(b, b' ' | b'\\' | b'{' | b'}' | b'\n' | b'\r' | b'\t' | b';')
                });
                if delimited {
                    control_words += 1;
                }
                tail
            }
            b'{' => {
                braces_open += 1;
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                after
            }
            b'}' => {
                braces_close += 1;
                depth -= 1;
                after
            }
            _ => after,
        };
    }
    let mut obj = serde_json::Map::new();
    obj.insert("control_word_count".into(), json!(control_words));
    obj.insert("group_depth_max".into(), json!(max_depth));
    obj.insert("brace_count".into(), json!(braces_open + braces_close));
    values.insert_key(value_key!("rtf.shape"), JsonValue::Object(obj));
    metrics.insert(metric!("rtf.control_word_count"), control_words as f64);
    metrics.insert(metric!("rtf.max_group_depth"), f64::from(max_depth));
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
    while pos + control_word.len() < bytes.len() {
        let abs = pos + find_from(bytes, pos, control_word)?;
        if let Some(open) = abs.checked_sub(1)
            && bytes.get(open) == Some(&b'{')
        {
            let after = bytes.get(abs + control_word.len()).copied().unwrap_or(b' ');
            if !after.is_ascii_alphabetic() {
                return Some(open);
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
    while let Some(&b) = bytes.get(i) {
        match b {
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
                    tracing::debug!(
                        target: "filefacts::rtf",
                        stage = "group",
                        offset = start,
                        cap = MAX_GROUP_DEPTH,
                        "group nests past the cap; read to end of input"
                    );
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
mod tests;
