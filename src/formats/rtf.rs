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
//! - `rtf.shape.{control_word_count, group_depth_max, brace_count}`
//!    — structural counts that fingerprint generator authenticity.

use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str};
use crate::output::{Metrics, Strings, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

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
    objects(bytes, values);
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
    std::str::from_utf8(&bytes[start..end]).ok().map(str::to_string)
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

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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
        let target = parts.next().unwrap_or("").trim().trim_matches('"').to_string();
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
fn objects(bytes: &[u8], values: &mut Values) {
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
    if !entries.is_empty() {
        values.insert("rtf.objects", JsonValue::Array(entries));
    }
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
            JsonValue::Array(found.into_iter().map(|s| JsonValue::String(s.into())).collect()),
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
                control_words += 1;
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                    i += 1;
                }
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
    metrics.insert("rtf.control_word_count", control_words as f64);
    metrics.insert("rtf.group_depth_max", f64::from(max_depth));
}

/// Locate `{\<word>` group opening in `bytes`. Returns the position
/// of the `{`. Useful for the well-known top-level groups (`\info`,
/// `\fonttbl`, `\colortbl`).
fn find_group(bytes: &[u8], control_word: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + control_word.len() + 1 <= bytes.len() {
        let rel = bytes[pos..].windows(control_word.len()).position(|w| w == control_word)?;
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

/// Return the position of the matching `}` for the `{` at `start`.
/// Returns `bytes.len()` on unterminated groups.
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
    fn parses_header_fields() {
        let rtf = b"{\\rtf1\\ansi\\ansicpg1252\\deflang1033 ...}";
        let (v, _) = extract_rtf(rtf);
        assert_eq!(v.get("rtf.version").and_then(|x| x.as_str()), Some("1"));
        assert_eq!(v.get("rtf.charset").and_then(|x| x.as_str()), Some("ansi"));
        assert_eq!(
            v.get("rtf.codepage").and_then(|x| x.as_str()),
            Some("1252")
        );
        assert_eq!(
            v.get("rtf.deflang").and_then(|x| x.as_str()),
            Some("1033")
        );
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
        assert_eq!(
            fields[0]["target"].as_str(),
            Some("https://evil.example/")
        );
    }

    #[test]
    fn extracts_object_class() {
        let rtf = b"{\\rtf1\\ansi {\\object\\objemb{\\*\\objclass Equation.3 }{\\objdata }}}";
        let (v, _) = extract_rtf(rtf);
        let objects = v.get("rtf.objects").and_then(|x| x.as_array()).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["class"].as_str(), Some("Equation.3"));
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
