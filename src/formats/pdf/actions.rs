//! Action sites, JavaScript payloads and embedded files: the parts of a
//! document that run or carry something.

use std::collections::HashMap;

use serde_json::{Value as JsonValue, json};

use super::MAX_INFLATED;
use super::filters::{decode_stream, find_filters};
use super::lex::{
    find_info_value, has_name, parse_indirect_ref_value, read_hex_string, read_literal_string,
    skip_while, truncate,
};
use super::objects::{DictRegion, ObjectIndex};

/// Cap on the snippet text we surface per action. Long JavaScript
/// payloads exist in malicious PDFs but the *first* few hundred
/// bytes contain the recognizable invocation patterns analysts
/// want; the rest is obfuscated runtime.
const SNIPPET_BYTES: usize = 200;

/// Decoded `/JS` content kept per document, across every site.
pub(super) const MAX_JS_TOTAL: usize = 16 << 20;

/// `/JS` sites resolved per document.
const MAX_JS_SITES: usize = 4096;

/// One action invocation site.
pub(super) struct Action {
    pub(super) kind: &'static str,
    /// `object:<id>`, `objstm:<id>` or `openaction`.
    pub(super) source: String,
    pub(super) snippet: String,
}

/// Walk each dictionary region for action invocation patterns and
/// emit one entry per occurrence. We don't deduplicate by source
/// object — each `/JS` site is independently interesting, since
/// malicious PDFs often stage the payload across several actions
/// to evade signature-based scanners that look at any one site.
///
/// The carrier object id is included as `source: "object:<id>"`.
/// When a containing object is also the catalog (i.e. carries
/// `/Type /Catalog`) the source is recorded as `"openaction"`
/// instead, since the catalog's actions are what a viewer runs on open.
///
/// At most `cap` sites are recorded.
pub(super) fn scan_actions(bytes: &[u8], dict_regions: &[DictRegion], cap: usize) -> Vec<Action> {
    const KINDS: &[(&[u8], &str)] = &[
        (b"/JS", "javascript"),
        (b"/Launch", "launch"),
        (b"/URI", "uri"),
        (b"/SubmitForm", "submitform"),
        (b"/GoToR", "gotor"),
        (b"/GoToE", "gotoe"),
        (b"/Movie", "movie"),
        (b"/Sound", "sound"),
        (b"/ImportData", "importdata"),
    ];
    let mut out = Vec::new();
    for region_info in dict_regions {
        if out.len() >= cap {
            break;
        }
        let region = region_info.dict(bytes);
        if region.is_empty() {
            continue;
        }
        let source = if has_name(region, b"Type", b"Catalog") {
            "openaction".to_string()
        } else {
            object_source(region_info.obj_id)
        };
        for &(needle, kind) in KINDS {
            let mut pos = 0;
            while let Some(rel) = region
                .get(pos..)
                .and_then(|rest| memchr::memmem::find(rest, needle))
            {
                let next = pos + rel + needle.len();
                pos = next;
                // Reject `/JS` matching `/JSON` or `/JavaScript`.
                if region.get(next).is_some_and(u8::is_ascii_alphabetic) {
                    continue;
                }
                // Only emit when the key has a value-bearing payload
                // — filters out `/S /URI` action-type declarations
                // (where `/URI` is a *name value*, not a key).
                if let Some(snippet) = action_snippet(region, next) {
                    if out.len() >= cap {
                        return out;
                    }
                    out.push(Action {
                        kind,
                        source: source.clone(),
                        snippet,
                    });
                }
            }
        }
    }
    out
}

/// Scan actions packed inside `/Type /ObjStm` object streams.
///
/// A cross-reference stream file keeps most of its objects inside compressed
/// object streams, so the annotation that carries the document's only link
/// never appears in the raw bytes at all -- and a scan of the file as written
/// reports a PDF with no actions in it. Malicious documents are routinely
/// built this way, which makes the compressed side the more important one.
///
/// Objects inside an ObjStm have no `obj` framing -- the stream is a table of
/// offsets followed by the dictionaries end to end -- so the decoded buffer is
/// handed to [`scan_actions`] as a single region. At most `cap` sites are
/// recorded.
pub(super) fn objstm_actions(decoded: &[(Option<u32>, Vec<u8>)], cap: usize) -> Vec<Action> {
    let mut out = Vec::new();
    for (obj_id, text) in decoded {
        let whole = DictRegion {
            start: 0,
            end: text.len(),
            obj_id: *obj_id,
            stream_range: None,
        };
        let left = cap.saturating_sub(out.len());
        for mut action in scan_actions(text, std::slice::from_ref(&whole), left) {
            // Say where it really came from: inside object stream <id>, not
            // object <id> itself.
            if let Some(id) = obj_id {
                action.source = format!("objstm:{id}");
            }
            out.push(action);
        }
    }
    out
}

fn object_source(obj_id: Option<u32>) -> String {
    obj_id.map_or_else(|| "object:unknown".to_string(), |id| format!("object:{id}"))
}

/// First ~200 chars of the value following an action key. Returns
/// `None` when the key is *not* used as a value-bearing dict entry
/// (e.g. `/S /URI` declares the action type; the `/URI (...)` entry
/// next to it carries the actual payload — only that second one
/// should produce an action record). Accepts `(literal)`, `<hex>`,
/// or an indirect reference `N N R`.
fn action_snippet(bytes: &[u8], start: usize) -> Option<String> {
    let cursor = skip_while(bytes, start, u8::is_ascii_whitespace);
    match *bytes.get(cursor)? {
        b'(' => read_literal_string(bytes, cursor + 1).map(|s| truncate(&s, SNIPPET_BYTES)),
        b'<' if bytes.get(cursor + 1) != Some(&b'<') => {
            read_hex_string(bytes, cursor + 1).map(|s| truncate(&s, SNIPPET_BYTES))
        }
        b'0'..=b'9' => {
            // Indirect reference `N N R`. Emit the reference token
            // so trait authors know an indirect lookup is in use.
            let end = (cursor + 16).min(bytes.len());
            let token: String = bytes
                .get(cursor..end)?
                .iter()
                .take_while(|&&b| !matches!(b, b'\n' | b'\r' | b'>' | b'/'))
                .map(|&b| b as char)
                .collect();
            let trimmed = token.trim();
            trimmed.ends_with('R').then(|| trimmed.to_string())
        }
        _ => None,
    }
}

/// The `pdf.javascript` entries, and why the scan stopped early if it did.
pub(super) struct JsScan {
    pub(super) payloads: Vec<JsonValue>,
    pub(super) limit: Option<String>,
}

struct JsPayload {
    target_object_id: Option<u32>,
    filters: Vec<String>,
    content: String,
}

/// Walk every `/JS` site and resolve it to its full byte content —
/// inline literals (`/JS (var x=1;)`), hex strings (`/JS <76617220...>`),
/// and indirect references (`/JS 42 0 R`) that point at a string or
/// stream object, decoded through the stream's filters. Distinct from
/// [`scan_actions`], which records each site with a 200-byte snippet for
/// at-a-glance triage; here the *whole* payload is kept so a consumer can
/// analyse each one as JavaScript in its own right.
///
/// Returns one entry per site with `{source, target_object_id?,
/// filters?, content, content_bytes}`. `target_object_id` is set when
/// the site referenced another object (so consumers can map the JS
/// payload back to a specific object id); `filters` records the
/// stream's filter chain when the payload was decoded from a stream.
pub(super) fn scan_javascript_payloads(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    objects: &ObjectIndex<'_>,
) -> JsScan {
    let mut out = Vec::new();
    // Decoded bytes left for the document. Sites can repeat one target
    // (`/JS 2 0 R` a thousand times over); each target is decoded once,
    // and the budget bounds what distinct targets and inline strings add.
    let mut budget = MAX_JS_TOTAL;
    let mut sites = 0_usize;
    // Every target resolved so far, with its decoded length (`None`: it
    // did not resolve), so a repeat is answered without decoding again.
    let mut seen: HashMap<u32, Option<u64>> = HashMap::new();
    let mut limit = None;
    'regions: for region in dict_regions {
        let dict = region.dict(bytes);
        let mut pos = 0;
        while let Some(rel) = dict
            .get(pos..)
            .and_then(|rest| memchr::memmem::find(rest, b"/JS"))
        {
            let next = pos + rel + 3;
            pos = next;
            // Reject /JSON, /JavaScript (the *name*, not the key form).
            if dict.get(next).is_some_and(u8::is_ascii_alphabetic) {
                continue;
            }
            if sites >= MAX_JS_SITES {
                limit = Some(format!("stopped after {MAX_JS_SITES} /JS sites"));
                break 'regions;
            }
            sites += 1;
            let source = object_source(region.obj_id);
            let cursor = skip_while(dict, next, u8::is_ascii_whitespace);
            let target = js_reference(dict, cursor);
            if let Some(&known) = target.and_then(|id| seen.get(&id)) {
                // The payload is the earlier entry's with the same
                // `target_object_id`; repeating its content would only
                // multiply the output.
                if let (Some(id), Some(len)) = (target, known) {
                    out.push(json!({
                        "source": source,
                        "target_object_id": id,
                        "content_bytes": len,
                    }));
                }
                continue;
            }
            if budget == 0 {
                limit = Some(format!(
                    "/JS payloads past the {MAX_JS_TOTAL}-byte decode budget not read"
                ));
                break 'regions;
            }
            let payload = match target {
                Some(id) => resolve_indirect_js(bytes, id, objects, budget.min(MAX_INFLATED)),
                None => resolve_inline_js(dict, cursor),
            };
            if let Some(id) = target {
                seen.insert(id, payload.as_ref().map(|p| p.content.len() as u64));
            }
            let Some(payload) = payload else {
                continue;
            };
            budget = budget.saturating_sub(payload.content.len());
            let mut entry = serde_json::Map::new();
            entry.insert("source".into(), JsonValue::String(source));
            if let Some(target) = payload.target_object_id {
                entry.insert("target_object_id".into(), json!(target));
            }
            if !payload.filters.is_empty() {
                entry.insert("filters".into(), json!(payload.filters));
            }
            entry.insert("content_bytes".into(), json!(payload.content.len()));
            entry.insert("content".into(), JsonValue::String(payload.content));
            out.push(JsonValue::Object(entry));
        }
    }
    JsScan {
        payloads: out,
        limit,
    }
}

/// An inline `/JS` value at `dict[cursor..]`: a `(literal)` or a `<hex>`
/// string.
fn resolve_inline_js(dict: &[u8], cursor: usize) -> Option<JsPayload> {
    let content = match dict.get(cursor)? {
        b'(' => read_literal_string(dict, cursor + 1)?,
        b'<' if dict.get(cursor + 1) != Some(&b'<') => read_hex_string(dict, cursor + 1)?,
        _ => return None,
    };
    Some(JsPayload {
        target_object_id: None,
        filters: Vec::new(),
        content,
    })
}

/// The object id of an `N G R` indirect reference at `dict[cursor..]`.
fn js_reference(dict: &[u8], cursor: usize) -> Option<u32> {
    if !dict.get(cursor)?.is_ascii_digit() {
        return None;
    }
    let end = (cursor + 32).min(dict.len());
    let token: String = dict
        .get(cursor..end)?
        .iter()
        .take_while(|&&b| !matches!(b, b'\n' | b'\r' | b'>' | b'/' | b'('))
        .map(|&b| b as char)
        .collect();
    let reference = token.trim().strip_suffix('R')?;
    reference.split_whitespace().next()?.parse().ok()
}

/// Dereference object `target_id` to recover the underlying string- or
/// stream-object's content, decoding at most `cap` bytes of a stream.
fn resolve_indirect_js(
    bytes: &[u8],
    target_id: u32,
    objects: &ObjectIndex<'_>,
    cap: usize,
) -> Option<JsPayload> {
    let Some(target) = objects.get(&target_id).copied() else {
        tracing::debug!(
            target: "filefacts::pdf",
            stage = "javascript",
            object = target_id,
            "/JS reference names no object in the file"
        );
        return None;
    };

    // Two shapes — a stream object (most common for /JS, since JS
    // blobs are bigger than a string-literal-friendly size) or a
    // bare string object. Try stream first.
    if let Some((s, e)) = target.stream_range
        && let Some(raw) = bytes.get(s..e).filter(|raw| !raw.is_empty())
    {
        let filters = find_filters(target.dict(bytes)).unwrap_or_default();
        match decode_stream(raw, &filters, cap) {
            // Surface as a string. `String::from_utf8_lossy` so any
            // embedded shellcode bytes survive as `U+FFFD` rather than
            // throwing the whole payload away — the downstream JS parser
            // sees the same UTF-8 it would see opening the PDF in a viewer
            // that ignores the odd byte.
            Ok(decoded) => {
                return Some(JsPayload {
                    target_object_id: Some(target_id),
                    filters,
                    content: String::from_utf8_lossy(&decoded).into_owned(),
                });
            }
            Err(e) => tracing::debug!(
                target: "filefacts::pdf",
                stage = "javascript",
                object = target_id,
                offset = s,
                len = raw.len(),
                error = %e,
                "/JS stream not decoded"
            ),
        }
    }
    // String-object fallback — the target dict region may just be a
    // bare `(literal)` or `<hex>` string instead of an actual dict.
    let target_dict = target.dict(bytes);
    let p = skip_while(target_dict, 0, u8::is_ascii_whitespace);
    let content = match target_dict.get(p) {
        Some(&b'(') => read_literal_string(target_dict, p + 1)?,
        Some(&b'<') if target_dict.get(p + 1) != Some(&b'<') => {
            read_hex_string(target_dict, p + 1)?
        }
        _ => return None,
    };
    Some(JsPayload {
        target_object_id: Some(target_id),
        filters: Vec::new(),
        content,
    })
}

/// Scan for `/Type /Filespec` records and return each
/// `(filename, size?)` pair. `filename` comes from `/UF` (Unicode)
/// when present, falling back to `/F` (legacy). `size` is the
/// `/Length` of the embedded-file stream referenced by `/EF /F
/// <id> <gen> R` — recovered by walking the dict-region index back
/// to the target object.
pub(super) fn scan_embedded_files(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    objects: &ObjectIndex<'_>,
) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    for region in dict_regions {
        let dict = region.dict(bytes);
        if !has_name(dict, b"Type", b"Filespec") {
            continue;
        }
        let name = find_info_value(dict, b"/UF").or_else(|| find_info_value(dict, b"/F"));
        let Some(filename) = name.filter(|n| !n.is_empty()) else {
            continue;
        };
        // `/EF` is an embedded-files dict: `<< /F <ref> /UF <ref> >>`.
        // Find the indirect reference and chase it.
        let size = find_ef_stream_length(dict, objects, bytes);
        out.push((filename, size));
    }
    out
}

/// Pull the `/Length` (file size in bytes) of the embedded-file
/// stream referenced from a `/Filespec` dict's `/EF` entry. Walks
/// `/EF` → indirect ref → target object dict's `/Length`. Resolves
/// `/Length` itself if it's also an indirect ref (rare but legal).
fn find_ef_stream_length(
    filespec_dict: &[u8],
    objects: &ObjectIndex<'_>,
    bytes: &[u8],
) -> Option<u64> {
    // Locate `/EF` then the inner `/F <id> <gen> R` or
    // `/UF <id> <gen> R` reference.
    let ef_pos = memchr::memmem::find(filespec_dict, b"/EF").filter(|&p| {
        filespec_dict
            .get(p + 3)
            .is_some_and(|b| !b.is_ascii_alphabetic())
    })?;
    let window_end = (ef_pos + 256).min(filespec_dict.len());
    let window = filespec_dict.get(ef_pos..window_end)?;
    let target_id = parse_indirect_ref_value(window, b"/F")
        .or_else(|| parse_indirect_ref_value(window, b"/UF"))?;
    let target_dict = objects.get(&target_id)?.dict(bytes);
    let length_text = find_info_value(target_dict, b"/Length")?;
    if let Ok(direct) = length_text.parse::<u64>() {
        return Some(direct);
    }
    // Indirect length — try `<id> <gen> R` form. The length object's
    // body is the bare number.
    let length_ref = parse_indirect_ref_value(target_dict, b"/Length")?;
    let digits: String = objects
        .get(&length_ref)?
        .dict(bytes)
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    digits.parse().ok()
}
