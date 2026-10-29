//! Object boundaries: the `<id> <gen> obj` regions of the file as written,
//! the objects packed into object streams, and the facts read from them as
//! a set (types, references, object-stream counts).

use std::collections::{BTreeSet, HashMap};

use super::MAX_INFLATED;
use super::filters::{decode_stream, find_filters};
use super::lex::{
    byte_before, dict_names, find_info_value, find_token_between, has_name, is_name_char,
    skip_while,
};

/// Upper bound on how many `<id> <gen> obj` dict regions we collect
/// from a single PDF. Adversarial inputs can stuff millions of
/// skeleton objects to amplify every downstream pass. Real-world
/// PDFs hold a few thousand objects; cap with comfortable headroom
/// and surface a metric so trait rules can spot truncation.
pub(super) const MAX_DICT_REGIONS: usize = 50_000;

/// Object boundaries within the file: dict range plus, when the
/// object carries a `stream` body, the stream byte range. Action /
/// filter scans use only `start..end` so they never see stream-body
/// bytes (high-entropy binary that false-positives `/JS` and friends).
#[derive(Debug, Clone)]
pub(super) struct DictRegion {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) obj_id: Option<u32>,
    /// Byte range of the stream body (the bytes between `stream\n`
    /// and `\nendstream`) when this object has one.
    pub(super) stream_range: Option<(usize, usize)>,
}

impl DictRegion {
    /// The dictionary bytes, `start..end` of `bytes`. Regions always lie
    /// inside the bytes they were collected from; anything else reads as
    /// an empty dictionary.
    pub(super) fn dict<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        bytes.get(self.start..self.end).unwrap_or_default()
    }
}

/// The object regions of a file, and what it cost to find them.
pub(super) struct RegionWalk {
    pub(super) regions: Vec<DictRegion>,
    /// Bytes handed to token searches over the walk. The walk is linear
    /// when this stays within a small multiple of the input length.
    pub(super) searched: usize,
}

/// Walk every `<id> <gen> obj` … (`stream`|`endobj`) block. Each
/// returned region carries the dict byte range and, when a stream
/// body was present, the stream byte range too. Output is capped
/// at [`MAX_DICT_REGIONS`] entries — adversarial inputs that stuff
/// millions of skeleton objects would otherwise turn every
/// downstream pass into a quadratic walk.
pub(super) fn collect_dict_regions(bytes: &[u8]) -> RegionWalk {
    let mut regions = Vec::new();
    let mut searched = 0;
    let mut pos = 0;
    let mut next_endobj = NextToken::new(b"endobj");
    let mut next_endstream = NextToken::new(b"endstream");
    while pos < bytes.len() && regions.len() < MAX_DICT_REGIONS {
        let rest = bytes.get(pos..).unwrap_or_default();
        let Some(rel) = memchr::memmem::find(rest, b"obj") else {
            searched += rest.len();
            break;
        };
        searched += rel + 3;
        let obj_pos = pos + rel;
        // Require whole-token: the byte before `obj` must be
        // whitespace and the byte after must not be a name char
        // (avoids matching `endobj`, `objstm`, etc.).
        let before = byte_before(bytes, obj_pos);
        let after = bytes.get(obj_pos + 3).copied().unwrap_or(b' ');
        if !before.is_ascii_whitespace() || is_name_char(after) {
            pos = obj_pos + 3;
            continue;
        }
        let obj_id = parse_obj_id_before(bytes, obj_pos);
        let dict_start = obj_pos + 3;
        // Dict ends at the nearest `stream` or `endobj` token. Both are
        // whole tokens, so accept any non-name char as the delimiter
        // (space, newline, etc.). `endobj` first, and `stream` only inside
        // this object: an object without a stream would otherwise search
        // on to the next stream in the file, and a tagged PDF ends with
        // thousands of stream-less structure objects, each of which would
        // scan to end-of-file.
        let endobj_end = next_endobj.find(bytes, dict_start);
        let bound = endobj_end.unwrap_or(bytes.len());
        let stream_end_marker = find_token_between(bytes, dict_start, bound, b"stream");
        searched += stream_end_marker
            .map_or(bound, |s| s + b"stream".len())
            .saturating_sub(dict_start);
        let dict_end = match (stream_end_marker, endobj_end) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        // A stream is present when the `stream` token came before
        // `endobj`; find where its body ends.
        let stream_range = match (stream_end_marker, endobj_end) {
            (Some(s), Some(e)) if s < e => {
                // Skip past `stream` + optional CR/LF.
                let mut body_start = s + b"stream".len();
                if bytes.get(body_start) == Some(&b'\r') {
                    body_start += 1;
                }
                if bytes.get(body_start) == Some(&b'\n') {
                    body_start += 1;
                }
                let dict = bytes.get(dict_start..dict_end).unwrap_or_default();
                let declared = match classify_stream_length(dict) {
                    LengthValue::Direct(n) => declared_stream_end(bytes, body_start, n),
                    _ => None,
                };
                let body_end = declared.unwrap_or_else(|| {
                    let endstream = next_endstream.find(bytes, body_start).unwrap_or(e);
                    fallback_stream_end(bytes, body_start, endstream)
                });
                Some((body_start, body_end))
            }
            _ => None,
        };
        regions.push(DictRegion {
            start: dict_start,
            end: dict_end,
            obj_id,
            stream_range,
        });
        // Skip past the stream body if one was present: `endobj_end`
        // is the first `endobj` after the dict, so it is the one after
        // `endstream` too.
        pos = match (stream_end_marker, endobj_end) {
            (Some(s), Some(e)) if s < e => e,
            _ => dict_end,
        };
    }
    RegionWalk {
        regions,
        searched: searched + next_endobj.searched + next_endstream.searched,
    }
}

/// Recover the `<id>` from a `<id> <gen> obj` preamble immediately
/// before `obj_pos`. Returns `None` when the preamble doesn't parse
/// (object stream entries, malformed inputs).
fn parse_obj_id_before(bytes: &[u8], obj_pos: usize) -> Option<u32> {
    /// `bytes` split before its trailing run of bytes that satisfy `pred`.
    fn split_trailing(bytes: &[u8], pred: impl Fn(&u8) -> bool) -> (&[u8], &[u8]) {
        let run = bytes.iter().rev().take_while(|b| pred(b)).count();
        bytes
            .split_at_checked(bytes.len() - run)
            .unwrap_or((bytes, &[]))
    }
    // Walk back over whitespace then digits twice (gen, then id),
    // with whitespace between them.
    let (head, _) = split_trailing(bytes.get(..obj_pos)?, u8::is_ascii_whitespace);
    let (head, generation) = split_trailing(head, u8::is_ascii_digit);
    if generation.is_empty() {
        return None;
    }
    let (head, _) = split_trailing(head, u8::is_ascii_whitespace);
    let (_, id) = split_trailing(head, u8::is_ascii_digit);
    std::str::from_utf8(id).ok()?.parse().ok()
}

/// The first whole-token occurrence of a needle at or after a position, for
/// a walk whose positions only grow.
///
/// The answer for one position holds for every later one up to the token
/// itself, and "none left" holds for good, so a search runs again only once
/// the walk has passed the token it found. Searching afresh for each object
/// would make a file of objects missing their `endobj` or `endstream`
/// quadratic: every one would scan to end-of-file for the token that is not
/// there.
struct NextToken {
    needle: &'static [u8],
    /// Whether `found` holds a search result yet.
    started: bool,
    /// The last search's result; `None` once none is left.
    found: Option<usize>,
    /// Bytes searched so far.
    searched: usize,
}

impl NextToken {
    fn new(needle: &'static [u8]) -> Self {
        Self {
            needle,
            started: false,
            found: None,
            searched: 0,
        }
    }

    fn find(&mut self, bytes: &[u8], from: usize) -> Option<usize> {
        if self.started {
            match self.found {
                Some(at) if at >= from => return Some(at),
                None => return None,
                Some(_) => {}
            }
        }
        self.started = true;
        self.found = find_token_between(bytes, from, bytes.len(), self.needle);
        self.searched += self
            .found
            .map_or(bytes.len(), |at| at + self.needle.len())
            .saturating_sub(from);
        self.found
    }
}

/// Return the stream body end implied by a direct `/Length`, but only
/// when `endstream` sits exactly at that boundary. PDF writers
/// normally put an EOL before `endstream`, but real generated PDFs may
/// omit it; in that case compressed body bytes can end with a name
/// character and form raw byte strings such as `sendstream`. A whole
/// token scan misses those valid boundaries, so prefer the declared
/// length when it is self-consistent.
fn declared_stream_end(bytes: &[u8], body_start: usize, declared: u64) -> Option<usize> {
    let declared = usize::try_from(declared).ok()?;
    let body_end = body_start.checked_add(declared)?;
    if body_end > bytes.len() {
        return None;
    }
    let mut marker = body_end;
    if bytes.get(marker) == Some(&b'\r') {
        marker += 1;
    }
    if bytes.get(marker) == Some(&b'\n') {
        marker += 1;
    }
    bytes
        .get(marker..marker.saturating_add(b"endstream".len()))
        .filter(|w| *w == b"endstream")
        .map(|_| body_end)
}

/// The end of a stream body that runs from `body_start` to `endstream`
/// (the `endstream` token, or the object's end when there is none), less
/// a single trailing CR/LF.
fn fallback_stream_end(bytes: &[u8], body_start: usize, endstream: usize) -> usize {
    let mut body_end = endstream;
    if body_end > body_start && byte_before(bytes, body_end) == b'\n' {
        body_end -= 1;
    }
    if body_end > body_start && byte_before(bytes, body_end) == b'\r' {
        body_end -= 1;
    }
    body_end
}

/// Classification of a stream dictionary's `/Length` value.
///
/// The PDF spec allows three concrete shapes — direct numeric,
/// indirect reference, or absent — and adversarial inputs add a
/// fourth (junk).
#[derive(Debug)]
pub(super) enum LengthValue {
    Missing,
    Invalid,
    Indirect,
    Direct(u64),
}

/// Inspect a stream dict for its `/Length` value and classify it.
pub(super) fn classify_stream_length(dict: &[u8]) -> LengthValue {
    let key = b"/Length";
    let mut cursor = 0;
    while cursor + key.len() <= dict.len() {
        let Some(rel) = dict
            .get(cursor..)
            .and_then(|rest| memchr::memmem::find(rest, key))
        else {
            return LengthValue::Missing;
        };
        let after = cursor + rel + key.len();
        // Reject suffix collisions: `/LengthBytes`, `/Length1` (font
        // subset metadata) — both are valid name characters after the
        // key.
        match dict.get(after).copied() {
            Some(b) if is_name_char(b) => {
                cursor = after;
                continue;
            }
            None => return LengthValue::Missing,
            _ => {}
        }
        // Capture the run of non-delimiter bytes up to the next
        // `/` or `>>` boundary. Whitespace is permitted (indirect
        // refs span three whitespace-separated tokens).
        let end = skip_while(dict, after, |b| {
            !matches!(b, b'/' | b'<' | b'>' | b'[' | b']')
        });
        let value = dict
            .get(after..end)
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("")
            .trim();
        if value.is_empty() {
            return LengthValue::Missing;
        }
        if let Ok(n) = value.parse::<u64>() {
            return LengthValue::Direct(n);
        }
        // Indirect ref: `<id> <gen> R` — three whitespace tokens.
        let parts: Vec<&str> = value.split_whitespace().collect();
        if let [id, generation, "R"] = parts.as_slice()
            && id.parse::<u32>().is_ok()
            && generation.parse::<u32>().is_ok()
        {
            return LengthValue::Indirect;
        }
        return LengthValue::Invalid;
    }
    LengthValue::Missing
}

/// Every object with an id, for following indirect references. When an id
/// repeats (an incremental update rewrote the object), the last one wins,
/// as it does for a viewer reading the final state of the document.
pub(super) type ObjectIndex<'r> = HashMap<u32, &'r DictRegion>;

/// Dictionaries counted by their `/Type`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct TypeCounts {
    pub(super) page: usize,
    pub(super) annot: usize,
    pub(super) xobject: usize,
    pub(super) font: usize,
    pub(super) metadata: usize,
    pub(super) objstm: usize,
    pub(super) xref: usize,
    pub(super) sig: usize,
}

impl TypeCounts {
    /// Count every `/Type` entry in `bytes`, in any spelling
    /// [`dict_names`] reads.
    pub(super) fn add(&mut self, bytes: &[u8]) {
        for name in dict_names(bytes, b"Type") {
            let slot = match &*name {
                b"Page" => &mut self.page,
                b"Annot" => &mut self.annot,
                b"XObject" => &mut self.xobject,
                b"Font" => &mut self.font,
                b"Metadata" => &mut self.metadata,
                b"ObjStm" => &mut self.objstm,
                b"XRef" => &mut self.xref,
                b"Sig" => &mut self.sig,
                _ => continue,
            };
            *slot += 1;
        }
    }
}

/// Decoded object streams, each carrier's object id alongside the objects
/// it holds.
pub(super) struct ObjectStreams {
    pub(super) decoded: Vec<(Option<u32>, Vec<u8>)>,
    /// Object streams left undecoded once the budget was spent.
    pub(super) over_budget: usize,
    /// Object streams whose filter chain would not decode.
    pub(super) undecodable: usize,
    /// Which object stream failed first, and why.
    pub(super) first_failure: Option<String>,
}

/// Decode every `/Type /ObjStm` stream through its `/Filter` chain,
/// keeping at most `budget` decoded bytes across all of them.
pub(super) fn decode_object_streams(
    bytes: &[u8],
    dict_regions: &[DictRegion],
    mut budget: usize,
) -> ObjectStreams {
    let mut out = ObjectStreams {
        decoded: Vec::new(),
        over_budget: 0,
        undecodable: 0,
        first_failure: None,
    };
    for region in dict_regions {
        let Some((s, e)) = region.stream_range else {
            continue;
        };
        let dict = region.dict(bytes);
        if !has_name(dict, b"Type", b"ObjStm") {
            continue;
        }
        if budget == 0 {
            out.over_budget += 1;
            continue;
        }
        let raw = bytes.get(s..e).unwrap_or_default();
        let filters = find_filters(dict).unwrap_or_default();
        match decode_stream(raw, &filters, budget.min(MAX_INFLATED)) {
            Ok(decoded) => {
                budget = budget.saturating_sub(decoded.len());
                out.decoded.push((region.obj_id, decoded));
            }
            Err(e) => {
                tracing::debug!(
                    target: "filefacts::pdf",
                    stage = "object-stream",
                    object = region.obj_id,
                    offset = s,
                    len = raw.len(),
                    filters = ?filters,
                    error = %e,
                    "object stream not decoded"
                );
                out.undecodable += 1;
                let id = region
                    .obj_id
                    .map_or_else(|| "?".to_string(), |id| id.to_string());
                out.first_failure
                    .get_or_insert_with(|| format!("object {id}: {e}"));
            }
        }
    }
    out
}

/// Sum the declared `/N` count across every `/Type /ObjStm` object
/// stream. An object stream packs multiple indirect objects into a
/// single compressed body; `/N` is the spec-mandated header field
/// stating how many objects live inside. The declared count is read
/// as written, decoded or not.
pub(super) fn object_stream_inner_count(bytes: &[u8], dict_regions: &[DictRegion]) -> u32 {
    let mut total: u32 = 0;
    for region in dict_regions {
        let dict = region.dict(bytes);
        if !has_name(dict, b"Type", b"ObjStm") {
            continue;
        }
        if let Some(n) = find_info_value(dict, b"/N").and_then(|n| n.trim().parse::<u32>().ok()) {
            total = total.saturating_add(n);
        }
    }
    total
}

/// Count object ids that are never referenced from any dict in the
/// document. Walks every dict for `<id> <gen> R` triples and
/// subtracts the reference set from the id set. Pure-orphan objects
/// don't participate in the catalog graph — a structural anomaly.
pub(super) fn unreferenced_object_count(bytes: &[u8], dict_regions: &[DictRegion]) -> u32 {
    let mut ids: BTreeSet<u32> = BTreeSet::new();
    let mut refs: BTreeSet<u32> = BTreeSet::new();
    for region in dict_regions {
        if let Some(id) = region.obj_id {
            ids.insert(id);
        }
        // Any non-alphanumeric byte separates tokens: PDF delimiters
        // (`[`, `]`, `<`, `>`, `(`, `)`, `/`) and whitespace alike, so
        // `[2 0 R]` and `12 0 R` both contribute.
        let text = String::from_utf8_lossy(region.dict(bytes));
        let tokens: Vec<&str> = text
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();
        for window in tokens.windows(3) {
            if let [id, _, "R"] = window
                && let Ok(id) = id.parse::<u32>()
            {
                refs.insert(id);
            }
        }
    }
    crate::bytes::sat_u32(ids.difference(&refs).count())
}
