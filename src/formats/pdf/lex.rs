//! PDF byte-level syntax: names, strings, and the small scanners the rest of
//! the extractor is built on. Every reader takes untrusted bytes and an
//! offset, and answers `None` rather than reading past what it was given.

use std::borrow::Cow;

use crate::formats::common::hex_nibble;

/// Input bytes one literal string may span. Four per output byte covers a
/// string of 1 KiB written entirely in `\ddd` escapes, the densest spelling
/// there is.
const MAX_LITERAL_SPAN: usize = 4 * 1024;

pub(super) fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// PDF whitespace (ISO 32000-1 §7.2.2): NUL, HT, LF, FF, CR and space.
pub(super) fn is_white(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// The byte before `at`, or a space at the start of the input.
pub(super) fn byte_before(bytes: &[u8], at: usize) -> u8 {
    at.checked_sub(1)
        .and_then(|i| bytes.get(i))
        .copied()
        .unwrap_or(b' ')
}

/// The first position at or after `from` whose byte fails `pred`, or the
/// end of `bytes`.
pub(super) fn skip_while(bytes: &[u8], from: usize, pred: impl Fn(&u8) -> bool) -> usize {
    from + bytes
        .get(from..)
        .map_or(0, |rest| rest.iter().take_while(|b| pred(b)).count())
}

/// The first position at or after `at` that is neither whitespace nor part
/// of a comment (`%` to the end of the line).
fn skip_white_and_comments(bytes: &[u8], mut at: usize) -> usize {
    loop {
        at = skip_while(bytes, at, |&b| is_white(b));
        if bytes.get(at) != Some(&b'%') {
            return at;
        }
        at = skip_while(bytes, at, |&b| b != b'\n' && b != b'\r');
    }
}

/// A name's characters with each `#xx` escape (§7.3.5) replaced by the byte
/// it stands for. A `#` not followed by two hex digits is itself.
fn decode_name(raw: &[u8]) -> Cow<'_, [u8]> {
    if !raw.contains(&b'#') {
        return Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((&b, tail)) = rest.split_first() {
        if let (b'#', [hi, lo, after @ ..]) = (b, tail)
            && let (Some(h), Some(l)) = (hex_nibble(*hi), hex_nibble(*lo))
        {
            out.push((h << 4) | l);
            rest = after;
            continue;
        }
        out.push(b);
        rest = tail;
    }
    Cow::Owned(out)
}

/// The decoded name whose `/` is at `slash`, and the position just past it.
/// A name runs to the first whitespace or delimiter (§7.2.2).
fn name_at(bytes: &[u8], slash: usize) -> Option<(Cow<'_, [u8]>, usize)> {
    let start = slash + 1;
    let end = skip_while(bytes, start, |&b| {
        !is_white(b)
            && !matches!(
                b,
                b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
            )
    });
    Some((decode_name(bytes.get(start..end)?), end))
}

/// The position just past each `key` entry's key in `dict`, wherever the
/// name appears (nested dictionaries included).
///
/// Every name is compared decoded: writers that obfuscate spell keys and
/// values with escapes (`/Ty#70e` is `/Type`) to slip past byte searches.
pub(super) fn key_ends<'a>(dict: &'a [u8], key: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut pos = 0;
    std::iter::from_fn(move || {
        let slash = pos + memchr::memchr(b'/', dict.get(pos..)?)?;
        let (name, end) = name_at(dict, slash)?;
        pos = end;
        Some((name, end))
    })
    .filter(move |(name, _)| **name == *key)
    .map(|(_, end)| end)
}

/// The name values of every `key` entry in `dict`, decoded. Key and value
/// may be separated by any whitespace or comments, and either may carry
/// `#xx` escapes; `/Type\n/Sig`, `/Type  /Sig` and `/Ty#70e/Sig` all read
/// as a `Sig` type.
pub(super) fn dict_names<'a>(
    dict: &'a [u8],
    key: &'a [u8],
) -> impl Iterator<Item = Cow<'a, [u8]>> + 'a {
    key_ends(dict, key).filter_map(|end| {
        let at = skip_white_and_comments(dict, end);
        if dict.get(at) != Some(&b'/') {
            return None;
        }
        name_at(dict, at).map(|(name, _)| name)
    })
}

/// Whether some `key` entry of `dict` has the name `value`.
pub(super) fn has_name(dict: &[u8], key: &[u8], value: &[u8]) -> bool {
    dict_names(dict, key).any(|name| *name == *value)
}

/// The names a `/Filter` value at `at` lists: one name, or an array of
/// them. An array missing its `]` is read to the end of the input.
pub(super) fn name_list(bytes: &[u8], at: usize) -> Option<Vec<String>> {
    let at = skip_white_and_comments(bytes, at);
    let mut out = Vec::new();
    match *bytes.get(at)? {
        b'/' => out.push(name_at(bytes, at)?.0),
        b'[' => {
            let mut cursor = at + 1;
            loop {
                cursor = skip_white_and_comments(bytes, cursor);
                match bytes.get(cursor) {
                    Some(b']') | None => break,
                    Some(b'/') => {
                        let (name, end) = name_at(bytes, cursor)?;
                        out.push(name);
                        cursor = end;
                    }
                    Some(_) => return None,
                }
            }
        }
        _ => return None,
    }
    if out.is_empty() || out.iter().any(|n| n.is_empty()) {
        return None;
    }
    Some(
        out.iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect(),
    )
}

/// PDF names start with `/` and continue with regular characters until
/// whitespace or a delimiter. Returned as written, slash included.
pub(super) fn read_name(bytes: &[u8], start: usize) -> Option<String> {
    let end = skip_while(bytes, start, |&b| {
        !matches!(
            b,
            b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'<' | b'>' | b'[' | b']' | b'('
        )
    });
    let name = bytes.get(start..end).filter(|n| !n.is_empty())?;
    Some(format!("/{}", String::from_utf8_lossy(name)))
}

/// Locate `/Key` and return its associated string-or-name value.
/// Handles `(…)` literal strings, `<…>` hex strings, and bare names
/// (`/Producer /WatermarkPDF`). Returns `None` when the key isn't
/// followed by a recognizable value.
///
/// Suffix-collision aware: scanning continues past matches whose
/// trailing byte is a name char (so searching for `/T` skips past
/// `/Type` and `/Title` until it finds a real `/T` boundary).
pub(super) fn find_info_value(bytes: &[u8], key: &[u8]) -> Option<String> {
    let mut cursor = 0;
    while cursor + key.len() <= bytes.len() {
        let rel = memchr::memmem::find(bytes.get(cursor..)?, key)?;
        let after_key = cursor + rel + key.len();
        let next = *bytes.get(after_key)?;
        if next.is_ascii_alphabetic() || next == b'_' {
            cursor = after_key;
            continue;
        }
        return value_after_key(bytes, after_key);
    }
    None
}

/// The value of a key that ends at `after_key`: a literal or hex string, a
/// name, or a bare number, after optional spaces and tabs.
pub(super) fn value_after_key(bytes: &[u8], after_key: usize) -> Option<String> {
    let value_pos = skip_while(bytes, after_key, |&b| b == b' ' || b == b'\t');
    match *bytes.get(value_pos)? {
        b'(' => read_literal_string(bytes, value_pos + 1),
        b'<' if bytes.get(value_pos + 1) != Some(&b'<') => read_hex_string(bytes, value_pos + 1),
        b'/' => read_name(bytes, value_pos + 1),
        b'0'..=b'9' | b'-' => {
            // A bare number (`/Length 42`): the digit and sign run.
            let end = skip_while(bytes, value_pos, |&b| {
                b.is_ascii_digit() || b == b'-' || b == b'.'
            });
            std::str::from_utf8(bytes.get(value_pos..end)?)
                .ok()
                .map(str::to_string)
        }
        _ => None,
    }
}

/// PDF literal strings are `(text)` with balanced parens and `\)`
/// escapes. We cap at 1024 bytes and decode lossily to UTF-8.
///
/// The input read is capped too, at [`MAX_LITERAL_SPAN`]: a line
/// continuation produces no output, so an output cap alone would let every
/// site in a dictionary of continuations read to its end.
pub(super) fn read_literal_string(bytes: &[u8], start: usize) -> Option<String> {
    const CAP: usize = 1024;
    let mut depth = 1_i32;
    let mut out = Vec::new();
    let mut i = start;
    let span_end = start.saturating_add(MAX_LITERAL_SPAN);
    while out.len() < CAP && i < span_end {
        let Some(&b) = bytes.get(i) else {
            break;
        };
        // PDF escape sequences inside literal strings:
        //   \n \r \t \b \f \( \) \\  → single-byte escapes
        //   \NNN                       → 1-3 octal digits
        //   \<eol>                     → line continuation
        if let (b'\\', Some(&esc)) = (b, bytes.get(i + 1)) {
            match esc {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'b' => out.push(8),
                b'f' => out.push(12),
                b'(' | b')' | b'\\' => out.push(esc),
                b'\n' | b'\r' => { /* line continuation: drop */ }
                b'0'..=b'7' => {
                    let mut j = i + 1;
                    let mut value: u16 = 0;
                    let mut count = 0;
                    while count < 3 {
                        let Some(&digit) = bytes.get(j).filter(|d| (b'0'..=b'7').contains(*d))
                        else {
                            break;
                        };
                        value = value * 8 + u16::from(digit - b'0');
                        j += 1;
                        count += 1;
                    }
                    out.push((value & 0xFF) as u8);
                    i = j;
                    continue;
                }
                _ => out.push(esc),
            }
            i += 2;
            continue;
        }
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        out.push(b);
        i += 1;
    }
    if out.is_empty() {
        return None;
    }
    Some(decode_text_string(&out))
}

/// A decoded PDF string as text. PDF Title/Author are frequently UTF-16BE
/// with the `FE FF` BOM: decode those; fall back to lossy UTF-8 otherwise.
fn decode_text_string(raw: &[u8]) -> String {
    if let Some(be) = raw.strip_prefix(&[0xFE, 0xFF]) {
        return crate::bytes::utf16_lossy(be, crate::bytes::Endian::Big)
            .trim()
            .to_string();
    }
    String::from_utf8_lossy(raw).trim().to_string()
}

/// PDF hex strings are `<HH HH …>`, decoded to text the same way as
/// literal strings.
pub(super) fn read_hex_string(bytes: &[u8], start: usize) -> Option<String> {
    let (out, closed) = decode_hex(bytes.get(start..)?.iter().copied(), usize::MAX);
    (closed && !out.is_empty()).then(|| decode_text_string(&out))
}

/// Decode hex digit pairs up to a closing `>`, skipping whitespace and
/// keeping at most `cap` bytes; a final odd digit is the high nibble of a
/// last byte. The flag says whether `>` closed the run.
///
/// The read stops at the first byte that is neither a hex digit nor
/// whitespace, so it never runs past the value: finding the closing `>`
/// first would make each of many `/URI <` sites in one dictionary scan the
/// rest of it.
pub(super) fn decode_hex(input: impl IntoIterator<Item = u8>, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut high = None;
    for b in input {
        if out.len() >= cap {
            break;
        }
        if b == b'>' {
            if let Some(h) = high {
                out.push(h << 4);
            }
            return (out, true);
        }
        if is_white(b) {
            continue;
        }
        let Some(nibble) = hex_nibble(b) else {
            break;
        };
        match high.take() {
            None => high = Some(nibble),
            Some(h) => out.push((h << 4) | nibble),
        }
    }
    (out, false)
}

/// `s` cut to at most `max` bytes, on a character boundary.
pub(super) fn truncate(s: &str, max: usize) -> String {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_string()
}

/// Find `/key` then read the immediately-following `N M R` indirect
/// reference, returning the object id `N`. Returns `None` when the
/// key isn't present or its value isn't an indirect reference.
pub(super) fn parse_indirect_ref_value(bytes: &[u8], key: &[u8]) -> Option<u32> {
    let mut cursor = 0;
    while cursor + key.len() <= bytes.len() {
        let rel = memchr::memmem::find(bytes.get(cursor..)?, key)?;
        let after_idx = cursor + rel + key.len();
        let after = *bytes.get(after_idx)?;
        if after.is_ascii_alphabetic() || after == b'_' {
            cursor = after_idx;
            continue;
        }
        // Expect digits, whitespace, digits, whitespace, 'R'.
        let id_start = skip_while(bytes, after_idx, u8::is_ascii_whitespace);
        let id_end = skip_while(bytes, id_start, u8::is_ascii_digit);
        let id: u32 = std::str::from_utf8(bytes.get(id_start..id_end)?)
            .ok()?
            .parse()
            .ok()?;
        let gen_start = skip_while(bytes, id_end, u8::is_ascii_whitespace);
        let gen_end = skip_while(bytes, gen_start, u8::is_ascii_digit);
        if gen_end == gen_start {
            return None;
        }
        let p = skip_while(bytes, gen_end, u8::is_ascii_whitespace);
        return (bytes.get(p) == Some(&b'R')).then_some(id);
    }
    None
}

/// The first `needle` in `from..to` that is a whole token: neither the
/// preceding nor following byte may be a name char. The bytes on either
/// side of a match are judged from `bytes`, so a token at the bound is
/// accepted or rejected exactly as an unbounded search would.
pub(super) fn find_token_between(
    bytes: &[u8],
    from: usize,
    to: usize,
    needle: &[u8],
) -> Option<usize> {
    let to = to.min(bytes.len());
    if from >= to {
        return None;
    }
    memchr::memmem::find_iter(bytes.get(from..to)?, needle)
        .map(|rel| from + rel)
        .find(|&abs| {
            let before = byte_before(bytes, abs);
            let after = bytes.get(abs + needle.len()).copied().unwrap_or(b' ');
            !is_name_char(before) && !is_name_char(after)
        })
}
