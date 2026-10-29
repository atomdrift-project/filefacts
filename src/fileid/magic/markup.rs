//! Markup read the way a parser reads it: a document's root element, Windows
//! Script Host documents, and Script Encoder output.

use std::path::Path;

use super::{DetectionSource, FileType, Sniff};
use crate::fileid::text::{find_ci, strip_utf8_bom};

/// How far into a Windows Script Host document the `<script>` element is
/// looked for. Droppers pad the opening tags with whitespace.
pub(in crate::fileid) const WSH_SCRIPT_WINDOW: usize = 64 * 1024;

/// A `.wsf` / `.wsc` / `.sct` document, typed by the language of its first
/// `<script>`: VBScript or JScript. The root element decides it is one --
/// `<job>`, `<package>`, `<component>` or `<scriptlet>`; an HTML page with a
/// VBScript block stays HTML.
pub(super) fn script_host_document(sniff: &Sniff<'_>) -> Option<FileType> {
    // These are written by hand in Notepad as often as by tools, UTF-16 included.
    let data = sniff.data;
    let data = if data.starts_with(b"\xFF\xFE") || data.starts_with(b"\xFE\xFF") {
        sniff.decoded()?
    } else {
        data
    };
    // `<!-- :` is cmd.exe's half of a batch/WSF hybrid: the batch lines hide
    // in that comment, and cmd.exe runs them first. The batch grammar decides.
    let opening = data.trim_ascii_start();
    if opening
        .get(..6)
        .is_some_and(|open| open.eq_ignore_ascii_case(b"<!-- :"))
    {
        return None;
    }
    let head = xml_head(data)?;
    let root = head.root?;
    if !["job", "package", "component", "scriptlet"]
        .iter()
        .any(|r| root.eq_ignore_ascii_case(r.as_bytes()))
    {
        return None;
    }
    let mut rest = data.get(..WSH_SCRIPT_WINDOW).unwrap_or(data);
    while let Some(at) = find_ci(rest, b"<script") {
        let Some(after) = rest.get(at + b"<script".len()..) else {
            break;
        };
        let tag = memchr::memchr(b'>', after)
            .and_then(|end| after.get(..end))
            .unwrap_or(after);
        if let Some(language) = attribute_value(tag, b"language") {
            let language = decode_char_refs(language).to_ascii_lowercase();
            if language.starts_with("vbs") {
                return Some(FileType::Vbs);
            }
            if language.starts_with("jscript") || language.starts_with("javascript") {
                return Some(FileType::JavaScript);
            }
        }
        rest = after;
    }
    None
}

/// The value of `name="..."` (or single-quoted) inside a tag, whitespace
/// around the `=` allowed.
pub(super) fn attribute_value<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut from = 0;
    while let Some(at) = find_ci(tag.get(from..)?, name) {
        let start = from + at;
        let (before, found) = tag.split_at_checked(start)?;
        let rest = found.get(name.len()..)?.trim_ascii_start();
        let boundary = before.last().is_none_or(u8::is_ascii_whitespace);
        if let (true, Some(value)) = (boundary, rest.strip_prefix(b"=")) {
            let value = value.trim_ascii_start();
            let (&quote, inner) = value.split_first()?;
            if quote == b'"' || quote == b'\'' {
                return inner.split(|&b| b == quote).next();
            }
            return value
                .split(|b| b.is_ascii_whitespace() || *b == b'/')
                .next();
        }
        from = start + name.len();
    }
    None
}

/// Resolve `&#86;` / `&#x56;` character references, which obfuscated
/// scriptlets use to spell `VBScript` without the letters.
pub(super) fn decode_char_refs(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some((&b, tail)) = rest.split_first() {
        if b == b'&' && tail.first() == Some(&b'#') {
            if let Some(end) = tail.iter().position(|&c| c == b';') {
                let digits = tail
                    .get(1..end)
                    .and_then(|d| std::str::from_utf8(d).ok())
                    .unwrap_or("");
                let code = match digits.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => digits.parse().ok(),
                };
                if let Some(c) = code.and_then(char::from_u32) {
                    out.push(c);
                    rest = tail.get(end + 1..).unwrap_or_default();
                    continue;
                }
            }
        }
        out.push(char::from(b));
        rest = tail;
    }
    out
}

/// Script Encoder output: `#@~^` + base64 length + `==`. The cipher hides
/// which language was encoded, so the one call the bytes cannot make falls to
/// the name: `.jse` is JScript, anything else the far more common VBScript.
pub(super) fn encoded_script(path: &Path, head: &[u8]) -> Option<FileType> {
    let rest = strip_utf8_bom(head).strip_prefix(b"#@~^")?;
    let length = rest.get(..6)?;
    if !length
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        || rest.get(6..8) != Some(b"==")
    {
        return None;
    }
    let jse = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("jse"));
    Some(if jse {
        FileType::JavaScript
    } else {
        FileType::Vbs
    })
}

/// Type a markup document by its root element: `plist`, `svg`, a known XML
/// vocabulary, or any document with an `<?xml` prolog. HTML is claimed
/// earlier and by the heuristics, not here.
pub(super) fn detect_xml(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    let head = xml_head(data)?;
    let ft = match head.root {
        Some(b"plist") => FileType::Plist,
        Some(b"svg") => FileType::Svg,
        // MSBuild projects often omit the prolog and open with `<Project`;
        // the namespace keeps some other `<Project>` out.
        Some(b"Project")
            if memchr::memmem::find(head.text, b"schemas.microsoft.com/developer/msbuild")
                .is_some() =>
        {
            FileType::Xml
        }
        Some(
            b"rss" | b"feed" | b"RDF" | b"rdf:RDF" | b"configuration" | b"Configuration"
            | b"manifest",
        ) => FileType::Xml,
        _ if head.prolog => FileType::Xml,
        _ => return None,
    };
    Some((ft, DetectionSource::Magic))
}

/// How far into a document [`xml_head`] looks for the root element.
const XML_HEAD: usize = 1024;

/// The opening of a markup document, read the way a parser reads it.
struct XmlHead<'a> {
    /// The bytes read.
    text: &'a [u8],
    /// Whether an `<?xml` declaration came first.
    prolog: bool,
    /// The root element's name: the first element, or the doctype's name when
    /// the head ends before any element. `None` when the two disagree -- a
    /// document that contradicts itself is claimed by neither.
    root: Option<&'a [u8]>,
}

/// Read past a BOM, whitespace, processing instructions, comments and the
/// doctype to the root element. `None` unless the document opens with `<`.
fn xml_head(data: &[u8]) -> Option<XmlHead<'_>> {
    let text = data.get(..XML_HEAD).unwrap_or(data);
    let mut rest = strip_utf8_bom(text).trim_ascii_start();
    if !rest.starts_with(b"<") {
        return None;
    }
    let prolog = rest.starts_with(b"<?xml");
    let mut doctype = None;
    let element = loop {
        rest = rest.trim_ascii_start();
        let close: &[u8] = if rest.starts_with(b"<?") {
            b"?>"
        } else if rest.starts_with(b"<!--") {
            b"-->"
        } else if let Some((open, after)) = rest.split_at_checked(9)
            && open.eq_ignore_ascii_case(b"<!DOCTYPE")
        {
            doctype = Some(markup_name(after.trim_ascii_start()));
            b">"
        } else if rest.starts_with(b"<!") {
            b">"
        } else if let Some(name) = rest.strip_prefix(b"<") {
            break Some(markup_name(name));
        } else {
            break None;
        };
        match memchr::memmem::find(rest, close).and_then(|end| rest.get(end + close.len()..)) {
            Some(after) => rest = after,
            None => break None,
        }
    };
    let root = match (doctype, element) {
        (Some(d), Some(e)) if d != e => None,
        (d, e) => e.or(d),
    };
    Some(XmlHead {
        text,
        prolog,
        root: root.filter(|r| !r.is_empty()),
    })
}

/// The name that opens `bytes`, up to whitespace, `>`, `/` or `[`.
fn markup_name(bytes: &[u8]) -> &[u8] {
    bytes
        .split(|&b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/' | b'['))
        .next()
        .unwrap_or(bytes)
}
