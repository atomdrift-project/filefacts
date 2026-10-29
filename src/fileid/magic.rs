//! Content-based detection: magic bytes, shebangs, and structural markers.
//!
//! A dozen checks run in sequence first: text-shaped headers that may sit
//! behind whitespace or a BOM (HTML, Windows Script Host, lockfiles, `go.mod`),
//! and signatures that are not at offset 0 (an `ftyp` box at 4, an ISO volume
//! descriptor at 32 KiB, a DMG trailer at the end). The binary signatures then
//! dispatch through a first-byte jump table, so each file is compared against
//! only the formats that start with its first byte. Rarer structural checks
//! (a `ustar` header, tampered PEs, ASAR, LZMA) run last.

use std::{io::Read, path::Path};

use super::{
    Compression, DetectionSource, FileType,
    ext::{ends_with_ci, lowercase_ext},
    sniff::Sniff,
    text::{Controls, UTF8_BOM, control_bytes, strip_utf8_bom},
    torch,
};
use crate::bytes;

mod archive;
mod markup;

use archive::{Inside, TAR_HEAD_LIMIT, TAR_PEEK_LIMIT, classify_pk, classify_tar, tar_layout};
pub(super) use markup::WSH_SCRIPT_WINDOW;
use markup::{detect_xml, encoded_script, script_host_document};

/// LNK shell link CLSID header (20 bytes).
const LNK_MAGIC: &[u8] = &[
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];

/// Opening section of a Windows URL shortcut. Section names are matched
/// case-insensitively, as Windows itself matches them.
const URL_SHORTCUT_SECTION: &[u8] = b"[InternetShortcut]";

/// Recognize the narrow RTF junkfuscation shape seen in weaponized documents:
/// the `\\rt` prefix followed by junk, plus both an object group and objdata
/// in the bounded head. Those controls alone are common in text, so they only
/// count with the RTF-like opening.
pub(crate) fn looks_like_obfuscated_rtf(data: &[u8]) -> bool {
    if !data.starts_with(b"{\\rt") {
        return false;
    }
    let head = data.get(..64 * 1024).unwrap_or(data);
    memchr::memmem::find(head, b"\\object").is_some()
        && memchr::memmem::find(head, b"\\objdata").is_some()
}

/// The first line of a `.reg` file since Windows 2000, up to the version
/// number. regedit writes it as UTF-16LE behind a byte-order mark; a copy
/// re-saved in an editor may be UTF-8, with or without one.
const REGISTRY_EDITOR_HEADER: &[u8] = b"Windows Registry Editor Version";

/// Whether UTF-16LE `data` opens with the ASCII text `prefix`.
fn utf16le_starts_with(data: &[u8], prefix: &[u8]) -> bool {
    data.len() >= prefix.len() * 2
        && data
            .as_chunks::<2>()
            .0
            .iter()
            .zip(prefix)
            .all(|(unit, &b)| *unit == [b, 0])
}

/// Compiled Android XML. The container chunk says how long the document is,
/// and the next chunk is the string pool. Both have to agree; `03 00 08 00`
/// by itself is four bytes and shows up in unrelated binaries.
fn looks_like_axml(data: &[u8]) -> bool {
    if data.len() > 16 * 1024 * 1024 {
        return false;
    }
    // Chunk type 0x0003 and header size 8 (u16 LE each), the u32 file size,
    // then the string pool's chunk type, 0x0001, in a header of 12 bytes.
    let &[0x03, 0x00, 0x08, 0x00, s0, s1, s2, s3, 0x01, 0x00, _, _, ..] = data else {
        return false;
    };
    u32::from_le_bytes([s0, s1, s2, s3]) as usize == data.len()
}

/// A content check's verdict: the type and how it was detected.
type Found = (FileType, DetectionSource);

/// What every content rule reads: the sniffed input, with the facts most of
/// them share worked out once.
struct Probe<'s, 'a> {
    sniff: &'s Sniff<'a>,
    path: &'a Path,
    data: &'a [u8],
    first: u8,
    second: u8,
    /// [`content_is_text`] of `data`. Every binary header this module claims
    /// by a short signature carries a NUL or control byte near the front; a
    /// script that merely opens with the same letters (`MZ=1;…`, `true && …`,
    /// `GIF89a=…`) carries none.
    text: bool,
    /// `data` past leading whitespace.
    head: &'a [u8],
}

/// The content rules in the order they are tried; the first that claims the
/// bytes decides. Text-shaped headers that may sit behind whitespace or a BOM
/// and signatures that are not at offset 0 come first, then the first-byte
/// jump table, then the rarer structural checks.
const RULES: &[fn(&Probe<'_, '_>) -> Option<Found>] = &[
    cold_fusion_template,
    phar,
    go_module,
    iso_base_media,
    url_shortcut,
    script_host,
    script_encoder,
    lockfile,
    postscript,
    android_binary_xml,
    html_document,
    udif_dmg,
    vhd_image,
    iso_image,
    certificate_signature,
    image4_trustcache,
    tiff_header,
    renpy_compiled_script,
    renpy_archive,
    leading_signature,
    ustar,
    python_bytecode,
    tampered_pe,
    markup,
    asar,
    lzma_alone,
    github_actions_workflow,
    chrome_manifest,
];

/// The signature stage: the first content rule that claims the bytes.
pub(super) fn detect_from_sniff(sniff: &Sniff<'_>) -> Option<Found> {
    let data = sniff.data;
    let &[first, second, ..] = data else {
        return None;
    };
    let probe = Probe {
        sniff,
        path: sniff.path,
        data,
        first,
        second,
        text: content_is_text(data),
        head: data.trim_ascii_start(),
    };
    RULES.iter().find_map(|rule| rule(&probe))
}

/// RPA v2/v3 puts a zlib-compressed pickle index at the offset named in this
/// fixed-width header. Identifying the container needs no pickle decoding.
/// Accept a header-only prefix because file identification can receive less
/// than the whole archive; check the zlib header when the index is available.
fn renpy_archive(p: &Probe<'_, '_>) -> Option<Found> {
    let (header_len, offset_bytes) = if p.data.starts_with(b"RPA-3.0 ") {
        let header = p.data.get(..34)?;
        if header.get(24) != Some(&b' ')
            || header.get(33) != Some(&b'\n')
            || !header.get(25..33)?.iter().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        (34, header.get(8..24)?)
    } else if p.data.starts_with(b"RPA-2.0 ") {
        let header = p.data.get(..25)?;
        if header.get(24) != Some(&b'\n') {
            return None;
        }
        (25, header.get(8..24)?)
    } else {
        return None;
    };
    if !offset_bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let offset = usize::from_str_radix(std::str::from_utf8(offset_bytes).ok()?, 16).ok()?;
    if offset < header_len {
        return None;
    }
    if let Some(&[cmf, flg]) = p.data.get(offset..offset.checked_add(2)?) {
        if cmf & 0x0f != 8 || cmf >> 4 > 7 || u16::from_be_bytes([cmf, flg]) % 31 != 0 {
            return None;
        }
    }
    Some((FileType::Rpa, DetectionSource::Magic))
}

/// RPC2 files declare their identity before their slot table. A short prefix
/// suffices for identification; the format extractor validates slot extents.
fn renpy_compiled_script(p: &Probe<'_, '_>) -> Option<Found> {
    p.data
        .starts_with(b"RENPY RPC2")
        .then_some((FileType::Rpyc, DetectionSource::Magic))
}

/// Compiled ColdFusion templates retain a clear-text Allaire header while
/// the template body is encrypted. Treat it as content identity so a
/// renamed `.cfm` file still reaches the CFML static decoder.
fn cold_fusion_template(p: &Probe<'_, '_>) -> Option<Found> {
    (p.data
        .starts_with(b"Allaire Cold Fusion Template\nHeader Size: ")
        || p.data
            .starts_with(b"Allaire Cold Fusion Template\r\nHeader Size: "))
    .then_some((FileType::Cfml, DetectionSource::Magic))
}

/// DER tags (ITU-T X.690 §8.6, §8.9) an X.509 certificate is framed with.
const DER_SEQUENCE: u8 = 0x30;
const DER_BIT_STRING: u8 = 0x03;

/// The detached signature sidecars shipped with several content-decryption
/// clients: a single length-framed certificate, signature material, and a
/// flags field. Every boundary has to agree; neither a `.sig` name nor an
/// embedded DER prefix alone establishes this format. No authenticity or
/// trust is inferred.
fn certificate_signature(p: &Probe<'_, '_>) -> Option<Found> {
    let mut rest = p.data.strip_prefix(&[0, 1])?;
    let cert_len = signature_varint(&mut rest)?;
    let cert = rest.get(..cert_len)?;
    rest = rest.get(cert_len..)?;
    // A SEQUENCE with a two-byte long-form length that spans the field.
    let &[DER_SEQUENCE, 0x82, hi, lo, ref body @ ..] = cert else {
        return None;
    };
    if usize::from(u16::from_be_bytes([hi, lo])) + 4 != cert.len() {
        return None;
    }
    // An X.509 Certificate has a TBS sequence, an algorithm sequence,
    // and a BIT STRING signature, with no additional top-level fields.
    let mut der = body;
    for tag in [DER_SEQUENCE, DER_SEQUENCE, DER_BIT_STRING] {
        if *der.first()? != tag {
            return None;
        }
        der = der.get(1..)?;
        let len = signature_der_length(&mut der)?;
        if len == 0 {
            return None;
        }
        der = der.get(len..)?;
    }
    if !der.is_empty() {
        return None;
    }
    rest = rest.strip_prefix(&[2])?;
    let signature_len = signature_varint(&mut rest)?;
    if !(128..=4096).contains(&signature_len) {
        return None;
    }
    rest = rest.get(signature_len..)?.strip_prefix(&[3])?;
    let flags_len = signature_varint(&mut rest)?;
    (flags_len == 1 && matches!(rest, [0 | 1]))
        .then_some((FileType::CertificateSignature, DetectionSource::Magic))
}

/// An Image4 payload carrying a trust-cache table.
fn image4_trustcache(p: &Probe<'_, '_>) -> Option<Found> {
    super::image4_trustcache::parse(p.data)
        .map(|_| (FileType::Image4TrustCache, DetectionSource::Magic))
}

/// A little-endian base-128 length, as protobuf frames its fields.
fn signature_varint(rest: &mut &[u8]) -> Option<usize> {
    let mut value = 0usize;
    for shift in (0..28).step_by(7) {
        let (&byte, tail) = rest.split_first()?;
        *rest = tail;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// A DER definite length (X.690 §8.1.3) of at most two octets.
fn signature_der_length(rest: &mut &[u8]) -> Option<usize> {
    let (&byte, tail) = rest.split_first()?;
    *rest = tail;
    if byte < 0x80 {
        return Some(usize::from(byte));
    }
    let count = usize::from(byte & 0x7f);
    if !(1..=2).contains(&count) {
        return None;
    }
    let bytes = rest.get(..count)?;
    *rest = rest.get(count..)?;
    Some(bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b)))
}

/// A Go module manifest has no magic bytes, but its first non-comment
/// directive is unambiguous. Detect it from content so renamed `go.mod`
/// files still reach module-aware facts and rules before extension fallback.
fn go_module(p: &Probe<'_, '_>) -> Option<Found> {
    if !(p.text && looks_like_go_mod(p.data)) {
        return None;
    }
    // Keep the canonical manifest name as a consistent identity while
    // allowing content to override every other filename or extension.
    let source = if p
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("go.mod"))
    {
        DetectionSource::Filename
    } else {
        DetectionSource::Heuristic
    };
    Some((FileType::GoMod, source))
}

/// ISO base media (`.mp4`/`.m4a`/`.mov`): the size-prefixed `ftyp` box.
/// Keyed at offset 4, so it cannot live in the first-byte jump table.
fn iso_base_media(p: &Probe<'_, '_>) -> Option<Found> {
    if p.text || p.data.len() < 12 || p.data.get(4..8) != Some(b"ftyp") {
        return None;
    }
    // AVIF uses the same box framing as MP4, but is an image carrier.
    // Read brands only inside the declared, bounded FileTypeBox; a word
    // in media payload bytes or the minor-version field is not a brand.
    let short_size = bytes::u32_be(p.data, 0)?;
    let (size, header) = match short_size {
        0 => (p.data.len(), 8),
        1 => (usize::try_from(bytes::u64_be(p.data, 8)?).ok()?, 16),
        n => (n as usize, 8),
    };
    let avif = p.data.get(header..size).is_some_and(|brands| {
        brands.len() >= 8
            && brands.len().is_multiple_of(4)
            && brands
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
                .any(|(i, brand)| i != 1 && (brand == b"avif" || brand == b"avis"))
    });
    Some((
        if avif { FileType::Avif } else { FileType::Mp4 },
        DetectionSource::Magic,
    ))
}

/// A Windows URL shortcut: an INI whose first section is
/// `[InternetShortcut]`. It carries no magic number and scores as no known
/// language, so only this section names it, whatever the file is called.
fn url_shortcut(p: &Probe<'_, '_>) -> Option<Found> {
    p.head
        .get(..URL_SHORTCUT_SECTION.len())
        .is_some_and(|section| section.eq_ignore_ascii_case(URL_SHORTCUT_SECTION))
        .then_some((FileType::Text, DetectionSource::Magic))
}

/// Windows Script Host documents: a `.wsf` job, a `.wsc` component or a
/// `.sct` scriptlet is XML whose `<script language=...>` names what runs.
/// Ahead of the XML arm, which would call it plain XML.
fn script_host(p: &Probe<'_, '_>) -> Option<Found> {
    script_host_document(p.sniff).map(|ft| (ft, DetectionSource::Magic))
}

/// Script Encoder output (`.vbe`, `.jse`): `#@~^`, a six-character base64
/// length, `==`. The body is ciphertext full of control bytes, which no
/// other rule would read as a script.
fn script_encoder(p: &Probe<'_, '_>) -> Option<Found> {
    encoded_script(p.path, p.head).map(|ft| (ft, DetectionSource::Magic))
}

/// Lockfiles announce themselves in their opening lines, so a lockfile
/// renamed for storage (`yarn.<sha>.lock`) is still one.
fn lockfile(p: &Probe<'_, '_>) -> Option<Found> {
    lockfile_header(p.data)
        .or_else(|| npm_json_lockfile(p.data))
        .map(|ft| (ft, DetectionSource::Magic))
}

/// npm's JSON lockfile family, independent of a collector-chosen filename.
/// A bounded, complete JSON parse is required: quoted markers or trailing code
/// are not format identity. This is declaration framing, not dependency trust.
fn npm_json_lockfile(data: &[u8]) -> Option<FileType> {
    if data.len() > 16 * 1024 * 1024 {
        return None;
    }
    let data = strip_utf8_bom(data).trim_ascii();
    if !data.starts_with(b"{") || memchr::memmem::find(data, b"\"lockfileVersion\"").is_none() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(data).ok()?;
    let root = value.as_object()?;
    let version = root.get("lockfileVersion")?.as_u64()?;
    if !matches!(version, 1..=3)
        || root.get("name").is_some_and(|v| !v.is_string())
        || root.get("version").is_some_and(|v| !v.is_string())
        || root.get("requires").is_some_and(|v| !v.is_boolean())
    {
        return None;
    }
    let records = if version == 1 {
        root.get("name")?.as_str()?;
        root.get("version")?.as_str()?;
        root.get("dependencies")?.as_object()?
    } else {
        root.get("packages")?.as_object()?
    };
    if !records.values().all(serde_json::Value::is_object) {
        return None;
    }
    Some(FileType::PackageLockJson)
}

/// PostScript and EPS. `%!PS` at the start is the format; a `.ps` extension
/// is only the fallback for a file that does not carry the header.
fn postscript(p: &Probe<'_, '_>) -> Option<Found> {
    (p.head.len() >= 4 && p.head.starts_with(b"%!PS"))
        .then_some((FileType::PostScript, DetectionSource::Magic))
}

/// Android binary XML: chunk type 0x0003, header size 8, a file-size field
/// that covers this buffer, and a string-pool chunk next.
fn android_binary_xml(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_axml(p.data).then_some((FileType::Xml, DetectionSource::Magic))
}

/// An HTML document, whatever it is called and however it is indented:
/// keyed off `head` rather than `data`, because real pages are not flush
/// left.
///
/// Both unambiguous openings are accepted. Nothing but a web page starts
/// `<!DOCTYPE html`, and a file whose first bytes are `<html` is one too --
/// that is narrower than the `<body`/`<div`/`<script` shapes, which also
/// open templates and fragments that other arms own and which stay out of
/// magic deliberately. `<!DOCTYPE svg` and an `<?xml` prolog are unaffected:
/// neither begins with either of these.
fn html_document(p: &Probe<'_, '_>) -> Option<Found> {
    let head = strip_utf8_bom(p.head).trim_ascii_start();
    let open = head.get(..5)?;
    let doctype_html = head
        .get(..14)
        .is_some_and(|tag| tag.eq_ignore_ascii_case(b"<!DOCTYPE html"));
    let html_root = open.eq_ignore_ascii_case(b"<html")
        && head.get(5).is_none_or(|c| !c.is_ascii_alphanumeric());
    // Some compromised pages prepend a short external-script loader before
    // the doctype. The complete document root still provides stronger type
    // evidence than a hash-like or misleading filename. Keep this bounded
    // and require the doctype and root together so ordinary JavaScript
    // fragments containing one HTML token do not become documents.
    let prefixed_html_document = {
        let prefix = head.get(..512).unwrap_or(head);
        let doctype = prefix
            .windows(14)
            .position(|w| w.eq_ignore_ascii_case(b"<!DOCTYPE html"));
        let root = prefix
            .windows(5)
            .position(|w| w.eq_ignore_ascii_case(b"<html"));
        let starts_with_script = prefix
            .get(..7)
            .is_some_and(|tag| tag.eq_ignore_ascii_case(b"<script"));
        let script_end = prefix
            .windows(9)
            .position(|w| w.eq_ignore_ascii_case(b"</script>"));
        starts_with_script
            && matches!((doctype, root, script_end), (Some(d), Some(r), Some(e)) if e < d && d < r)
            && root.is_some_and(|r| prefix.get(r + 5).is_none_or(|c| !c.is_ascii_alphanumeric()))
    };
    (doctype_html || html_root || prefixed_html_document)
        .then_some((FileType::Html, DetectionSource::Magic))
}

/// Apple UDIF disk image: the 512-byte `koly` trailer, version 4 or later,
/// that declares its own size.
fn udif_dmg(p: &Probe<'_, '_>) -> Option<Found> {
    let trailer = p.data.last_chunk::<512>()?;
    (trailer.starts_with(b"koly")
        && bytes::u32_be(trailer, 4).is_some_and(|version| version >= 4)
        && bytes::u32_be(trailer, 8) == Some(512))
    .then_some((FileType::Dmg, DetectionSource::Magic))
}

/// Optical-disc image (`.iso`): ISO 9660 and/or UDF.
///
/// The Volume Descriptor set begins at sector 16 (offset `0x8000`); each
/// 2048-byte descriptor is `[type:1][standard_identifier:5]`. ISO 9660 volume
/// descriptors carry `"CD001"`; a UDF bridge Volume Recognition Sequence carries
/// `"BEA01"`/`"NSR02"`/`"NSR03"`/`"TEA01"` (Windows install media are UDF). Either
/// identifier in the first several sectors means 7-Zip can unpack the image.
fn iso_image(p: &Probe<'_, '_>) -> Option<Found> {
    (16..=22usize)
        .any(|sector| {
            let off = sector * 2048 + 1;
            matches!(
                p.data.get(off..off + 5),
                Some(b"CD001" | b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01")
            )
        })
        .then_some((FileType::Iso, DetectionSource::Magic))
}

/// TIFF's byte-order/version header identifies the container, not a valid IFD.
fn tiff_header(p: &Probe<'_, '_>) -> Option<Found> {
    let data = p.data;
    let classic =
        data.len() >= 8 && (data.starts_with(b"II\x2a\0") || data.starts_with(b"MM\0\x2a"));
    let big = data.len() >= 16
        && (data.starts_with(b"II\x2b\0\x08\0\0\0") || data.starts_with(b"MM\0\x2b\0\x08\0\0"));
    (classic || big).then_some((FileType::Tiff, DetectionSource::Magic))
}

/// A short signature proves nothing when only text follows it. Formats
/// whose header is text by design keep their claim; any other claim falls
/// through to the rules after this one.
fn leading_signature(p: &Probe<'_, '_>) -> Option<Found> {
    first_byte_signature(p)
        .filter(|&(ft, source)| source != DetectionSource::Magic || !p.text || has_text_header(ft))
}

/// The first-byte jump table. Dispatch on `data[0]` to avoid evaluating 30+
/// conditions sequentially: each arm only checks formats that start with that
/// byte.
fn first_byte_signature(p: &Probe<'_, '_>) -> Option<Found> {
    let (path, data, second) = (p.path, p.data, p.second);
    match p.first {
        0x00 => {
            // AppleDouble (`._<name>`) resource forks: 00 05 16 07.
            // macOS routinely smuggles these into tarballs alongside real
            // files. Their bodies are binary metadata blobs (xattrs, finder
            // info, resource forks), not the file types their extension
            // claims, so they are Unknown: `._foo.php` is not PHP, and a
            // consumer that skips what `is_program` rejects skips it.
            if data.starts_with(&[0x00, 0x05, 0x16, 0x07]) {
                Some((FileType::Unknown, DetectionSource::Magic))
            } else if let &[_, 0x00, 0x01 | 0x02, 0x00, lo, hi, ..] = data
                && (1..=512).contains(&u16::from_le_bytes([lo, hi]))
            {
                // Windows icon/cursor: reserved=0, type=1|2, then a plausible
                // image count. Checked before the sfnt arm because sfnt 1.0 is
                // `00 01 00 00`, which an icon header can never be (its type
                // field would have to be 0x0100).
                Some((FileType::Ico, DetectionSource::Magic))
            } else if let &[_, a, b, c, d, _, _, _, _, 1, 0, 0, 0, 0, 0, 0, 0, ..] = data
                && [a, b, c, d] != [0; 4]
            {
                // NRBF SerializedStreamHeader (MS-NRBF 2.6.1): record kind 0,
                // nonzero root ID, ignored header ID, and little-endian
                // version 1.0. Root ID 1 collides with the first four SFNT
                // bytes, so this is checked before the font arm.
                Some((FileType::Nrbf, DetectionSource::Magic))
            } else if let Some(rest) = data.strip_prefix(&[0x00, 0x01, 0x00, 0x00])
                && !rest.starts_with(b"Standard Jet DB")
                && !rest.starts_with(b"Standard ACE DB")
            {
                // sfnt version 1.0 — the TrueType flavor every `.ttf` uses.
                // A Microsoft Access database opens with the same four bytes
                // and then names its engine, so an .mdb/.accdb would otherwise
                // be handed to the font parser and read as a corrupt font
                // rather than as a database with macros in it.
                // Four bytes is a weak signature, so this arm is reached only
                // after the AppleDouble check above and is confirmed
                // downstream by formats/font.rs walking the table directory.
                Some((FileType::Font, DetectionSource::Magic))
            } else if data.starts_with(b"\0asm\x01\0\0\0") {
                // WebAssembly binary module: `\0asm` magic followed by the
                // little-endian u32 version (`01 00 00 00`). The version guard
                // keeps `\0asm`-prefixed binary noise from misclassifying.
                Some((FileType::Wasm, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x7F => {
            // ELF: 7F 45 4C 46
            if data.starts_with(b"\x7FELF") {
                Some((FileType::Elf, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'M' => {
            // MZ-prefixed Windows programs include both PE and the older NE
            // format. Route NE to its own generic-binary file type instead of
            // calling it PE (which the PE analyzer correctly rejects).
            if second == b'Z' {
                let file_type = if looks_like_ne_executable(data) {
                    FileType::Ne
                } else {
                    FileType::Pe
                };
                Some((file_type, DetectionSource::Magic))
            } else if data.starts_with(b"MSCF") {
                Some((FileType::Cab, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'P' => {
            // ZIP record signatures are four bytes. A Tar member named
            // PKGBUILD also begins with PK; those letters alone are not ZIP.
            if second == b'K'
                && data.get(2..4).is_some_and(|signature| {
                    matches!(signature, [3, 4] | [5, 6] | [7, 8] | [6, 6] | [6, 7])
                })
            {
                Some((classify_pk(p.sniff), DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCA => {
            // Java class and Mach-O fat both start with CAFEBABE.
            // Java's bytes 6..8 are the class-file `major_version`
            // (45 = Java 1.1, 52 = Java 8, 65 = Java 21 — well over
            // a decade of headroom in 45..=70). Mach-O fat's bytes
            // 4..8 are `nfat_arch` (BE u32), realistically ≤ 12.
            //
            // Either signal alone misfires on random or hostile bytes
            // shaped like CAFEBABE: a junk file whose `major_version`
            // lands at 0x01F4 (500) fails the Java check, then the
            // Mach-O parser tries to slice with a several-billion
            // offset. Combine both checks so we only call it Mach-O
            // when nfat_arch is plausible AND the Java major isn't.
            if let &[_, 0xFE, 0xBA, 0xBE, n0, n1, m0, m1, ..] = data {
                let major = u16::from_be_bytes([m0, m1]);
                let nfat_arch = u32::from_be_bytes([n0, n1, m0, m1]);
                if (45..=70).contains(&major) || nfat_arch > 16 {
                    Some((FileType::JavaClass, DetectionSource::Magic))
                } else {
                    Some((FileType::MachO, DetectionSource::Magic))
                }
            } else {
                None
            }
        }
        0xFE => {
            // Mach-O: FEEDFACE (32-bit) or FEEDFACF (64-bit)
            if matches!(data, [_, 0xED, 0xFA, 0xCE | 0xCF, ..]) {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCE => {
            // Mach-O 32-bit swapped: CEFAEDFE
            if data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCF => {
            // Mach-O 64-bit swapped: CFFAEDFE
            if data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xBE => {
            // Mach-O fat swapped: BEBAFECA
            if data.starts_with(&[0xBE, 0xBA, 0xFE, 0xCA]) {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xFF => {
            // JPEG: FF D8 FF
            if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
                Some((FileType::Jpeg, DetectionSource::Magic))
            } else if data
                .strip_prefix(b"\xFF\xFE")
                .is_some_and(|rest| utf16le_starts_with(rest, REGISTRY_EDITOR_HEADER))
            {
                // What regedit exports: UTF-16LE behind a byte-order mark.
                Some((FileType::Reg, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x89 => {
            // PNG: 89 50 4E 47 0D 0A 1A 0A
            if data.starts_with(b"\x89PNG\r\n\x1a\n") {
                Some((FileType::Png, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'G' => {
            // GIF87a / GIF89a.
            if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
                Some((FileType::Gif, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'O' => {
            // OpenType with CFF outlines: the sfnt version is the tag `OTTO`.
            if data.starts_with(b"OTTO") {
                Some((FileType::Font, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'w' => {
            // Web font wrappers: `wOFF` (WOFF 1) and `wOF2` (WOFF 2).
            if data.starts_with(b"wOFF") || data.starts_with(b"wOF2") {
                Some((FileType::Font, DetectionSource::Magic))
            } else {
                None
            }
        }
        b't' => {
            // Apple sfnt flavors: `true` (TrueType), `typ1` (PostScript in an
            // sfnt wrapper), `ttcf` (TrueType collection).
            if data.starts_with(b"true") || data.starts_with(b"typ1") || data.starts_with(b"ttcf") {
                Some((FileType::Font, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xD0 => {
            // OLE2/CFBF: D0 CF 11 E0 A1 B1 1A E1. Shared by Office documents
            // (.doc/.xls/.ppt/.msg) and Windows Installer packages (.msi/.msp);
            // the root storage's CLSID says which. The name decides only when
            // the root directory sector lies outside the bytes at hand.
            if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
                let installer = ole_root_clsid(data).map_or_else(
                    || {
                        matches!(
                            lowercase_ext(path).as_deref(),
                            Some("msi" | "msp" | "mst" | "msm")
                        )
                    },
                    |clsid| MSI_CLSIDS.contains(&clsid),
                );
                let ty = if installer {
                    FileType::Msi
                } else {
                    FileType::OleDoc
                };
                Some((ty, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x4C => {
            // LNK: 4C 00 00 00 01 14 02 00 ...
            if data.len() >= LNK_MAGIC.len() && data.starts_with(LNK_MAGIC) {
                Some((FileType::Lnk, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'R' => {
            // RAR: Rar!
            if data.starts_with(b"Rar!") {
                Some((FileType::Rar, DetectionSource::Magic))
            } else if data.starts_with(b"REGEDIT4") {
                // A .reg file's first line names the format, whatever the
                // file is called: nothing but a registry script opens with
                // this line. REGEDIT4 is the Windows 9x/NT4 spelling; the
                // Windows 2000+ one is handled in the `W` arm below.
                Some((FileType::Reg, DetectionSource::Magic))
            } else if (data.starts_with(b"RIFF") || data.starts_with(b"RIFX")) && data.len() >= 12 {
                // RIFF container: `RIFF` + u32 length + form type. WAVE, WEBP,
                // AVI and animated cursors (`ACON`) share the wrapper, so the
                // form type at offset 8 decides.
                let kind = match data.get(8..12) {
                    Some(b"WEBP") => Some(FileType::Webp),
                    Some(b"WAVE") => Some(FileType::Wav),
                    Some(b"ACON") => Some(FileType::Ani),
                    _ => None,
                };
                kind.map(|file_type| (file_type, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'F' => {
            // Compiled AppleScript: Fasd
            if data.starts_with(b"Fasd") {
                Some((FileType::AppleScript, DetectionSource::Magic))
            } else if data.starts_with(b"FOR1") && data.get(8..12) == Some(b"BEAM") {
                // Erlang/Elixir BEAM bytecode: IFF container `FOR1` <u32 size> `BEAM`.
                Some((FileType::Beam, DetectionSource::Magic))
            } else if data.starts_with(b"FORM")
                && matches!(data.get(8..12), Some(b"AIFF" | b"AIFC"))
            {
                // IFF audio shares the container family with BEAM above; the
                // form type at offset 8 is what separates them.
                Some((FileType::Aiff, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'd' => {
            // Dalvik executable bytecode: dex\n035\0, dex\n038\0, etc.
            if let &[_, b'e', b'x', b'\n', v0, v1, v2, 0, ..] = data
                && [v0, v1, v2].iter().all(u8::is_ascii_digit)
            {
                Some((FileType::Dex, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'I' => {
            // Compiled HTML Help: ITSF
            if data.starts_with(b"ITSF") {
                Some((FileType::Chm, DetectionSource::Magic))
            } else if data.starts_with(b"ID3") {
                // ID3v2-tagged MPEG audio.
                Some((FileType::Mp3, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'{' => {
            // RTF: {\rtf
            if data.starts_with(b"{\\rtf") {
                Some((FileType::Rtf, DetectionSource::Magic))
            } else if looks_like_obfuscated_rtf(data) {
                Some((FileType::Rtf, DetectionSource::Heuristic))
            } else {
                None
            }
        }
        b'%' => {
            // PDF: %PDF-
            if data.starts_with(b"%PDF-") {
                Some((FileType::Pdf, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x80 => looks_like_pickle(path, data).then_some((FileType::Pickle, DetectionSource::Magic)),
        b'b' => {
            // Binary Plist: bplist. A `.nib` with this magic is a keyed-archive
            // nib (NSKeyedArchiver output inside an older nib bundle), but the
            // bytes are a plain property list either way, so it is typed
            // Plist for every plist-aware consumer.
            if data.starts_with(b"bplist") {
                Some((FileType::Plist, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'N' => {
            // Compiled Interface Builder archive (NIBArchive)
            if data.starts_with(b"NIBArchive") {
                Some((FileType::Nib, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'!' => {
            // Unix `ar` archive (`!<arch>\n`). This magic is shared by Debian
            // packages and static libraries (.a). Distinguish by the first `ar`
            // member: a `.deb` always leads with `debian-binary`; a static
            // library leads with a symbol/string table (`/`, `//`, `__.SYMDEF`)
            // or an object file. Without this split every `.a` was mis-typed as
            // `Deb`, so its object bytes were scanned as an opaque package.
            if data.starts_with(b"!<arch>\n") {
                let ty = if ar_first_member_is(data, b"debian-binary") {
                    FileType::Deb
                } else {
                    FileType::StaticLib
                };
                Some((ty, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'x' => {
            // XAR (macOS PKG): xar!
            if data.starts_with(b"xar!") {
                Some((FileType::PkgMacos, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'C' => {
            // Chrome extension: Cr24
            if data.starts_with(b"Cr24") {
                Some((FileType::Crx, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'h' => {
            // SquashFS superblock, little-endian: hsqs
            if data.starts_with(b"hsqs") {
                Some((squashfs_type(path), DetectionSource::Magic))
            } else {
                None
            }
        }
        b's' => {
            // SquashFS superblock, big-endian: sqsh
            if data.starts_with(b"sqsh") {
                Some((squashfs_type(path), DetectionSource::Magic))
            } else {
                None
            }
        }
        b'-' => {
            // ASCII-armored OpenPGP detached signature. The binary packet form
            // has no byte we can claim safely — its tag byte collides with PNG
            // and other formats — so that one is left to the extension.
            if data.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
                Some((FileType::PgpSignature, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xED => {
            // RPM: ED AB EE DB
            if data.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
                Some((FileType::Rpm, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x1F => {
            // Gzip: 1F 8B, then CM 8 (deflate), the only method ever defined.
            // What it wraps is read, not guessed from the name: packages in
            // content-addressed stores are named by their hash.
            if second == 0x8B && data.get(2) == Some(&8) {
                let inside = tar_layout(
                    flate2::read::GzDecoder::new(data).take(TAR_PEEK_LIMIT),
                    false,
                );
                let ft = classify_tar(p.sniff, Compression::Gzip, inside);
                Some((ft.unwrap_or(FileType::Gz), DetectionSource::Magic))
            } else {
                None
            }
        }
        0xFD => {
            // XZ: FD 37 7A 58 5A 00. No xz decoder is linked, so only the name
            // can say whether a tar is inside.
            if data.starts_with(b"\xfd7zXZ\0") {
                let ft = classify_tar(p.sniff, Compression::Xz, Inside::Unreadable);
                Some((ft.unwrap_or(FileType::Xz), DetectionSource::Magic))
            } else {
                None
            }
        }
        b'B' => {
            if looks_like_bmp(data) {
                Some((FileType::Bmp, DetectionSource::Magic))
            } else if matches!(data, [b'B', b'Z', b'h', b'1'..=b'9', ..])
                && matches!(
                    data.get(4..10),
                    Some(b"1AY&SY" | b"\x17\x72\x45\x38\x50\x90")
                )
            {
                // Bzip2: `BZh`, the block-size digit, then the first block's
                // magic (BCD pi) or, for an empty stream, the end-of-stream
                // magic (BCD sqrt(pi)). No bzip2 decoder is linked, so only the
                // name can say whether a tar is inside.
                let ft = classify_tar(p.sniff, Compression::Bzip2, Inside::Unreadable);
                Some((ft.unwrap_or(FileType::Bz2), DetectionSource::Magic))
            } else {
                None
            }
        }
        b'0' => {
            // ASCII CPIO. The six-digit magic alone is six ordinary digits, so
            // require the whole fixed-size header to be digits of its radix.
            if looks_like_ascii_cpio(data) {
                Some((FileType::Cpio, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'7' => {
            // 7z: 37 7A BC AF 27 1C
            if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
                Some((FileType::SevenZ, DetectionSource::Magic))
            } else {
                None
            }
        }
        0x28 => {
            // Zstandard: 28 B5 2F FD
            if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
                // FreeBSD, Arch and Void packages are all zstd tars; their
                // leading members say which.
                let inside = zstd::stream::read::Decoder::new(data)
                    .map_or(Inside::Unreadable, |d| {
                        tar_layout(d.take(TAR_HEAD_LIMIT), false)
                    });
                let ft = classify_tar(p.sniff, Compression::Zstd, inside);
                Some((ft.unwrap_or(FileType::Zst), DetectionSource::Magic))
            } else {
                None
            }
        }
        b'#' => {
            // Shebang: #!
            if second == b'!' {
                detect_shebang(data)
            } else {
                None
            }
        }
        0xEF => {
            // A UTF-8 BOM ahead of a shebang: Windows editors write it along
            // with CRLF. The kernel will not exec it, but `perl x`, `python x`
            // and `bash x` still run the body, so it is still that language.
            // A registry export re-saved as UTF-8 may keep a BOM too.
            match data.strip_prefix(UTF8_BOM) {
                Some(rest) if rest.starts_with(b"#!") => detect_shebang(rest),
                Some(rest) if rest.starts_with(REGISTRY_EDITOR_HEADER) => {
                    Some((FileType::Reg, DetectionSource::Magic))
                }
                _ => None,
            }
        }
        b'\n' | b'\r' | b' ' | b'\t' => {
            // Blank lines ahead of a shebang: the kernel will not exec it, but
            // a script served to `curl … | sh` or run as `bash x` executes the
            // body all the same, so it is still that language. Bounded so a
            // stray `#!` deep in whitespace-padded text is not a shebang.
            let rest = data.trim_ascii_start();
            if data.len() - rest.len() <= 64 && rest.starts_with(b"#!") {
                detect_shebang(rest)
            } else {
                None
            }
        }
        b'/' => {
            // Xcode writes this exact comment as the first line of every
            // `project.pbxproj`; it is the format's only signature.
            if data.starts_with(b"// !$*UTF8*$!") {
                Some((FileType::Pbxproj, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'W' => {
            // The modern .reg header as UTF-8 without a BOM; the UTF-16LE and
            // UTF-8 BOM spellings are claimed in the 0xFF and 0xEF arms. Same
            // reasoning as the `REGEDIT4` arm above.
            if data.starts_with(REGISTRY_EDITOR_HEADER) {
                Some((FileType::Reg, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'<' => {
            // PHP opening tag: <?php
            if data.starts_with(b"<?php") {
                Some((FileType::Php, DetectionSource::Magic))
            } else {
                detect_xml(data)
            }
        }
        _ => None,
    }
}

// ── Fallback checks (rare paths) ─────────────────────────────────────
// These are guarded by cheap pre-checks to avoid unnecessary work.

/// Uncompressed tar carries no leading magic — the `ustar` signature sits at
/// offset 257. Its members say whether it is a gem, an OCI image, a Gentoo
/// package or a plain tar. A tar is a tar whatever it is named: renaming one
/// must not hide its members from the archive walker.
fn ustar(p: &Probe<'_, '_>) -> Option<Found> {
    if !(p.data.len() > 262 && p.data.get(257..262) == Some(b"ustar")) {
        return None;
    }
    let ft = classify_tar(p.sniff, Compression::None, tar_layout(p.data, true));
    Some((ft.unwrap_or(FileType::Tar), DetectionSource::Magic))
}

/// Python bytecode: a supported little-endian magic number ending in CRLF,
/// then flags or a timestamp. Match known CPython releases so unrelated
/// binary formats cannot claim a pyc type by coincidence.
fn python_bytecode(p: &Probe<'_, '_>) -> Option<Found> {
    (!p.text
        && p.data.len() >= 8
        && p.data.get(2..4) == Some(b"\r\n")
        && is_supported_python_bytecode_magic(u16::from_le_bytes([p.first, p.second])))
    .then_some((FileType::PythonBytecode, DetectionSource::Magic))
}

/// A PE whose `MZ` is not at offset 0: `MZ` within the first 64 bytes whose
/// `e_lfanew` leads to a valid `PE\0\0` signature. Offset 0 was already
/// checked by the MZ arm.
fn tampered_pe(p: &Probe<'_, '_>) -> Option<Found> {
    let window = p.data.get(..64).unwrap_or(p.data);
    window
        .windows(2)
        .enumerate()
        .skip(1)
        .filter(|&(_, pair)| pair == b"MZ")
        .any(|(i, _)| {
            p.data.get(i..).is_some_and(|pe| {
                bytes::u32_le(pe, 0x3C)
                    .and_then(|e_lfanew| pe.get(e_lfanew as usize..))
                    .is_some_and(|nt| nt.starts_with(b"PE\0\0"))
            })
        })
        .then_some((FileType::Pe, DetectionSource::Magic))
}

/// Markup after a BOM or leading whitespace.
fn markup(p: &Probe<'_, '_>) -> Option<Found> {
    detect_xml(p.data)
}

/// A native PHP archive: a stub ending in `__HALT_COMPILER();` and a manifest
/// that parses. Tried ahead of the script and image rules, because the stub is
/// PHP, a shebang, or anything at all (a JPEG header makes a polyglot), and
/// the archive is what `phar://` opens.
fn phar(p: &Probe<'_, '_>) -> Option<Found> {
    super::phar::is_phar(p.data).then_some((FileType::Phar, DetectionSource::Magic))
}

/// Electron ASAR: a Chromium pickle holding the header size (`04 00 00 00`,
/// then the size), a second pickle whose payload is 4 bytes shorter, and the
/// JSON file table as its string.
fn asar(p: &Probe<'_, '_>) -> Option<Found> {
    let u32_at = |off| bytes::u32_le(p.data, off);
    (u32_at(0) == Some(4)
        && u32_at(4).is_some_and(|size| u32_at(8) == size.checked_sub(4))
        && p.data
            .get(16..)
            .is_some_and(|rest| rest.starts_with(b"{\"files\":")))
    .then_some((FileType::Asar, DetectionSource::Magic))
}

/// LZMA-alone (`.lzma`): the properties byte every mainstream encoder writes
/// (0x5D: lc=3, lp=0, pb=2), a dictionary size that `xz` and 7-Zip only ever
/// write as 2^n or 2^n + 2^(n-1) between 4 KiB and 1.5 GiB, and an
/// uncompressed size that is either unknown (all ones) or under 2^40. The
/// header has no magic, so all three must hold; Chromium's `.pak` resources
/// satisfy the last two.
fn lzma_alone(p: &Probe<'_, '_>) -> Option<Found> {
    if p.data.len() < 14 || p.first != 0x5D {
        return None;
    }
    let dict = bytes::u32_le(p.data, 1)?;
    let size = bytes::u64_le(p.data, 5)?;
    let n = dict.trailing_zeros();
    let dict_ok = (12..=30).contains(&n) && (dict == 1 << n || dict == 3 << (n - 1));
    (dict_ok && (size == u64::MAX || size < 1 << 40))
        .then_some((FileType::Lzma, DetectionSource::Magic))
}

/// A GitHub Actions workflow outside `.github/workflows/`: a YAML name and
/// top-level `on:` and `jobs:` keys.
fn github_actions_workflow(p: &Probe<'_, '_>) -> Option<Found> {
    if !(path_ends_with_ci(p.path, b".yml") || path_ends_with_ci(p.path, b".yaml")) {
        return None;
    }

    let text = std::str::from_utf8(p.data.get(..16 * 1024).unwrap_or(p.data)).ok()?;

    let mut has_on = false;
    let mut has_jobs = false;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("---") || line.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }

        let Some((key, _)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim_matches(|c| c == '\'' || c == '"' || c == ' ');
        match key {
            "on" => has_on = true,
            "jobs" => has_jobs = true,
            _ => {}
        }
        if has_on && has_jobs {
            return Some((FileType::GithubActions, DetectionSource::Heuristic));
        }
    }
    None
}

/// A Chrome extension manifest: `manifest.json` carrying `manifest_version`
/// and at least one Chrome-specific key. The name alone is shared with web
/// app manifests and container image indexes.
fn chrome_manifest(p: &Probe<'_, '_>) -> Option<Found> {
    let named = p
        .path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("manifest.json"));
    let has = |key: &[u8]| memchr::memmem::find(p.data, key).is_some();
    (named
        && has(b"\"manifest_version\"")
        && (has(b"\"permissions\"")
            || has(b"\"content_scripts\"")
            || has(b"\"background\"")
            || has(b"\"host_permissions\"")))
    .then_some((FileType::ChromeManifest, DetectionSource::Filename))
}

/// Magic numbers for Python versions whose bytecode layout is handled by
/// the PYC facts extractor. Broad numeric ranges admit unrelated binary
/// formats whose first four bytes happen to end in CRLF.
fn is_supported_python_bytecode_magic(magic: u16) -> bool {
    matches!(
        magic,
        3379
            | 3390..=3394
            | 3400..=3413
            | 3420..=3425
            | 3430..=3439
            | 3450..=3495
            | 3500..=3531
            | 3550..=3571
            | 3627
            | 62211
    )
}

/// Check the DOS MZ header's `e_lfanew` pointer for a Windows NE signature.
/// NE is a 16-bit executable format; it must not be routed to the PE parser.
fn looks_like_ne_executable(data: &[u8]) -> bool {
    if !data.starts_with(b"MZ") {
        return false;
    }
    // `e_lfanew` closes the 64-byte DOS header.
    let Some(offset) = bytes::u32_le(data, 0x3c) else {
        return false;
    };
    let offset = offset as usize;
    data.get(offset..offset.saturating_add(2)) == Some(b"NE")
}

/// A SquashFS image is the wire format of a Snap package, so the superblock
/// magic alone cannot tell the two apart — reading `meta/snap.yaml` would mean
/// decompressing the filesystem. The `.snap` extension is the available signal,
/// mirroring how `.xbps` separates a Void package from a generic zstd tar.
fn squashfs_type(path: &Path) -> FileType {
    if path_ends_with_ci(path, b".snap") {
        FileType::Snap
    } else {
        FileType::SquashFs
    }
}

/// Peek the first `ar` member's name and compare it to `want`.
///
/// An `ar` archive is `!<arch>\n` (8 bytes) followed by fixed 60-byte member
/// headers; the name is the leading 16-byte field, space-padded and sometimes
/// terminated with `/` (GNU). Used to tell a Debian package (first member
/// `debian-binary`) from a static library (a symbol/string table or object).
fn ar_first_member_is(data: &[u8], want: &[u8]) -> bool {
    const AR_MAGIC_LEN: usize = 8; // "!<arch>\n"
    let Some(field) = data.get(AR_MAGIC_LEN..AR_MAGIC_LEN + 16) else {
        return false;
    };
    let mut name = field;
    while let [head @ .., b' '] = name {
        name = head;
    }
    let name = name.strip_suffix(b"/").unwrap_or(name);
    name == want
}

/// ASCII CPIO (`odc`, `newc`, `newc`+checksum), identified by a complete and
/// well-formed fixed-size first header rather than by the magic alone. Binary
/// and RPM-stripped CPIO carry different framing and are not claimed here.
fn looks_like_ascii_cpio(data: &[u8]) -> bool {
    let (header, radix) = match data.get(..6) {
        Some(b"070707") => (76, 8),
        Some(b"070701" | b"070702") => (110, 16),
        _ => return false,
    };
    data.get(6..header).is_some_and(|fields| {
        fields.iter().all(|b| match radix {
            8 => matches!(b, b'0'..=b'7'),
            _ => b.is_ascii_hexdigit(),
        })
    })
}

// Legacy VHD v1 footer; this does not identify the different VHDX format.
// https://www.microsoft.com/en-us/download/details.aspx?id=23850
fn vhd_image(p: &Probe<'_, '_>) -> Option<Found> {
    let footer = p.data.last_chunk::<512>()?;
    if &footer[..8] != b"conectix" || bytes::u32_be(footer, 12) != Some(0x0001_0000) {
        return None;
    }
    let checksum = !footer
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .map(|(_, b)| u32::from(*b))
        .sum::<u32>();
    if bytes::u32_be(footer, 64) != Some(checksum) {
        return None;
    }
    let size = bytes::u64_be(footer, 48)?;
    if size == 0 || size % 512 != 0 {
        return None;
    }
    match bytes::u32_be(footer, 60)? {
        2 => {
            if bytes::u64_be(footer, 16) != Some(u64::MAX)
                || size.checked_add(512)? != p.data.len() as u64
            {
                return None;
            }
        }
        3 | 4 => {
            let offset = usize::try_from(bytes::u64_be(footer, 16)?).ok()?;
            let header = p.data.get(offset..offset.checked_add(1024)?)?;
            if !header.starts_with(b"cxsparse") || bytes::u32_be(header, 24) != Some(0x0001_0000) {
                return None;
            }
        }
        _ => return None,
    }
    Some((FileType::Vhd, DetectionSource::Magic))
}

/// Case-insensitive suffix match on path bytes (no allocation).
fn path_ends_with_ci(path: &Path, suffix: &[u8]) -> bool {
    ends_with_ci(path.to_string_lossy().as_bytes(), suffix)
}

/// How much of a file [`content_is_text`] reads. Binary headers put a NUL or
/// a control byte well inside it: a PE's `e_lfanew`, a font's table count, a
/// RIFF or ISO-BMFF box size.
const TEXT_PROBE: usize = 64;

/// Whether the head of `data` reads as plain text: UTF-8 with no control
/// bytes beyond what any text carries. A character cut off by the end of the
/// probe still counts.
///
/// The probe is short, so where the classifier in `text` weighs the share
/// of control bytes across a window, one control byte here is enough to
/// doubt a short signature.
pub(super) fn content_is_text(data: &[u8]) -> bool {
    let head = data.get(..TEXT_PROBE).unwrap_or(data);
    if control_bytes(head, Controls::Text) > 0 {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

/// Formats whose header is text by design, so an all-text head is no reason
/// to doubt them: markup, registry scripts, PDF, RTF, ASCII armor, and the
/// archives whose member headers are ASCII (`ar`, ASCII cpio).
fn has_text_header(ft: FileType) -> bool {
    matches!(
        ft,
        FileType::Php
            | FileType::Xml
            | FileType::Plist
            | FileType::Svg
            | FileType::Reg
            | FileType::Pbxproj
            | FileType::PgpSignature
            | FileType::Pdf
            | FileType::Rtf
            | FileType::Cpio
            | FileType::Deb
            | FileType::StaticLib
    )
}

/// A lockfile's tool-written header: pnpm's first line, or a line of the
/// leading comment block that Yarn v1, Cargo or Poetry write.
fn lockfile_header(data: &[u8]) -> Option<FileType> {
    let head = strip_utf8_bom(data.get(..512).unwrap_or(data));
    let lines = head.split(|&b| b == b'\n').map(<[u8]>::trim_ascii_end);
    if lines.clone().next()?.starts_with(b"lockfileVersion:") {
        return Some(FileType::PnpmLock);
    }
    lines
        .take_while(|line| line.is_empty() || line.starts_with(b"#"))
        .find_map(|line| {
            if line == b"# yarn lockfile v1" {
                Some(FileType::YarnLock)
            } else if line.starts_with(b"# This file is automatically @generated by Cargo.") {
                Some(FileType::CargoLock)
            } else if line.starts_with(b"# This file is automatically @generated by Poetry") {
                Some(FileType::PoetryLock)
            } else {
                None
            }
        })
}

/// Root-storage CLSIDs of Windows Installer databases: package (and merge
/// module), patch, and transform — `{000C1084,86,82-0000-0000-C000-000000000046}`
/// in on-disk byte order.
const MSI_CLSIDS: [[u8; 16]; 3] = [
    *b"\x84\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46",
    *b"\x86\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46",
    *b"\x82\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46",
];

/// The CLSID of a compound file's root storage: the first entry of the first
/// directory sector. `None` when that sector is not within `data`.
fn ole_root_clsid(data: &[u8]) -> Option<[u8; 16]> {
    let shift = u16::from_le_bytes(data.get(0x1E..0x20)?.try_into().ok()?);
    if !matches!(shift, 9 | 12) {
        return None;
    }
    let first = u32::from_le_bytes(data.get(0x30..0x34)?.try_into().ok()?) as usize;
    let at = first
        .checked_add(1)?
        .checked_mul(1 << shift)?
        .checked_add(0x50)?;
    data.get(at..at + 16)?.try_into().ok()
}

/// Python pickle. Protocol 4 and 5 open with a FRAME whose u64 length has
/// no business near 2^40, and legacy `torch.save` with its own magic: either
/// is the format itself. Protocols 2 and 3 open with two bytes that other
/// binary formats share, so there the name has to agree.
fn looks_like_pickle(path: &Path, data: &[u8]) -> bool {
    match data {
        [0x80, 4 | 5, 0x95, frame @ ..] => bytes::u64_le(frame, 0).is_some_and(|len| len < 1 << 40),
        _ if data.starts_with(torch::LEGACY_MAGIC) => true,
        [0x80, 2 | 3, ..] => matches!(
            lowercase_ext(path).as_deref(),
            Some("pkl" | "pickle" | "joblib" | "debug_pkl" | "pt" | "pth")
        ),
        _ => false,
    }
}

/// A Windows bitmap: `BM`, then the info header that follows the 14-byte file
/// header. `BM` alone is two letters, and the file-size field is routinely
/// wrong in real bitmaps (truncated downloads, writers that leave it zero), so
/// the claim rests on the info header instead: its size field names one of the
/// header versions Windows and OS/2 defined, it has one colour plane, and its
/// pixel depth is one a decoder accepts.
fn looks_like_bmp(data: &[u8]) -> bool {
    data.starts_with(b"BM") && data.get(14..).is_some_and(looks_like_dib_header)
}

/// A bitmap info header (`BITMAPCOREHEADER` through `BITMAPV5HEADER`, and
/// OS/2's variants). This is also the whole start of a headerless `.dib`.
pub(crate) fn looks_like_dib_header(dib: &[u8]) -> bool {
    let u16_at = |i| bytes::u16_le(dib, i);
    let Some(size) = bytes::u32_le(dib, 0) else {
        return false;
    };
    // The 12-byte core header has 16-bit dimensions; every later one 32-bit.
    let (planes, bits) = match size {
        12 => (u16_at(8), u16_at(10)),
        16 | 40 | 52 | 56 | 64 | 108 | 124 => (u16_at(12), u16_at(14)),
        _ => return false,
    };
    planes == Some(1) && matches!(bits, Some(0 | 1 | 2 | 4 | 8 | 16 | 24 | 32 | 48 | 64))
}

/// Detect shebang-based file types.
///
/// Reads the line the way the kernel does: the first word is the interpreter
/// path, and only its basename matters. A launcher (`env`, `busybox`) defers
/// to the first word after its own options.
fn detect_shebang(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    // The kernel reads a shebang line through BINPRM_BUF_SIZE (256 bytes).
    let buf = data.get(..256).unwrap_or(data);
    let line = buf.split(|&b| b == b'\n').next().unwrap_or(buf);
    // Any whitespace ends a word, not just space and tab: a CRLF script's
    // `#!/usr/bin/perl\r` names perl, whatever the kernel makes of the `\r`.
    let mut words = line
        .strip_prefix(b"#!")?
        .split(|&b| b.is_ascii_whitespace() || b == 0)
        .filter(|w| !w.is_empty());
    let mut name = basename(words.next()?);
    if name == b"env" || name == b"busybox" {
        name = basename(launched_interpreter(&mut words)?);
    }
    // `python3.11`, `perl5.36`, `ruby3.2` and `ksh93` are the same languages.
    while let [stem @ .., b'0'..=b'9' | b'.'] = name {
        name = stem;
    }
    let file_type = match name {
        b"sh" | b"bash" | b"rbash" | b"zsh" | b"dash" | b"ash" | b"ksh" | b"mksh" | b"yash"
        | b"fish" | b"tcsh" | b"csh" | b"atf-sh" => FileType::Shell,
        // debian/rules and friends: `#!/usr/bin/make -f`. Without this the
        // content heuristics mis-type make scripts as source code.
        b"make" | b"gmake" => FileType::Makefile,
        b"python" | b"pypy" => FileType::Python,
        b"node" | b"nodejs" | b"deno" | b"bun" => FileType::JavaScript,
        b"ts-node" | b"tsx" => FileType::TypeScript,
        b"ruby" | b"jruby" => FileType::Ruby,
        b"perl" => FileType::Perl,
        b"php" => FileType::Php,
        b"lua" | b"luajit" => FileType::Lua,
        b"pwsh" | b"powershell" => FileType::PowerShell,
        // JXA is `osascript -l JavaScript`; the body is JavaScript, and typing
        // it AppleScript would hide it from every JavaScript rule.
        b"osascript" if words.any(|w| w.eq_ignore_ascii_case(b"JavaScript")) => {
            FileType::JavaScript
        }
        b"osascript" => FileType::AppleScript,
        b"elixir" => FileType::Elixir,
        b"groovy" => FileType::Groovy,
        b"scala" => FileType::Scala,
        b"kotlin" | b"kscript" => FileType::Kotlin,
        b"swift" => FileType::Swift,
        // Babashka runs Clojure.
        b"bb" => FileType::Clojure,
        _ => return None,
    };
    Some((file_type, DetectionSource::Shebang))
}

/// The path segment after the last `/`.
fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|&b| b == b'/').next().unwrap_or(path)
}

/// The interpreter a launcher runs: the first word that is neither an option
/// nor a `NAME=value` assignment, as in `env -S perl -w` or `env -u X python3`.
fn launched_interpreter<'a>(words: &mut impl Iterator<Item = &'a [u8]>) -> Option<&'a [u8]> {
    while let Some(word) = words.next() {
        match word {
            // env options that consume the next word as their argument.
            b"-u" | b"--unset" | b"-C" | b"--chdir" => {
                words.next();
            }
            _ if word.starts_with(b"-") || word.contains(&b'=') => {}
            _ => return Some(word),
        }
    }
    None
}

/// Maximum prefix examined when identifying a Go module manifest by content.
const GO_MOD_HEAD_LIMIT: usize = 4096;

/// Go's module directive is the first non-comment directive in a `go.mod`.
/// Checking that narrow grammar is constant-space and avoids assigning module
/// semantics to ordinary prose or Go source declarations such as `export module`.
fn looks_like_go_mod(data: &[u8]) -> bool {
    let head = data.get(..GO_MOD_HEAD_LIMIT).unwrap_or(data);
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("//"))
    else {
        return false;
    };
    let Some(rest) = line.strip_prefix("module") else {
        return false;
    };
    if !(rest.starts_with(' ') || rest.starts_with('\t')) {
        return false;
    }
    let rest = rest.trim_start();
    let rest = rest
        .find("//")
        .and_then(|offset| rest.get(..offset))
        .filter(|before| before.ends_with(|c: char| c.is_ascii_whitespace()))
        .unwrap_or(rest)
        .trim();
    if rest.is_empty() || rest.split_whitespace().count() != 1 {
        return false;
    }

    let path = ['"', '`']
        .into_iter()
        .find_map(|quote| rest.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(rest);
    !path.is_empty()
        && path.bytes().any(|b| b.is_ascii_alphanumeric())
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./_~-!".contains(&b))
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.starts_with('.'))
}

#[cfg(test)]
mod tests;
