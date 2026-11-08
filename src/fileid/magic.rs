//! The signature stage: magic bytes, shebangs and structural markers.
//!
//! [`RULES`] runs in order and the first claim wins. Text-shaped headers that
//! may sit behind whitespace or a BOM (HTML, Windows Script Host, lockfiles,
//! `go.mod`) and signatures that are not at offset 0 (an `ftyp` box at 4, an
//! ISO volume descriptor at 32 KiB, a DMG or VHD trailer at the end) come
//! first. The binary signatures then dispatch through a first-byte jump
//! table, so each file is compared against only the formats that start with
//! its first byte. Rarer structural checks (a `ustar` header, tampered PEs,
//! ASAR, LZMA, a FAT boot sector) run last.
//!
//! The name is read only where the parent module's precedence allows: to
//! split one signature between the formats that share it.

use std::{io::Read, path::Path};

use super::{
    Compression, DetectionSource, FileType,
    ext::{lowercase_ext, name_ends_with_ci},
    file_type::Strength,
    go_module, shebang,
    sniff::Sniff,
    text::{UTF8_BOM, head_is_text, strip_utf8_bom},
    torch,
};
use crate::bytes;

mod archive;
mod certificate;
mod lockfile;
mod markup;
mod vhd;

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
    /// [`head_is_text`] of `data`. Every binary header this module claims
    /// by a short signature carries a NUL or control byte near the front; a
    /// script that merely opens with the same letters (`MZ=1;…`, `true && …`,
    /// `GIF89a=…`) carries none.
    text: bool,
    /// `data` past leading whitespace.
    head: &'a [u8],
}

impl Probe<'_, '_> {
    /// Whether the name claims a programming language. A text signature is a
    /// line any script can open with (a comment, a section header that the
    /// interpreter reports and skips), so under such a name the script is
    /// what runs.
    fn named_language(&self) -> bool {
        self.sniff
            .claim()
            .is_some_and(|c| c.file_type.strength() == Strength::Language)
    }
}

/// The content rules in the order they are tried; the first that claims the
/// bytes decides. Text-shaped headers that may sit behind whitespace or a BOM
/// and signatures that are not at offset 0 come first, then the first-byte
/// jump table, then the rarer structural checks.
const RULES: &[fn(&Probe<'_, '_>) -> Option<Found>] = &[
    cold_fusion_template,
    phar,
    executable_head,
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
    cms_property_list,
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
    fat_boot_sector,
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
        text: head_is_text(data),
        head: data.trim_ascii_start(),
    };
    RULES.iter().find_map(|rule| rule(&probe))
}

/// A program the operating system runs as it stands: a PE, ELF or Mach-O
/// image, or a script whose `#!` line names its interpreter. The loader reads
/// the head and ignores what follows, so a trailer (a DMG `koly` block, a VHD
/// footer), a mark at a fixed offset (an `ftyp` box in the DOS header's unused
/// fields) or a comment that opens a lockfile does not make it anything else.
/// A type-1 AppImage is an ELF runtime at the head of an ISO 9660 image that
/// holds the application; the image is the payload, so it stays an image.
fn executable_head(p: &Probe<'_, '_>) -> Option<Found> {
    // Only the jump-table arms that can yield a program, so an archive's
    // members are not walked twice.
    if !matches!(
        p.first,
        b'M' | 0x7F | 0xCA | 0xCE | 0xCF | 0xFE | 0xBE | b'#' | 0xEF | b'\n' | b'\r' | b' ' | b'\t'
    ) {
        return None;
    }
    leading_signature(p)
        .filter(|&(ft, source)| {
            source == DetectionSource::Shebang
                || matches!(ft, FileType::Pe | FileType::Elf | FileType::MachO)
        })
        .filter(|_| iso_image(p).is_none())
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
            || !header.get(25..33)?.iter().all(u8::is_ascii_hexdigit)
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
    if !offset_bytes.iter().all(u8::is_ascii_hexdigit) {
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

/// CMS framing around a parsed property list, independent of its filename.
fn cms_property_list(p: &Probe<'_, '_>) -> Option<Found> {
    crate::formats::cms::encapsulated_plist(p.data)
        .map(|_| (FileType::Plist, DetectionSource::Magic))
}

/// The detached signature sidecars shipped with several content-decryption
/// clients: a length-framed X.509 certificate, signature material and flags.
fn certificate_signature(p: &Probe<'_, '_>) -> Option<Found> {
    certificate::looks_like_certificate_signature(p.data)
        .map(|()| (FileType::CertificateSignature, DetectionSource::Magic))
}

/// A legacy VHD v1 image, by its footer.
fn vhd_image(p: &Probe<'_, '_>) -> Option<Found> {
    vhd::looks_like_vhd(p.data).map(|()| (FileType::Vhd, DetectionSource::Magic))
}

/// An Image4 payload carrying a trust-cache table.
fn image4_trustcache(p: &Probe<'_, '_>) -> Option<Found> {
    super::image4_trustcache::parse(p.data)
        .map(|_| (FileType::Image4TrustCache, DetectionSource::Magic))
}

/// A Go module manifest has no magic bytes, but its first non-comment
/// directive is unambiguous. Detect it from content so renamed `go.mod`
/// files still reach module-aware facts and rules before extension fallback.
fn go_module(p: &Probe<'_, '_>) -> Option<Found> {
    // Under a language's name, a block left open at the end is a script
    // whose lines the block swallows rather than a cut-off manifest.
    let manifest = if p.named_language() {
        go_module::go_mod_blocks_closed(p.data) == Some(true)
    } else {
        go_module::looks_like_go_mod(p.data)
    };
    (p.text && manifest).then_some((FileType::GoMod, DetectionSource::Heuristic))
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
        n => (bytes::sat_usize(n), 8),
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
/// language, so only this section names it, under any name but a
/// language's ([`Probe::named_language`]).
fn url_shortcut(p: &Probe<'_, '_>) -> Option<Found> {
    if p.named_language() {
        return None;
    }
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
/// renamed for storage (`yarn.<sha>.lock`) is still one. A header is a line
/// of comments a script under a language's name may open with as well; npm's
/// JSON is parsed whole, so nothing else can follow it.
fn lockfile(p: &Probe<'_, '_>) -> Option<Found> {
    lockfile::lockfile_header(p.data)
        .filter(|_| !p.named_language())
        .or_else(|| lockfile::npm_json_lockfile(p.data))
        .map(|ft| (ft, DetectionSource::Magic))
}

/// PostScript and EPS. `%!PS` at the start is the format; a `.ps` extension
/// is only the fallback for a file that does not carry the header. PowerShell
/// skips that line with an error, so under its name the script stands.
fn postscript(p: &Probe<'_, '_>) -> Option<Found> {
    (!p.named_language() && p.head.starts_with(b"%!PS"))
        .then_some((FileType::PostScript, DetectionSource::Magic))
}

/// Compiled Android XML. The container chunk says how long the document is,
/// and the next chunk is the string pool. Both have to agree; `03 00 08 00`
/// by itself is four bytes and shows up in unrelated binaries.
fn android_binary_xml(p: &Probe<'_, '_>) -> Option<Found> {
    // Chunk type 0x0003 and header size 8 (u16 LE each), the u32 file size,
    // then the string pool's chunk type, 0x0001, in a header of 12 bytes.
    let &[0x03, 0x00, 0x08, 0x00, s0, s1, s2, s3, 0x01, 0x00, _, _, ..] = p.data else {
        return None;
    };
    (p.data.len() <= 16 * 1024 * 1024
        && usize::try_from(u32::from_le_bytes([s0, s1, s2, s3])) == Ok(p.data.len()))
    .then_some((FileType::Xml, DetectionSource::Magic))
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
/// whose header is text by design keep their claim, and so does a PE whose
/// `e_lfanew` leads to its `PE\0\0` header: the loader reads nothing else of
/// the DOS header, so all of it may be printable. Any other claim falls
/// through to the rules after this one.
fn leading_signature(p: &Probe<'_, '_>) -> Option<Found> {
    first_byte_signature(p).filter(|&(ft, source)| {
        source != DetectionSource::Magic
            || !p.text
            || has_text_header(ft)
            || (ft == FileType::Pe && new_header(p.data).is_some_and(|h| h.starts_with(b"PE\0\0")))
    })
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
            // consumer that skips what `is_analyzed` rejects skips it.
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
        // ELF: 7F 45 4C 46
        0x7F => data
            .starts_with(b"\x7FELF")
            .then_some((FileType::Elf, DetectionSource::Magic)),
        b'M' => {
            // MZ-prefixed Windows programs include both PE and the older NE
            // format. Route NE to its own generic-binary file type instead of
            // calling it PE (which the PE analyzer correctly rejects).
            if second == b'Z' {
                let file_type = if looks_like_ne_executable(data) {
                    FileType::Ne
                } else if new_header(data).is_some_and(|h| h.starts_with(b"PE\0\0"))
                    || coherent_pe_with_damaged_signature(data)
                {
                    FileType::Pe
                } else if super::dos::looks_like_dos_mz(data) && !has_extended_mz_header(data) {
                    // Preserve a validated 16-bit DOS image for generic byte
                    // analysis rather than routing it to the PE parser.
                    FileType::Data
                } else {
                    // `MZ` and nothing behind it -- text that happens to start
                    // so, a truncated header: let the other rules type it.
                    return None;
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
        // Mach-O: FEEDFACE (32-bit) or FEEDFACF (64-bit)
        0xFE => matches!(data, [_, 0xED, 0xFA, 0xCE | 0xCF, ..])
            .then_some((FileType::MachO, DetectionSource::Magic)),
        // Mach-O 32-bit swapped: CEFAEDFE
        0xCE => data
            .starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
            .then_some((FileType::MachO, DetectionSource::Magic)),
        // Mach-O 64-bit swapped: CFFAEDFE
        0xCF => data
            .starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
            .then_some((FileType::MachO, DetectionSource::Magic)),
        // Mach-O fat swapped: BEBAFECA
        0xBE => data
            .starts_with(&[0xBE, 0xBA, 0xFE, 0xCA])
            .then_some((FileType::MachO, DetectionSource::Magic)),
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
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        0x89 => data
            .starts_with(b"\x89PNG\r\n\x1a\n")
            .then_some((FileType::Png, DetectionSource::Magic)),
        // GIF87a / GIF89a.
        b'G' => (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a"))
            .then_some((FileType::Gif, DetectionSource::Magic)),
        // OpenType with CFF outlines: the sfnt version is the tag `OTTO`.
        b'O' => data
            .starts_with(b"OTTO")
            .then_some((FileType::Font, DetectionSource::Magic)),
        // Web font wrappers: `wOFF` (WOFF 1) and `wOF2` (WOFF 2).
        b'w' => (data.starts_with(b"wOFF") || data.starts_with(b"wOF2"))
            .then_some((FileType::Font, DetectionSource::Magic)),
        // Apple sfnt flavors: `true` (TrueType), `typ1` (PostScript in an
        // sfnt wrapper), `ttcf` (TrueType collection).
        b't' => {
            (data.starts_with(b"true") || data.starts_with(b"typ1") || data.starts_with(b"ttcf"))
                .then_some((FileType::Font, DetectionSource::Magic))
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
        // LNK: 4C 00 00 00 01 14 02 00 ...
        0x4C => data
            .starts_with(LNK_MAGIC)
            .then_some((FileType::Lnk, DetectionSource::Magic)),
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
        // PDF: %PDF-
        b'%' => data
            .starts_with(b"%PDF-")
            .then_some((FileType::Pdf, DetectionSource::Magic)),
        0x80 => looks_like_pickle(path, data).then_some((FileType::Pickle, DetectionSource::Magic)),
        // Binary Plist: bplist. A `.nib` with this magic is a keyed-archive
        // nib (NSKeyedArchiver output inside an older nib bundle), but the
        // bytes are a plain property list either way, so it is typed
        // Plist for every plist-aware consumer.
        b'b' => data
            .starts_with(b"bplist")
            .then_some((FileType::Plist, DetectionSource::Magic)),
        // Compiled Interface Builder archive (NIBArchive)
        b'N' => data
            .starts_with(b"NIBArchive")
            .then_some((FileType::Nib, DetectionSource::Magic)),
        b'!' => {
            // Unix `ar` archive (`!<arch>\n`). This magic is shared by Debian
            // packages and static libraries (.a). Distinguish by the first `ar`
            // member: a `.deb` always leads with `debian-binary`; a static
            // library leads with a symbol/string table (`/`, `//`, `__.SYMDEF`)
            // or an object file, whose bytes are code, not an opaque package.
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
        // XAR (macOS PKG): xar!
        b'x' => data
            .starts_with(b"xar!")
            .then_some((FileType::PkgMacos, DetectionSource::Magic)),
        // Chrome extension: Cr24
        b'C' => data
            .starts_with(b"Cr24")
            .then_some((FileType::Crx, DetectionSource::Magic)),
        // SquashFS superblock, little-endian: hsqs
        b'h' => data
            .starts_with(b"hsqs")
            .then(|| (squashfs_type(path), DetectionSource::Magic)),
        // SquashFS superblock, big-endian: sqsh
        b's' => data
            .starts_with(b"sqsh")
            .then(|| (squashfs_type(path), DetectionSource::Magic)),
        // ASCII-armored OpenPGP detached signature. The binary packet form
        // has no byte we can claim safely — its tag byte collides with PNG
        // and other formats — so that one is left to the extension.
        b'-' => data
            .starts_with(b"-----BEGIN PGP SIGNATURE-----")
            .then_some((FileType::PgpSignature, DetectionSource::Magic)),
        // RPM: ED AB EE DB
        0xED => data
            .starts_with(&[0xED, 0xAB, 0xEE, 0xDB])
            .then_some((FileType::Rpm, DetectionSource::Magic)),
        // Java Object Serialization Stream Protocol: STREAM_MAGIC (0xACED),
        // STREAM_VERSION (0x0005), followed by a valid leading stream tag
        // (TC_NULL..=TC_MAX: 0x70..=0x7E).
        0xAC => matches!(data, [0xAC, 0xED, 0x00, 0x05, 0x70..=0x7E, ..])
            .then_some((FileType::Data, DetectionSource::Magic)),
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
            // A Windows bitmap: `BM`, then the info header that follows the
            // 14-byte file header. `BM` alone is two letters, and the
            // file-size field is routinely wrong in real bitmaps (truncated
            // downloads, writers that leave it zero), so the claim rests on
            // the info header instead: its size field names one of the header
            // versions Windows and OS/2 defined, it has one colour plane, and
            // its pixel depth is one a decoder accepts.
            if data.starts_with(b"BM") && data.get(14..).is_some_and(looks_like_dib_header) {
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
        // ASCII CPIO. The six-digit magic alone is six ordinary digits, so
        // require the whole fixed-size header to be digits of its radix.
        b'0' => looks_like_ascii_cpio(data).then_some((FileType::Cpio, DetectionSource::Magic)),
        // 7z: 37 7A BC AF 27 1C
        b'7' => data
            .starts_with(b"7z\xBC\xAF\x27\x1C")
            .then_some((FileType::SevenZ, DetectionSource::Magic)),
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
                shebang::detect_shebang(data)
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
                Some(rest) if rest.starts_with(b"#!") => shebang::detect_shebang(rest),
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
                shebang::detect_shebang(rest)
            } else {
                None
            }
        }
        // Xcode writes this exact comment as the first line of every
        // `project.pbxproj`; it is the format's only signature.
        b'/' => data
            .starts_with(b"// !$*UTF8*$!")
            .then_some((FileType::Pbxproj, DetectionSource::Magic)),
        // The modern .reg header as UTF-8 without a BOM; the UTF-16LE and
        // UTF-8 BOM spellings are claimed in the 0xFF and 0xEF arms. Same
        // reasoning as the `REGEDIT4` arm above.
        b'W' => data
            .starts_with(REGISTRY_EDITOR_HEADER)
            .then_some((FileType::Reg, DetectionSource::Magic)),
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
    if p.data.get(257..262) != Some(b"ustar") {
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
            p.data
                .get(i..)
                .and_then(new_header)
                .is_some_and(|header| header.starts_with(b"PE\0\0"))
        })
        .then_some((FileType::Pe, DetectionSource::Magic))
}

/// Markup after a BOM or leading whitespace. Markup flush at the start was
/// read by the `<` arm of the jump table.
fn markup(p: &Probe<'_, '_>) -> Option<Found> {
    if p.first == b'<' {
        return None;
    }
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
    // 2^n has n trailing zeros; 2^n + 2^(n-1) = 3 * 2^(n-1) has n - 1.
    let k = dict.trailing_zeros();
    let dict_ok =
        ((12..=30).contains(&k) && dict == 1 << k) || ((11..=29).contains(&k) && dict == 3 << k);
    (dict_ok && (size == u64::MAX || size < 1 << 40))
        .then_some((FileType::Lzma, DetectionSource::Magic))
}

/// A standalone FAT volume boot sector has no container magic; its validated
/// BIOS parameter block identifies it.
fn fat_boot_sector(p: &Probe<'_, '_>) -> Option<Found> {
    super::dos::looks_like_fat_boot_sector(p.data)
        .then_some((FileType::FatBootSector, DetectionSource::Heuristic))
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

/// Preserve newer executable formats that share the MZ prefix; their DOS stub
/// can itself have a coherent page count and entry point.
fn has_extended_mz_header(data: &[u8]) -> bool {
    matches!(
        new_header(data).and_then(|header| header.get(..2)),
        Some(b"PE" | b"NE" | b"LE" | b"LX" | b"W3" | b"W4")
    )
}

/// Check the DOS MZ header's `e_lfanew` pointer for a Windows NE signature.
/// NE is a 16-bit executable format; it must not be routed to the PE parser.
fn looks_like_ne_executable(data: &[u8]) -> bool {
    data.starts_with(b"MZ") && new_header(data).is_some_and(|header| header.starts_with(b"NE"))
}

/// A PE image whose `PE\0\0` signature was overwritten -- a reflective
/// loader's trick -- but whose headers still describe a loadable program:
/// a known machine and optional-header magic, a sane section count, the
/// executable bit, every section inside the image and the file, and an entry
/// point in stored executable bytes. MZ-prefixed text and truncated headers
/// fail it.
fn coherent_pe_with_damaged_signature(data: &[u8]) -> bool {
    let u16_at = |at: usize| bytes::u16_le(data, at);
    let u32_at = |at: usize| bytes::u32_le(data, at);
    let check = || -> Option<bool> {
        let nt = usize::try_from(u32_at(0x3c)?).ok()?;
        if nt < 0x40 {
            return Some(false);
        }
        let coff = nt.checked_add(4)?;
        let machine = u16_at(coff)?;
        let count = usize::from(u16_at(coff.checked_add(2)?)?);
        let opt_size = usize::from(u16_at(coff.checked_add(16)?)?);
        let characteristics = u16_at(coff.checked_add(18)?)?;
        let opt = coff.checked_add(20)?;
        let min_opt = match (machine, u16_at(opt)?) {
            (0x014c, 0x010b) => 0xe0,
            (0x8664 | 0xaa64, 0x020b) => 0xf0,
            _ => return Some(false),
        };
        if !(1..=96).contains(&count) || opt_size < min_opt || characteristics & 2 == 0 {
            return Some(false);
        }
        let entry = u32_at(opt.checked_add(16)?)?;
        let image_size = u32_at(opt.checked_add(56)?)?;
        let headers_size = usize::try_from(u32_at(opt.checked_add(60)?)?).ok()?;
        let table = opt.checked_add(opt_size)?;
        let table_end = table.checked_add(count.checked_mul(40)?)?;
        if entry == 0
            || entry >= image_size
            || table_end > headers_size
            || headers_size > data.len()
        {
            return Some(false);
        }
        let mut executable_entry = false;
        for section in data.get(table..table_end)?.as_chunks::<40>().0 {
            let field = |at: usize| bytes::u32_le(section, at);
            let (virtual_size, virtual_start) = (field(8)?, field(12)?);
            let (raw_size, raw_start, flags) = (field(16)?, field(20)?, field(36)?);
            if virtual_start.checked_add(virtual_size.max(raw_size))? > image_size {
                return Some(false);
            }
            if raw_size != 0 {
                let start = usize::try_from(raw_start).ok()?;
                let end = start.checked_add(usize::try_from(raw_size).ok()?)?;
                if start < headers_size || end > data.len() {
                    return Some(false);
                }
                // Stored executable bytes at the entry point, not a
                // virtual-only zero-fill section with fabricated flags.
                executable_entry |= flags & 0x2000_0000 != 0
                    && entry >= virtual_start
                    && entry < virtual_start.checked_add(raw_size)?;
            }
        }
        Some(executable_entry)
    };
    check().unwrap_or(false)
}

/// The bytes from the header an MZ image's `e_lfanew` points at. `e_lfanew`
/// closes the 64-byte DOS header, so an offset inside that header names no
/// new header.
fn new_header(mz: &[u8]) -> Option<&[u8]> {
    let offset = usize::try_from(bytes::u32_le(mz, 0x3c)?).ok()?;
    if offset < 0x40 {
        return None;
    }
    mz.get(offset..)
}

/// A SquashFS image is the wire format of a Snap package, so the superblock
/// magic alone cannot tell the two apart — reading `meta/snap.yaml` would mean
/// decompressing the filesystem. The `.snap` extension is the available signal,
/// mirroring how `.xbps` separates a Void package from a generic zstd tar.
fn squashfs_type(path: &Path) -> FileType {
    if name_ends_with_ci(path, ".snap") {
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
    let (header, is_digit): (usize, fn(&u8) -> bool) = match data.get(..6) {
        Some(b"070707") => (76, |b| matches!(b, b'0'..=b'7')),
        Some(b"070701" | b"070702") => (110, u8::is_ascii_hexdigit),
        _ => return false,
    };
    data.get(6..header)
        .is_some_and(|fields| fields.iter().all(is_digit))
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
    let shift = bytes::u16_le(data, 0x1E)?;
    if !matches!(shift, 9 | 12) {
        return None;
    }
    let first = usize::try_from(bytes::u32_le(data, 0x30)?).ok()?;
    let at = first
        .checked_add(1)?
        .checked_mul(1 << shift)?
        .checked_add(0x50)?;
    data.get(at..at.checked_add(16)?)?.try_into().ok()
}

/// Python pickle. Protocol 4 and 5 open with a FRAME whose u64 length has
/// no business near 2^40, and legacy `torch.save` with its own magic: either
/// is the format itself. Protocols 2 and 3 open with two bytes that other
/// binary formats share, so there the name has to agree: one of pickle's own,
/// or a model or checkpoint suffix (`.pt`, `.ckpt`, scikit-learn's `.sav`)
/// that `pickle.load` and `torch.load` read whatever it says.
fn looks_like_pickle(path: &Path, data: &[u8]) -> bool {
    match data {
        [0x80, 4 | 5, 0x95, frame @ ..] => bytes::u64_le(frame, 0).is_some_and(|len| len < 1 << 40),
        _ if data.starts_with(torch::LEGACY_MAGIC) => true,
        [0x80, 2 | 3, ..] => matches!(
            lowercase_ext(path).as_deref(),
            Some("pkl" | "pickle" | "p" | "joblib" | "debug_pkl" | "pt" | "pth" | "ckpt" | "sav")
        ),
        _ => false,
    }
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

#[cfg(test)]
mod tests;
