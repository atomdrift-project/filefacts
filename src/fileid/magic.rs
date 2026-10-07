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

use super::ext::{ends_with_ci, is_odf_extension, lowercase_ext};
use super::scripts::find_ci;
use super::{
    ArchiveFormat, Compression, DetectionSource, FileType, UTF8_BOM, container_of, sniff::Sniff,
    strip_utf8_bom,
};
use crate::bytes;

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

/// Detect file type from content. Returns the type and how it was detected.
pub(crate) fn detect_from_content(path: &Path, data: &[u8]) -> Option<(FileType, DetectionSource)> {
    detect_from_sniff(&Sniff::new(path, data))
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
    iso_image,
    leading_signature,
    ustar,
    python_bytecode,
    tampered_pe,
    markup,
    asar,
    lzma_alone,
    github_actions_workflow,
    manifest,
];

/// [`detect_from_content`], reusing what `sniff` has already derived.
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
    (!p.text && p.data.len() >= 12 && p.data.get(4..8) == Some(b"ftyp"))
        .then_some((FileType::Mp4, DetectionSource::Magic))
}

/// A Windows URL shortcut: an INI whose first section is
/// `[InternetShortcut]`. It carries no magic number and scores as no known
/// language, so a copy named `invoice.pdf.url` came back `unknown` -- and an
/// unidentified archive member is skipped whole. One in this corpus is the
/// entire payload of a delivery zip: `URL=file:\\<ip>@80\...\scan.pdf.lnk`,
/// a WebDAV fetch of a second shortcut, padded to 346 KB with NULs.
fn url_shortcut(p: &Probe<'_, '_>) -> Option<Found> {
    p.head
        .get(..URL_SHORTCUT_SECTION.len())
        .is_some_and(|section| section.eq_ignore_ascii_case(URL_SHORTCUT_SECTION))
        .then_some((FileType::Text, DetectionSource::Magic))
}

/// Windows Script Host documents: a `.wsf` job, a `.wsc` component or a
/// `.sct` scriptlet is XML whose `<script language=...>` names what runs.
/// The XML arm below would call the prolog'd ones plain XML, and markup
/// sniffing called the rest HTML, so a VBScript dropper in a `<job>` was
/// never scored as a script.
fn script_host(p: &Probe<'_, '_>) -> Option<Found> {
    script_host_document(p.sniff).map(|ft| (ft, DetectionSource::Magic))
}

/// Script Encoder output (`.vbe`, `.jse`): `#@~^`, a six-character base64
/// length, `==`. The body is ciphertext full of control bytes, so it was
/// typed opaque data.
fn script_encoder(p: &Probe<'_, '_>) -> Option<Found> {
    encoded_script(p.path, p.head).map(|ft| (ft, DetectionSource::Magic))
}

/// Lockfiles announce themselves in their opening lines. Hopper copies are
/// often renamed `yarn.<sha>.lock`, so the header, not the name, has to
/// carry them to the lockfile traits.
fn lockfile(p: &Probe<'_, '_>) -> Option<Found> {
    lockfile_header(p.data).map(|ft| (ft, DetectionSource::Magic))
}

/// PostScript and EPS. `%!PS` at the start is the format; a `.ps` extension
/// is only the fallback for a file that does not carry the header.
fn postscript(p: &Probe<'_, '_>) -> Option<Found> {
    (p.head.len() >= 4 && p.head.starts_with(b"%!PS"))
        .then_some((FileType::PostScript, DetectionSource::Magic))
}

/// Android binary XML: chunk type 0x0003, header size 8, a file-size field
/// that covers this buffer, and a string-pool chunk next. A `.xml` name
/// used to be the only signal, so a compiled layout was "XML" by extension
/// while the text parser never saw a tag.
fn android_binary_xml(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_axml(p.data).then_some((FileType::Xml, DetectionSource::Magic))
}

/// An HTML document, whatever it is called and however it is indented.
/// Keyed off `head` rather than `data` because real pages are not flush
/// left: four VirusShare samples open with four spaces before the doctype,
/// which a `starts_with` on byte 0 misses, and they were then scored as
/// JavaScript on the strength of the jQuery inside them.
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

fn udif_dmg(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_udif_dmg(p.data).then_some((FileType::Dmg, DetectionSource::Magic))
}

fn iso_image(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_iso_or_udf(p.data).then_some((FileType::Iso, DetectionSource::Magic))
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
            // claims. Return Unknown so cleave's `is_program()` skip kicks
            // in — otherwise `._foo.php` gets analyzed as PHP, the binary
            // body trips entropy/obfuscation traits, and a benign Composer
            // tarball lights up at suspicious.
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
            } else if let Some(rest) = data.strip_prefix(&[0x00, 0x01, 0x00, 0x00])
                && !rest.starts_with(b"Standard Jet DB")
                && !rest.starts_with(b"Standard ACE DB")
            {
                // sfnt version 1.0 — the TrueType flavor every `.ttf` uses.
                // A Microsoft Access database opens with the same four bytes
                // and then names its engine, so an .mdb/.accdb would otherwise
                // be handed to the font parser and read as a corrupt font
                // rather than as a database with macros in it. Seen on
                // vxheaven's Virus.MSAccess.Detox.a.
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
            // ZIP/JAR/OOXML: PK
            if second == b'K' {
                Some(classify_pk(path, data))
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
                // A .reg file's first line names the format. `FileType::Reg`
                // was once reachable only from a `.reg` extension, so a registry
                // script under any other name -- vxheaven's
                // `Trojan.WinREG.AntiFireWall.a`, where the `.a` is a variant
                // letter -- was typed by whatever the trailing component
                // happened to mean. Nothing but a registry script opens with
                // this line. REGEDIT4 is the Windows 9x/NT4 spelling; the
                // Windows 2000+ one is handled in the `W` arm below.
                Some((FileType::Reg, DetectionSource::Magic))
            } else if (data.starts_with(b"RIFF") || data.starts_with(b"RIFX")) && data.len() >= 12 {
                // RIFF container: `RIFF` + u32 length + form type. WAVE, WEBP
                // and AVI share the wrapper, so the form type at offset 8
                // decides. An animated cursor (`ACON`) is not audio.
                let kind = match data.get(8..12) {
                    Some(b"WEBP") => Some(FileType::Webp),
                    Some(b"WAVE") => Some(FileType::Wav),
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
            // bytes are a plain property list either way -- type it Plist so
            // every plist-aware consumer (including rule engines that don't
            // know a distinct Nib type) can address it.
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
            // What it wraps is read, not guessed from the name: npm packages,
            // sdists and crates arrive as `<hash>.sample` in content-addressed
            // stores.
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
/// package or a plain tar.
///
/// This used to fall through to the extension fallback, which meant a tar
/// was only recognized when it was *named* `.tar`: the same bytes under any
/// other extension were typed `Data` and never walked, so every member went
/// unanalyzed. That is a detection gap an attacker gets for free by renaming
/// a file — an XMRig 6.24.0 release tarball named `<sha256>.bin` scored one
/// finding as an opaque blob and six once renamed to `.tar`.
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

/// Tampered PE: only scan if there's an 'M' in the first 64 bytes.
fn tampered_pe(p: &Probe<'_, '_>) -> Option<Found> {
    if !p.data.iter().take(64).skip(1).any(|&b| b == b'M') {
        return None;
    }
    detect_tampered_pe(p.data).map(|ft| (ft, DetectionSource::Magic))
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
    crate::formats::phar::is_phar(p.data).then_some((FileType::Phar, DetectionSource::Magic))
}

fn asar(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_asar(p.data).then_some((FileType::Asar, DetectionSource::Magic))
}

fn lzma_alone(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_lzma_alone(p.data).then_some((FileType::Lzma, DetectionSource::Magic))
}

fn github_actions_workflow(p: &Probe<'_, '_>) -> Option<Found> {
    looks_like_github_actions_workflow(p.path, p.data)
        .then_some((FileType::GithubActions, DetectionSource::Heuristic))
}

/// Manifest files — only checked when there's a filename component.
fn manifest(p: &Probe<'_, '_>) -> Option<Found> {
    p.path.file_name()?;
    detect_manifest(p.path, p.data).map(|ft| (ft, DetectionSource::Filename))
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

fn looks_like_udif_dmg(data: &[u8]) -> bool {
    let Some(trailer) = data.last_chunk::<512>() else {
        return false;
    };
    trailer.starts_with(b"koly")
        && bytes::u32_be(trailer, 4).is_some_and(|version| version >= 4)
        && bytes::u32_be(trailer, 8) == Some(512)
}

/// Optical-disc image (`.iso`): ISO 9660 and/or UDF.
///
/// The Volume Descriptor set begins at sector 16 (offset `0x8000`); each
/// 2048-byte descriptor is `[type:1][standard_identifier:5]`. ISO 9660 volume
/// descriptors carry `"CD001"`; a UDF bridge Volume Recognition Sequence carries
/// `"BEA01"`/`"NSR02"`/`"NSR03"`/`"TEA01"` (Windows install media are UDF). Either
/// identifier in the first several sectors means 7-Zip can unpack the image.
fn looks_like_iso_or_udf(data: &[u8]) -> bool {
    (16..=22usize).any(|sector| {
        let off = sector * 2048 + 1;
        matches!(
            data.get(off..off + 5),
            Some(b"CD001" | b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01")
        )
    })
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
/// bytes other than whitespace. A character cut off by the end of the probe
/// still counts.
///
/// The strictest of the three binary/text tests in fileid, because it has the
/// least to read: one control byte in the probe doubts a short signature, and
/// form feed is the only control byte beyond tab and line breaks that plain
/// text is allowed. `heuristics::looks_like_binary` and `scripts::is_binary`
/// judge whole scoring windows by the share of control bytes instead, and the
/// script grammars also allow the escapes that batch and IRC scripts print.
pub(crate) fn content_is_text(data: &[u8]) -> bool {
    let head = data.get(..TEXT_PROBE).unwrap_or(data);
    let control = |b: &u8| (*b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0C)) || *b == 0x7F;
    if head.iter().any(control) {
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

/// The pickle `torch.save` wrote before its zip format: protocol 2, then a
/// ten-byte LONG1 holding the magic number 0x1950a86a20f9469cfc6c.
const TORCH_LEGACY_MAGIC: &[u8] = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19";

/// Python pickle. Protocol 4 and 5 open with a FRAME whose u64 length has
/// no business near 2^40, and legacy `torch.save` with its own magic: either
/// is the format itself. Protocols 2 and 3 open with two bytes that other
/// binary formats share, so there the name has to agree.
fn looks_like_pickle(path: &Path, data: &[u8]) -> bool {
    match data {
        [0x80, 4 | 5, 0x95, frame @ ..] => bytes::u64_le(frame, 0).is_some_and(|len| len < 1 << 40),
        _ if data.starts_with(TORCH_LEGACY_MAGIC) => true,
        [0x80, 2 | 3, ..] => matches!(
            lowercase_ext(path).as_deref(),
            Some("pkl" | "pickle" | "joblib" | "pt" | "pth")
        ),
        _ => false,
    }
}

/// Electron ASAR: a Chromium pickle holding the header size (`04 00 00 00`,
/// then the size), a second pickle whose payload is 4 bytes shorter, and the
/// JSON file table as its string.
fn looks_like_asar(data: &[u8]) -> bool {
    let u32_at = |off| bytes::u32_le(data, off);
    u32_at(0) == Some(4)
        && u32_at(4).is_some_and(|size| u32_at(8) == size.checked_sub(4))
        && data
            .get(16..)
            .is_some_and(|rest| rest.starts_with(b"{\"files\":"))
}

/// LZMA-alone (`.lzma`): the properties byte every mainstream encoder writes
/// (0x5D: lc=3, lp=0, pb=2), a dictionary size that `xz` and 7-Zip only ever
/// write as 2^n or 2^n + 2^(n-1) between 4 KiB and 1.5 GiB, and an
/// uncompressed size that is either unknown (all ones) or under 2^40. The
/// header has no magic, so all three must hold; Chromium's `.pak` resources
/// satisfy the last two.
fn looks_like_lzma_alone(data: &[u8]) -> bool {
    if data.len() < 14 || data.first() != Some(&0x5D) {
        return false;
    }
    let (Some(dict), Some(size)) = (bytes::u32_le(data, 1), bytes::u64_le(data, 5)) else {
        return false;
    };
    let n = dict.trailing_zeros();
    let dict_ok = (12..=30).contains(&n) && (dict == 1 << n || dict == 3 << (n - 1));
    dict_ok && (size == u64::MAX || size < 1 << 40)
}

/// How far detection will inflate a gzip tar while reading its member names.
/// npm packages, sdists and crates name themselves anywhere under their one
/// root, and sdists often put `PKG-INFO` last, after generated clients, tests
/// and documentation, so this is generous; it still bounds a decompression
/// bomb.
const TAR_PEEK_LIMIT: u64 = 64 << 20;

/// How far detection will inflate a zstd tar. Its packages (FreeBSD, Arch,
/// Void) name themselves in their leading members.
const TAR_HEAD_LIMIT: u64 = 1 << 20;

/// Members a plain tar is read through for an image's markers; a `docker
/// save` bundle writes `manifest.json` after its layers.
const TAR_DEEP_MEMBERS: usize = 512;

/// Members read before a tar with several top-level entries is settled.
/// Every first-member and metadata marker sits within them.
const TAR_SHALLOW_MEMBERS: usize = 8;

/// What a container's decoded bytes turned out to be.
#[derive(Clone, Copy)]
enum Inside {
    /// The codec could not produce a first block: a truncated or corrupt
    /// stream, or no decoder linked. The content has not spoken.
    Unreadable,
    /// The stream decoded and is not a tar.
    NotTar,
    /// A tar, typed by its layout: a package, or plain [`FileType::Tar`].
    Tar(FileType),
}

/// What a tar's member names make it: a package with a fixed layout, or
/// plain [`FileType::Tar`]. `deep` reads on for container-image markers,
/// which only a plain tar can carry.
///
/// * First member: `<root>/gpkg-1` (Gentoo), `.SIGN.*` (Alpine),
///   `+COMPACT_MANIFEST`/`+MANIFEST` (FreeBSD), `props.plist` (Void).
/// * Anywhere: `.PKGINFO` with `.MTREE` or `.BUILDINFO` (Arch);
///   `metadata.gz` with `data.tar.gz` (gem); `oci-layout` with `index.json`,
///   or `manifest.json` with layers (OCI / `docker save`).
/// * One top-level directory holding `package/package.json` (npm),
///   `<root>/PKG-INFO` (Python sdist) or `<root>/Cargo.toml.orig` (crate).
fn tar_layout(mut reader: impl Read, deep: bool) -> Inside {
    // Read the first header block by hand, so a stream the codec cannot
    // decode is told apart from one that decodes to something else.
    let mut block = [0u8; 512];
    let mut filled = 0;
    while let Some(unfilled @ [_, ..]) = block.get_mut(filled..) {
        match reader.read(unfilled) {
            Ok(0) => return Inside::NotTar,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Inside::Unreadable,
        }
    }
    let mut archive = tar::Archive::new(std::io::Cursor::new(block).chain(reader));
    let Ok(mut entries) = archive.entries() else {
        return Inside::NotTar;
    };
    // Some while every member so far shares one top-level directory.
    let mut root: Option<Option<String>> = Some(None);
    let mut members = 0usize;
    let (mut pkginfo, mut arch_meta) = (false, false);
    let (mut gem_metadata, mut gem_data) = (false, false);
    let (mut oci_layout, mut oci_index) = (false, false);
    let (mut docker_manifest, mut docker_layers) = (false, false);
    loop {
        let entry = match entries.next() {
            Some(Ok(entry)) => entry,
            // A stream whose first header does not parse is not a tar.
            Some(Err(_)) if members == 0 => return Inside::NotTar,
            Some(Err(_)) | None => break,
        };
        if matches!(
            entry.header().entry_type(),
            tar::EntryType::XGlobalHeader
                | tar::EntryType::XHeader
                | tar::EntryType::GNULongName
                | tar::EntryType::GNULongLink
        ) {
            continue;
        }
        let Ok(path) = entry.path() else { continue };
        let path = path.to_string_lossy();
        let name = path.trim_start_matches("./").trim_end_matches('/');
        let (top, rest) = name.split_once('/').unwrap_or((name, ""));
        let base = name.rsplit('/').next().unwrap_or(name);
        // macOS AppleDouble sidecars that `tar` smuggles in are not members.
        if base.starts_with("._") || name.is_empty() {
            continue;
        }
        members += 1;

        if members == 1 {
            if base == "gpkg-1" && rest == "gpkg-1" {
                return Inside::Tar(FileType::GentooBinpkg);
            }
            if name.starts_with(".SIGN.") {
                return Inside::Tar(FileType::ApkAlpine);
            }
            if matches!(name, "+COMPACT_MANIFEST" | "+MANIFEST") {
                return Inside::Tar(FileType::PkgFreebsd);
            }
            if name == "props.plist" {
                return Inside::Tar(FileType::Xbps);
            }
        }
        match name {
            ".PKGINFO" => pkginfo = true,
            ".MTREE" | ".BUILDINFO" => arch_meta = true,
            "metadata.gz" => gem_metadata = true,
            "data.tar.gz" => gem_data = true,
            "oci-layout" => oci_layout = true,
            "index.json" => oci_index = true,
            "manifest.json" => docker_manifest = true,
            "repositories" => docker_layers = true,
            _ if name.ends_with("/layer.tar") || name.starts_with("blobs/") => {
                docker_layers = true;
            }
            _ => {}
        }
        if pkginfo && arch_meta {
            return Inside::Tar(FileType::PkgArch);
        }
        if gem_metadata && gem_data {
            return Inside::Tar(FileType::Gem);
        }
        if (oci_layout && oci_index) || (docker_manifest && docker_layers) {
            return Inside::Tar(FileType::OciImage);
        }

        match &mut root {
            Some(r @ None) => *r = Some(top.to_owned()),
            Some(Some(r)) if r != top => root = None,
            _ => {}
        }
        if let Some(Some(r)) = &root {
            match rest {
                "package.json" if r == "package" => return Inside::Tar(FileType::Npm),
                "PKG-INFO" => return Inside::Tar(FileType::PythonSdist),
                "Cargo.toml.orig" => return Inside::Tar(FileType::Crate),
                _ => {}
            }
        }
        // A single-root package may name itself last; the byte budget on
        // `reader` bounds that walk. Anything else is settled early.
        let cap = if deep {
            TAR_DEEP_MEMBERS
        } else if root.is_some() {
            usize::MAX
        } else {
            TAR_SHALLOW_MEMBERS
        };
        if members >= cap {
            break;
        }
    }
    if members > 0 {
        Inside::Tar(FileType::Tar)
    } else {
        Inside::NotTar
    }
}

/// Settle a file compressed with `compression`: the package its layout
/// names, else the package its name names on the same container, else the
/// generic tar. `None` when it is no tar at all. When the content could not be
/// read, only a name can say a tar is inside.
fn classify_tar(sniff: &Sniff<'_>, compression: Compression, inside: Inside) -> Option<FileType> {
    let (path, data) = (sniff.path, sniff.data);
    let layout = match inside {
        Inside::NotTar => return None,
        Inside::Unreadable => None,
        Inside::Tar(ft) => Some(ft),
    };
    let fits = |ft: FileType| {
        container_of(ft, data)
            .is_some_and(|c| c.archive == ArchiveFormat::Tar && c.compression == compression)
    };
    if let Some(ft) = layout.filter(|&ft| ft != FileType::Tar && fits(ft)) {
        return Some(ft);
    }
    // `.apk` names Android's zip or Alpine's gzip tar; the container decides.
    let claim = if path_ends_with_ci(path, b".apk") {
        Some(FileType::ApkAlpine)
    } else {
        sniff.ext_type()
    };
    if let Some(ft) = claim.filter(|&ft| fits(ft)) {
        return Some(ft);
    }
    layout.map(|_| match compression {
        Compression::Gzip => FileType::TarGz,
        Compression::Bzip2 => FileType::TarBz2,
        Compression::Xz => FileType::TarXz,
        Compression::Zstd => FileType::TarZst,
        _ => FileType::Tar,
    })
}

fn looks_like_github_actions_workflow(path: &Path, data: &[u8]) -> bool {
    if !(path_ends_with_ci(path, b".yml") || path_ends_with_ci(path, b".yaml")) {
        return false;
    }

    let Ok(text) = std::str::from_utf8(data.get(..16 * 1024).unwrap_or(data)) else {
        return false;
    };

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
            return true;
        }
    }

    false
}

/// The entry names along a zip's local-header chain, in order.
///
/// A plain `memmem` for a member name answers a different question: whether
/// the bytes appear anywhere. They do whenever a zip stores an Office document
/// uncompressed, because the inner package's own header is then present
/// verbatim in the outer file -- which is how a zip holding one `.docx` came
/// to be identified as a `.docx`, and its members never walked.
///
/// So step from header to header by each entry's declared compressed size.
/// When the iterator ends, `complete` says whether it reached a real end of
/// chain (or the entry cap). A walk that lost the thread -- a streaming entry
/// with no size to step by, a header whose sizes are nonsense -- proves
/// nothing absent, and callers fall back to a looser test rather than
/// reporting a confident "no".
struct ZipNames<'a> {
    data: &'a [u8],
    /// The next local header, or `None` once the walk has stopped.
    off: Option<usize>,
    left: usize,
    complete: bool,
}

impl<'a> ZipNames<'a> {
    /// Entries to walk. A package names its content types first, but a
    /// marker such as an APK's `AndroidManifest.xml` sits wherever the
    /// packager put it: entry 905 in one 21 MB sample here. Each step is a
    /// bounds check and a few integer reads, so the ceiling is set by what a
    /// real archive holds rather than by what the walk costs.
    const MAX_ENTRIES: usize = 8192;

    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            off: Some(0),
            left: Self::MAX_ENTRIES,
            complete: false,
        }
    }
}

impl<'a> Iterator for ZipNames<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let data = self.data;
        let off = self.off.take()?;
        if self.left == 0 {
            self.complete = true;
            return None;
        }
        self.left -= 1;
        let u16_at = |at| bytes::u16_le(data, at).map(usize::from);
        let u32_at = |at| bytes::u32_le(data, at).map(|v| v as usize);
        let sig = data.get(off..off + 4)?;
        if sig != b"PK\x03\x04" {
            // Only a real end-of-chain marker completes the walk. Anything else
            // means it lost the thread: the malformed packages this corpus is
            // full of are still Office documents, and saying otherwise routes
            // them to a reader that rejects them outright.
            self.complete = matches!(
                sig,
                b"PK\x01\x02" | b"PK\x05\x06" | b"PK\x06\x06" | b"PK\x06\x07"
            );
            return None;
        }
        let flags = u16_at(off + 6)?;
        let compressed = u32_at(off + 18)?;
        let name_len = u16_at(off + 26)?;
        let extra_len = u16_at(off + 28)?;
        let name = data.get(off + 30..off + 30 + name_len)?;
        // Bit 3: the sizes are repeated in a trailing data descriptor. When
        // the local header carries them too they can still be stepped by;
        // when it does not, there is nothing to step by and the walk stops.
        self.off = (flags & 0x08 == 0 || compressed != 0)
            .then(|| off.checked_add(30 + name_len + extra_len + compressed))
            .flatten()
            .filter(|&next| next <= data.len())
            .and_then(|next| {
                if flags & 0x08 == 0 || data.get(next..next + 4) != Some(b"PK\x07\x08") {
                    return Some(next);
                }
                // Signature + crc + two sizes, four bytes each, or eight each
                // in zip64. Which one is in use is not declared here, so take
                // the length that lands on something a chain continues with.
                [16usize, 24]
                    .into_iter()
                    .map(|skip| next + skip)
                    .find(|&at| {
                        matches!(
                            data.get(at..at + 4),
                            Some(b"PK\x03\x04" | b"PK\x01\x02" | b"PK\x05\x06")
                        )
                    })
            });
        Some(name)
    }
}

/// Whether `name` is an entry of this zip; `None` when the walk could not
/// finish without finding it.
#[cfg(test)]
fn zip_has_top_level_entry(data: &[u8], name: &[u8]) -> Option<bool> {
    let mut names = ZipNames::new(data);
    if names.any(|n| n == name) {
        return Some(true);
    }
    names.complete.then_some(false)
}

/// The members that name a zip-based package, gathered in one walk.
#[derive(Default)]
struct ZipMarks {
    android: bool,
    content_types: bool,
    mimetype: bool,
    vsix: bool,
    appx: bool,
    nuspec: bool,
    jar: bool,
    wheel: bool,
    egg: bool,
    ipa: bool,
    conda_metadata: bool,
    conda_info: bool,
    xpi: bool,
    complete: bool,
}

impl ZipMarks {
    fn scan(data: &[u8]) -> Self {
        let mut m = Self::default();
        let mut names = ZipNames::new(data);
        for name in names.by_ref() {
            let top_level = !name.contains(&b'/');
            match name {
                b"AndroidManifest.xml" => m.android = true,
                b"[Content_Types].xml" => m.content_types = true,
                b"mimetype" => m.mimetype = true,
                b"extension.vsixmanifest" => m.vsix = true,
                b"AppxManifest.xml" | b"AppxMetadata/AppxBundleManifest.xml" => m.appx = true,
                b"META-INF/MANIFEST.MF" => m.jar = true,
                b"EGG-INFO/PKG-INFO" => m.egg = true,
                b"metadata.json" => m.conda_metadata = true,
                b"install.rdf" | b"META-INF/mozilla.rsa" => m.xpi = true,
                _ if top_level && name.ends_with(b".nuspec") => m.nuspec = true,
                _ if top_level && name.starts_with(b"info-") && name.ends_with(b".tar.zst") => {
                    m.conda_info = true;
                }
                _ if name
                    .strip_suffix(b".dist-info/WHEEL")
                    .is_some_and(|dir| !dir.is_empty() && !dir.contains(&b'/')) =>
                {
                    m.wheel = true;
                }
                _ if name.starts_with(b"Payload/")
                    && memchr::memmem::find(name, b".app/").is_some() =>
                {
                    m.ipa = true;
                }
                _ => {}
            }
        }
        m.complete = names.complete;
        m
    }
}

/// Names that claim an archive, not a document: a zip so named holding an
/// OPC `[Content_Types].xml` stays the archive it says it is.
const ARCHIVE_EXTS: &[&str] = &[
    "zip",
    "jar",
    "war",
    "ear",
    "vsix",
    "nupkg",
    "xpi",
    "whl",
    "epub",
    "apk",
    "ipa",
    "aar",
    "egg",
    "phar",
    "pyz",
    "conda",
    "msix",
    "appx",
    "msixbundle",
    "appxbundle",
    "aab",
    "apks",
    "xapk",
    "cbz",
];

/// The zip-based package a name claims, trusted when no member contradicts
/// it. Office names are absent on purpose: an office extension is a claim,
/// not the format, and without the OPC marker the file is a zip.
fn zip_name_claim(ext: &str) -> Option<FileType> {
    Some(match ext {
        "jar" | "war" | "ear" => FileType::Jar,
        "xpi" => FileType::Xpi,
        "whl" => FileType::Whl,
        "apk" => FileType::ApkAndroid,
        "conda" => FileType::Conda,
        "egg" => FileType::Egg,
        "nupkg" => FileType::Nupkg,
        "ipa" => FileType::Ipa,
        "vsix" => FileType::Vsix,
        ext if is_odf_extension(ext) => FileType::Odf,
        _ => return None,
    })
}

/// Classify a zip by the members only one kind of package carries; the name
/// settles only what the members leave open.
///
/// That order decides whether anything looks inside. A file typed Ooxml goes
/// to the office analyzer, which reads OPC parts; a file typed Zip goes to the
/// archive analyzer, which walks the members. Three samples here are zips
/// holding one payload apiece -- a `documents.doc` under an `.xlsm` name, a
/// `.pdf.url` shortcut beside a decoy docx -- and none of those members were
/// analyzed while the name was believed. And an APK, JAR or NuGet package
/// delivered without its extension reached none of its own analysis.
fn classify_pk(path: &Path, data: &[u8]) -> (FileType, DetectionSource) {
    let ext = lowercase_ext(path);
    let ext = ext.as_deref().unwrap_or("");
    let m = ZipMarks::scan(data);
    // Where the walk lost the thread, a marker's bytes anywhere are the best
    // evidence left.
    let loose = |marker: &[u8]| !m.complete && memchr::memmem::find(data, marker).is_some();
    let opc = m.content_types || loose(b"[Content_Types].xml");
    // An OpenDocument file stores `mimetype` first; an Android package can
    // carry the namespace URI in any of its resources and is not one.
    let odf =
        m.mimetype && memchr::memmem::find(data, b"application/vnd.oasis.opendocument.").is_some();

    let ft = if m.android {
        FileType::ApkAndroid
    } else if m.vsix || loose(b"extension.vsixmanifest") {
        // VSIX and NuGet are OPC zips too; their manifests win.
        FileType::Vsix
    } else if m.appx || loose(b"AppxManifest.xml") || loose(b"AppxMetadata/AppxBundleManifest.xml")
    {
        // So are MSIX/APPX packages, which carry whole application trees
        // (a bundled Python runtime, helper executables) that only the archive
        // analyzer walks. The manifest is usually written last, past the
        // entry cap on a large package, hence the loose fallback.
        FileType::Zip
    } else if opc && m.nuspec {
        FileType::Nupkg
    } else if opc && !ARCHIVE_EXTS.contains(&ext) {
        FileType::Ooxml
    } else if odf {
        FileType::Odf
    } else if let Some(claimed) = zip_name_claim(ext) {
        claimed
    } else if m.ipa {
        FileType::Ipa
    } else if m.wheel {
        FileType::Whl
    } else if m.egg {
        FileType::Egg
    } else if m.conda_metadata && m.conda_info {
        FileType::Conda
    } else if m.xpi {
        FileType::Xpi
    } else if m.jar {
        FileType::Jar
    } else {
        FileType::Zip
    };
    (ft, DetectionSource::Magic)
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

/// [`script_host_document`] of `data` alone.
#[cfg(test)]
fn windows_script_host(data: &[u8]) -> Option<FileType> {
    script_host_document(&Sniff::new(Path::new(""), data))
}

/// How far into a Windows Script Host document the `<script>` element is
/// looked for. Droppers pad the opening tags with whitespace.
const WSH_SCRIPT_WINDOW: usize = 64 * 1024;

/// A `.wsf` / `.wsc` / `.sct` document, typed by the language of its first
/// `<script>`: VBScript or JScript. The root element decides it is one --
/// `<job>`, `<package>`, `<component>` or `<scriptlet>`; an HTML page with a
/// VBScript block stays HTML.
fn script_host_document(sniff: &Sniff<'_>) -> Option<FileType> {
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
fn attribute_value<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
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
fn decode_char_refs(value: &[u8]) -> String {
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
fn encoded_script(path: &Path, head: &[u8]) -> Option<FileType> {
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
fn detect_xml(data: &[u8]) -> Option<(FileType, DetectionSource)> {
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

/// Detect tampered PE: MZ within first 64 bytes with valid PE\0\0 signature.
fn detect_tampered_pe(data: &[u8]) -> Option<FileType> {
    let window = data.get(..64).unwrap_or(data);
    window
        .windows(2)
        .enumerate()
        // Offset 0 was already checked by the MZ arm.
        .skip(1)
        .filter(|&(_, pair)| pair == b"MZ")
        .any(|(i, _)| {
            data.get(i..).is_some_and(|pe| {
                bytes::u32_le(pe, 0x3C)
                    .and_then(|e_lfanew| pe.get(e_lfanew as usize..))
                    .is_some_and(|nt| nt.starts_with(b"PE\0\0"))
            })
        })
        .then_some(FileType::Pe)
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

/// Detect manifest file types that require content inspection.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "`name` is lowercased before matching"
)]
fn detect_manifest(path: &Path, data: &[u8]) -> Option<FileType> {
    let file_name = path.file_name()?.to_str()?;

    // Stack-allocated lowercase (manifest names are short). A longer name is
    // cut to the buffer.
    let mut buf = [0u8; 32];
    let file_name = file_name.as_bytes();
    let file_name = file_name.get(..buf.len()).unwrap_or(file_name);
    let lower = buf.get_mut(..file_name.len())?;
    lower.copy_from_slice(file_name);
    lower.make_ascii_lowercase();
    let name = std::str::from_utf8(lower).unwrap_or("");

    match name {
        "package.json" => Some(FileType::PackageJson),
        "package-lock.json" => Some(FileType::PackageLockJson),
        "go.mod" => Some(FileType::GoMod),
        "go.sum" => Some(FileType::GoSum),
        "requirements.txt" => Some(FileType::RequirementsTxt),
        "poetry.lock" => Some(FileType::PoetryLock),
        "pipfile.lock" => Some(FileType::PipfileLock),
        "gemfile.lock" => Some(FileType::GemfileLock),
        "composer.lock" => Some(FileType::ComposerLock),
        "yarn.lock" => Some(FileType::YarnLock),
        "pnpm-lock.yaml" => Some(FileType::PnpmLock),
        "manifest.json" => {
            // Chrome extension: manifest_version + at least one Chrome-specific key
            if memchr::memmem::find(data, b"\"manifest_version\"").is_some()
                && (memchr::memmem::find(data, b"\"permissions\"").is_some()
                    || memchr::memmem::find(data, b"\"content_scripts\"").is_some()
                    || memchr::memmem::find(data, b"\"background\"").is_some()
                    || memchr::memmem::find(data, b"\"host_permissions\"").is_some())
            {
                Some(FileType::ChromeManifest)
            } else {
                None
            }
        }
        "extension.vsixmanifest" => Some(FileType::VsixManifest),
        ".pkginfo" | ".buildinfo" | ".mtree" => Some(FileType::Text),
        "pkg-info" | "metadata" => Some(FileType::PkgInfo),
        "action.yml" | "action.yaml" => Some(FileType::GithubActions),
        _ => {
            if name.ends_with(".vsixmanifest") {
                Some(FileType::VsixManifest)
            } else if name.starts_with("yarn.") && name.ends_with(".lock") {
                Some(FileType::YarnLock)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod odf_confirmation_tests {
    use super::*;

    /// A ZIP whose local-header walk cannot complete, carrying the
    /// OpenDocument namespace URI somewhere in its body -- the shape of the
    /// 88MB .xapk that was typed OpenDocument.
    fn unwalkable_zip_mentioning_odf() -> Vec<u8> {
        let mut d = b"PK\x03\x04".to_vec();
        // A local header with a nonsense name length, so the walk loses the
        // thread and reports `None` rather than a confident "no".
        d.extend_from_slice(&[0xFF; 26]);
        d.extend_from_slice(b"application/vnd.oasis.opendocument.text");
        d.resize(4096, 0x41);
        d
    }

    #[test]
    fn indeterminate_walk_is_not_opendocument() {
        let d = unwalkable_zip_mentioning_odf();
        assert_ne!(classify_pk(Path::new("x.xapk"), &d).0, FileType::Odf);
    }

    #[test]
    fn odf_extension_still_wins() {
        let d = unwalkable_zip_mentioning_odf();
        assert_eq!(classify_pk(Path::new("x.odt"), &d).0, FileType::Odf);
    }
}

#[cfg(test)]
mod jet_db_sfnt_collision_tests {
    use super::*;

    /// A real TrueType font still identifies as a font.
    #[test]
    fn sfnt_version_one_is_still_a_font() {
        let mut data = vec![0x00, 0x01, 0x00, 0x00];
        data.extend_from_slice(&[0x00, 0x0a, 0x00, 0x80, 0x00, 0x03, 0x00, 0x20]);
        data.extend_from_slice(b"cmap");
        assert_eq!(
            detect_from_content(Path::new("x.ttf"), &data).map(|(ft, _)| ft),
            Some(FileType::Font)
        );
    }

    /// An Access database opens with the same four bytes and must not be
    /// handed to the font parser.
    #[test]
    fn jet_db_header_is_not_a_font() {
        let mut data = vec![0x00, 0x01, 0x00, 0x00];
        data.extend_from_slice(b"Standard Jet DB\x00");
        data.extend_from_slice(&[0u8; 32]);
        assert_ne!(
            detect_from_content(Path::new("db.mdb"), &data).map(|(ft, _)| ft),
            Some(FileType::Font)
        );
    }

    /// The newer ACE engine names itself the same way.
    #[test]
    fn ace_db_header_is_not_a_font() {
        let mut data = vec![0x00, 0x01, 0x00, 0x00];
        data.extend_from_slice(b"Standard ACE DB\x00");
        data.extend_from_slice(&[0u8; 32]);
        assert_ne!(
            detect_from_content(Path::new("db.accdb"), &data).map(|(ft, _)| ft),
            Some(FileType::Font)
        );
    }
}

#[cfg(test)]
mod html_doctype_magic_tests {
    use super::*;
    use crate::FileId;

    #[test]
    fn utf8_bom_html_is_detected_under_misleading_names() {
        for body in [
            "<!DOCTYPE html><html><body>page</body></html>",
            "  <HTML><body><script>document.write('x')</script></body></HTML>",
            "<script src='https://example.invalid/a.js'></script>\n<!doctype html><html>",
        ] {
            let mut data = UTF8_BOM.to_vec();
            data.extend_from_slice(body.as_bytes());
            let file = FileId::from_path_and_bytes(Path::new("sample.vir"), &data);
            assert_eq!(file.file_type(), FileType::Html, "{body}");
        }
    }

    /// A page under a name that claims another language is still a page.
    #[test]
    fn doctype_html_is_detected_by_content() {
        let data =
            b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n<HTML></HTML>";
        assert_eq!(
            detect_from_content(Path::new("Trojan.JS.DeltreeY.c"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }

    /// The doctype keyword is case-insensitive in HTML and in the wild.
    #[test]
    fn lowercase_doctype_html_is_detected() {
        let data = b"<!doctype html>\n<html><body>x</body></html>";
        assert_eq!(
            detect_from_content(Path::new("x"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }

    /// The SVG arm compares the root name, so it keeps its own doctype.
    #[test]
    fn doctype_svg_is_not_html() {
        let data = b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\">\n<svg xmlns=\"x\"/>";
        assert_ne!(
            detect_from_content(Path::new("x.svg"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }

    /// Real pages are not flush left. Four VirusShare samples open with four
    /// spaces before the doctype and were scored as JavaScript for the jQuery
    /// inside them.
    #[test]
    fn indented_doctype_is_still_html() {
        let data = b"    <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\">\n<html>";
        assert_eq!(
            detect_from_content(Path::new("VirusShare_4bcf5cc475"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }

    /// A file whose first bytes are `<html` is a page, doctype or not.
    #[test]
    fn bare_html_root_is_html() {
        let data = b"<html data-adblockkey=\"MFwwDQYJ\"><head><title>Redirecting</title>";
        assert_eq!(
            detect_from_content(Path::new("VirusShare_f54b1d8fed"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }

    /// The root-element check stops at a word boundary, so an XML document
    /// whose root merely begins with those letters is untouched.
    #[test]
    fn htmlspecialchars_root_is_not_html() {
        let data = b"<htmlspecialchars>not a page</htmlspecialchars>";
        assert_ne!(
            detect_from_content(Path::new("x.xml"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }

    /// A short injected loader before a complete document must not hide the
    /// page from content-based type detection under an extensionless name.
    #[test]
    fn doctype_html_after_leading_script_is_detected_by_content() {
        let data = b"<script src='https://example.invalid/stat.js'></script>\n<!DOCTYPE html>\n<html><head><title>x</title></head><body>x</body></html>";
        let extensionless = FileId::from_path_and_bytes(Path::new("VirusShare_0123456789"), data);
        assert_eq!(extensionless.file_type(), FileType::Html);
        assert_eq!(extensionless.source(), DetectionSource::Magic);
        assert!(!extensionless.extension_mismatch());

        let misleading_name = FileId::from_path_and_bytes(Path::new("page.js"), data);
        assert_eq!(misleading_name.file_type(), FileType::Html);
        assert_eq!(misleading_name.source(), DetectionSource::Magic);
        assert!(misleading_name.extension_mismatch());
    }

    /// A script with an HTML doctype in its source string but no HTML root is
    /// still a script, rather than an HTML document.
    #[test]
    fn doctype_string_without_html_root_is_not_a_document() {
        let data = b"const x = '<!DOCTYPE html>'; eval(x);";
        assert_ne!(
            detect_from_content(Path::new("x"), data).map(|(ft, _)| ft),
            Some(FileType::Html)
        );
    }
}

#[cfg(test)]
mod registry_script_magic_tests {
    use super::*;

    /// The Windows 9x/NT4 header, under a name that claims another type.
    #[test]
    fn regedit4_header_is_a_registry_script() {
        let data = b"REGEDIT4\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Foo]\r\n\"Bar\"=\"baz\"\r\n";
        assert_eq!(
            detect_from_content(Path::new("Trojan.WinREG.AntiFireWall.a"), data).map(|(ft, _)| ft),
            Some(FileType::Reg)
        );
    }

    /// The Windows 2000+ header.
    #[test]
    fn modern_registry_header_is_a_registry_script() {
        let data = b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\X]\r\n";
        assert_eq!(
            detect_from_content(Path::new("x"), data).map(|(ft, _)| ft),
            Some(FileType::Reg)
        );
    }

    /// Prose that merely begins with the same word is not a registry script.
    #[test]
    fn unrelated_w_text_is_not_a_registry_script() {
        let data = b"Windows compatibility notes\n\nThis document describes...\n";
        assert_ne!(
            detect_from_content(Path::new("notes.txt"), data).map(|(ft, _)| ft),
            Some(FileType::Reg)
        );
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend(
            "Windows compatibility notes\r\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        assert_ne!(
            detect_from_content(Path::new("notes.txt"), &utf16).map(|(ft, _)| ft),
            Some(FileType::Reg)
        );
    }

    /// What regedit writes: UTF-16LE behind a byte-order mark. A copy
    /// re-saved as UTF-8 may keep a mark of its own.
    #[test]
    fn bom_prefixed_registry_exports_are_registry_scripts() {
        let header = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\X]\r\n";
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend(header.encode_utf16().flat_map(u16::to_le_bytes));
        let mut utf8 = UTF8_BOM.to_vec();
        utf8.extend_from_slice(header.as_bytes());
        for data in [utf16, utf8] {
            assert_eq!(
                detect_from_content(Path::new("export.reg"), &data),
                Some((FileType::Reg, DetectionSource::Magic))
            );
            assert_eq!(
                super::super::detect(Path::new("export.reg"), &data).map(|d| d.file_type),
                Some(FileType::Reg)
            );
        }
    }

    /// Every header spelling under its own `.reg` name is consistent with
    /// the extension. Before `.reg` was in the extension table, each one
    /// reported a mismatch against an unknown extension.
    #[test]
    fn reg_extension_agrees_with_every_header_spelling() {
        let body = "\r\n\r\n[HKEY_CURRENT_USER\\X]\r\n\"A\"=dword:00000001\r\n";
        let modern = format!("Windows Registry Editor Version 5.00{body}");
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend(modern.encode_utf16().flat_map(u16::to_le_bytes));
        let mut utf8_bom = UTF8_BOM.to_vec();
        utf8_bom.extend_from_slice(modern.as_bytes());
        let regedit4 = format!("REGEDIT4{body}").into_bytes();
        for data in [utf16, utf8_bom, modern.into_bytes(), regedit4] {
            let det = super::super::detect(Path::new("Export.REG"), &data).unwrap();
            assert_eq!(det.file_type, FileType::Reg);
            assert_eq!(det.source, DetectionSource::Magic);
            assert!(!det.extension_mismatch());
            let id = crate::FileId::from_path_and_bytes(Path::new("export.reg"), &data);
            assert_eq!(id.file_type().label(), "reg");
            assert!(!id.extension_mismatch());
        }
    }

    /// The header defines the format, so a `.reg` name on anything else is
    /// a mismatch, and the body is typed by its content.
    #[test]
    fn reg_extension_without_a_header_is_a_mismatch() {
        let prose = b"These notes describe how the settings were changed last week.\n";
        let det = super::super::detect(Path::new("notes.reg"), prose).unwrap();
        assert_eq!(det.file_type, FileType::Text);
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Reg));
        // An empty file has nothing to contradict its name.
        let empty = super::super::detect(Path::new("empty.reg"), b"").unwrap();
        assert_eq!(empty.file_type, FileType::Reg);
        assert!(!empty.extension_mismatch());
    }

    /// Package-registry metadata keeps `registry`; it shares nothing with a
    /// registry export but the word.
    #[test]
    fn package_registry_metadata_is_not_a_registry_export() {
        let doc = br#"{"ecosystem":"npm","name":"left-pad","version":"1.3.0"}"#;
        let det = super::super::detect(Path::new("left-pad@1.3.0.registry.json"), doc).unwrap();
        assert_eq!(det.file_type, FileType::Registry);
        assert_eq!(det.file_type.label(), "registry");
        assert_eq!(FileType::from_label("reg"), Some(FileType::Reg));
        assert!(FileType::Registry.is_structured_data());
        assert!(!FileType::Reg.is_structured_data());
    }
}

#[cfg(test)]
mod windows_script_host_tests {
    use super::*;

    #[test]
    fn character_references_resolve() {
        assert_eq!(decode_char_refs(b"&#86;&#66;&#x53;cript"), "VBScript");
        // A malformed reference is left as it is.
        assert_eq!(decode_char_refs(b"&#zz;x"), "&#zz;x");
    }

    #[test]
    fn attribute_values() {
        assert_eq!(
            attribute_value(b" language='JScript' src=x", b"language"),
            Some(&b"JScript"[..])
        );
        assert_eq!(
            attribute_value(b"\r\nlanguage = \"VBScript\"", b"language"),
            Some(&b"VBScript"[..])
        );
        assert_eq!(
            attribute_value(b" language=VBS/", b"language"),
            Some(&b"VBS"[..])
        );
        // `xlanguage` is a different attribute.
        assert_eq!(
            attribute_value(b" xlanguage=\"VBScript\"", b"language"),
            None
        );
    }

    #[test]
    fn script_host_roots_only() {
        let job = b"<component>\n<script language=\"VBScript\">x = 1</script>\n</component>\n";
        assert_eq!(windows_script_host(job), Some(FileType::Vbs));
        // No language, or one the host does not run: not claimed.
        assert_eq!(
            windows_script_host(b"<job><script>x = 1</script></job>"),
            None
        );
        assert_eq!(
            windows_script_host(b"<job><script language=\"PerlScript\">1;</script></job>"),
            None
        );
        // Other XML is left to the XML arm.
        assert_eq!(
            windows_script_host(
                b"<?xml version=\"1.0\"?><rss><script language=\"VBScript\"/></rss>"
            ),
            None
        );
    }

    #[test]
    fn dib_header_versions() {
        let header = |size: u32, planes: u16, bits: u16| {
            let mut h = size.to_le_bytes().to_vec();
            h.resize(40, 0);
            let at = if size == 12 { 8 } else { 12 };
            h[at..at + 2].copy_from_slice(&planes.to_le_bytes());
            h[at + 2..at + 4].copy_from_slice(&bits.to_le_bytes());
            h
        };
        for size in [12, 16, 40, 52, 56, 64, 108, 124] {
            assert!(looks_like_dib_header(&header(size, 1, 8)), "size {size}");
        }
        assert!(!looks_like_dib_header(&header(41, 1, 8)));
        assert!(!looks_like_dib_header(&header(40, 0, 8)));
        assert!(!looks_like_dib_header(&header(40, 1, 3)));
        assert!(!looks_like_dib_header(&[40, 0, 0]));
    }
}
