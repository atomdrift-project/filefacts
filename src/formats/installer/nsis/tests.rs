#![allow(clippy::unwrap_used)]
use super::*;
use std::io::Write as _;

/// A string table under construction, in ANSI or UTF-16LE units.
struct Table {
    units: Vec<u16>,
    unicode: bool,
    codes: Codes,
}

impl Table {
    fn new(unicode: bool, codes: Codes) -> Self {
        // Offset 0 is the empty string.
        Self {
            units: vec![0],
            unicode,
            codes,
        }
    }

    /// Append a string; `$INSTDIR` and `$TEMP` become variable codes.
    fn add(&mut self, text: &str) -> i32 {
        let at = i32::try_from(self.units.len()).unwrap();
        let mut rest = text;
        while !rest.is_empty() {
            if let Some((name, index)) = [("$INSTDIR", 21u16), ("$TEMP", 25)]
                .into_iter()
                .find(|(name, _)| rest.starts_with(name))
            {
                self.units.push(self.codes.var);
                if self.unicode {
                    self.units.push(0x8000 | index);
                } else {
                    self.units.push(0x80 | (index & 0x7f));
                    self.units.push(0x80 | (index >> 7));
                }
                rest = &rest[name.len()..];
            } else {
                let c = rest.chars().next().unwrap();
                self.units.push(u16::try_from(u32::from(c)).unwrap());
                rest = &rest[c.len_utf8()..];
            }
        }
        self.units.push(0);
        at
    }

    fn bytes(&self) -> Vec<u8> {
        if self.unicode {
            self.units.iter().flat_map(|u| u.to_le_bytes()).collect()
        } else {
            self.units
                .iter()
                .map(|&u| u8::try_from(u).unwrap())
                .collect()
        }
    }
}

/// A decompressed NSIS header: flags, the eight blocks, the entries, the
/// string table and a language table after it.
fn header(entries: &[[i32; 7]], table: &Table) -> Vec<u8> {
    let entries_at = 4 + 8 * 8;
    let strings_at = entries_at + entries.len() * ENTRY_LEN;
    let strings = table.bytes();
    let langtables_at = strings_at + strings.len();
    let mut blocks = [(0u32, 0u32); 8];
    blocks[BLOCK_ENTRIES] = (
        u32::try_from(entries_at).unwrap(),
        u32::try_from(entries.len()).unwrap(),
    );
    blocks[BLOCK_STRINGS] = (u32::try_from(strings_at).unwrap(), 0);
    blocks[BLOCK_LANGTABLES] = (u32::try_from(langtables_at).unwrap(), 1);
    let mut out = 0u32.to_le_bytes().to_vec();
    for (offset, count) in blocks {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
    }
    for entry in entries {
        for field in entry {
            out.extend_from_slice(&field.to_le_bytes());
        }
    }
    out.extend_from_slice(&strings);
    out.extend_from_slice(&[0x09, 0x04, 0, 0]);
    out
}

/// Raw LZMA as NSIS stores it: the properties byte, the dictionary size,
/// then the stream.
fn lzma(data: &[u8]) -> Vec<u8> {
    let options = lzma_rust2::LzmaOptions::with_preset(6);
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &options, true).unwrap();
    let props = writer.props();
    writer.write_all(data).unwrap();
    let stream = writer.finish().unwrap();
    let mut raw = vec![props];
    raw.extend_from_slice(&options.dict_size.to_le_bytes());
    raw.extend_from_slice(&stream);
    raw
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// An installer: a 512-byte stub, the first header, then `body`.
fn installer(header_len: usize, body: &[u8]) -> Vec<u8> {
    let mut out = b"MZ".to_vec();
    out.resize(FIRST_HEADER_ALIGN, 0);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(FIRST_HEADER_MAGIC);
    out.extend_from_slice(&u32::try_from(header_len).unwrap().to_le_bytes());
    let total = u32::try_from(body.len() + FIRST_HEADER_LEN).unwrap();
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Non-solid: the header as its own compressed block.
fn non_solid(header: &[u8], compressed: &[u8]) -> Vec<u8> {
    let mut body = (u32::try_from(compressed.len()).unwrap() | 0x8000_0000)
        .to_le_bytes()
        .to_vec();
    body.extend_from_slice(compressed);
    body.extend_from_slice(b"file data follows");
    installer(header.len(), &body)
}

/// Solid: the header's length, the header and the files in one stream.
fn solid_stream(header: &[u8]) -> Vec<u8> {
    let mut stream = u32::try_from(header.len()).unwrap().to_le_bytes().to_vec();
    stream.extend_from_slice(header);
    stream.extend_from_slice(&[0x41; 3000]);
    stream
}

const RUNDLL: &str = r#""c:\windows\system32\rundll32.exe" "$INSTDIR\TmProvider.dll",RunDllEntry"#;
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// A trojanized installer's script, rebuilt: extract two files, hide them,
/// run the DLL through rundll32; plus a Run key, a shortcut and an opcode
/// this decoder does not name.
fn trojan_script(unicode: bool, codes: Codes) -> Vec<u8> {
    let mut t = Table::new(unicode, codes);
    let instdir = t.add("$INSTDIR");
    let temp = t.add("$TEMP");
    let setup = t.add("egrabitsetup.exe");
    let dll = t.add("TmProvider.dll");
    let rundll = t.add(RUNDLL);
    let run_setup = t.add(r#""$INSTDIR\egrabitsetup.exe""#);
    let run_key = t.add(RUN_KEY);
    let value = t.add("TmProvider");
    let link = t.add(r"$TEMP\Provider.lnk");
    let hkcu = 0x8000_0001_u32.cast_signed();
    let entries = [
        [11, instdir, 1, 0, 0, 0, 0],
        [20, 0x0500_0090, setup, 0, 0, 0, 0],
        [20, 0x0500_0090, dll, 2_349_089, 0, 0, 0],
        [10, setup, 2, 0, 0, 0, 0],
        [10, dll, 2, 0, 0, 0, 0],
        [41, rundll, 0, 0, 0, 0, 0],
        [41, run_setup, 0, 1, 0, 0, 0],
        [51, hkcu, run_key, value, rundll, 1, 1],
        [45, link, rundll, 0, 0, 0, 0],
        [25, 3, temp, 0, 0, 0, 0],
        [200, setup, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0],
    ];
    header(&entries, &t)
}

fn trojan_lines() -> Vec<String> {
    let rundll = format!("'{RUNDLL}'");
    vec![
        "SetOutPath $INSTDIR".to_string(),
        "File egrabitsetup.exe".to_string(),
        "File TmProvider.dll".to_string(),
        "SetFileAttributes egrabitsetup.exe HIDDEN".to_string(),
        "SetFileAttributes TmProvider.dll HIDDEN".to_string(),
        format!("Exec {rundll}"),
        r#"ExecWait '"$INSTDIR\egrabitsetup.exe"'"#.to_string(),
        format!("WriteRegStr HKCU {RUN_KEY} TmProvider {rundll}"),
        format!(r#"CreateShortCut $TEMP\Provider.lnk {rundll} "" """#),
        r#"StrCpy $3 $TEMP "" """#.to_string(),
        "; opcode 200 egrabitsetup.exe".to_string(),
        "Return".to_string(),
    ]
}

fn assert_trojan_script(decoded: &Script) {
    let rendered = decoded.render();
    let lines: Vec<&str> = rendered.lines().skip(2).collect();
    assert_eq!(lines, trojan_lines(), "{rendered}");
}

#[test]
fn decodes_non_solid_lzma_nsis2_ansi() {
    let header = trojan_script(false, CODES_V2);
    let decoded = script(&non_solid(&header, &lzma(&header))).unwrap();
    assert!(!decoded.unicode);
    assert_eq!(decoded.declared, 12);
    assert_trojan_script(&decoded);
}

#[test]
fn decodes_solid_lzma_and_both_deflate_layouts() {
    let header = trojan_script(false, CODES_V2);
    let solid_lzma = installer(header.len(), &lzma(&solid_stream(&header)));
    assert_trojan_script(&script(&solid_lzma).unwrap());
    let solid_deflate = installer(header.len(), &deflate(&solid_stream(&header)));
    assert_trojan_script(&script(&solid_deflate).unwrap());
    assert_trojan_script(&script(&non_solid(&header, &deflate(&header))).unwrap());
}

#[test]
fn decodes_branch_filter_flag_when_clear() {
    let header = trojan_script(false, CODES_V2);
    let mut flagged = vec![0u8];
    flagged.extend_from_slice(&lzma(&header));
    assert_trojan_script(&script(&non_solid(&header, &flagged)).unwrap());
    // A set flag means the x86 filter ran; it is not decoded.
    flagged[0] = 1;
    assert!(script(&non_solid(&header, &flagged)).is_err());
}

#[test]
fn decodes_stored_header_block() {
    let header = trojan_script(false, CODES_V2);
    let mut body = u32::try_from(header.len()).unwrap().to_le_bytes().to_vec();
    body.extend_from_slice(&header);
    assert_trojan_script(&script(&installer(header.len(), &body)).unwrap());
}

#[test]
fn decodes_nsis3_ansi_and_unicode_strings() {
    let header = trojan_script(false, CODES_V3);
    assert_trojan_script(&script(&non_solid(&header, &lzma(&header))).unwrap());
    let header = trojan_script(true, CODES_UNICODE);
    let decoded = script(&non_solid(&header, &lzma(&header))).unwrap();
    assert!(decoded.unicode);
    assert!(decoded.render().contains("; 12 entries, Unicode strings"));
    assert_trojan_script(&decoded);
}

#[test]
fn renders_shell_folders_and_language_strings() {
    let mut t = Table::new(false, CODES_V2);
    let at = i32::try_from(t.units.len()).unwrap();
    t.units.extend([CODES_V2.shell, 0x1a, 0x23]);
    t.units.extend(r"\evil.exe".encode_utf16());
    t.units.push(0);
    let header = header(&[[21, at, 0, 0, 0, 0, 0], [6, -3, 0, 0, 0, 0, 0]], &t);
    let rendered = script(&non_solid(&header, &lzma(&header)))
        .unwrap()
        .render();
    assert!(rendered.contains(r"Delete $APPDATA\evil.exe"), "{rendered}");
    assert!(rendered.contains("DetailPrint $(LSTR_2)"), "{rendered}");
}

#[test]
fn malformed_installers_fail_gracefully() {
    let header = trojan_script(false, CODES_V2);
    let good = non_solid(&header, &lzma(&header));
    let with_u32 = |at: usize, value: u32| {
        let mut data = good.clone();
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        data
    };

    // No first header at all, or one cut short.
    assert!(script(b"MZ not an installer").is_err());
    assert!(script(&good[..FIRST_HEADER_ALIGN + 20]).is_err());
    // The header block cut off part-way.
    assert!(script(&good[..good.len() - 40]).is_err());
    // A header length past the limit, and one the data cannot fill.
    assert!(script(&with_u32(FIRST_HEADER_ALIGN + 20, u32::MAX)).is_err());
    let longer = u32::try_from(header.len() + 1000).unwrap();
    assert!(script(&with_u32(FIRST_HEADER_ALIGN + 20, longer)).is_err());
    // A block length far past the end of the file.
    assert!(script(&with_u32(FIRST_HEADER_ALIGN + 28, 0xffff_fff0)).is_err());
    // Corrupt compressed bytes. LZMA carries no checksum, so this may decode
    // to garbage; it must neither panic nor run past the command bound.
    let mut corrupt = good.clone();
    let start = FIRST_HEADER_ALIGN + 32 + 6;
    corrupt[start..start + 40].fill(0xa5);
    if let Ok(decoded) = script(&corrupt) {
        assert!(decoded.commands.len() <= MAX_COMMANDS);
    }
}

#[test]
fn hostile_header_tables_fail_or_stay_bounded() {
    let t = Table::new(false, CODES_V2);
    // An entry table claiming far more entries than the header holds.
    let mut lying = header(&[[1, 0, 0, 0, 0, 0, 0]], &t);
    let at = 4 + 8 * BLOCK_ENTRIES + 4;
    lying[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(script(&non_solid(&lying, &lzma(&lying))).is_err());
    // A string table offset past the header.
    let mut strings = header(&[[6, 1, 0, 0, 0, 0, 0]], &t);
    let at = 4 + 8 * BLOCK_STRINGS;
    strings[at..at + 4].copy_from_slice(&0x00ff_ffff_u32.to_le_bytes());
    assert!(script(&non_solid(&strings, &lzma(&strings))).is_err());
    // String references past the table decode as empty, not as a panic.
    let refs = header(
        &[
            [6, 0x7fff_0000, 0, 0, 0, 0, 0],
            [6, i32::MIN, 0, 0, 0, 0, 0],
        ],
        &t,
    );
    let rendered = script(&non_solid(&refs, &lzma(&refs))).unwrap().render();
    assert!(rendered.contains("DetailPrint \"\""), "{rendered}");
}

#[test]
fn bzip2_is_declined_and_lzma_dictionary_is_clamped() {
    let header = trojan_script(false, CODES_V2);
    let mut bzip2 = (0x64_u32 | 0x8000_0000).to_le_bytes().to_vec();
    bzip2.extend_from_slice(&[0x31, 9]);
    bzip2.resize(104, 0);
    assert!(script(&installer(header.len(), &bzip2)).is_err());

    // A declared multi-gigabyte dictionary still decodes the small header.
    let mut raw = lzma(&header);
    raw[1..5].copy_from_slice(&0xff00_0000_u32.to_le_bytes());
    assert_trojan_script(&script(&non_solid(&header, &raw)).unwrap());
}

#[test]
fn quoting_picks_a_free_delimiter() {
    assert_eq!(quote("plain"), "plain");
    assert_eq!(quote(""), "\"\"");
    assert_eq!(quote("two words"), "\"two words\"");
    assert_eq!(quote("a \"b\""), "'a \"b\"'");
    assert_eq!(quote("a \"b\" 'c'"), "`a \"b\" 'c'`");
    assert_eq!(quote("\"'`"), "\"$\\\"'`\"");
}

#[test]
fn publishes_install_commands_as_values() {
    let header = trojan_script(false, CODES_V2);
    let decoded = script(&non_solid(&header, &lzma(&header))).unwrap();
    let values = values(&decoded);
    assert_eq!(values["exec"], json!([RUNDLL]));
    assert_eq!(
        values["exec_wait"],
        json!([r#""$INSTDIR\egrabitsetup.exe""#])
    );
    assert_eq!(
        values["files"],
        json!(["egrabitsetup.exe", "TmProvider.dll"])
    );
    assert_eq!(
        values["file_attributes"][1],
        json!({"path": "TmProvider.dll", "attributes": "HIDDEN"})
    );
    assert_eq!(
        values["registry_writes"][0],
        json!({
            "op": "WriteRegStr",
            "root": "HKCU",
            "key": RUN_KEY,
            "name": "TmProvider",
            "data": RUNDLL,
        })
    );
    assert_eq!(values["shortcuts"][0]["target"], json!(RUNDLL));
    assert_eq!(values["commands"].as_array().unwrap().len(), 12);
    assert_eq!(values["entry_count"], json!(12));
}

/// The installer facts carry the decoded script of an NSIS installer.
#[test]
fn installer_values_include_the_script() {
    let header = trojan_script(false, CODES_V2);
    let mut data = non_solid(&header, &lzma(&header));
    data.extend_from_slice(b"Nullsoft Install System");
    let mut values = crate::output::Values::default();
    super::super::emit(&data, &[], &mut values);
    let installer = values
        .lookup(crate::value_key!("binary.installer"))
        .unwrap();
    assert_eq!(installer["kind"], json!("nsis"));
    assert_eq!(installer["script"]["exec"], json!([RUNDLL]));
}
