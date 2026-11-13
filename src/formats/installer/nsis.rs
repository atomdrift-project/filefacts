//! The install script of an NSIS installer, decoded from its header.
//!
//! An NSIS installer's commands -- `Exec`, `SetFileAttributes`,
//! `WriteRegStr`, `CreateShortCut` -- live in a compressed header block after
//! the stub, not in any file the installer extracts. This module decompresses
//! that header and decodes its entries against the string table.
//!
//! The layout, after the 512-byte-aligned "first header":
//!
//! ```text
//! first header  u32 flags  EF BE AD DE "NullsoftInst"  u32 header_len  u32 data_len
//! non-solid     u32 block_len|0x80000000  compressed header block  ...files
//! solid         one compressed stream:  u32 header_len  header  ...files
//! header        u32 flags  8 x (u32 offset, u32 count)   pages, sections,
//!               entries, strings, language tables, ...
//! entry         7 x i32: opcode, 6 parameters
//! ```
//!
//! LZMA and deflate (NSIS's `zlib`) headers are decoded, solid or not, in
//! NSIS 2.x and 3.x, ANSI and Unicode builds. bzip2 and the x86 branch filter
//! are not; instructions past the range both major versions number alike are
//! kept as `; opcode N` with their strings. Only the bytes present are
//! trusted: every offset is checked, the header is bounded, and the LZMA
//! dictionary never exceeds the output the decoder may produce.

use std::io::Read;

use serde_json::{Map, Value as JsonValue, json};

use crate::bytes::{Endian, sat_u32, sat_usize, u32_le, utf16_units};
use crate::error::Error;

/// Largest decompressed header accepted. Real headers are kilobytes; one of a
/// very large installer with many languages is a few megabytes.
pub const MAX_HEADER_LEN: usize = 16 * 1024 * 1024;
/// Most entries decoded.
pub const MAX_COMMANDS: usize = 200_000;

/// Longest single string decoded, in characters.
const MAX_STRING_CHARS: usize = 8 * 1024;
/// Most rendered commands and most items per command list published as
/// values.
const MAX_PUBLISHED: usize = 1024;
/// The bytes that follow a first header's flags.
const FIRST_HEADER_MAGIC: &[u8] = b"\xef\xbe\xad\xdeNullsoftInst";
/// First header length.
const FIRST_HEADER_LEN: usize = 28;
/// First headers sit on 512-byte boundaries.
const FIRST_HEADER_ALIGN: usize = 512;
/// Bytes of one entry: an opcode and six parameters.
const ENTRY_LEN: usize = 28;
/// Header block indexes.
const BLOCK_ENTRIES: usize = 2;
const BLOCK_STRINGS: usize = 3;
const BLOCK_LANGTABLES: usize = 4;
/// The smallest LZMA dictionary.
const LZMA_MIN_DICT: u32 = 4096;
/// Format label for errors.
const FORMAT: &str = "nsis";

/// One decoded install-script instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Command {
    /// The instruction's raw opcode.
    pub opcode: i32,
    /// Its NSIS script name (`Exec`, `WriteRegStr`), or `None` for an opcode
    /// this decoder does not name.
    pub name: Option<&'static str>,
    /// Its parameters, decoded: strings resolved against the string table
    /// (variables as `$INSTDIR`, shell folders as `$APPDATA`), variables by
    /// name, integers and flags as text. For an unnamed opcode, its non-empty
    /// string parameters.
    pub args: Vec<String>,
}

impl Command {
    /// The instruction as one NSIS script line, its arguments quoted.
    pub fn render(&self) -> String {
        let mut line = match self.name {
            Some(name) => name.to_string(),
            None => format!("; opcode {}", self.opcode),
        };
        for arg in &self.args {
            line.push(' ');
            line.push_str(&quote(arg));
        }
        line
    }

    fn arg(&self, i: usize) -> &str {
        self.args.get(i).map_or("", String::as_str)
    }
}

/// An installer's decoded install script.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Script {
    /// Whether the installer is a Unicode build (UTF-16 strings).
    pub unicode: bool,
    /// The entry count the header declares.
    pub declared: usize,
    /// The decoded instructions, in entry order.
    pub commands: Vec<Command>,
}

impl Script {
    /// The script as NSIS-style text, one instruction per line.
    pub fn render(&self) -> String {
        let mut out = format!(
            "; NSIS install script decoded from the installer header\n; {} entries, {} strings\n",
            self.declared,
            if self.unicode { "Unicode" } else { "ANSI" },
        );
        for command in &self.commands {
            out.push_str(&command.render());
            out.push('\n');
        }
        out
    }
}

/// The install script of the NSIS installer `data` holds.
///
/// # Errors
///
/// [`Error::Malformed`] when no first header is found, the header is larger
/// than [`MAX_HEADER_LEN`], uses bzip2 or the x86 branch filter, does not
/// decompress, or its entry or string table lies outside it.
pub fn script(data: &[u8]) -> Result<Script, Error> {
    let header = header(data)?;
    let block = |index: usize| -> Option<(usize, usize)> {
        let at = index.checked_mul(8)?.checked_add(4)?;
        let offset = sat_usize(u32_le(&header, at)?);
        let count = sat_usize(u32_le(&header, at.checked_add(4)?)?);
        Some((offset, count))
    };
    let truncated = || Error::malformed(FORMAT, "header block table truncated");
    let (entries_at, declared) = block(BLOCK_ENTRIES).ok_or_else(truncated)?;
    let (strings_at, _) = block(BLOCK_STRINGS).ok_or_else(truncated)?;
    let (langtables_at, _) = block(BLOCK_LANGTABLES).ok_or_else(truncated)?;
    let strings_end = if langtables_at > strings_at {
        langtables_at
    } else {
        header.len()
    };
    let strings = Strings::new(&header, strings_at, strings_end)
        .ok_or_else(|| Error::malformed(FORMAT, "string table outside the header"))?;
    let entries = declared
        .checked_mul(ENTRY_LEN)
        .and_then(|len| entries_at.checked_add(len))
        .and_then(|end| header.get(entries_at..end))
        .ok_or_else(|| Error::malformed(FORMAT, "entry table outside the header"))?;
    let commands = entries
        .as_chunks::<ENTRY_LEN>()
        .0
        .iter()
        .take(MAX_COMMANDS)
        .map(|raw| {
            let mut entry = [0i32; 7];
            for (field, bytes) in entry.iter_mut().zip(raw.as_chunks::<4>().0) {
                *field = i32::from_le_bytes(*bytes);
            }
            decode(&strings, &entry)
        })
        .collect();
    Ok(Script {
        unicode: strings.unicode,
        declared,
        commands,
    })
}

/// The decompressed header of the installer `data` holds.
fn header(data: &[u8]) -> Result<Vec<u8>, Error> {
    let first =
        first_header(data).ok_or_else(|| Error::malformed(FORMAT, "no NSIS first header"))?;
    let header_len = first
        .checked_add(20)
        .and_then(|at| u32_le(data, at))
        .map(sat_usize)
        .ok_or_else(|| Error::malformed(FORMAT, "truncated first header"))?;
    if header_len > MAX_HEADER_LEN {
        return Err(Error::malformed(
            FORMAT,
            format!("header of {header_len} bytes exceeds {MAX_HEADER_LEN}"),
        ));
    }
    let body = first
        .checked_add(FIRST_HEADER_LEN)
        .and_then(|at| data.get(at..))
        .ok_or_else(|| Error::malformed(FORMAT, "truncated first header"))?;
    let layout = detect_layout(body, header_len);
    tracing::debug!(target: "filefacts::nsis", first_header = first, header_len, ?layout, "decoding NSIS header");
    match decode_header(body, layout, header_len) {
        // Solid deflate data opens with arbitrary bits, which can pass for a
        // non-solid block length with the compressed flag set.
        Err(error) if layout.method == Method::Deflate && !layout.solid => {
            let solid = Layout {
                solid: true,
                ..layout
            };
            decode_header(body, solid, header_len).map_err(|_| error)
        }
        decoded => decoded,
    }
}

/// The offset of the first header: the first 512-byte boundary followed by
/// the NSIS signature.
pub(crate) fn first_header(data: &[u8]) -> Option<usize> {
    (0..data.len()).step_by(FIRST_HEADER_ALIGN).find(|&at| {
        at.checked_add(4)
            .and_then(|start| data.get(start..))
            .is_some_and(|rest| rest.starts_with(FIRST_HEADER_MAGIC))
    })
}

/// How the header (and the files) are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Stored,
    Deflate,
    Lzma,
    Bzip2,
}

/// How the data after the first header is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    method: Method,
    /// One stream holding the header and every file.
    solid: bool,
    /// The compressed data opens with a one-byte branch-filter flag.
    filter_flag: bool,
}

/// Whether `p` begins LZMA properties as NSIS writes them (`lc=3 lp=0 pb=2`,
/// a dictionary that is a multiple of 64 KiB) followed by the range coder's
/// zero first byte and a first literal -- the test 7-Zip's NSIS reader makes.
fn is_lzma(p: &[u8]) -> bool {
    matches!(p, [0x5d, 0, 0, _, _, 0, next, ..] if next & 0x80 == 0)
}

/// The layout of the data after the first header, by the signature tests
/// 7-Zip's NSIS reader makes.
fn detect_layout(body: &[u8], header_len: usize) -> Layout {
    let layout = |method, solid, filter_flag| Layout {
        method,
        solid,
        filter_flag,
    };
    let flagged_lzma =
        |p: &[u8]| p.first().is_some_and(|&f| f <= 1) && p.get(1..).is_some_and(is_lzma);
    let is_bzip2 = |p: &[u8]| matches!(p, [0x31, level, ..] if *level < 14);
    let after_len = body.get(4..).unwrap_or_default();
    if is_lzma(body) {
        return layout(Method::Lzma, true, false);
    }
    if flagged_lzma(body) {
        return layout(Method::Lzma, true, true);
    }
    if is_lzma(after_len) {
        return layout(Method::Lzma, false, false);
    }
    if flagged_lzma(after_len) {
        return layout(Method::Lzma, false, true);
    }
    let first_word = u32_le(body, 0);
    if first_word.is_some_and(|word| word & 0x8000_0000 != 0) {
        let method = if is_bzip2(after_len) {
            Method::Bzip2
        } else {
            Method::Deflate
        };
        return layout(method, false, false);
    }
    // A header block stored as is: its length without the compressed flag.
    if first_word.is_some_and(|word| sat_usize(word) == header_len) {
        return layout(Method::Stored, false, false);
    }
    if is_bzip2(body) {
        layout(Method::Bzip2, true, false)
    } else {
        layout(Method::Deflate, true, false)
    }
}

/// `data` past its branch-filter flag byte, when the layout has one. The
/// filter itself is not decoded, so a set flag is an error.
fn past_filter_flag(data: &[u8], layout: Layout) -> Result<&[u8], Error> {
    if !layout.filter_flag {
        return Ok(data);
    }
    match data.split_first() {
        Some((0, rest)) => Ok(rest),
        Some(_) => Err(Error::malformed(FORMAT, "x86 branch filter is not decoded")),
        None => Err(Error::malformed(FORMAT, "truncated data")),
    }
}

/// The `header_len`-byte header from `body`, the data after the first
/// header, laid out as `layout` says.
fn decode_header(body: &[u8], layout: Layout, header_len: usize) -> Result<Vec<u8>, Error> {
    if layout.method == Method::Bzip2 {
        return Err(Error::malformed(FORMAT, "bzip2 compression is not decoded"));
    }
    if layout.solid {
        // One stream: the header's length, then the header.
        let mut stream = decompressor(layout.method, past_filter_flag(body, layout)?, None)?;
        let mut len = [0u8; 4];
        stream
            .read_exact(&mut len)
            .map_err(|e| Error::malformed_with_source(FORMAT, "solid stream", e))?;
        if sat_usize(u32::from_le_bytes(len)) != header_len {
            return Err(Error::malformed(
                FORMAT,
                "solid stream does not start with the header",
            ));
        }
        return read_exactly(stream, header_len);
    }
    let block = u32_le(body, 0).ok_or_else(|| Error::malformed(FORMAT, "truncated data"))?;
    let block_len = sat_usize(block & 0x7fff_ffff);
    let block_data = body
        .get(4..)
        .and_then(|rest| rest.get(..block_len))
        .ok_or_else(|| Error::malformed(FORMAT, "header block runs past the end of the file"))?;
    let (method, block_data) = if block & 0x8000_0000 == 0 {
        (Method::Stored, block_data)
    } else {
        (layout.method, past_filter_flag(block_data, layout)?)
    };
    read_exactly(
        decompressor(method, block_data, Some(header_len))?,
        header_len,
    )
}

/// A reader of `data` decompressed with `method`. `size` is the output length
/// when known (the solid stream holds the files too). The LZMA dictionary is
/// clamped to the most the caller reads: match distances never reach past
/// the bytes already decoded, so a declared 4 GiB dictionary cannot make the
/// decoder allocate more than that.
fn decompressor<'a>(
    method: Method,
    data: &'a [u8],
    size: Option<usize>,
) -> Result<Box<dyn Read + 'a>, Error> {
    Ok(match method {
        Method::Stored => Box::new(data),
        Method::Deflate => Box::new(flate2::read::DeflateDecoder::new(data)),
        Method::Bzip2 => {
            return Err(Error::malformed(FORMAT, "bzip2 compression is not decoded"));
        }
        Method::Lzma => {
            let Some(&[props, d0, d1, d2, d3]) = data.first_chunk::<5>() else {
                return Err(Error::malformed(FORMAT, "truncated LZMA properties"));
            };
            let needed = size.unwrap_or(MAX_HEADER_LEN.saturating_add(4));
            let dict = u32::from_le_bytes([d0, d1, d2, d3])
                .min(sat_u32(needed))
                .max(LZMA_MIN_DICT);
            // The size is passed as unknown: NSIS streams may or may not end
            // in an end marker, and the caller reads only what it needs.
            let reader = lzma_rust2::LzmaReader::new_with_props(
                data.get(5..).unwrap_or_default(),
                u64::MAX,
                props,
                dict,
                None,
            )
            .map_err(|e| Error::malformed_with_source(FORMAT, "LZMA properties", e))?;
            Box::new(reader)
        }
    })
}

/// Exactly `len` bytes from `reader`.
fn read_exactly(reader: Box<dyn Read + '_>, len: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(len.min(1024 * 1024));
    reader
        .take(len as u64)
        .read_to_end(&mut out)
        .map_err(|e| Error::malformed_with_source(FORMAT, "header does not decompress", e))?;
    if out.len() != len {
        return Err(Error::malformed(
            FORMAT,
            format!("header decompressed to {} of {len} bytes", out.len()),
        ));
    }
    Ok(out)
}

/// The special-character codes NSIS embeds in its strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Codes {
    skip: u16,
    var: u16,
    shell: u16,
    lang: u16,
}

/// NSIS 2.x ANSI.
const CODES_V2: Codes = Codes {
    skip: 252,
    var: 253,
    shell: 254,
    lang: 255,
};
/// NSIS 3.x ANSI.
const CODES_V3: Codes = Codes {
    lang: 1,
    shell: 2,
    var: 3,
    skip: 4,
};
/// NSIS 3.x Unicode.
const CODES_UNICODE: Codes = Codes {
    skip: 0xe000,
    var: 0xe001,
    shell: 0xe002,
    lang: 0xe003,
};

/// NSIS's built-in variables, by index.
const VARS: [&str; 32] = [
    "$0",
    "$1",
    "$2",
    "$3",
    "$4",
    "$5",
    "$6",
    "$7",
    "$8",
    "$9",
    "$R0",
    "$R1",
    "$R2",
    "$R3",
    "$R4",
    "$R5",
    "$R6",
    "$R7",
    "$R8",
    "$R9",
    "$CMDLINE",
    "$INSTDIR",
    "$OUTDIR",
    "$EXEDIR",
    "$LANGUAGE",
    "$TEMP",
    "$PLUGINSDIR",
    "$EXEPATH",
    "$EXEFILE",
    "$HWNDPARENT",
    "$_CLICK",
    "$_OUTDIR",
];

/// The name of variable `index`.
fn var_name(index: usize) -> String {
    VARS.get(index)
        .map_or_else(|| format!("$_{index}_"), |name| (*name).to_string())
}

/// Shell folders by CSIDL, as NSIS names them.
fn shell_folder(csidl: u8) -> Option<&'static str> {
    Some(match csidl {
        0x00 | 0x10 | 0x19 => "$DESKTOP",
        0x02 | 0x17 => "$SMPROGRAMS",
        0x05 | 0x2e => "$DOCUMENTS",
        0x06 => "$FAVORITES",
        0x07 | 0x18 => "$SMSTARTUP",
        0x08 => "$RECENT",
        0x09 => "$SENDTO",
        0x0b | 0x16 => "$STARTMENU",
        0x0d | 0x35 => "$MUSIC",
        0x0e | 0x37 => "$VIDEOS",
        0x13 => "$NETHOOD",
        0x14 => "$FONTS",
        0x15 => "$TEMPLATES",
        0x1a | 0x23 => "$APPDATA",
        0x1b => "$PRINTHOOD",
        0x1c => "$LOCALAPPDATA",
        0x20 => "$INTERNET_CACHE",
        0x21 => "$COOKIES",
        0x22 => "$HISTORY",
        0x24 => "$WINDIR",
        0x25 => "$SYSDIR",
        0x26 => "$PROGRAMFILES",
        0x27 | 0x36 => "$PICTURES",
        0x28 => "$PROFILE",
        0x2b => "$COMMONFILES",
        0x2f | 0x30 => "$ADMINTOOLS",
        0x38 => "$RESOURCES",
        0x39 => "$RESOURCES_LOCALIZED",
        0x3b => "$CDBURN_AREA",
        _ => return None,
    })
}

/// The installer's string table, as code units, and how to read it.
struct Strings {
    units: Vec<u16>,
    codes: Codes,
    unicode: bool,
}

impl Strings {
    /// The string table at `offset` in `header`, its encoding and code set
    /// detected from its content.
    fn new(header: &[u8], offset: usize, end: usize) -> Option<Self> {
        let table = header.get(offset..end.clamp(offset, header.len().max(offset)))?;
        // The table opens with the empty string: one zero unit. In a Unicode
        // build that unit is two zero bytes; in an ANSI one the next string's
        // text follows the first zero byte.
        let unicode = table.starts_with(&[0, 0]) && table.len() % 2 == 0;
        let units: Vec<u16> = if unicode {
            utf16_units(table, Endian::Little).collect()
        } else {
            table.iter().map(|&b| u16::from(b)).collect()
        };
        // Codes 1-4 never occur in ANSI text; NSIS 2's 252-255 can (`ü`).
        let codes = if unicode {
            CODES_UNICODE
        } else if units.iter().any(|&u| (1..=4).contains(&u)) {
            CODES_V3
        } else {
            CODES_V2
        };
        Some(Self {
            units,
            codes,
            unicode,
        })
    }

    /// The string a parameter names: a string-table offset, or a language
    /// string when negative.
    fn get(&self, param: i32) -> String {
        let Ok(start) = usize::try_from(param) else {
            return format!("$(LSTR_{})", param.unsigned_abs().saturating_sub(1));
        };
        let mut out = String::new();
        let mut units = self.units.get(start..).unwrap_or_default().iter().copied();
        let mut chars = 0usize;
        while let Some(unit) = units.next() {
            if unit == 0 || chars >= MAX_STRING_CHARS {
                break;
            }
            chars = chars.saturating_add(1);
            if unit == self.codes.skip {
                if let Some(next) = units.next() {
                    out.push(self.char_of(next));
                }
                continue;
            }
            if unit != self.codes.var && unit != self.codes.shell && unit != self.codes.lang {
                out.push(self.char_of(unit));
                continue;
            }
            // The code's operand: one unit in a Unicode build, two seven-bit
            // bytes in an ANSI one.
            let operand = if self.unicode {
                units.next().map(u16::to_le_bytes)
            } else {
                units
                    .next()
                    .zip(units.next())
                    .map(|(a, b)| [a.to_le_bytes()[0], b.to_le_bytes()[0]])
            };
            let Some([lo, hi]) = operand else {
                break;
            };
            if unit == self.codes.shell {
                out.push_str(&self.shell_name(lo, hi));
                continue;
            }
            let index = if self.unicode {
                usize::from(u16::from_le_bytes([lo, hi]) & 0x7fff)
            } else {
                usize::from(lo & 0x7f) | (usize::from(hi & 0x7f) << 7)
            };
            if unit == self.codes.var {
                out.push_str(&var_name(index));
            } else {
                out.push_str(&format!("$(LSTR_{index})"));
            }
        }
        out
    }

    /// A shell-folder code's name: the folder's CSIDL for the current user
    /// and for all users, or a registry value naming it.
    fn shell_name(&self, current: u8, all_users: u8) -> String {
        if current & 0x80 != 0 {
            // A folder read from the registry under `CurrentVersion`; the
            // value name sits in the string table.
            let name = self.get(i32::from(current & 0x3f));
            return match name.as_str() {
                "ProgramFilesDir" => "$PROGRAMFILES".to_string(),
                "CommonFilesDir" => "$COMMONFILES".to_string(),
                _ => format!("$SHELL[{name}]"),
            };
        }
        shell_folder(current)
            .or_else(|| shell_folder(all_users))
            .map_or_else(|| format!("$SHELL[{current:#x}]"), str::to_string)
    }

    fn char_of(&self, unit: u16) -> char {
        if self.unicode {
            char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER)
        } else {
            // ANSI code pages agree with Latin-1 on ASCII, which is what
            // commands, paths and registry keys are written in.
            char::from(u8::try_from(unit).unwrap_or(b'?'))
        }
    }
}

/// How one parameter of an instruction is decoded.
#[derive(Debug, Clone, Copy)]
enum Arg {
    /// A string-table reference.
    S(usize),
    /// A variable index.
    V(usize),
    /// A plain integer.
    I(usize),
}

use Arg::{I, S, V};

/// An instruction's script name and parameters, for the opcodes NSIS 2.x and
/// 3.x number alike (`EW_RET` .. `EW_FGETS`). Opcodes needing more than a
/// parameter list are special-cased in [`decode`].
fn instruction(op: i32) -> Option<(&'static str, &'static [Arg])> {
    let found: (&'static str, &'static [Arg]) = match op {
        1 => ("Return", &[]),
        2 => ("Nop", &[]),
        3 => ("Abort", &[S(0)]),
        4 => ("Quit", &[]),
        5 => ("Call", &[I(0)]),
        6 => ("DetailPrint", &[S(0)]),
        7 => ("Sleep", &[S(0)]),
        8 => ("BringToFront", &[]),
        9 => ("SetDetailsView", &[I(0), I(1)]),
        12 => ("IfFileExists", &[S(0), I(1), I(2)]),
        13 => ("SetFlag", &[I(0), S(1)]),
        14 => ("IfFlag", &[I(0), I(1), I(2), I(3)]),
        15 => ("GetFlag", &[V(0), I(1)]),
        16 => ("Rename", &[S(0), S(1)]),
        17 => ("GetFullPathName", &[V(0), S(1)]),
        18 => ("SearchPath", &[V(0), S(1)]),
        19 => ("GetTempFileName", &[V(0), S(1)]),
        20 => ("File", &[S(1)]),
        21 => ("Delete", &[S(0)]),
        22 => ("MessageBox", &[I(0), S(1)]),
        23 => ("RMDir", &[S(0)]),
        24 => ("StrLen", &[V(0), S(1)]),
        25 => ("StrCpy", &[V(0), S(1), S(2), S(3)]),
        26 => ("StrCmp", &[S(0), S(1), I(2), I(3)]),
        27 => ("ReadEnvStr", &[V(0), S(1)]),
        28 => ("IntCmp", &[S(0), S(1), I(2), I(3), I(4)]),
        29 => ("IntOp", &[V(0), S(1), I(3), S(2)]),
        30 => ("IntFmt", &[V(0), S(1), S(2)]),
        32 => ("FindWindow", &[V(0), S(1), S(2), S(3), S(4)]),
        33 => ("SendMessage", &[S(1), S(2), S(3), S(4), V(0)]),
        34 => ("IsWindow", &[S(0), I(1), I(2)]),
        35 => ("GetDlgItem", &[V(0), S(1), S(2)]),
        36 => ("SetCtlColors", &[S(0), I(1)]),
        37 => ("SetBrandingImage", &[S(0)]),
        38 => ("CreateFont", &[V(0), S(1), S(2), S(3)]),
        39 => ("ShowWindow", &[S(0), S(1)]),
        40 => ("ExecShell", &[S(0), S(1), S(2), I(3)]),
        42 => ("GetFileTime", &[S(0), V(1), V(2)]),
        43 => ("GetDLLVersion", &[S(0), V(1), V(2)]),
        44 => ("CallInstDLL", &[S(0), S(1)]),
        45 => ("CreateShortCut", &[S(0), S(1), S(2), S(3)]),
        46 => ("CopyFiles", &[S(0), S(1)]),
        47 => ("Reboot", &[]),
        48 => ("WriteINIStr", &[S(3), S(0), S(1), S(2)]),
        49 => ("ReadINIStr", &[V(0), S(3), S(1), S(2)]),
        53 => ("EnumReg", &[V(0), I(1), S(2), S(3)]),
        54 => ("FileClose", &[V(0)]),
        55 => ("FileOpen", &[V(0), S(3), I(1)]),
        56 => ("FileWrite", &[V(0), S(1)]),
        57 => ("FileRead", &[V(0), V(1), S(2)]),
        _ => return None,
    };
    Some(found)
}

/// The instructions past `EW_FGETS`. A Unicode build inserts the two UTF-16LE
/// file instructions there, shifting the rest by two.
fn late_instruction(op: i32, unicode: bool) -> Option<(&'static str, &'static [Arg])> {
    let op = if unicode {
        match op {
            58 => return Some(("FileWriteUTF16LE", &[V(0), S(1)])),
            59 => return Some(("FileReadUTF16LE", &[V(0), V(1), S(2)])),
            _ => op.checked_sub(2)?,
        }
    } else {
        op
    };
    let found: (&'static str, &'static [Arg]) = match op {
        58 => ("FileSeek", &[V(0), S(2), I(3), V(1)]),
        59 => ("FindClose", &[V(0)]),
        60 => ("FindNext", &[V(1), V(0)]),
        61 => ("FindFirst", &[V(1), V(0), S(2)]),
        62 => ("WriteUninstaller", &[S(0)]),
        _ => return None,
    };
    Some(found)
}

/// A registry root key as NSIS writes it.
fn root_key(value: i32) -> String {
    match value.cast_unsigned() {
        0 => "SHCTX".to_string(),
        0x8000_0000 => "HKCR".to_string(),
        0x8000_0001 => "HKCU".to_string(),
        0x8000_0002 => "HKLM".to_string(),
        0x8000_0003 => "HKU".to_string(),
        0x8000_0005 => "HKCC".to_string(),
        other => format!("{other:#x}"),
    }
}

/// `SetFileAttributes` flags by name.
fn file_attributes(value: i32) -> String {
    const NAMES: [(i32, &str); 8] = [
        (0x1, "READONLY"),
        (0x2, "HIDDEN"),
        (0x4, "SYSTEM"),
        (0x20, "ARCHIVE"),
        (0x80, "NORMAL"),
        (0x100, "TEMPORARY"),
        (0x1000, "OFFLINE"),
        (0x2000, "NOT_CONTENT_INDEXED"),
    ];
    let names: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|&(_, name)| name)
        .collect();
    if names.is_empty() {
        format!("{value:#x}")
    } else {
        names.join("|")
    }
}

/// `text` as one NSIS argument: bare when it holds no whitespace, quote or
/// comment character, otherwise quoted with whichever of `"`, `'` and `` ` ``
/// it does not contain.
fn quote(text: &str) -> String {
    let needs_quotes = text.is_empty()
        || text.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ';' | '#'));
    if !needs_quotes {
        return text.to_string();
    }
    match ['"', '\'', '`'].into_iter().find(|q| !text.contains(*q)) {
        Some(q) => format!("{q}{text}{q}"),
        None => format!("\"{}\"", text.replace('"', "$\\\"")),
    }
}

/// One entry, decoded.
fn decode(strings: &Strings, entry: &[i32; 7]) -> Command {
    let [op, params @ ..] = entry;
    let op = *op;
    let p = |i: usize| params.get(i).copied().unwrap_or(0);
    let s = |i: usize| strings.get(p(i));
    let var = |i: usize| usize::try_from(p(i)).map_or_else(|_| format!("$_{}_", p(i)), var_name);
    let named = |name: &'static str, args: Vec<String>| Command {
        opcode: op,
        name: Some(name),
        args,
    };
    match op {
        10 => named("SetFileAttributes", vec![s(0), file_attributes(p(1))]),
        11 if p(1) != 0 => named("SetOutPath", vec![s(0)]),
        11 => named("CreateDirectory", vec![s(0)]),
        31 if p(2) != 0 => named("Exch", vec![p(2).to_string()]),
        31 if p(1) != 0 => named("Pop", vec![var(0)]),
        31 => named("Push", vec![s(0)]),
        41 if p(2) != 0 => named("ExecWait", vec![s(0)]),
        41 => named("Exec", vec![s(0)]),
        50 => named("DeleteReg", vec![root_key(p(1)), s(2), s(3)]),
        51 => {
            let name = match (p(5), p(4)) {
                (1, _) => "WriteRegStr",
                (2, _) => "WriteRegExpandStr",
                (3, _) | (_, 3) => "WriteRegBin",
                (4, _) | (_, 2) => "WriteRegDWORD",
                _ => "WriteReg",
            };
            named(name, vec![root_key(p(0)), s(1), s(2), s(3)])
        }
        52 => {
            let name = if p(4) != 0 {
                "ReadRegDWORD"
            } else {
                "ReadRegStr"
            };
            named(name, vec![var(0), root_key(p(1)), s(2), s(3)])
        }
        _ => match instruction(op).or_else(|| late_instruction(op, strings.unicode)) {
            Some((name, args)) => named(
                name,
                args.iter()
                    .map(|arg| match *arg {
                        S(i) => s(i),
                        V(i) => var(i),
                        I(i) => p(i).to_string(),
                    })
                    .collect(),
            ),
            // An instruction this decoder does not name: keep its strings so
            // rules still see them.
            None => Command {
                opcode: op,
                name: None,
                args: (0..6)
                    .filter(|&i| p(i) > 0)
                    .map(s)
                    .filter(|text| !text.is_empty())
                    .collect(),
            },
        },
    }
}

/// The script's install commands as values: `commands` (each rendered as a
/// script line) and, by kind, `exec`, `exec_wait`, `exec_shell`, `files`,
/// `deletes`, `file_attributes`, `registry_writes`, `shortcuts` and
/// `dll_calls`. Each list holds at most [`MAX_PUBLISHED`] items.
pub(crate) fn values(script: &Script) -> JsonValue {
    let mut lists: Map<String, JsonValue> = Map::new();
    let mut push = |key: &str, value: JsonValue| {
        if let JsonValue::Array(items) = lists
            .entry(key)
            .or_insert_with(|| JsonValue::Array(Vec::new()))
            && items.len() < MAX_PUBLISHED
        {
            items.push(value);
        }
    };
    for command in &script.commands {
        push("commands", command.render().into());
        let a = |i| command.arg(i);
        match command.name {
            Some("Exec") => push("exec", a(0).into()),
            Some("ExecWait") => push("exec_wait", a(0).into()),
            Some("ExecShell") => push(
                "exec_shell",
                json!({"verb": a(0), "file": a(1), "parameters": a(2)}),
            ),
            Some("File") => push("files", a(0).into()),
            Some("Delete") => push("deletes", a(0).into()),
            Some("SetFileAttributes") => {
                push("file_attributes", json!({"path": a(0), "attributes": a(1)}))
            }
            Some(
                op @ ("WriteRegStr" | "WriteRegExpandStr" | "WriteRegBin" | "WriteRegDWORD"
                | "WriteReg"),
            ) => push(
                "registry_writes",
                json!({"op": op, "root": a(0), "key": a(1), "name": a(2), "data": a(3)}),
            ),
            Some("CreateShortCut") => push(
                "shortcuts",
                json!({"link": a(0), "target": a(1), "parameters": a(2)}),
            ),
            Some("CallInstDLL") => push("dll_calls", json!({"dll": a(0), "function": a(1)})),
            _ => {}
        }
    }
    lists.insert("unicode".into(), script.unicode.into());
    lists.insert("entry_count".into(), script.declared.into());
    JsonValue::Object(lists)
}

#[cfg(test)]
mod tests;
