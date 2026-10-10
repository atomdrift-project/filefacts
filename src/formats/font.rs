//! Font extractor: sfnt (TrueType/OpenType), WOFF, WOFF2, EOT.
//!
//! Fonts are opaque binary containers that reviewers skim past and that
//! bundlers copy verbatim into `public/`, `static/`, `assets/` and package
//! payloads. That makes them a standing carrier for two families of abuse:
//!
//! - **Masquerade.** A file named `*.woff2` whose bytes are a script or a PE.
//!   The loader that runs it names it explicitly (`node ./fonts/x.woff2`), so
//!   the disguise only has to survive a human skim and a type-driven scanner
//!   that skips "media".
//! - **Steganography / stowaway payloads.** A structurally *valid* font whose
//!   table directory does not account for every byte: data appended past the
//!   last table, data parked in the gaps between tables, or a private
//!   four-character table tag holding a blob. The font still renders, so
//!   nothing downstream complains.
//!
//! This module is a single bounded pass that answers "is this actually a font,
//! and does its structure account for its bytes". It never decodes glyph
//! outlines, decompresses WOFF table data, or renders anything.
//!
//! Emitted facts:
//!
//! - `font.format` — `truetype`, `opentype`, `truetype_collection`, `woff`,
//!   `woff2`, `eot`, or `none` when no known font signature is present.
//! - `font.valid` — the signature is a known font format *and* its declared
//!   structure fits inside the file.
//! - `font.tables[]` / `font.unknown_tables[]` — four-character table tags in
//!   directory order, and the subset outside the registered OpenType set.
//! - `font.features[]` — Pike-style flag array: `trailing_data`,
//!   `interior_gaps`, `overlapping_tables`, `table_out_of_bounds`,
//!   `truncated`, `size_mismatch`, `unknown_tables`, `signed` (DSIG),
//!   `variable` (fvar), `bitmap` (colour/bitmap strikes), `text_content`.
//! - `font.stowaway[]` — what the bytes the table directory does not account
//!   for turn out to be: `pe`, `elf`, `macho`, `zip`, `gzip`, `xz`, `bzip2`,
//!   `sevenz`, `rar`, `cab`, `zstd`, `shebang`, `base64`, `text`,
//!   `high_entropy`. This is the difference between "a font with slack" and
//!   "a font carrying a Windows executable".
//! - `font.content_kind` — for a file with no font signature, the same
//!   classification applied to the whole file.
//! - `font.problems[]` — why `font.valid` is false, in analyst-readable form.
//! - `font.sfnt_version` — the wrapped sfnt flavor for WOFF/WOFF2/EOT.
//!
//! Metrics mirror the PNG extractor's shape so rules read the same way across
//! carrier formats: `font.table_count`, `font.unknown_table_count`,
//! `font.trailing_bytes`, `font.gap_bytes`, `font.largest_table_bytes`,
//! `font.declared_size_delta`, `font.printable_ratio`,
//! `font.leading_whitespace_bytes`.

use crate::metric;
use crate::value_key;
use serde_json::Value as JsonValue;
use std::collections::HashSet;

use crate::formats::carrier::{classify_region, leading_whitespace, printable_ratio};
use crate::formats::common::bytes_at::u32_be;
use crate::formats::common::{XorScan, extract_binary_strings, hex_encode};
use crate::output::{Metrics, Strings, Values};
use crate::scan::entropy;

/// sfnt table records are 16 bytes: tag, checksum, offset, length.
const SFNT_RECORD_LEN: usize = 16;
/// WOFF table records are 20 bytes: tag, offset, compLength, origLength, checksum.
const WOFF_RECORD_LEN: usize = 20;
/// Offset of the EOT `MagicNumber` field (`0x504C`, little-endian).
const EOT_MAGIC_OFFSET: usize = 34;

/// Most table records read from one directory. OpenType registers about a
/// hundred tags and a font carries each at most once; real fonts hold 10-40.
const MAX_TABLES: usize = 1024;

/// Region bytes examined per file byte. The regions of a well-formed font
/// are disjoint, so together they read the file at most once; table records
/// may overlap, though, and up to 1024 per directory -- or half a million
/// across a collection -- each naming the whole file made the scan quadratic.
const SCAN_PASSES: u64 = 2;

/// A table directory entry reduced to what structural analysis needs.
struct TableEntry {
    /// `None` for a WOFF container region (metadata or private block),
    /// which claims bytes but is not a table.
    tag: Option<[u8; 4]>,
    offset: u64,
    length: u64,
}

/// Which font container the signature says this is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    TrueType,
    OpenType,
    Collection,
    Woff,
    Woff2,
    Eot,
    /// No recognised font signature. The file is named like a font and is
    /// being analysed as one, but its bytes are something else.
    None,
}

impl Format {
    const fn label(self) -> &'static str {
        match self {
            Self::TrueType => "truetype",
            Self::OpenType => "opentype",
            Self::Collection => "truetype_collection",
            Self::Woff => "woff",
            Self::Woff2 => "woff2",
            Self::Eot => "eot",
            Self::None => "none",
        }
    }
}

/// Accumulates the structural verdict as the pass walks the container.
#[derive(Default)]
struct Report {
    /// Distinct table tags as labels, in directory order.
    tables: Vec<String>,
    unknown_tables: Vec<String>,
    /// The raw tags behind `tables`, for O(1) de-duplication.
    seen_tables: HashSet<[u8; 4]>,
    features: Vec<&'static str>,
    problems: Vec<String>,
    sfnt_version: Option<String>,
    trailing_bytes: u64,
    gap_bytes: u64,
    largest_table_bytes: u64,
    /// Bytes held by table tags outside the registered set. Vendor-private
    /// tags are common and tiny (FontForge's `FFTM` is 12 bytes, Monotype's
    /// `MTfn` a few dozen); a private tag holding kilobytes is a carrier.
    unknown_table_bytes: u64,
    /// What the bytes a font does not account for turn out to be — see
    /// [`classify_region`]. Empty when every byte is claimed by a registered
    /// table, which is the normal case.
    stowaway: Vec<&'static str>,
    /// Total size of the regions no table accounts for: interior gaps,
    /// trailing data, and tables under an unregistered tag. The `name`/`post`
    /// string tables are searched for payload signatures too but are *not*
    /// counted here — they are legitimately claimed content, and counting
    /// them reported 4 KB of "stowaway" on every ordinary font. WOFF metadata
    /// and private blocks are treated the same way.
    stowaway_bytes: u64,
    /// Shannon entropy over those same regions. Near 8.0 means compressed or
    /// encrypted content, which no font format leaves lying between tables.
    stowaway_entropy: f64,
    /// For a file with no font signature: what its bytes actually are.
    content_kind: Option<&'static str>,
    /// Declared total size minus actual size. Non-zero means the header and
    /// the file disagree about how many bytes the font occupies.
    declared_size_delta: i64,
    structure_ok: bool,
    /// Bytes [`note_region`] may still read; see [`SCAN_PASSES`].
    scan_budget: u64,
}

impl Report {
    fn flag(&mut self, name: &'static str) {
        if !self.features.contains(&name) {
            self.features.push(name);
        }
    }

    fn stow(&mut self, kind: &'static str) {
        if !self.stowaway.contains(&kind) {
            self.stowaway.push(kind);
        }
    }

    fn problem(&mut self, what: impl Into<String>) {
        self.structure_ok = false;
        let what = what.into();
        if !self.problems.contains(&what) {
            self.problems.push(what);
        }
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    // A font that is really a script still deserves a string view: the
    // masquerade case is exactly the one where the strings are the evidence.
    extract_binary_strings(bytes, strings, XorScan::No);

    let format = classify(bytes);
    let mut report = Report {
        structure_ok: format != Format::None,
        scan_budget: (bytes.len() as u64).saturating_mul(SCAN_PASSES),
        ..Report::default()
    };

    match format {
        Format::TrueType | Format::OpenType => walk_sfnt(bytes, &mut report),
        Format::Collection => walk_collection(bytes, &mut report),
        Format::Woff => walk_woff(bytes, &mut report),
        Format::Woff2 => walk_woff2(bytes, &mut report),
        Format::Eot => walk_eot(bytes, &mut report),
        Format::None => {
            report.problem("no font signature");
            // Nothing here is a font, so say what it is instead. This is the
            // reachable case where cleave still typed the file `font` — the
            // bytes carry no magic of their own (a raw compressed blob, an
            // encrypted stage, base64) so no other analyzer claimed them.
            report.content_kind = classify_region(bytes).or(Some("unknown"));
        }
    }

    // Text masquerading as a font. A real font is compressed glyph data and
    // binary tables; a printable-ASCII ratio near 1.0 means the bytes are
    // source, markup, or an encoded blob wearing a font extension. Reported
    // for every font-typed file, valid or not: a *valid* font that is also
    // mostly printable is worth a look too.
    let printable = printable_ratio(bytes);
    if printable > 0.95 && !bytes.is_empty() {
        report.flag("text_content");
    }

    values.insert_key(
        value_key!("font.format"),
        JsonValue::String(format.label().to_string()),
    );
    values.insert_key(
        value_key!("font.valid"),
        JsonValue::Bool(report.structure_ok),
    );
    if let Some(v) = report.sfnt_version.take() {
        values.insert_key(value_key!("font.sfnt_version"), JsonValue::String(v));
    }
    if !report.tables.is_empty() {
        values.insert_key(
            value_key!("font.tables"),
            JsonValue::Array(
                report
                    .tables
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    if !report.unknown_tables.is_empty() {
        report.flag("unknown_tables");
        values.insert_key(
            value_key!("font.unknown_tables"),
            JsonValue::Array(
                report
                    .unknown_tables
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    if let Some(kind) = report.content_kind {
        values.insert_key(
            value_key!("font.content_kind"),
            JsonValue::String(kind.to_string()),
        );
    }
    if !report.stowaway.is_empty() {
        report.flag("stowaway");
        values.insert_key(
            value_key!("font.stowaway"),
            JsonValue::Array(
                report
                    .stowaway
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
    if !report.problems.is_empty() {
        values.insert_key(
            value_key!("font.problems"),
            JsonValue::Array(
                report
                    .problems
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    if !report.features.is_empty() {
        values.insert_key(
            value_key!("font.features"),
            JsonValue::Array(
                report
                    .features
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }

    metrics.insert(metric!("font.table_count"), report.tables.len() as f64);
    metrics.insert(
        metric!("font.unknown_table_count"),
        report.unknown_tables.len() as f64,
    );
    metrics.insert(
        metric!("font.unknown_table_bytes"),
        report.unknown_table_bytes as f64,
    );
    metrics.insert(metric!("font.trailing_bytes"), report.trailing_bytes as f64);
    metrics.insert(metric!("font.gap_bytes"), report.gap_bytes as f64);
    metrics.insert(
        metric!("font.largest_table_bytes"),
        report.largest_table_bytes as f64,
    );
    #[allow(clippy::cast_precision_loss)]
    metrics.insert(
        metric!("font.declared_size_delta"),
        report.declared_size_delta as f64,
    );
    metrics.insert(metric!("font.stowaway_bytes"), report.stowaway_bytes as f64);
    metrics.insert(metric!("font.stowaway_entropy"), report.stowaway_entropy);
    metrics.insert(metric!("font.printable_ratio"), printable);
    metrics.insert(
        metric!("font.leading_whitespace_bytes"),
        leading_whitespace(bytes) as f64,
    );
}

/// Identify the container from its signature alone.
fn classify(bytes: &[u8]) -> Format {
    if let Some(magic) = bytes.first_chunk::<4>() {
        match magic {
            b"OTTO" => return Format::OpenType,
            b"ttcf" => return Format::Collection,
            b"wOFF" => return Format::Woff,
            b"wOF2" => return Format::Woff2,
            // `true` and `typ1` are the legacy Apple sfnt flavors; 0x00010000
            // is the Microsoft/Windows one that essentially every `.ttf` uses.
            b"true" | b"typ1" | [0x00, 0x01, 0x00, 0x00] => return Format::TrueType,
            _ => {}
        }
    }
    // EOT has no leading signature — it opens with two little-endian sizes.
    // The `MagicNumber` field at byte 34 is what identifies it.
    if bytes.get(EOT_MAGIC_OFFSET..EOT_MAGIC_OFFSET + 2) == Some(&[0x4C, 0x50][..]) {
        return Format::Eot;
    }
    Format::None
}

/// Walk an sfnt table directory starting at `base`, returning its entries and
/// the offset where the directory ends. Coverage is folded in by the caller so
/// a collection can account for every member against one shared picture.
fn read_sfnt_dir(bytes: &[u8], base: usize, report: &mut Report) -> (Vec<TableEntry>, u64) {
    let Some(header) = bytes.get(base..).and_then(<[u8]>::first_chunk::<12>) else {
        report.problem("header truncated");
        report.flag("truncated");
        return (Vec::new(), 0);
    };
    report.sfnt_version = Some(sfnt_version_label(&header[..4]));

    let num_tables = u16::from_be_bytes([header[4], header[5]]) as usize;
    if num_tables > MAX_TABLES {
        report.problem("implausible table count");
        return (Vec::new(), 0);
    }
    let dir_start = base + 12;
    let Some(dir_end) = num_tables
        .checked_mul(SFNT_RECORD_LEN)
        .and_then(|n| dir_start.checked_add(n))
    else {
        report.problem("table count overflows");
        return (Vec::new(), 0);
    };
    let Some(dir) = bytes.get(dir_start..dir_end) else {
        report.problem("table directory truncated");
        report.flag("truncated");
        return (Vec::new(), 0);
    };

    let entries = dir
        .as_chunks::<SFNT_RECORD_LEN>()
        .0
        .iter()
        .map(|rec| TableEntry {
            tag: Some([rec[0], rec[1], rec[2], rec[3]]),
            offset: u64::from(u32::from_be_bytes([rec[8], rec[9], rec[10], rec[11]])),
            length: u64::from(u32::from_be_bytes([rec[12], rec[13], rec[14], rec[15]])),
        })
        .collect();
    (entries, dir_end as u64)
}

/// A bare `.ttf`/`.otf`: one directory, folded straight into coverage.
fn walk_sfnt(bytes: &[u8], report: &mut Report) {
    let (entries, dir_end) = read_sfnt_dir(bytes, 0, report);
    record_tables(bytes, dir_end, &entries, report);
}

/// A TrueType collection is a header of offsets into sfnt directories whose
/// members deliberately *share* table data — a `.ttc` exists precisely so two
/// faces can point at one `glyf`. Coverage must therefore be computed across
/// the union of every member's directory; folding each member in on its own
/// reports the bytes claimed by earlier members as unaccounted-for, which
/// marked every shipped macOS `.ttc` invalid.
fn walk_collection(bytes: &[u8], report: &mut Report) {
    let Some(header) = bytes.first_chunk::<16>() else {
        report.problem("collection header truncated");
        report.flag("truncated");
        return;
    };
    report.sfnt_version = Some("ttcf".to_string());
    let num_fonts = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    // A collection with thousands of members is malformed, not a font. The
    // cap keeps a hostile header from turning into a long walk.
    if num_fonts == 0 || num_fonts > 512 {
        report.problem("implausible collection member count");
        return;
    }
    // The header itself, plus the offset array, is covered ground.
    let mut dir_end = (12 + num_fonts * 4) as u64;
    let mut all: Vec<TableEntry> = Vec::new();
    // Members that share a directory contribute identical entries, which
    // the dedup below would collapse anyway; walk each directory once so a
    // header pointing all 512 members at one large directory costs one walk.
    let mut walked = HashSet::new();
    for i in 0..num_fonts {
        let Some(off) = u32_be(bytes, 12 + i * 4) else {
            report.problem("collection offset table truncated");
            report.flag("truncated");
            return;
        };
        let off = off as usize;
        if !walked.insert(off) {
            continue;
        }
        if off >= bytes.len() {
            report.problem("collection member offset out of bounds");
            report.flag("table_out_of_bounds");
            continue;
        }
        let (entries, member_dir_end) = read_sfnt_dir(bytes, off, report);
        dir_end = dir_end.max(member_dir_end);
        all.extend(entries);
    }
    // Shared tables appear once per referencing member. Collapse them so an
    // extent is neither double-counted nor mistaken for an overlap.
    all.sort_unstable_by_key(|e| (e.offset, e.length));
    all.dedup_by(|a, b| a.offset == b.offset && a.length == b.length && a.tag == b.tag);
    record_tables(bytes, dir_end, &all, report);
}

/// WOFF wraps an sfnt in a per-table-compressed container. The directory is
/// uncompressed, so table extents are readable without inflating anything.
fn walk_woff(bytes: &[u8], report: &mut Report) {
    let Some(header) = bytes.first_chunk::<44>() else {
        report.problem("header truncated");
        report.flag("truncated");
        return;
    };
    report.sfnt_version = Some(sfnt_version_label(&header[4..8]));
    let declared = u64::from(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]));
    note_declared_size(declared, bytes.len(), report);

    let num_tables = u16::from_be_bytes([header[12], header[13]]) as usize;
    if num_tables > MAX_TABLES {
        report.problem("implausible table count");
        return;
    }
    let dir_start = 44usize;
    let Some(dir_end) = num_tables
        .checked_mul(WOFF_RECORD_LEN)
        .and_then(|n| dir_start.checked_add(n))
    else {
        report.problem("table count overflows");
        return;
    };
    let Some(dir) = bytes.get(dir_start..dir_end) else {
        report.problem("table directory truncated");
        report.flag("truncated");
        return;
    };

    let mut entries: Vec<TableEntry> = dir
        .as_chunks::<WOFF_RECORD_LEN>()
        .0
        .iter()
        .map(|rec| TableEntry {
            tag: Some([rec[0], rec[1], rec[2], rec[3]]),
            offset: u64::from(u32::from_be_bytes([rec[4], rec[5], rec[6], rec[7]])),
            // compLength is the on-disk extent; origLength is the inflated size.
            length: u64::from(u32::from_be_bytes([rec[8], rec[9], rec[10], rec[11]])),
        })
        .collect();
    // The metadata and private blocks are legitimate parts of the container,
    // so count them as covered rather than reporting them as stowaways.
    // `record_tables` still searches them for payload signatures, as it does
    // the string tables: their contents are free-form.
    let mut extra = Vec::new();
    // metaOffset/metaLength sit at 24/28, privOffset/privLength at 36/40. The
    // header is 44 bytes, so every read lands; an unreadable field would mean
    // an undeclared block.
    let field = |at: usize| u32_be(header, at).map_or(0, u64::from);
    for (off, len) in [(field(24), field(28)), (field(36), field(40))] {
        if off > 0 && len > 0 {
            extra.push(TableEntry {
                tag: None,
                offset: off,
                length: len,
            });
        }
    }
    entries.extend(extra);
    record_tables(bytes, dir_end as u64, &entries, report);
}

/// WOFF2 has an uncompressed variable-length table directory followed by one
/// Brotli stream. Recover tags and check physical block bounds without claiming
/// to validate the compressed font tables themselves.
fn walk_woff2(bytes: &[u8], report: &mut Report) {
    let Some(header) = bytes.first_chunk::<48>() else {
        report.problem("header truncated");
        report.flag("truncated");
        return;
    };
    report.sfnt_version = Some(sfnt_version_label(&header[4..8]));
    let declared = u64::from(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]));
    note_declared_size(declared, bytes.len(), report);

    let num_tables = u16::from_be_bytes([header[12], header[13]]) as usize;
    if num_tables == 0 {
        report.problem("no tables declared");
        return;
    }
    if num_tables > MAX_TABLES {
        report.problem("implausible table count");
        return;
    }
    let compressed = u64::from(u32::from_be_bytes([
        header[20], header[21], header[22], header[23],
    ]));
    report.largest_table_bytes = compressed;
    let collection = header.get(4..8) == Some(b"ttcf".as_slice());
    let mut cursor = 48;
    for _ in 0..num_tables {
        let Some((tag, _length)) = read_woff2_entry(bytes, &mut cursor) else {
            report.problem("invalid or truncated WOFF2 table directory");
            report.flag("truncated");
            return;
        };
        if report.seen_tables.insert(tag) {
            let label = tag_label(&tag);
            if !is_registered_tag(tag) {
                report.unknown_tables.push(label.clone());
            }
            report.tables.push(label);
        } else if !collection {
            report.problem("duplicate WOFF2 table tag");
        }
        match &tag {
            b"fvar" => report.flag("variable"),
            b"CBDT" | b"EBDT" | b"sbix" | b"SVG " => report.flag("bitmap"),
            b"DSIG" => report.flag("signed"),
            _ => {}
        }
    }
    if collection && !skip_woff2_collection(bytes, &mut cursor, num_tables) {
        report.problem("invalid or truncated WOFF2 collection directory");
        report.flag("truncated");
        return;
    }
    let stream_end = (cursor as u64).saturating_add(compressed);
    if stream_end > bytes.len() as u64 || compressed == 0 {
        report.problem("WOFF2 compressed stream missing or out of bounds");
        report.flag("table_out_of_bounds");
        return;
    }
    // Metadata and private blocks are physically addressable. The shared
    // compressed stream has no addressable per-table byte ranges: do not
    // classify its ordinary compressed bytes as unclaimed table payloads.
    let mut blocks = vec![(cursor as u64, stream_end)];
    for (offset_at, length_at) in [(28, 32), (40, 44)] {
        let offset = u32_be(header, offset_at).map_or(0, u64::from);
        let length = u32_be(header, length_at).map_or(0, u64::from);
        if offset == 0 && length == 0 {
            continue;
        }
        let end = offset.saturating_add(length);
        if offset == 0 || length == 0 || end > bytes.len() as u64 {
            report.problem("WOFF2 auxiliary block out of bounds");
            report.flag("table_out_of_bounds");
            continue;
        }
        blocks.push((offset, end));
        note_region(bytes, offset, end, report, RegionKind::Claimed);
    }
    blocks.sort_unstable();
    let mut covered = cursor as u64;
    for (start, end) in blocks {
        if start < covered {
            report.problem("WOFF2 data blocks overlap");
            report.flag("overlapping_tables");
        } else if start - covered > 3
            || bytes
                .get(crate::bytes::sat_usize(covered)..crate::bytes::sat_usize(start))
                .is_some_and(|gap| gap.iter().any(|&b| b != 0))
        {
            report.gap_bytes += start - covered;
            report.problem("bytes not claimed by WOFF2 blocks");
            report.flag("interior_gaps");
            note_region(bytes, covered, start, report, RegionKind::Unclaimed);
        }
        covered = covered.max(end);
    }
    let Some(trailing) = bytes.get(crate::bytes::sat_usize(covered)..) else {
        report.problem("WOFF2 covered extent out of bounds");
        return;
    };
    if trailing.len() > 3 || trailing.iter().any(|&b| b != 0) {
        report.trailing_bytes = report.trailing_bytes.max(trailing.len() as u64);
        report.problem("data appended after WOFF2 blocks");
        report.flag("trailing_data");
        note_region(
            bytes,
            covered,
            bytes.len() as u64,
            report,
            RegionKind::Unclaimed,
        );
    }
}

const WOFF2_TAGS: [[u8; 4]; 63] = [
    *b"cmap", *b"head", *b"hhea", *b"hmtx", *b"maxp", *b"name", *b"OS/2", *b"post", *b"cvt ",
    *b"fpgm", *b"glyf", *b"loca", *b"prep", *b"CFF ", *b"VORG", *b"EBDT", *b"EBLC", *b"gasp",
    *b"hdmx", *b"kern", *b"LTSH", *b"PCLT", *b"VDMX", *b"vhea", *b"vmtx", *b"BASE", *b"GDEF",
    *b"GPOS", *b"GSUB", *b"EBSC", *b"JSTF", *b"MATH", *b"CBDT", *b"CBLC", *b"COLR", *b"CPAL",
    *b"SVG ", *b"sbix", *b"acnt", *b"avar", *b"bdat", *b"bloc", *b"bsln", *b"cvar", *b"fdsc",
    *b"feat", *b"fmtx", *b"fvar", *b"gvar", *b"hsty", *b"just", *b"lcar", *b"mort", *b"morx",
    *b"opbd", *b"prop", *b"trak", *b"Zapf", *b"Silf", *b"Glat", *b"Gloc", *b"Feat", *b"Sill",
];

fn font_byte(bytes: &[u8], cursor: &mut usize) -> Option<u8> {
    let byte = *bytes.get(*cursor)?;
    *cursor += 1;
    Some(byte)
}

/// WOFF2 UIntBase128 rejects leading zero groups, overflow and >5 bytes.
fn woff2_base128(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let mut value = 0u32;
    for i in 0..5 {
        let byte = font_byte(bytes, cursor)?;
        if (i == 0 && byte == 0x80) || value & 0xfe00_0000 != 0 {
            return None;
        }
        value = (value << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn read_woff2_entry(bytes: &[u8], cursor: &mut usize) -> Option<([u8; 4], u32)> {
    let flags = font_byte(bytes, cursor)?;
    let tag = if flags & 63 == 63 {
        let tag = bytes.get(*cursor..*cursor + 4)?.try_into().ok()?;
        *cursor += 4;
        tag
    } else {
        *WOFF2_TAGS.get(usize::from(flags & 63))?
    };
    let original = woff2_base128(bytes, cursor)?;
    let version = flags >> 6;
    let outlines = matches!(&tag, b"glyf" | b"loca");
    if (outlines && !matches!(version, 0 | 3))
        || (!outlines && version != 0 && !(&tag == b"hmtx" && version == 1))
    {
        return None;
    }
    let transformed = if outlines { version != 3 } else { version != 0 };
    let length = if transformed {
        woff2_base128(bytes, cursor)?
    } else {
        original
    };
    if transformed && &tag == b"loca" && length != 0 {
        return None;
    }
    Some((tag, length))
}

fn woff2_255u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    match font_byte(bytes, cursor)? {
        253 => {
            Some(u16::from(font_byte(bytes, cursor)?) * 256 + u16::from(font_byte(bytes, cursor)?))
        }
        254 => Some(506 + u16::from(font_byte(bytes, cursor)?)),
        255 => Some(253 + u16::from(font_byte(bytes, cursor)?)),
        byte => Some(u16::from(byte)),
    }
}

fn skip_woff2_collection(bytes: &[u8], cursor: &mut usize, tables: usize) -> bool {
    let Some(version) = u32_be(bytes, *cursor) else {
        return false;
    };
    *cursor += 4;
    if !matches!(version, 0x0001_0000 | 0x0002_0000) {
        return false;
    }
    let Some(fonts) = woff2_255u16(bytes, cursor) else {
        return false;
    };
    if fonts == 0 || fonts > 512 {
        return false;
    }
    for _ in 0..fonts {
        let Some(count) = woff2_255u16(bytes, cursor) else {
            return false;
        };
        if count == 0 || usize::from(count) > tables || bytes.get(*cursor..*cursor + 4).is_none() {
            return false;
        }
        *cursor += 4;
        for _ in 0..count {
            if woff2_255u16(bytes, cursor).is_none_or(|index| usize::from(index) >= tables) {
                return false;
            }
        }
    }
    true
}

/// Embedded OpenType: a little-endian header wrapping an sfnt (optionally
/// MTX-compressed). Validate the two size fields against the file.
fn walk_eot(bytes: &[u8], report: &mut Report) {
    let Some(header) = bytes.first_chunk::<{ EOT_MAGIC_OFFSET + 2 }>() else {
        report.problem("header truncated");
        report.flag("truncated");
        return;
    };
    let eot_size = u64::from(u32::from_le_bytes([
        header[0], header[1], header[2], header[3],
    ]));
    let font_data_size = u64::from(u32::from_le_bytes([
        header[4], header[5], header[6], header[7],
    ]));
    report.sfnt_version = Some("eot".to_string());
    note_declared_size(eot_size, bytes.len(), report);
    if font_data_size > bytes.len() as u64 {
        report.problem("font data size exceeds file");
        report.flag("table_out_of_bounds");
    }
    report.largest_table_bytes = font_data_size;
}

/// Compare a header-declared total size against the real one.
fn note_declared_size(declared: u64, actual: usize, report: &mut Report) {
    let actual = actual as u64;
    if declared == 0 || declared == actual {
        return;
    }
    // In i128: a declared size at or past 2^63 would overflow an i64 subtraction.
    let delta = i128::from(declared) - i128::from(actual);
    report.declared_size_delta =
        i64::try_from(delta).unwrap_or(if delta < 0 { i64::MIN } else { i64::MAX });
    report.flag("size_mismatch");
    if declared > actual {
        report.problem("declared size exceeds file");
        report.flag("truncated");
    } else {
        // Extra bytes past what the header claims: the renderer stops at
        // `declared`, so everything after it rides along unread.
        report.trailing_bytes = actual - declared;
        report.flag("trailing_data");
        report.problem("file larger than declared size");
    }
}

/// Fold a table directory into the coverage picture: bounds, overlaps, the
/// bytes no table claims, and the bytes past the last one.
fn record_tables(bytes: &[u8], dir_end: u64, entries: &[TableEntry], report: &mut Report) {
    let file_len = bytes.len() as u64;
    if entries.is_empty() {
        report.problem("no tables declared");
        return;
    }

    let mut extents: Vec<(u64, u64)> = Vec::with_capacity(entries.len());
    for e in entries {
        // Untagged entries are WOFF container regions, not tables: covered,
        // and neither registered nor unknown.
        let registered = e.tag.is_some_and(is_registered_tag);
        if let Some(tag) = e.tag {
            if report.seen_tables.insert(tag) {
                let label = tag_label(&tag);
                if !registered {
                    report.unknown_tables.push(label.clone());
                }
                report.tables.push(label);
            }
            if !registered {
                report.unknown_table_bytes = report.unknown_table_bytes.saturating_add(e.length);
            }
        }
        report.largest_table_bytes = report.largest_table_bytes.max(e.length);
        let Some(end) = e.offset.checked_add(e.length) else {
            report.problem("table extent overflows");
            report.flag("table_out_of_bounds");
            continue;
        };
        if end > file_len {
            report.problem("table extends past end of file");
            report.flag("table_out_of_bounds");
            continue;
        }
        extents.push((e.offset, end));

        // A table under an unregistered tag is the one place inside the
        // directory where a payload can sit and still render, because nothing
        // reads it. `name`/`post` are scanned too: they are the format's
        // string tables, so an executable or archive signature in them is
        // unambiguous even though readable text there is expected. WOFF
        // metadata and private blocks are declared by the header, so they are
        // covered the same way: scanned for signatures, never counted.
        let kind = match e.tag {
            Some(_) if !registered => Some(RegionKind::Unclaimed),
            Some(tag) => matches!(&tag, b"name" | b"post").then_some(RegionKind::Claimed),
            None => Some(RegionKind::Claimed),
        };
        if let Some(kind) = kind {
            note_region(bytes, e.offset, end, report, kind);
        }
    }
    if extents.is_empty() {
        return;
    }

    extents.sort_unstable();
    let mut covered_to = dir_end;
    let mut gaps: u64 = 0;
    for &(start, end) in &extents {
        if start < covered_to {
            // sfnt permits nothing to overlap; sharing bytes between tables is
            // a hand-built file, and the overlap is where a payload hides.
            report.flag("overlapping_tables");
        } else {
            // Anything past the 4-byte alignment slack is a real hole. Skip
            // the slack itself so ordinary padding is not classified.
            if start - covered_to > 3 {
                note_region(bytes, covered_to, start, report, RegionKind::Unclaimed);
            }
            gaps += start - covered_to;
        }
        covered_to = covered_to.max(end);
    }

    // Tables are 4-byte aligned, so up to 3 bytes of padding between any two
    // is expected. Charge gaps only beyond that slack.
    let slack = 3 * extents.len() as u64;
    report.gap_bytes = gaps.saturating_sub(slack);
    if report.gap_bytes > 0 {
        report.flag("interior_gaps");
        report.problem("bytes not claimed by any table");
    }

    // Trailing data past the last table. `note_declared_size` may already have
    // charged this for WOFF; keep the larger of the two views.
    let trailing = file_len.saturating_sub(covered_to);
    let trailing = trailing.saturating_sub(3); // final table's alignment padding
    if trailing > 0 {
        report.trailing_bytes = report.trailing_bytes.max(trailing);
        report.flag("trailing_data");
        report.problem("data appended after last table");
        note_region(bytes, covered_to, file_len, report, RegionKind::Unclaimed);
    }

    let flags: Vec<&'static str> = report
        .tables
        .iter()
        .filter_map(|tag| match tag.as_str() {
            "DSIG" => Some("signed"),
            "fvar" => Some("variable"),
            "CBDT" | "EBDT" | "sbix" | "SVG " => Some("bitmap"),
            _ => None,
        })
        .collect();
    for flag in flags {
        report.flag(flag);
    }
}

/// Why a region is being examined, which decides how its findings count.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegionKind {
    /// Bytes no table claims: interior gaps, trailing data, and tables under
    /// an unregistered tag. These are the stowaway surface, so their size and
    /// entropy are the reported totals and every classification counts.
    Unclaimed,
    /// Claimed content whose bytes are free-form: a registered string table
    /// (`name`, `post`), where the format puts readable text on purpose, or a
    /// WOFF metadata/private block, which the header declares and which holds
    /// compressed XML or vendor data. The bytes are legitimate content — they
    /// must not inflate `font.stowaway_bytes`. Only a payload signature is
    /// worth reporting.
    Claimed,
}

/// Examine one region and fold what it contains into the stowaway verdict.
/// Classification itself is [`super::carrier::classify_region`], shared with every
/// other container so a payload is named the same way wherever it hides.
fn note_region(bytes: &[u8], start: u64, end: u64, report: &mut Report, kind: RegionKind) {
    let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
        return;
    };
    let Some(region) = bytes.get(start..end.min(bytes.len())) else {
        return;
    };
    if region.is_empty() {
        return;
    }
    let len = region.len() as u64;
    if kind == RegionKind::Unclaimed {
        report.stowaway_bytes = report.stowaway_bytes.saturating_add(len);
    }
    let Some(left) = report.scan_budget.checked_sub(len) else {
        report.problem("overlapping regions past the scan budget not examined");
        return;
    };
    report.scan_budget = left;
    if kind == RegionKind::Unclaimed {
        report.stowaway_entropy = report.stowaway_entropy.max(entropy::shannon(region));
    }
    if let Some(found) = classify_region(region)
        && (kind == RegionKind::Unclaimed || !matches!(found, "text" | "base64" | "high_entropy"))
    {
        report.stow(found);
    }
}

/// Render a four-byte sfnt version as an analyst-readable label.
fn sfnt_version_label(v: &[u8]) -> String {
    match v {
        [0x00, 0x01, 0x00, 0x00] => "1.0".to_string(),
        _ => tag_label(v),
    }
}

/// A four-character tag, with non-printable bytes escaped so a hostile tag
/// cannot inject control characters into the report.
fn tag_label(raw: &[u8]) -> String {
    let mut label = String::with_capacity(raw.len());
    for &b in raw {
        if (0x20..0x7f).contains(&b) {
            label.push(char::from(b));
        } else {
            label.push_str("\\x");
            label.push_str(&hex_encode(&[b]));
        }
    }
    label
}

/// Registered OpenType/TrueType table tags (OpenType 1.9 plus the Apple and
/// colour-font extensions in common use). Anything outside this set surfaces
/// in `font.unknown_tables` the way `png.unknown_chunks` does.
///
/// An unknown tag is a lead, never a verdict: ~5% of the fonts macOS ships
/// carry a vendor-private tag (`MERG`, `TSIV`, `MTfn`, `clas`, `BUSG`). What
/// separates those from a carrier is size, which is why
/// `font.unknown_table_bytes` is emitted alongside the count — a real private
/// tag holds tens of bytes, a payload holds kilobytes.
fn is_registered_tag(tag: [u8; 4]) -> bool {
    matches!(
        &tag,
        // Required / core
        b"cmap" | b"head" | b"hhea" | b"hmtx" | b"maxp" | b"name" | b"OS/2" | b"post"
        // TrueType outlines
        | b"cvt " | b"fpgm" | b"glyf" | b"loca" | b"prep" | b"gasp"
        // CFF outlines
        | b"CFF " | b"CFF2" | b"VORG"
        // Bitmap / colour
        | b"EBDT" | b"EBLC" | b"EBSC" | b"CBDT" | b"CBLC" | b"sbix" | b"COLR" | b"CPAL" | b"SVG "
        // Advanced typography
        | b"BASE" | b"GDEF" | b"GPOS" | b"GSUB" | b"JSTF" | b"MATH"
        // Variable fonts
        | b"avar" | b"cvar" | b"fvar" | b"gvar" | b"HVAR" | b"MVAR" | b"STAT" | b"VVAR"
        // Other registered
        | b"DSIG" | b"hdmx" | b"kern" | b"LTSH" | b"PCLT" | b"VDMX" | b"vhea" | b"vmtx"
        // Apple Advanced Typography
        | b"acnt" | b"ankr" | b"bdat" | b"bloc" | b"bsln" | b"fdsc" | b"feat" | b"fmtx"
        | b"fond" | b"just" | b"lcar" | b"ltag" | b"meta" | b"mort" | b"morx" | b"opbd"
        | b"prop" | b"trak" | b"xref" | b"Zapf" | b"kerx" | b"bhed"
        // Not in the OpenType registry, but emitted by mainstream font
        // toolchains and shipped in fonts on every desktop. Treating these as
        // unknown would make `font.unknown_table_count` fire on Font Awesome,
        // DejaVu, Charis and most libre families, and
        // `font.unknown_table_bytes` fire on Apple Color Emoji (300 KB across
        // `cntr`/`bgcl`), Arial Narrow (40 KB of `TSIV`) and Futura (35 KB of
        // `BUSG`/`SOPG`) — which would cost both metrics their meaning as
        // stowaway signals. Measured against the 566 fonts macOS ships: with
        // this set registered, none reports an unknown table at all.
        //
        // This is a name list, so it bounds what the metrics can prove: an
        // author who parks a payload under one of these tags is not
        // distinguishable by tag alone. The coverage legs (`font.gap_bytes`,
        // `font.trailing_bytes`) do not depend on tag names and still apply.
        // FontForge toolchain:
        | b"FFTM" | b"PfEd" | b"TeX " | b"BDF " | b"FFTB"
        // SIL Graphite smart fonts:
        | b"Feat" | b"Glat" | b"Gloc" | b"Silf" | b"Sill"
        // Apple: Color Emoji layer tables, SF merge data, Skia classification,
        // and the AppleMyungjo pair.
        | b"cntr" | b"bgcl" | b"MERG" | b"clas" | b"CVTM" | b"TPNM"
        // Monotype / Agfa: sign-instruction and font-metadata tables shipped
        // in the Arial, Trebuchet and Futura families.
        | b"TSIV" | b"MTfn" | b"BUSG" | b"SOPG"
    )
}

#[cfg(test)]
mod tests;
