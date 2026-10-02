//! Authenticode image hash (a.k.a. "Authentihash") — the digest that
//! a PE Authenticode signature actually authenticates.
//!
//! The Authenticode signing spec defines the image hash as a digest
//! over the PE file's bytes with three holes punched in it:
//!
//! 1. The 4-byte CheckSum field in the optional header.
//! 2. The 8-byte Certificate Table entry in the data-directory array
//!    (the `(RVA, Size)` pair pointing at the signature itself).
//! 3. The bytes of the Certificate Table at the tail of the file —
//!    the signature can't authenticate itself.
//!
//! The hash is computed by feeding the hasher: header bytes (with the
//! two holes), then each section in `PointerToRawData` order, then
//! any trailing overlay bytes that sit between the sections and the
//! cert table. The same byte layout works for SHA-1, SHA-256,
//! SHA-384, and SHA-512 — only the hash function changes, so every
//! wanted digest is fed from one walk over the regions.
//!
//! Emits:
//! - `pe.image_hash.sha256` — hex digest, always: it is the Authentihash
//!   catalogues and threat intelligence key on.
//! - `pe.image_hash.sha1` / `.sha384` / `.sha512` — only when a signature
//!   on the image (nested ones included) commits to that algorithm, which
//!   is what `pe_signature_trust` compares against. Nothing else reads them.
//! - `pe.overlay_padding` (metric) — bytes between sections-end and
//!   the cert table that the signature also covers. Non-zero implies
//!   data was appended to the binary post-signing-time but inside the
//!   region the signature authenticates.
//! - `pe.image_hash_skipped` (metric) — the section table makes the image
//!   hash cover more than [`MAX_HASHED_FILE_MULTIPLE`] times the file, which
//!   only overlapping raw ranges can do; no digest is emitted.

use crate::metric;
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};

use goblin::pe::PE;
use goblin::pe::optional_header::{
    MAGIC_32, MAGIC_64, OFFSET_WINDOWS_FIELDS_32_CHECKSUM, OFFSET_WINDOWS_FIELDS_64_CHECKSUM,
    SIZEOF_STANDARD_FIELDS_32, SIZEOF_STANDARD_FIELDS_64, SIZEOF_WINDOWS_FIELDS_32,
    SIZEOF_WINDOWS_FIELDS_64,
};

use crate::formats::common::hex_encode;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Authenticode digest algorithm. `Sha256` is the modern default;
/// `Sha1` survives as the algorithm used on dual-signed legacy
/// binaries; `Sha384` / `Sha512` exist for forward compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeHashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl PeHashAlg {
    const ALL: [Self; 4] = [Self::Sha1, Self::Sha256, Self::Sha384, Self::Sha512];

    /// Lowercase short name used in emitted key paths and OID labels.
    fn name(self) -> &'static str {
        match self {
            PeHashAlg::Sha1 => "sha1",
            PeHashAlg::Sha256 => "sha256",
            PeHashAlg::Sha384 => "sha384",
            PeHashAlg::Sha512 => "sha512",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.name() == name)
    }

    fn hasher(self) -> Box<dyn DynDigest> {
        match self {
            PeHashAlg::Sha1 => Box::new(Sha1::new()),
            PeHashAlg::Sha256 => Box::new(Sha256::new()),
            PeHashAlg::Sha384 => Box::new(Sha384::new()),
            PeHashAlg::Sha512 => Box::new(Sha512::new()),
        }
    }
}

/// The byte ranges that an Authenticode hash is computed over. Built
/// once per PE; reused across hash algorithms so the section-walking
/// logic isn't duplicated.
struct Regions {
    ranges: Vec<core::ops::Range<usize>>,
    /// Overlay padding — bytes between the last section and the cert
    /// table that the signature also authenticates. Non-zero means
    /// data was added inside the signed region post-link.
    overlay_padding: u64,
}

impl Regions {
    /// Bytes the image hash covers, counting overlapping ranges each time.
    fn hashed_len(&self) -> u64 {
        self.ranges.iter().map(|r| r.len() as u64).sum()
    }

    /// Hex digests for `algs`, all fed from one walk over the ranges.
    /// `None` when a range falls outside `bytes`; `derive_regions` only
    /// builds in-bounds ranges, so that means a caller passed other bytes.
    fn digests(&self, bytes: &[u8], algs: &[PeHashAlg]) -> Option<Vec<(PeHashAlg, String)>> {
        let mut hashers: Vec<_> = algs.iter().map(|&alg| (alg, alg.hasher())).collect();
        for range in &self.ranges {
            let chunk = bytes.get(range.clone())?;
            for (_, hasher) in &mut hashers {
                hasher.update(chunk);
            }
        }
        Some(
            hashers
                .into_iter()
                .map(|(alg, hasher)| (alg, hex_encode(&hasher.finalize())))
                .collect(),
        )
    }
}

/// Most bytes the image hash may cover, as a multiple of the file size.
/// A canonical layout covers each byte at most once; only section headers
/// whose raw ranges overlap can exceed this, and a crafted table of
/// 96 sections over one region would otherwise hash the file 96 times per
/// algorithm. A capped digest would be a wrong digest, so past the cap none
/// is emitted.
const MAX_HASHED_FILE_MULTIPLE: u64 = 4;

/// Emit `pe.image_hash.*` digests and `pe.overlay_padding` for a
/// parsed PE. No-op when the optional header is missing or any of
/// the hashed regions overflow the file — Authenticode strictly
/// requires the canonical layout.
///
/// Runs after the Authenticode parse, so the algorithms the image's
/// signatures commit to are already in `values`.
pub(super) fn extract(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    if let Some(regions) = derive_regions(pe, bytes) {
        emit(&regions, bytes, values, metrics);
    }
}

fn emit(regions: &Regions, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    if regions.overlay_padding > 0 {
        metrics.insert(
            metric!("pe.overlay_padding"),
            regions.overlay_padding as f64,
        );
    }
    if regions.hashed_len() > (bytes.len() as u64).saturating_mul(MAX_HASHED_FILE_MULTIPLE) {
        metrics.insert(metric!("pe.image_hash_skipped"), 1.0);
        return;
    }
    let algs = wanted_algorithms(values);
    let Some(digests) = regions.digests(bytes, &algs) else {
        return;
    };
    for (alg, digest) in digests {
        values.insert_key_at(
            value_key!("pe.image_hash"),
            alg.name(),
            JsonValue::String(digest),
        );
    }
}

/// SHA-256 always, plus every algorithm a signature on the image commits
/// to (`signature_digest_algorithm`, nested signatures included).
fn wanted_algorithms(values: &Values) -> Vec<PeHashAlg> {
    fn claimed(sig: &JsonValue, out: &mut Vec<PeHashAlg>) {
        if let Some(alg) = sig
            .get("signature_digest_algorithm")
            .and_then(JsonValue::as_str)
            .and_then(PeHashAlg::from_name)
            && !out.contains(&alg)
        {
            out.push(alg);
        }
        for nested in sig
            .get("nested")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
        {
            claimed(nested, out);
        }
    }
    let mut algs = vec![PeHashAlg::Sha256];
    for sig in values
        .get_key(value_key!("pe.signatures"))
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
    {
        claimed(sig, &mut algs);
    }
    algs
}

/// Locate the holes in the header (checksum field, cert-table entry)
/// and compute the section + overlay ranges that an Authenticode
/// signature would authenticate. Returns `None` for any layout that
/// can't be hashed canonically — partial extraction is a footgun.
fn derive_regions(pe: &PE<'_>, bytes: &[u8]) -> Option<Regions> {
    let opt = pe.header.optional_header.as_ref()?;
    let pe_offset = pe.header.dos_header.pe_pointer as usize;
    let optional_header_offset = pe_offset.checked_add(4 + 20)?;

    // The optional header layout differs between PE32 and PE32+ — the
    // 32-bit form omits the high half of the image-base, shifting the
    // checksum field and everything after it by 12 bytes. We resolve
    // the two interesting offsets — CheckSum and the Certificate Table
    // data-directory slot — relative to the optional header start.
    let (checksum_offset, cert_dir_offset) = match opt.standard_fields.magic {
        MAGIC_32 => {
            let sf = optional_header_offset.checked_add(SIZEOF_STANDARD_FIELDS_32)?;
            // CheckSum is at offset 0x40 inside windows_fields on PE32.
            let checksum = sf.checked_add(OFFSET_WINDOWS_FIELDS_32_CHECKSUM)?;
            // Data-directories follow windows_fields; cert table is slot 4 (× 8 = 32).
            let cert_dir = sf
                .checked_add(SIZEOF_WINDOWS_FIELDS_32)?
                .checked_add(CERT_TABLE_SLOT_BYTES)?;
            (checksum, cert_dir)
        }
        MAGIC_64 => {
            let sf = optional_header_offset.checked_add(SIZEOF_STANDARD_FIELDS_64)?;
            let checksum = sf.checked_add(OFFSET_WINDOWS_FIELDS_64_CHECKSUM)?;
            let cert_dir = sf
                .checked_add(SIZEOF_WINDOWS_FIELDS_64)?
                .checked_add(CERT_TABLE_SLOT_BYTES)?;
            (checksum, cert_dir)
        }
        _ => return None,
    };

    let size_of_headers = opt.windows_fields.size_of_headers as usize;
    if checksum_offset + 4 > bytes.len()
        || cert_dir_offset + 8 > bytes.len()
        || size_of_headers > bytes.len()
    {
        return None;
    }
    // Sanity: the two holes must sit inside the header, in order.
    if checksum_offset + 4 > cert_dir_offset || cert_dir_offset + 8 > size_of_headers {
        return None;
    }

    let mut ranges: Vec<core::ops::Range<usize>> = Vec::with_capacity(6);
    ranges.push(0..checksum_offset);
    ranges.push((checksum_offset + 4)..cert_dir_offset);
    ranges.push((cert_dir_offset + 8)..size_of_headers);

    // Sections in PointerToRawData order — virtual layout has no
    // bearing on the hash. Sections with raw_size = 0 are pure-BSS
    // and contribute nothing.
    let mut by_raw_offset: Vec<&goblin::pe::section_table::SectionTable> = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data > 0)
        .collect();
    by_raw_offset.sort_by_key(|s| s.pointer_to_raw_data);

    let mut sum_hashed = size_of_headers as u64;
    for s in &by_raw_offset {
        let start = s.pointer_to_raw_data as usize;
        let end = start.checked_add(s.size_of_raw_data as usize)?;
        if end > bytes.len() {
            return None;
        }
        ranges.push(start..end);
        sum_hashed = sum_hashed.saturating_add(u64::from(s.size_of_raw_data));
    }

    // Trailing overlay between `sum_hashed` and the cert table at
    // file-end. The signature blob itself sits at `file_size -
    // cert_table_size .. file_size` and is excluded.
    let cert_table_size = opt
        .data_directories
        .data_directories
        .get(4)
        .and_then(|slot| slot.as_ref())
        .map(|(_, dd)| u64::from(dd.size))
        .unwrap_or(0);
    let file_size = bytes.len() as u64;
    let mut overlay_padding = 0_u64;
    if file_size > sum_hashed.saturating_add(cert_table_size) {
        let extra_start = crate::bytes::sat_usize(sum_hashed);
        let extra_end = crate::bytes::sat_usize(file_size - cert_table_size);
        if extra_start < extra_end && extra_end <= bytes.len() {
            ranges.push(extra_start..extra_end);
            overlay_padding = (extra_end - extra_start) as u64;
        }
    }

    Some(Regions {
        ranges,
        overlay_padding,
    })
}

/// Number of bytes from the start of the data-directory table to the
/// Certificate Table slot: 4 entries × 8 bytes.
const CERT_TABLE_SLOT_BYTES: usize = 4 * 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    fn extract_values(bytes: &[u8]) -> (Values, Metrics) {
        let mut out = crate::formats::Sinks::default();
        crate::formats::pe::extract(bytes, out.ctx()).unwrap();
        let crate::formats::Sinks {
            values: v,
            metrics: m,
            ..
        } = out;
        (v, m)
    }

    /// SHA-256 always lands for a parseable PE — the fixture is an unsigned
    /// 64-bit MSVC build that uses the canonical PE layout — and the other
    /// algorithms only when a signature commits to them.
    #[test]
    fn image_hashes_emitted_for_well_formed_pe() {
        let bytes = fixture("test.exe");
        let (v, _) = extract_values(&bytes);
        let h = v
            .get("pe.image_hash.sha256")
            .and_then(|x| x.as_str())
            .expect("pe.image_hash.sha256 missing");
        assert_eq!(h.len(), hex_len("sha256"));
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {h}");
        for alg in ["sha1", "sha384", "sha512"] {
            assert!(
                v.get(&format!("pe.image_hash.{alg}")).is_none(),
                "{alg} computed for an unsigned image"
            );
        }
    }

    /// Every algorithm a signature names, nested ones included, is computed
    /// alongside SHA-256 in the same walk.
    #[test]
    fn claimed_algorithms_are_hashed() {
        let bytes = fixture("test.exe");
        let pe = goblin::pe::PE::parse(&bytes).expect("parse");
        let mut v = Values::new();
        v.insert(
            "pe.signatures",
            serde_json::json!([{
                "signature_digest_algorithm": "sha1",
                "nested": [{"signature_digest_algorithm": "sha512"}],
            }]),
        );
        let mut m = Metrics::new();
        super::extract(&pe, &bytes, &mut v, &mut m);
        for alg in ["sha1", "sha256", "sha512"] {
            let h = v
                .get(&format!("pe.image_hash.{alg}"))
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("{alg} missing"));
            assert_eq!(h.len(), hex_len(alg));
        }
        assert!(v.get("pe.image_hash.sha384").is_none());
        // The SHA-1 digest is the one the region walker has always produced.
        assert_eq!(
            v.get("pe.image_hash.sha1").and_then(|x| x.as_str()),
            Some("444ac776b5ecd5c48d9c6254f10b5f6d5aae5567"),
        );
    }

    /// Section headers whose raw ranges all cover the same bytes would make
    /// the hash walk the file once per section. Past the cap no digest is
    /// emitted and the skip is recorded.
    #[test]
    fn overlapping_sections_past_the_cap_are_not_hashed() {
        let bytes = fixture("test.exe");
        let pe = goblin::pe::PE::parse(&bytes).expect("parse");
        let mut regions = derive_regions(&pe, &bytes).expect("regions");
        // What `derive_regions` yields for a table of sections whose raw
        // ranges all cover the whole file.
        regions
            .ranges
            .extend(std::iter::repeat_n(0..bytes.len(), 8));
        assert!(regions.hashed_len() > bytes.len() as u64 * MAX_HASHED_FILE_MULTIPLE);
        let mut v = Values::new();
        let mut m = Metrics::new();
        emit(&regions, &bytes, &mut v, &mut m);
        assert!(v.get("pe.image_hash.sha256").is_none());
        assert_eq!(m.get("pe.image_hash_skipped"), Some(1.0));
    }

    /// Pin the SHA-256 image hash of `test.exe` to its known value. Any
    /// unintended change in the region walker — the number of bytes
    /// hashed, the order, the holes punched in the header — will produce
    /// a different digest and trip this test. Regenerate by running
    /// `cargo run --bin filefacts -- tests/fixtures/test.exe` if the
    /// fixture itself is ever replaced.
    #[test]
    fn image_hashes_test_exe_pinned_values() {
        let bytes = fixture("test.exe");
        let (v, _) = extract_values(&bytes);
        assert_eq!(
            v.get("pe.image_hash.sha256").and_then(|x| x.as_str()),
            Some("218103c5f4caf14299d61dab1cced6f6d6b6cd47ee6cfba204856fb1ea205120"),
        );
    }

    /// Determinism — two extractions over the same bytes must produce
    /// the same digest. Guards against accidental non-determinism in
    /// the region walker (e.g. iterating a HashMap of sections).
    #[test]
    fn image_hash_is_deterministic() {
        let bytes = fixture("test.exe");
        let (v1, _) = extract_values(&bytes);
        let (v2, _) = extract_values(&bytes);
        for alg in ["sha1", "sha256", "sha384", "sha512"] {
            let k = format!("pe.image_hash.{alg}");
            assert_eq!(v1.get(&k), v2.get(&k));
        }
    }

    /// Changing the checksum field in the header must NOT change the
    /// image hash — Authenticode explicitly excludes those four
    /// bytes. This is the load-bearing property of the algorithm
    /// (otherwise every Windows PE that has its CheckSum recomputed
    /// post-link would invalidate its own signature).
    #[test]
    fn image_hash_ignores_checksum_field() {
        let mut bytes = fixture("test.exe");
        let pe_offset =
            u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
        // CheckSum lives 0x40 bytes into the windows_fields; for a
        // PE32+ test.exe that's `pe_offset + 24 + SIZEOF_STANDARD_FIELDS_64 + 0x40`.
        // We derive it by re-running the region walker rather than
        // hard-coding the offset.
        let pe = goblin::pe::PE::parse(&bytes).expect("parse");
        let opt = pe.header.optional_header.as_ref().expect("opt");
        let optional_header_offset = pe_offset + 4 + 20;
        let checksum_offset = match opt.standard_fields.magic {
            MAGIC_32 => {
                optional_header_offset
                    + SIZEOF_STANDARD_FIELDS_32
                    + OFFSET_WINDOWS_FIELDS_32_CHECKSUM
            }
            MAGIC_64 => {
                optional_header_offset
                    + SIZEOF_STANDARD_FIELDS_64
                    + OFFSET_WINDOWS_FIELDS_64_CHECKSUM
            }
            _ => panic!("unsupported magic"),
        };
        let (v_before, _) = extract_values(&bytes);
        // Flip every bit in the checksum field.
        bytes[checksum_offset] ^= 0xff;
        bytes[checksum_offset + 1] ^= 0xff;
        bytes[checksum_offset + 2] ^= 0xff;
        bytes[checksum_offset + 3] ^= 0xff;
        let (v_after, _) = extract_values(&bytes);
        for alg in ["sha1", "sha256", "sha384", "sha512"] {
            let k = format!("pe.image_hash.{alg}");
            assert_eq!(
                v_before.get(&k),
                v_after.get(&k),
                "{k} changed when checksum field was perturbed",
            );
        }
    }

    /// `derive_regions` returns `None` whenever the optional header
    /// is missing, the header sentinel sits past EOF, or any of the
    /// hash ranges would overflow the file. The `extract` entry
    /// point uses that signal to skip emitting any
    /// `pe.image_hash.*` keys; this test exercises the `None` paths
    /// directly so we don't need a header-only fixture (which would
    /// fail the upstream PE parse anyway).
    #[test]
    fn derive_regions_rejects_truncated_inputs() {
        // Valid PE → derive_regions returns Some(...) on a real
        // fixture; the negative cases are easier to drive by feeding
        // truncated copies of the real bytes back through goblin.
        let full = fixture("test.exe");
        let pe = goblin::pe::PE::parse(&full).expect("fixture parses");
        assert!(
            super::derive_regions(&pe, &full).is_some(),
            "regions should derive for the full fixture",
        );
        // Truncate to less than `size_of_headers` — every header
        // range bound should fail the in-range check.
        let truncated = &full[..0x100];
        assert!(
            super::derive_regions(&pe, truncated).is_none(),
            "truncated bytes should fail region derivation",
        );
    }

    fn hex_len(alg: &str) -> usize {
        match alg {
            "sha1" => 40,
            "sha256" => 64,
            "sha384" => 96,
            "sha512" => 128,
            _ => unreachable!(),
        }
    }
}
