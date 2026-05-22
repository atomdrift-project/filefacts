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
//! SHA-384, and SHA-512 — only the hash function changes.
//!
//! Emits:
//! - `pe.image_hash.sha1` / `.sha256` / `.sha384` / `.sha512` — hex digests
//! - `pe.overlay_padding` (metric) — bytes between sections-end and
//!   the cert table that the signature also covers. Non-zero implies
//!   data was appended to the binary post-signing-time but inside the
//!   region the signature authenticates.

use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};

use goblin::pe::optional_header::{
    MAGIC_32, MAGIC_64, OFFSET_WINDOWS_FIELDS_32_CHECKSUM, OFFSET_WINDOWS_FIELDS_64_CHECKSUM,
    SIZEOF_STANDARD_FIELDS_32, SIZEOF_STANDARD_FIELDS_64, SIZEOF_WINDOWS_FIELDS_32,
    SIZEOF_WINDOWS_FIELDS_64,
};
use goblin::pe::PE;

use crate::formats::common::{hex_encode, put_str};
use crate::output::{Metrics, Values};

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
    /// Lowercase short name used in emitted key paths and OID labels.
    fn name(self) -> &'static str {
        match self {
            PeHashAlg::Sha1 => "sha1",
            PeHashAlg::Sha256 => "sha256",
            PeHashAlg::Sha384 => "sha384",
            PeHashAlg::Sha512 => "sha512",
        }
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
    fn digest(&self, bytes: &[u8], alg: PeHashAlg) -> String {
        let mut hasher = alg.hasher();
        for range in &self.ranges {
            hasher.update(&bytes[range.clone()]);
        }
        hex_encode(&hasher.finalize())
    }
}

/// Emit `pe.image_hash.*` digests and `pe.overlay_padding` for a
/// parsed PE. No-op when the optional header is missing or any of
/// the hashed regions overflow the file — Authenticode strictly
/// requires the canonical layout.
pub(super) fn extract(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(regions) = derive_regions(pe, bytes) else {
        return;
    };
    for alg in [
        PeHashAlg::Sha1,
        PeHashAlg::Sha256,
        PeHashAlg::Sha384,
        PeHashAlg::Sha512,
    ] {
        put_str(
            values,
            &format!("pe.image_hash.{}", alg.name()),
            regions.digest(bytes, alg),
        );
    }
    if regions.overlay_padding > 0 {
        metrics.insert("pe.overlay_padding", regions.overlay_padding as f64);
    }
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
        sum_hashed = sum_hashed.saturating_add(s.size_of_raw_data as u64);
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
    if file_size > sum_hashed + cert_table_size {
        let extra_start = sum_hashed as usize;
        let extra_end = (file_size - cert_table_size) as usize;
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
    use crate::output::Errors;
    use crate::Strings;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("../cleave/tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    fn extract_values(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut errors = Errors::new();
        crate::formats::pe::extract(
            bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut functions,
            &mut errors,
        )
        .unwrap();
        (v, m)
    }

    /// All four hashes should land for a parseable PE — the fixture
    /// is a 64-bit MSVC build that uses the canonical PE layout.
    #[test]
    fn image_hashes_emitted_for_well_formed_pe() {
        let bytes = fixture("test.exe");
        let (v, _) = extract_values(&bytes);
        for alg in ["sha1", "sha256", "sha384", "sha512"] {
            let key = format!("pe.image_hash.{alg}");
            let h = v
                .get(&key)
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("{key} missing"));
            assert_eq!(
                h.len(),
                hex_len(alg),
                "{key} wrong length: got {} expected {}",
                h.len(),
                hex_len(alg),
            );
            assert!(
                h.chars().all(|c| c.is_ascii_hexdigit()),
                "{key} not lowercase hex: {h}",
            );
        }
    }

    /// Pin the SHA-1 and SHA-256 image hashes of `test.exe` to their
    /// known values. Any unintended change in the region walker — the
    /// number of bytes hashed, the order, the holes punched in the
    /// header — will produce a different digest and trip this test.
    /// Regenerate by running `cargo run --bin filefacts -- ../cleave/tests/fixtures/test.exe`
    /// if the fixture itself is ever replaced.
    #[test]
    fn image_hashes_test_exe_pinned_values() {
        let bytes = fixture("test.exe");
        let (v, _) = extract_values(&bytes);
        assert_eq!(
            v.get("pe.image_hash.sha1").and_then(|x| x.as_str()),
            Some("444ac776b5ecd5c48d9c6254f10b5f6d5aae5567"),
        );
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
