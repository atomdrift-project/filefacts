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
//!   is what the trust judgement compares against. Nothing else reads them.
//! - `pe.overlay_padding` (metric) — bytes between sections-end and
//!   the cert table that the signature also covers. Non-zero implies
//!   data was appended to the binary post-signing-time but inside the
//!   region the signature authenticates.
//! - `pe.image_hash_skipped` (metric) — the section table makes the image
//!   hash cover more than [`MAX_HASHED_FILE_MULTIPLE`] times the file, which
//!   only overlapping raw ranges can do; no digest is emitted.

use std::ops::Range;

use goblin::pe::PE;
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::formats::cms::Signature;
use crate::formats::common::hex_encode;
use crate::formats::pe::layout::{self, CERTIFICATE_DIRECTORY};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// An Authenticode digest algorithm. SHA-256 is the modern default, SHA-1
/// the one dual-signed binaries carry beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    const ALL: [Self; 4] = [Self::Sha1, Self::Sha256, Self::Sha384, Self::Sha512];

    /// The label signatures name the algorithm by, and the key under
    /// `pe.image_hash`.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    pub(super) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.name() == name)
    }

    fn hasher(self) -> Box<dyn DynDigest> {
        match self {
            Self::Sha1 => Box::new(Sha1::new()),
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha384 => Box::new(Sha384::new()),
            Self::Sha512 => Box::new(Sha512::new()),
        }
    }
}

/// The recomputed image digests, hex, by algorithm.
#[derive(Debug, Default)]
pub(super) struct ImageHashes(pub(super) Vec<(HashAlg, String)>);

impl ImageHashes {
    /// The digest under the algorithm a signature names, if recomputed.
    pub(super) fn get(&self, name: &str) -> Option<&str> {
        let alg = HashAlg::from_name(name)?;
        self.0
            .iter()
            .find(|(have, _)| *have == alg)
            .map(|(_, digest)| digest.as_str())
    }
}

/// The byte ranges that an Authenticode hash is computed over. Built
/// once per PE; reused across hash algorithms so the section-walking
/// logic isn't duplicated.
struct Regions {
    ranges: Vec<Range<usize>>,
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
    fn digests(&self, bytes: &[u8], algs: &[HashAlg]) -> Option<ImageHashes> {
        let mut hashers: Vec<_> = algs.iter().map(|&alg| (alg, alg.hasher())).collect();
        for range in &self.ranges {
            let chunk = bytes.get(range.clone())?;
            for (_, hasher) in &mut hashers {
                hasher.update(chunk);
            }
        }
        Some(ImageHashes(
            hashers
                .into_iter()
                .map(|(alg, hasher)| (alg, hex_encode(&hasher.finalize())))
                .collect(),
        ))
    }
}

/// Most bytes the image hash may cover, as a multiple of the file size.
/// A canonical layout covers each byte at most once; only section headers
/// whose raw ranges overlap can exceed this, and a crafted table of
/// 96 sections over one region would otherwise hash the file 96 times per
/// algorithm. A capped digest would be a wrong digest, so past the cap none
/// is emitted.
const MAX_HASHED_FILE_MULTIPLE: u64 = 4;

/// Emit `pe.image_hash.*` digests and `pe.overlay_padding` for a parsed PE,
/// hashing SHA-256 and every algorithm `signatures` commit to, and return
/// the digests. Empty when the layout cannot be hashed canonically:
/// Authenticode strictly requires it, and partial extraction is a footgun.
pub(super) fn extract(
    pe: &PE<'_>,
    bytes: &[u8],
    signatures: &[Signature],
    values: &mut Values,
    metrics: &mut Metrics,
) -> ImageHashes {
    let Some(regions) = derive_regions(pe, bytes) else {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "image-hash",
            len = bytes.len(),
            "header or sections not in canonical layout; no image hash"
        );
        return ImageHashes::default();
    };
    emit(
        &regions,
        bytes,
        &wanted_algorithms(signatures),
        values,
        metrics,
    )
}

fn emit(
    regions: &Regions,
    bytes: &[u8],
    algs: &[HashAlg],
    values: &mut Values,
    metrics: &mut Metrics,
) -> ImageHashes {
    if regions.overlay_padding > 0 {
        metrics.insert(
            metric!("pe.overlay_padding"),
            regions.overlay_padding as f64,
        );
    }
    if regions.hashed_len() > (bytes.len() as u64).saturating_mul(MAX_HASHED_FILE_MULTIPLE) {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "image-hash",
            len = bytes.len(),
            hashed = regions.hashed_len(),
            "overlapping sections would hash the file many times over; skipped"
        );
        metrics.insert(metric!("pe.image_hash_skipped"), 1.0);
        return ImageHashes::default();
    }
    let Some(hashes) = regions.digests(bytes, algs) else {
        return ImageHashes::default();
    };
    for (alg, digest) in &hashes.0 {
        values.insert_key_at(
            value_key!("pe.image_hash"),
            alg.name(),
            JsonValue::String(digest.clone()),
        );
    }
    hashes
}

/// SHA-256 always, plus every algorithm a signature on the image commits
/// to (`signature_digest_algorithm`, nested signatures included).
fn wanted_algorithms(signatures: &[Signature]) -> Vec<HashAlg> {
    fn claimed(sig: &Signature, out: &mut Vec<HashAlg>) {
        if let Some(alg) = sig
            .signature_digest_algorithm
            .as_deref()
            .and_then(HashAlg::from_name)
            && !out.contains(&alg)
        {
            out.push(alg);
        }
        for nested in &sig.nested {
            claimed(nested, out);
        }
    }
    let mut algs = vec![HashAlg::Sha256];
    for sig in signatures {
        claimed(sig, &mut algs);
    }
    algs
}

/// Locate the holes in the header (checksum field, cert-table entry)
/// and compute the section + overlay ranges that an Authenticode
/// signature would authenticate. Returns `None` for any layout that
/// can't be hashed canonically.
fn derive_regions(pe: &PE<'_>, bytes: &[u8]) -> Option<Regions> {
    let opt = pe.header.optional_header.as_ref()?;
    let pe_pointer = pe.header.dos_header.pe_pointer as usize;
    let magic = opt.standard_fields.magic;
    let checksum_offset = layout::checksum_offset(pe_pointer, magic)?;
    let cert_dir_offset = layout::data_directory_offset(pe_pointer, magic, CERTIFICATE_DIRECTORY)?;

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

    let mut ranges: Vec<Range<usize>> = Vec::with_capacity(6);
    ranges.push(0..checksum_offset);
    ranges.push((checksum_offset + 4)..cert_dir_offset);
    ranges.push((cert_dir_offset + 8)..size_of_headers);

    // Sections in PointerToRawData order — virtual layout has no
    // bearing on the hash. Sections with raw_size = 0 are pure-BSS
    // and contribute nothing.
    let mut by_raw_offset: Vec<_> = pe
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
        .get_certificate_table()
        .map_or(0, |dd| u64::from(dd.size));
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

#[cfg(test)]
mod tests;
