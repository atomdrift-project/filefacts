//! xar archive signatures: who signed a macOS installer package (`.pkg`).
//!
//! A xar archive is a 28-byte big-endian header (`xar!`, header size,
//! version, compressed and uncompressed TOC lengths, checksum algorithm), a
//! zlib-compressed XML table of contents, and a heap the TOC addresses by
//! offset. The TOC's `<checksum>` names a heap range holding the hash of the
//! compressed TOC; `productsign` signs that hash, twice over:
//!
//! - `<x-signature style="CMS">`: a detached CMS `SignedData` over the
//!   checksum bytes, parsed by [`super::cms`] with its certificate bag;
//! - `<signature style="RSA">`: a bare RSA PKCS #1 v1.5 signature whose
//!   DigestInfo is the checksum itself, with the signer's certificate chain,
//!   leaf first, in `<KeyInfo><X509Data><X509Certificate>`.
//!
//! Both are published under `xar.signatures[]`, CMS first, in the
//! [`Signature`] shape with their `style` beside it.
//! A signature is `verified` only when it verifies over the checksum and the
//! checksum is the hash of this archive's TOC (`digest_matches`): one lifted
//! from another package with its checksum verifies perfectly over that
//! package's TOC. The TOC, in turn, carries each member's own checksum,
//! which is the installer's to check as it extracts; members are not read
//! here. A notarization ticket, when stapled, lives outside the archive.
//!
//! Every read is bounded: the TOC by [`MAX_TOC_BYTES`] compressed and
//! inflated, signatures by [`MAX_SIGNATURE_BYTES`], certificates by
//! [`MAX_CERTIFICATES`]; heap ranges are checked against the file.

use std::io::Cursor;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::bufread::ZlibDecoder;
use roxmltree::Node;
use serde_json::Value as JsonValue;

use super::bounded::{Limits, OnError, inflate_capped};
use super::cms::{self, DigestAlg, Failure, Signature, Verdict};
use crate::bytes::{Reader, sat_usize};
use crate::output::{Errors, Stage, Values};
use crate::value_key;

/// The fixed part of the header; `header size` may name a longer one.
const HEADER_LEN: u16 = 28;
/// TOC bytes read, compressed and inflated alike. An installer package's
/// TOC lists a handful of members in a few KiB; a large plain archive lists
/// one element per file.
const MAX_TOC_BYTES: u64 = 16 << 20;
/// Heap bytes read for one signature: an RSA signature is at most 1 KiB,
/// and a CMS blob holds a few certificates.
const MAX_SIGNATURE_BYTES: u64 = 1 << 20;
/// Certificates decoded from one `<signature>`'s `KeyInfo`. Real chains
/// carry three: the signer, its CA and the root.
const MAX_CERTIFICATES: usize = 8;
/// Base64 text of one `<X509Certificate>`: real ones are 2-3 KiB.
const MAX_CERTIFICATE_TEXT: usize = 64 << 10;

/// Read the signatures of the xar archive `bytes` into `xar.signatures`.
/// A header or TOC that does not read is recorded in `errors`.
pub(super) fn extract(bytes: &[u8], values: &mut Values, errors: &mut Errors) {
    let mut limits = Limits::default();
    match read(bytes, &mut limits) {
        Ok(signatures) if !signatures.is_empty() => {
            values.insert_key(value_key!("xar.signatures"), JsonValue::Array(signatures));
        }
        Ok(_) => {}
        Err(why) => errors.record_malformed(Stage::FormatExtract, format!("xar: {why}")),
    }
    limits.emit(values, value_key!("xar.limits"));
}

/// The header fields the signatures depend on.
struct Header {
    header_len: u16,
    toc_len: u64,
    /// `cksum_alg`: 0 none, 1 SHA-1, 2 MD5, 3 named by the TOC.
    checksum_alg: u32,
}

fn header(bytes: &[u8]) -> Result<Header, &'static str> {
    let mut r = Reader::new(bytes);
    if r.bytes(4) != Some(b"xar!".as_slice()) {
        return Err("no xar! magic");
    }
    let short = "header cut short";
    let header_len = r.u16_be().ok_or(short)?;
    // The version, then the TOC's compressed length.
    r.skip(2).ok_or(short)?;
    let toc_len = r.u64_be().ok_or(short)?;
    // The inflated length is the archive's claim; the cap bounds the read.
    r.skip(8).ok_or(short)?;
    let checksum_alg = r.u32_be().ok_or(short)?;
    if header_len < HEADER_LEN {
        return Err("header size below 28 bytes");
    }
    Ok(Header {
        header_len,
        toc_len,
        checksum_alg,
    })
}

/// The published signatures of `bytes`; `Err` when the header or TOC does
/// not read. Caps hit go to `limits`.
fn read(bytes: &[u8], limits: &mut Limits) -> Result<Vec<JsonValue>, &'static str> {
    let header = header(bytes)?;
    if header.toc_len > MAX_TOC_BYTES {
        limits.push(
            "toc",
            format!(
                "compressed TOC of {} bytes over the {MAX_TOC_BYTES}-byte cap",
                header.toc_len
            ),
        );
        return Ok(Vec::new());
    }
    let toc_start = usize::from(header.header_len);
    let heap_start = toc_start
        .checked_add(sat_usize(header.toc_len))
        .ok_or("TOC length overflows")?;
    let toc = bytes
        .get(toc_start..heap_start)
        .ok_or("TOC runs past the end of the file")?;
    let heap = bytes.get(heap_start..).unwrap_or_default();

    let inflated = inflate_capped(
        ZlibDecoder::new(Cursor::new(toc)),
        MAX_TOC_BYTES,
        OnError::Discard,
    )
    .map_err(|_| "TOC does not inflate")?;
    if inflated.truncated {
        limits.push(
            "toc",
            format!("TOC inflates past the {MAX_TOC_BYTES}-byte cap"),
        );
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(&inflated.bytes).map_err(|_| "TOC is not UTF-8")?;
    let doc = roxmltree::Document::parse(text).map_err(|e| {
        tracing::debug!(target: "filefacts::xar", stage = "toc", error = %e, "TOC XML does not parse");
        "TOC XML does not parse"
    })?;
    let root = doc.root_element();
    let toc_node = Some(root)
        .filter(|root| root.has_tag_name("xar"))
        .and_then(|root| child(root, "toc"))
        .ok_or("TOC has no <xar><toc>")?;

    let checksum = Checksum::read(toc_node, &header, toc, heap);
    let mut signatures = Vec::new();
    // CMS first: its certificate bag and signed attributes say more.
    for (tag, style) in [("x-signature", "CMS"), ("signature", "RSA")] {
        let Some(node) = toc_node
            .children()
            .find(|n| n.has_tag_name(tag) && n.attribute("style") == Some(style))
        else {
            continue;
        };
        let Some(blob) = heap_range(node, heap, MAX_SIGNATURE_BYTES, limits) else {
            continue;
        };
        let parsed = match (style, &checksum) {
            ("CMS", Some(checksum)) => cms::parse_detached_cms(blob, checksum.signed),
            ("CMS", None) => cms::parse_unbound_cms_blob(blob),
            (_, Some(checksum)) => {
                cms::parse_prehashed_rsa(&certificates(node), checksum.alg, checksum.signed, blob)
            }
            // A bare RSA signature over nothing readable proves nothing and
            // names no one the KeyInfo did not already claim.
            (_, None) => None,
        };
        let Some(mut sig) = parsed else {
            tracing::debug!(target: "filefacts::xar", stage = "signature", style, "signature does not parse");
            continue;
        };
        if let Some(checksum) = &checksum {
            bind(&mut sig, checksum.matches);
        }
        let mut sig = sig.to_json();
        if let Some(obj) = sig.as_object_mut() {
            obj.insert("style".into(), JsonValue::String(style.into()));
        }
        signatures.push(sig);
    }
    Ok(signatures)
}

/// The TOC checksum: the bytes the signatures sign, and whether they are
/// the hash of this TOC.
struct Checksum<'a> {
    alg: DigestAlg,
    signed: &'a [u8],
    matches: bool,
}

impl<'a> Checksum<'a> {
    /// `None` when the TOC names no checksum, an algorithm not read here, or
    /// a range outside the heap.
    fn read(toc_node: Node<'_, '_>, header: &Header, toc: &[u8], heap: &'a [u8]) -> Option<Self> {
        let node = child(toc_node, "checksum")?;
        let alg = match node.attribute("style")?.to_ascii_lowercase().as_str() {
            "sha1" => DigestAlg::Sha1,
            "sha256" => DigestAlg::Sha256,
            "sha384" => DigestAlg::Sha384,
            "sha512" => DigestAlg::Sha512,
            "md5" => DigestAlg::Md5,
            other => {
                tracing::debug!(target: "filefacts::xar", stage = "checksum", style = other, "TOC checksum algorithm not read");
                return None;
            }
        };
        let signed = heap_slice(node, heap, 64)?;
        // The header names the algorithm too; xar computes with the
        // header's, so a TOC naming another one is not what was hashed.
        let agrees = matches!(
            (header.checksum_alg, alg),
            (1, DigestAlg::Sha1)
                | (2, DigestAlg::Md5)
                | (3, DigestAlg::Sha256 | DigestAlg::Sha384 | DigestAlg::Sha512)
        );
        let matches = agrees && alg.digest(toc) == signed;
        if !matches {
            tracing::debug!(
                target: "filefacts::xar",
                stage = "checksum",
                header_alg = header.checksum_alg,
                style = alg.label(),
                "TOC checksum is not the hash of the TOC"
            );
        }
        Some(Self {
            alg,
            signed,
            matches,
        })
    }
}

/// Fold whether the checksum `sig` signs is this TOC's into `sig`: a
/// signature over another TOC's checksum is not this archive's.
fn bind(sig: &mut Signature, matches: bool) {
    sig.digest_matches = Some(matches);
    if !matches && sig.is_verified() {
        sig.verified = Some(Verdict::Failed(Failure::TocChecksumMismatch));
    }
}

/// The first child element of `node` named `name`.
fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|n| n.has_tag_name(name))
}

/// The number in child element `name` of `node`.
fn number(node: Node<'_, '_>, name: &str) -> Option<u64> {
    child(node, name)?.text()?.trim().parse().ok()
}

/// The heap bytes `node`'s `<offset>` and `<size>` name, when they lie in
/// `heap` and are at most `max` bytes.
fn heap_slice<'a>(node: Node<'_, '_>, heap: &'a [u8], max: u64) -> Option<&'a [u8]> {
    let offset = number(node, "offset")?;
    let size = number(node, "size").filter(|&size| size <= max)?;
    let end = offset.checked_add(size)?;
    heap.get(usize::try_from(offset).ok()?..usize::try_from(end).ok()?)
}

/// [`heap_slice`] for a signature, recording an oversized one in `limits`.
fn heap_range<'a>(
    node: Node<'_, '_>,
    heap: &'a [u8],
    max: u64,
    limits: &mut Limits,
) -> Option<&'a [u8]> {
    if number(node, "size").is_some_and(|size| size > max) {
        limits.push("signature", format!("signature over the {max}-byte cap"));
        return None;
    }
    let slice = heap_slice(node, heap, max);
    if slice.is_none() {
        tracing::debug!(target: "filefacts::xar", stage = "signature", "signature range missing or outside the file");
    }
    slice
}

/// The DER certificates in `node`'s `KeyInfo`, in order, up to
/// [`MAX_CERTIFICATES`]. A certificate that does not decode ends the list:
/// the ones after it no longer stand in a known place in the chain.
fn certificates(node: Node<'_, '_>) -> Vec<Vec<u8>> {
    node.descendants()
        .filter(|n| n.has_tag_name("X509Certificate"))
        .take(MAX_CERTIFICATES)
        .map_while(|n| {
            let text = n.text().filter(|t| t.len() <= MAX_CERTIFICATE_TEXT)?;
            let compact: String = text.split_ascii_whitespace().collect();
            STANDARD.decode(compact).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests;
