//! Certificate-bearing detached signature sidecars.

use crate::fileid::image4_trustcache::{DER_BIT_STRING, DER_SEQUENCE, element};

/// The detached signature sidecars shipped with several content-decryption
/// clients: a single length-framed certificate, signature material, and a
/// flags field. Every boundary has to agree; neither a `.sig` name nor an
/// embedded DER prefix alone establishes this format. No authenticity or
/// trust is inferred.
pub(super) fn looks_like_certificate_signature(data: &[u8]) -> Option<()> {
    let mut rest = data.strip_prefix(&[0, 1])?;
    let cert_len = signature_varint(&mut rest)?;
    let cert = rest.get(..cert_len)?;
    rest = rest.get(cert_len..)?;
    // A SEQUENCE with a two-byte long-form length that spans the field.
    let &[DER_SEQUENCE, 0x82, hi, lo, ref body @ ..] = cert else {
        return None;
    };
    if usize::from(u16::from_be_bytes([hi, lo])) + 4 != cert.len() {
        return None;
    }
    // An X.509 Certificate has a TBS sequence, an algorithm sequence,
    // and a BIT STRING signature, with no additional top-level fields.
    let mut der = body;
    for tag in [DER_SEQUENCE, DER_SEQUENCE, DER_BIT_STRING] {
        if element(&mut der, tag)?.is_empty() {
            return None;
        }
    }
    if !der.is_empty() {
        return None;
    }
    rest = rest.strip_prefix(&[2])?;
    let signature_len = signature_varint(&mut rest)?;
    if !(128..=4096).contains(&signature_len) {
        return None;
    }
    rest = rest.get(signature_len..)?.strip_prefix(&[3])?;
    let flags_len = signature_varint(&mut rest)?;
    (flags_len == 1 && matches!(rest, [0 | 1])).then_some(())
}

/// A little-endian base-128 length, as protobuf frames its fields.
fn signature_varint(rest: &mut &[u8]) -> Option<usize> {
    let mut value = 0usize;
    for shift in (0..28).step_by(7) {
        let (&byte, tail) = rest.split_first()?;
        *rest = tail;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}
