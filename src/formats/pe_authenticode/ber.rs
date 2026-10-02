//! BER to DER normalization for CMS blobs.
//!
//! Apple encodes the SignedData in a Mach-O code signature with BER
//! indefinite lengths, and the strict-DER `cms` crate rejects that at the
//! first length byte. Normalizing re-encodes every indefinite or non-minimal
//! length as a minimal definite one and folds constructed OCTET STRINGs into a
//! single primitive string, which covers what Apple and OpenSSL's streaming
//! encoder produce. Other BER freedoms (unsorted SET OF, non-canonical
//! booleans) are left alone; a blob relying on them still fails the strict
//! decode afterwards, which is the right outcome for a verifier.
//!
//! The signed attributes a CMS signature covers are DER by rule, so this
//! changes nothing a signature check depends on.

/// Nesting deeper than any CMS structure needs. Bounds recursion on a blob of
/// nothing but indefinite-length headers.
const MAX_DEPTH: usize = 64;

/// Universal tag of a primitive OCTET STRING, and its constructed form.
const OCTET_STRING: u8 = 0x04;
const OCTET_STRING_CONSTRUCTED: u8 = 0x24;

/// The DER form of the first element in `ber`, or `None` when it is not
/// well-formed BER within [`MAX_DEPTH`]. Bytes after the element (the zero
/// padding a code-signature blob carries) are ignored.
pub(super) fn to_der(ber: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(ber.len());
    element(ber, &mut out, 0)?;
    Some(out)
}

/// Read one element from `input`, append its DER form to `out`, and return
/// the bytes after it.
fn element<'a>(input: &'a [u8], out: &mut Vec<u8>, depth: usize) -> Option<&'a [u8]> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (&tag, rest) = input.split_first()?;
    // High-tag-number form (low five bits all set) never occurs in CMS.
    if tag & 0x1F == 0x1F {
        return None;
    }
    let constructed = tag & 0x20 != 0;
    let (&first, mut rest) = rest.split_first()?;
    if first == 0x80 {
        // Indefinite length: children up to an end-of-contents marker. Only
        // constructed encodings may use it.
        if !constructed {
            return None;
        }
        let mut body = Vec::new();
        loop {
            if let [0, 0, tail @ ..] = rest {
                rest = tail;
                break;
            }
            rest = element(rest, &mut body, depth + 1)?;
        }
        emit(tag, &body, out)?;
        return Some(rest);
    }
    let (len, rest) = definite_length(first, rest)?;
    let content = rest.get(..len)?;
    let tail = rest.get(len..)?;
    if constructed {
        let mut body = Vec::new();
        let mut inner = content;
        while !inner.is_empty() {
            inner = element(inner, &mut body, depth + 1)?;
        }
        emit(tag, &body, out)?;
    } else {
        emit(tag, content, out)?;
    }
    Some(tail)
}

/// Decode a definite length whose first octet is `first`.
fn definite_length(first: u8, rest: &[u8]) -> Option<(usize, &[u8])> {
    if first < 0x80 {
        return Some((usize::from(first), rest));
    }
    let count = usize::from(first & 0x7F);
    // 0x80 is indefinite (handled by the caller); five or more length octets
    // would describe a blob larger than any input this sees.
    if count == 0 || count > 4 {
        return None;
    }
    let (octets, rest) = rest.split_at_checked(count)?;
    let len = octets
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    Some((len, rest))
}

/// Append `tag`, a minimal definite length, and `content`. A constructed
/// OCTET STRING, whose `content` is already-normalized primitive chunks, is
/// folded into one primitive string as DER requires.
fn emit(tag: u8, content: &[u8], out: &mut Vec<u8>) -> Option<()> {
    if tag == OCTET_STRING_CONSTRUCTED {
        let mut joined = Vec::with_capacity(content.len());
        let mut chunks = content;
        while !chunks.is_empty() {
            let (&chunk_tag, rest) = chunks.split_first()?;
            if chunk_tag != OCTET_STRING {
                return None;
            }
            let (&first, rest) = rest.split_first()?;
            let (len, rest) = definite_length(first, rest)?;
            joined.extend_from_slice(rest.get(..len)?);
            chunks = rest.get(len..)?;
        }
        return emit(OCTET_STRING, &joined, out);
    }
    out.push(tag);
    push_length(content.len(), out);
    out.extend_from_slice(content);
    Some(())
}

/// Append a DER definite length: short form below 128, otherwise `0x80 | n`
/// followed by the `n` significant big-endian octets.
pub(super) fn push_length(len: usize, out: &mut Vec<u8>) {
    if let Ok(short @ 0..0x80) = u8::try_from(len) {
        out.push(short);
        return;
    }
    let octets = len.to_be_bytes();
    let skip = octets.iter().take_while(|&&b| b == 0).count();
    let significant = octets.get(skip..).unwrap_or_default();
    // At most size_of::<usize>() octets, well inside the 7-bit count.
    out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7f));
    out.extend_from_slice(significant);
}

#[cfg(test)]
mod tests {
    use super::to_der;

    #[test]
    fn definite_der_passes_through_unchanged() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xAA];
        assert_eq!(to_der(&der).unwrap(), der);
    }

    #[test]
    fn indefinite_lengths_become_definite() {
        // SEQUENCE (indefinite) { INTEGER 5 } EOC, then trailing padding.
        let ber = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(to_der(&ber).unwrap(), [0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn non_minimal_lengths_are_shortened() {
        let ber = [0x04, 0x82, 0x00, 0x02, 0xAA, 0xBB];
        assert_eq!(to_der(&ber).unwrap(), [0x04, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn constructed_octet_strings_are_folded() {
        // OCTET STRING (constructed, indefinite) { "ab", "c" } EOC.
        let ber = [
            0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0x00, 0x00,
        ];
        assert_eq!(to_der(&ber).unwrap(), [0x04, 0x03, b'a', b'b', b'c']);
    }

    #[test]
    fn long_contents_get_a_long_form_length() {
        let mut ber = vec![0x30, 0x80, 0x04, 0x81, 0xC8];
        ber.extend([0u8; 200]);
        ber.extend([0x00, 0x00]);
        let der = to_der(&ber).unwrap();
        assert_eq!(der.get(..3), Some(&[0x30, 0x81, 0xCB][..]));
        assert_eq!(der.len(), 3 + 203);
    }

    #[test]
    fn malformed_input_is_rejected() {
        // Primitive element with an indefinite length.
        assert!(to_der(&[0x04, 0x80, 0x00, 0x00]).is_none());
        // Missing end-of-contents.
        assert!(to_der(&[0x30, 0x80, 0x02, 0x01, 0x05]).is_none());
        // Length past the input.
        assert!(to_der(&[0x04, 0x05, 0x01]).is_none());
        // A constructed OCTET STRING holding something other than chunks.
        assert!(to_der(&[0x24, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]).is_none());
    }

    #[test]
    fn nesting_beyond_the_cap_is_rejected() {
        let mut ber = Vec::new();
        for _ in 0..100 {
            ber.extend([0x30, 0x80]);
        }
        for _ in 0..100 {
            ber.extend([0x00, 0x00]);
        }
        assert!(to_der(&ber).is_none());
    }
}
