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
    normalize(ber).map(|(der, _)| der)
}

/// Normalize the first element of `ber` in two passes, so the work is linear
/// in the input however deep it nests: the first validates the element and
/// records the DER content length of each constructed element in pre-order,
/// the second writes the output with those lengths already known. Returns
/// the DER bytes and the input after the element.
pub(super) fn normalize(ber: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let mut lengths = Vec::new();
    let (rest, _, len) = measure(ber, 0, &mut lengths)?;
    let mut out = Vec::with_capacity(encoded_len(len)?);
    write(ber, &mut out, &mut lengths.into_iter(), true)?;
    Some((out, rest))
}

/// Where a BER element's contents end.
#[derive(Clone, Copy)]
enum Extent<'a> {
    /// A definite length: the contents and the bytes after them.
    Definite { content: &'a [u8], tail: &'a [u8] },
    /// An indefinite length: children up to an end-of-contents marker,
    /// starting at these bytes.
    Indefinite(&'a [u8]),
}

/// Read the identifier and length octets of the element at `input`.
fn header(input: &[u8]) -> Option<(u8, Extent<'_>)> {
    let (&tag, rest) = input.split_first()?;
    // High-tag-number form (low five bits all set) never occurs in CMS.
    if tag & 0x1F == 0x1F {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    if first == 0x80 {
        // Only constructed encodings may use an indefinite length.
        return is_constructed(tag).then_some((tag, Extent::Indefinite(rest)));
    }
    let (len, rest) = definite_length(first, rest)?;
    let (content, tail) = rest.split_at_checked(len)?;
    Some((tag, Extent::Definite { content, tail }))
}

fn is_constructed(tag: u8) -> bool {
    tag & 0x20 != 0
}

/// Call `child` on each child of a constructed element, with the input
/// starting at that child; `child` returns the input after it. Returns the
/// input after the element.
fn children<'a>(
    extent: Extent<'a>,
    mut child: impl FnMut(&'a [u8]) -> Option<&'a [u8]>,
) -> Option<&'a [u8]> {
    match extent {
        Extent::Definite { mut content, tail } => {
            while !content.is_empty() {
                content = child(content)?;
            }
            Some(tail)
        }
        Extent::Indefinite(mut rest) => loop {
            if let [0, 0, tail @ ..] = rest {
                return Some(tail);
            }
            rest = child(rest)?;
        },
    }
}

/// The DER tag for BER `tag`: a constructed OCTET STRING is folded into a
/// primitive one.
fn der_tag(tag: u8) -> u8 {
    if tag == OCTET_STRING_CONSTRUCTED {
        OCTET_STRING
    } else {
        tag
    }
}

/// Validate the element at `input` and push the DER content length of it
/// and each constructed element inside it to `lengths`, in pre-order.
/// Returns the input after the element, its DER tag and its DER content
/// length.
fn measure<'a>(
    input: &'a [u8],
    depth: usize,
    lengths: &mut Vec<usize>,
) -> Option<(&'a [u8], u8, usize)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (tag, extent) = header(input)?;
    if !is_constructed(tag) {
        let Extent::Definite { content, tail } = extent else {
            return None;
        };
        return Some((tail, tag, content.len()));
    }
    let slot = lengths.len();
    lengths.push(0);
    let fold = tag == OCTET_STRING_CONSTRUCTED;
    let mut len = 0usize;
    let rest = children(extent, |child| {
        let (rest, child_tag, child_len) = measure(child, depth + 1, lengths)?;
        // A folded OCTET STRING keeps only its chunks' contents.
        let encoded = if fold {
            (child_tag == OCTET_STRING).then_some(child_len)?
        } else {
            encoded_len(child_len)?
        };
        len = len.checked_add(encoded)?;
        Some(rest)
    })?;
    *lengths.get_mut(slot)? = len;
    Some((rest, der_tag(tag), len))
}

/// Write the DER form of the element at `input`, already validated by
/// [`measure`], taking constructed lengths from `lengths` in the same
/// pre-order. A chunk of a folded OCTET STRING is written without its
/// header. Returns the input after the element.
fn write<'a>(
    input: &'a [u8],
    out: &mut Vec<u8>,
    lengths: &mut std::vec::IntoIter<usize>,
    with_header: bool,
) -> Option<&'a [u8]> {
    let (tag, extent) = header(input)?;
    if !is_constructed(tag) {
        let Extent::Definite { content, tail } = extent else {
            return None;
        };
        if with_header {
            out.push(tag);
            push_length(content.len(), out);
        }
        copy(content, out);
        return Some(tail);
    }
    let len = lengths.next()?;
    if with_header {
        out.push(der_tag(tag));
        push_length(len, out);
    }
    let fold = tag == OCTET_STRING_CONSTRUCTED;
    children(extent, |child| write(child, out, lengths, !fold))
}

/// Decode a definite length whose first octet is `first`. BER allows the
/// non-minimal forms `der::Header` refuses, which is why this module reads
/// lengths itself.
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

/// Bytes a DER element with `len` content bytes occupies: tag, length
/// octets and contents.
fn encoded_len(len: usize) -> Option<usize> {
    let octets = if len < 0x80 {
        1
    } else {
        1 + len.bit_width().div_ceil(8) as usize
    };
    len.checked_add(1 + octets)
}

#[cfg(test)]
thread_local! {
    /// Content bytes appended to DER output on this thread.
    static COPIED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn copy(content: &[u8], out: &mut Vec<u8>) {
    #[cfg(test)]
    COPIED.with(|copied| copied.set(copied.get() + content.len()));
    out.extend_from_slice(content);
}

/// Append a DER definite length: short form below 128, otherwise `0x80 | n`
/// followed by the `n` significant big-endian octets.
fn push_length(len: usize, out: &mut Vec<u8>) {
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
mod tests;
