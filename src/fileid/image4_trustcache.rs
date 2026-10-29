//! Bounded Image4 trca payload carrying a version-2 trust-cache table.
//! This reports declarations, never signature validity or executable trust.
//!
//! An Image4 payload is the DER `SEQUENCE { IA5String "IM4P", IA5String
//! type, IA5String description, OCTET STRING payload }`; a trust cache's
//! payload is a little-endian table of 24-byte entries, each a 20-byte code
//! directory hash, a hash type, flags, a constraint category and a reserved
//! byte, sorted by hash.

/// DER tags (ITU-T X.690 §8.7, §8.9, §8.23) of the Image4 payload fields.
const DER_OCTET_STRING: u8 = 0x04;
const DER_IA5_STRING: u8 = 0x16;
const DER_SEQUENCE: u8 = 0x30;

/// The version-2 trust-cache header: version (u32), UUID (16 bytes) and
/// entry count (u32).
const HEADER_LEN: usize = 24;

/// One version-2 entry.
const ENTRY_LEN: usize = 24;

/// What a trust cache declares.
pub(crate) struct Parsed<'a> {
    /// The Image4 description string.
    pub(crate) description: &'a str,
    /// The table's UUID.
    pub(crate) uuid: &'a [u8],
    /// The entries, [`ENTRY_LEN`] bytes each.
    pub(crate) entries: &'a [u8],
}

/// The body of the DER element of tag `expected` at the front of `input`,
/// which is advanced past it. Lengths follow X.690 §8.1.3 in its definite,
/// minimal (DER) form of at most four octets.
fn element<'a>(input: &mut &'a [u8], expected: u8) -> Option<&'a [u8]> {
    if input.first().copied()? != expected {
        return None;
    }
    *input = input.get(1..)?;
    let first = *input.first()?;
    *input = input.get(1..)?;
    let size = if first & 128 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        if !(1..=4).contains(&count) || input.first().copied()? == 0 {
            return None;
        }
        let mut size = 0usize;
        for byte in input.get(..count)? {
            size = size.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        if size < 128 {
            return None;
        }
        *input = input.get(count..)?;
        size
    };
    let body = input.get(..size)?;
    *input = input.get(size..)?;
    Some(body)
}

/// `data` as an Image4 trust-cache payload, when every boundary agrees.
pub(crate) fn parse(data: &[u8]) -> Option<Parsed<'_>> {
    if data.len() > 16 * 1024 * 1024 {
        return None;
    }
    let mut outer = data;
    let mut sequence = element(&mut outer, DER_SEQUENCE)?;
    if !outer.is_empty()
        || element(&mut sequence, DER_IA5_STRING)? != b"IM4P"
        || element(&mut sequence, DER_IA5_STRING)? != b"trca"
    {
        return None;
    }
    let description = element(&mut sequence, DER_IA5_STRING)?;
    if description.len() > 4096 || !description.iter().all(|b| b.is_ascii()) {
        return None;
    }
    let description = std::str::from_utf8(description).ok()?;
    let payload = element(&mut sequence, DER_OCTET_STRING)?;
    if !sequence.is_empty() || payload.get(..4)? != 2u32.to_le_bytes() {
        return None;
    }
    let count = u32::from_le_bytes(payload.get(20..24)?.try_into().ok()?) as usize;
    if count > 100_000 || payload.len() != HEADER_LEN.checked_add(count.checked_mul(ENTRY_LEN)?)? {
        return None;
    }
    let entries = payload.get(HEADER_LEN..)?;
    let mut previous: Option<&[u8]> = None;
    for entry in entries.as_chunks::<ENTRY_LEN>().0 {
        if entry[23] != 0 || previous.is_some_and(|p| p > &entry[..20]) {
            return None;
        }
        previous = Some(&entry[..20]);
    }
    Some(Parsed {
        description,
        uuid: payload.get(4..20)?,
        entries,
    })
}

#[cfg(test)]
mod tests;
