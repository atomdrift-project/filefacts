//! Bounded parsing of untrusted property lists.
//!
//! `plist::Value::from_reader` builds its tree without recursing, but two
//! input shapes still take the process down:
//!
//! - A binary plist may reference one collection from many places (a DAG; the
//!   reader rejects only cycles), and the reader expands every reference into
//!   its own copy. A 171-byte DAG expanded to 124 GB.
//! - Everything done with the tree afterwards — converting it, deserializing
//!   from it, dropping it — recurses once per level, so a deep nest overflows
//!   the stack.
//!
//! [`parse`] refuses both before they cost anything. Every extractor that
//! parses a plist from file bytes goes through it.

use std::fmt;

/// Nesting cap, the same as for YAML. Real Apple artifacts stay far below it.
pub(crate) const MAX_DEPTH: usize = 128;

/// Values a binary plist may expand to beyond two per input byte. Every
/// object costs a marker byte and every reference at least one more, so only
/// a plist reusing one collection under many references can exceed this.
const EXTRA_VALUES: u64 = 4096;

/// Why [`parse`] refused a plist.
#[derive(Debug)]
pub(crate) enum PlistError {
    /// A binary plist whose shared references expand past `cap` values.
    Expansion { cap: u64 },
    /// Collections nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The `plist` reader rejected the input.
    Parse(plist::Error),
}

impl fmt::Display for PlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expansion { cap } => {
                write!(f, "binary plist references expand past {cap} values")
            }
            Self::TooDeep => write!(f, "plist nests deeper than {MAX_DEPTH} levels"),
            Self::Parse(_) => write!(f, "plist parse failed"),
        }
    }
}

impl std::error::Error for PlistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Expansion { .. } | Self::TooDeep => None,
        }
    }
}

impl PlistError {
    /// The crate error for a plist read as `format`.
    pub(crate) fn into_error(self, format: &'static str) -> crate::Error {
        match self {
            Self::Parse(e) => crate::Error::malformed_caused_by(format, e),
            refused => crate::Error::malformed(format, refused.to_string()),
        }
    }
}

/// Parse a plist (XML, binary or ASCII), refusing reference expansion past
/// what the input's size allows and nesting past [`MAX_DEPTH`]. The returned
/// tree is safe to convert, deserialize from and drop recursively.
pub(crate) fn parse(bytes: &[u8]) -> Result<plist::Value, PlistError> {
    if bytes.starts_with(b"bplist00") {
        let cap = (bytes.len() as u64)
            .saturating_mul(2)
            .saturating_add(EXTRA_VALUES);
        if bplist_expanded_len(bytes, cap).is_some_and(|len| len > cap) {
            return Err(PlistError::Expansion { cap });
        }
    }
    let parsed =
        plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(PlistError::Parse)?;
    if depth_exceeds(&parsed, MAX_DEPTH) {
        dismantle(parsed);
        return Err(PlistError::TooDeep);
    }
    Ok(parsed)
}

/// Whether any collection in `value` sits deeper than `cap`, the root being
/// at depth 1. Iterative, so it is safe on the trees it rejects.
fn depth_exceeds(value: &plist::Value, cap: usize) -> bool {
    let mut stack = vec![(value, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        match value {
            plist::Value::Array(items) if depth <= cap => {
                stack.extend(items.iter().map(|child| (child, depth + 1)));
            }
            plist::Value::Dictionary(entries) if depth <= cap => {
                stack.extend(entries.values().map(|child| (child, depth + 1)));
            }
            plist::Value::Array(_) | plist::Value::Dictionary(_) => return true,
            _ => {}
        }
    }
    false
}

/// Drop a plist tree without recursing. `Vec` and `Dictionary` drop their
/// elements recursively, which a deep enough tree turns into a stack
/// overflow; moving each collection's children out first keeps it flat.
fn dismantle(value: plist::Value) {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            plist::Value::Array(items) => stack.extend(items),
            plist::Value::Dictionary(entries) => stack.extend(entries.into_iter().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// The number of values a binary plist expands to, counting a shared object
/// again at every reference, saturating just past `cap`. `None` when the
/// object table cannot be read, or has a cycle; the plist reader then
/// reports the malformation itself.
fn bplist_expanded_len(bytes: &[u8], cap: u64) -> Option<u64> {
    /// A big-endian unsigned integer of `width` (1..=8) bytes at `at`.
    fn be_uint(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
        let field = bytes.get(at..at.checked_add(width)?)?;
        (width <= 8).then(|| field.iter().fold(0, |n, &b| (n << 8) | u64::from(b)))
    }

    let mut trailer = crate::bytes::Reader::at(bytes, bytes.len().checked_sub(32)? + 6);
    let offset_width = usize::from(trailer.u8()?);
    let ref_width = usize::from(trailer.u8()?);
    let objects = usize::try_from(trailer.u64_be()?).ok()?;
    let top = usize::try_from(trailer.u64_be()?).ok()?;
    let table = usize::try_from(trailer.u64_be()?).ok()?;
    if !(1..=8).contains(&offset_width) || !(1..=8).contains(&ref_width) || objects > bytes.len() {
        return None;
    }
    // The objects a collection references; empty for a scalar.
    let children = |object: usize| -> Option<Vec<usize>> {
        let at = usize::try_from(be_uint(
            bytes,
            table.checked_add(object.checked_mul(offset_width)?)?,
            offset_width,
        )?)
        .ok()?;
        let marker = *bytes.get(at)?;
        let refs_per_entry = match marker >> 4 {
            0xA..=0xC => 1,
            0xD => 2,
            _ => return Some(Vec::new()),
        };
        let (count, refs_at) = match marker & 0x0F {
            0x0F => {
                // The count follows as an int object: 0x1n, then 2^n bytes.
                let int_marker = *bytes.get(at + 1)?;
                if int_marker >> 4 != 0x1 {
                    return None;
                }
                let width = 1usize.checked_shl(u32::from(int_marker & 0x0F))?;
                (be_uint(bytes, at + 2, width)?, at + 2 + width)
            }
            n => (u64::from(n), at + 1),
        };
        let refs = usize::try_from(count).ok()?.checked_mul(refs_per_entry)?;
        if refs.checked_mul(ref_width)? > bytes.len() {
            return None;
        }
        (0..refs)
            .map(|i| {
                let child = be_uint(bytes, refs_at.checked_add(i * ref_width)?, ref_width)?;
                usize::try_from(child).ok().filter(|&c| c < objects)
            })
            .collect()
    };

    // Post-order walk with memoized sizes: a collection is its start and end
    // plus everything its references expand to.
    //
    // Each reference read is an edge the expansion repeats at least once, so
    // reading more than `cap` of them already shows the expansion passes it.
    // Without that count, many objects sharing one large collection's bytes
    // made the walk itself quadratic before any size reached the cap.
    const OPEN: u64 = u64::MAX;
    let mut size = vec![0u64; objects];
    let top_kids = children(top)?;
    let mut refs_read = top_kids.len() as u64;
    let mut stack = vec![(top, top_kids, 0usize)];
    *size.get_mut(top)? = OPEN;
    while let Some((object, kids, next)) = stack.last_mut() {
        if refs_read > cap {
            return Some(refs_read);
        }
        if let Some(&kid) = kids.get(*next) {
            *next += 1;
            match *size.get(kid)? {
                OPEN => return None,
                0 => {
                    let grandkids = children(kid)?;
                    refs_read = refs_read.saturating_add(grandkids.len() as u64);
                    if grandkids.is_empty() {
                        *size.get_mut(kid)? = 1;
                    } else {
                        *size.get_mut(kid)? = OPEN;
                        stack.push((kid, grandkids, 0));
                    }
                }
                _ => {}
            }
            continue;
        }
        let total = kids
            .iter()
            .try_fold(2u64, |total, &kid| {
                Some(total.saturating_add(*size.get(kid)?))
            })?
            .min(cap.saturating_add(1));
        let object = *object;
        *size.get_mut(object)? = total;
        stack.pop();
        if total > cap {
            return Some(total);
        }
    }
    size.get(top).copied()
}

/// An XML plist of `levels` nested `<array>`s.
#[cfg(test)]
pub(super) fn nested_xml(levels: usize) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><plist version=\"1.0\">{}<string>x</string>{}</plist>",
        "<array>".repeat(levels),
        "</array>".repeat(levels)
    )
    .into_bytes()
}

/// A binary plist of `levels` arrays, each holding 14 references to the
/// next: a few hundred bytes that expand to 14^`levels` values.
#[cfg(test)]
pub(super) fn reference_dag(levels: u8) -> Vec<u8> {
    let mut bytes = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for level in 0..levels {
        offsets.push(bytes.len() as u8);
        // An array marker with its count, 14, in the low nibble.
        bytes.push(0xA0 | 0x0E);
        bytes.extend(std::iter::repeat_n(level + 1, 14));
    }
    offsets.push(bytes.len() as u8);
    bytes.extend([0x10, 0x00]);
    let table = bytes.len() as u64;
    bytes.extend(&offsets);
    bytes.extend([0u8; 6]);
    bytes.extend([1, 1]);
    bytes.extend((offsets.len() as u64).to_be_bytes());
    bytes.extend(0u64.to_be_bytes());
    bytes.extend(table.to_be_bytes());
    bytes
}

/// A binary plist whose top array references `shared` objects that all sit at
/// one offset: an array of `shared` references to a single integer. A few
/// bytes per reference, and `shared`² references to walk.
#[cfg(test)]
pub(super) fn shared_collection(shared: u32) -> Vec<u8> {
    let array = |refs: &mut dyn Iterator<Item = u32>| {
        let mut out = vec![0xAF, 0x12];
        out.extend(shared.to_be_bytes());
        refs.for_each(|r| out.extend(r.to_be_bytes()));
        out
    };
    let mut bytes = b"bplist00".to_vec();
    let top_at = bytes.len() as u32;
    bytes.extend(array(&mut (1..=shared)));
    let shared_at = bytes.len() as u32;
    bytes.extend(array(&mut std::iter::repeat_n(shared + 1, shared as usize)));
    let int_at = bytes.len() as u32;
    bytes.extend([0x10, 0x00]);
    let table = bytes.len() as u64;
    bytes.extend(top_at.to_be_bytes());
    (0..shared).for_each(|_| bytes.extend(shared_at.to_be_bytes()));
    bytes.extend(int_at.to_be_bytes());
    bytes.extend([0u8; 6]);
    bytes.extend([4, 4]);
    bytes.extend((u64::from(shared) + 2).to_be_bytes());
    bytes.extend(0u64.to_be_bytes());
    bytes.extend(table.to_be_bytes());
    bytes
}

/// Run `f` on a 2 MiB thread, the stack a rayon worker gets.
#[cfg(test)]
pub(super) fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[cfg(test)]
mod tests;
