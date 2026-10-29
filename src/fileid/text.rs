//! Byte-level text tests shared by every stage of identification: whether a
//! window reads as text or as object code, and ASCII case-insensitive search.

/// The UTF-8 byte-order mark. Windows editors write it ahead of scripts and
/// markup alike, so content checks read past it.
pub(super) const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// `data` without a leading [`UTF8_BOM`].
pub(super) fn strip_utf8_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(UTF8_BOM).unwrap_or(data)
}

/// The control bytes a kind of text may carry.
#[derive(Clone, Copy)]
pub(super) enum Controls {
    /// Tab, the line breaks and form feed: what any text file carries.
    Text,
    /// [`Controls::Text`], plus what scripts print or end with: ESC (ANSI
    /// colour in `echo` lines), SUB (the DOS end-of-file mark), and IRC's
    /// formatting codes -- bold, colour, reset, reverse, italic, underline --
    /// which mIRC scripts put in the messages they send.
    Script,
}

impl Controls {
    const fn allows(self, b: u8) -> bool {
        match self {
            Self::Text => matches!(b, b'\t' | b'\n' | b'\r' | 0x0C),
            Self::Script => matches!(
                b,
                b'\t'
                    | b'\n'
                    | b'\r'
                    | 0x0C
                    | 0x1A
                    | 0x1B
                    | 0x02
                    | 0x03
                    | 0x0F
                    | 0x16
                    | 0x1D
                    | 0x1F
            ),
        }
    }
}

/// How many bytes of `window` are control bytes `allowed` does not excuse:
/// below 0x20, or DEL. Bytes at or above 0x80 are ordinary in UTF-8 and
/// Latin-1 text, so they are never counted.
pub(super) fn control_bytes(window: &[u8], allowed: Controls) -> usize {
    window
        .iter()
        .filter(|&&b| (b < 0x20 && !allowed.allows(b)) || b == 0x7F)
        .count()
}

/// The text/binary classifier: whether `window` carries the control bytes of
/// object code. Source and scripts essentially never carry a control byte
/// beyond the ones `allowed` excuses, and object code is full of them, so a
/// share of 3% separates the two decisively without judging encodings. Under
/// a line of text the share alone is one stray byte, so a short window needs
/// three outright.
pub(super) fn is_binary(window: &[u8], allowed: Controls) -> bool {
    const MIN_BYTES: usize = 8;
    const MAX_CONTROL_PERCENT: usize = 3;
    const MIN_CONTROL_SHORT: usize = 3;
    if window.len() < MIN_BYTES {
        return false;
    }
    let control = control_bytes(window, allowed);
    control * 100 > window.len() * MAX_CONTROL_PERCENT
        && (window.len() >= 64 || control >= MIN_CONTROL_SHORT)
}

/// Offset of `needle` in `hay`, ignoring ASCII case. Every line of a file
/// passes through a few dozen of these, so candidates are found with `memchr`
/// on the needle's first byte rather than by comparing at every offset.
pub(super) fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, _) = needle.split_first()?;
    let (lower, upper) = (first.to_ascii_lowercase(), first.to_ascii_uppercase());
    // Every offset a match could start at.
    let starts = hay.get(..=hay.len().checked_sub(needle.len())?)?;
    memchr::memchr2_iter(lower, upper, starts).find(|&at| {
        hay.get(at..at + needle.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle))
    })
}

/// Whether `needle` occurs in `hay`. The needles here are a few bytes long
/// and the lines short, where a `memchr` on the first byte beats building a
/// substring searcher per call.
pub(super) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return false;
    };
    memchr::memchr_iter(first, hay)
        .any(|at| hay.get(at + 1..).is_some_and(|tail| tail.starts_with(rest)))
}

/// Whether `needle` occurs in `hay`, ignoring ASCII case.
pub(super) fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    find_ci(hay, needle).is_some()
}

/// Whether `s` opens with `prefix`, ignoring ASCII case.
pub(super) fn starts_ci(s: &[u8], prefix: &[u8]) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests;
