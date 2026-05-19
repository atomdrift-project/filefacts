//! Printable-ASCII run extractor.
//!
//! Scans a byte slice for maximal runs of printable 7-bit ASCII bytes
//! (`0x20..=0x7E`, plus `\t`). Runs shorter than `min_len` are dropped.
//! Output is streaming-style — emitted lazily as the scanner walks the
//! input, so callers can collect into any container or apply a cap
//! mid-scan.

use crate::output::{ExtractedString, StringCategory};

/// Default minimum string length. Matches `strings(1)` and is the
/// long-standing convention for forensic ASCII extraction.
pub(crate) const DEFAULT_MIN_LEN: usize = 4;

/// Yield every maximal printable-ASCII run of at least `min_len` bytes
/// found in `bytes`. Offsets are relative to the start of `bytes`.
///
/// The iterator never allocates beyond the per-string buffer it returns;
/// callers that don't need owned strings should consume the iterator and
/// drop them.
pub(crate) fn extract_runs(
    bytes: &[u8],
    min_len: usize,
) -> impl Iterator<Item = ExtractedString> + '_ {
    AsciiRuns {
        bytes,
        pos: 0,
        min_len,
    }
}

struct AsciiRuns<'a> {
    bytes: &'a [u8],
    pos: usize,
    min_len: usize,
}

impl Iterator for AsciiRuns<'_> {
    type Item = ExtractedString;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.bytes.len() {
            // Skip non-printable bytes.
            while self.pos < self.bytes.len() && !is_printable(self.bytes[self.pos]) {
                self.pos += 1;
            }
            let start = self.pos;
            while self.pos < self.bytes.len() && is_printable(self.bytes[self.pos]) {
                self.pos += 1;
            }
            if self.pos - start >= self.min_len {
                // `is_printable` only accepts ASCII bytes, so the slice is
                // valid UTF-8 by construction.
                let text =
                    std::str::from_utf8(&self.bytes[start..self.pos])
                        .expect("ascii slice is valid utf-8")
                        .to_owned();
                return Some(ExtractedString {
                    category: StringCategory::Ascii,
                    text,
                    offset: start,
                });
            }
        }
        None
    }
}

#[inline]
fn is_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\t')
}

#[cfg(test)]
mod tests {
    use super::{extract_runs, DEFAULT_MIN_LEN};

    #[test]
    fn finds_simple_runs() {
        let bytes = b"\x00\x01hello\x00world!\x00";
        let runs: Vec<_> = extract_runs(bytes, DEFAULT_MIN_LEN).collect();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].text, "hello");
        assert_eq!(runs[0].offset, 2);
        assert_eq!(runs[1].text, "world!");
    }

    #[test]
    fn respects_min_len() {
        let bytes = b"abc\x00abcd\x00abcde";
        let runs: Vec<_> = extract_runs(bytes, 4).collect();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].text, "abcd");
        assert_eq!(runs[1].text, "abcde");
    }

    #[test]
    fn includes_tab() {
        let bytes = b"key\tvalue\x00";
        let runs: Vec<_> = extract_runs(bytes, DEFAULT_MIN_LEN).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "key\tvalue");
    }

    #[test]
    fn rejects_high_bytes() {
        let bytes = b"hello\xffworld";
        let runs: Vec<_> = extract_runs(bytes, DEFAULT_MIN_LEN).collect();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].text, "hello");
        assert_eq!(runs[1].text, "world");
    }

    #[test]
    fn empty_input() {
        let runs: Vec<_> = extract_runs(&[], DEFAULT_MIN_LEN).collect();
        assert!(runs.is_empty());
    }

    #[test]
    fn all_unprintable() {
        let bytes = vec![0u8; 100];
        let runs: Vec<_> = extract_runs(&bytes, DEFAULT_MIN_LEN).collect();
        assert!(runs.is_empty());
    }
}
