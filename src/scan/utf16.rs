//! UTF-16LE printable-run extractor.
//!
//! Scans for runs of `(printable ASCII, 0x00)` byte pairs aligned on
//! even offsets — the on-disk shape of ASCII characters when stored in
//! UTF-16 little-endian. PE resources, Windows-side malware C2 strings,
//! and pickled .NET assemblies routinely encode text this way.
//!
//! We do not attempt full UTF-16 decode here. Supplementary-plane runs
//! and non-ASCII BMP runs are rare in forensic contexts and would
//! require a much larger state machine for marginal benefit; format
//! extractors that need full decoding can fall back to the `widestring`
//! crate.

use crate::output::{ExtractedString, StringCategory};

/// Default minimum length (in *characters*, not bytes).
pub(crate) const DEFAULT_MIN_LEN: usize = 4;

/// Yield every maximal printable-ASCII run encoded as UTF-16LE in
/// `bytes`. `min_len` is in characters; a run of N characters occupies
/// `2N` bytes.
pub(crate) fn extract_runs(
    bytes: &[u8],
    min_len: usize,
) -> impl Iterator<Item = ExtractedString> + '_ {
    Utf16Runs {
        bytes,
        pos: 0,
        min_len,
    }
}

struct Utf16Runs<'a> {
    bytes: &'a [u8],
    pos: usize,
    min_len: usize,
}

impl Iterator for Utf16Runs<'_> {
    type Item = ExtractedString;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos + 1 < self.bytes.len() {
            if is_printable_utf16le_unit(self.bytes[self.pos], self.bytes[self.pos + 1]) {
                let start = self.pos;
                let mut text = String::new();
                while self.pos + 1 < self.bytes.len()
                    && is_printable_utf16le_unit(self.bytes[self.pos], self.bytes[self.pos + 1])
                {
                    text.push(self.bytes[self.pos] as char);
                    self.pos += 2;
                }
                if text.len() >= self.min_len {
                    return Some(ExtractedString {
                        category: StringCategory::Utf16Le,
                        text,
                        offset: start,
                        method: None,
                        kind: None,
                        section: None,
                    });
                }
            } else {
                self.pos += 1;
            }
        }
        None
    }
}

#[inline]
fn is_printable_utf16le_unit(lo: u8, hi: u8) -> bool {
    hi == 0 && matches!(lo, 0x20..=0x7E | b'\t')
}

#[cfg(test)]
mod tests {
    use super::{extract_runs, DEFAULT_MIN_LEN};

    fn utf16le(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for c in s.chars() {
            out.push(c as u8);
            out.push(0);
        }
        out
    }

    #[test]
    fn finds_aligned_run() {
        let bytes = utf16le("hello");
        let runs: Vec<_> = extract_runs(&bytes, DEFAULT_MIN_LEN).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "hello");
        assert_eq!(runs[0].offset, 0);
    }

    #[test]
    fn ignores_short_runs() {
        let bytes = utf16le("ab");
        let runs: Vec<_> = extract_runs(&bytes, DEFAULT_MIN_LEN).collect();
        assert!(runs.is_empty());
    }

    #[test]
    fn handles_interleaved_data() {
        let mut bytes = vec![0u8, 0u8, 0xff, 0xff];
        bytes.extend_from_slice(&utf16le("world"));
        bytes.extend_from_slice(&[0xee, 0xee]);
        let runs: Vec<_> = extract_runs(&bytes, DEFAULT_MIN_LEN).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "world");
        assert_eq!(runs[0].offset, 4);
    }

    #[test]
    fn rejects_high_bytes_in_low_byte() {
        let bytes = b"\xff\x00\xff\x00\xff\x00\xff\x00";
        let runs: Vec<_> = extract_runs(bytes, DEFAULT_MIN_LEN).collect();
        assert!(runs.is_empty());
    }
}
