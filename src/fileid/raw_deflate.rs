//! Raw deflate: the codec inside zip and gzip with no header around it.
//!
//! .NET's `DeflateStream`, zlib with negative window bits and PHP's
//! `gzdeflate` all write it. With no magic, length or checksum, the only
//! evidence that bytes are a raw deflate stream is what they inflate to, so
//! a stream is recognized only when its output opens with a program: a PE,
//! ELF or Mach-O image, or a `#!` script. Droppers ship payloads this way.
//! A consumer inflates the stream as it does any other compressed file.

use flate2::{Decompress, FlushDecompress};

/// Inflated bytes that decide whether a stream holds a program.
const HEAD: usize = 4096;

/// Whether `data` is a raw deflate stream whose output opens with a program.
/// At most [`HEAD`] bytes are inflated; most other bytes fail on the first
/// block header.
pub(super) fn holds_program(data: &[u8]) -> bool {
    // Block type 3 is reserved: a quarter of arbitrary bytes end here.
    if data.first().is_none_or(|b| (b >> 1) & 3 == 3) {
        return false;
    }
    let mut head = Vec::with_capacity(HEAD);
    Decompress::new(false)
        .decompress_vec(data, &mut head, FlushDecompress::Finish)
        .is_ok_and(|_| super::is_program(&head))
}

#[cfg(test)]
mod tests;
