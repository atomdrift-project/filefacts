//! Compressed Flash movies (`CWS`): the zlib-compressed body whose strings
//! the dispatcher's text scan reads.

use super::bounded::{OnError, inflate_capped};

/// Largest movie inflated: a hostile declared length cannot expand past it.
const MAX_MOVIE_BYTES: u32 = 1 << 20;

/// The inflated movie of a CWS file. The u32 at offset 4 is the movie's
/// uncompressed size, header included; a size out of range, or a body that
/// does not inflate, yields `None`.
pub(super) fn movie(bytes: &[u8]) -> Option<Vec<u8>> {
    let body = bytes.strip_prefix(b"CWS")?.get(5..)?;
    let skipped = |reason: &str| {
        tracing::debug!(target: "filefacts::formats", format = "cws", reason, "movie not inflated");
    };
    let declared = crate::bytes::u32_le(bytes, 4)?;
    if !(8..=MAX_MOVIE_BYTES).contains(&declared) {
        skipped("declared movie size out of range");
        return None;
    }
    match inflate_capped(
        flate2::read::ZlibDecoder::new(body),
        u64::from(declared),
        OnError::Discard,
    ) {
        Ok(movie) if !movie.bytes.is_empty() => Some(movie.bytes),
        Ok(_) => {
            skipped("empty zlib stream");
            None
        }
        Err(e) => {
            skipped(&format!("zlib stream did not inflate: {e}"));
            None
        }
    }
}
