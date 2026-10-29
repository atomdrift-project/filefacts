//! Fixture builders shared by the archive and package extractors' tests.

use std::io::{Cursor, Write};

use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

use super::zip::{Archive, open_and_walk};
use crate::output::{Errors, Metrics, Values};

/// A ZIP of `entries`, each stored uncompressed, in order.
pub(crate) fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, body) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Open `bytes` for reading members as the archive walk does, restoring
/// corrupted local-header signatures if that is what stops the `zip` crate.
/// `None` when no member can be read.
pub(crate) fn open_zip(bytes: &[u8]) -> Option<Archive<'_>> {
    let (mut values, mut metrics, mut errors) = (Values::new(), Metrics::new(), Errors::new());
    open_and_walk(
        bytes,
        &mut values,
        &mut metrics,
        &mut Vec::new(),
        &mut errors,
    )
    .ok()
    .flatten()
}
