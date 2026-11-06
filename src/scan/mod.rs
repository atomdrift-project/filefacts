//! Byte-level scanners shared across format extractors.
//!
//! Each scanner takes a raw byte slice and produces low-level facts:
//! Shannon entropy, byte classes, etc. Format-specific extractors call these
//! on whatever subset of the input is appropriate (e.g. just the `.rdata`
//! section for PE, the full file for opaque blobs).

pub(crate) mod classify;
pub(crate) mod entropy;
