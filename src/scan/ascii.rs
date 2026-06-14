//! Shared ASCII-extraction constant.
//!
//! filefacts no longer carries its own byte-scan run extractor — all string
//! extraction goes through the single `stng` codepath (see
//! [`crate::formats::common`]). Only the shared minimum-run length remains.

/// Default minimum string length. Matches `strings(1)` and is the
/// long-standing convention for forensic ASCII extraction.
pub(crate) const DEFAULT_MIN_LEN: usize = 4;
