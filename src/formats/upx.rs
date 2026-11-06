//! UPX packer detection.
//!
//! UPX (the Ultimate Packer for eXecutables) wraps the original
//! binary in a tiny decompression stub plus an LZMA/NRV-compressed
//! payload. The stub leaves two stable byte-level fingerprints:
//!
//! - the four-byte magic `"UPX!"` placed at the head of the
//!   compressed payload (and at file-end as a terminator),
//! - a copyright string of the form
//!   `"$Info: This file is packed with the UPX executable packer …"`
//!   followed by `"$Id: UPX <version> Copyright (C) <years> the UPX
//!   Team. All Rights Reserved. $"`.
//!
//! The copyright string carries the packer's version verbatim, so
//! when present we surface it under `binary.packer_version`. The
//! `binary.packer = "upx"` marker is set whenever either signature
//! matches — UPX-packed PE and Mach-O binaries pass through here
//! too, hence the cross-format keys.
//!
//! UPX is the most common packer on Linux malware and the simplest to
//! identify reliably from byte signatures alone.

use memchr::memmem;

use crate::formats::common::put_str;
use crate::output::Values;
use crate::value_key;

/// Set `binary.packer` (and `binary.packer_version` when decodable)
/// if the file carries UPX's byte-level signatures. Safe to call on
/// any file format — the magic strings are intentionally arbitrary
/// enough to avoid colliding with normal binary content.
pub(super) fn detect(bytes: &[u8], values: &mut Values) {
    if !has_upx_signature(bytes) {
        return;
    }
    put_str(values, value_key!("binary.packer"), "upx");
    if let Some(version) = extract_version(bytes) {
        put_str(values, value_key!("binary.packer_version"), version);
    }
}

/// Where UPX writes its stub and the packed payload's header: the start of
/// the packed file, in all three executable formats.
const STUB_WINDOW: usize = 16 * 1024;

/// The longest version token taken from the banner (`3.96`, `4.2.4`,
/// `3.96w`, `5.0.0-git`).
const MAX_VERSION_LEN: usize = 16;

/// `true` when the `"UPX!"` four-byte magic or the `$Info: This file is
/// packed with the UPX executable packer` copyright banner lies where UPX
/// writes it into the file it packs: the stub at the head of the file, or
/// (the magic only) the trailer at its very end. The banner is the safer
/// signal — `"UPX!"` is short enough to land inside random compressed data
/// — but the magic counts too because re-packers sometimes overwrite the
/// banner. Either signature deeper in the file belongs to something the
/// file carries, such as an embedded UPX-packed payload, not to the file.
fn has_upx_signature(bytes: &[u8]) -> bool {
    let head = bytes.get(..STUB_WINDOW).unwrap_or(bytes);
    memmem::find(head, b"$Info: This file is packed with the UPX").is_some()
        || memmem::find(head, b"UPX!").is_some()
        || bytes
            .last_chunk::<64>()
            .is_some_and(|tail| memmem::find(tail, b"UPX!").is_some())
}

/// Pull the UPX version out of the copyright banner. The banner
/// reads `$Id: UPX <version> Copyright (C) <years> the UPX Team. All
/// Rights Reserved. $`; we keep just the `<version>` token, when it is a
/// short run of version characters.
fn extract_version(bytes: &[u8]) -> Option<String> {
    let needle = b"$Id: UPX ";
    let start = memmem::find(bytes, needle)? + needle.len();
    let rest = bytes.get(start..)?;
    let rest = rest.get(..=MAX_VERSION_LEN).unwrap_or(rest);
    let token = rest.get(..rest.iter().position(|&b| b == b' ' || b == b'\t')?)?;
    let valid = !token.is_empty()
        && token
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
    valid.then(|| String::from_utf8_lossy(token).into_owned())
}

#[cfg(test)]
mod tests;
