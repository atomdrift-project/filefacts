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
//! UPX is the dominant Linux packer in malware samples (every kube-
//! diag-packed, mozi, kinsing variant I've seen ships with stock
//! UPX), and the simplest packer to identify reliably from byte
//! signatures alone.

use crate::formats::common::put_str;
use crate::output::Values;

/// Set `binary.packer` (and `binary.packer_version` when decodable)
/// if the file carries UPX's byte-level signatures. Safe to call on
/// any file format — the magic strings are intentionally arbitrary
/// enough to avoid colliding with normal binary content.
pub(super) fn detect(bytes: &[u8], values: &mut Values) {
    if !has_upx_signature(bytes) {
        return;
    }
    put_str(values, "binary.packer", "upx");
    if let Some(version) = extract_version(bytes) {
        put_str(values, "binary.packer_version", version);
    }
}

/// `true` when either the `"UPX!"` four-byte magic or the
/// `$Info: This file is packed with the UPX executable packer`
/// copyright banner appears anywhere in the file. The banner is the
/// safer signal — `"UPX!"` is short enough to land inside random
/// compressed data — but we accept the magic too because the banner
/// is sometimes overwritten by re-packers.
fn has_upx_signature(bytes: &[u8]) -> bool {
    if find_bytes(bytes, b"$Info: This file is packed with the UPX").is_some() {
        return true;
    }
    // Magic only matches when it lands inside the stub region (first
    // 16 KiB) or at the very end of the file. UPX places the magic
    // at the compressed-payload header, which sits near the start
    // for both PE and ELF and at the tail-marker for ELF. Restricting
    // the search avoids false positives from random `UPX!` triples
    // inside arbitrary file content.
    let head_window = bytes.len().min(16 * 1024);
    if find_bytes(&bytes[..head_window], b"UPX!").is_some() {
        return true;
    }
    if bytes.len() >= 64 {
        let tail_start = bytes.len().saturating_sub(64);
        if find_bytes(&bytes[tail_start..], b"UPX!").is_some() {
            return true;
        }
    }
    false
}

/// Pull the UPX version out of the copyright banner. The banner
/// reads `$Id: UPX <version> Copyright (C) <years> the UPX Team. All
/// Rights Reserved. $`; we keep just the `<version>` token.
fn extract_version(bytes: &[u8]) -> Option<String> {
    let needle = b"$Id: UPX ";
    let start = find_bytes(bytes, needle)? + needle.len();
    let rest = bytes.get(start..)?;
    // Version runs up to the next whitespace.
    let end = rest.iter().position(|&b| b == b' ' || b == b'\t')?;
    let v = &rest[..end];
    std::str::from_utf8(v).ok().map(str::to_string)
}

/// Naive substring search. The needles here are short and rare
/// enough that a memchr-driven scan would not measurably help.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_banner_anywhere_in_file() {
        let mut buf = vec![0u8; 1000];
        buf.extend_from_slice(b"$Info: This file is packed with the UPX executable packer\0");
        assert!(has_upx_signature(&buf));
    }

    #[test]
    fn detects_magic_in_stub_window() {
        let mut buf = vec![0u8; 1000];
        buf[300..304].copy_from_slice(b"UPX!");
        assert!(has_upx_signature(&buf));
    }

    #[test]
    fn ignores_magic_in_middle_of_file() {
        // UPX! a few hundred KB into the file is more likely random
        // content (esp. inside a UPX-compressed payload that's
        // *itself* embedded in something) than a packer marker.
        let mut buf = vec![0u8; 1_000_000];
        buf[500_000..500_004].copy_from_slice(b"UPX!");
        assert!(!has_upx_signature(&buf));
    }

    #[test]
    fn version_extracts_token() {
        let buf = b"$Id: UPX 5.11 Copyright (C) 1996-2026 the UPX Team. All Rights Reserved. $";
        assert_eq!(extract_version(buf), Some("5.11".to_string()));
    }
}
