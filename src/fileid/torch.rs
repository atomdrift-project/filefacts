//! PyTorch serialization conventions, recognized without loading a model or
//! trusting code: the legacy pickle framing and the ZIP carrier.

use std::io::Read;

use super::{Sniff, zip_probe};

/// The pickle `torch.save` wrote before its zip format: protocol 2, then a
/// ten-byte LONG1 holding the magic number 0x1950a86a20f9469cfc6c.
pub(crate) const LEGACY_MAGIC: &[u8] = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19";

/// The legacy magic, then protocol version 1001: the framing of the bounded
/// multi-pickle carrier, not trust or whole-file validity. Other torch
/// serialization protocols are not covered.
pub(crate) fn legacy_header(data: &[u8]) -> bool {
    data.strip_prefix(LEGACY_MAGIC)
        .is_some_and(|rest| rest.starts_with(b".\x80\x02M\xe9\x03."))
}

/// A modern `torch.save` or TorchScript ZIP: one root directory holding a
/// small `version` member and a `data.pkl` pickle.
pub(super) fn recognized(sniff: &Sniff<'_>) -> bool {
    let Some(mut archive) = sniff.zip() else {
        return false;
    };
    if archive.is_empty() || archive.len() > 100_000 {
        return false;
    }
    let Some(first) = zip_probe::names(&archive).next() else {
        return false;
    };
    let Some((root, _)) = first.split_once('/') else {
        return false;
    };
    if root.is_empty() || root == "." || root == ".." {
        return false;
    }
    let prefix = format!("{root}/");
    if !zip_probe::names(&archive).all(|name| {
        name.starts_with(&prefix)
            && !name.contains('\\')
            && !name.split('/').any(|part| part == "." || part == "..")
    }) {
        return false;
    }
    let version_name = format!("{prefix}version");
    let data_name = format!("{prefix}data.pkl");
    let version = {
        let Ok(entry) = archive.by_name(&version_name) else {
            return false;
        };
        if entry.is_dir() || entry.size() > 16 {
            return false;
        }
        // The declared size is the archive's claim; a deflated member that
        // declares 16 bytes can inflate to gigabytes. Read one byte past it.
        let mut bytes = Vec::new();
        if entry.take(17).read_to_end(&mut bytes).is_err() || bytes.len() > 16 {
            return false;
        }
        bytes
    };
    let Ok(version) = std::str::from_utf8(&version) else {
        return false;
    };
    // Bound known carrier versions. Unknown future conventions retain the
    // existing mismatch signal until their format has been reviewed.
    let version = version.trim_ascii();
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !version.parse::<u32>().is_ok_and(|v| (1..=10).contains(&v)) {
        return false;
    }
    let Ok(mut entry) = archive.by_name(&data_name) else {
        return false;
    };
    let mut header = [0; 2];
    !entry.is_dir()
        && entry.read_exact(&mut header).is_ok()
        && header[0] == 0x80
        && (2..=5).contains(&header[1])
}

#[cfg(test)]
mod tests;
