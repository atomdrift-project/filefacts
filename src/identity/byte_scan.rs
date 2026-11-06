//! Byte scans for identity strings that no extractor recorded: a user-home
//! build path, and a `KEY:value` stamp.

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;

/// Whether `path` lies under a user's home directory.
pub(super) fn reveals_home(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/users/") || lower.contains("/home/") || lower.contains("\\users\\")
}

/// The three home-path prefixes, matched in one pass by a shared
/// automaton. Pattern index 2 (`C:\Users\`) uses the Windows byte
/// class; the others use the Unix class. The patterns are constants, so a
/// build failure is a bug here, not something an input can cause.
static HOME_FINDER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(["/Users/", "/home/", "C:\\Users\\"])
        .expect("static home-path patterns are valid")
});

/// Find the first user-home path embedded in the bytes and return it
/// verbatim. A single shared-automaton forward pass over the file.
pub(super) fn home_path_scan(bytes: &[u8]) -> Option<&str> {
    let m = HOME_FINDER.find(bytes)?;
    let windows = m.pattern().as_usize() == 2;
    let is_path_byte: fn(u8) -> bool = if windows {
        |b| {
            matches!(
                b,
                b'\\' | b':' | b'.' | b'-' | b'_' | b'+' | b'~' | b'@' | b' '
            ) || b.is_ascii_alphanumeric()
        }
    } else {
        |b| matches!(b, b'/' | b'.' | b'-' | b'_' | b'+' | b'~' | b'@') || b.is_ascii_alphanumeric()
    };
    let path = bytes
        .get(m.start()..)?
        .split(|&b| !is_path_byte(b))
        .next()?;
    // Require at least one path byte past the prefix (a real username).
    if path.len() <= m.len() {
        return None;
    }
    std::str::from_utf8(path).ok()
}

/// Scan for a `KEY:value` token (Apple `what(1)` stamps), returning the
/// value up to the next whitespace / control byte.
pub(super) fn scan_token<'a>(bytes: &'a [u8], needle: &[u8]) -> Option<&'a str> {
    let pos = memchr::memmem::find(bytes, needle)?;
    let after = bytes.get(pos + needle.len()..)?;
    let start = after.iter().position(|&b| b != b' ' && b != b'\t')?;
    let token = after
        .get(start..)?
        .split(|&b| b <= b' ' || b == 0x7f)
        .next()?;
    if token.is_empty() {
        return None;
    }
    std::str::from_utf8(token).ok()
}
