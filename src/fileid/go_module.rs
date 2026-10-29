//! Go proxy distribution ZIPs, identified without inflating member contents.

use super::{Sniff, zip_probe};

/// Recognize the distribution convention, not whether Go would accept every
/// byte of this package. Older modules need not have a go.mod or a .go file.
/// https://go.dev/ref/mod#zip-files
pub(super) fn recognized(sniff: &Sniff<'_>) -> bool {
    let data = sniff.data;
    // Most ZIPs cannot be modules. Check the first local name before opening
    // the central directory; member sizes are deliberately not used here, as
    // Go's streaming writer leaves them in data descriptors instead.
    let Some(name_len) = crate::bytes::u16_le(data, 26).map(usize::from) else {
        return false;
    };
    let Some(name) = data
        .get(30..30 + name_len)
        .and_then(|b| std::str::from_utf8(b).ok())
    else {
        return false;
    };
    let Some(prefix) = module_prefix(name) else {
        return false;
    };
    let Some(archive) = sniff.zip() else {
        return false;
    };
    let mut has_file = false;
    for name in zip_probe::names(&archive) {
        let Some(relative) = name.strip_prefix(prefix) else {
            return false;
        };
        if name.contains('\\')
            || relative
                .trim_end_matches('/')
                .split('/')
                .any(|p| p == "." || p == ".." || (p.is_empty() && !relative.is_empty()))
        {
            return false;
        }
        has_file |= !relative.is_empty() && !name.ends_with('/');
    }
    has_file
}

fn module_prefix(name: &str) -> Option<&str> {
    let (module, after) = name.split_once('@')?;
    let (version, _) = after.split_once('/')?;
    let host = module.split('/').next()?;
    // Downloadable module paths have a DNS-shaped first element; Go's !x
    // URL escaping is not used in archive member names (uppercase is literal).
    if !host.contains('.')
        || host.starts_with(['.', '-'])
        || !host
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-".contains(&c))
        || !module.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
        })
        || !canonical_version(version)
    {
        return None;
    }
    name.get(..module.len() + version.len() + 2)
}

fn canonical_version(version: &str) -> bool {
    let Some(version) = version.strip_prefix('v') else {
        return false;
    };
    let version = version.strip_suffix("+incompatible").unwrap_or(version);
    let (core, pre) = version
        .split_once('-')
        .map_or((version, None), |(a, b)| (a, Some(b)));
    let mut parts = core.split('.');
    if !(0..3).all(|_| parts.next().is_some_and(number)) || parts.next().is_some() {
        return false;
    }
    pre.is_none_or(|pre| {
        pre.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && (!part.bytes().all(|c| c.is_ascii_digit()) || number(part))
        })
    })
}

fn number(part: &str) -> bool {
    !part.is_empty()
        && (part.len() == 1 || !part.starts_with('0'))
        && part.bytes().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests;
