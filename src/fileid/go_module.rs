//! Go modules by content: a `go.mod` manifest by its grammar, and a Go proxy
//! distribution ZIP without inflating member contents.

use super::{Sniff, zip_probe};

/// Recognize the distribution convention, not whether Go would accept every
/// byte of this package. Older modules need not have a go.mod or a .go file.
/// <https://go.dev/ref/mod#zip-files>
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

/// How far into a file the `module` directive may begin.
const GO_MOD_HEAD_LIMIT: usize = 4096;

/// Directives a `go.mod` may hold after its `module` line.
const GO_MOD_DIRECTIVES: &[&str] = &[
    "go",
    "toolchain",
    "godebug",
    "require",
    "replace",
    "exclude",
    "retract",
    "tool",
    "ignore",
];

/// Go's module directive is the first non-comment directive in a `go.mod`, and
/// every line after it is another directive, a comment, or an entry of a
/// parenthesized directive block. Checking that narrow grammar is
/// constant-space and avoids assigning module semantics to ordinary prose,
/// Go source declarations such as `export module`, or another language's
/// module declaration — Ruby's `module Name` is followed by Ruby, not by
/// `require` lines.
pub(super) fn looks_like_go_mod(data: &[u8]) -> bool {
    go_mod_blocks_closed(data).is_some()
}

/// [`looks_like_go_mod`], read over the whole file: `None` when `data` is
/// not a `go.mod`, otherwise whether every `( … )` block it opens is closed.
/// A shell or `cmd.exe` runs past each directive as an unknown command, so a
/// grammar that held only for a prefix would let a script hide behind one.
pub(super) fn go_mod_blocks_closed(data: &[u8]) -> Option<bool> {
    // Text that is all blank lines and comments for a whole head is not a
    // manifest; it is not read further.
    data.get(..GO_MOD_HEAD_LIMIT)
        .unwrap_or(data)
        .split(|&b| b == b'\n')
        .map(<[u8]>::trim_ascii)
        .find(|line| !(line.is_empty() || line.starts_with(b"//")))?;
    let mut lines = data
        .split(|&b| b == b'\n')
        .map(|line| std::str::from_utf8(line).map(str::trim))
        .filter(|line| !matches!(line, Ok(l) if l.is_empty() || l.starts_with("//")));
    if !go_module_directive(lines.next()?.ok()?) {
        return None;
    }
    let mut in_block = false;
    for line in lines {
        let line = line.ok()?;
        if in_block {
            in_block = !line.starts_with(')');
            continue;
        }
        let keyword = line
            .split(|c: char| c.is_ascii_whitespace() || c == '(')
            .next()
            .unwrap_or_default();
        if !GO_MOD_DIRECTIVES.contains(&keyword) {
            return None;
        }
        let code = line.split("//").next().unwrap_or(line).trim_end();
        in_block = code.ends_with('(');
    }
    Some(!in_block)
}

/// `module <path>`, with a well-formed module path.
fn go_module_directive(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("module") else {
        return false;
    };
    if !(rest.starts_with(' ') || rest.starts_with('\t')) {
        return false;
    }
    let rest = rest.trim_start();
    let rest = rest
        .find("//")
        .and_then(|offset| rest.get(..offset))
        .filter(|before| before.ends_with(|c: char| c.is_ascii_whitespace()))
        .unwrap_or(rest)
        .trim();
    if rest.is_empty() || rest.split_whitespace().count() != 1 {
        return false;
    }

    let path = ['"', '`']
        .into_iter()
        .find_map(|quote| rest.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(rest);
    !path.is_empty()
        && path.bytes().any(|b| b.is_ascii_alphanumeric())
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./_~-!".contains(&b))
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.starts_with('.'))
}

#[cfg(test)]
mod tests;
