//! The interpreter a `#!` line names, read the way the kernel reads it.

use super::{DetectionSource, FileType};

/// Detect shebang-based file types.
///
/// Reads the line the way the kernel does: the first word is the interpreter
/// path, and only its basename matters. A launcher (`env`, `busybox`) defers
/// to the first word after its own options.
pub(super) fn detect_shebang(data: &[u8]) -> Option<(FileType, DetectionSource)> {
    // The kernel reads a shebang line through BINPRM_BUF_SIZE (256 bytes).
    let buf = data.get(..256).unwrap_or(data);
    let line = buf.split(|&b| b == b'\n').next().unwrap_or(buf);
    // Any whitespace ends a word, not just space and tab: a CRLF script's
    // `#!/usr/bin/perl\r` names perl, whatever the kernel makes of the `\r`.
    let mut words = line
        .strip_prefix(b"#!")?
        .split(|&b| b.is_ascii_whitespace() || b == 0)
        .filter(|w| !w.is_empty());
    let mut name = basename(words.next()?);
    if name == b"env" || name == b"busybox" {
        name = basename(launched_interpreter(&mut words)?);
    }
    // `python3.11`, `perl5.36`, `ruby3.2` and `ksh93` are the same languages.
    while let [stem @ .., b'0'..=b'9' | b'.'] = name {
        name = stem;
    }
    let file_type = match name {
        b"sh" | b"bash" | b"rbash" | b"zsh" | b"dash" | b"ash" | b"ksh" | b"mksh" | b"yash"
        | b"fish" | b"tcsh" | b"csh" | b"atf-sh" => FileType::Shell,
        // debian/rules and friends: `#!/usr/bin/make -f`. Without this the
        // content heuristics mis-type make scripts as source code.
        b"make" | b"gmake" => FileType::Makefile,
        b"python" | b"pypy" => FileType::Python,
        b"node" | b"nodejs" | b"deno" | b"bun" => FileType::JavaScript,
        b"ts-node" | b"tsx" => FileType::TypeScript,
        b"ruby" | b"jruby" => FileType::Ruby,
        b"perl" => FileType::Perl,
        b"php" => FileType::Php,
        b"lua" | b"luajit" => FileType::Lua,
        b"pwsh" | b"powershell" => FileType::PowerShell,
        // JXA is `osascript -l JavaScript`; the body is JavaScript, and typing
        // it AppleScript would hide it from every JavaScript rule.
        b"osascript" if words.any(|w| w.eq_ignore_ascii_case(b"JavaScript")) => {
            FileType::JavaScript
        }
        b"osascript" => FileType::AppleScript,
        b"elixir" => FileType::Elixir,
        b"groovy" => FileType::Groovy,
        b"scala" => FileType::Scala,
        b"kotlin" | b"kscript" => FileType::Kotlin,
        b"swift" => FileType::Swift,
        // Babashka runs Clojure.
        b"bb" => FileType::Clojure,
        _ => return None,
    };
    Some((file_type, DetectionSource::Shebang))
}

/// The path segment after the last `/`.
fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|&b| b == b'/').next().unwrap_or(path)
}

/// The interpreter a launcher runs: the first word that is neither an option
/// nor a `NAME=value` assignment, as in `env -S perl -w` or `env -u X python3`.
fn launched_interpreter<'a>(words: &mut impl Iterator<Item = &'a [u8]>) -> Option<&'a [u8]> {
    while let Some(word) = words.next() {
        match word {
            // env options that consume the next word as their argument.
            b"-u" | b"--unset" | b"-C" | b"--chdir" => {
                words.next();
            }
            _ if word.starts_with(b"-") || word.contains(&b'=') => {}
            _ => return Some(word),
        }
    }
    None
}

#[cfg(test)]
mod tests;
