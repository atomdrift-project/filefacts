//! A shell prologue that immediately re-execs this same file through Perl.
//! This identifies the documented dual-language launch convention, not the
//! provenance or safety of the interpreter or the rest of the program.

use regex::Regex;
use std::sync::LazyLock;

pub(super) fn recognized(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data.get(..32 * 1024).unwrap_or(data)) else {
        return false;
    };
    // The caller has already identified a shell shebang. Only comments and
    // blank lines may precede the shim: an earlier shell command is not this
    // immediate handoff convention.
    let mut lines = text.lines().filter_map(|line| {
        let line = line.trim();
        (!line.is_empty() && !line.starts_with('#')).then_some(line)
    });
    let Some(eval) = lines.next() else {
        return false;
    };
    let Some(guard) = lines.next() else {
        return false;
    };
    let guard = guard.split_once('#').map_or(guard, |(code, _)| code).trim();
    if guard != "if 0;" {
        return false;
    }
    static SHIM: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"^eval 'exec (?:perl|/[A-Za-z0-9_./-]+/perl|\$\{PERL:=/[A-Za-z0-9_./-]+/perl\})(?: -[wWSxTt]+)* \$0 \$\{1\+"\$@"\}'$"#,
        ).expect("fixed Perl self-exec shim grammar")
    });
    SHIM.is_match(eval)
}

#[cfg(test)]
mod tests;
