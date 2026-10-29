//! Call-target (command-name) obfuscation metrics.
//!
//! Most static analysis keys on *which* command a script runs. Obfuscators
//! defeat that by constructing the command **name** itself at runtime —
//! shattering it across quoted fragments, gluing variable expansions between
//! its letters, decoding it from escapes, or producing it from a command
//! substitution. The resulting call has a target string that no human writes
//! by hand.
//!
//! This pass classifies each call's static target and emits two
//! language-agnostic counts so trait authors don't need per-shape regexes:
//!
//! - `calls.obfuscated_target_count` — command names that are demonstrably
//!   constructed/hidden (quote-shatter, backslash escapes, command
//!   substitution, default-value parameters, expansions glued into a word).
//!   These never occur in hand-written source and are safe to flag on their
//!   own.
//! - `calls.dynamic_target_count` — command names that are a single plain
//!   variable/positional expansion (`$CC`, `$1`). Legitimate on its own
//!   (interpreter-in-a-variable) but a useful gate when a whole tiny script
//!   does nothing but expand-and-exec.
//!
//! The classifier dispatches on language. Only `bash` is implemented today;
//! `python`, `ruby`, and `javascript` (computed/indirect callees, `getattr`/
//! `send`/`Function` reconstruction) are the planned next arms — the trait
//! layer already consumes the generic metric, so adding a language is purely
//! additive here.

use crate::metric;
use crate::output::{Metrics, Symbol};

use super::langs::Lang;

/// How a call's command-name target was expressed.
#[derive(Debug, PartialEq, Eq)]
enum TargetKind {
    /// A literal command name (`echo`, `git`, `printf`) or a benign
    /// path/expansion we don't treat as obfuscation.
    Clean,
    /// A single plain variable/positional expansion used as the command
    /// (`$CC`, `$1`, `${VAR}`). Legitimate but worth gating on.
    Dynamic,
    /// A command name that is constructed or hidden — never hand-written.
    Obfuscated,
}

/// Emit the call-target obfuscation counts for the given calls.
///
/// `calls` is the in-order slice of [`Symbol::Call`] records; `lang` picks the
/// classifier for the language they were parsed from.
pub(super) fn emit(calls: &[Symbol], lang: Lang, metrics: &mut Metrics) {
    let mut obfuscated = 0u64;
    let mut dynamic = 0u64;
    for call in calls {
        let Symbol::Call {
            target: Some(target),
            ..
        } = call
        else {
            continue;
        };
        match classify(target, lang) {
            TargetKind::Obfuscated => obfuscated += 1,
            TargetKind::Dynamic => dynamic += 1,
            TargetKind::Clean => {}
        }
    }
    if obfuscated > 0 {
        metrics.insert(metric!("calls.obfuscated_target_count"), obfuscated as f64);
    }
    if dynamic > 0 {
        metrics.insert(metric!("calls.dynamic_target_count"), dynamic as f64);
    }
}

fn classify(target: &str, lang: Lang) -> TargetKind {
    match lang {
        Lang::Bash => classify_shell(target),
        // python / ruby / javascript arms land here next: computed member
        // access, getattr/send reconstruction, Function()/eval indirection.
        _ => TargetKind::Clean,
    }
}

/// Classify a shell command-name token.
fn classify_shell(target: &str) -> TargetKind {
    // Path-form commands (`/usr/bin/x`, `$HOME/bin/y`, `./script`, a quoted
    // path with spaces) are normal program locations, never name-hiding —
    // settle them first so the rules below only see bare tokens.
    if target.contains('/') {
        return TargetKind::Clean;
    }
    // Strip quotes and judge the inner form. A single quoted token (`"$VAR"`,
    // `"ls"`) is the normal, recommended way to run a command; quote-SHATTERED
    // literals (`"b"'u'"n"`) are left to the text char-split traits, which
    // distinguish adjacent single-char fragments from ordinary quoted strings
    // (error messages carry many quotes too — `"Failed to run 'foo'"`).
    let unquoted;
    let target = if target.contains('"') || target.contains('\'') {
        unquoted = target.replace(['"', '\''], "");
        unquoted.as_str()
    } else {
        target
    };
    // Command substitution as the command name. Hiding shows up as a decoder
    // or escape sequence inside the substitution (`$(printf '\x62')`,
    // `$(echo bun)`); a resolver (`$(command -v python)`) is benign-dynamic.
    if target.contains("$(") || target.contains('`') {
        if is_decoding_substitution(target) {
            return TargetKind::Obfuscated;
        }
        return TargetKind::Dynamic;
    }
    // A command NAME is a single token. A target carrying internal whitespace
    // or a newline is a tree-sitter mis-parse of a string argument / here-doc
    // (an eval'd command string, a multi-line Tcl literal), not a welded
    // command name — the byte-level rules below would misfire on it.
    if target
        .bytes()
        .any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        return TargetKind::Clean;
    }
    // Backslash escapes on a command name (`\b\u\n`) decode to the same bytes
    // and exist only to break the token up for scanners. A single leading
    // backslash (`\rm`, `\ls`) is the benign alias-bypass idiom, so require
    // two or more escapes.
    if target.bytes().filter(|&b| b == b'\\').count() >= 2 {
        return TargetKind::Obfuscated;
    }
    // NOTE: default/alternate parameter expansion (`${x:-cat}`) is deliberately
    // NOT treated as obfuscation — `${PAGER:-less}` / `${filt:-cat}` command
    // fallbacks are a standard idiom (zdiff, pager/editor wrappers) and are
    // structurally indistinguishable from a malicious `${b:-bun}`.
    //
    // Expansions welded into a word (`b$@u`, `$A$B`, `b${UNSET}u${NOPE}n`).
    if has_welded_expansion(target) {
        return TargetKind::Obfuscated;
    }
    // A bare single expansion as the command (`$CC`, `$1`, `${VAR}`,
    // `${x:-default}`): dynamic but legitimate. Gate downstream on file size /
    // lack of structure.
    if target.starts_with('$') {
        return TargetKind::Dynamic;
    }
    TargetKind::Clean
}

/// A command substitution whose body decodes/echoes its output rather than
/// resolving a program path — the hiding shape, as opposed to a benign
/// `$(command -v python)` resolver or a `$(printf '%sX\n' "$1")` formatter.
fn is_decoding_substitution(target: &str) -> bool {
    // base64/xxd: always a byte decoder.
    if target.contains("base64") || target.contains("xxd") {
        return true;
    }
    // printf only counts when it reconstructs bytes from hex (`\x62`) or octal
    // (`\142`) escapes — a normal format string (`printf '%sX\n'`) is not a
    // decoder. `has_byte_escape` excludes `\n`/`\t`-style letter escapes.
    if target.contains("printf") && has_byte_escape(target) {
        return true;
    }
    // `$(echo word)` runs the echoed literal as the command — pointless unless
    // hiding the name. `$(echo "$x" | sed …)` is benign indent/format
    // plumbing, so exclude pipelines.
    target.contains("echo") && !target.contains('|')
}

/// True when the string contains a `\xHH` hex escape or a `\NNN`-style octal
/// escape (backslash followed by an octal digit), the byte-reconstruction
/// shapes — not letter escapes like `\n`/`\t`.
fn has_byte_escape(target: &str) -> bool {
    target
        .as_bytes()
        .windows(2)
        .any(|w| matches!(w, [b'\\', b'x' | b'X' | b'0'..=b'7']))
}

/// True when an expansion is welded into a word rather than standing alone.
/// Requires an alphanumeric directly against a `$` AND either a special
/// parameter (`$@`/`$*`) inside the token or two-plus expansions glued
/// together. This catches `b$@u`, `$A$B`, and `b${X}u${Y}n` while leaving a
/// single `python${VER}` (one expansion on a real word) as merely dynamic.
fn has_welded_expansion(target: &str) -> bool {
    let bytes = target.as_bytes();
    let alnum_before_dollar = bytes
        .windows(2)
        .any(|w| matches!(w, [before, b'$'] if before.is_ascii_alphanumeric()));
    if !alnum_before_dollar {
        return false;
    }
    let dollar_count = bytes.iter().filter(|&&b| b == b'$').count();
    dollar_count >= 2 || target.contains("$@") || target.contains("$*")
}

#[cfg(test)]
mod tests;
