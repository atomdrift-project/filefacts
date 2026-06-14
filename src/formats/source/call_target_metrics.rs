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

use crate::output::{Metrics, Symbol};

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
/// `calls` is the in-order slice of [`Symbol::Call`] records; `lang` is the
/// canonical language name from the active `LangConfig`.
pub(super) fn emit(calls: &[Symbol], lang: &str, metrics: &mut Metrics) {
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
        metrics.insert("calls.obfuscated_target_count", obfuscated as f64);
    }
    if dynamic > 0 {
        metrics.insert("calls.dynamic_target_count", dynamic as f64);
    }
}

fn classify(target: &str, lang: &str) -> TargetKind {
    match lang {
        "bash" => classify_shell(target),
        // python / ruby / javascript arms land here next: computed member
        // access, getattr/send reconstruction, Function()/eval indirection.
        _ => TargetKind::Clean,
    }
}

/// Classify a shell command-name token.
fn classify_shell(target: &str) -> TargetKind {
    // Path-form commands (`/usr/bin/x`, `$HOME/bin/y`, `./script`, a quoted
    // path with spaces) are normal program locations, never name-hiding —
    // settle them first so the quote/glue rules below only see bare tokens.
    if target.contains('/') {
        return TargetKind::Clean;
    }
    // Command substitution as the command name. Hiding shows up as a decoder
    // or escape sequence inside the substitution (`$(printf '\x62')`,
    // `$(echo bun)`); a resolver (`$(command -v python)`) is benign-dynamic.
    if target.contains("$(") || target.contains('`') {
        if is_decoding_substitution(target) {
            return TargetKind::Obfuscated;
        }
        return TargetKind::Dynamic;
    }
    // Quote characters in a command name shatter a literal into fragments
    // (`"b"'u'"n"`) — there is no benign reason to quote a command name
    // character-by-character.
    if target.contains('"') || target.contains('\'') {
        return TargetKind::Obfuscated;
    }
    // Backslash escapes on a command name (`\b\u\n`) decode to the same bytes
    // and exist only to break up the token for scanners.
    if target.contains('\\') {
        return TargetKind::Obfuscated;
    }
    // Default/alternate parameter expansion used to *produce* the command name
    // (`${b:-bun}`). Real scripts use these for argument fallbacks, not to name
    // the program being run.
    if target.contains(":-")
        || target.contains(":=")
        || target.contains(":+")
        || target.contains(":?")
    {
        return TargetKind::Obfuscated;
    }
    // Expansions welded into a word (`b$@u`, `$A$B`, `b${UNSET}u${NOPE}n`).
    if has_welded_expansion(target) {
        return TargetKind::Obfuscated;
    }
    // A bare single expansion as the command (`$CC`, `$1`, `${VAR}`, and the
    // benign `python${VER}` welded form ruled out above): dynamic but
    // legitimate. Gate downstream on file size / lack of structure.
    if target.starts_with('$') {
        return TargetKind::Dynamic;
    }
    TargetKind::Clean
}

/// A command substitution whose body decodes/echoes its output rather than
/// resolving a program path — the hiding shape, as opposed to a benign
/// `$(command -v python)` resolver.
fn is_decoding_substitution(target: &str) -> bool {
    const DECODERS: [&str; 4] = ["printf", "echo", "base64", "xxd"];
    target.contains('\\') || DECODERS.iter().any(|d| target.contains(d))
}

/// True when an expansion is welded into a word rather than standing alone.
/// Requires an alphanumeric directly against a `$` AND either a special
/// parameter (`$@`/`$*`) inside the token or two-plus expansions glued
/// together. This catches `b$@u`, `$A$B`, and `b${X}u${Y}n` while leaving a
/// single `python${VER}` (one expansion on a real word) as merely dynamic.
fn has_welded_expansion(target: &str) -> bool {
    let bytes = target.as_bytes();
    let alnum_before_dollar = bytes
        .iter()
        .enumerate()
        .skip(1)
        .any(|(i, &b)| b == b'$' && bytes[i - 1].is_ascii_alphanumeric());
    if !alnum_before_dollar {
        return false;
    }
    let dollar_count = bytes.iter().filter(|&&b| b == b'$').count();
    dollar_count >= 2 || target.contains("$@") || target.contains("$*")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(target: &str) -> TargetKind {
        classify(target, "bash")
    }

    #[test]
    fn clean_literals_are_clean() {
        for t in ["echo", "base64", "sh", "set", "alias", "printf", "git", "f"] {
            assert_eq!(shell(t), TargetKind::Clean, "{t}");
        }
    }

    #[test]
    fn benign_variable_and_path_commands() {
        // Interpreter-in-a-variable and path-prefixed commands are NOT
        // obfuscation; the bare ones are merely dynamic.
        assert_eq!(shell("$CC"), TargetKind::Dynamic);
        assert_eq!(shell("$1"), TargetKind::Dynamic);
        assert_eq!(shell("${PYTHON}"), TargetKind::Dynamic);
        assert_eq!(shell("$HOME/bin/tool"), TargetKind::Clean);
        assert_eq!(shell("${PREFIX}/sbin/daemon"), TargetKind::Clean);
        // A single expansion welded onto a real word (versioned interpreter)
        // reads as an ordinary name — neither obfuscated nor flag-worthy.
        assert_eq!(shell("python${VER}"), TargetKind::Clean);
        // Resolver command substitutions are dynamic, not obfuscated.
        assert_eq!(shell("$(command -v python)"), TargetKind::Dynamic);
        assert_eq!(shell("$(which gcc)"), TargetKind::Dynamic);
    }

    #[test]
    fn obfuscated_command_names() {
        for t in [
            "\"b\"'u'\"n\"",         // 01 quote-shatter
            "\\b\\u\\n",             // 02 backslash escapes
            "$A$B",                  // 04 glued expansions
            "b$@u$n",                // 08 $@ glue
            "b$*u$n",                // 09 $* glue
            "b${UNSET}u${NOPE}n",    // 10 empty-var glue
            "$(echo bun)",           // 12 command-sub decoder
            "$(printf \"\\x62\")",   // 14 command-sub decoder
            "${b:-bun}",             // 19 default-param
        ] {
            assert_eq!(shell(t), TargetKind::Obfuscated, "{t}");
        }
    }

    #[test]
    fn non_shell_languages_emit_nothing_yet() {
        assert_eq!(classify("$A$B", "javascript"), TargetKind::Clean);
        assert_eq!(classify("foo.bar", "python"), TargetKind::Clean);
    }

    #[test]
    fn emit_counts_into_metrics() {
        let calls = vec![
            Symbol::Call {
                target: Some("$A$B".to_string()),
                args: vec![],
                offset: None,
            },
            Symbol::Call {
                target: Some("$CC".to_string()),
                args: vec![],
                offset: None,
            },
            Symbol::Call {
                target: Some("echo".to_string()),
                args: vec![],
                offset: None,
            },
        ];
        let mut metrics = Metrics::default();
        emit(&calls, "bash", &mut metrics);
        assert_eq!(metrics.get("calls.obfuscated_target_count"), Some(1.0));
        assert_eq!(metrics.get("calls.dynamic_target_count"), Some(1.0));
    }
}
