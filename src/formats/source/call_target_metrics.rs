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
        metrics.insert(metric!("calls.obfuscated_target_count"), obfuscated as f64);
    }
    if dynamic > 0 {
        metrics.insert(metric!("calls.dynamic_target_count"), dynamic as f64);
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
    let bytes = target.as_bytes();
    bytes.windows(2).any(|w| {
        w[0] == b'\\' && (w[1] == b'x' || w[1] == b'X' || w[1].is_ascii_digit() && w[1] <= b'7')
    })
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
        // A quoted variable command (best practice) is dynamic, not shattered.
        assert_eq!(shell("\"$SANE_SH\""), TargetKind::Dynamic);
        assert_eq!(shell("\"$python_version\""), TargetKind::Dynamic);
        // A quoted literal command unwraps to a plain name.
        assert_eq!(shell("\"ls\""), TargetKind::Clean);
        // Default/alternate parameter command fallbacks are a standard idiom.
        assert_eq!(shell("${filt:-cat}"), TargetKind::Dynamic);
        assert_eq!(shell("${PAGER:-less}"), TargetKind::Dynamic);
        // A single leading backslash is the benign alias-bypass idiom.
        assert_eq!(shell("\\rm"), TargetKind::Clean);
    }

    #[test]
    fn obfuscated_command_names() {
        for t in [
            "\\b\\u\\n",                // 02 backslash escapes
            "$A$B",                     // 04 glued expansions
            "b$@u$n",                   // 08 $@ glue
            "b$*u$n",                   // 09 $* glue
            "b${UNSET}u${NOPE}n",       // 10 empty-var glue
            "$(echo bun)",              // 12 command-sub decoder
            "$(printf \"\\142\\165\")", // 13 octal-escape decoder
            "$(printf \"\\x62\")",      // 14 hex-escape decoder
        ] {
            assert_eq!(shell(t), TargetKind::Obfuscated, "{t}");
        }
    }

    #[test]
    fn quote_shatter_and_format_printf_are_not_metric_obfuscated() {
        // Quote-shattered literals unwrap to a plain name here (the text
        // char-split traits own that signal); a printf format string and an
        // error message with embedded quotes must not be flagged.
        assert_eq!(shell("\"b\"'u'\"n\""), TargetKind::Clean);
        assert_eq!(
            shell("`printf '%sX\\n' \"$1\" | sed \"$e\"`"),
            TargetKind::Dynamic
        );
        assert_eq!(
            shell("\"Failed to start 'pamcat' process\""),
            TargetKind::Clean
        );
        // A spaced/multi-line "target" is a mis-parsed string argument, not a
        // welded command name — backslash continuations must not trip it.
        assert_eq!(
            shell("pgmtoppm \\\"$colorlist[0]\\\" >$outfile"),
            TargetKind::Clean
        );
        // `echo "$x" | sed` indent plumbing is not a decoder.
        assert_eq!(
            shell("`echo \"$indent\" | sed 's|.| |g'`"),
            TargetKind::Dynamic
        );
    }

    #[test]
    fn default_param_command_is_dynamic_not_obfuscated() {
        // `${b:-bun}` (sample 19) is structurally identical to the benign
        // `${PAGER:-less}` idiom, so it must classify as dynamic, never
        // obfuscated — there is no FP-safe way to flag it.
        assert_eq!(shell("${b:-bun}"), TargetKind::Dynamic);
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
