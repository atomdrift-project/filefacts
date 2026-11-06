//! The value a string-literal node denotes: its prefix, delimiters and
//! escapes resolved by the rules of the language's [`StringSyntax`].

use super::escapes;
use super::langs::{LangConfig, StringSyntax};
use tree_sitter::Node;

/// The value a quoted string literal denotes: prefix and delimiters stripped,
/// escapes decoded unless the literal is raw. Shared by the literal tier, call
/// arguments, subscript folding and both flow analyses, so all of them agree
/// on what `f"…"`, `r#"…"#` or `@"…"` holds.
///
/// `None` when the node is not a complete quoted literal: an unterminated
/// one, or an unquoted form such as a heredoc body or Perl `q{…}`, whose text
/// callers treat as they see fit. Interpolations stay as written.
pub(super) fn decode_string_literal(
    node: Node<'_>,
    source: &str,
    config: &LangConfig,
) -> Option<String> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    let kind = node.kind();
    match config.strings {
        StringSyntax::Quoted => quoted(raw, kind.contains("raw") || kind.contains("verbatim")),
        StringSyntax::RawTriple => raw_triple(raw),
        StringSyntax::Hashed => hashed(raw),
        StringSyntax::Rust => rust(raw),
        StringSyntax::CSharp => csharp(raw),
        StringSyntax::C => c_family(raw, kind),
        StringSyntax::Lua => lua(raw),
        StringSyntax::Elixir if raw.starts_with("\"\"\"") || raw.starts_with("'''") => {
            escapes::decode_elixir_heredoc(raw)
        }
        StringSyntax::Elixir => quoted(raw, false),
    }
}

/// Source text of a string-kind node that has no opening quote at all, which
/// [`decode_string_literal`] leaves to its caller.
pub(super) fn unquoted_literal<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    let first = raw.trim_start_matches(is_string_prefix).chars().next()?;
    (!matches!(first, '"' | '\'' | '`')).then_some(raw)
}

fn is_string_prefix(c: char) -> bool {
    matches!(c, 'b' | 'B' | 'r' | 'R' | 'f' | 'F' | 'u' | 'U')
}

/// Which quote runs open a literal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Run {
    /// One quote character.
    Single,
    /// One, or three when the literal opens with three.
    UpToThree,
    /// One, or however many (three or more) the literal opens with.
    Any,
}

/// The body of `text`, which must open with one of `quotes` repeated as
/// `run` allows and close with the same run followed by `hashes` `#`s, and
/// the length of the opening run.
fn unquote<'t>(text: &'t str, quotes: &str, run: Run, hashes: usize) -> Option<(&'t str, usize)> {
    let open = text.chars().next().filter(|&c| quotes.contains(c))?;
    let opened = text.bytes().take_while(|&b| char::from(b) == open).count();
    let len = match run {
        Run::UpToThree if opened >= 3 => 3,
        Run::Any if opened >= 3 => opened,
        _ => 1,
    };
    // `open` is an ASCII quote, so `len` bytes are `len` characters.
    let body = text.get(len..)?;
    let (body, close) = body.split_at_checked(body.len().checked_sub(len + hashes)?)?;
    let (quotes, marks) = close.as_bytes().split_at_checked(len)?;
    (quotes.iter().all(|&b| char::from(b) == open) && marks.iter().all(|&b| b == b'#'))
        .then_some((body, len))
}

/// `"…"`, `'…'` or `` `…` ``, single or triple quoted, behind any of the
/// `b`/`r`/`f`/`u` prefixes; an `r` prefix or a raw node kind keeps
/// backslashes as data.
fn quoted(raw: &str, raw_kind: bool) -> Option<String> {
    let text = raw.trim_start_matches(is_string_prefix);
    let prefix = &raw[..raw.len() - text.len()];
    let (body, _) = unquote(text, "\"'`", Run::UpToThree, 0)?;
    Some(if raw_kind || prefix.contains(['r', 'R']) {
        body.to_owned()
    } else {
        escapes::decode(body)
    })
}

/// Kotlin and Scala: a triple-quoted literal is raw, a single- or
/// character-quoted one decodes its escapes. A Scala interpolator
/// prefix (`s"…"`) decodes escapes for the standard `s` and `f`; `raw` and
/// custom interpolators get the text as written.
fn raw_triple(raw: &str) -> Option<String> {
    let text = raw.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
    let interpolator = &raw[..raw.len() - text.len()];
    let (body, run) = unquote(text, "\"'", Run::UpToThree, 0)?;
    let decodes = match interpolator {
        "" => run == 1,
        "s" | "f" => true,
        _ => false,
    };
    Some(if decodes {
        escapes::decode(body)
    } else {
        body.to_owned()
    })
}

/// Swift: `#`s around the quotes make a raw literal whose escapes are
/// `\` followed by as many `#`s; a triple-quoted literal loses its opening
/// and closing lines and the closing line's indentation.
fn hashed(raw: &str) -> Option<String> {
    let text = raw.trim_start_matches('#');
    let hashes = raw.len() - text.len();
    let (body, run) = unquote(text, "\"", Run::UpToThree, hashes)?;
    let dedented;
    let body = if run == 3 {
        dedented = dedent(body)?;
        dedented.as_str()
    } else {
        body
    };
    if hashes == 0 {
        return Some(escapes::decode(body));
    }
    // Rewrite to ordinary escapes: `\#…#` opens one, a bare `\` is data.
    let marker = format!("\\{}", "#".repeat(hashes));
    let mut plain = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find('\\') {
        plain.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix(marker.as_str()) {
            plain.push('\\');
            rest = after;
        } else {
            plain.push_str("\\\\");
            rest = &rest[1..];
        }
    }
    plain.push_str(rest);
    Some(escapes::decode(&plain))
}

/// Rust: an optional `b` or `c` prefix, then either `"…"` with escapes or a
/// raw `r"…"` / `r#"…"#` with any number of `#`s.
fn rust(raw: &str) -> Option<String> {
    let text = raw
        .strip_prefix('b')
        .or_else(|| raw.strip_prefix('c'))
        .unwrap_or(raw);
    match text.strip_prefix('r') {
        Some(text) => {
            let quoted = text.trim_start_matches('#');
            let hashes = text.len() - quoted.len();
            let (body, _) = unquote(quoted, "\"", Run::Single, hashes)?;
            Some(body.to_owned())
        }
        None => unquote(text, "\"", Run::Single, 0).map(|(body, _)| escapes::decode(body)),
    }
}

/// C#: `@` (verbatim, `""` for a quote), `$` (interpolated) in either order,
/// raw literals of three or more quotes, and a `u8` suffix.
fn csharp(raw: &str) -> Option<String> {
    let text = raw.trim_start_matches(['@', '$']);
    let verbatim = raw[..raw.len() - text.len()].contains('@');
    let text = text
        .strip_suffix("u8")
        .or_else(|| text.strip_suffix("U8"))
        .unwrap_or(text);
    let (body, run) = unquote(text, "\"", Run::Any, 0)?;
    if run >= 3 {
        // A raw literal: multi-line when its opening line is otherwise empty.
        return Some(if body.starts_with(['\n', '\r']) {
            dedent(body)?
        } else {
            body.to_owned()
        });
    }
    Some(if verbatim {
        body.replace("\"\"", "\"")
    } else {
        escapes::decode(body)
    })
}

/// C, C++ and Objective-C: an encoding prefix (`u8`, `u`, `U`, `L`) or
/// Objective-C's `@`, and C++ raw literals `R"delim(…)delim"`.
fn c_family(raw: &str, kind: &str) -> Option<String> {
    let text = ["u8", "u", "U", "L", "@"]
        .into_iter()
        .find_map(|prefix| raw.strip_prefix(prefix))
        .unwrap_or(raw);
    if kind == "raw_string_literal" {
        let (delimiter, body) = text.strip_prefix("R\"")?.split_once('(')?;
        if delimiter.len() > 16 {
            return None;
        }
        return body
            .strip_suffix(&format!("){delimiter}\""))
            .map(str::to_owned);
    }
    unquote(text, "\"'", Run::Single, 0).map(|(body, _)| escapes::decode(body))
}

/// Lua: long brackets `[==[…]==]` are raw, ignore an initial line break and
/// normalize every line ending to `\n`; quoted strings use Lua's escapes.
fn lua(raw: &str) -> Option<String> {
    let Some(after_open) = raw.strip_prefix('[') else {
        return unquote(raw, "\"'", Run::Single, 0).map(|(body, _)| escapes::decode_lua(body));
    };
    let level = after_open.bytes().take_while(|&byte| byte == b'=').count();
    let body = after_open.get(level..)?.strip_prefix('[')?;
    let close = format!("]{}]", "=".repeat(level));
    let body = body.strip_suffix(&close)?;
    let body = body
        .strip_prefix("\r\n")
        .or_else(|| body.strip_prefix("\n\r"))
        .or_else(|| body.strip_prefix('\n'))
        .or_else(|| body.strip_prefix('\r'))
        .unwrap_or(body);
    Some(
        body.replace("\r\n", "\n")
            .replace("\n\r", "\n")
            .replace('\r', "\n"),
    )
}

/// A multi-line literal body (Swift, C# raw) without its opening line break,
/// its closing line, the line break before that, and the closing line's
/// indentation on every line. `None` when the body is not in that form.
fn dedent(body: &str) -> Option<String> {
    let (opening, rest) = body.split_once('\n')?;
    if !opening.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r')) {
        return None;
    }
    let (content, indent) = rest.rsplit_once('\n').unwrap_or(("", rest));
    if !indent.bytes().all(|b| matches!(b, b' ' | b'\t')) {
        return None;
    }
    if !rest.contains('\n') {
        return Some(String::new());
    }
    let content = content.strip_suffix('\r').unwrap_or(content);
    let lines: Vec<&str> = content
        .split('\n')
        .map(|line| {
            line.strip_prefix(indent).unwrap_or_else(|| {
                if line.trim_ascii().is_empty() {
                    ""
                } else {
                    line
                }
            })
        })
        .collect();
    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests;
