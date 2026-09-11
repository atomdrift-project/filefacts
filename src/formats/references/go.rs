//! Declarative Go module facts. Checksum history is not a dependency graph.
use super::Refs;
use crate::{HashAlgo, PinnedHash, RefKind, RefLocator};

// Tokenize directive lines without mistaking quoted // for comments. A
// malformed quoted token is not guessed. No shell or environment expansion.
pub(crate) fn words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            break;
        }
        if c == '=' && chars.peek() == Some(&'>') {
            chars.next();
            words.push("=>".into());
            if words.len() > 64 {
                return None;
            }
            continue;
        }
        if c == '"' || c == '`' {
            let quote = c;
            let mut value = String::new();
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == quote {
                    closed = true;
                    break;
                }
                if c == '\\' && quote == '"' {
                    value.push(c);
                    value.push(chars.next()?);
                } else {
                    value.push(c);
                }
            }
            if !closed {
                return None;
            }
            if quote == '"' {
                value = crate::decode_source_escapes(&value);
            }
            words.push(value);
        } else if matches!(c, '(' | ')') {
            words.push(c.to_string());
        } else {
            let mut value = c.to_string();
            while let Some(c) = chars.peek().copied() {
                if c.is_whitespace() || matches!(c, '(' | ')') {
                    break;
                }
                let mut ahead = chars.clone();
                ahead.next();
                if (c == '=' && ahead.next() == Some('>'))
                    || (c == '/' && chars.clone().nth(1) == Some('/'))
                {
                    break;
                }
                value.push(c);
                chars.next();
            }
            words.push(value);
        }
        if words.len() > 64 {
            return None;
        }
    }
    Some(words)
}

fn incomplete(out: &mut Refs<'_>, source: &str, evidence: &str) {
    out.push(
        RefLocator::Path(source.into()),
        RefKind::Undefined,
        "go.manifest.incomplete",
        evidence,
        None,
    );
}

pub(super) fn manifest(out: &mut Refs<'_>, source: &str) {
    let Some(text) = out.text else { return };
    if text.len() > 2 * 1024 * 1024 {
        incomplete(out, source, "source-byte-budget");
        return;
    }
    let mut block = String::new();
    for (index, line) in text.lines().enumerate() {
        if index >= 20_000 {
            incomplete(out, source, "directive-budget");
            break;
        }
        let Some(mut tokens) = words(line) else {
            incomplete(out, source, line);
            continue;
        };
        if tokens.is_empty() {
            continue;
        }
        if tokens == [")"] {
            if block.is_empty() {
                incomplete(out, source, line);
            }
            block.clear();
            continue;
        }
        let directive = if block.is_empty() {
            tokens.remove(0)
        } else {
            block.clone()
        };
        if tokens == ["("] {
            block = directive;
            continue;
        }
        let fields: Vec<_> = tokens.iter().map(String::as_str).collect();
        match (directive.as_str(), fields.as_slice()) {
            ("require", [module, version]) if source == "go.mod" => out.push(
                RefLocator::Purl(purl(module, version)),
                RefKind::Dependency,
                source,
                line.trim(),
                None,
            ),
            ("replace", _) => {
                let Some(split) = fields.iter().position(|v| *v == "=>") else {
                    incomplete(out, source, line);
                    continue;
                };
                if !(1..=2).contains(&split) {
                    incomplete(out, source, line);
                    continue;
                }
                let target = &fields[split + 1..];
                let locator = match target {
                    [path] => RefLocator::Path((*path).into()),
                    [module, version] => RefLocator::Purl(purl(module, version)),
                    _ => {
                        incomplete(out, source, line);
                        continue;
                    }
                };
                // A replacement directive alone does not select a dependency.
                out.push(
                    locator,
                    RefKind::Undefined,
                    format!("{source}.replace"),
                    line.trim().strip_prefix("replace").unwrap_or(line).trim(),
                    None,
                );
            }
            ("exclude", [module, version]) if source == "go.mod" => out.push(
                RefLocator::Purl(purl(module, version)),
                RefKind::Undefined,
                "go.mod.exclude",
                line.trim(),
                None,
            ),
            ("use", [path]) if source == "go.work" => out.push(
                RefLocator::Path((*path).into()),
                RefKind::Local,
                "go.work.use",
                line.trim(),
                None,
            ),
            ("tool", [path]) => out.push(
                RefLocator::Path((*path).into()),
                RefKind::Undefined,
                "go.mod.tool",
                line.trim(),
                None,
            ),
            ("module" | "go" | "toolchain" | "godebug" | "retract", _) => {}
            _ => incomplete(out, source, line),
        }
    }
    if !block.is_empty() {
        incomplete(out, source, "unterminated-directive-block");
    }
}

pub(super) fn sums(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    if text.len() > 2 * 1024 * 1024 {
        incomplete(out, "go.sum", "source-byte-budget");
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if index >= 20_000 {
            incomplete(out, "go.sum", "checksum-budget");
            break;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let [module, version, hash] = fields.as_slice() else {
            incomplete(out, "go.sum", line);
            continue;
        };
        let Some(hash) = hash.strip_prefix("h1:") else {
            incomplete(out, "go.sum", line);
            continue;
        };
        let metadata = version.ends_with("/go.mod");
        out.push(
            RefLocator::Purl(purl(module, version.trim_end_matches("/go.mod"))),
            RefKind::Undefined,
            if metadata { "go.sum.go.mod" } else { "go.sum" },
            line.trim(),
            Some(PinnedHash {
                algo: HashAlgo::GoModH1,
                value: hash.into(),
            }),
        );
    }
}

pub(super) fn vendor(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    if text.len() > 2 * 1024 * 1024 {
        incomplete(out, "modules.txt", "source-byte-budget");
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if index >= 20_000 {
            incomplete(out, "modules.txt", "vendor-budget");
            break;
        }
        let Some(entry) = line.strip_prefix("# ") else {
            continue;
        };
        let fields: Vec<_> = entry.split_whitespace().take(3).collect();
        if let [module, version, ..] = fields.as_slice() {
            if version.starts_with('v') {
                out.push(
                    RefLocator::Purl(purl(module, version)),
                    RefKind::Undefined,
                    "go.vendor.module",
                    line,
                    None,
                );
            }
        }
    }
}

fn purl(module: &str, version: &str) -> String {
    format!("pkg:golang/{module}@{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_directives_handle_comments_quotes_and_adjacent_arrow() {
        assert_eq!(
            words("replace example.test/lib=>../fork// comment").unwrap(),
            ["replace", "example.test/lib", "=>", "../fork"]
        );
        assert_eq!(
            words("use \"./folder//name\" // comment").unwrap(),
            ["use", "./folder//name"]
        );
        assert!(words("use \"unfinished").is_none());
        assert!(words(&"token ".repeat(65)).is_none());
    }

    #[test]
    fn go_vendor_truncation_is_explicit() {
        let text = "# example.test/lib v1.0.0\n".repeat(20_001);
        let parsed =
            crate::open_with_path(std::path::Path::new("vendor/modules.txt"), text.as_bytes())
                .unwrap();
        assert!(
            parsed
                .references()
                .iter()
                .any(|r| r.source == "go.manifest.incomplete")
        );
    }
}
