//! Declarative Go module facts. Checksum history is not a dependency graph.
use super::Refs;
use crate::{HashAlgo, PinnedHash, RefKind, RefLocator};

/// The `source` of each Go reference this module emits. The context pass
/// (`go_dependency_context`) matches on them, so both sides name them here.
pub(crate) mod source {
    pub(crate) const MOD: &str = "go.mod";
    pub(crate) const WORK: &str = "go.work";
    pub(crate) const SUM: &str = "go.sum";
    pub(crate) const SUM_GO_MOD: &str = "go.sum.go.mod";
    pub(crate) const MOD_REPLACE: &str = "go.mod.replace";
    pub(crate) const WORK_REPLACE: &str = "go.work.replace";
    pub(crate) const MOD_EXCLUDE: &str = "go.mod.exclude";
    pub(crate) const MOD_TOOL: &str = "go.mod.tool";
    pub(crate) const WORK_USE: &str = "go.work.use";
    pub(crate) const VENDOR_MODULE: &str = "go.vendor.module";
    /// A limit marker: the named manifest did not parse completely.
    pub(crate) const INCOMPLETE: &str = "go.manifest.incomplete";
}

/// Largest manifest read; a bigger one is marked incomplete unread.
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
/// Most manifest lines read; the rest are marked incomplete.
const MAX_MANIFEST_LINES: usize = 20_000;
/// Most words on one directive line.
const MAX_LINE_WORDS: usize = 64;

// Tokenize directive lines without mistaking quoted // for comments. A
// malformed quoted token is not guessed. No shell or environment expansion.
fn words(line: &str) -> Option<Vec<String>> {
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
            if words.len() > MAX_LINE_WORDS {
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
                value = crate::decode_source_escapes_for_type(&value, crate::FileType::Go);
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
                let next = chars.clone().nth(1);
                if (c == '=' && next == Some('>')) || (c == '/' && next == Some('/')) {
                    break;
                }
                value.push(c);
                chars.next();
            }
            words.push(value);
        }
        if words.len() > MAX_LINE_WORDS {
            return None;
        }
    }
    Some(words)
}

fn incomplete(out: &mut Refs<'_>, manifest: &str, evidence: &str) {
    tracing::debug!(
        target: "filefacts::references::go",
        format = manifest,
        len = evidence.len(),
        "Go manifest line not modelled; references from it are incomplete"
    );
    out.push(
        RefLocator::Path(manifest.into()),
        RefKind::Undefined,
        source::INCOMPLETE,
        evidence,
        None,
    );
}

/// `go.mod` or `go.work` directives; `manifest` is [`source::MOD`] or
/// [`source::WORK`].
pub(super) fn manifest(out: &mut Refs<'_>, manifest: &str) {
    let Some(text) = out.text else { return };
    if text.len() > MAX_MANIFEST_BYTES {
        incomplete(out, manifest, "source-byte-budget");
        return;
    }
    let mut block = String::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MANIFEST_LINES {
            incomplete(out, manifest, "directive-budget");
            break;
        }
        let Some(mut tokens) = words(line) else {
            incomplete(out, manifest, line);
            continue;
        };
        if tokens.is_empty() {
            continue;
        }
        if tokens == [")"] {
            if block.is_empty() {
                incomplete(out, manifest, line);
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
            ("require", [module, version]) if manifest == source::MOD => out.push(
                RefLocator::Purl(purl(module, version)),
                RefKind::Dependency,
                manifest,
                line.trim(),
                None,
            ),
            ("replace", _) => {
                let Some(split) = fields.iter().position(|v| *v == "=>") else {
                    incomplete(out, manifest, line);
                    continue;
                };
                if !(1..=2).contains(&split) {
                    incomplete(out, manifest, line);
                    continue;
                }
                let target = fields.get(split + 1..).unwrap_or_default();
                let locator = match target {
                    [path] => RefLocator::Path((*path).into()),
                    [module, version] => RefLocator::Purl(purl(module, version)),
                    _ => {
                        incomplete(out, manifest, line);
                        continue;
                    }
                };
                // A replacement directive alone does not select a dependency.
                out.push(
                    locator,
                    RefKind::Undefined,
                    if manifest == source::MOD {
                        source::MOD_REPLACE
                    } else {
                        source::WORK_REPLACE
                    },
                    line.trim().strip_prefix("replace").unwrap_or(line).trim(),
                    None,
                );
                if let (Some(reference), Some(module)) = (out.refs.last_mut(), fields.first()) {
                    let version = (split == 2)
                        .then(|| fields.get(1).map(|v| (*v).to_string()))
                        .flatten();
                    reference.replaces = Some(crate::Replaced::new(*module, version));
                }
            }
            ("exclude", [module, version]) if manifest == source::MOD => out.push(
                RefLocator::Purl(purl(module, version)),
                RefKind::Undefined,
                source::MOD_EXCLUDE,
                line.trim(),
                None,
            ),
            ("use", [path]) if manifest == source::WORK => out.push(
                RefLocator::Path((*path).into()),
                RefKind::Local,
                source::WORK_USE,
                line.trim(),
                None,
            ),
            ("tool", [path]) => out.push(
                RefLocator::Path((*path).into()),
                RefKind::Undefined,
                source::MOD_TOOL,
                line.trim(),
                None,
            ),
            ("module" | "go" | "toolchain" | "godebug" | "retract", _) => {}
            _ => incomplete(out, manifest, line),
        }
    }
    if !block.is_empty() {
        incomplete(out, manifest, "unterminated-directive-block");
    }
}

pub(super) fn sums(out: &mut Refs<'_>) {
    let Some(text) = out.text else { return };
    if text.len() > MAX_MANIFEST_BYTES {
        incomplete(out, "go.sum", "source-byte-budget");
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MANIFEST_LINES {
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
            if metadata {
                source::SUM_GO_MOD
            } else {
                source::SUM
            },
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
    if text.len() > MAX_MANIFEST_BYTES {
        incomplete(out, "modules.txt", "source-byte-budget");
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_MANIFEST_LINES {
            incomplete(out, "modules.txt", "vendor-budget");
            break;
        }
        let Some(entry) = line.strip_prefix("# ") else {
            continue;
        };
        let fields: Vec<_> = entry.split_whitespace().take(3).collect();
        if let [module, version, ..] = fields.as_slice()
            && version.starts_with('v')
        {
            out.push(
                RefLocator::Purl(purl(module, version)),
                RefKind::Undefined,
                source::VENDOR_MODULE,
                line,
                None,
            );
        }
    }
}

fn purl(module: &str, version: &str) -> String {
    format!("pkg:golang/{module}@{version}")
}

#[cfg(test)]
mod tests;
