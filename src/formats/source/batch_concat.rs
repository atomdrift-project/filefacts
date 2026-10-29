//! Straight-line batch snapshot/concatenation loops, read over the shared
//! line model ([`super::batch_lines`]). Facts describe source-local requests,
//! not runtime success. Conditional/unknown loop bodies never establish these
//! profiles.
use super::batch_lines::{BODY_BUDGET, Lines, Unmodelled, comment, words};
use crate::formats::common::starts_with_ci;
use crate::{Metrics, metric};
use std::collections::{HashMap, HashSet};

#[derive(Default, Debug)]
struct Stats {
    loops: usize,
    seeded: usize,
    fanout: usize,
    limited: bool,
}

pub(super) fn emit(source: &str, metrics: &mut Metrics) {
    let stats = analyze(source);
    metrics.insert(
        metric!("source.batch.unbounded_snapshot_concat_loops"),
        stats.loops as f64,
    );
    metrics.insert(
        metric!("source.batch.seeded_snapshot_concat_loops"),
        stats.seeded as f64,
    );
    metrics.insert(
        metric!("source.batch.snapshot_concat_max_fanout"),
        stats.fanout as f64,
    );
    if stats.limited {
        metrics.insert(metric!("source.batch.concat_analysis_limited"), 1.0);
    }
}

fn analyze(source: &str) -> Stats {
    let lines = match Lines::new(source) {
        Ok(lines) => lines,
        Err(why) => {
            tracing::debug!(
                target: "filefacts::source",
                format = "batch",
                len = source.len(),
                reason = ?why,
                "batch concat: file not modelled"
            );
            return Stats {
                limited: why == Unmodelled::TooLarge,
                ..Stats::default()
            };
        }
    };
    let mut stats = Stats::default();
    let mut budget = BODY_BUDGET;
    for (start, end) in lines.loops() {
        let Some(body) = lines.lines.get(start + 1..end) else {
            continue;
        };
        if body.len() > budget {
            stats.limited = true;
            break;
        }
        budget -= body.len();
        if let Some((seeded, fanout)) = loop_body(body) {
            stats.loops += 1;
            stats.seeded += usize::from(seeded);
            stats.fanout = stats.fanout.max(fanout);
        }
    }
    stats
}

fn expand(text: &str, env: &HashMap<String, String>) -> Option<String> {
    let mut result = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        result.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let end = rest.find('%')?;
        result.push_str(env.get(&rest[..end].to_ascii_lowercase())?);
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    Some(result)
}

fn path(text: &str) -> Option<String> {
    let text = text.trim();
    let text = if text.starts_with('"') {
        text.strip_prefix('"')?.strip_suffix('"')?
    } else {
        text
    };
    if text.is_empty() || text.chars().any(|c| "*?%\"&|<>!".contains(c)) {
        return None;
    }
    let mut text = text.replace('/', "\\").to_ascii_lowercase();
    let unc = text.starts_with("\\\\");
    while text.contains("\\\\") {
        text = text.replace("\\\\", "\\");
    }
    if unc {
        text.insert(0, '\\');
    }
    while let Some(rest) = text.strip_prefix(".\\") {
        text = rest.to_string();
    }
    Some(text)
}

fn tokens(text: &str, plus_separator: bool) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for c in text.chars() {
        if c == '"' {
            quoted = !quoted;
            token.push(c);
        } else if !quoted
            && (if plus_separator {
                c == '+'
            } else {
                c.is_whitespace()
            })
        {
            if !token.is_empty() {
                result.push(std::mem::take(&mut token));
            } else if plus_separator {
                return None;
            }
        } else {
            token.push(c);
        }
    }
    if quoted || (plus_separator && token.is_empty()) {
        return None;
    }
    if !token.is_empty() {
        result.push(token);
    }
    Some(result)
}

fn loop_body(body: &[&str]) -> Option<(bool, usize)> {
    let mut env = HashMap::new();
    let mut versions: HashMap<String, usize> = HashMap::new();
    let mut snapshots: HashMap<String, (String, usize, usize)> = HashMap::new();
    let mut resets = HashSet::new();
    let mut seeds = HashSet::new();
    let mut growth: HashMap<String, usize> = HashMap::new();
    for line in body {
        if line.is_empty() || comment(line) {
            continue;
        }
        let (cmd, rest) = words(line);
        // Inline control operators would invalidate the linear body proof.
        if line.chars().any(|c| "&|()^".contains(c)) {
            return None;
        }
        if cmd.eq_ignore_ascii_case("set") {
            let assignment = rest
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(rest);
            let (name, value) = assignment.split_once('=')?;
            if name.is_empty()
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                || value.chars().any(|c| "%!<>".contains(c))
            {
                return None;
            }
            env.insert(name.to_ascii_lowercase(), value.to_string());
        } else if cmd.eq_ignore_ascii_case("cls") || cmd.eq_ignore_ascii_case("ctty") {
            if (cmd.eq_ignore_ascii_case("cls") && !rest.is_empty())
                || (cmd.eq_ignore_ascii_case("ctty")
                    && !rest.eq_ignore_ascii_case("nul")
                    && !rest.eq_ignore_ascii_case("con"))
            {
                return None;
            }
            // Console operations without redirection do not mutate files.
        } else if cmd.eq_ignore_ascii_case("echo") || starts_with_ci(cmd, "echo.") {
            let text = if cmd.eq_ignore_ascii_case("echo") {
                rest
            } else {
                // `cmd` is `line`'s first word, so this skips its `echo.`.
                line.get(5..).unwrap_or_default()
            };
            let append = text.contains(">>");
            if let Some((data, target)) = text.split_once(if append { ">>" } else { ">" }) {
                if data.contains('>') || target.contains('>') || target.contains('<') {
                    return None;
                }
                let file = path(&expand(target, &env)?)?;
                *versions.entry(file.clone()).or_default() += 1;
                if append
                    && !data.contains(['%', '!'])
                    && !data.trim().eq_ignore_ascii_case("off")
                    && !data.trim().eq_ignore_ascii_case("on")
                    && (!data.trim().is_empty() || starts_with_ci(cmd, "echo."))
                {
                    seeds.insert(file);
                } else if !append {
                    resets.insert(file);
                }
            }
        } else if cmd.eq_ignore_ascii_case("copy") {
            let expanded = expand(rest, &env)?;
            let parts = tokens(&expanded, false)?;
            let mut binary = false;
            let mut operands = Vec::new();
            for part in parts {
                if part.eq_ignore_ascii_case("/b") {
                    binary = true;
                } else if part.eq_ignore_ascii_case("/y") {
                } else if part.starts_with('/') {
                    return None;
                } else {
                    operands.push(part);
                }
            }
            let (sources, destination) = match operands.as_slice() {
                [sources] if binary => (sources, None),
                [sources, destination] if binary => (sources, Some(destination)),
                _ => return None,
            };
            let sources: Vec<_> = tokens(sources, true)?
                .iter()
                .map(|s| path(s))
                .collect::<Option<_>>()?;
            let destination = match destination {
                Some(destination) => path(destination)?,
                None => sources.first()?.clone(),
            };
            let (source, appended) = sources.split_first()?;
            if appended.is_empty() {
                if source == &destination {
                    return None;
                }
                let source_version = *versions.get(source).unwrap_or(&0);
                let version = versions.entry(destination.clone()).or_default();
                *version += 1;
                snapshots.insert(
                    destination.clone(),
                    (source.clone(), source_version, *version),
                );
                resets.insert(destination);
            } else {
                // Omitted destination concatenation appends to its first source.
                // A different destination overwrites rather than amplifying it.
                if &destination != source {
                    resets.insert(destination.clone());
                } else if appended.iter().all(|snapshot| {
                    snapshots
                        .get(snapshot)
                        .is_some_and(|(origin, version, dest_version)| {
                            origin == source
                                && *version == *versions.get(source).unwrap_or(&0)
                                && *dest_version == *versions.get(snapshot).unwrap_or(&0)
                        })
                }) {
                    growth.insert(source.clone(), appended.len());
                }
                *versions.entry(destination).or_default() += 1;
            }
        } else {
            return None;
        }
    }
    let valid: Vec<_> = growth
        .iter()
        .filter(|(source, _)| !resets.contains(*source))
        .collect();
    let fanout = valid.iter().map(|(_, count)| **count).max()?;
    Some((
        valid.iter().any(|(source, _)| seeds.contains(*source)),
        fanout,
    ))
}

#[cfg(test)]
mod tests;
