//! A bounded line grammar for straight-line batch snapshot/concatenation loops.
//! Numeric and punctuation labels are read independently of tree-sitter's
//! narrower label grammar. Facts describe source-local requests, not runtime
//! success. Conditional/unknown loop bodies never establish these profiles.
use crate::{Metrics, metric};
use std::collections::{HashMap, HashSet, VecDeque};

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

fn bare(line: &str) -> &str {
    let line = line.trim();
    line.strip_prefix('@').unwrap_or(line).trim_start()
}

fn words(line: &str) -> (&str, &str) {
    line.split_once(char::is_whitespace)
        .map_or((line, ""), |(a, b)| (a, b.trim_start()))
}

fn label_name(name: &str) -> Option<String> {
    let name = name.trim().strip_prefix(':').unwrap_or(name.trim());
    (!name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.$#!-".contains(c)))
    .then(|| name.to_ascii_lowercase())
}

fn label(line: &str) -> Option<String> {
    if line.starts_with("::") {
        return None;
    }
    let name = line.strip_prefix(':')?;
    label_name(name.split_whitespace().next()?)
}

fn jump(line: &str) -> Option<String> {
    let (cmd, rest) = words(line);
    cmd.eq_ignore_ascii_case("goto")
        .then(|| label_name(rest))
        .flatten()
}

fn analyze(source: &str) -> Stats {
    if source.len() > 512 * 1024 {
        return Stats {
            limited: true,
            ..Stats::default()
        };
    }
    let lines: Vec<_> = source.lines().map(bare).collect();
    if lines.len() > 10_000 {
        return Stats {
            limited: true,
            ..Stats::default()
        };
    }
    let mut labels = HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(name) = label(line) {
            if labels.insert(name, i).is_some() {
                return Stats::default();
            }
        }
    }
    let mut reachable = HashSet::new();
    let mut pending = VecDeque::from([0]);
    while let Some(i) = pending.pop_front() {
        let Some(&line) = lines.get(i) else {
            continue;
        };
        if !reachable.insert(i) {
            continue;
        }
        let (cmd, rest) = words(line);
        // Comments and labels cannot change entry flow. Other compound lines,
        // nested interpreters and batch transfers require interprocedural flow
        // analysis; stop rather than claiming their fallthrough reaches a loop.
        if cmd.eq_ignore_ascii_case("rem")
            || line.starts_with(':')
            || line.to_ascii_lowercase().starts_with("<html>rem ")
        {
            pending.push_back(i + 1);
            continue;
        }
        if line.chars().any(|c| "&|()^".contains(c))
            || ["call", "for", "cmd", "cmd.exe", "command", "command.com"]
                .iter()
                .any(|name| cmd.eq_ignore_ascii_case(name))
            || cmd.trim_matches('"').to_ascii_lowercase().ends_with(".bat")
            || cmd.trim_matches('"').to_ascii_lowercase().ends_with(".cmd")
        {
            continue;
        }
        if cmd.eq_ignore_ascii_case("exit") {
            continue;
        }
        if cmd.eq_ignore_ascii_case("goto") {
            if let Some(target) = jump(line).and_then(|name| labels.get(&name)) {
                pending.push_back(*target);
            }
            continue;
        }
        if cmd.eq_ignore_ascii_case("if") {
            // Read both paths of this simple conditional; unsupported control
            // syntax stops the proof instead of being treated as fallthrough.
            let tokens: Vec<_> = rest.split_whitespace().collect();
            let &[kind, level, goto, target] = tokens.as_slice() else {
                continue;
            };
            if !kind.eq_ignore_ascii_case("errorlevel")
                || level.parse::<u32>().is_err()
                || !goto.eq_ignore_ascii_case("goto")
            {
                continue;
            }
            if let Some(target) = label_name(target).and_then(|name| labels.get(&name)) {
                pending.push_back(*target);
            }
        }
        pending.push_back(i + 1);
    }
    let mut stats = Stats::default();
    let mut budget = 20_000usize;
    for (end, line) in lines.iter().enumerate() {
        let Some(start) = jump(line).and_then(|name| labels.get(&name).copied()) else {
            continue;
        };
        if start >= end || !reachable.contains(&start) || !reachable.contains(&end) {
            continue;
        }
        let Some(body) = lines.get(start + 1..end) else {
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
        if line.is_empty() || line.starts_with("::") {
            continue;
        }
        let (cmd, rest) = words(line);
        if cmd.eq_ignore_ascii_case("rem") {
            continue;
        }
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
        } else if cmd.eq_ignore_ascii_case("echo") || cmd.to_ascii_lowercase().starts_with("echo.")
        {
            let text = if cmd.eq_ignore_ascii_case("echo") {
                rest
            } else {
                &line[5..]
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
                    && (!data.trim().is_empty() || cmd.to_ascii_lowercase().starts_with("echo."))
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
mod tests {
    use super::*;
    const LOOP: &str = ":1\nset alias=cache\necho 0000>>data\ncopy /b data %alias%\ncopy /b data+%alias%+%alias%\ncopy /b data+data+data\ngoto 1\n";
    #[test]
    fn snapshot_source_and_backedge_are_bound() {
        let s = analyze(LOOP);
        assert_eq!((s.loops, s.seeded, s.fanout), (1, 1, 2));
        let s = analyze(
            &LOOP
                .replace(":1", ":again!")
                .replace("goto 1", "goto again!"),
        );
        assert_eq!((s.loops, s.seeded), (1, 1));
        let s = analyze(
            &LOOP
                .replace("data", "different.bin")
                .replace("cache", "snapshot.tmp"),
        );
        assert_eq!((s.loops, s.seeded), (1, 1));
    }
    #[test]
    fn unrelated_or_reset_files_do_not_amplify() {
        for s in [
            LOOP.replace("copy /b data %alias%", "copy /b other %alias%"),
            LOOP.replace("goto 1", "goto missing"),
            LOOP.replace("goto 1", "if errorlevel 1 goto 1"),
            LOOP.replace("echo 0000>>data", "echo 0000>data"),
            LOOP.replace(
                "copy /b data+%alias%",
                "echo changed>>%alias%\ncopy /b data+%alias%",
            ),
            LOOP.replace("goto 1", "echo replaced>data\ngoto 1"),
        ] {
            assert_eq!(analyze(&s).loops, 0, "{s}");
        }
    }
    #[test]
    fn dead_or_quoted_loops_do_not_establish_execution() {
        assert_eq!(analyze(&format!("exit /b\n{LOOP}")).loops, 0);
        for prefix in [
            "echo ignored & exit /b",
            "call :stop",
            "other.bat",
            "cmd /c exit",
        ] {
            assert_eq!(
                analyze(&format!("{prefix}\n{LOOP}\n:stop\nexit /b")).loops,
                0
            );
        }
        assert_eq!(
            analyze(&format!("goto done\n{LOOP}\n:done\nexit /b")).loops,
            0
        );
        assert_eq!(
            analyze(
                &LOOP
                    .lines()
                    .map(|s| format!("rem {s}\n"))
                    .collect::<String>()
            )
            .loops,
            0
        );
        assert_eq!(
            analyze(
                &LOOP
                    .lines()
                    .map(|s| format!("echo {s}\n"))
                    .collect::<String>()
            )
            .loops,
            0
        );
    }
    #[test]
    fn empty_or_bounded_profiles_are_distinct() {
        let s = analyze(&LOOP.replace("echo 0000>>data\n", ""));
        assert_eq!((s.loops, s.seeded), (1, 0));
        assert_eq!(analyze(&LOOP.replace("goto 1", "exit /b")).loops, 0);
        assert!(analyze(&"x".repeat(512 * 1024 + 1)).limited);
    }
    #[test]
    fn seed_target_is_bound_to_amplified_source() {
        let s = analyze(&LOOP.replace("echo 0000>>data", "echo 0000>>unrelated"));
        assert_eq!((s.loops, s.seeded), (1, 0));
        let s = analyze(&LOOP.replace(
            "data+%alias%+%alias%",
            "data+%alias%+%alias% separate-output",
        ));
        assert_eq!(s.loops, 0);
    }

    #[test]
    fn redirects_prompts_and_unknown_seed_values_do_not_convict() {
        assert_eq!(
            analyze(&LOOP.replace("set alias=cache", "ctty nul>data\nset alias=cache")).loops,
            0
        );
        assert_eq!(
            analyze(&LOOP.replace("copy /b data %alias%", "copy /b /-y data %alias%")).loops,
            0
        );
        assert_eq!(
            analyze(&LOOP.replace("echo 0000>>data", "echo %unknown%>>data")).seeded,
            0
        );
        assert_ne!(path(r"\\server\data"), path(r"\server\data"));
    }

    #[test]
    fn simple_errorlevel_prelude_reaches_loop() {
        let source =
            format!("if errorlevel 1 goto start\necho alternate\ngoto start\n:start\n{LOOP}");
        assert_eq!(analyze(&source).seeded, 1);
    }
}
