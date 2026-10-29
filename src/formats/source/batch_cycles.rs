//! Bounded source-local process-spawn cycles, independent of label spelling.
use crate::{Metrics, metric};
use std::collections::{HashMap, HashSet};

pub(super) fn emit(source: &str, metrics: &mut Metrics) {
    let count = cycles(source);
    metrics.insert(
        metric!("source.batch.unconditional_start_cycles"),
        count as f64,
    );
}

fn bare(s: &str) -> &str {
    s.trim().trim_start_matches('@').trim_start()
}
fn comment(s: &str) -> bool {
    s.starts_with("::")
        || s.eq_ignore_ascii_case("rem")
        || s.get(..4).is_some_and(|h| h.eq_ignore_ascii_case("rem "))
}
fn cycles(source: &str) -> usize {
    if source.len() > 512 * 1024 {
        return 0;
    }
    let lines: Vec<_> = source.lines().map(bare).collect();
    if lines.len() > 10_000 {
        return 0;
    }
    let mut labels = HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        if comment(line) {
            continue;
        }
        if let Some(name) = line.strip_prefix(':') {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty() || name.contains(char::is_whitespace) {
                continue;
            }
            if labels.insert(name, i).is_some() {
                return 0;
            }
        }
    }
    // Follow only entry control flow that can be established statically.
    // Ambiguous branches, command transfers and compound syntax stop proof.
    let mut reachable = HashSet::new();
    let mut pc = 0;
    while let Some(line) = lines.get(pc).copied() {
        if !reachable.insert(pc) {
            break;
        }
        if line.is_empty() || comment(line) || line.starts_with(':') {
            pc += 1;
            continue;
        }
        if line.chars().any(|c| "&|()^<>".contains(c)) {
            break;
        }
        let (head, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        if head.eq_ignore_ascii_case("goto") {
            if rest.trim().eq_ignore_ascii_case(":eof") {
                break;
            }
            let target = rest.trim().trim_start_matches(':').to_ascii_lowercase();
            let Some(&target_pc) = labels.get(&target) else {
                break;
            };
            pc = target_pc;
            continue;
        }
        if [
            "exit",
            "if",
            "for",
            "call",
            "cmd",
            "cmd.exe",
            "command",
            "command.com",
        ]
        .iter()
        .any(|name| head.eq_ignore_ascii_case(name))
            || head
                .trim_matches('"')
                .to_ascii_lowercase()
                .ends_with(".bat")
            || head
                .trim_matches('"')
                .to_ascii_lowercase()
                .ends_with(".cmd")
        {
            break;
        }
        pc += 1;
    }
    let mut count = 0;
    let mut budget = 20_000usize;
    for (end, line) in lines.iter().enumerate() {
        let Some((head, target)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if !head.eq_ignore_ascii_case("goto") {
            continue;
        }
        let target = target.trim().trim_start_matches(':').to_ascii_lowercase();
        let Some(&start) = labels.get(&target) else {
            continue;
        };
        if start >= end || !reachable.contains(&start) || !reachable.contains(&end) {
            continue;
        }
        let Some(body) = lines.get(start + 1..end) else {
            continue;
        };
        if body.len() > budget {
            break;
        }
        budget -= body.len();
        let mut launches = 0;
        let valid = body.iter().all(|line| {
            if line.is_empty() || comment(line) {
                return true;
            }
            let mut words = line.split_whitespace();
            if !words
                .next()
                .is_some_and(|w| w.eq_ignore_ascii_case("start"))
            {
                return false;
            }
            // Reject wait, compound commands, redirects and escaped syntax.
            if line.chars().any(|c| "&|<>^()".contains(c)) {
                return false;
            }
            if words.any(|w| w.starts_with('/') || (w.starts_with('%') && w.ends_with('%'))) {
                return false;
            }
            launches += 1;
            true
        });
        if valid && launches > 0 {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_arbitrary_labels_and_excludes_forward_and_wait() {
        assert_eq!(
            cycles(":unusual_42\nstart cmd.exe\nstart notepad.exe\ngoto unusual_42\n"),
            1
        );
        assert_eq!(cycles(":again\nstart\ngoto :again\n"), 1);
        assert_eq!(
            cycles("goto start\n:start\nstart node.exe\ngoto done\n:done\n"),
            0
        );
        assert_eq!(cycles(":a\nstart /wait tool.exe\ngoto a\n"), 0);
        assert_eq!(cycles(":a\nstart tool.exe\ntimeout /t 5\ngoto a\n"), 0);
        assert_eq!(
            cycles(":a\nstart tool.exe\nif errorlevel 1 exit /b\ngoto a\n"),
            0
        );
        assert_eq!(cycles(":a\nstart tool.exe\ngoto b\n:b\n"), 0);
        assert_eq!(cycles(":a\nstart tool.exe & exit\ngoto a\n"), 0);
        assert_eq!(cycles("exit /b\n:a\nstart tool.exe\ngoto a\n"), 0);
        assert_eq!(cycles("goto done\n:a\nstart tool.exe\ngoto a\n:done\n"), 0);
        assert_eq!(cycles(":a\nstart %OPTIONS% tool.exe\ngoto a\n"), 0);
        assert_eq!(
            cycles("if exist flag goto a\n:a\nstart tool.exe\ngoto a\n"),
            0
        );
        assert_eq!(cycles("goto :eof\n:eof\nstart tool.exe\ngoto eof\n"), 0);
    }
}
