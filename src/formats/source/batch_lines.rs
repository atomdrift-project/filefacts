//! One line model of a Batch file, shared by the loop analyses
//! ([`super::batch_concat`], [`super::batch_cycles`]): the lines with their
//! leading `@` removed, the labels, and the lines entry control flow can be
//! shown to reach.
//!
//! Labels are read independently of tree-sitter's narrower label grammar,
//! so numeric and punctuation labels count. Facts describe source-local
//! requests, not runtime success.
use std::collections::{HashMap, VecDeque};

/// Largest source modelled.
const MAX_BYTES: usize = 512 * 1024;
/// Most lines modelled.
const MAX_LINES: usize = 10_000;
/// Loop-body lines each analysis reads, summed over every loop.
pub(super) const BODY_BUDGET: usize = 20_000;

/// Why a file has no [`Lines`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unmodelled {
    /// Past [`MAX_BYTES`] or [`MAX_LINES`]; an analysis reports itself
    /// limited.
    TooLarge,
    /// A label is defined twice, so which one a `goto` reaches depends on
    /// where it runs from.
    DuplicateLabel,
}

pub(super) struct Lines<'s> {
    pub(super) lines: Vec<&'s str>,
    labels: HashMap<String, usize>,
    /// Indexed by line.
    reachable: Vec<bool>,
}

/// The first word of `line` and the rest, trimmed.
pub(super) fn words(line: &str) -> (&str, &str) {
    line.split_once(char::is_whitespace)
        .map_or((line, ""), |(a, b)| (a, b.trim_start()))
}

/// A `::` or `rem` comment line.
pub(super) fn comment(line: &str) -> bool {
    line.starts_with("::") || words(line).0.eq_ignore_ascii_case("rem")
}

fn label_name(name: &str) -> Option<String> {
    let name = name.trim().strip_prefix(':').unwrap_or(name.trim());
    (!name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.$#!-".contains(c)))
    .then(|| name.to_ascii_lowercase())
}

/// Lines that hand control elsewhere or change it in ways the model does
/// not follow: compound syntax, nested interpreters and batch transfers.
fn opaque(line: &str) -> bool {
    let cmd = words(line).0;
    line.chars().any(|c| "&|()^".contains(c))
        || ["call", "for", "cmd", "cmd.exe", "command", "command.com"]
            .iter()
            .any(|name| cmd.eq_ignore_ascii_case(name))
        || std::path::Path::new(cmd.trim_matches('"'))
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("bat") || ext.eq_ignore_ascii_case("cmd"))
}

impl<'s> Lines<'s> {
    pub(super) fn new(source: &'s str) -> Result<Self, Unmodelled> {
        if source.len() > MAX_BYTES {
            return Err(Unmodelled::TooLarge);
        }
        let lines: Vec<&str> = source
            .lines()
            .map(|line| line.trim().trim_start_matches('@').trim_start())
            .collect();
        if lines.len() > MAX_LINES {
            return Err(Unmodelled::TooLarge);
        }
        let mut labels = HashMap::new();
        for (i, line) in lines.iter().enumerate() {
            let name = line
                .strip_prefix(':')
                .filter(|rest| !rest.starts_with(':'))
                .and_then(|rest| label_name(rest.split_whitespace().next()?));
            if let Some(name) = name {
                if labels.insert(name, i).is_some() {
                    return Err(Unmodelled::DuplicateLabel);
                }
            }
        }
        let mut model = Self {
            reachable: vec![false; lines.len()],
            lines,
            labels,
        };
        model.reach();
        Ok(model)
    }

    /// The label line a `goto` on `line` jumps to. `None` for any other
    /// line, an unknown label, and `goto :eof`, which ends the script.
    pub(super) fn jump(&self, line: &str) -> Option<usize> {
        let (cmd, rest) = words(line);
        if !cmd.eq_ignore_ascii_case("goto") || rest.trim().eq_ignore_ascii_case(":eof") {
            return None;
        }
        self.labels.get(&label_name(rest)?).copied()
    }

    pub(super) fn reachable(&self, line: usize) -> bool {
        self.reachable.get(line).copied().unwrap_or(false)
    }

    /// Mark the lines entry control flow reaches. Comments and labels pass
    /// control on; a simple `if errorlevel N goto L` reaches both paths;
    /// `exit`, `goto :eof` and every [`opaque`] line stop the proof rather
    /// than be treated as falling through.
    fn reach(&mut self) {
        let mut pending = VecDeque::from([0]);
        while let Some(i) = pending.pop_front() {
            let (Some(&line), Some(seen)) = (self.lines.get(i), self.reachable.get_mut(i)) else {
                continue;
            };
            if std::mem::replace(seen, true) {
                continue;
            }
            if comment(line) || line.starts_with(':') {
                pending.push_back(i + 1);
                continue;
            }
            let (cmd, rest) = words(line);
            if opaque(line) || cmd.eq_ignore_ascii_case("exit") {
                continue;
            }
            if cmd.eq_ignore_ascii_case("goto") {
                pending.extend(self.jump(line));
                continue;
            }
            if cmd.eq_ignore_ascii_case("if") {
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
                pending.extend(label_name(target).and_then(|name| self.labels.get(&name)));
            }
            pending.push_back(i + 1);
        }
    }

    /// Every reachable backward `goto` whose target label is reachable: the
    /// loop's label line and its `goto` line.
    pub(super) fn loops(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.lines.iter().enumerate().filter_map(|(end, line)| {
            let start = self.jump(line)?;
            (start < end && self.reachable(start) && self.reachable(end)).then_some((start, end))
        })
    }
}
