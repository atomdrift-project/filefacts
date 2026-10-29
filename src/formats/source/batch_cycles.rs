//! Bounded source-local process-spawn cycles, independent of label
//! spelling, read over the shared line model ([`super::batch_lines`]).
use super::batch_lines::{BODY_BUDGET, Lines, Unmodelled, comment};
use crate::{Metrics, metric};

pub(super) fn emit(source: &str, metrics: &mut Metrics) {
    let (count, limited) = cycles(source);
    metrics.insert(
        metric!("source.batch.unconditional_start_cycles"),
        count as f64,
    );
    if limited {
        metrics.insert(metric!("source.batch.cycle_analysis_limited"), 1.0);
    }
}

/// The number of loops whose body only starts programs, without waiting,
/// and whether a cap cut the count short.
fn cycles(source: &str) -> (usize, bool) {
    let lines = match Lines::new(source) {
        Ok(lines) => lines,
        Err(why) => {
            tracing::debug!(
                target: "filefacts::source",
                format = "batch",
                len = source.len(),
                reason = ?why,
                "batch cycles: file not modelled"
            );
            return (0, why == Unmodelled::TooLarge);
        }
    };
    let mut count = 0;
    let mut budget = BODY_BUDGET;
    for (start, end) in lines.loops() {
        let Some(body) = lines.lines.get(start + 1..end) else {
            continue;
        };
        if body.len() > budget {
            return (count, true);
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
    (count, false)
}

#[cfg(test)]
mod tests;
