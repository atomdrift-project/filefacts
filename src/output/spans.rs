//! Byte-span provenance for located facts.

use serde::{Deserialize, Serialize};

/// A contiguous byte range within the file: where the evidence for a fact
/// physically lives. Carried on [`crate::output::Fact`] so a measurement and
/// its location travel together — there is no separate "spans" channel to
/// join against by name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// Offset of the range from the start of the file, in bytes.
    pub offset: u64,
    /// Length of the range, in bytes.
    pub len: u64,
}

impl Span {
    /// Construct a span from an `(offset, len)` pair.
    #[must_use]
    pub fn new(offset: u64, len: u64) -> Self {
        Self { offset, len }
    }
}

impl From<(u64, u64)> for Span {
    fn from((offset, len): (u64, u64)) -> Self {
        Self { offset, len }
    }
}

/// Accumulates byte spans for a located metric, coalescing contiguous ones
/// into runs and bounding the total kept.
///
/// Push spans in ascending offset order. A pushed span whose offset equals the
/// previous span's end extends that run (so a contiguous block of invisible
/// chars, or adjacent high-entropy windows, becomes one span); otherwise it
/// starts a new run until `cap` distinct runs are held, after which further
/// non-adjacent spans are dropped. The owning metric's scalar value stays the
/// exact total — `spans` is a bounded, localised sample, not a full index.
///
/// One place for the adjacency arithmetic that every located metric needs, so
/// the off-by-one lives (or doesn't) in exactly one tested spot.
#[derive(Debug, Clone)]
pub struct SpanBuilder {
    spans: Vec<Span>,
    cap: usize,
}

impl SpanBuilder {
    /// A builder that keeps at most `cap` coalesced runs.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            spans: Vec::new(),
            cap,
        }
    }

    /// Add a `[offset, offset+len)` span. Zero-length spans are ignored.
    /// Adjacent to the previous run → extends it; otherwise a new run (subject
    /// to the cap).
    pub fn push(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        if let Some(last) = self.spans.last_mut()
            && last.offset + last.len == offset
        {
            last.len += len;
            return;
        }
        if self.spans.len() < self.cap {
            self.spans.push(Span::new(offset, len));
        }
    }

    /// True when no spans have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Consume the builder, yielding the coalesced runs.
    #[must_use]
    pub fn into_spans(self) -> Vec<Span> {
        self.spans
    }
}

#[cfg(test)]
mod tests {
    use super::{Span, SpanBuilder};

    #[test]
    fn coalesces_adjacent_runs() {
        let mut b = SpanBuilder::with_cap(8);
        b.push(2, 3); // [2,5)
        b.push(5, 3); // adjacent → extends to [2,8)
        b.push(20, 1); // gap → new run
        assert_eq!(b.into_spans(), vec![Span::new(2, 6), Span::new(20, 1)]);
    }

    #[test]
    fn cap_drops_excess_distinct_runs() {
        let mut b = SpanBuilder::with_cap(2);
        b.push(0, 1);
        b.push(10, 1);
        b.push(20, 1); // 3rd distinct run, over cap → dropped
        b.push(30, 1); // dropped
        assert_eq!(b.into_spans(), vec![Span::new(0, 1), Span::new(10, 1)]);
    }

    #[test]
    fn adjacency_extends_even_when_cap_is_full() {
        let mut b = SpanBuilder::with_cap(2);
        b.push(0, 1);
        b.push(10, 1); // cap full
        b.push(11, 1); // adjacent to the last kept run → extends it
        assert_eq!(b.into_spans(), vec![Span::new(0, 1), Span::new(10, 2)]);
    }

    #[test]
    fn zero_length_is_ignored() {
        let mut b = SpanBuilder::with_cap(4);
        b.push(5, 0);
        assert!(b.is_empty());
    }
}
