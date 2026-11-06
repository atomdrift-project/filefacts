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
    assert!(b.into_spans().is_empty());
}

#[test]
fn spans_near_the_top_of_the_offset_range_do_not_overflow() {
    let mut b = SpanBuilder::with_cap(4);
    b.push(u64::MAX - 1, 2); // ends past u64::MAX
    b.push(0, 1); // not adjacent to a run that ends past u64::MAX
    b.push(1, u64::MAX); // an adjacent run whose length cannot grow
    b.push(2, 1);
    assert_eq!(
        b.into_spans(),
        vec![
            Span::new(u64::MAX - 1, 2),
            Span::new(0, u64::MAX),
            Span::new(2, 1)
        ]
    );
}
