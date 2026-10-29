use super::*;

#[test]
fn masking_preserves_offsets_strings_and_line_breaks() {
    let source =
        b"// fake()\nactual(/* comment */'http://x'); <!--- fake() <!--- inner ---> --->\n";
    let masked = mask_comments(source, std::slice::from_ref(&(0..source.len())));
    assert_eq!(masked.len(), source.len());
    assert_eq!(masked.iter().filter(|b| **b == b'\n').count(), 2);
    let (ranges, limited) = calls(&masked, 0..masked.len());
    assert!(!limited);
    assert_eq!(ranges.len(), 1);
    assert_eq!(&source[ranges[0].start..ranges[0].start + 6], b"actual");
    assert!(masked.windows(8).any(|s| s == b"http://x"));
}
#[test]
fn lexical_calls_are_bounded_and_do_not_include_function_signatures() {
    let source = b"function demo(x) { actual(); } if (check()) { other().method(); }";
    let (ranges, limited) = calls(source, 0..source.len());
    assert!(!limited);
    assert_eq!(
        ranges
            .iter()
            .map(|r| &source[r.clone()])
            .collect::<Vec<_>>(),
        vec![b"actual()".as_slice(), b"check()", b"other().method()"]
    );
    for end in 0..=source.len() {
        let (ranges, _) = calls(&source[..end], 0..end);
        assert!(ranges.iter().all(|r| r.start < r.end && r.end <= end));
    }
    let source = b"f();".repeat(super::super::MAX_TAGS + 1);
    let (ranges, limited) = calls(&source, 0..source.len());
    assert!(limited);
    assert_eq!(ranges.len(), super::super::MAX_TAGS);
    let source = format!("f({}x{})", "(".repeat(40), ")".repeat(40));
    assert!(calls(source.as_bytes(), 0..source.len()).1);
}
#[test]
fn long_member_chain_is_scanned_once() {
    // Rescanning the chain from each of its 200k names would walk about
    // 2×10¹¹ bytes, far past the chain-scan budget of twice the input, and
    // report the scan as limited; a linear scan stays within it.
    let source = format!("a = b{}; g(); x.y . z();", ".c".repeat(200_000));
    let (ranges, limited) = calls(source.as_bytes(), 0..source.len());
    assert!(!limited);
    assert_eq!(
        ranges
            .iter()
            .map(|r| &source.as_bytes()[r.clone()])
            .collect::<Vec<_>>(),
        vec![b"g()".as_slice(), b"x.y . z()"]
    );
}

#[test]
fn statement_regions_are_ordered_bounded_and_ignore_literal_delimiters() {
    let source = b"if(check()) { value=f(';}'); out(value); } else { out(other); }";
    let (events, limited) = statements(source, 0..source.len());
    assert!(!limited);
    let ranges: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Statement(r, _) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert!(ranges.windows(2).all(|p| p[0].end <= p[1].start));
    assert!(
        ranges
            .iter()
            .any(|r| &source[r.clone()] == b" value=f(';}')")
    );
    for end in 0..=source.len() {
        let (events, _) = statements(&source[..end], 0..end);
        assert!(events.iter().all(|e| match e {
            Event::Statement(r, _) => r.start < r.end && r.end <= end,
            _ => true,
        }));
    }
    for source in ["([)]", "][", ")"] {
        assert!(statements(source.as_bytes(), 0..source.len()).1);
    }
    for (open, close) in [("(", ")"), ("[", "]"), ("{", "}")] {
        let exact = format!("{}{}", open.repeat(32), close.repeat(32));
        assert!(!statements(exact.as_bytes(), 0..exact.len()).1);
    }
    let exact = "f();".repeat(super::super::MAX_TAGS - 2);
    let (events, limited) = statements(exact.as_bytes(), 0..exact.len());
    assert!(!limited);
    assert_eq!(events.len(), super::super::MAX_TAGS - 2);
    for source in [
        "{".repeat(33),
        "(".repeat(33),
        "[".repeat(33),
        "f();".repeat(super::super::MAX_TAGS),
    ] {
        let (events, limited) = statements(source.as_bytes(), 0..source.len());
        assert!(limited);
        assert!(events.len() <= super::super::MAX_TAGS);
    }
}
