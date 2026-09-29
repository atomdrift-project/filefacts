//! Bounded lexical call ranges for CFScript. No execution or control-flow claims.
use std::ops::Range;

pub(super) fn mask_comments(bytes: &[u8], ranges: &[Range<usize>]) -> Vec<u8> {
    let mut masked = bytes.to_vec();
    for range in ranges {
        let mut at = range.start;
        while at < range.end {
            if matches!(bytes[at], b'\'' | b'"') {
                if !super::quoted(&bytes[..range.end], &mut at) {
                    break;
                }
                continue;
            }
            let start = at;
            if bytes[at..range.end].starts_with(b"//") {
                while at < range.end && !matches!(bytes[at], b'\n' | b'\r') {
                    at += 1;
                }
            } else if bytes[at..range.end].starts_with(b"/*") {
                at += 2;
                while at < range.end && !bytes[at..range.end].starts_with(b"*/") {
                    at += 1;
                }
                at = (at + 2).min(range.end);
            } else if bytes[at..range.end].starts_with(b"<!---") {
                let mut depth = 1;
                at += 5;
                while at < range.end && depth > 0 {
                    if bytes[at..range.end].starts_with(b"<!---") {
                        depth += 1;
                        at += 5;
                    } else if bytes[at..range.end].starts_with(b"--->") {
                        depth -= 1;
                        at += 4;
                    } else {
                        at += 1;
                    }
                }
            } else {
                at += 1;
                continue;
            }
            for byte in &mut masked[start..at] {
                if !matches!(*byte, b'\n' | b'\r') {
                    *byte = b' ';
                }
            }
        }
    }
    masked
}

fn whitespace(bytes: &[u8], mut at: usize, end: usize) -> usize {
    while at < end && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}
fn identifier(bytes: &[u8], mut at: usize, end: usize) -> usize {
    if at == end || !(bytes[at].is_ascii_alphabetic() || bytes[at] == b'_') {
        return at;
    }
    at += 1;
    while at < end && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
        at += 1;
    }
    at
}
fn parentheses(bytes: &[u8], mut at: usize, end: usize) -> Option<usize> {
    let mut depth = 0usize;
    while at < end {
        match bytes[at] {
            b'\'' | b'"' => {
                if !super::quoted(&bytes[..end], &mut at) {
                    return None;
                }
                continue;
            }
            b'(' => {
                depth += 1;
                if depth > 32 {
                    return None;
                }
            }
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(at + 1);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

pub(super) fn calls(bytes: &[u8], range: Range<usize>) -> (Vec<Range<usize>>, bool) {
    let mut out = Vec::new();
    let mut at = range.start;
    let mut declaration = false;
    while at < range.end {
        if matches!(bytes[at], b'\'' | b'"') {
            if !super::quoted(&bytes[..range.end], &mut at) {
                return (out, true);
            }
            continue;
        }
        let start = at;
        let name_end = identifier(bytes, at, range.end);
        if name_end == at {
            at += 1;
            continue;
        }
        let name = String::from_utf8_lossy(&bytes[start..name_end]).to_ascii_lowercase();
        at = name_end;
        if name == "function" {
            declaration = true;
            continue;
        }
        if matches!(name.as_str(), "if" | "for" | "while" | "switch" | "catch") {
            continue;
        }
        let mut end = whitespace(bytes, at, range.end);
        // Static dotted receivers are part of the call target.
        while bytes.get(end) == Some(&b'.') {
            let next = whitespace(bytes, end + 1, range.end);
            let next_end = identifier(bytes, next, range.end);
            if next_end == next {
                break;
            }
            end = whitespace(bytes, next_end, range.end);
        }
        if bytes.get(end) != Some(&b'(') {
            declaration = false;
            continue;
        }
        let Some(mut end) = parentheses(bytes, end, range.end) else {
            return (out, true);
        };
        if declaration {
            declaration = false;
            at = end;
            continue;
        }
        loop {
            let dot = whitespace(bytes, end, range.end);
            if bytes.get(dot) != Some(&b'.') {
                break;
            }
            let name = whitespace(bytes, dot + 1, range.end);
            let name_end = identifier(bytes, name, range.end);
            let open = whitespace(bytes, name_end, range.end);
            if name_end == name || bytes.get(open) != Some(&b'(') {
                break;
            }
            let Some(next) = parentheses(bytes, open, range.end) else {
                return (out, true);
            };
            end = next;
        }
        if out.len() == super::MAX_TAGS {
            return (out, true);
        }
        out.push(start..end);
        at = end;
    }
    (out, false)
}

#[cfg(test)]
mod tests {
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
}

/// Source-ordered statement regions. Braces delimit independent local blocks;
/// unsupported expression/object bodies never become variable assignments.
pub(super) enum Event {
    Statement(Range<usize>, bool),
    Barrier,
}
pub(super) fn statements(bytes: &[u8], range: Range<usize>) -> (Vec<Event>, bool) {
    fn block_header(bytes: &[u8], range: Range<usize>) -> bool {
        let Ok(text) = std::str::from_utf8(&bytes[range.clone()]) else {
            return false;
        };
        let text = text.trim();
        if text.is_empty()
            || ["else", "try", "finally"]
                .iter()
                .any(|s| text.eq_ignore_ascii_case(s))
        {
            return true;
        }
        let mut at = whitespace(bytes, range.start, range.end);
        let mut end = identifier(bytes, at, range.end);
        if bytes[at..end].eq_ignore_ascii_case(b"else") {
            at = whitespace(bytes, end, range.end);
            end = identifier(bytes, at, range.end);
        }
        let control = [b"if".as_slice(), b"for", b"while", b"catch", b"switch"]
            .iter()
            .any(|name| bytes[at..end].eq_ignore_ascii_case(name));
        let function = bytes[at..end].eq_ignore_ascii_case(b"function");
        if !control && !function {
            return false;
        }
        at = whitespace(bytes, end, range.end);
        if function {
            end = identifier(bytes, at, range.end);
            if end == at {
                return false;
            }
            at = whitespace(bytes, end, range.end);
        }
        if bytes.get(at) != Some(&b'(') {
            return false;
        }
        parentheses(bytes, at, range.end)
            .is_some_and(|end| whitespace(bytes, end, range.end) == range.end)
    }
    let mut out = Vec::new();
    let mut start = range.start;
    let mut at = start;
    let mut delimiters = Vec::new();
    let mut blocks = vec![true];
    while at < range.end {
        if out.len() >= super::MAX_TAGS - 2 {
            return (out, true);
        }
        match bytes[at] {
            b'\'' | b'"' => {
                if !super::quoted(&bytes[..range.end], &mut at) {
                    return (out, true);
                }
                continue;
            }
            b'(' | b'[' => {
                if delimiters.len() == 32 {
                    return (out, true);
                }
                delimiters.push(bytes[at]);
            }
            b')' | b']' => {
                let expected = if bytes[at] == b')' { b'(' } else { b'[' };
                if delimiters.pop() != Some(expected) {
                    return (out, true);
                }
            }
            b';' | b'{' | b'}' if delimiters.is_empty() => {
                let allowed = *blocks.last().unwrap();
                if start < at {
                    out.push(Event::Statement(start..at, allowed));
                }
                if bytes[at] == b'{' {
                    if blocks.len() == 33 {
                        return (out, true);
                    }
                    blocks.push(allowed && block_header(bytes, start..at));
                    out.push(Event::Barrier);
                } else if bytes[at] == b'}' {
                    if blocks.len() == 1 {
                        return (out, true);
                    }
                    blocks.pop();
                    out.push(Event::Barrier);
                }
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    let limited = !delimiters.is_empty() || blocks.len() != 1;
    if start < range.end && !limited {
        out.push(Event::Statement(start..range.end, *blocks.last().unwrap()));
    }
    (out, limited)
}

#[cfg(test)]
mod statement_tests {
    use super::*;
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
}
