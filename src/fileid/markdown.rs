//! Bounded document-shape check for Markdown containing source examples.

const WINDOW: usize = 16 * 1024;

pub(super) fn document_structure(data: &[u8]) -> bool {
    let data = super::strip_utf8_bom(data);
    let head = data.get(..WINDOW).unwrap_or(data);
    let mut lines = head.split(|b| *b == b'\n');
    let Some(mut first) = lines.find(|line| !line.trim_ascii().is_empty()) else {
        return false;
    };
    // YAML front matter precedes the document heading in agent policies and
    // static-site pages. Its quoted examples are data, not source-language
    // evidence. Require mapping-shaped fields and a complete closing marker.
    if first.trim_ascii() == b"---" {
        let mut fields = 0;
        let mut closed = false;
        for line in lines.by_ref() {
            let trimmed = line.trim_ascii();
            if trimmed == b"---" || trimmed == b"..." {
                closed = fields > 0;
                break;
            }
            if trimmed.is_empty() || trimmed.starts_with(b"#") {
                continue;
            }
            if line.first().is_some_and(u8::is_ascii_whitespace) {
                continue;
            }
            let Some(colon) = trimmed.iter().position(|b| *b == b':') else {
                return false;
            };
            if colon == 0
                || !trimmed
                    .iter()
                    .take(colon)
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            {
                return false;
            }
            fields += 1;
        }
        if !closed {
            return false;
        }
        let Some(heading) = lines.find(|line| !line.trim_ascii().is_empty()) else {
            return false;
        };
        first = heading;
    }
    let document_start = first.as_ptr() as usize - head.as_ptr() as usize;
    let first = first.trim_ascii();
    let hashes = first.iter().take_while(|b| **b == b'#').count();
    let atx = (1..=6).contains(&hashes) && first.get(hashes).is_some_and(u8::is_ascii_whitespace);
    if !atx {
        let Some(underline) = lines.next() else {
            return false;
        };
        let underline = underline.trim_ascii();
        let Some(&rule) = underline.first().filter(|b| matches!(b, b'=' | b'-')) else {
            return false;
        };
        if underline.len() < 3 || !underline.iter().all(|b| *b == rule) {
            return false;
        }
    }

    let mut fence = None;
    let mut in_list = false;
    for line in lines {
        // A truncated final line cannot establish a closing fence.
        if data.len() > WINDOW && line.as_ptr_range().end == head.as_ptr_range().end {
            break;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let spaces = line.iter().take_while(|b| **b == b' ').count();
        let Some(line) = line.get(spaces..) else {
            continue;
        };
        if fence.is_none() && spaces <= 3 && !line.trim_ascii().is_empty() {
            in_list = list_item(line);
        }
        // Four spaces is an indented code block at the top level, but inside
        // a list item it is the item's content indent, and a fence there is
        // still a fence. wolfSSL's IDE/WORKBENCH/README.md indents every
        // example under a numbered step that way and typed as C.
        let max_indent = if in_list { 7 } else { 3 };
        if spaces > max_indent {
            continue;
        }
        let Some(&marker) = line.first().filter(|b| matches!(b, b'`' | b'~')) else {
            continue;
        };
        let width = line.iter().take_while(|b| **b == marker).count();
        let info = line.get(width..).unwrap_or_default();
        if let Some((open_marker, open_width)) = fence {
            if marker == open_marker && width >= open_width && info.trim_ascii().is_empty() {
                return true;
            }
        } else if width >= 3 && (marker != b'`' || !info.contains(&b'`')) {
            // A Python comment can look like an ATX heading, followed by
            // executable source and a triple-quoted string with fence lines.
            // Source evidence before the examples must still win.
            let before = line.as_ptr() as usize - head.as_ptr() as usize;
            if head
                .get(document_start..before)
                .is_none_or(|prefix| super::heuristics::detect_from_content(prefix).is_some())
            {
                return false;
            }
            fence = Some((marker, width));
        }
    }
    false
}

/// A bullet (`-`, `*`, `+`) or ordered (`1.`, `1)`) list marker followed by a
/// space. A line that starts anything else at the margin ends the list.
fn list_item(line: &[u8]) -> bool {
    let digits = line.iter().take_while(|b| b.is_ascii_digit()).count();
    let marker = match (digits, line.get(digits)) {
        (0, Some(b'-' | b'*' | b'+')) => 1,
        (1..=9, Some(b'.' | b')')) => digits + 1,
        _ => return false,
    };
    line.get(marker).is_some_and(|b| *b == b' ' || *b == b'\t')
}

#[cfg(test)]
mod tests;
