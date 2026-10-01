//! Bounded content-shape check for reStructuredText documents with code examples.

const WINDOW: usize = 16 * 1024;

pub(super) fn document_structure(data: &[u8]) -> bool {
    let data = super::strip_utf8_bom(data);
    let head = data.get(..WINDOW).unwrap_or(data);
    let lines: Vec<&[u8]> = head.split(|b| *b == b'\n').collect();
    let mut headings = 0;
    let mut directive = false;
    let mut literal_block = false;

    for (index, raw_line) in lines.iter().enumerate() {
        let line = raw_line
            .strip_suffix(b"\r")
            .unwrap_or(raw_line)
            .trim_ascii();
        if line.starts_with(b".. ") && line.windows(2).any(|w| w == b"::") {
            directive = true;
        }
        if line.ends_with(b"::") {
            literal_block |= lines
                .get(index + 1..)
                .unwrap_or_default()
                .iter()
                .take(4)
                .map(|next| next.strip_suffix(b"\r").unwrap_or(next))
                .find(|next| !next.trim_ascii().is_empty())
                .is_some_and(|next| next.first().is_some_and(u8::is_ascii_whitespace));
        }
        if line.len() < 3 {
            continue;
        }
        let Some(previous) = index.checked_sub(1).and_then(|i| lines.get(i)) else {
            continue;
        };
        let previous = previous
            .strip_suffix(b"\r")
            .unwrap_or(previous)
            .trim_ascii();
        if previous.is_empty() || previous.len() > 120 || !previous.is_ascii() {
            continue;
        }
        if line.first().is_some_and(|&rule| {
            matches!(
                rule,
                b'=' | b'-' | b'~' | b'^' | b'"' | b'`' | b':' | b'#' | b'*' | b'+' | b'_'
            ) && line.iter().all(|b| *b == rule)
        }) {
            headings += 1;
        }
    }

    headings >= 2 && (directive || literal_block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileId, FileType};
    use std::path::Path;

    #[test]
    fn sectioned_rst_with_examples_is_text_even_when_examples_score_as_kotlin() {
        let doc = br#"netifaces 0.10.6
================

.. image:: https://example.test/status.png

1. What is this?
----------------

This package reports network interface addresses.

2. How do I use it?
-------------------

Type::

    >>> import kotlin.io.println
    >>> println("interface")
"#;
        assert!(document_structure(doc));
        let id = FileId::from_path_and_bytes(Path::new("README.rst"), doc);
        assert_eq!(id.file_type(), FileType::Text);
        assert!(!id.extension_mismatch());
    }

    #[test]
    fn source_named_rst_without_document_structure_stays_source() {
        let source = br#"package com.example
import kotlin.io.println
fun main() { println("ok") }
"#;
        assert!(!document_structure(source));
        let id = FileId::from_path_and_bytes(Path::new("source.rst"), source);
        assert_eq!(id.file_type(), FileType::Kotlin);
        assert!(id.extension_mismatch());
    }

    #[test]
    fn ordinary_text_with_one_underlined_heading_is_not_enough() {
        let text = b"Title\n=====\n\nSome prose with a Python-like phrase: return value\n";
        assert!(!document_structure(text));
    }
}
