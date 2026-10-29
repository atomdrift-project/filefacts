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
