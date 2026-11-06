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
    assert!(rst_document_structure(doc));
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
    assert!(!rst_document_structure(source));
    let id = FileId::from_path_and_bytes(Path::new("source.rst"), source);
    assert_eq!(id.file_type(), FileType::Kotlin);
    assert!(id.extension_mismatch());
}

#[test]
fn ordinary_text_with_one_underlined_heading_is_not_enough() {
    let text = b"Title\n=====\n\nSome prose with a Python-like phrase: return value\n";
    assert!(!rst_document_structure(text));
}

/// The bitmask is exactly [`CODE_PUNCT`], over every byte value.
#[test]
fn code_punct_mask_matches_list() {
    for b in 0..=u8::MAX {
        assert_eq!(is_code_punct(b), CODE_PUNCT.contains(&b), "byte {b:#04x}");
    }
}

#[test]
fn recognizes_cms_exec_but_not_comment_examples_or_binary() {
    let good = b"/* REXX */\nsay 'hello'\npull name\n\"EXECIO * DISKR FILE NAMES A (FIFO\"\ndo while queued() > 0\n say name\nend\n";
    assert!(looks_like_cms_exec(good));
    assert!(!looks_like_cms_exec(
        b"/*\nsay x\npull y\n\"EXECIO * DISKR\"\ndo while x\nend\n*/\n"
    ));
    assert!(!looks_like_cms_exec(
        b"/* text */\nsay x\npull y\ndo while x\nend\n"
    ));
    let mut binary = good.to_vec();
    binary.extend_from_slice(&[0; 32]);
    assert!(!looks_like_cms_exec(&binary));
}

#[test]
fn recognizes_report_but_not_comment_only_or_binary() {
    let source = b"REPORT demo.\nREAD REPORT name INTO src.\nLOOP AT src INTO row.\nENDLOOP.\n";
    assert!(looks_like_abap_report(source));
    // ABAP keywords are case-insensitive.
    assert!(looks_like_abap_report(
        b"report demo.\nread report name into src.\nloop at src into row.\nendloop.\n"
    ));
    assert!(!looks_like_abap_report(
        b"*REPORT demo.\n*READ REPORT name INTO src.\n*LOOP AT src INTO row.\n*ENDLOOP.\n"
    ));
    assert!(!looks_like_abap_report(
        b"REPORT demo.\nLOOP AT src INTO row.\nENDLOOP.\n"
    ));
    let mut binary = source.to_vec();
    binary.extend_from_slice(&[0; 32]);
    assert!(!looks_like_abap_report(&binary));
}
