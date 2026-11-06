use std::path::Path;

use super::*;
use crate::fileid::detect;

/// A target in column zero is a target whatever ends its line: Windows
/// editors write CRLF, and trailing blanks are common.
#[test]
fn makefile_target_line_may_end_in_crlf_or_blanks() {
    let crlf = b"all: build\r\n\tcc -o app main.c\r\n";
    assert!(looks_like_makefile(crlf));
    let blanks = b"all: build  \n\tcc -o app main.c\n";
    assert!(looks_like_makefile(blanks));
    assert_eq!(
        detect(Path::new("build-fragment"), crlf).map(|d| d.file_type),
        Some(FileType::Makefile)
    );
    // An indented label is still not a target.
    assert!(!looks_like_makefile(
        b"  all: build\r\n\tcc -o app main.c\r\n"
    ));
}

/// A target and its recipe must be adjacent lines of text: a label in
/// markup, a folded mail header, an Objective-C method, or a target split
/// from its recipe by binary bytes is not a make rule.
#[test]
fn target_and_recipe_must_be_related_text() {
    assert!(looks_like_makefile(b"all:\n\tcc main.c\n"));
    assert!(looks_like_makefile(b"all:\n# comment\n\n\tcc main.c\n"));
    assert!(looks_like_makefile(
        b"OUT := out\nSOURCES := $(OUT)/a $(OUT)/b\nDATA := $(OUT)/c\n"
    ));
    assert!(!looks_like_makefile(
        b"<%@ Page Language=\"C#\"%>\nlabel:\n<script>\n\tcode();\n"
    ));
    assert!(!looks_like_makefile(
        b"Content-Type: text/html;\n\tcharset=\"utf-8\"\n"
    ));
    assert!(!looks_like_makefile(
        b"-(void)handle:(id)sender {\n\t[self process];\n}"
    ));
    assert!(!looks_like_makefile(
        b"title:\n\x00\x01\x02\x03\x04\x05\x06\x07\n\tcommand\n"
    ));
}
