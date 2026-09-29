//! Bounded document-shape check for Markdown containing source examples.

const WINDOW: usize = 16 * 1024;

pub(super) fn document_structure(data: &[u8]) -> bool {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let head = &data[..data.len().min(WINDOW)];
    let mut lines = head.split(|b| *b == b'\n');
    let Some(first) = lines.find(|line| !line.trim_ascii().is_empty()) else {
        return false;
    };
    let first = first.trim_ascii();
    let hashes = first.iter().take_while(|b| **b == b'#').count();
    let atx = (1..=6).contains(&hashes) && first.get(hashes).is_some_and(u8::is_ascii_whitespace);
    if !atx {
        let Some(underline) = lines.next() else {
            return false;
        };
        let underline = underline.trim_ascii();
        if underline.len() < 3
            || !matches!(underline[0], b'=' | b'-')
            || !underline.iter().all(|b| *b == underline[0])
        {
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
        if fence.is_none() && spaces <= 3 && !line.trim_ascii().is_empty() {
            in_list = list_item(&line[spaces..]);
        }
        // Four spaces is an indented code block at the top level, but inside
        // a list item it is the item's content indent, and a fence there is
        // still a fence. wolfSSL's IDE/WORKBENCH/README.md indents every
        // example under a numbered step that way and typed as C.
        let max_indent = if in_list { 7 } else { 3 };
        if spaces > max_indent {
            continue;
        }
        let line = &line[spaces..];
        let Some(&marker) = line.first().filter(|b| matches!(b, b'`' | b'~')) else {
            continue;
        };
        let width = line.iter().take_while(|b| **b == marker).count();
        if let Some((open_marker, open_width)) = fence {
            if marker == open_marker && width >= open_width && line[width..].trim_ascii().is_empty()
            {
                return true;
            }
        } else if width >= 3 && (marker != b'`' || !line[width..].contains(&b'`')) {
            // A Python comment can look like an ATX heading, followed by
            // executable source and a triple-quoted string with fence lines.
            // Source evidence before the examples must still win.
            let before = line.as_ptr() as usize - head.as_ptr() as usize;
            if super::heuristics::detect_from_content(&head[..before]).is_some() {
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
mod tests {
    use super::*;
    use crate::{FileId, FileType};
    use std::path::Path;

    #[test]
    fn fences_indented_under_list_items_count() {
        let doc = b"## Workbench with wolfSSL\n\
1. Include the following at the top of usrAppInit.c:\n\n\
    ```c\n\
    #include <wolfssl/ssl.h>\n\
    extern int benchmark_test(void* args);\n\
    ```\n\n\
2. Call it from `usrAppInit()`:\n\n\
    ```c\n\
    typedef struct func_args { int argc; char** argv; } func_args;\n\
    func_args args;\n\
    wolfcrypt_test(&args);\n\
    ```\n";
        assert!(document_structure(doc));
        let id = FileId::from_path_and_bytes(Path::new("README.md"), doc);
        assert_eq!(id.file_type(), FileType::Markdown);
    }

    #[test]
    fn original_readmes_with_program_examples_remain_markdown() {
        for bytes in [
            include_bytes!("../../testdata/markdown/puppeteer-browsers-readme.md").as_slice(),
            include_bytes!("../../testdata/markdown/https-proxy-agent-readme.md").as_slice(),
            include_bytes!("../../testdata/markdown/debug-readme.md").as_slice(),
            include_bytes!("../../testdata/markdown/proxy-agent-readme.md").as_slice(),
        ] {
            let id = FileId::from_path_and_bytes(Path::new("README.md"), bytes);
            assert_eq!(id.file_type(), FileType::Markdown);
            assert!(!id.extension_mismatch());
        }
    }

    #[test]
    fn fenced_document_shapes() {
        for bytes in [
            b"# Guide\n\n```js\nconst x = require('fs');\n```\n".as_slice(),
            b"Title\n=====\n\n~~~python\nimport os\n~~~\n",
            b"\xef\xbb\xbf\r\n## Guide\r\n   ````js\r\n```\r\n   `````\r\n",
        ] {
            assert!(document_structure(bytes));
        }
        for bytes in [
            b"const x = require('fs');\n```\nx\n```\n".as_slice(),
            b"# Guide\n```js\nx\n~~~\n",
            b"# Guide\n````js\nx\n```\n",
            b"# Guide\n```js\nx\n``` trailing\n",
            b"# Guide\n    ```js\nx\n    ```\n",
            b"# Guide\n```js`bad\nx\n```\n",
        ] {
            assert!(!document_structure(bytes));
        }
    }

    #[test]
    fn source_and_magic_still_override_markdown_names() {
        for (bytes, expected) in [
            (b"const fs = require('fs');\nmodule.exports = function () { return fs.readFileSync('x'); };\n".as_slice(), FileType::JavaScript),
            (b"#!/bin/sh\n# Guide\n```\nx\n```\n", FileType::Shell),
            (b"# Guide\nimport os\nimport sys\ndef run():\n    return os.getcwd()\ntext = '''\n```\nexample\n```\n'''\n", FileType::Python),
            (b"\x7fELF\x02\x01\x01\0# Guide\n```\nx\n```\n", FileType::Elf),
        ] {
            assert_eq!(FileId::from_path_and_bytes(Path::new("notes.md"), bytes).file_type(), expected);
        }
    }

    #[test]
    fn document_probe_is_bounded_and_handles_all_truncations() {
        let mut bytes = b"# Guide\n```js\n".to_vec();
        bytes.resize(WINDOW - 2, b'x');
        bytes.extend_from_slice(b"\n```\n");
        assert!(!document_structure(&bytes));
        let sample = include_bytes!("../../testdata/markdown/https-proxy-agent-readme.md");
        for end in 0..=sample.len() {
            let _ = document_structure(&sample[..end]);
        }
    }
}
