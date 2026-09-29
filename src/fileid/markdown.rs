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
    for line in lines {
        // A truncated final line cannot establish a closing fence.
        if data.len() > WINDOW && line.as_ptr_range().end == head.as_ptr_range().end {
            break;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let spaces = line.iter().take_while(|b| **b == b' ').count();
        if spaces > 3 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileId, FileType};
    use std::path::Path;

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
