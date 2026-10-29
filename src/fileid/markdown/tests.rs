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
fn readmes_with_program_examples_remain_markdown() {
    for bytes in [
        include_bytes!("../../../testdata/markdown/puppeteer-browsers-readme.md").as_slice(),
        include_bytes!("../../../testdata/markdown/https-proxy-agent-readme.md").as_slice(),
        include_bytes!("../../../testdata/markdown/debug-readme.md").as_slice(),
        include_bytes!("../../../testdata/markdown/proxy-agent-readme.md").as_slice(),
        include_bytes!("../../../testdata/markdown/appsec-front-matter-policy.md").as_slice(),
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
fn front_matter_precedes_fenced_document_not_disguised_source() {
    let doc = b"---\ninclusion: always\npriority: 0\napplies_to:\n  - all_languages\n---\n\n# Security policy\n\nDo not generate insecure code.\n\n```javascript\nconst x = require('fs');\n```\n";
    assert!(document_structure(doc));
    let id = FileId::from_path_and_bytes(Path::new("appsec-rules.md"), doc);
    assert_eq!(id.file_type(), FileType::Markdown);
    assert!(!id.extension_mismatch());
    for bytes in [
        b"---\ninclusion: always\n# Guide\n```js\nx\n```\n".as_slice(),
        b"---\nconst x = require('fs');\n---\n# Guide\n```js\nx\n```\n",
        b"---\ntitle: Guide\n---\nconst x = require('fs');\n```js\nx\n```\n",
        b"---\ntitle: Guide\n---\n# Guide\nconst x = require('fs');\n```js\nx\n```\n",
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
    let sample = include_bytes!("../../../testdata/markdown/https-proxy-agent-readme.md");
    for end in 0..=sample.len() {
        let _ = document_structure(&sample[..end]);
    }
}
