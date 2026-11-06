#![no_main]

use filefacts::{FileType, OpenOptions, Origin};
use std::path::Path;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    filefacts_fuzz::forced(FileType::Html, "sample.html", data);
    // An aligned inline script must lie inside the page.
    for file_type in [FileType::Html, FileType::Svg] {
        let parsed = OpenOptions::new()
            .cache(false)
            .path(Path::new("sample.html"))
            .file_type(file_type)
            .open(data);
        for source in parsed.embedded_sources() {
            if let Origin::Script {
                offset,
                aligned: true,
                ..
            } = source.origin
            {
                assert!(offset + source.source.len() <= data.len());
            }
        }
    }
});
