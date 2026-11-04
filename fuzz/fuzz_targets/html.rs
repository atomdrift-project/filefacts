#![no_main]

use filefacts::{FileType, OpenOptions};
use std::path::Path;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    filefacts_fuzz::forced(FileType::Html, "sample.html", data);
    // A page's inline-script layer must keep the page's coordinates.
    for file_type in [FileType::Html, FileType::Svg] {
        let parsed = OpenOptions::new()
            .cache(false)
            .path(Path::new("sample.html"))
            .file_type(file_type)
            .open(data);
        for source in parsed.embedded_sources().filter(|s| s.layer) {
            assert_eq!(source.source.len(), data.len());
        }
    }
});
