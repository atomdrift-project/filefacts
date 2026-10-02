#![no_main]

use filefacts::FileType;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    filefacts_fuzz::forced(FileType::Plist, "sample.plist", data);
});
