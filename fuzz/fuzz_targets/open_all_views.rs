#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| filefacts_fuzz::open_all_views(data));
