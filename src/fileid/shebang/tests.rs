use super::*;

#[test]
fn shebang_without_interpreter() {
    for data in [
        &b"#!\n"[..],
        b"#! \r\n",
        b"#!/usr/bin/env\n",
        b"#!/usr/bin/env -S\n",
        b"#!/opt/x/unknown\n",
    ] {
        assert_eq!(
            detect_shebang(data),
            None,
            "{}",
            String::from_utf8_lossy(data).escape_debug()
        );
    }
}
