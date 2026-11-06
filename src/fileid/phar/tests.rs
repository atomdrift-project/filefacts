use super::*;

/// The stub ends where PHP's reader says: a ` ?>` after the token is part of
/// it, as is one newline after that, and nothing else is.
#[test]
fn the_stub_ends_where_php_says() {
    for (tail, extra) in [
        (&b""[..], 0),
        (b" ?>", 3),
        (b" ?>\n", 4),
        (b" ?>\r\n", 5),
        (b"\n?>\n", 4),
        (b"\n", 0),
    ] {
        let mut data = b"<?php __HALT_COMPILER();".to_vec();
        let token_end = data.len();
        data.extend_from_slice(tail);
        data.extend_from_slice(b"rest");
        assert_eq!(stub_end(&data, token_end), token_end + extra, "{tail:?}");
    }
}

/// `stub`, then an empty manifest as PHP writes one.
fn unsigned_phar(stub: &[u8]) -> Vec<u8> {
    let mut manifest = 0u32.to_le_bytes().to_vec();
    manifest.extend_from_slice(&[0x11, 0x00]);
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    let mut out = stub.to_vec();
    out.extend_from_slice(&u32::try_from(manifest.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&manifest);
    out
}

/// An unsigned phar is searched for only when it opens as PHP: a PHP tag, or
/// a shebang line and then one. An XML prolog or a shell script is neither,
/// so it is not searched however it continues.
#[test]
fn an_unsigned_stub_must_open_as_php() {
    for stub in [
        &b"<?php __HALT_COMPILER(); ?>\r\n"[..],
        b"<?PHP __HALT_COMPILER();",
        b"<?= 1; __HALT_COMPILER();",
        b"<? __HALT_COMPILER();",
        b"  \n<?php\n__HALT_COMPILER();",
        b"#!/usr/bin/env php\n<?php __HALT_COMPILER();",
        b"#!/usr/bin/php -d phar.readonly=0\r\n<?php __HALT_COMPILER();",
    ] {
        assert!(is_phar(&unsigned_phar(stub)), "{}", stub.escape_ascii());
    }
    for stub in [
        &b"<?xml version=\"1.0\"?><x>__HALT_COMPILER();"[..],
        b"#!/bin/sh\necho __HALT_COMPILER();",
        b"<?phpx __HALT_COMPILER();",
    ] {
        assert!(!is_phar(&unsigned_phar(stub)), "{}", stub.escape_ascii());
    }
}
