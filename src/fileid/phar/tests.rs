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
