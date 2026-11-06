use super::*;

#[test]
fn literal_and_identifier_rules() {
    assert!(is_base64_literal("SGVsbG8gV29ybGQh"));
    assert!(!is_base64_literal("SGVsbG8gV29ybGQhX"));
    assert!(!is_base64_literal("sgvsbg8gv29ybgqh"));
    assert!(!is_base64_literal("SGVs=G8gV29ybGQh"));
    assert!(is_base64_literal("SGVsbG8gV29ybA=="));
    assert!(is_base64_identifier("aB3dE5gH"));
    assert!(!is_base64_identifier("aBcdEfgH"));
    assert!(is_hex_literal("deadbeef"));
    assert!(is_hex_literal("0xdeadbeef"));
    assert!(!is_hex_literal("deadbeefa"));
    assert!(is_hex_identifier("deadbe"));
    assert!(!is_hex_identifier("deadbz"));
}

#[test]
fn tally_counts_each_class() {
    let tally = Tally::of(b"aB3+/=\r\n-");
    assert_eq!(
        tally,
        Tally {
            len: 9,
            base64: 6,
            line_breaks: 2,
            upper: true,
            lower: true,
            digit: true,
        }
    );
}

#[test]
fn comment_words_need_length_density_and_mixed_case() {
    assert!(is_base64_comment_word("aGVsbG8gd29ybGQgdGhpcyBpcw=="));
    assert!(!is_base64_comment_word("aGVsbG8gd29ybGQ"));
    assert!(!is_base64_comment_word("abcdefghijklmnopqrstuvwxyz"));
    assert!(!is_base64_comment_word("deadbeefdeadbeefdeadbeef"));
    // 18 of 20 alphabet bytes is exactly 90%, which is not more than 90%.
    assert!(!is_base64_comment_word("aBcDeFgHiJkLmNoPqR--"));
    assert!(is_base64_comment_word("aBcDeFgHiJkLmNoPqRsT-"));
}

#[test]
fn regions_tolerate_line_breaks_but_not_prose() {
    let wrapped = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n".repeat(4);
    assert!(is_base64_region(wrapped.as_bytes()));
    let prose = "The quick brown fox jumps over the lazy dog. ".repeat(4);
    assert!(!is_base64_region(prose.as_bytes()));
    assert!(!is_base64_region(b"QUJD"));
}

#[test]
fn random_token_rule() {
    for token in [
        "AKIAZ7QX4M2PLRWB9TKD",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "q3Zt9vX2LkP0mWbN8rJc5YhG1sFdA7eUo4TiK6wRzEx=",
    ] {
        assert!(is_random_token(token.as_bytes()), "{token}");
    }
    for text in [
        "The quick brown fox jumps over the lazy dog",
        "initializeComponentRegistry",
        "deadbeefdeadbeefdeadbeef",
        "1234567890123456789",
        "aB3dE5gH",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
    ] {
        assert!(!is_random_token(text.as_bytes()), "{text}");
    }
}

#[test]
fn expected_random_entropy_approaches_the_alphabet() {
    // Sixteen symbols from sixteen: about ten distinct, 3.3 bits.
    let short = expected_random_entropy(16, 16);
    assert!((3.0..3.5).contains(&short), "{short}");
    for k in [16, 64] {
        let long = expected_random_entropy(1 << 20, k);
        let max = f64::from(k).log2();
        assert!(long < max && long > 0.99 * max, "{k}: {long}");
    }
}
