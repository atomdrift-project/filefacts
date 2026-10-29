use super::to_der;

#[test]
fn definite_der_passes_through_unchanged() {
    let der = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xAA];
    assert_eq!(to_der(&der).unwrap(), der);
}

#[test]
fn indefinite_lengths_become_definite() {
    // SEQUENCE (indefinite) { INTEGER 5 } EOC, then trailing padding.
    let ber = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(to_der(&ber).unwrap(), [0x30, 0x03, 0x02, 0x01, 0x05]);
}

#[test]
fn non_minimal_lengths_are_shortened() {
    let ber = [0x04, 0x82, 0x00, 0x02, 0xAA, 0xBB];
    assert_eq!(to_der(&ber).unwrap(), [0x04, 0x02, 0xAA, 0xBB]);
}

#[test]
fn constructed_octet_strings_are_folded() {
    // OCTET STRING (constructed, indefinite) { "ab", "c" } EOC.
    let ber = [
        0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0x00, 0x00,
    ];
    assert_eq!(to_der(&ber).unwrap(), [0x04, 0x03, b'a', b'b', b'c']);
}

#[test]
fn long_contents_get_a_long_form_length() {
    let mut ber = vec![0x30, 0x80, 0x04, 0x81, 0xC8];
    ber.extend([0u8; 200]);
    ber.extend([0x00, 0x00]);
    let der = to_der(&ber).unwrap();
    assert_eq!(der.get(..3), Some(&[0x30, 0x81, 0xCB][..]));
    assert_eq!(der.len(), 3 + 203);
}

#[test]
fn malformed_input_is_rejected() {
    // Primitive element with an indefinite length.
    assert!(to_der(&[0x04, 0x80, 0x00, 0x00]).is_none());
    // Missing end-of-contents.
    assert!(to_der(&[0x30, 0x80, 0x02, 0x01, 0x05]).is_none());
    // Length past the input.
    assert!(to_der(&[0x04, 0x05, 0x01]).is_none());
    // A constructed OCTET STRING holding something other than chunks.
    assert!(to_der(&[0x24, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]).is_none());
}

#[test]
fn nesting_beyond_the_cap_is_rejected() {
    let mut ber = Vec::new();
    for _ in 0..100 {
        ber.extend([0x30, 0x80]);
    }
    for _ in 0..100 {
        ber.extend([0x00, 0x00]);
    }
    assert!(to_der(&ber).is_none());
}
