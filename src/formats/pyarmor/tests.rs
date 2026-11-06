use super::*;

#[test]
fn independent_openssl_fixture_and_negative_controls() {
    let runtime = include_bytes!("../../../testdata/pyarmor/runtime-data.bin");
    let container = include_bytes!("../../../testdata/pyarmor/container.bin");
    let expected = include_bytes!("../../../testdata/pyarmor/plain.bin");
    assert_eq!(
        recover(runtime, container)
            .as_ref()
            .map(|r| r.container.as_slice()),
        Some(expected.as_slice())
    );
    let mut wrong_salt = *runtime;
    wrong_salt[0x300] ^= 1;
    assert!(recover(&wrong_salt, container).is_none());
    let mut wrong_nonce = *container;
    wrong_nonce[0x2c] ^= 1;
    assert!(recover(runtime, &wrong_nonce).is_none());
    assert!(recover(runtime, &container[..100]).is_none());
}
#[test]
fn ctr_roundtrip_and_structural_near_misses() {
    let mut header = vec![0u8; 80];
    for (at, v) in [(0, 32u32), (8, 48), (12, 0x40912), (16, 8)] {
        header[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    let decrypted =
        ctr(&header, &[0x7a; 16], &[0x19; 12]).and_then(|enc| ctr(&enc, &[0x7a; 16], &[0x19; 12]));
    assert_eq!(decrypted, Some(header.clone()));
    assert!(header_valid(&header, 80, 0x40912));
    assert!(!header_valid(&header, 81, 0x40912));
    header[16] = 9;
    assert!(!header_valid(&header, 80, 0x40912));
    assert!(recover(b"MZ", b"PY000000").is_none());
}

#[test]
fn parsed_wrapper_to_standard_pyc_preserves_constants_and_names() {
    let source = include_bytes!("../../../testdata/pyarmor/wrapper.py");
    let containers = python_containers(source);
    assert_eq!(containers.len(), 1);
    assert_eq!(
        containers[0],
        include_bytes!("../../../testdata/pyarmor/marshal-container.bin")
    );
    let decoded = recover(
        include_bytes!("../../../testdata/pyarmor/runtime-data.bin"),
        &containers[0],
    )
    .unwrap();
    assert_eq!(
        decoded.container,
        include_bytes!("../../../testdata/pyarmor/marshal-plain.bin")
    );
    let pyc = decoded.pyc().unwrap().data;
    let parsed = crate::OpenOptions::new()
        .file_type(crate::FileType::PythonBytecode)
        .open(&pyc);
    assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
    assert!(parsed.symbols().iter().any(|s| s.name() == Some("message")));
}
#[test]
fn literal_reader_does_not_execute_expressions_or_decode_documentation() {
    for source in [
        b"data = b'PY000000'".as_slice(),
        b"# loader(a, b, b'PY000000')".as_slice(),
        b"doc = \"loader(a, b, b'PY000000')\"".as_slice(),
        b"loader(a, b, build_payload())".as_slice(),
        b"loader(a, b, 'PY000000')".as_slice(),
    ] {
        assert!(python_containers(source).is_empty());
    }
    assert_eq!(
        python_bytes(br#"b'PY000000\x00\377\n\\'"#).unwrap(),
        b"PY000000\x00\xff\n\\"
    );
    assert_eq!(
        python_bytes(br#"br'PY000000\x00'"#).unwrap(),
        br"PY000000\x00"
    );
    assert!(python_bytes(br#"b'PY000000\xQQ'"#).is_none());
    assert!(python_bytes(b"b'bad\\'").is_none());
}
#[test]
fn malformed_inputs_and_non_code_containers_do_not_become_pyc() {
    let runtime = include_bytes!("../../../testdata/pyarmor/runtime-data.bin");
    let container = include_bytes!("../../../testdata/pyarmor/marshal-container.bin");
    for end in 0..container.len() {
        assert!(recover(runtime, &container[..end]).is_none());
    }
    assert!(
        recover(
            runtime,
            include_bytes!("../../../testdata/pyarmor/container.bin")
        )
        .unwrap()
        .pyc()
        .is_err()
    );
    let mut corrupt = container.to_vec();
    corrupt[12..16].fill(0);
    assert!(recover(runtime, &corrupt).unwrap().pyc().is_err());
}

#[test]
fn independent_nested_instruction_fixture() {
    let runtime = include_bytes!("../../../testdata/pyarmor/runtime-data.bin");
    let container = include_bytes!("../../../testdata/pyarmor/nested-container.bin");
    let recovered = recover(runtime, container).unwrap().pyc().unwrap();
    assert_eq!(
        recovered.data,
        include_bytes!("../../../testdata/pyarmor/nested-normalized.pyc")
    );
    assert_eq!(recovered.code_objects, 2);
    assert_eq!(recovered.decrypted_regions, 2);
    assert!(recovered.limitations.is_empty());
    for end in 0..recovered.data.len().saturating_sub(16) {
        let body = &recovered.data[16..16 + end];
        assert!(marshal::normalize(body, 11, &[0; 16]).is_err());
    }
    let mut recovery = recover(runtime, container).unwrap();
    // Both short metadata and an invalid descriptor index must fail closed.
    *recovery.container.last_mut().unwrap() = 255;
    assert!(recovery.pyc().is_err());
}
#[test]
fn recognizes_nondefault_serials() {
    assert!(is_container(b"PY123456"));
    assert!(!is_container(b"PYabc123"));
    let runtime = include_bytes!("../../../testdata/pyarmor/runtime-data.bin");
    let mut blob = include_bytes!("../../../testdata/pyarmor/nested-container.bin").to_vec();
    blob[2..8].copy_from_slice(b"123456");
    assert_eq!(
        recover(runtime, &blob).unwrap().pyc().unwrap().code_objects,
        2
    );
}
#[test]
fn der_key_recovery_is_independent_of_native_file_format() {
    let runtime = include_bytes!("../../../testdata/pyarmor/der-runtime.bin");
    let blob = include_bytes!("../../../testdata/pyarmor/der-container.bin");
    for signature in [
        b"\x7fELF",
        b"MZ\0\0",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ] {
        let mut runtime = runtime.to_vec();
        runtime[..4].copy_from_slice(signature);
        assert!(recover(&runtime, blob).unwrap().pyc().is_ok());
    }
    let mut wrong = *runtime;
    wrong[768 + 20] ^= 1;
    assert!(recover(&wrong, blob).is_none());
}
#[test]
fn unknown_instruction_nonce_protection_is_explicit() {
    let runtime = include_bytes!("../../../testdata/pyarmor/runtime-data.bin");
    let container = include_bytes!("../../../testdata/pyarmor/nested-container.bin");
    let mut recovery = recover(runtime, container).unwrap();
    let mut descriptor = vec![0; 12];
    descriptor.extend_from_slice(&6u32.to_le_bytes());
    descriptor.extend_from_slice(&1u32.to_le_bytes());
    let at = recovery
        .container
        .windows(20)
        .position(|v| v == descriptor)
        .unwrap();
    recovery.container[at + 8] = 4;
    let result = recovery.pyc().unwrap();
    assert_eq!(result.decrypted_regions, 1);
    assert!(
        result
            .limitations
            .contains(&"instruction nonce-XOR protection remains encrypted")
    );
}
#[test]
fn relocated_prologues_and_short_nonce_descriptors() {
    let runtime = include_bytes!("../../../testdata/pyarmor/runtime-data.bin");
    for (blob, expected) in [
        (
            include_bytes!("../../../testdata/pyarmor/prologue-8-container.bin").as_slice(),
            include_bytes!("../../../testdata/pyarmor/prologue-8-normalized.pyc").as_slice(),
        ),
        (
            include_bytes!("../../../testdata/pyarmor/prologue-10-container.bin").as_slice(),
            include_bytes!("../../../testdata/pyarmor/prologue-10-normalized.pyc").as_slice(),
        ),
    ] {
        let result = recover(runtime, blob).unwrap().pyc().unwrap();
        assert_eq!(result.data, expected);
        assert_eq!(result.decrypted_regions, 1);
        assert!(result.limitations.is_empty());
    }
}
