use super::*;

fn script_rpm(tags: Vec<(u32, u32, u32, Vec<u8>)>) -> Vec<u8> {
    let mut out = vec![0; 96];
    out[..4].copy_from_slice(&RPM_LEAD_MAGIC);
    out.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
    let size: usize = tags.iter().map(|t| t.3.len()).sum();
    out.extend_from_slice(&(size as u32).to_be_bytes());
    let mut offset = 0u32;
    for (tag, typ, count, value) in &tags {
        for field in [*tag, *typ, offset, *count] {
            out.extend_from_slice(&field.to_be_bytes());
        }
        offset += value.len() as u32;
    }
    for (_, _, _, value) in tags {
        out.extend(value);
    }
    out
}

#[test]
fn declared_lifecycle_scriptlets_are_separate_units() {
    let mut tags = vec![(1000, 6, 1, b"fixture\0".to_vec())];
    for (_, body, program, _) in SCRIPTLETS {
        tags.push((body, 6, 1, b"echo 'ready'\n\0".to_vec()));
        tags.push((program, 6, 1, b"/bin/sh\0".to_vec()));
    }
    let bytes = script_rpm(tags);
    let parsed = crate::open(&bytes);
    let sources: Vec<_> = parsed.embedded_sources().collect();
    assert_eq!(sources.len(), 9);
    for (name, _, _, _) in SCRIPTLETS {
        let pointer = format!("/rpm/scriptlets/{name}/body");
        let source = sources.iter().find(|s| s.pointer == pointer).unwrap();
        assert_eq!(source.source, "echo 'ready'\n");
        assert_eq!(source.file_type, Some(crate::FileType::Shell));
    }
    assert!(parsed.errors().is_empty());
    assert_eq!(
        parsed.values().get("rpm.name").unwrap().as_str(),
        Some("fixture")
    );
}

#[test]
fn declared_interpreters_defaults_and_processing_flags() {
    use crate::FileType;
    for (program, expected) in [
        (None, Some(FileType::Shell)),
        (Some("/usr/bin/python3"), Some(FileType::Python)),
        (Some("/usr/bin/perl"), Some(FileType::Perl)),
        (Some("/usr/bin/ruby"), Some(FileType::Ruby)),
        (Some("<lua>"), Some(FileType::Lua)),
        (Some("/usr/local/bin/custom"), None),
    ] {
        let mut tags = vec![(1024, 6, 1, b"print('ready')\0".to_vec())];
        if let Some(program) = program {
            tags.push((1086, 8, 1, format!("{program}\0").into_bytes()));
        }
        let bytes = script_rpm(tags);
        let parsed = crate::open(&bytes);
        assert_eq!(
            parsed.embedded_sources().next().unwrap().file_type,
            expected
        );
    }
    for tag in [
        (5021, 4, 1, 1u32.to_be_bytes().to_vec()),
        (1086, 8, 2, b"/bin/sh\0-c\0".to_vec()),
    ] {
        let bytes = script_rpm(vec![(1024, 6, 1, b"echo 'ready'\0".to_vec()), tag]);
        let parsed = crate::open(&bytes);
        assert!(
            parsed
                .embedded_sources()
                .next()
                .unwrap()
                .file_type
                .is_none()
        );
        assert!(parsed.errors().is_empty());
    }
}

#[test]
fn invalid_bodies_do_not_hide_later_valid_scriptlets() {
    for bad in [
        (1023, 8, 1, b"echo bad\0".to_vec()),
        (1023, 6, 2, b"echo bad\0".to_vec()),
        (1023, 6, 1, vec![0xff, 0]),
    ] {
        let bytes = script_rpm(vec![bad, (1024, 6, 1, b"echo 'ready'\0".to_vec())]);
        let parsed = crate::open(&bytes);
        assert_eq!(parsed.embedded_sources().count(), 1);
        assert!(!parsed.errors().is_empty());
    }
    for bad in [b"unterminated".to_vec(), vec![b'x'; MAX_SCRIPT_BYTES + 1]] {
        let bytes = script_rpm(vec![
            (1024, 6, 1, b"echo 'ready'\0".to_vec()),
            (1023, 6, 1, bad),
        ]);
        let parsed = crate::open(&bytes);
        assert_eq!(parsed.embedded_sources().count(), 1);
        assert!(!parsed.errors().is_empty());
    }
}

#[test]
fn duplicate_body_is_ambiguous_and_invalid_program_never_defaults() {
    let bytes = script_rpm(vec![
        (1024, 6, 1, b"echo first\0".to_vec()),
        (1024, 6, 1, b"echo second\0".to_vec()),
        (1026, 6, 1, b"echo third\0".to_vec()),
    ]);
    let parsed = crate::open(&bytes);
    assert_eq!(parsed.embedded_sources().count(), 1);
    assert!(!parsed.errors().is_empty());
    for bad in [
        (1086, 6, 2, b"/bin/sh\0-c\0".to_vec()),
        (1086, 7, 1, b"/bin/sh\0".to_vec()),
        (1086, 6, 1, b"/bin/sh".to_vec()),
        (1086, 8, 0, Vec::new()),
        (1086, 8, 1, b"/bin/sh".to_vec()),
        (1086, 8, u32::MAX, Vec::new()),
        (5021, 6, 1, b"0\0".to_vec()),
    ] {
        let bytes = script_rpm(vec![(1024, 6, 1, b"echo 'ready'\0".to_vec()), bad]);
        let parsed = crate::open(&bytes);
        assert!(
            parsed
                .embedded_sources()
                .next()
                .unwrap()
                .file_type
                .is_none()
        );
        assert!(!parsed.errors().is_empty());
    }
}

#[test]
fn descriptive_header_strings_are_not_scriptlets() {
    let bytes = script_rpm(vec![
        (1000, 6, 1, b"fixture\0".to_vec()),
        (1004, 9, 1, b"echo 'ready'\0".to_vec()),
        (1086, 8, 1, b"/bin/sh\0".to_vec()),
    ]);
    let parsed = crate::open(&bytes);
    assert_eq!(parsed.embedded_sources().count(), 0);
    assert!(parsed.errors().is_empty());
}

fn build_minimal_rpm() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&RPM_LEAD_MAGIC);
    out.extend_from_slice(&[0u8; 92]);

    // Empty signature header.
    out.extend_from_slice(&RPM_HEADER_MAGIC);
    out.push(1);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());

    // Main header: NAME / VERSION / BUILDHOST / BUILDTIME.
    out.extend_from_slice(&RPM_HEADER_MAGIC);
    out.push(1);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&4u32.to_be_bytes());
    out.extend_from_slice(&38u32.to_be_bytes());

    for &(tag, typ, offset, count) in &[
        (main_tag::NAME, 6u32, 0u32, 1u32),
        (main_tag::VERSION, 6, 8, 1),
        (main_tag::BUILDHOST, 6, 14, 1),
        (main_tag::BUILDTIME, 4, 34, 1),
    ] {
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
    }
    out.extend_from_slice(b"openssh\0");
    out.extend_from_slice(b"9.9p1\0");
    out.extend_from_slice(b"build-1.example.org\0");
    out.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    out
}

fn run(bytes: &[u8]) -> (Values, Metrics, Errors) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    let mut e = Errors::new();
    extract(bytes, &mut v, &mut s, &mut m, &mut e).unwrap();
    (v, m, e)
}

/// The one recorded error's stage, kind and message.
fn only_error(errors: &Errors) -> (Stage, crate::ErrorKind, &str) {
    assert_eq!(errors.len(), 1, "{errors:?}");
    let e = &errors.as_slice()[0];
    (e.stage, e.kind, e.message.as_str())
}

#[test]
fn rejects_non_rpm() {
    let (v, _, e) = run(b"not an rpm");
    assert!(v.get("rpm.name").is_none());
    assert!(e.is_empty());
}

#[test]
fn surfaces_main_header() {
    let rpm = build_minimal_rpm();
    let (v, m, e) = run(&rpm);
    assert!(e.is_empty(), "{e:?}");
    assert!(v.get("rpm.limits").is_none());
    assert_eq!(v.get("rpm.name").and_then(|x| x.as_str()), Some("openssh"));
    assert_eq!(v.get("rpm.version").and_then(|x| x.as_str()), Some("9.9p1"));
    assert_eq!(
        v.get("rpm.buildhost").and_then(|x| x.as_str()),
        Some("build-1.example.org")
    );
    assert_eq!(m.get("rpm.buildtime"), Some(1_700_000_000.0));
    // No signing tags in minimal sample → no signature subtree.
    assert!(v.get("rpm.signature").is_none());
}

#[test]
fn truncated_lead_is_silent() {
    let (v, _, e) = run(&[0u8; 10]);
    assert!(v.get("rpm.name").is_none());
    assert!(e.is_empty());
}

#[test]
fn wrong_lead_magic_is_silent() {
    let mut bad = vec![0u8; LEAD_BYTES + 16];
    bad[0..4].copy_from_slice(b"NOPE");
    let (v, _, e) = run(&bad);
    assert!(v.get("rpm.name").is_none());
    assert!(e.is_empty());
}

#[test]
fn rpm_cut_inside_the_lead_records_a_malformed_signature_header() {
    let (v, _, e) = run(&build_minimal_rpm()[..LEAD_BYTES - 1]);
    let (stage, kind, message) = only_error(&e);
    assert_eq!(
        (stage, kind),
        (Stage::RpmParse, crate::ErrorKind::Malformed)
    );
    assert!(message.starts_with("signature-header:"), "{message}");
    assert!(v.get("rpm.limits").is_none());
}

#[test]
fn bad_signature_header_magic_records_one_malformed_error() {
    let mut rpm = build_minimal_rpm();
    rpm[LEAD_BYTES] = 0;
    let (v, _, e) = run(&rpm);
    let (stage, kind, message) = only_error(&e);
    assert_eq!(
        (stage, kind),
        (Stage::RpmParse, crate::ErrorKind::Malformed)
    );
    assert_eq!(message, "signature-header: bad header magic");
    assert!(v.get("rpm.name").is_none());
    assert!(v.get("rpm.limits").is_none());
}

/// A header that really is larger than the cap is a coverage limit, not
/// a parse failure: it lands in `rpm.limits` and leaves `errors` empty.
#[test]
fn oversized_signature_header_is_a_limit_not_an_error() {
    let hsize = MAX_HEADER_BYTES + 1;
    let mut rpm = build_minimal_rpm();
    rpm[LEAD_BYTES + 12..LEAD_BYTES + 16].copy_from_slice(&(hsize as u32).to_be_bytes());
    rpm.resize(LEAD_BYTES + 16 + hsize, 0);
    let (v, _, e) = run(&rpm);
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("rpm.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits.len(), 1);
    assert_eq!(limits[0]["stage"], "signature-header");
    assert!(limits[0]["reason"].as_str().unwrap().contains("header cap"));
}

/// The same oversized claim in a file too short to hold it is a lying
/// size: malformed, not a limit.
#[test]
fn header_size_past_end_of_file_is_malformed_not_a_limit() {
    let mut rpm = build_minimal_rpm();
    rpm[LEAD_BYTES + 12..LEAD_BYTES + 16]
        .copy_from_slice(&(MAX_HEADER_BYTES as u32 + 1).to_be_bytes());
    let (v, _, e) = run(&rpm);
    let (stage, kind, message) = only_error(&e);
    assert_eq!(
        (stage, kind),
        (Stage::RpmParse, crate::ErrorKind::Malformed)
    );
    assert!(message.contains("past the end of the file"), "{message}");
    assert!(v.get("rpm.limits").is_none());
}

#[test]
fn truncated_main_header_doesnt_crash() {
    // Valid lead + valid (empty) sig header + main-header magic
    // claiming 1 entry but truncated before entry bytes.
    let mut out = Vec::new();
    out.extend_from_slice(&RPM_LEAD_MAGIC);
    out.extend_from_slice(&[0u8; 92]);
    out.extend_from_slice(&RPM_HEADER_MAGIC);
    out.push(1);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    // Main header claims 1 entry of 100 bytes but supplies neither.
    out.extend_from_slice(&RPM_HEADER_MAGIC);
    out.push(1);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&100u32.to_be_bytes());
    let (v, _, e) = run(&out);
    assert!(v.get("rpm.name").is_none());
    let (stage, kind, message) = only_error(&e);
    assert_eq!(
        (stage, kind),
        (Stage::RpmParse, crate::ErrorKind::Malformed)
    );
    assert!(message.starts_with("main-header:"), "{message}");
}

#[test]
fn rpm_ending_after_the_signature_header_records_a_missing_main_header() {
    let rpm = build_minimal_rpm();
    let (v, _, e) = run(&rpm[..LEAD_BYTES + 16]);
    assert_eq!(
        only_error(&e),
        (
            Stage::RpmParse,
            crate::ErrorKind::Malformed,
            "main-header: file ends before the header"
        )
    );
    assert!(v.get("rpm.name").is_none());
}
