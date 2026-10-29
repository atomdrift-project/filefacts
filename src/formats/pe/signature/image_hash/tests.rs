use super::*;
use goblin::pe::optional_header::{
    MAGIC_32, MAGIC_64, OFFSET_WINDOWS_FIELDS_32_CHECKSUM, OFFSET_WINDOWS_FIELDS_64_CHECKSUM,
    SIZEOF_STANDARD_FIELDS_32, SIZEOF_STANDARD_FIELDS_64,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

fn extract_values(bytes: &[u8]) -> (Values, Metrics) {
    let mut out = crate::formats::Sinks::default();
    crate::formats::pe::extract(bytes, out.ctx()).unwrap();
    let crate::formats::Sinks {
        values: v,
        metrics: m,
        ..
    } = out;
    (v, m)
}

/// SHA-256 always lands for a parseable PE — the fixture is an unsigned
/// 64-bit MSVC build that uses the canonical PE layout — and the other
/// algorithms only when a signature commits to them.
#[test]
fn image_hashes_emitted_for_well_formed_pe() {
    let bytes = fixture("test.exe");
    let (v, _) = extract_values(&bytes);
    let h = v
        .get("pe.image_hash.sha256")
        .and_then(|x| x.as_str())
        .expect("pe.image_hash.sha256 missing");
    assert_eq!(h.len(), hex_len("sha256"));
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {h}");
    for alg in ["sha1", "sha384", "sha512"] {
        assert!(
            v.get(&format!("pe.image_hash.{alg}")).is_none(),
            "{alg} computed for an unsigned image"
        );
    }
}

/// Every algorithm a signature names, nested ones included, is computed
/// alongside SHA-256 in the same walk.
#[test]
fn claimed_algorithms_are_hashed() {
    let bytes = fixture("test.exe");
    let pe = goblin::pe::PE::parse(&bytes).expect("parse");
    let signatures: Vec<Signature> = serde_json::from_value(serde_json::json!([{
        "signature_digest_algorithm": "sha1",
        "nested": [{"signature_digest_algorithm": "sha512"}],
    }]))
    .unwrap();
    let mut v = Values::new();
    let mut m = Metrics::new();
    super::extract(&pe, &bytes, &signatures, &mut v, &mut m);
    for alg in ["sha1", "sha256", "sha512"] {
        let h = v
            .get(&format!("pe.image_hash.{alg}"))
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("{alg} missing"));
        assert_eq!(h.len(), hex_len(alg));
    }
    assert!(v.get("pe.image_hash.sha384").is_none());
    // The SHA-1 digest of the canonical region walk over the fixture.
    assert_eq!(
        v.get("pe.image_hash.sha1").and_then(|x| x.as_str()),
        Some("444ac776b5ecd5c48d9c6254f10b5f6d5aae5567"),
    );
}

/// Section headers whose raw ranges all cover the same bytes would make
/// the hash walk the file once per section. Past the cap no digest is
/// emitted and the skip is recorded.
#[test]
fn overlapping_sections_past_the_cap_are_not_hashed() {
    let bytes = fixture("test.exe");
    let pe = goblin::pe::PE::parse(&bytes).expect("parse");
    let mut regions = derive_regions(&pe, &bytes).expect("regions");
    // What `derive_regions` yields for a table of sections whose raw
    // ranges all cover the whole file.
    regions
        .ranges
        .extend(std::iter::repeat_n(0..bytes.len(), 8));
    assert!(regions.hashed_len() > bytes.len() as u64 * MAX_HASHED_FILE_MULTIPLE);
    let mut v = Values::new();
    let mut m = Metrics::new();
    emit(&regions, &bytes, &[HashAlg::Sha256], &mut v, &mut m);
    assert!(v.get("pe.image_hash.sha256").is_none());
    assert_eq!(m.get("pe.image_hash_skipped"), Some(1.0));
}

/// Pin the SHA-256 image hash of `test.exe` to its known value. Any
/// unintended change in the region walker — the number of bytes
/// hashed, the order, the holes punched in the header — will produce
/// a different digest and trip this test. Regenerate by running
/// `cargo run --bin filefacts -- tests/fixtures/test.exe` if the
/// fixture itself is ever replaced.
#[test]
fn image_hashes_test_exe_pinned_values() {
    let bytes = fixture("test.exe");
    let (v, _) = extract_values(&bytes);
    assert_eq!(
        v.get("pe.image_hash.sha256").and_then(|x| x.as_str()),
        Some("218103c5f4caf14299d61dab1cced6f6d6b6cd47ee6cfba204856fb1ea205120"),
    );
}

/// Determinism — two extractions over the same bytes must produce
/// the same digest. Guards against accidental non-determinism in
/// the region walker (e.g. iterating a HashMap of sections).
#[test]
fn image_hash_is_deterministic() {
    let bytes = fixture("test.exe");
    let (v1, _) = extract_values(&bytes);
    let (v2, _) = extract_values(&bytes);
    for alg in ["sha1", "sha256", "sha384", "sha512"] {
        let k = format!("pe.image_hash.{alg}");
        assert_eq!(v1.get(&k), v2.get(&k));
    }
}

/// Changing the checksum field in the header must NOT change the
/// image hash — Authenticode explicitly excludes those four
/// bytes. This is the load-bearing property of the algorithm
/// (otherwise every Windows PE that has its CheckSum recomputed
/// post-link would invalidate its own signature).
#[test]
fn image_hash_ignores_checksum_field() {
    let mut bytes = fixture("test.exe");
    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    // CheckSum lives 0x40 bytes into the windows_fields; for a
    // PE32+ test.exe that's `pe_offset + 24 + SIZEOF_STANDARD_FIELDS_64 + 0x40`.
    // We derive it by re-running the region walker rather than
    // hard-coding the offset.
    let pe = goblin::pe::PE::parse(&bytes).expect("parse");
    let opt = pe.header.optional_header.as_ref().expect("opt");
    let optional_header_offset = pe_offset + 4 + 20;
    let checksum_offset = match opt.standard_fields.magic {
        MAGIC_32 => {
            optional_header_offset + SIZEOF_STANDARD_FIELDS_32 + OFFSET_WINDOWS_FIELDS_32_CHECKSUM
        }
        MAGIC_64 => {
            optional_header_offset + SIZEOF_STANDARD_FIELDS_64 + OFFSET_WINDOWS_FIELDS_64_CHECKSUM
        }
        _ => panic!("unsupported magic"),
    };
    let (v_before, _) = extract_values(&bytes);
    // Flip every bit in the checksum field.
    bytes[checksum_offset] ^= 0xff;
    bytes[checksum_offset + 1] ^= 0xff;
    bytes[checksum_offset + 2] ^= 0xff;
    bytes[checksum_offset + 3] ^= 0xff;
    let (v_after, _) = extract_values(&bytes);
    for alg in ["sha1", "sha256", "sha384", "sha512"] {
        let k = format!("pe.image_hash.{alg}");
        assert_eq!(
            v_before.get(&k),
            v_after.get(&k),
            "{k} changed when checksum field was perturbed",
        );
    }
}

/// `derive_regions` returns `None` whenever the optional header
/// is missing, the header sentinel sits past EOF, or any of the
/// hash ranges would overflow the file. The `extract` entry
/// point uses that signal to skip emitting any
/// `pe.image_hash.*` keys; this test exercises the `None` paths
/// directly so we don't need a header-only fixture (which would
/// fail the upstream PE parse anyway).
#[test]
fn derive_regions_rejects_truncated_inputs() {
    // Valid PE → derive_regions returns Some(...) on a real
    // fixture; the negative cases are easier to drive by feeding
    // truncated copies of the real bytes back through goblin.
    let full = fixture("test.exe");
    let pe = goblin::pe::PE::parse(&full).expect("fixture parses");
    assert!(
        super::derive_regions(&pe, &full).is_some(),
        "regions should derive for the full fixture",
    );
    // Truncate to less than `size_of_headers` — every header
    // range bound should fail the in-range check.
    let truncated = &full[..0x100];
    assert!(
        super::derive_regions(&pe, truncated).is_none(),
        "truncated bytes should fail region derivation",
    );
}

fn hex_len(alg: &str) -> usize {
    match alg {
        "sha1" => 40,
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => unreachable!(),
    }
}
