use super::*;
use std::io::{Read, Write};

/// A Developer ID Installer package cut off after its signatures: SHA-1
/// checksum, RSA and CMS signatures, chain to Apple Root CA.
const DEVELOPER_ID: &[u8] =
    include_bytes!("../../../tests/fixtures/xar/developer-id-installer-prefix.pkg");
/// A self-signed archive with a SHA-256 checksum and only the RSA signature.
const RSA_SHA256: &[u8] = include_bytes!("../../../tests/fixtures/xar/rsa-sha256.xar");

fn run(bytes: &[u8]) -> (Values, Errors) {
    let mut values = Values::default();
    let mut errors = Errors::new();
    extract(bytes, &mut values, &mut errors);
    (values, errors)
}

fn signatures(values: &Values) -> Vec<serde_json::Map<String, JsonValue>> {
    values
        .lookup(value_key!("xar.signatures"))
        .and_then(JsonValue::as_array)
        .map(|sigs| {
            sigs.iter()
                .map(|sig| sig.as_object().unwrap().clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Where the TOC starts and the heap starts in `bytes`.
fn layout(bytes: &[u8]) -> (usize, usize) {
    let header_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let toc_len = u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
    (header_len, header_len + toc_len)
}

/// `bytes` with its TOC XML rewritten by `edit` and recompressed. With
/// `rehash`, the heap checksum is recomputed under that algorithm to match
/// the new TOC, as an attacker who edits the TOC would; otherwise it is
/// left alone.
fn retoc(bytes: &[u8], edit: impl Fn(&str) -> String, rehash: Option<DigestAlg>) -> Vec<u8> {
    let (header_len, heap_start) = layout(bytes);
    let mut xml = String::new();
    flate2::read::ZlibDecoder::new(&bytes[header_len..heap_start])
        .read_to_string(&mut xml)
        .unwrap();
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(edit(&xml).as_bytes()).unwrap();
    let toc = z.finish().unwrap();
    let mut header = bytes[..header_len].to_vec();
    header[8..16].copy_from_slice(&(toc.len() as u64).to_be_bytes());
    let mut heap = bytes[heap_start..].to_vec();
    if let Some(alg) = rehash {
        let digest = alg.digest(&toc);
        heap[..digest.len()].copy_from_slice(&digest);
    }
    [header, toc, heap].concat()
}

fn add_creator(xml: &str) -> String {
    xml.replace("<toc>", "<toc><creator>attacker</creator>")
}

#[test]
fn a_developer_id_package_names_its_signer_twice() {
    let (values, errors) = run(DEVELOPER_ID);
    assert!(errors.is_empty(), "{errors:?}");
    let sigs = signatures(&values);
    let styles: Vec<_> = sigs.iter().map(|s| s["style"].as_str().unwrap()).collect();
    assert_eq!(styles, ["CMS", "RSA"]);
    for sig in &sigs {
        assert_eq!(sig["verified"], JsonValue::Bool(true), "{sig:?}");
        assert_eq!(sig["digest_matches"], JsonValue::Bool(true));
        assert_eq!(sig["chain_anchor"], "apple");
        assert!(
            sig["subject"]
                .as_str()
                .unwrap()
                .contains("CN=Developer ID Installer: Magno Partners Consulting (F7S4WH844B)")
        );
        assert_eq!(sig["chain_sha256"].as_array().unwrap().len(), 3);
    }
}

#[test]
fn a_bare_rsa_signature_over_a_sha256_checksum_verifies() {
    let (values, errors) = run(RSA_SHA256);
    assert!(errors.is_empty(), "{errors:?}");
    let sigs = signatures(&values);
    assert_eq!(sigs.len(), 1);
    let sig = &sigs[0];
    assert_eq!(sig["style"], "RSA");
    assert_eq!(sig["verified"], JsonValue::Bool(true), "{sig:?}");
    assert_eq!(sig["digest_matches"], JsonValue::Bool(true));
    assert_eq!(sig["digest_algorithm"], "sha256");
    assert_eq!(
        sig["subject"],
        "O=Filefacts Fixtures,CN=filefacts xar fixture"
    );
    assert!(sig.get("chain_anchor").is_none());
}

/// A TOC edited after signing no longer hashes to the checksum the
/// signatures sign: they still verify over that checksum, which is not
/// this archive's.
#[test]
fn an_edited_toc_unbinds_its_signatures() {
    for (fixture, count) in [(DEVELOPER_ID, 2), (RSA_SHA256, 1)] {
        let (values, errors) = run(&retoc(fixture, add_creator, None));
        assert!(errors.is_empty(), "{errors:?}");
        let sigs = signatures(&values);
        assert_eq!(sigs.len(), count);
        for sig in sigs {
            assert_eq!(sig["verified"], JsonValue::Bool(false), "{sig:?}");
            assert_eq!(sig["verification_failure"], "toc_checksum_mismatch");
            assert_eq!(sig["digest_matches"], JsonValue::Bool(false));
        }
    }
}

/// Rewriting the checksum to match an edited TOC leaves the signatures over
/// a checksum their keys never signed.
#[test]
fn a_rehashed_toc_fails_its_signatures() {
    for (fixture, alg) in [
        (DEVELOPER_ID, DigestAlg::Sha1),
        (RSA_SHA256, DigestAlg::Sha256),
    ] {
        let (values, _) = run(&retoc(fixture, add_creator, Some(alg)));
        let sigs = signatures(&values);
        assert!(!sigs.is_empty());
        for sig in sigs {
            assert_eq!(sig["verified"], JsonValue::Bool(false), "{sig:?}");
            assert_eq!(sig["digest_matches"], JsonValue::Bool(true));
        }
    }
}

/// xar hashes the TOC with the header's algorithm; a TOC naming another
/// one does not describe what was hashed.
#[test]
fn a_header_checksum_algorithm_that_disagrees_unbinds() {
    let mut bytes = RSA_SHA256.to_vec();
    bytes[24..28].copy_from_slice(&1u32.to_be_bytes());
    let (values, _) = run(&bytes);
    let sig = &signatures(&values)[0];
    assert_eq!(sig["digest_matches"], JsonValue::Bool(false));
    assert_ne!(sig["verified"], JsonValue::Bool(true));
}

/// A checksum the heap cannot hold leaves the CMS signature unbound and
/// the bare RSA signature, which signs nothing else, unread.
#[test]
fn an_unreadable_checksum_binds_nothing() {
    for offset in ["18446744073709551615", "99999999", "-1", "x"] {
        let bytes = retoc(
            DEVELOPER_ID,
            |xml| {
                xml.replacen(
                    "<offset>0</offset>",
                    &format!("<offset>{offset}</offset>"),
                    1,
                )
            },
            None,
        );
        let (values, errors) = run(&bytes);
        assert!(errors.is_empty(), "{errors:?}");
        let sigs = signatures(&values);
        assert_eq!(sigs.len(), 1, "{offset}");
        assert_eq!(sigs[0]["style"], "CMS");
        assert_eq!(sigs[0]["verified"], JsonValue::Null);
        assert!(sigs[0].get("digest_matches").is_none());
    }
}

/// Every prefix of a signed archive reads without panicking. A cut inside
/// the header or TOC is a malformed archive and names no signer; a cut in
/// the heap loses the signatures it reaches. Past the first signature,
/// where each prefix costs public-key work, prefixes are sampled.
#[test]
fn truncated_archives_never_panic_or_invent_a_signer() {
    for fixture in [DEVELOPER_ID, RSA_SHA256] {
        let (_, heap_start) = layout(fixture);
        for len in (0..fixture.len()).filter(|&len| len < heap_start + 300 || len % 127 == 0) {
            let (values, errors) = run(&fixture[..len]);
            let sigs = signatures(&values);
            if len < heap_start {
                assert!(sigs.is_empty(), "len {len}");
                assert_eq!(errors.len(), 1, "len {len}");
            } else {
                assert!(errors.is_empty(), "len {len}");
            }
            assert!(
                sigs.iter().all(|s| s["verified"] != JsonValue::Bool(true)
                    || s["digest_matches"] == JsonValue::Bool(true)),
                "len {len}"
            );
        }
    }
}

#[test]
fn malformed_headers_are_errors_not_panics() {
    let mut huge_toc = DEVELOPER_ID.to_vec();
    huge_toc[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut past_end = DEVELOPER_ID.to_vec();
    past_end[8..16].copy_from_slice(&(DEVELOPER_ID.len() as u64).to_be_bytes());
    let mut short_header = DEVELOPER_ID.to_vec();
    short_header[4..6].copy_from_slice(&4u16.to_be_bytes());
    let mut not_zlib = DEVELOPER_ID.to_vec();
    not_zlib[28..40].fill(0xff);
    for (bytes, limited) in [
        (&huge_toc, true),
        (&past_end, false),
        (&short_header, false),
        (&not_zlib, false),
    ] {
        let (values, errors) = run(bytes);
        assert!(signatures(&values).is_empty());
        assert_eq!(values.lookup(value_key!("xar.limits")).is_some(), limited);
        assert_eq!(errors.len(), usize::from(!limited), "{errors:?}");
    }
}

/// A TOC that is not a xar document, or one past the inflate cap.
#[test]
fn foreign_and_oversized_tocs_name_no_signer() {
    let foreign = retoc(DEVELOPER_ID, |_| "<plist><toc/></plist>".into(), None);
    let (values, errors) = run(&foreign);
    assert!(signatures(&values).is_empty());
    assert_eq!(errors.len(), 1);

    let bomb = retoc(
        DEVELOPER_ID,
        |xml| xml.replace("<toc>", &format!("<toc><!--{}-->", " ".repeat(17 << 20))),
        None,
    );
    let (values, errors) = run(&bomb);
    assert!(signatures(&values).is_empty());
    assert!(errors.is_empty(), "{errors:?}");
    assert!(values.lookup(value_key!("xar.limits")).is_some());
}
