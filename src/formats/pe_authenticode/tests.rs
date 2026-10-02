use super::{
    gen_time_from_tst_info, is_ecdsa_oid, is_rsa_oid, oid_to_label, parse_generalized_time,
    read_tlv, signature_algorithm_name, trim_to_der_object,
};
use der::oid::ObjectIdentifier;

/// A real Authenticode blob: Tencent's leaf, issued by DigiCert's SHA2
/// Assured ID Code Signing CA (the root is not in the bag).
const DIGICERT_TENCENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/authenticode-digicert-tencent.p7b"
));
const TENCENT_LEAF: &str = "9a989f4a4ff379a003d2f6dfe471f598fd583f3dbcf18aff5fea42dd5a83d8d9";
const DIGICERT_CODE_SIGNING_CA: &str =
    "51044706bd237b91b89b781337e6d62656c69f0fcffbe8e43741367948127862";

fn parse(blob: &[u8]) -> serde_json::Value {
    super::parse_pkcs7(trim_to_der_object(blob).unwrap()).unwrap()
}

fn chain(sig: &serde_json::Value) -> Vec<&str> {
    sig["chain_sha256"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect()
}

#[test]
fn chain_follows_issuers_whose_keys_verify() {
    let sig = parse(DIGICERT_TENCENT);
    assert_eq!(chain(&sig), [TENCENT_LEAF, DIGICERT_CODE_SIGNING_CA]);
    assert_eq!(sig["thumbprint_sha256"], TENCENT_LEAF);
}

/// Certs-only bags produced by `tests/fixtures/chains/generate.sh`.
mod bags {
    use der::{Decode, Encode};
    use sha2::{Digest, Sha256};

    pub(super) struct Bag {
        pub(super) sd: cms::signed_data::SignedData,
    }

    impl Bag {
        pub(super) fn load(bytes: &[u8]) -> Self {
            let ci = cms::content_info::ContentInfo::from_der(bytes).unwrap();
            Self {
                sd: ci.content.decode_as().unwrap(),
            }
        }

        pub(super) fn certs(&self) -> Vec<&x509_cert::Certificate> {
            self.sd
                .certificates
                .iter()
                .flat_map(|set| set.0.iter())
                .filter_map(|entry| match entry {
                    cms::cert::CertificateChoices::Certificate(c) => Some(c),
                    _ => None,
                })
                .collect()
        }

        /// The certificate with this CN whose issuer has `issuer_cn`.
        pub(super) fn cert(&self, cn: &str, issuer_cn: &str) -> &x509_cert::Certificate {
            self.certs()
                .into_iter()
                .find(|c| {
                    c.tbs_certificate.subject.to_string() == format!("CN={cn}")
                        && c.tbs_certificate.issuer.to_string() == format!("CN={issuer_cn}")
                })
                .unwrap()
        }

        /// `verified_chain` from `signer`, as subject names.
        pub(super) fn walk(&self, signer: &x509_cert::Certificate) -> Vec<String> {
            super::super::verified_chain(&self.sd, signer)
                .iter()
                .map(|t| self.name_of(t))
                .collect()
        }

        pub(super) fn thumbprint(cert: &x509_cert::Certificate) -> String {
            super::super::hex_encode(&Sha256::digest(cert.to_der().unwrap()))
        }

        fn name_of(&self, thumbprint: &str) -> String {
            let cert = self
                .certs()
                .into_iter()
                .find(|c| Self::thumbprint(c) == thumbprint)
                .unwrap();
            cert.tbs_certificate
                .subject
                .to_string()
                .trim_start_matches("CN=")
                .to_string()
        }
    }
}

const BAG_IMPOSTOR_ONLY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/rsa-impostor-only.p7b"
));
const BAG_IMPOSTOR_AND_REAL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/rsa-impostor-and-real.p7b"
));
const BAG_SHA1: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/sha1.p7b"
));
const BAG_ECDSA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/ecdsa.p7b"
));
const BAG_OFFPAIR: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/offpair.p7b"
));
const BAG_DEPTH: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/depth.p7b"
));
const BAG_LOOP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/loop.p7b"
));

/// A CA with the real issuer's exact name but its own key must never be
/// linked. Bag order is DER-sorted on decode, so this is checked both
/// ways: alone, the walk has to try the impostor and reject it; beside the
/// real CA, it has to pick the one whose key actually signed the leaf.
#[test]
fn chain_rejects_an_impostor_with_the_issuers_name() {
    let alone = bags::Bag::load(BAG_IMPOSTOR_ONLY);
    assert_eq!(
        alone.walk(alone.cert("Chain Leaf", "Chain CA")),
        ["Chain Leaf"]
    );

    let both = bags::Bag::load(BAG_IMPOSTOR_AND_REAL);
    let leaf = both.cert("Chain Leaf", "Chain CA");
    assert_eq!(both.walk(leaf), ["Chain Leaf", "Chain CA", "Chain Root"]);
    let chain = super::verified_chain(&both.sd, leaf);
    assert_eq!(
        chain[1],
        bags::Bag::thumbprint(both.cert("Chain CA", "Chain Root"))
    );
    assert!(!chain.contains(&bags::Bag::thumbprint(both.cert("Chain CA", "Chain CA"))));
}

#[test]
fn chain_stops_at_a_self_issued_certificate() {
    let bag = bags::Bag::load(BAG_IMPOSTOR_AND_REAL);
    assert_eq!(
        bag.walk(bag.cert("Chain Root", "Chain Root")),
        ["Chain Root"]
    );
}

#[test]
fn chain_stops_when_the_issuer_is_not_in_the_bag() {
    let bag = bags::Bag::load(BAG_SHA1);
    let other = bags::Bag::load(BAG_ECDSA);
    // An EC leaf walked against a bag that does not hold its issuer.
    let leaf = other.cert("EC Leaf", "EC CA");
    assert_eq!(super::verified_chain(&bag.sd, leaf).len(), 1);
}

/// Legacy SHA-1 links (VC++ 2010-era Microsoft chains) must verify.
#[test]
fn chain_follows_sha1_rsa_links() {
    let bag = bags::Bag::load(BAG_SHA1);
    assert_eq!(
        bag.walk(bag.cert("SHA1 Leaf", "SHA1 Root")),
        ["SHA1 Leaf", "SHA1 Root"]
    );
}

/// P-384 root over a P-256 CA (ecdsa-with-SHA384) over a leaf
/// (ecdsa-with-SHA256): the issuer's curve, not the child's, decides.
#[test]
fn chain_follows_ecdsa_links_across_curves() {
    let bag = bags::Bag::load(BAG_ECDSA);
    assert_eq!(
        bag.walk(bag.cert("EC Leaf", "EC CA")),
        ["EC Leaf", "EC CA", "EC Root"]
    );
}

/// A link the verifier cannot check (P-256 key, SHA-384 signature) ends
/// the walk rather than being assumed good.
#[test]
fn chain_stops_at_an_unverifiable_algorithm() {
    let bag = bags::Bag::load(BAG_OFFPAIR);
    assert_eq!(
        bag.walk(bag.cert("Offpair Leaf", "Offpair CA")),
        ["Offpair Leaf"]
    );
}

#[test]
fn chain_is_capped_at_eight_certificates() {
    let bag = bags::Bag::load(BAG_DEPTH);
    let chain = bag.walk(bag.cert("Depth 9", "Depth 8"));
    assert_eq!(chain.len(), 8);
    assert_eq!(chain.first().unwrap(), "Depth 9");
    assert_eq!(chain.last().unwrap(), "Depth 2");
}

/// Two CAs certifying each other must not make the walk loop.
#[test]
fn chain_terminates_on_cross_signed_cycles() {
    let bag = bags::Bag::load(BAG_LOOP);
    assert_eq!(
        bag.walk(bag.cert("Loop Leaf", "Loop A")),
        ["Loop Leaf", "Loop A", "Loop B"]
    );
}

/// The emitted chain starts with the same thumbprint the signer fields use.
#[test]
fn chain_starts_with_the_signer_thumbprint() {
    let sig = parse(DIGICERT_TENCENT);
    assert_eq!(sig["chain_sha256"][0], sig["thumbprint_sha256"]);
}

/// Every name still lines up after one byte of the leaf's certificate
/// signature changes, but the CA's key no longer verifies it, so the CA
/// must drop out of the chain. This is the forgery the chain exists to
/// stop: a leaf that merely claims a well-known issuer.
#[test]
fn chain_stops_where_a_signature_does_not_verify() {
    use der::Decode;
    let blob = trim_to_der_object(DIGICERT_TENCENT).unwrap();
    let ci = cms::content_info::ContentInfo::from_der(blob).unwrap();
    let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
    let leaf_sig = sd
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .find_map(|entry| match entry {
            cms::cert::CertificateChoices::Certificate(c)
                if c.tbs_certificate.subject != c.tbs_certificate.issuer
                    && c.tbs_certificate.subject.to_string().contains("Tencent") =>
            {
                c.signature.as_bytes().map(<[u8]>::to_vec)
            }
            _ => None,
        })
        .unwrap();
    let at = blob
        .windows(leaf_sig.len())
        .position(|w| w == leaf_sig)
        .unwrap();
    let mut forged = blob.to_vec();
    forged[at + leaf_sig.len() - 1] ^= 0x01;

    let sig = parse(&forged);
    let links = chain(&sig);
    assert_eq!(links.len(), 1, "only the (altered) leaf itself: {links:?}");
    assert!(!links.contains(&DIGICERT_CODE_SIGNING_CA));
    // The signer's own signature over the signed attributes is untouched.
    assert_eq!(sig["verified"], true);
}

#[test]
fn known_digest_oids() {
    let sha256 = ObjectIdentifier::new("2.16.840.1.101.3.4.2.1").unwrap();
    assert_eq!(oid_to_label(&sha256), "sha256");
    let sha1 = ObjectIdentifier::new("1.3.14.3.2.26").unwrap();
    assert_eq!(oid_to_label(&sha1), "sha1");
}

#[test]
fn trim_strips_short_form_trailing_padding() {
    // SEQUENCE of 3 bytes content, then 4 padding bytes.
    let bytes = [0x30, 0x03, b'a', b'b', b'c', 0, 0, 0, 0];
    let out = trim_to_der_object(&bytes).expect("short-form length");
    assert_eq!(out, &[0x30, 0x03, b'a', b'b', b'c']);
}

#[test]
fn trim_strips_long_form_trailing_padding() {
    // SEQUENCE with `0x82` two-byte length = 0x0003 = 3, then pad.
    let bytes = [0x30, 0x82, 0x00, 0x03, b'x', b'y', b'z', 0, 0, 0, 0];
    let out = trim_to_der_object(&bytes).expect("long-form length");
    assert_eq!(out, &[0x30, 0x82, 0x00, 0x03, b'x', b'y', b'z']);
}

#[test]
fn trim_handles_zero_padded_authenticode_shape() {
    // The exact failure mode that broke Microsoft-signed DLLs: the
    // PE certificate-table record's `dwLength` rounded the PKCS#7
    // blob up to an 8-byte boundary, leaving three null padding
    // bytes after the SEQUENCE.
    let header = [0x30, 0x82, 0x00, 0x05];
    let content = [1, 2, 3, 4, 5];
    let mut padded = Vec::new();
    padded.extend_from_slice(&header);
    padded.extend_from_slice(&content);
    padded.extend_from_slice(&[0, 0, 0]); // 3 bytes of pad
    let out = trim_to_der_object(&padded).expect("trimmed");
    assert_eq!(out.len(), header.len() + content.len());
}

#[test]
fn trim_rejects_truncated_length() {
    // Long-form length declares 4 length bytes but only 2 follow.
    let bytes = [0x30, 0x84, 0x00, 0x00];
    assert!(trim_to_der_object(&bytes).is_none());
}

#[test]
fn trim_rejects_oversized_length() {
    // Claims 1000-byte content but only 4 bytes are present.
    let bytes = [0x30, 0x82, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00];
    assert!(trim_to_der_object(&bytes).is_none());
}

/// `is_rsa_oid` must accept every RSA OID Authenticode emitters
/// have been observed to put on PE signatures — the bare
/// `rsaEncryption` plus the hash-specific composites. Unknown
/// OIDs must NOT match, otherwise `verify_signer_signature`
/// would dispatch RSA verification on an ECDSA cert (or worse).
#[test]
fn is_rsa_oid_covers_known_authenticode_oids() {
    // Bare rsaEncryption + every hash-specific composite shipped
    // in Windows Authenticode signatures.
    for oid in [
        "1.2.840.113549.1.1.1",  // rsaEncryption
        "1.2.840.113549.1.1.4",  // md5WithRSA
        "1.2.840.113549.1.1.5",  // sha1WithRSA
        "1.2.840.113549.1.1.11", // sha256WithRSA
        "1.2.840.113549.1.1.12", // sha384WithRSA
        "1.2.840.113549.1.1.13", // sha512WithRSA
    ] {
        assert!(is_rsa_oid(oid), "should classify {oid} as RSA");
    }
    // ECDSA OIDs must NOT match — they go through verify_ecdsa.
    assert!(!is_rsa_oid("1.2.840.10045.4.3.2"));
    // Garbage / Ed25519 / dsa-with-sha256 OIDs are unsupported.
    assert!(!is_rsa_oid("1.3.101.112"));
    assert!(!is_rsa_oid(""));
}

#[test]
fn is_ecdsa_oid_covers_known_authenticode_oids() {
    for oid in [
        "1.2.840.10045.4.1",   // ecdsa-with-SHA1
        "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3", // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4", // ecdsa-with-SHA512
    ] {
        assert!(is_ecdsa_oid(oid), "should classify {oid} as ECDSA");
    }
    // RSA OIDs must NOT match.
    assert!(!is_ecdsa_oid("1.2.840.113549.1.1.11"));
    // Curve OIDs (subject_public_key_info parameters) must NOT
    // be mistaken for signature algorithms.
    assert!(!is_ecdsa_oid("1.2.840.10045.3.1.7")); // P-256
    assert!(!is_ecdsa_oid(""));
}

/// `signature_algorithm_name` returns the canonical RFC label for
/// every signature-algorithm OID we recognise, and the dotted-OID
/// fallback for the long tail. Trait authors match against these
/// strings.
#[test]
fn signature_algorithm_name_maps_known_oids() {
    let oid = ObjectIdentifier::new("1.2.840.113549.1.1.11").unwrap();
    assert_eq!(signature_algorithm_name(&oid), "sha256WithRSAEncryption");
    let oid = ObjectIdentifier::new("1.2.840.10045.4.3.2").unwrap();
    assert_eq!(signature_algorithm_name(&oid), "ecdsa-with-SHA256");
}

/// Unknown / exotic OIDs fall through to the dotted-OID string
/// itself. The legacy `"other"` fallback threw away the only
/// piece of forensically useful information; the dotted form lets
/// an analyst look the algorithm up directly.
#[test]
fn signature_algorithm_name_falls_back_to_dotted_oid() {
    let oid = ObjectIdentifier::new("1.3.6.1.4.1.99999").unwrap();
    assert_eq!(signature_algorithm_name(&oid), "1.3.6.1.4.1.99999");
    // RSASSA-PSS (1.2.840.113549.1.1.10) — not in our friendly
    // table yet but still emitted as a usable identifier.
    let oid = ObjectIdentifier::new("1.2.840.113549.1.1.10").unwrap();
    assert_eq!(signature_algorithm_name(&oid), "1.2.840.113549.1.1.10");
}

/// A short-form TLV: tag, one length byte, contents.
#[test]
fn tlv_short_form_splits_tag_body_and_remainder() {
    let (tag, body, rest) = read_tlv(&[0x04, 0x03, 1, 2, 3, 0xFF]).unwrap();
    assert_eq!(tag, 0x04);
    assert_eq!(body, &[1, 2, 3]);
    assert_eq!(rest, &[0xFF]);
}

/// Long-form lengths are what real certificates use; a token is far larger
/// than 127 bytes, so getting this wrong would fail on every real input.
#[test]
fn tlv_long_form_length_is_decoded() {
    let mut input = vec![0x30, 0x82, 0x01, 0x02];
    input.extend(std::iter::repeat_n(0xAA, 258));
    let (tag, body, rest) = read_tlv(&input).unwrap();
    assert_eq!(tag, 0x30);
    assert_eq!(body.len(), 258);
    assert!(rest.is_empty());
}

/// A length running past the buffer must be refused, not panic — these
/// bytes come from untrusted files.
#[test]
fn tlv_rejects_length_beyond_input() {
    assert!(read_tlv(&[0x04, 0x7F, 1, 2, 3]).is_none());
    assert!(read_tlv(&[0x04]).is_none());
    assert!(read_tlv(&[]).is_none());
}

#[test]
fn generalized_time_converts_to_unix_seconds() {
    let (display, unix) = parse_generalized_time("20230406164252Z").unwrap();
    assert_eq!(display, "2023-04-06 16:42:52 UTC");
    assert_eq!(unix, 1_680_799_372);
    // Fractional seconds are permitted and ignored.
    let (_, frac) = parse_generalized_time("20230406164252.500Z").unwrap();
    assert_eq!(frac, unix);
}

#[test]
fn generalized_time_epoch_and_leap_day() {
    assert_eq!(parse_generalized_time("19700101000000Z").unwrap().1, 0);
    // 2024-02-29 exists; a naive month table would slip a day here.
    assert_eq!(
        parse_generalized_time("20240229000000Z").unwrap().1,
        1_709_164_800
    );
}

#[test]
fn generalized_time_rejects_truncated_input() {
    assert!(parse_generalized_time("2023Z").is_none());
    assert!(parse_generalized_time("20230406164252").is_none());
}

/// genTime sits in the timestamp token, an unsigned attribute anyone can
/// rewrite. Valid UTF-8 with a two-byte char straddling a field edge used
/// to panic slicing the year off at a non-char boundary.
#[test]
fn generalized_time_rejects_multibyte_char_across_field_edge() {
    assert!(parse_generalized_time("200\u{e9}0406164252Z").is_none());
    assert!(parse_generalized_time("2023040616425\u{e9}Z").is_none());
}

/// genTime is the fifth TSTInfo element; the walk must skip exactly the
/// four before it.
#[test]
fn tst_info_walk_reaches_gen_time() {
    let mut body = Vec::new();
    body.extend([0x02, 0x01, 0x01]); // version
    body.extend([0x06, 0x01, 0x2A]); // policy
    body.extend([0x30, 0x02, 0x05, 0x00]); // messageImprint
    body.extend([0x02, 0x01, 0x07]); // serialNumber
    body.extend([0x18, 0x0F]); // genTime
    body.extend(b"20230406164252Z");
    let mut seq = vec![0x30, body.len() as u8];
    seq.extend(&body);

    let (display, unix) = gen_time_from_tst_info(&seq).unwrap();
    assert_eq!(display, "2023-04-06 16:42:52 UTC");
    assert_eq!(unix, 1_680_799_372);
}

/// A TSTInfo that ends before genTime yields nothing rather than reading
/// past the structure.
#[test]
fn tst_info_walk_stops_when_truncated() {
    let body = [0x02, 0x01, 0x01, 0x06, 0x01, 0x2A];
    let mut seq = vec![0x30, body.len() as u8];
    seq.extend(body);
    assert!(gen_time_from_tst_info(&seq).is_none());
}
