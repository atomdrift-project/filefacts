use super::{
    Budget, DigestAlg, Scheme, gen_time_from_tst_info, oid_to_label, parse_generalized_time,
    read_tlv, signature_algorithm, signature_algorithm_name, trim_to_der_object,
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
    super::parse_pkcs7(trim_to_der_object(blob).unwrap(), None, &mut Budget::new()).unwrap()
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
            super::super::verified_chain(&self.certs(), signer)
                .thumbprints
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
    let chain = super::verified_chain(&both.certs(), leaf).thumbprints;
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
    assert_eq!(
        super::verified_chain(&bag.certs(), leaf).thumbprints.len(),
        1
    );
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

fn scheme(oid: &str) -> Option<Scheme> {
    signature_algorithm(&ObjectIdentifier::new(oid).unwrap()).map(|alg| alg.scheme)
}

/// Every RSA OID Authenticode emitters have been observed to put on PE
/// signatures — the bare `rsaEncryption` plus the hash-specific
/// composites — must dispatch to RSA. Unknown OIDs must not, otherwise
/// verification would run RSA on an ECDSA cert (or worse).
#[test]
fn rsa_oids_cover_known_authenticode_oids() {
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
        assert_eq!(scheme(oid), Some(Scheme::Rsa), "{oid} should be RSA");
    }
    // ECDSA OIDs go through verify_ecdsa.
    assert_eq!(scheme("1.2.840.10045.4.3.2"), Some(Scheme::Ecdsa));
    // Ed25519 / RSASSA-PSS are unsupported.
    assert_eq!(scheme("1.3.101.112"), None);
    assert_eq!(scheme("1.2.840.113549.1.1.10"), None);
}

#[test]
fn ecdsa_oids_cover_known_authenticode_oids() {
    for oid in [
        "1.2.840.10045.4.1",   // ecdsa-with-SHA1
        "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3", // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4", // ecdsa-with-SHA512
    ] {
        assert_eq!(scheme(oid), Some(Scheme::Ecdsa), "{oid} should be ECDSA");
    }
    // Curve OIDs (subject_public_key_info parameters) must not be
    // mistaken for signature algorithms.
    assert_eq!(scheme("1.2.840.10045.3.1.7"), None); // P-256
}

/// Hash-specific signature OIDs fix the digest a certificate signature is
/// checked with; generic `rsaEncryption` leaves it to the SignerInfo.
#[test]
fn signature_oids_fix_their_digest() {
    let digest = |oid: &str| {
        signature_algorithm(&ObjectIdentifier::new(oid).unwrap()).and_then(|alg| alg.digest)
    };
    assert_eq!(digest("1.2.840.113549.1.1.11"), Some(DigestAlg::Sha256));
    assert_eq!(digest("1.2.840.10045.4.3.3"), Some(DigestAlg::Sha384));
    assert_eq!(digest("1.2.840.113549.1.1.1"), None);
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

// ---------------------------------------------------------------------
// Content binding (messageDigest / contentType).
// ---------------------------------------------------------------------

fn signed_data(der: &[u8]) -> cms::signed_data::SignedData {
    use der::Decode;
    cms::content_info::ContentInfo::from_der(der)
        .unwrap()
        .content
        .decode_as()
        .unwrap()
}

/// Flip the last byte of the first occurrence of `needle` in `blob`.
fn flip(blob: &[u8], needle: &[u8]) -> Vec<u8> {
    let at = blob
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present");
    let mut out = blob.to_vec();
    out[at + needle.len() - 1] ^= 0x01;
    out
}

/// The bytes of a signature's `signature_digest`.
fn claimed_digest(sig: &serde_json::Value) -> Vec<u8> {
    let text = sig["signature_digest"].as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The real Authenticode blob verifies, and its `messageDigest` binds the
/// SpcIndirectDataContent it carries.
#[test]
fn genuine_signature_binds_its_content() {
    let sig = parse(DIGICERT_TENCENT);
    assert_eq!(sig["verified"], true);
    assert!(sig.get("verification_failure").is_none());
}

/// The graft: a genuine SignerInfo and certificate bag around content of
/// the attacker's choosing (here, the same structure claiming a different
/// Authentihash). The signer's signature over its attributes still
/// verifies, because nothing in them changed — only the binding catches it.
#[test]
fn grafted_signer_info_does_not_verify_new_content() {
    let genuine = parse(DIGICERT_TENCENT);
    let sig = parse(&flip(DIGICERT_TENCENT, &claimed_digest(&genuine)));
    assert_ne!(sig["signature_digest"], genuine["signature_digest"]);
    assert_eq!(sig["verified"], false);
    assert_eq!(sig["verification_failure"], "message_digest_mismatch");
}

/// A grafted signature must not read as intact once the integrity summary
/// runs, even when the forged Authentihash matches the file.
#[test]
fn grafted_signature_is_not_intact() {
    use serde_json::json;
    let genuine = parse(DIGICERT_TENCENT);
    let forged = parse(&flip(DIGICERT_TENCENT, &claimed_digest(&genuine)));
    let mut values = crate::output::Values::new();
    values.insert(
        "pe.image_hash",
        json!({"sha256": forged["signature_digest"].clone()}),
    );
    values.insert("pe.signatures", json!([forged]));
    let mut metrics = crate::output::Metrics::new();
    crate::formats::pe_signature_trust::derive(&mut values, &mut metrics, 0);
    assert_eq!(
        values
            .get("pe.signature_integrity")
            .and_then(|v| v.as_str()),
        Some("invalid")
    );
}

fn attr(oid: ObjectIdentifier, values: Vec<der::Any>) -> x509_cert::attr::Attribute {
    x509_cert::attr::Attribute {
        oid,
        values: der::asn1::SetOfVec::try_from(values).unwrap(),
    }
}

fn octets(bytes: &[u8]) -> der::Any {
    der::Any::encode_from(&der::asn1::OctetString::new(bytes).unwrap()).unwrap()
}

/// Each way the binding can be missing or ambiguous is its own failure.
#[test]
fn binding_requires_exactly_one_matching_digest_and_content_type() {
    use super::{CONTENT_TYPE_OID, Failure, MESSAGE_DIGEST_OID, check_binding};
    let content = b"signed content";
    let data_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    let other_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    let content_type = |oid| attr(CONTENT_TYPE_OID, vec![der::Any::encode_from(&oid).unwrap()]);
    let digest_of = |bytes: &[u8]| octets(&DigestAlg::Sha256.digest(bytes));
    let good_digest = || attr(MESSAGE_DIGEST_OID, vec![digest_of(content)]);
    let check = |attrs: &[x509_cert::attr::Attribute]| {
        check_binding(attrs, DigestAlg::Sha256, Some(data_oid), content)
    };

    assert_eq!(check(&[content_type(data_oid), good_digest()]), Ok(()));
    assert_eq!(
        check(&[content_type(data_oid)]),
        Err(Failure::MessageDigestMissing)
    );
    assert_eq!(
        check(&[
            content_type(data_oid),
            attr(MESSAGE_DIGEST_OID, vec![digest_of(b"other content")])
        ]),
        Err(Failure::MessageDigestMismatch)
    );
    assert_eq!(
        check(&[content_type(data_oid), good_digest(), good_digest()]),
        Err(Failure::MessageDigestMalformed)
    );
    assert_eq!(
        check(&[
            content_type(data_oid),
            attr(
                MESSAGE_DIGEST_OID,
                vec![digest_of(content), digest_of(b"other content")]
            )
        ]),
        Err(Failure::MessageDigestMalformed)
    );
    assert_eq!(
        check(&[content_type(other_oid), good_digest()]),
        Err(Failure::ContentTypeMismatch)
    );
    assert_eq!(check(&[good_digest()]), Err(Failure::ContentTypeMismatch));
    // A countersignature names no content type and needs none.
    assert_eq!(
        check_binding(&[good_digest()], DigestAlg::Sha256, None, content),
        Ok(())
    );
}

// ---------------------------------------------------------------------
// Timestamps.
// ---------------------------------------------------------------------

/// The Tencent blob's RFC 3161 token verifies over this signature, so its
/// time is attested and the authority's chain is reported for pinning.
#[test]
fn rfc3161_token_verifies() {
    let sig = parse(DIGICERT_TENCENT);
    assert_eq!(sig["signing_time_source"], "rfc3161");
    assert!(!sig["timestamp_chain_sha256"].as_array().unwrap().is_empty());
}

/// A token stamped over some other signature — here, its imprint no longer
/// matches — keeps its time but loses the attestation.
#[test]
fn rfc3161_token_over_another_signature_is_unverified() {
    use sha2::{Digest, Sha256};
    let blob = trim_to_der_object(DIGICERT_TENCENT).unwrap();
    let outer = signed_data(blob);
    let imprint = Sha256::digest(outer.signer_infos.0.as_slice()[0].signature.as_bytes());
    let sig = parse(&flip(DIGICERT_TENCENT, &imprint));
    assert_eq!(sig["signing_time_source"], "unverified_rfc3161");
    assert_eq!(sig["signing_time"], parse(DIGICERT_TENCENT)["signing_time"]);
    assert!(sig.get("timestamp_chain_sha256").is_none());
    // The signature itself is untouched.
    assert_eq!(sig["verified"], true);
}

const COUNTERSIG_OUTER: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/countersig-outer.der"
));
const COUNTERSIG_COUNTER: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/countersig-counter.der"
));

/// `generate.sh` signs content, then signs that signature's value as
/// detached content with a second key. Grafting the second SignerInfo (and
/// its certificate) onto the first as a PKCS#9 counterSignature gives the
/// legacy Authenticode timestamp shape. `tamper` alters the
/// countersignature's signature value before grafting.
fn countersigned(tamper: bool) -> cms::signed_data::SignedData {
    use cms::signed_data::{CertificateSet, SignerInfos};
    let mut outer = signed_data(COUNTERSIG_OUTER);
    let counter_sd = signed_data(COUNTERSIG_COUNTER);
    let mut counter = counter_sd.signer_infos.0.as_slice()[0].clone();
    if tamper {
        let mut bytes = counter.signature.as_bytes().to_vec();
        bytes[0] ^= 0x01;
        counter.signature = der::asn1::OctetString::new(bytes).unwrap();
    }
    let mut signers = outer.signer_infos.0.into_vec();
    signers[0].unsigned_attrs = Some(
        der::asn1::SetOfVec::try_from(vec![attr(
            super::COUNTERSIGNATURE_OID,
            vec![der::Any::encode_from(&counter).unwrap()],
        )])
        .unwrap(),
    );
    outer.signer_infos = SignerInfos(der::asn1::SetOfVec::try_from(signers).unwrap());
    let mut certs = outer.certificates.take().unwrap().0.into_vec();
    certs.extend(counter_sd.certificates.unwrap().0.into_vec());
    outer.certificates = Some(CertificateSet(
        der::asn1::SetOfVec::try_from(certs).unwrap(),
    ));
    outer
}

fn countersignature_sources(sd: &cms::signed_data::SignedData) -> Vec<(&'static str, bool)> {
    let bag = super::cert_bag(sd);
    super::countersignature_times(&sd.signer_infos.0.as_slice()[0], &bag)
        .map(|t| (t.source, t.chain.is_empty()))
        .collect()
}

#[test]
fn countersignature_over_this_signature_is_attested() {
    let sd = countersigned(false);
    assert_eq!(countersignature_sources(&sd), [("countersignature", false)]);
}

#[test]
fn countersignature_that_does_not_verify_is_labelled_unverified() {
    let sd = countersigned(true);
    assert_eq!(
        countersignature_sources(&sd),
        [("unverified_countersignature", true)]
    );
}

// ---------------------------------------------------------------------
// Chain constraints and anchors.
// ---------------------------------------------------------------------

const BAG_NOCA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/noca.p7b"
));
const BAG_KEYUSAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/keyusage.p7b"
));
const BAG_PATHLEN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/pathlen.p7b"
));

/// An issuer whose own certificate says `CA:FALSE` is a leaf: its key
/// verifying the child proves nothing about the child.
#[test]
fn chain_stops_at_an_issuer_that_is_not_a_ca() {
    let bag = bags::Bag::load(BAG_NOCA);
    assert_eq!(bag.walk(bag.cert("NC Leaf", "NC Issuer")), ["NC Leaf"]);
}

#[test]
fn chain_stops_at_an_issuer_without_key_cert_sign() {
    let bag = bags::Bag::load(BAG_KEYUSAGE);
    assert_eq!(bag.walk(bag.cert("KU Leaf", "KU Issuer")), ["KU Leaf"]);
}

/// CA0 allows no intermediates below it; CA1 is one, so CA0 cannot close
/// the path even though its key signed CA1.
#[test]
fn chain_stops_where_a_path_length_is_exceeded() {
    let bag = bags::Bag::load(BAG_PATHLEN);
    assert_eq!(
        bag.walk(bag.cert("PL Leaf", "PL CA1")),
        ["PL Leaf", "PL CA1"]
    );
    // Walked from CA1, nothing sits between CA0 and the signer.
    assert_eq!(
        bag.walk(bag.cert("PL CA1", "PL CA0")),
        ["PL CA1", "PL CA0", "PL Root"]
    );
}

/// A chain closes at a pinned root, whether the bag carries the root or
/// only certificates below it, and names that root's vendor.
#[test]
fn chain_anchors_at_a_pinned_root() {
    let bag = bags::Bag::load(BAG_ECDSA);
    let root = bag.cert("EC Root", "EC Root").clone();
    let pinned = [super::PinnedRoot {
        vendor: super::Vendor::Apple,
        thumbprint: bags::Bag::thumbprint(&root),
        cert: root,
    }];
    let leaf = bag.cert("EC Leaf", "EC CA");
    let without_root: Vec<_> = bag
        .certs()
        .into_iter()
        .filter(|c| c.tbs_certificate.subject != c.tbs_certificate.issuer)
        .collect();
    for certs in [bag.certs(), without_root] {
        let chain = super::walk_chain(&certs, leaf, &pinned);
        assert_eq!(chain.anchor, Some(super::Vendor::Apple));
        assert_eq!(chain.thumbprints.len(), 3);
        assert_eq!(chain.thumbprints[2], pinned[0].thumbprint);
    }
    // Unpinned, the same chain names no anchor.
    assert_eq!(super::walk_chain(&bag.certs(), leaf, &[]).anchor, None);
}

/// A real SHA-1-era Microsoft signature (mfc100.dll 10.00.30319.01): the
/// leaf under "Microsoft Code Signing PCA", which the 1997 "Microsoft Root
/// Authority" issued. The root is not in the bag.
const MICROSOFT_1997: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/authenticode-microsoft-root-authority-1997.p7b"
));
const MICROSOFT_ROOT_AUTHORITY_1997: &str =
    "f38406e540d7a9d90cb4a9479299640ffb6df9e224ecc7a01c0d9558d8dad77d";

/// The 1997 root has no extensions at all, so no BasicConstraints. Pinned,
/// it still closes the chain, and the countersignature's chain, as an anchor.
#[test]
fn sha1_era_microsoft_chains_anchor_at_the_1997_root() {
    let sig = parse(MICROSOFT_1997);
    assert_eq!(sig["verified"], true);
    assert_eq!(sig["chain_anchor"], "microsoft");
    let chain = chain(&sig);
    assert_eq!(chain.len(), 3);
    assert_eq!(chain.last(), Some(&MICROSOFT_ROOT_AUTHORITY_1997));
    let timestamp_chain: Vec<_> = sig["timestamp_chain_sha256"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(timestamp_chain.last(), Some(&MICROSOFT_ROOT_AUTHORITY_1997));
}

/// Only a pinned anchor is exempt from the issuing constraints: the same
/// extension-less root carried in the bag, unpinned, cannot issue.
#[test]
fn an_unpinned_certificate_without_basic_constraints_cannot_issue() {
    use der::Decode;
    let root = super::PINNED_ROOTS
        .iter()
        .find(|r| r.thumbprint == MICROSOFT_ROOT_AUTHORITY_1997)
        .map(|r| r.cert.clone())
        .unwrap();
    let blob = trim_to_der_object(MICROSOFT_1997).unwrap();
    let content = cms::content_info::ContentInfo::from_der(blob).unwrap();
    let signed: cms::signed_data::SignedData = content.content.decode_as().unwrap();
    let mut certs: Vec<x509_cert::Certificate> = signed
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    let leaf = certs
        .iter()
        .find(|c| {
            c.tbs_certificate
                .subject
                .to_string()
                .starts_with("CN=Microsoft Corporation,OU=MOPR")
        })
        .cloned()
        .unwrap();
    certs.push(root);
    let bag: Vec<_> = certs.iter().collect();
    let chain = super::walk_chain(&bag, &leaf, &[]);
    assert_eq!(chain.anchor, None);
    assert_eq!(chain.thumbprints.len(), 2, "stops at the PCA");
}

/// The roots shipped in the binary parse, and are the certificates their
/// vendors publish (SHA-256 thumbprints as Microsoft and Apple list them).
#[test]
fn pinned_roots_are_the_published_certificates() {
    use super::Vendor::{Apple, Microsoft};
    let thumbprints: Vec<_> = super::PINNED_ROOTS
        .iter()
        .map(|r| (r.vendor, r.thumbprint.as_str()))
        .collect();
    assert_eq!(
        thumbprints,
        [
            (
                Microsoft,
                "f38406e540d7a9d90cb4a9479299640ffb6df9e224ecc7a01c0d9558d8dad77d"
            ),
            (
                Microsoft,
                "885de64c340e3ea70658f01e1145f957fcda27aabeea1ab9faa9fdb0102d4077"
            ),
            (
                Microsoft,
                "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
            ),
            (
                Microsoft,
                "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61"
            ),
            (
                Apple,
                "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
            ),
            (
                Apple,
                "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
            ),
        ]
    );
}

// ---------------------------------------------------------------------
// Nested signatures.
// ---------------------------------------------------------------------

/// `blob` with `extra` added to its signer's unsigned attributes, which the
/// signature does not cover, so it still verifies.
fn with_unsigned(blob: &[u8], extra: x509_cert::attr::Attribute) -> Vec<u8> {
    use cms::signed_data::SignerInfos;
    use der::{Decode, Encode};
    let content_type = cms::content_info::ContentInfo::from_der(blob)
        .unwrap()
        .content_type;
    let mut sd = signed_data(blob);
    let mut signers = sd.signer_infos.0.into_vec();
    let mut attrs = signers[0].unsigned_attrs.take().unwrap().into_vec();
    attrs.push(extra);
    signers[0].unsigned_attrs = Some(der::asn1::SetOfVec::try_from(attrs).unwrap());
    sd.signer_infos = SignerInfos(der::asn1::SetOfVec::try_from(signers).unwrap());
    cms::content_info::ContentInfo {
        content_type,
        content: der::Any::encode_from(&sd).unwrap(),
    }
    .to_der()
    .unwrap()
}

/// The Tencent blob nested `levels` deep inside itself, with `width`
/// values in the nested-signature attribute at each level. A SET OF
/// rejects duplicates, so each copy carries a distinct unsigned marker.
fn nested(levels: usize, width: usize) -> Vec<u8> {
    use der::Decode;
    let base = trim_to_der_object(DIGICERT_TENCENT).unwrap().to_vec();
    let marker = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");
    let mut blob = base.clone();
    for _ in 0..levels {
        let copies = (0..width)
            .map(|i| {
                let tag = der::Any::encode_from(&(i as u32)).unwrap();
                der::Any::from_der(&with_unsigned(&blob, attr(marker, vec![tag]))).unwrap()
            })
            .collect();
        blob = with_unsigned(&base, attr(super::MS_NESTED_SIGNATURE_OID, copies));
    }
    blob
}

fn nesting_depth(sig: &serde_json::Value) -> usize {
    sig.get("nested")
        .and_then(|n| n.as_array())
        .and_then(|n| n.first())
        .map_or(0, |n| 1 + nesting_depth(n))
}

/// Every value of the nested-signature attribute is read, not just the
/// first: a triple-signed binary carries two.
#[test]
fn every_nested_signature_value_is_read() {
    let sig = parse(&nested(1, 2));
    let nested = sig["nested"].as_array().unwrap();
    assert_eq!(nested.len(), 2);
    assert!(nested.iter().all(|n| n["verified"] == true));
}

/// Nesting is followed to a fixed depth, so a blob of signatures inside
/// signatures cannot recurse without bound.
#[test]
fn nested_signatures_stop_at_the_depth_cap() {
    let sig = parse(&nested(6, 1));
    assert_eq!(nesting_depth(&sig), usize::from(super::MAX_NESTING) - 1);
}

/// The signature budget is shared across levels and siblings.
#[test]
fn nested_signatures_share_one_budget() {
    fn count(sig: &serde_json::Value) -> usize {
        1 + sig
            .get("nested")
            .and_then(|n| n.as_array())
            .map_or(0, |n| n.iter().map(count).sum())
    }
    let sig = parse(&nested(2, 6));
    assert_eq!(count(&sig), usize::from(super::MAX_SIGNATURES));
}

// ---------------------------------------------------------------------
// BER (Mach-O) signatures.
// ---------------------------------------------------------------------

const BER_DETACHED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/ber-detached.der"
));
const BER_CONTENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/ber-content.bin"
));

/// A detached BER signature decodes after normalization and verifies
/// against the content it covers — and only that content.
#[test]
fn detached_ber_signature_verifies_against_its_content() {
    use der::Decode;
    assert!(cms::content_info::ContentInfo::from_der(BER_DETACHED).is_err());
    let sig = super::parse_detached_cms_blob(BER_DETACHED, BER_CONTENT).unwrap();
    assert_eq!(sig["verified"], true);

    let mut other = BER_CONTENT.to_vec();
    *other.last_mut().unwrap() ^= 0x01;
    let sig = super::parse_detached_cms_blob(BER_DETACHED, &other).unwrap();
    assert_eq!(sig["verified"], false);
    assert_eq!(sig["verification_failure"], "message_digest_mismatch");

    // With nothing to bind it to, a detached signature proves nothing.
    let sig = super::parse_cms_blob(BER_DETACHED).unwrap();
    assert_eq!(sig["verified"], serde_json::Value::Null);
}

// ---------------------------------------------------------------------
// Grafted content and planted timestamps.
// ---------------------------------------------------------------------

/// `blob` as the one record of a PE certificate table.
fn win_certificate(blob: &[u8]) -> Vec<u8> {
    let length = u32::try_from(blob.len() + 8).unwrap();
    let mut table = length.to_le_bytes().to_vec();
    table.extend(0x0200_u16.to_le_bytes());
    table.extend(0x0002_u16.to_le_bytes());
    table.extend(blob);
    table.resize(table.len().next_multiple_of(8), 0);
    table
}

/// A genuine signature over something other than an `SpcIndirectDataContent`
/// (a vendor-signed catalog, say) verifies as CMS, but lifted into a PE's
/// certificate table it names no image digest and so authenticates nothing
/// about that PE — at the top level or nested.
#[test]
fn pe_signature_without_an_image_digest_does_not_verify() {
    let sig = super::parse_cms_blob(COUNTERSIG_OUTER).unwrap();
    assert_eq!(sig["verified"], true, "the graft is a genuine signature");
    assert!(sig.get("signature_digest").is_none());

    let mut values = crate::output::Values::new();
    super::parse(&win_certificate(COUNTERSIG_OUTER), &mut values);
    let sig = values.get("pe.signatures[0]").unwrap();
    assert_eq!(sig["verified"], false);
    assert_eq!(sig["verification_failure"], "image_digest_missing");

    use der::Decode;
    let base = trim_to_der_object(DIGICERT_TENCENT).unwrap();
    let carrier = with_unsigned(
        base,
        attr(
            super::MS_NESTED_SIGNATURE_OID,
            vec![der::Any::from_der(COUNTERSIG_OUTER).unwrap()],
        ),
    );
    let mut values = crate::output::Values::new();
    super::parse(&win_certificate(&carrier), &mut values);
    assert_eq!(values.get("pe.signatures[0].verified"), Some(&true.into()));
    let nested = values.get("pe.signatures[0].nested[0]").unwrap();
    assert_eq!(nested["verified"], false);
    assert_eq!(nested["verification_failure"], "image_digest_missing");
}

/// A TSTInfo-shaped forgery planted in a timestamp token ahead of the real
/// TSTInfo — here as the parameters of an unsigned `digestAlgorithms` entry —
/// must not borrow the authority's signature for its time. The verified time
/// is the one the authority signed.
#[test]
fn rfc3161_time_comes_from_the_signed_tst_info() {
    use super::{
        ContentInfo, MS_TIMESTAMP_TOKEN_OID, TST_INFO_OID_DER, cert_bag,
        decode_signed_data_lenient, gen_time_from_token, signing_time,
    };
    use der::{Decode, Encode};

    let outer = signed_data(trim_to_der_object(DIGICERT_TENCENT).unwrap());
    let bag = cert_bag(&outer);
    let mut signer = outer.signer_infos.0.as_slice()[0].clone();
    let genuine = signing_time(&signer, &bag).unwrap();
    assert_eq!(genuine.source, "rfc3161");

    // TSTInfo { version, policy, messageImprint, serialNumber, genTime }
    // claiming 2000-01-01, wrapped the way gen_time_from_token looks for it:
    // id-ct-TSTInfo, [0] { OCTET STRING { TSTInfo } }.
    let mut tst = vec![0x30, 0x1D, 0x02, 0x01, 0x01, 0x06, 0x02, 0x2A, 0x03];
    tst.extend([0x30, 0x00, 0x02, 0x01, 0x01, 0x18, 0x0F]);
    tst.extend(b"20000101000000Z");
    let mut octets = vec![0x04, 0x1F];
    octets.extend(&tst);
    let mut explicit = vec![0xA0, 0x21];
    explicit.extend(&octets);
    let mut bait = TST_INFO_OID_DER.to_vec();
    bait.extend(&explicit);
    let mut params = vec![0x30, u8::try_from(bait.len()).unwrap()];
    params.extend(&bait);

    let mut attrs = signer.unsigned_attrs.take().unwrap().into_vec();
    let mut planted = Vec::new();
    for attr in attrs.iter_mut().filter(|a| a.oid == MS_TIMESTAMP_TOKEN_OID) {
        let tokens: Vec<der::Any> = attr
            .values
            .iter()
            .map(|any| {
                let ci = ContentInfo::from_der(&any.to_der().unwrap()).unwrap();
                let mut sd = decode_signed_data_lenient(&ci.content).unwrap();
                let mut algs = sd.digest_algorithms.into_vec();
                algs[0].parameters = Some(der::Any::from_der(&params).unwrap());
                sd.digest_algorithms = der::asn1::SetOfVec::try_from(algs).unwrap();
                let token = ContentInfo {
                    content_type: ci.content_type,
                    content: der::Any::encode_from(&sd).unwrap(),
                }
                .to_der()
                .unwrap();
                planted.push(token.clone());
                der::Any::from_der(&token).unwrap()
            })
            .collect();
        attr.values = der::asn1::SetOfVec::try_from(tokens).unwrap();
    }
    signer.unsigned_attrs = Some(der::asn1::SetOfVec::try_from(attrs).unwrap());

    // The bait is what a byte search for the TSTInfo finds first.
    assert_eq!(
        gen_time_from_token(&planted[0]).map(|(_, unix)| unix),
        Some(946_684_800)
    );
    let time = signing_time(&signer, &bag).unwrap();
    assert_eq!(time.source, "rfc3161", "the token itself still verifies");
    assert_eq!(time.unix, genuine.unix);
    assert_eq!(time.text, genuine.text);
}

/// Bytes stretched into the certificate table past a signature — inside its
/// WIN_CERTIFICATE or after the last one — are covered by neither the image
/// hash nor the signature, and nothing else in the output would show them.
#[test]
fn unsigned_bytes_in_the_certificate_table_are_counted() {
    let blob = trim_to_der_object(DIGICERT_TENCENT).unwrap();
    let unsigned = |table: &[u8]| {
        let mut values = crate::output::Values::new();
        super::parse(table, &mut values);
        assert_eq!(values.get("pe.signatures[0].verified"), Some(&true.into()));
        values
            .get("pe.signatures[0].unsigned_trailing_bytes")
            .and_then(serde_json::Value::as_u64)
    };
    // Alignment padding is the signature's own.
    assert_eq!(unsigned(&win_certificate(blob)), None);

    // A payload inside the record, dwLength stretched over it.
    let mut stretched = blob.to_vec();
    stretched.resize(stretched.len().next_multiple_of(8) + 64, 0x90);
    let mut table = win_certificate(&stretched);
    assert_eq!(unsigned(&table), Some(64));

    // And another after the last record, the directory stretched over it.
    table.extend([0xCC; 16]);
    assert_eq!(unsigned(&table), Some(80));
}

/// Each same-named candidate issuer costs a signature check, so a walk tries
/// a bounded number of them: decoys past the budget hide the real issuer
/// rather than buying the attacker unbounded public-key work.
#[test]
fn chain_walk_tries_a_bounded_number_of_issuers() {
    let bag = bags::Bag::load(BAG_IMPOSTOR_AND_REAL);
    let leaf = bag.cert("Chain Leaf", "Chain CA");
    let impostor = bag.cert("Chain CA", "Chain CA");
    let real = [
        bag.cert("Chain CA", "Chain Root"),
        bag.cert("Chain Root", "Chain Root"),
    ];
    let walk = |decoys: usize| {
        let mut certs = vec![impostor; decoys];
        certs.extend(real);
        super::walk_chain(&certs, leaf, &[]).thumbprints.len()
    };
    // The budget covers the whole walk: the CA and the root take one try
    // each after the decoys.
    assert_eq!(walk(super::MAX_LINK_ATTEMPTS - 2), 3);
    assert_eq!(walk(super::MAX_LINK_ATTEMPTS - 1), 2);
    assert_eq!(walk(super::MAX_LINK_ATTEMPTS), 1);
}
