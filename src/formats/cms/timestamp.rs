//! Signing times: the signer's `signingTime`, PKCS#9 countersignatures and
//! RFC 3161 timestamp tokens.

use ::cms::content_info::ContentInfo;
use ::cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode, Reader as _};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use super::chain::{cert_bag, find_signer_cert, verified_chain};
use super::verify::{DigestAlg, SignedContent, Verdict, verify_signer};
use super::{time_to_string, time_to_unix, unix_secs};

/// Countersignature attribute values examined per signer.
const MAX_COUNTERSIGNATURES: usize = 4;

/// Who attested a signing time, published as `signing_time_source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TimeSource {
    /// The signer's own signed `signingTime` attribute: the key holder's
    /// word, not an attestation.
    Signer,
    /// A PKCS#9 countersignature that verified over this signature.
    Countersignature,
    UnverifiedCountersignature,
    /// An RFC 3161 timestamp token that verified over this signature.
    Rfc3161,
    UnverifiedRfc3161,
}

impl TimeSource {
    /// Whether a timestamping authority's verified signature attests the
    /// time. Every other time is one the file chose: the signer's own
    /// `signingTime`, or a timestamp that did not check out.
    pub(crate) fn is_attested(self) -> bool {
        matches!(self, Self::Countersignature | Self::Rfc3161)
    }
}

/// A signing time and who attested it.
pub(super) struct SigningTime {
    pub(super) text: String,
    pub(super) unix: i64,
    pub(super) source: TimeSource,
    /// `chain_sha256` of the timestamping authority; empty unless the
    /// timestamp verified.
    pub(super) chain: Vec<String>,
}

impl SigningTime {
    /// A timestamp's time, labelled `verified` or `unverified` by whether its
    /// signature and binding checked out; `chain` is the authority's verified
    /// chain, or `None` when they did not.
    fn timestamp(
        (text, unix): (String, i64),
        (verified, unverified): (TimeSource, TimeSource),
        chain: Option<Vec<String>>,
    ) -> Self {
        let source = if chain.is_some() {
            verified
        } else {
            unverified
        };
        Self {
            text,
            unix,
            source,
            chain: chain.unwrap_or_default(),
        }
    }
}

/// The signing time in precedence order: a verified timestamp, then the
/// signer's own `signingTime` attribute, then an unverified timestamp
/// (labelled as such). The signer's attribute is only the key holder's word:
/// whoever holds a leaked key can date a signature inside its certificate's
/// validity window, so an authority's attested time outranks it.
pub(super) fn signing_time(signer: &SignerInfo, bag: &[&Certificate]) -> Option<SigningTime> {
    let mut unverified = None;
    for found in countersignature_times(signer, bag).chain(rfc3161_times(signer)) {
        if found.source.is_attested() {
            return Some(found);
        }
        unverified.get_or_insert(found);
    }
    extract_signing_time(signer)
        .map(|(text, unix)| SigningTime {
            text,
            unix,
            source: TimeSource::Signer,
            chain: Vec::new(),
        })
        .or(unverified)
}

/// PKCS#9 counterSignature attribute.
pub(super) const COUNTERSIGNATURE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");

/// Signing times from PKCS#9 countersignatures, the older Authenticode
/// timestamp: a SignerInfo whose `messageDigest` covers the outer signer's
/// signature value, carrying an ordinary `signingTime`. The countersigner's
/// certificate sits in the outer SignedData's bag.
///
/// Verified means the countersigner's key signed its attributes and their
/// `messageDigest` equals the hash of the outer signature, i.e. this time
/// was attested over this signature and not lifted from another one.
pub(super) fn countersignature_times<'a>(
    signer: &'a SignerInfo,
    bag: &'a [&'a Certificate],
) -> impl Iterator<Item = SigningTime> + 'a {
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == COUNTERSIGNATURE_OID)
        .flat_map(|attr| attr.values.iter())
        .take(MAX_COUNTERSIGNATURES)
        .filter_map(move |any| {
            let counter: SignerInfo = any.decode_as().ok()?;
            let time = extract_signing_time(&counter)?;
            let content = SignedContent {
                content_type: None,
                bytes: Some(signer.signature.as_bytes()),
            };
            let chain = find_signer_cert(bag, &counter)
                .filter(|cert| verify_signer(&counter, cert, &content) == Verdict::Verified)
                .map(|cert| verified_chain(bag, cert).thumbprints);
            Some(SigningTime::timestamp(
                time,
                (
                    TimeSource::Countersignature,
                    TimeSource::UnverifiedCountersignature,
                ),
                chain,
            ))
        })
}

/// Microsoft's RFC 3161 timestamp-token attribute.
pub(super) const MS_TIMESTAMP_TOKEN_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
/// `id-ct-TSTInfo`, the encapsulated content type of a timestamp token.
const TST_INFO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Signing times from RFC 3161 timestamp tokens.
///
/// Modern Authenticode timestamps with a token rather than a PKCS#9
/// countersignature: the unsigned attribute (OID 1.3.6.1.4.1.311.3.3.1) holds a
/// ContentInfo wrapping SignedData whose encapsulated content is a TSTInfo, and
/// the authority's attested instant is TSTInfo's `genTime`. Microsoft signs
/// its binaries this way, so without it the signing time — and any judgement
/// about whether a signature was made while its certificate was valid — is
/// unavailable for most signed software.
///
/// Verified means the token's own SignerInfo verifies over the TSTInfo (with
/// the content binding [`verify_signer`] checks) and the TSTInfo's
/// `messageImprint` is the hash of the outer signer's signature value — the
/// authority stamped this signature, not some other one. A verified time is
/// read from that same TSTInfo: the byte search [`gen_time_from_token`] does
/// would find a TSTInfo-shaped forgery planted in front of the real one (in an
/// unsigned `digestAlgorithms` parameter, say) and pass its time off under the
/// authority's signature.
fn rfc3161_times(signer: &SignerInfo) -> impl Iterator<Item = SigningTime> + '_ {
    signer
        .unsigned_attrs
        .iter()
        .flat_map(|attrs| attrs.iter())
        .filter(|attr| attr.oid == MS_TIMESTAMP_TOKEN_OID)
        .flat_map(|attr| attr.values.iter())
        .take(MAX_COUNTERSIGNATURES)
        .filter_map(|any| {
            let token_der = any.to_der().ok()?;
            let labels = (TimeSource::Rfc3161, TimeSource::UnverifiedRfc3161);
            Some(
                match verify_token(&token_der, signer.signature.as_bytes()) {
                    Some(token) => SigningTime::timestamp(token.time, labels, Some(token.chain)),
                    None => SigningTime::timestamp(gen_time_from_token(&token_der)?, labels, None),
                },
            )
        })
}

/// A timestamp token that verified: the time its signed TSTInfo attests and
/// the authority's verified chain.
struct VerifiedToken {
    time: (String, i64),
    chain: Vec<String>,
}

/// Verify a timestamp token over `stamped` (the outer signature value).
/// `None` when anything fails, the signed TSTInfo's `genTime` included.
fn verify_token(token_der: &[u8], stamped: &[u8]) -> Option<VerifiedToken> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    let signed_data = decode_signed_data_lenient(&ci.content)?;
    let encap = &signed_data.encap_content_info;
    if encap.econtent_type != TST_INFO_OID {
        return None;
    }
    // The eContent is an OCTET STRING whose value is the TSTInfo DER.
    let tst_info = encap.econtent.as_ref()?.decode_as::<OctetString>().ok()?;
    let tst = TstInfo::decode(tst_info.as_bytes())?;
    if tst.imprint_alg.digest(stamped) != tst.imprint {
        return None;
    }
    let bag = cert_bag(&signed_data);
    let token_signer = signed_data.signer_infos.0.as_slice().first()?;
    let cert = find_signer_cert(&bag, token_signer)?;
    let content = SignedContent {
        content_type: Some(TST_INFO_OID),
        bytes: Some(tst_info.as_bytes()),
    };
    if verify_signer(token_signer, cert, &content) != Verdict::Verified {
        return None;
    }
    Some(VerifiedToken {
        time: tst.gen_time?,
        chain: verified_chain(&bag, cert).thumbprints,
    })
}

/// Decode a SignedData, dropping its `crls [1]` field first if the strict
/// model rejects it. Timestamp tokens carry CRL forms the `cms` crate does
/// not model (`unexpected ASN.1 DER tag: got CONTEXT-SPECIFIC [1]`); no check
/// here reads them, and nothing a signature covers lives there.
pub(super) fn decode_signed_data_lenient(content: &der::Any) -> Option<SignedData> {
    if let Ok(sd) = content.decode_as::<SignedData>() {
        return Some(sd);
    }
    let mut body = Vec::with_capacity(content.value().len());
    let mut reader = der::SliceReader::new(content.value()).ok()?;
    while !reader.is_finished() {
        let element = reader.tlv_bytes().ok()?;
        if element.first() != Some(&0xA1) {
            body.extend_from_slice(element);
        }
    }
    let der = der::asn1::AnyRef::new(der::Tag::Sequence, &body)
        .ok()?
        .to_der()
        .ok()?;
    SignedData::from_der(&der).ok()
}

/// The TSTInfo fields a timestamp is checked and dated by (RFC 3161 §2.4.2):
///
/// ```text
/// TSTInfo ::= SEQUENCE {
///     version INTEGER, policy OBJECT IDENTIFIER,
///     messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier,
///                               hashedMessage OCTET STRING },
///     serialNumber INTEGER, genTime GeneralizedTime,
///     accuracy, ordering, nonce, tsa, extensions -- optional, not read }
/// ```
pub(super) struct TstInfo {
    pub(super) imprint_alg: DigestAlg,
    pub(super) imprint: Vec<u8>,
    /// `None` when `genTime` is not a valid GeneralizedTime.
    pub(super) gen_time: Option<(String, i64)>,
}

impl TstInfo {
    /// Decode the fields up to `genTime`, each checked against its ASN.1
    /// type. `der`'s own `GeneralizedTime` refuses fractional seconds, which
    /// RFC 3161 permits and timestamping authorities emit, so `genTime` is
    /// taken as its raw value and read by [`parse_generalized_time`].
    pub(super) fn decode(tst_der: &[u8]) -> Option<Self> {
        use der::Tagged as _;
        use der::asn1::{AnyRef, IntRef, OctetStringRef};
        let mut reader = der::SliceReader::new(tst_der).ok()?;
        let (alg, imprint, gen_time) = reader
            .sequence(|seq| {
                let _version = u8::decode(seq)?;
                // The policy is not read, only checked to be an OID.
                AnyRef::decode(seq)?
                    .tag()
                    .assert_eq(der::Tag::ObjectIdentifier)?;
                let (alg, imprint) = seq.sequence(|message_imprint| {
                    let alg = message_imprint.sequence(|alg_id| {
                        let oid = ObjectIdentifier::decode(alg_id)?;
                        // Digest parameters are NULL or absent; neither matters.
                        alg_id.read_slice(alg_id.remaining_len())?;
                        Ok(oid)
                    })?;
                    let imprint = OctetStringRef::decode(message_imprint)?;
                    Ok((alg, imprint.as_bytes().to_vec()))
                })?;
                let _serial = IntRef::decode(seq)?;
                let gen_time = AnyRef::decode(seq)?;
                seq.read_slice(seq.remaining_len())?;
                Ok((alg, imprint, gen_time))
            })
            .ok()?;
        let gen_time = (gen_time.tag() == der::Tag::GeneralizedTime)
            .then(|| parse_generalized_time(std::str::from_utf8(gen_time.value()).ok()?))
            .flatten();
        Some(Self {
            imprint_alg: DigestAlg::from_oid(&alg)?,
            imprint,
            gen_time,
        })
    }
}

/// DER encoding of the `id-ct-TSTInfo` OID (1.2.840.113549.1.9.16.1.4), which
/// appears exactly once in a token — as `encapContentInfo.eContentType`.
pub(super) const TST_INFO_OID_DER: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// Locate the TSTInfo inside a timestamp token and read its `genTime`.
///
/// The fallback for a token that does not verify, so its time is reported as
/// unverified: such tokens carry the optional `crls [1]` field or other
/// damage the `cms::SignedData` model rejects. Only one value is wanted, and
/// it sits at a fixed place relative to the `id-ct-TSTInfo` content-type OID,
/// so the search anchors there and reads forward. After the content-type OID
/// comes `eContent [0] EXPLICIT OCTET STRING`, whose bytes are the TSTInfo.
/// Some producers wrap the TSTInfo in a further OCTET STRING, so one extra
/// layer is unwrapped when present.
pub(super) fn gen_time_from_token(token_der: &[u8]) -> Option<(String, i64)> {
    let at = memchr::memmem::find(token_der, TST_INFO_OID_DER)?;
    let after_oid = token_der.get(at + TST_INFO_OID_DER.len()..)?;

    let (tag, explicit) = first_element(after_oid)?;
    // [0] EXPLICIT, constructed.
    if tag != 0xA0 {
        return None;
    }
    let (tag, mut body) = first_element(explicit)?;
    if tag != 0x04 {
        return None;
    }
    // Unwrap a redundant OCTET STRING layer if one is present.
    if let Some((0x04, inner)) = first_element(body) {
        body = inner;
    }
    TstInfo::decode(body)?.gen_time
}

/// The tag byte and contents of the DER element opening `bytes`; whatever
/// follows it is ignored.
fn first_element(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let mut reader = der::SliceReader::new(bytes).ok()?;
    let element = der::asn1::AnyRef::decode(&mut reader).ok()?;
    Some((der::Tagged::tag(&element).into(), element.value()))
}

/// Parse `YYYYMMDDHHMMSS[.fff]Z` into a display string and Unix seconds. The
/// calendar fields are checked by [`der::DateTime::new`], so a thirteenth
/// month or a 30 February is refused rather than rolled into another date.
pub(super) fn parse_generalized_time(text: &str) -> Option<(String, i64)> {
    let digits = text.get(..text.find(['.', 'Z'])?)?;
    if digits.len() < 14 {
        return None;
    }
    // `str::get`: the text is only known to be UTF-8, so a multi-byte char
    // can put a field edge off a char boundary.
    let field = |a: usize, b: usize| digits.get(a..b)?.parse::<u8>().ok();
    let year = digits.get(0..4)?.parse::<u16>().ok()?;
    let dt = der::DateTime::new(
        year,
        field(4, 6)?,
        field(6, 8)?,
        field(8, 10)?,
        field(10, 12)?,
        field(12, 14)?,
    )
    .ok()?;
    Some((dt.to_string(), unix_secs(dt.unix_duration())))
}

/// PKCS#9 signing-time OID.
const SIGNING_TIME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// Recover the signing time from the SignerInfo signed-attributes
/// bag. Returns the ISO-8601 string alongside its Unix-epoch seconds
/// so consumers don't have to reparse the string for arithmetic.
fn extract_signing_time(signer: &SignerInfo) -> Option<(String, i64)> {
    use x509_cert::time::Time;
    let attrs = signer.signed_attrs.as_ref()?;
    let attr = attrs.iter().find(|attr| attr.oid == SIGNING_TIME_OID)?;
    // CHOICE { UTCTime, GeneralizedTime }.
    let any = attr.values.as_slice().first()?;
    let time = any
        .decode_as()
        .map(Time::UtcTime)
        .or_else(|_| any.decode_as().map(Time::GeneralTime))
        .ok()?;
    Some((time_to_string(time), time_to_unix(time)))
}
