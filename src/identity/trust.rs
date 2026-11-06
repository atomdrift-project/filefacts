//! Trust policy: what a signature's certificate says about its signer,
//! and how far cryptography backs it.

use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::formats::cms::{Signature, Vendor};
use crate::output::{Signer, Trust};

/// A published signature value, read through the type that wrote it.
pub(super) fn signature(value: &JsonValue) -> Option<Signature> {
    Signature::deserialize(value)
        .inspect_err(|e| {
            tracing::debug!(
                target: "filefacts::identity",
                stage = "signature",
                error = %e,
                "published signature does not decode"
            );
        })
        .ok()
}

/// Resolved fields from a signature.
pub(super) struct CertInfo {
    cn: Option<String>,
    /// The subject's organization (`O`).
    pub(super) o: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    self_issued: bool,
    /// An issuer's key verifiably signed the signer's certificate: the
    /// verified chain (`chain_sha256`) reaches past the leaf.
    vouched: bool,
    /// The thumbprint of that issuer, when `vouched`.
    issuer_thumbprint: Option<String>,
    /// The signature verified cryptographically.
    pub(super) verified: bool,
    /// The leaf's Extended Key Usage names `codeSigning`.
    code_signing: bool,
    /// The platform root the verified chain ends at (`chain_anchor`).
    anchor: Option<Vendor>,
    signed_at: Option<String>,
}

impl CertInfo {
    /// `None` for a signature whose signer certificate was not found.
    pub(super) fn from_signature(sig: &Signature) -> Option<Self> {
        if sig.subject.is_none() && sig.issuer.is_none() {
            return None;
        }
        let subject = sig.subject.clone();
        Some(Self {
            cn: subject.as_deref().and_then(|d| dn_attr(d, "CN")),
            o: subject.as_deref().and_then(|d| dn_attr(d, "O")),
            self_issued: sig.self_issued || (subject.is_some() && subject == sig.issuer),
            vouched: sig
                .chain_sha256
                .as_ref()
                .is_some_and(|chain| chain.len() > 1),
            issuer_thumbprint: sig
                .chain_sha256
                .as_ref()
                .and_then(|chain| chain.get(1).cloned()),
            subject,
            issuer: sig.issuer.clone(),
            verified: sig.is_verified(),
            code_signing: sig.eku_code_signing == Some(true),
            anchor: sig.chain_anchor,
            signed_at: sig.signing_time.clone(),
        })
    }
}

/// The published [`Signer`] for a resolved certificate, credited to the
/// field `source`.
pub(super) fn signer_struct(ci: CertInfo, source: &str) -> Signer {
    Signer {
        common_name: ci.cn,
        organization: ci.o,
        subject: ci.subject,
        issuer: ci.issuer,
        signed_at: ci.signed_at,
        source: source.into(),
    }
}

/// SHA-256 thumbprints of `Apple Code Signing Certification Authority`, the
/// intermediate under Apple Root CA that issues the leaves Apple signs its
/// own operating system and applications with (`Software Signing`, `macOS
/// Software Signing`), and no developer's. Apple's root also issues the
/// developer CAs, whose leaves carry the organization an account holder
/// registered, and the Mac App Store CA, whose `Apple Inc.` leaf re-signs
/// every third-party store app; neither makes a signature Apple's own.
pub(super) const APPLE_CODE_SIGNING_CAS: &[&str] =
    &["76843e4c6e3acb216134a57ba8aff512e394672b3966b996da80f009ee7b4645"];

/// Trust tier of one signature object.
///
/// Only cryptography lifts a signature above `Unverified`: `verified` must be
/// true, which means the signer's key signed the attributes and those bind
/// the signed content. Only a verified issuer link lifts it above
/// `SelfSigned`: the issuer a certificate names is the minter's choice. A
/// certificate's names decide nothing on their own,
/// since anyone minting a certificate chooses them, so the vendor tiers also
/// require `chain_anchor` — a verified chain ending at the vendor's own root —
/// and a leaf whose Extended Key Usage names `codeSigning`, since a vendor
/// root also issues certificates for TLS, mail and timestamping. Within such
/// a chain the leaf's names then pick the tier, by exact match: Apple's
/// `Developer ID ` certificates are `DeveloperId`, and a leaf whose
/// organization is the vendor itself is `Platform` — for Apple, only when
/// its verified issuer is one of [`APPLE_CODE_SIGNING_CAS`], since Apple's
/// root also issues certificates naming organizations Apple does not
/// choose; every CA under Microsoft's pinned roots is Microsoft's own, so
/// a leaf's organization there is Microsoft's to set. Every other verified
/// signature, including one under a vendor root issued to a third party, is
/// `CaSigned` — a CA signed it, and which CAs to trust is left to consumers
/// pinning `chain_sha256`.
pub(super) fn cert_trust(ci: &CertInfo) -> Trust {
    if !ci.verified {
        return Trust::Unverified;
    }
    if ci.self_issued || !ci.vouched {
        return Trust::SelfSigned;
    }
    let organization = ci.o.as_deref();
    match ci.anchor.filter(|_| ci.code_signing) {
        Some(Vendor::Apple)
            if ci
                .cn
                .as_deref()
                .is_some_and(|cn| cn.starts_with("Developer ID ")) =>
        {
            Trust::DeveloperId
        }
        Some(Vendor::Apple)
            if organization == Some("Apple Inc.")
                && ci
                    .issuer_thumbprint
                    .as_deref()
                    .is_some_and(|issuer| APPLE_CODE_SIGNING_CAS.contains(&issuer)) =>
        {
            Trust::Platform
        }
        Some(Vendor::Microsoft) if organization == Some("Microsoft Corporation") => Trust::Platform,
        _ => Trust::CaSigned,
    }
}

/// Pull one attribute value out of an RFC 4514 distinguished name as
/// `x509-cert` renders a certificate's: most specific RDN first, no spaces
/// around separators, special characters in values escaped. Values are
/// split on unescaped `,` and `+`, and unescaped: `\` before a character is
/// that character, and `\` before two hex digits is that byte, so a UTF-8
/// sequence written as `\C3\A9` reads back as `é`. Values are not trimmed:
/// an escaped space at either end is part of the value, so `Microsoft
/// Corporation ` is not read as `Microsoft Corporation`.
fn dn_attr(dn: &str, attr: &str) -> Option<String> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::new();
    let mut rest = dn.as_bytes();
    while let Some((&c, tail)) = rest.split_first() {
        rest = tail;
        match c {
            b'\\' => match rest {
                [hi, lo, tail @ ..] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    let pair = [*hi, *lo];
                    if let Some(byte) = std::str::from_utf8(&pair)
                        .ok()
                        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    {
                        cur.push(byte);
                    }
                    rest = tail;
                }
                [escaped, tail @ ..] => {
                    cur.push(*escaped);
                    rest = tail;
                }
                [] => {}
            },
            b',' | b'+' => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts.iter().find_map(|part| {
        let part = String::from_utf8_lossy(part);
        let (key, value) = part.split_once('=')?;
        (key.eq_ignore_ascii_case(attr) && !value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests;
