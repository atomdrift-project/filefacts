//! JAR (v1) signing, as Android APKs and Mozilla XPIs use it: who signed the
//! archive, and whether that signature reaches its members.
//!
//! A signature block, `META-INF/<BASE>.RSA` / `.DSA` / `.EC`, is a detached
//! PKCS#7 over the signature file of the same base name, `<BASE>.SF`, which
//! is handed to the CMS parser as the content so the block can verify. The
//! `.SF` in turn digests the JAR manifest and the manifest every member
//! ([`binding`]); a block that verifies over its `.SF` is `verified` only
//! when that binding also holds, and `digest_matches` states it.
//!
//! The two platforms differ in the details [`Scheme`] carries: which blocks
//! they read, the manifest's name, which members need no digest, and how far
//! the `.SF` must go.

mod binding;

use std::collections::HashMap;
use std::io::{Read, Seek};

use serde_json::Value as JsonValue;

use super::bounded::Limits;
use super::cms::{Signature, Verdict};
use super::zip::{JarSigning, MemberError, read_member};
use crate::output::{Errors, Stage};

/// A v1 signature block is a few KB of DER.
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024 * 1024;
/// A `.SF` signature file holds a digest line per member, so it grows with
/// the archive; this is well past what the member cap allows for.
const MAX_SIGNATURE_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Signature blocks read and verified. A real archive carries one to three
/// signers; each block costs a read of up to [`MAX_SIGNATURE_BYTES`], one
/// of its `.SF` of up to [`MAX_SIGNATURE_FILE_BYTES`], and a CMS parse, and
/// overlapping central-directory entries let the block count grow with the
/// file. Blocks past this are counted, not read.
pub(super) const MAX_SIGNATURE_BLOCKS: usize = 8;

/// Whose rules a JAR signature is checked under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scheme {
    /// Android's v1 scheme, as apksig checks it: any block base name, the
    /// manifest at `META-INF/MANIFEST.MF`, and a `.SF` that lists every
    /// member.
    Android,
    /// Firefox's add-on signing: the block `META-INF/mozilla.rsa` over
    /// `mozilla.sf`, the manifest at `META-INF/manifest.mf`, and a `.SF`
    /// whose whole-manifest digest is the only one Firefox reads.
    Mozilla,
}

impl Scheme {
    /// Whether the platform reads the signature block of base name `base`.
    fn reads_block(self, base: &str) -> bool {
        match self {
            Self::Android => true,
            Self::Mozilla => base.eq_ignore_ascii_case("mozilla"),
        }
    }
}

/// The signature blocks an archive carries.
pub(super) struct Signed {
    /// Every signature block the scheme reads, including those past
    /// [`MAX_SIGNATURE_BLOCKS`].
    pub(super) blocks: usize,
    /// The blocks that parsed, as published values: a [`Signature`] with
    /// the block's `member` and, when found, its `.SF` as `signed_member`.
    pub(super) signatures: Vec<JsonValue>,
}

/// Read and verify `zip`'s signature blocks under `scheme`. Caps hit go to
/// `limits`; blocks that will not read are reported once, in aggregate, to
/// `errors`.
pub(super) fn read<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    scheme: Scheme,
    limits: &mut Limits,
    errors: &mut Errors,
) -> Signed {
    let mut names = Vec::new();
    // Signature files by upper-cased base name: `META-INF/CERT.RSA` signs
    // `META-INF/CERT.SF`, matched without regard to case.
    let mut signature_files = HashMap::new();
    for name in zip.file_names().filter_map(Result::ok) {
        match super::zip::jar_signing(&name) {
            Some((JarSigning::SignatureBlock, base)) if scheme.reads_block(base) => {
                names.push((name.to_string(), base.to_ascii_uppercase()));
            }
            Some((JarSigning::SignatureFile, base)) => {
                signature_files
                    .entry(base.to_ascii_uppercase())
                    .or_insert_with(|| name.to_string());
            }
            _ => {}
        }
    }
    let blocks = names.len();
    if blocks > MAX_SIGNATURE_BLOCKS {
        limits.push(
            "signature-blocks",
            format!("read {MAX_SIGNATURE_BLOCKS} of {blocks} v1 signature blocks"),
        );
        names.truncate(MAX_SIGNATURE_BLOCKS);
    }

    let total = names.len();
    let mut verifier = binding::Verifier::new(scheme, binding::MAX_HASHED_BYTES);
    let mut signatures = Vec::new();
    // A hostile archive can list any number of signature members, so
    // failures are reported once, in aggregate.
    let mut unreadable = 0usize;
    let mut first_failure = None;
    for (name, base) in names {
        let der = match read_member(zip, &name, MAX_SIGNATURE_BYTES) {
            Ok(Some(der)) => der,
            Ok(None) => continue,
            Err(why) => {
                unreadable += 1;
                first_failure.get_or_insert_with(|| format!("{name}: {why}"));
                continue;
            }
        };
        let signature_file = signature_files.get(&base).and_then(|sf_name| {
            match read_member(zip, sf_name, MAX_SIGNATURE_FILE_BYTES) {
                Ok(content) => content.map(|content| (sf_name, content)),
                Err(MemberError::TooLarge { max }) => {
                    limits.push(
                        "signature-file",
                        format!("{sf_name} over the {max}-byte cap; signature not verified"),
                    );
                    None
                }
                Err(why) => {
                    unreadable += 1;
                    first_failure.get_or_insert_with(|| format!("{sf_name}: {why}"));
                    None
                }
            }
        });
        // Without its signature file the block still names a signer, but it
        // reads as unverifiable: there is nothing to check the signature over.
        let parsed = match &signature_file {
            Some((sf_name, content)) => {
                super::cms::parse_detached_cms(&der, content).map(|mut sig| {
                    if sig.is_verified() {
                        let binding = verifier.bind(zip, content);
                        record_binding(&mut sig, binding, sf_name, limits);
                    }
                    sig.to_json()
                })
            }
            None => super::cms::parse_cms_blob(&der),
        };
        if let Some(mut sig) = parsed
            && let Some(obj) = sig.as_object_mut()
        {
            obj.insert("member".into(), JsonValue::String(name));
            if let Some((sf_name, _)) = signature_file {
                obj.insert("signed_member".into(), JsonValue::String(sf_name.clone()));
            }
            signatures.push(sig);
        }
    }
    if let Some(first) = first_failure {
        errors.record_malformed(
            Stage::ZipParse,
            format!("{unreadable} of {total} v1 signature blocks unreadable; first: {first}"),
        );
    }
    Signed { blocks, signatures }
}

/// Fold whether the `.SF` named `sf_name`, over which `sig` verified,
/// binds the archive into `sig`: `verified` stays true only when it does.
fn record_binding(
    sig: &mut Signature,
    binding: binding::Binding,
    sf_name: &str,
    limits: &mut Limits,
) {
    match binding {
        binding::Binding::Bound => sig.digest_matches = Some(true),
        binding::Binding::Broken(why) => {
            tracing::debug!(
                target: "filefacts::jar_signature",
                stage = "v1-binding",
                member = sf_name,
                failure = ?why,
                "v1 signature verifies over its signature file but does not bind the archive"
            );
            sig.verified = Some(Verdict::Failed(why));
            sig.digest_matches = Some(false);
        }
        binding::Binding::Unverifiable(reason) => {
            limits.push(
                "signature-binding",
                format!("{sf_name}: {reason}; signature not verified"),
            );
            sig.verified = Some(Verdict::Unsupported);
        }
    }
}
