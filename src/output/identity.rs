//! Normalized identity claims — who and what an artifact says it is.
//!
//! Every other view answers *what does this file contain or do*. This
//! one answers *who does it claim to be*. The values are scattered
//! across each format's structural view (`macho.code_signature.*`,
//! `pe.version.*`, `office.creator`, `npm.author.*`, …); this view
//! folds them into one shape so a consumer — a UI, or an LLM weighing
//! identity against behavior — reads identity the same way regardless
//! of format.
//!
//! ## Claimed vs. verified
//!
//! The crux is provenance. A `.docx` whose author is "Apple Inc." and
//! a Mach-O binary whose CMS chain proves Apple signed it are not the
//! same kind of statement. Every scalar field is a [`Claim`] carrying
//! its [`source`](Claim::source) (the `values` key it came from) and a
//! [`verified`](Claim::verified) flag that is `true` only when a
//! cryptographic signature backs it. The reader can then ask the
//! question the view exists to support: *here is the claimed identity,
//! here are the behaviors — do they agree?*
//!
//! Trust is summarized once, across formats, by [`Trust`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One identity assertion and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// The asserted value (a name, identifier, version, …).
    pub value: String,
    /// The `values` key (or extractor) the claim was read from, e.g.
    /// `macho.code_signature.identifier` or `office.creator`. Lets a
    /// reader trace every field back to its origin.
    pub source: String,
    /// `true` only when a verified cryptographic signature backs the
    /// claim (Authenticode / CMS / Mach-O code signature). Manifest and
    /// document-metadata claims, which anyone can write, are `false`.
    #[serde(default)]
    pub verified: bool,
}

impl Claim {
    /// A claim asserted by unauthenticated metadata (a manifest field,
    /// document property, embedded string).
    pub fn claimed(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: source.into(),
            verified: false,
        }
    }

    /// A claim backed by a verified cryptographic signature.
    pub fn verified(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: source.into(),
            verified: true,
        }
    }
}

/// A named party — a person or organization the artifact references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party {
    /// Display name, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Contact email, when given. A strong cross-package identifier
    /// (npm/PyPI maintainers, gem authors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Personal or project URL associated with the party.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The role the party plays: `author`, `maintainer`, `publisher`,
    /// `last_modified_by`, …
    pub role: String,
    /// The `values` key the party was read from.
    pub source: String,
}

/// What a referenced URL points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UrlKind {
    /// Project or product home page.
    Homepage,
    /// Source repository.
    Repository,
    /// Documentation site.
    Documentation,
    /// Issue / bug tracker.
    BugTracker,
    /// Funding / sponsorship link.
    Funding,
    /// Anything else the artifact advertises.
    Other,
}

/// A URL the artifact advertises, tagged by what it points to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Url {
    /// What the URL points to.
    pub kind: UrlKind,
    /// The URL itself.
    pub url: String,
    /// The `values` key the URL was read from.
    pub source: String,
}

/// The cryptographic signer, resolved from the signing certificate.
///
/// Present only when the artifact carries a signature whose signer
/// certificate we could parse. The fields are pulled out of the
/// certificate's distinguished names so a reader gets "Apple Inc."
/// rather than a full `CN=…, O=…, C=…` string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signer {
    /// Certificate subject common name (`CN`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Certificate subject organization (`O`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Full subject distinguished name, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Full issuer distinguished name, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// When the artifact was signed, ISO-8601, if the signature carries
    /// a trusted timestamp. The one timestamp that belongs to identity:
    /// it corroborates *when* this signer made its claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// The `values` key the signer was resolved from.
    pub source: String,
}

/// Normalized trust level of the artifact's signature, ordered from
/// least to most trusted. The same vocabulary spans every format: a
/// Mach-O platform binary, a Microsoft-signed PE, and a Developer-ID
/// app each land in the obvious tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Trust {
    /// No signature present.
    #[default]
    Unsigned,
    /// A signature structure is present, but its cryptographic proof has not
    /// been verified. This records signed packaging without overstating trust.
    Unverified,
    /// Ad-hoc signed: a code signature with no identifying certificate
    /// chain (Mach-O `CS_ADHOC`). Integrity without identity.
    AdHoc,
    /// Signed by a certificate that is its own issuer — asserts an
    /// identity nothing else vouches for.
    SelfSigned,
    /// Signed by a certificate chaining to a public CA, signer not
    /// otherwise recognized.
    CaSigned,
    /// Apple Developer ID — distributed outside the App Store by an
    /// enrolled developer.
    DeveloperId,
    /// Signed by the platform vendor (Microsoft, Apple software
    /// signing) but not a first-party OS component.
    Platform,
    /// A first-party operating-system component (Apple platform binary,
    /// system-bundled tool).
    System,
}

/// Normalized identity claims for an artifact.
///
/// Empty fields are omitted from the JSON. [`Identity::is_empty`]
/// reports whether anything was found at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Short program / package / product name (`ls`, the npm package
    /// name, the VSIX display name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Claim>,
    /// Human-facing document title (document properties).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Claim>,
    /// Canonical identifier: bundle id (`com.apple.ls`), package id,
    /// Chrome extension id, VSIX `publisher.name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Claim>,
    /// Source project / build provenance (`file_cmds-479`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<Claim>,
    /// Declared version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<Claim>,
    /// People associated with the artifact (authors, maintainers,
    /// `last_modified_by`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authors: Vec<Party>,
    /// Claimed publishing organization / company (document `Company`,
    /// PE `CompanyName`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Claim>,
    /// The tool that produced the artifact (authoring application,
    /// PDF producer, build toolchain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer: Option<Claim>,
    /// Build-time source path baked into the artifact (PE PDB path, Go
    /// build path, DWARF compile dir). An origin artifact: it commonly
    /// reveals the developer's account (`/Users/<name>/…`) or the build
    /// environment (`/builddir/build/BUILD`). Left as the raw path —
    /// the username is a substring a consumer can pull out, not
    /// something we guess at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_path: Option<Claim>,
    /// Resolved cryptographic signer, when signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    /// Normalized trust level.
    pub trust: Trust,
    /// Vendor team identifier / publisher namespace (Apple Team ID,
    /// VSIX publisher).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<Claim>,
    /// Distinct contact emails gathered across all parties — a flat,
    /// deduplicated list for quick correlation.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub emails: Vec<String>,
    /// URLs the artifact advertises.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub urls: Vec<Url>,
    /// Stable, often-cryptographic unique identifiers keyed by name:
    /// `cdhash`, `authenticode_thumbprint`, `crx_id`,
    /// `public_key_sha256`, host `machine_id`, …
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub unique_ids: BTreeMap<String, String>,
}

impl Identity {
    /// `true` when no identity claim of any kind was found and the
    /// artifact is unsigned — nothing worth showing.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.title.is_none()
            && self.identifier.is_none()
            && self.project.is_none()
            && self.version.is_none()
            && self.authors.is_empty()
            && self.organization.is_none()
            && self.producer.is_none()
            && self.build_path.is_none()
            && self.signer.is_none()
            && self.trust == Trust::Unsigned
            && self.team_id.is_none()
            && self.emails.is_empty()
            && self.urls.is_empty()
            && self.unique_ids.is_empty()
    }
}
