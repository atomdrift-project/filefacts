//! References an artifact points at — the external packages it declares or
//! installs and the URLs it stages, plus the *intra-artifact* files it names
//! (a manifest entry point, a relative import) — normalized for fetching,
//! cross-repo lookup, and intra-bundle resolution.
//!
//! Each row is a [`Reference`]. Extraction records *what* a file points at; it
//! does not fetch or resolve. A downstream fetcher resolves a fetchable
//! locator and fills in [`Reference::content_sha256`]; a bundle consumer
//! resolves a [`RefLocator::Path`] against the artifact's other files.

use serde::{Deserialize, Serialize};

/// A normalized identity for a referenced target.
///
/// A [`RefLocator::Purl`] is preferred wherever the ecosystem is
/// identifiable, because a package URL is canonical: two registry-mirror
/// URLs for the same package collapse to one PURL, which keeps cache keys
/// and cross-repo lookups stable. [`RefLocator::Url`] is reserved for a
/// genuine non-package fetch — a bare script on an arbitrary host. A
/// [`RefLocator::Path`] is an intra-artifact file reference, resolved against
/// the bundle's other files rather than fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefLocator {
    /// A package URL, e.g. `pkg:npm/%40scope/name@1.2.3` or
    /// `pkg:github/owner/repo`.
    Purl(String),
    /// A raw URL with no package identity.
    Url(String),
    /// A path to another file in the same artifact, as written
    /// (`./lib/index.js`, `index.js`, `bin/cli.js`). Relative to the
    /// referencing file's location; a consumer resolves it against the
    /// bundle's other files. Never a fetch target.
    Path(String),
}

/// The coarse nature of a reference — the *expression form* it was found
/// in, independent of the [`RefLocator`] address. The same package can be
/// referenced as a declared [`Dependency`](RefKind::Dependency) or as a
/// [`Command`](RefKind::Command) (`npm install foo`); a raw download is a
/// [`UrlFetch`](RefKind::UrlFetch). This is the stable hint a consumer
/// groups by, and it gates fetch selection: a [`Repository`](RefKind::Repository)
/// is identity and an [`Undefined`](RefKind::Undefined) is unclassified, so
/// neither is fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RefKind {
    /// A dependency declared in a manifest or lockfile (package.json deps,
    /// `.SRCINFO` `depends`/`source`, Cargo.lock).
    Dependency,
    /// A package named by a package-manager command invocation
    /// (`npm install foo`, `pip install bar`, `bun add baz`).
    Command,
    /// A direct URL retrieval — an install-hook `curl`/`wget`, or a second
    /// stage named in a binary or script.
    UrlFetch,
    /// The artifact's own source repository — identity, not a fetch target.
    Repository,
    /// A reference to another file *within the same artifact* — a manifest
    /// entry point (`package.json` `main`/`bin`), a relative `import`. Carries
    /// a [`RefLocator::Path`] and is resolved against sibling files, not
    /// fetched.
    Local,
    /// Recorded, but the kind could not be determined.
    Undefined,
}

/// A digest algorithm a manifest pins a reference to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HashAlgo {
    /// SHA-256 over the raw content (Cargo.lock `checksum`, wheel
    /// `--hash=sha256:`). Equals a fetched blob's `content_sha256`.
    Sha256,
    /// SHA-512 over the raw content (npm `integrity`, base64-encoded).
    Sha512,
    /// SHA-1 over the raw content (legacy npm `integrity`).
    Sha1,
    /// Go module checksum (`h1:` — base64 SHA-256 over a file *tree*, not
    /// a raw-content digest, so it never equals `content_sha256`).
    GoModH1,
}

/// A content hash a manifest pins a reference to. Drives cache lifetime —
/// a pinned reference is immutable, so it caches long — and lets a fetcher
/// verify retrieved bytes against what was declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedHash {
    /// The digest algorithm.
    pub algo: HashAlgo,
    /// The digest in the encoding the manifest carries: hex for the
    /// `sha*` content hashes, base64 for npm `integrity` and Go `h1:`.
    pub value: String,
}

/// One reference an artifact points at — an external package/URL (normalized
/// for fetching and cross-repo lookup) or an intra-artifact file path
/// (resolved against the bundle's other files).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    /// Normalized, fetchable identity. PURL where possible, else URL.
    pub locator: RefLocator,
    /// The coarse kind / expression form this reference was found in.
    pub kind: RefKind,
    /// Where the reference was found — a `values` key or parse site
    /// (`npm.repository.url`, `npm.scripts.postinstall`).
    pub source: String,
    /// The literal text the reference was extracted from — the `curl`/`wget`
    /// command, the manifest/lockfile entry, the `source=()` line — so the
    /// reference carries its own context.
    pub evidence: String,
    /// Byte offset into the analysed file, for highlighting and citation —
    /// the start of `evidence`, falling back to the start of the package
    /// name / URL when the full text isn't verbatim (a joined multi-line
    /// command). `0` only when the source is binary/compressed and nothing
    /// is locatable.
    pub offset: u64,
    /// The content hash the manifest pins this reference to, if any
    /// (go.sum, Cargo.lock, npm `integrity`). A pinned reference is
    /// immutable, which the fetcher uses to cache it longer and to verify
    /// the bytes it retrieves.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pinned_hash: Option<PinnedHash>,
    /// SHA-256 of the *referenced content*, lowercase hex — the key under
    /// which the fetched bytes are catalogued in hopper. Unknown until the
    /// content is fetched (or already in hand), so extraction usually
    /// leaves it `None`; a [`HashAlgo::Sha256`] pin is the one case it can
    /// be filled at extraction (the pin *is* the content hash).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content_sha256: Option<String>,
}

impl Reference {
    /// Whether this reference is a fetch target. A source repository is
    /// identity and an unclassified reference is not actioned, so neither
    /// is fetched; dependencies, commands, and URL fetches are.
    pub fn is_fetch_target(&self) -> bool {
        matches!(
            self.kind,
            RefKind::Dependency | RefKind::Command | RefKind::UrlFetch
        )
    }
}
