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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Recorded, but not a dependency selection of its own: a `replace` or
    /// `exclude` directive, a checksum line, a parser limit marker.
    Undefined,
}

/// How a declared dependency settled against the rest of its artifact (the
/// module's workspace, replacements, checksums and vendor directory). Set by
/// [`crate::go_dependency_context`]; `None` on references nothing reconciled.
/// Serialized as its kebab-case name; an unresolved one as
/// `{"unresolved": "<reason>"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Resolution {
    /// The declared minimum version stands. Minimal version selection may
    /// still build a higher one, which this does not compute.
    DeclaredMinimum,
    /// A `replace` directive redirected the dependency; the locator and
    /// source are the replacement's.
    Replaced,
    /// The artifact's vendor directory supplies the dependency.
    Vendored,
    /// The dependency could not be settled, so it is not a fetch target.
    Unresolved(UnresolvedReason),
}

/// Why a dependency is [`Resolution::Unresolved`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum UnresolvedReason {
    /// A manifest in the module's context did not parse completely.
    Manifest,
    /// An `exclude` directive names the declared minimum itself.
    ExcludedMinimum,
    /// A `replace` directive did not parse.
    Replacement,
    /// Replacements of equal priority disagree.
    ReplacementConflict,
    /// A local replacement path leaves the supplied artifact.
    LocalBoundary,
    /// A local replacement names a directory with no `go.mod`.
    LocalMissing,
    /// The checksum file pins the module to more than one hash.
    ChecksumConflict,
    /// The context work budget ran out before this module was reconciled.
    ContextBudget,
    /// `vendor/modules.txt` did not parse completely.
    VendorMetadata,
    /// `vendor/modules.txt` lists the module but its directory is absent.
    VendorMissing,
    /// A vendor directory exists but does not list the module.
    VendorUnlisted,
}

/// A digest algorithm a manifest pins a reference to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PinnedHash {
    /// The digest algorithm.
    pub algo: HashAlgo,
    /// The digest in the encoding the manifest carries: hex for the
    /// `sha*` content hashes, base64 for npm `integrity` and Go `h1:`.
    pub value: String,
}

/// Execution environment in which a declared dependency is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyScope {
    /// Installed application code.
    Runtime,
    /// Code executed to build an artifact.
    Build,
    /// Tooling used only in development or tests.
    Development,
    /// Code executed by a CI workflow.
    Ci,
}

/// Dependency context, independent of its locator and integrity constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DependencyContext {
    /// The environment in which the dependency is needed.
    pub scope: DependencyScope,
    /// Installation may omit this dependency on some platforms.
    #[serde(default)]
    pub optional: bool,
    /// The lockfile reports executable installation hooks.
    #[serde(default)]
    pub has_install_script: bool,
    /// The installed path in an npm v2/v3 lockfile, including alias names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_path: Option<String>,
}

/// One reference an artifact points at — an external package/URL (normalized
/// for fetching and cross-repo lookup) or an intra-artifact file path
/// (resolved against the bundle's other files).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Reference {
    /// Normalized, fetchable identity. PURL where possible, else URL.
    pub locator: RefLocator,
    /// The coarse kind / expression form this reference was found in.
    pub kind: RefKind,
    /// Where the reference was found: the manifest field or parse site,
    /// spelled as the format names it (`npm.repository.url`,
    /// `Cargo.toml:target.cfg(unix).dependencies.libc`). Open-ended by
    /// design, since manifest field paths are data; the reconciliation
    /// outcome is [`Self::resolution`], never encoded here.
    pub source: String,
    /// The literal text the reference was extracted from — the `curl`/`wget`
    /// command, the manifest/lockfile entry, the `source=()` line — so the
    /// reference carries its own context.
    pub evidence: String,
    /// Byte offset into the analysed file, for highlighting and citation —
    /// the start of `evidence`, falling back to the start of the package
    /// name / URL when the full text isn't verbatim (a joined multi-line
    /// command). `None` when nothing is locatable (a binary or compressed
    /// source, or the text was not found).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<u64>,
    /// The content hash the manifest pins this reference to, if any
    /// (go.sum, Cargo.lock, npm `integrity`). A pinned reference is
    /// immutable, which the fetcher uses to cache it longer and to verify
    /// the bytes it retrieves.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pinned_hash: Option<PinnedHash>,
    /// SHA-256 of the *referenced content*, lowercase hex — the key a
    /// fetcher catalogues the retrieved bytes under. Unknown until the
    /// content is fetched (or already in hand), so extraction usually
    /// leaves it `None`; a [`HashAlgo::Sha256`] pin is the one case it can
    /// be filled at extraction (the pin *is* the content hash).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content_sha256: Option<String>,
    /// Retained dependency scope and installation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<DependencyContext>,
    /// How the reference settled against the rest of its artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
}

impl Reference {
    /// A reference with no located offset, pin or content hash.
    #[must_use]
    pub fn new(
        locator: RefLocator,
        kind: RefKind,
        source: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            locator,
            kind,
            source: source.into(),
            evidence: evidence.into(),
            offset: None,
            pinned_hash: None,
            content_sha256: None,
            context: None,
            resolution: None,
        }
    }

    /// Whether this reference is a fetch target. A source repository is
    /// identity, an unclassified reference is not actioned, and an
    /// unresolved dependency names no version to fetch, so none of them is
    /// fetched; dependencies, commands, and URL fetches are.
    pub fn is_fetch_target(&self) -> bool {
        matches!(
            self.kind,
            RefKind::Dependency | RefKind::Command | RefKind::UrlFetch
        ) && !matches!(self.resolution, Some(Resolution::Unresolved(_)))
    }
}

#[cfg(test)]
mod tests;
