//! Normalized package-registry metadata — the upstream provider's own account
//! of a release, reduced to one ecosystem-agnostic shape.
//!
//! Where a manifest (`package.json`, `Cargo.toml`) is what a package *says about
//! itself*, a [`Registry`] record is what the *registry says about the package*:
//! when it was published, by whom, how widely it's installed, whether it's
//! deprecated. A registry client builds one from a registry round-trip;
//! serialized as a `*.registry.json` document it is parsed back into the same
//! `values`/`metrics` surface as any native manifest, so detection rules can
//! reason over both uniformly.
//!
//! The verbatim/derived split follows filefacts' convention: identity and text
//! (ecosystem, author, license, …) land in [`Values`]; the counted and measured
//! signals (downloads, rating, age) land in [`Metrics`], where trait authors can
//! threshold them with `min`/`max`.

mod lookalike;

use crate::metric;
use crate::value_key;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JsonValue;

use crate::output::{Metrics, Values};

/// Declares [`Ecosystem`] and its label table in one list, so a variant
/// cannot be added without its label.
macro_rules! ecosystems {
    ($($(#[$doc:meta])* $variant:ident => $label:literal,)*) => {
        /// The registry a [`Registry`] record came from.
        ///
        /// Serialized as its lowercase label (`"npm"`, `"pypi"`, `"crates"`,
        /// …). A label without a variant here reads as [`Ecosystem::Other`]
        /// and writes back as it was read, so a record naming a registry this
        /// build does not know still parses.
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Ecosystem {
            $($(#[$doc])* $variant,)*
            /// A registry without a variant here, by its label as written.
            Other(String),
        }

        impl Ecosystem {
            /// The serialized label, e.g. `"npm"`.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $label,)*
                    Self::Other(label) => label,
                }
            }

            /// The ecosystem `label` names, matched without regard to case.
            #[must_use]
            pub fn from_label(label: &str) -> Self {
                $(if label.eq_ignore_ascii_case($label) {
                    return Self::$variant;
                })*
                Self::Other(label.to_string())
            }
        }

        #[cfg(test)]
        const NAMED: &[Ecosystem] = &[$(Ecosystem::$variant,)*];
    };
}

ecosystems! {
    /// Alpine Linux packages.
    Alpine => "alpine",
    /// Arch Linux official repositories.
    Arch => "arch",
    /// The Arch User Repository.
    Aur => "aur",
    /// The Chrome Web Store.
    Chrome => "chrome",
    /// ClawHub skills.
    Clawhub => "clawhub",
    /// Clojars.
    Clojars => "clojars",
    /// The ComfyUI node registry.
    Comfyui => "comfyui",
    /// Packagist (Composer).
    Composer => "composer",
    /// conda channels.
    Conda => "conda",
    /// CPAN.
    Cpan => "cpan",
    /// CRAN.
    Cran => "cran",
    /// crates.io.
    Crates => "crates",
    /// Debian.
    Debian => "debian",
    /// The Dify plugin marketplace.
    Dify => "dify",
    /// Fedora.
    Fedora => "fedora",
    /// Firefox add-ons (AMO).
    Firefox => "firefox",
    /// FreeBSD ports.
    Freebsd => "freebsd",
    /// RubyGems.
    Gem => "gem",
    /// GitHub releases and repositories.
    Github => "github",
    /// Go modules.
    Golang => "golang",
    /// Hex (Erlang/Elixir).
    Hex => "hex",
    /// Homebrew.
    Homebrew => "homebrew",
    /// The Hugging Face Hub.
    Huggingface => "huggingface",
    /// The JetBrains plugin marketplace.
    Jetbrains => "jetbrains",
    /// JSR.
    Jsr => "jsr",
    /// Maven Central.
    Maven => "maven",
    /// NetBSD pkgsrc.
    Netbsd => "netbsd",
    /// npm.
    Npm => "npm",
    /// NuGet.
    Nuget => "nuget",
    /// OCI container registries.
    Oci => "oci",
    /// OpenBSD packages.
    Openbsd => "openbsd",
    /// openSUSE.
    Opensuse => "opensuse",
    /// Open VSX.
    Openvsx => "openvsx",
    /// pub.dev (Dart).
    Pub => "pub",
    /// PyPI.
    Pypi => "pypi",
    /// RPM Fusion, the add-on repositories for Fedora.
    Rpmfusion => "rpmfusion",
    /// The Snap Store.
    Snap => "snap",
    /// The Terraform registry.
    Terraform => "terraform",
    /// Ubuntu.
    Ubuntu => "ubuntu",
    /// The Visual Studio Code marketplace.
    Vscode => "vscode",
    /// Wolfi, Chainguard's container-first distribution.
    Wolfi => "wolfi",
    /// WordPress.org plugins.
    Wordpress => "wordpress",
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Ecosystem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Ecosystem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = std::borrow::Cow::<str>::deserialize(deserializer)?;
        Ok(Self::from_label(&label))
    }
}

/// A package release's registry metadata, normalized across ecosystems (npm,
/// PyPI, crates.io, Packagist, the AUR, …). Every field beyond
/// [`ecosystem`](Self::ecosystem)/[`name`](Self::name) is optional: registries
/// expose different subsets, and a missing field is "unknown", never a
/// fabricated default. Marketplace concepts ([`rating`](Self::rating), download
/// counts) sit beside library-registry ones so extension marketplaces map onto
/// the same record as a library registry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Registry {
    /// The source registry.
    pub ecosystem: Ecosystem,
    /// Package name as the registry knows it (scoped/`vendor/pkg` where so).
    pub name: String,
    /// The concrete version this record describes. Empty when the locator named
    /// no version and the registry reported no resolved one.
    pub version: String,
    /// Release publish time, Unix seconds. `None` when the registry omits it.
    pub published_at: Option<u64>,
    /// Days between publication and when this record was produced. Filled by the
    /// producer (which knows the wall clock); left `None` by a pure parse, since
    /// "age" is relative to an instant the document itself can't carry.
    pub age_days: Option<u64>,
    /// The registry's current latest/default version, for drift comparison.
    pub latest_version: Option<String>,
    /// Publishing author or maintainer, as a display string.
    pub author: Option<String>,
    /// Human-facing title/display name (marketplaces); libraries reuse `name`.
    pub title: Option<String>,
    /// One-line description/summary.
    pub description: Option<String>,
    /// Project homepage URL.
    pub homepage: Option<String>,
    /// Source repository URL.
    pub repository: Option<String>,
    /// Source-repository commit the release was built from, where the registry
    /// or its manifest records it (NuGet `.nuspec` `<repository commit=…>`). The
    /// artifact→source pin a bare [`repository`](Self::repository) URL can't give.
    pub repository_commit: Option<String>,
    /// SPDX (or registry-reported) license string.
    pub license: Option<String>,
    /// Lifetime download count, where the registry reports one.
    pub downloads_total: Option<u64>,
    /// Recent-window download count (window is registry-defined).
    pub downloads_recent: Option<u64>,
    /// Average user rating or popularity score (marketplaces, AUR). `None` for
    /// registries without a rating concept.
    pub rating: Option<f32>,
    /// Number of ratings/votes behind [`rating`](Self::rating).
    pub rating_count: Option<u64>,
    /// Deprecation notice when the registry flags the release or package.
    pub deprecated: Option<String>,
    /// Count of maintainers/owners, a thin custody signal.
    pub maintainers: Option<u32>,

    // ── Release history (package-level cadence, derived from the full version
    // timeline the registry exposes; npm carries it in the packument we already
    // fetch, PyPI in the package-level `releases` map). Counts and measures are
    // projected as metrics so traits can threshold them. ────────────────────
    /// Publish time of the package's *first-ever* release, Unix seconds — the
    /// package's birth, distinct from this version's [`published_at`](Self::published_at). `None`
    /// when the registry exposes no timeline.
    pub first_published_at: Option<u64>,
    /// Publish time of the release immediately preceding this version, Unix
    /// seconds. The gap to [`published_at`](Self::published_at) surfaces a dormant package that
    /// suddenly ships again (a hijack tell).
    pub previous_published_at: Option<u64>,
    /// Days from the first release to when this record was produced — the
    /// package's age. Filled by the producer (needs the wall clock), like
    /// [`age_days`](Self::age_days).
    pub package_age_days: Option<u64>,
    /// Total number of releases the registry lists for this package.
    pub release_count: Option<u32>,
    /// Releases published in the 24 hours before this record was produced —
    /// burst publishing is a supply-chain campaign tell. Producer-filled.
    pub releases_24h: Option<u32>,
    /// Releases published in the 48 hours before this record was produced.
    pub releases_48h: Option<u32>,

    // ── Custody (who actually pushed this release, vs. who is listed as
    // maintaining it — a mismatch is the account-takeover signal). ──────────
    /// The account that published *this version*, where the registry records it
    /// per-release (npm `_npmUser`, PyPI ownership). Distinct from the display
    /// [`author`](Self::author).
    pub publisher: Option<String>,
    /// Email domain of the publisher (the part after `@`), where exposed — a
    /// freemail/disposable domain on a sensitive package is a weak custody
    /// signal. The local-part is dropped; only the domain is retained.
    pub publisher_email_domain: Option<String>,
    /// Whether the publisher of this version is among the listed maintainers.
    /// `Some(false)` is the takeover tell; `None` when custody can't be
    /// determined.
    pub publisher_in_maintainers: Option<bool>,
    /// Whether the registry vouches for the publisher's identity — a verified
    /// publisher domain (VS Code `isDomainVerified`) or an owned/restricted
    /// namespace (Open VSX). `Some(false)` means anyone could have published
    /// under this name; `None` when the registry has no such concept.
    pub publisher_verified: Option<bool>,
    /// Whether the registry has replaced this package with a takedown
    /// placeholder — npm's `security holding package` stub, published by the
    /// registry's own security team after malicious code was removed. `Some(true)`
    /// is as authoritative a bad signal as a registry gives; `None` when the
    /// registry has no such tombstone concept.
    pub security_hold: Option<bool>,
    /// Whether *this version* has been removed from the registry — unpublished
    /// (npm `time.unpublished`) or yanked — while its metadata still resolves.
    /// A days-old package whose version was already pulled is, in practice,
    /// almost always a malware takedown. `None` when removal can't be
    /// determined.
    pub version_removed: Option<bool>,

    // ── Artifact shape (from the registry's own file records). ──────────────
    /// Unpacked size of the release in bytes, where the registry reports it
    /// (npm `dist.unpackedSize`; PyPI summed file sizes).
    pub unpacked_size: Option<u64>,
    /// Number of files in the release artifact (npm `dist.fileCount`).
    pub file_count: Option<u32>,
    /// Whether the registry flags an install-time script (npm
    /// `hasInstallScript` / an `install`/`preinstall`/`postinstall` entry).
    pub has_install_script: Option<bool>,
    /// Count of known vulnerabilities the registry reports for this release
    /// (PyPI `vulnerabilities`).
    pub vulnerability_count: Option<u32>,

    /// Every release's publish time, Unix seconds — the raw timeline the
    /// producer uses to derive the cadence counts above. Transient: never
    /// serialized into the `*.registry.json` document (the derived counts are
    /// what persist), so it carries no facts of its own.
    #[serde(skip)]
    pub release_times: Vec<u64>,
}

impl Registry {
    /// A record of `name` in `ecosystem` with every other field unknown.
    #[must_use]
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version: String::new(),
            published_at: None,
            age_days: None,
            latest_version: None,
            author: None,
            title: None,
            description: None,
            homepage: None,
            repository: None,
            repository_commit: None,
            license: None,
            downloads_total: None,
            downloads_recent: None,
            rating: None,
            rating_count: None,
            deprecated: None,
            maintainers: None,
            first_published_at: None,
            previous_published_at: None,
            package_age_days: None,
            release_count: None,
            releases_24h: None,
            releases_48h: None,
            publisher: None,
            publisher_email_domain: None,
            publisher_in_maintainers: None,
            publisher_verified: None,
            security_hold: None,
            version_removed: None,
            unpacked_size: None,
            file_count: None,
            has_install_script: None,
            vulnerability_count: None,
            release_times: Vec::new(),
        }
    }

    /// Seconds between [`published_at`](Self::published_at) and `now` (Unix
    /// seconds). `None` when the publish date is unknown. Saturates at zero so a
    /// clock skew that puts publication slightly ahead of `now` reads as "brand
    /// new", not a huge age.
    #[must_use]
    pub fn age_secs(&self, now: u64) -> Option<u64> {
        self.published_at.map(|p| now.saturating_sub(p))
    }

    /// Stamp the wall-clock-relative signals from `now` (Unix seconds),
    /// returning `self` — the producer's one chance to bake them in before the
    /// record is serialized and re-parsed as facts. Covers this version's
    /// [`age_days`](Self::age_days), the package's
    /// [`package_age_days`](Self::package_age_days), and the
    /// [`releases_24h`](Self::releases_24h)/[`releases_48h`](Self::releases_48h)
    /// burst counts derived from [`release_times`](Self::release_times).
    #[must_use]
    pub fn with_age(mut self, now: u64) -> Self {
        self.age_days = self.age_secs(now).map(|s| s / 86_400);
        self.package_age_days = self
            .first_published_at
            .map(|p| now.saturating_sub(p) / 86_400);
        if !self.release_times.is_empty() {
            let within = |window: u64| {
                let count = self
                    .release_times
                    .iter()
                    .filter(|&&t| now.saturating_sub(t) <= window)
                    .count();
                crate::bytes::sat_u32(count)
            };
            self.releases_24h = Some(within(86_400));
            self.releases_48h = Some(within(172_800));
        }
        self
    }

    /// Project this record onto the `values` (verbatim identity/text) and
    /// `metrics` (counted/measured) surfaces under the `registry.*` namespace,
    /// the same split every filefacts extractor follows. Empty optional fields
    /// are skipped, so a fact's presence is meaningful.
    ///
    /// Boolean facts become `0.0`/`1.0` metrics whenever the registry reported
    /// them: `0.0` is a known false, and an absent metric means the registry
    /// did not say. `registry.is_deprecated` is presence-only, `1.0` when a
    /// deprecation notice was reported: a record without one cannot tell "not
    /// deprecated" from "not reported". A `>= 1` threshold reads the same
    /// under both encodings.
    pub fn write_facts(&self, values: &mut Values, metrics: &mut Metrics) {
        // The author is a display string, often `"Name <email>"`; published
        // in the shape every package format uses for its people.
        crate::formats::people::put(
            values,
            value_key!("registry.authors"),
            self.author
                .as_deref()
                .map(crate::formats::people::Person::parse),
        );
        let mut put = |key: crate::ValueKey, v: Option<&str>| {
            if let Some(v) = v.filter(|s| !s.is_empty()) {
                values.insert_key(key, JsonValue::String(v.to_string()));
            }
        };
        put(
            value_key!("registry.ecosystem"),
            Some(self.ecosystem.as_str()),
        );
        put(value_key!("registry.name"), Some(&self.name));
        put(value_key!("registry.version"), Some(&self.version));
        put(
            value_key!("registry.latest_version"),
            self.latest_version.as_deref(),
        );
        put(value_key!("registry.title"), self.title.as_deref());
        put(
            value_key!("registry.description"),
            self.description.as_deref(),
        );
        put(value_key!("registry.homepage"), self.homepage.as_deref());
        put(
            value_key!("registry.repository"),
            self.repository.as_deref(),
        );
        put(
            value_key!("registry.repository_commit"),
            self.repository_commit.as_deref(),
        );
        put(value_key!("registry.license"), self.license.as_deref());
        put(
            value_key!("registry.deprecated"),
            self.deprecated.as_deref(),
        );
        put(value_key!("registry.publisher"), self.publisher.as_deref());
        put(
            value_key!("registry.publisher_email_domain"),
            self.publisher_email_domain.as_deref(),
        );

        let mut num = |key: crate::MetricKey, v: Option<f64>| {
            if let Some(v) = v {
                metrics.insert(key, v);
            }
        };
        num(
            metric!("registry.published_unix"),
            self.published_at.map(|v| v as f64),
        );
        num(
            metric!("registry.age_days"),
            self.age_days.map(|v| v as f64),
        );
        num(
            metric!("registry.downloads_total"),
            self.downloads_total.map(|v| v as f64),
        );
        num(
            metric!("registry.downloads_recent"),
            self.downloads_recent.map(|v| v as f64),
        );
        num(metric!("registry.rating"), self.rating.map(f64::from));
        num(
            metric!("registry.rating_count"),
            self.rating_count.map(|v| v as f64),
        );
        num(
            metric!("registry.maintainer_count"),
            self.maintainers.map(f64::from),
        );
        // A deprecation flag, so a rule can gate on `registry.is_deprecated
        // >= 1` without parsing the reason text.
        num(
            metric!("registry.is_deprecated"),
            self.deprecated.is_some().then_some(1.0),
        );

        // Release history — every count/measure is a metric so traits can
        // threshold it (e.g. `registry.releases_24h >= 3`, `package_age_days <= 7`).
        num(
            metric!("registry.first_published_unix"),
            self.first_published_at.map(|v| v as f64),
        );
        num(
            metric!("registry.previous_published_unix"),
            self.previous_published_at.map(|v| v as f64),
        );
        num(
            metric!("registry.package_age_days"),
            self.package_age_days.map(|v| v as f64),
        );
        num(
            metric!("registry.release_count"),
            self.release_count.map(f64::from),
        );
        num(
            metric!("registry.releases_24h"),
            self.releases_24h.map(f64::from),
        );
        num(
            metric!("registry.releases_48h"),
            self.releases_48h.map(f64::from),
        );
        // Days the package lay dormant before this release — a derived delta, so
        // it is a metric. Only when both endpoints of the gap are known.
        let days_since_previous = self
            .published_at
            .zip(self.previous_published_at)
            .map(|(now, prev)| (now.saturating_sub(prev) / 86_400) as f64);
        num(
            metric!("registry.days_since_previous_release"),
            days_since_previous,
        );

        // Custody and artifact shape.
        num(
            metric!("registry.unpacked_size"),
            self.unpacked_size.map(|v| v as f64),
        );
        num(
            metric!("registry.file_count"),
            self.file_count.map(f64::from),
        );
        num(
            metric!("registry.vulnerability_count"),
            self.vulnerability_count.map(f64::from),
        );
        // 0/1 flags, mirroring `registry.is_deprecated`: `0.0` is a reported
        // false, absence an unreported one (see `write_facts`).
        num(
            metric!("registry.has_install_script"),
            self.has_install_script.map(|b| f64::from(u8::from(b))),
        );
        num(
            metric!("registry.publisher_in_maintainers"),
            self.publisher_in_maintainers
                .map(|b| f64::from(u8::from(b))),
        );
        num(
            metric!("registry.publisher_verified"),
            self.publisher_verified.map(|b| f64::from(u8::from(b))),
        );
        num(
            metric!("registry.security_hold"),
            self.security_hold.map(|b| f64::from(u8::from(b))),
        );
        num(
            metric!("registry.version_removed"),
            self.version_removed.map(|b| f64::from(u8::from(b))),
        );
        // A name one keystroke from a popular package's, 0/1, and absent for an
        // ecosystem with no popularity list; see lookalike.
        num(
            metric!("registry.name_lookalike"),
            lookalike::name_lookalike(&self.ecosystem, &self.name),
        );
    }
}

#[cfg(test)]
mod tests;
