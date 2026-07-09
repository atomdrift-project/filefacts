//! Normalized package-registry metadata — the upstream provider's own account
//! of a release, reduced to one ecosystem-agnostic shape.
//!
//! Where a manifest (`package.json`, `Cargo.toml`) is what a package *says about
//! itself*, a [`Registry`] record is what the *registry says about the package*:
//! when it was published, by whom, how widely it's installed, whether it's
//! deprecated. fletch produces these from a registry round-trip; serialized as a
//! `*.registry.json` document they are parsed back — by
//! [`crate::formats`] — into the same `values`/`metrics` surface as any native
//! manifest, so detection traits can reason over them uniformly.
//!
//! The verbatim/derived split follows filefacts' convention: identity and text
//! (ecosystem, author, license, …) land in [`Values`]; the counted and measured
//! signals (downloads, rating, age) land in [`Metrics`], where trait authors can
//! threshold them with `min`/`max`.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::output::{Metrics, Values};

/// A package release's registry metadata, normalized across ecosystems (npm,
/// PyPI, crates.io, Packagist, the AUR, …). Every field beyond
/// [`ecosystem`](Self::ecosystem)/[`name`](Self::name) is optional: registries
/// expose different subsets, and a missing field is "unknown", never a
/// fabricated default. Marketplace concepts ([`rating`](Self::rating), download
/// counts) sit beside library-registry ones so extension marketplaces map onto
/// the same record as a library registry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Registry {
    /// The source registry: `npm`, `pypi`, `crates`, `composer`, `aur`, …
    pub ecosystem: String,
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
    /// package's birth, distinct from this version's [`published_at`]. `None`
    /// when the registry exposes no timeline.
    pub first_published_at: Option<u64>,
    /// Publish time of the release immediately preceding this version, Unix
    /// seconds. The gap to [`published_at`] surfaces a dormant package that
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
                self.release_times
                    .iter()
                    .filter(|&&t| now.saturating_sub(t) <= window)
                    .count() as u32
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
    pub fn write_facts(&self, values: &mut Values, metrics: &mut Metrics) {
        let mut put = |key: &str, v: Option<&str>| {
            if let Some(v) = v.filter(|s| !s.is_empty()) {
                values.insert(key, JsonValue::String(v.to_string()));
            }
        };
        put("registry.ecosystem", Some(&self.ecosystem));
        put("registry.name", Some(&self.name));
        put("registry.version", Some(&self.version));
        put("registry.latest_version", self.latest_version.as_deref());
        put("registry.author", self.author.as_deref());
        put("registry.title", self.title.as_deref());
        put("registry.description", self.description.as_deref());
        put("registry.homepage", self.homepage.as_deref());
        put("registry.repository", self.repository.as_deref());
        put(
            "registry.repository_commit",
            self.repository_commit.as_deref(),
        );
        put("registry.license", self.license.as_deref());
        put("registry.deprecated", self.deprecated.as_deref());
        put("registry.publisher", self.publisher.as_deref());
        put(
            "registry.publisher_email_domain",
            self.publisher_email_domain.as_deref(),
        );

        let mut num = |key: &str, v: Option<f64>| {
            if let Some(v) = v {
                metrics.insert(key, v);
            }
        };
        num("registry.published_at", self.published_at.map(|v| v as f64));
        num("registry.age_days", self.age_days.map(|v| v as f64));
        num(
            "registry.downloads_total",
            self.downloads_total.map(|v| v as f64),
        );
        num(
            "registry.downloads_recent",
            self.downloads_recent.map(|v| v as f64),
        );
        num("registry.rating", self.rating.map(f64::from));
        num("registry.rating_count", self.rating_count.map(|v| v as f64));
        num("registry.maintainers", self.maintainers.map(f64::from));
        // A boolean deprecation flag as a 0/1 metric, so a trait can gate on
        // `registry.is_deprecated >= 1` without parsing the reason text.
        num(
            "registry.is_deprecated",
            Some(f64::from(u8::from(self.deprecated.is_some()))),
        );

        // Release history — every count/measure is a metric so traits can
        // threshold it (e.g. `registry.releases_24h >= 3`, `package_age_days <= 7`).
        num(
            "registry.first_published_at",
            self.first_published_at.map(|v| v as f64),
        );
        num(
            "registry.previous_published_at",
            self.previous_published_at.map(|v| v as f64),
        );
        num(
            "registry.package_age_days",
            self.package_age_days.map(|v| v as f64),
        );
        num("registry.release_count", self.release_count.map(f64::from));
        num("registry.releases_24h", self.releases_24h.map(f64::from));
        num("registry.releases_48h", self.releases_48h.map(f64::from));
        // Days the package lay dormant before this release — a derived delta, so
        // it is a metric. Only when both endpoints of the gap are known.
        let days_since_previous = self
            .published_at
            .zip(self.previous_published_at)
            .map(|(now, prev)| (now.saturating_sub(prev) / 86_400) as f64);
        num("registry.days_since_previous_release", days_since_previous);

        // Custody and artifact shape.
        num(
            "registry.unpacked_size",
            self.unpacked_size.map(|v| v as f64),
        );
        num("registry.file_count", self.file_count.map(f64::from));
        num(
            "registry.vulnerability_count",
            self.vulnerability_count.map(f64::from),
        );
        // 0/1 flags, mirroring `registry.is_deprecated`.
        num(
            "registry.has_install_script",
            self.has_install_script.map(|b| f64::from(u8::from(b))),
        );
        num(
            "registry.publisher_in_maintainers",
            self.publisher_in_maintainers
                .map(|b| f64::from(u8::from(b))),
        );
        num(
            "registry.publisher_verified",
            self.publisher_verified.map(|b| f64::from(u8::from(b))),
        );
        num(
            "registry.security_hold",
            self.security_hold.map(|b| f64::from(u8::from(b))),
        );
        num(
            "registry.version_removed",
            self.version_removed.map(|b| f64::from(u8::from(b))),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_age_derives_cadence_relative_to_now() {
        let day = 86_400u64;
        let now = 100 * day;
        let reg = Registry {
            ecosystem: "pypi".into(),
            name: "widget".into(),
            published_at: Some(now), // this release: right now
            first_published_at: Some(now - 74 * day), // package born 74d ago
            previous_published_at: Some(now - 2 * day),
            // three releases inside 48h (one inside 24h), plus older ones
            release_times: vec![now, now - 2 * day, now - 30 * day, now - 74 * day],
            ..Default::default()
        }
        .with_age(now);

        assert_eq!(reg.age_days, Some(0), "this version is brand new");
        assert_eq!(reg.package_age_days, Some(74), "package is 74 days old");
        assert_eq!(reg.releases_24h, Some(1), "only the current release in 24h");
        assert_eq!(reg.releases_48h, Some(2), "current + the 2-days-ago one");
    }

    #[test]
    fn write_facts_routes_counts_to_metrics_and_identity_to_values() {
        let day = 86_400u64;
        let now = 100 * day;
        let reg = Registry {
            ecosystem: "npm".into(),
            name: "widget".into(),
            published_at: Some(now),
            previous_published_at: Some(now - 5 * day),
            first_published_at: Some(now - 40 * day),
            release_count: Some(12),
            publisher: Some("attacker".into()),
            publisher_email_domain: Some("gmail.com".into()),
            publisher_in_maintainers: Some(false),
            publisher_verified: Some(false),
            security_hold: Some(false),
            version_removed: Some(true),
            unpacked_size: Some(4096),
            file_count: Some(3),
            has_install_script: Some(true),
            vulnerability_count: Some(0),
            ..Default::default()
        }
        .with_age(now);

        let mut values = Values::new();
        let mut metrics = Metrics::new();
        reg.write_facts(&mut values, &mut metrics);

        // Identity → values.
        assert_eq!(
            values.get("registry.publisher").and_then(|v| v.as_str()),
            Some("attacker")
        );
        assert_eq!(
            values
                .get("registry.publisher_email_domain")
                .and_then(|v| v.as_str()),
            Some("gmail.com")
        );
        // Counts / measures / derived deltas / flags → metrics.
        assert_eq!(metrics.get("registry.release_count"), Some(12.0));
        assert_eq!(metrics.get("registry.package_age_days"), Some(40.0));
        assert_eq!(
            metrics.get("registry.days_since_previous_release"),
            Some(5.0)
        );
        assert_eq!(metrics.get("registry.unpacked_size"), Some(4096.0));
        assert_eq!(metrics.get("registry.file_count"), Some(3.0));
        assert_eq!(metrics.get("registry.has_install_script"), Some(1.0));
        assert_eq!(metrics.get("registry.publisher_in_maintainers"), Some(0.0));
        assert_eq!(metrics.get("registry.publisher_verified"), Some(0.0));
        assert_eq!(metrics.get("registry.security_hold"), Some(0.0));
        assert_eq!(metrics.get("registry.version_removed"), Some(1.0));
        // A present-but-zero count is still emitted (0 vulns is a real fact).
        assert_eq!(metrics.get("registry.vulnerability_count"), Some(0.0));
        // Publisher identity never leaks into metrics; counts never into values.
        assert!(metrics.get("registry.publisher").is_none());
        assert!(values.get("registry.release_count").is_none());
    }
}
