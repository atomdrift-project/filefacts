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

    /// Stamp [`age_days`](Self::age_days) from `now`, returning `self` — the
    /// producer's one chance to bake the relative-age signal into the record
    /// before it is serialized and re-parsed as facts.
    #[must_use]
    pub fn with_age(mut self, now: u64) -> Self {
        self.age_days = self.age_secs(now).map(|s| s / 86_400);
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
        put("registry.license", self.license.as_deref());
        put("registry.deprecated", self.deprecated.as_deref());

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
    }
}
