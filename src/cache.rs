//! Disk cache for filefacts analysis output.
//!
//! The canonical store for an [`crate::ParsedFile`]'s extraction
//! snapshot. Its reason to exist is the rizin disassembly pass: full
//! `aaa` recovery on a stripped binary costs seconds to minutes, and the
//! recovered imports/exports/functions/sections land in the cached
//! payload, so a second `open` of the same bytes never re-runs rizin.
//!
//! # Layout
//!
//! ```text
//! {cache_dir}/atomdrift/filefacts/v{SCHEMA_VERSION}/{key[0..2]}/{key}.bin
//! ```
//!
//! On the host platforms this resolves (via [`dirs::cache_dir`]) to the
//! idiomatic per-OS cache root: `~/Library/Caches/atomdrift/filefacts`
//! (macOS), `~/.cache/atomdrift/filefacts` (Linux/XDG),
//! `%LOCALAPPDATA%\atomdrift\filefacts` (Windows). The two-character
//! shard keeps any single directory bounded.
//!
//! # Format
//!
//! `serde_json`-encoded payload, then zstd-compressed at level 3. JSON
//! (not a positional format like bincode) is deliberate: the cached
//! types carry `#[serde(skip_serializing_if)]` fields, which a
//! self-describing format round-trips correctly and a positional one
//! silently corrupts. Writes go through a `.tmp` file followed by an
//! atomic rename so two processes hashing the same input cannot corrupt
//! the entry.
//!
//! # Invalidation
//!
//! The cache key is `sha256(content ∥ build_fingerprint ∥ variant)`:
//!
//! * **content** — the input bytes.
//! * **`build_fingerprint`** — filefacts' crate version *and* the running
//!   executable's mtime. filefacts is statically linked, so any change to
//!   its extraction logic forces the consumer to recompile, which moves
//!   the mtime and so retires every prior entry without a manual bump.
//!   The crate version covers released artifacts where the mtime may be
//!   reset by packaging.
//! * **variant** — the caller's [`crate::rizin::cache_fingerprint`]
//!   (rizin presence / version / native-arch slicing).
//!
//! [`CACHE_SCHEMA_VERSION`] is the manual lever on top, reserved for
//! deliberate format breaks; [`prune_old_versions`] removes superseded
//! version dirs and [`prune_stale`] ages out entries orphaned by
//! build-fingerprint churn.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI8, Ordering};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

/// Tri-state override for whether [`crate::ParsedFile`] self-caches:
/// `0` = default, `1` = forced on, `-1` = forced off. A counter-free
/// switch a host sets once; see [`set_caching_enabled`].
static CACHING_OVERRIDE: AtomicI8 = AtomicI8::new(0);

/// Force the [`crate::ParsedFile::open`]-time disk cache on or off for
/// the rest of the process. Overrides the default (on, except inside
/// filefacts' own test runs). A consumer that needs hermetic extraction
/// — its own test suite, a reproducibility check — disables it here.
pub fn set_caching_enabled(enabled: bool) {
    CACHING_OVERRIDE.store(if enabled { 1 } else { -1 }, Ordering::Relaxed);
}

/// Whether `open`-time self-caching is active.
///
/// Resolution order:
/// 1. a programmatic override from [`set_caching_enabled`];
/// 2. the `FILEFACTS_CACHE` env var (`0` / `false` disables, anything
///    else enables) — an ops/test escape hatch needing no recompile;
/// 3. default: on, except when filefacts itself is under `cargo test`
///    (kept hermetic so fixture assertions never read a shared entry).
#[must_use]
pub fn caching_enabled() -> bool {
    match CACHING_OVERRIDE.load(Ordering::Relaxed) {
        1 => true,
        -1 => false,
        // Cache the env-derived default: this runs once per file on the
        // scan hot path, and the environment is fixed at process start.
        _ => {
            static DEFAULT: OnceLock<bool> = OnceLock::new();
            *DEFAULT.get_or_init(|| match std::env::var("FILEFACTS_CACHE") {
                Ok(v) => !(v == "0" || v.eq_ignore_ascii_case("false")),
                Err(_) => !cfg!(test),
            })
        }
    }
}

/// On-disk cache schema version. Bump only on a deliberate, breaking
/// change to the on-disk *format* (not ordinary payload-field additions —
/// the build fingerprint in [`cache_key`] already retires stale entries
/// when extraction logic changes). Version 6 moved the payload from
/// positional bincode to self-describing JSON and folded the build
/// fingerprint into the key.
pub const CACHE_SCHEMA_VERSION: u32 = 6;

/// Process-wide build identity mixed into every cache key.
///
/// `{crate version}+{executable mtime}`. The mtime is the load-bearing
/// half: filefacts links statically, so changing its code forces the
/// consuming binary to relink, which bumps its mtime and invalidates
/// every entry from the old build — the simplest correct answer to "the
/// extraction logic changed." Probed once; `0` mtime when the executable
/// path or its metadata is unavailable (the crate version still differs
/// across releases).
fn build_fingerprint() -> &'static str {
    static FP: OnceLock<String> = OnceLock::new();
    FP.get_or_init(|| {
        let exe_mtime = std::env::current_exe()
            .and_then(fs::metadata)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        format!("{}+{exe_mtime}", env!("CARGO_PKG_VERSION"))
    })
}

/// Lowercase hex-encode a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// SHA-256 a byte slice, returning the lowercase hex digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Disk-cache key for `bytes` analysed under `variant`.
///
/// Content addressing is only sound when the cached payload is a pure
/// function of the key. Two things break that for a bare content hash,
/// and both are folded in here:
///
/// * the filefacts [`build_fingerprint`] — extraction logic changes
///   between builds, so a stale entry from an older filefacts must not be
///   reused;
/// * the caller's `variant` — the [`crate::rizin::cache_fingerprint`]
///   (rizin presence / version / native-arch slicing), since the *same*
///   bytes yield different recovery under different rizin configurations.
///
/// `variant` may be empty for a computation that never involves rizin;
/// the build fingerprint is always mixed in regardless.
#[must_use]
pub fn cache_key(bytes: &[u8], variant: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // Domain-separated so no concatenation of (content, build, variant)
    // can collide with a different split of the same bytes.
    hasher.update([0u8]);
    hasher.update(build_fingerprint().as_bytes());
    hasher.update([0u8]);
    hasher.update(variant.as_bytes());
    hex(&hasher.finalize())
}

/// Root cache directory for filefacts. Returns the first writable
/// candidate from (OS cache dir + `atomdrift/filefacts`) → temp dir +
/// `filefacts-cache`.
pub fn cache_root() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(base) = dirs::cache_dir() {
        candidates.push(base.join("atomdrift").join("filefacts"));
    }
    candidates.push(std::env::temp_dir().join("filefacts-cache"));
    for c in candidates {
        if fs::create_dir_all(&c).is_ok() {
            let probe = c.join(".write-test");
            if fs::write(&probe, b"ok").is_ok() {
                let _ = fs::remove_file(&probe);
                return Some(c);
            }
        }
    }
    None
}

/// Directory holding cache entries for the current schema version.
pub fn version_dir() -> Option<PathBuf> {
    let root = cache_root()?;
    let dir = root.join(format!("v{CACHE_SCHEMA_VERSION}"));
    fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Full on-disk path for a cache entry with the given SHA-256 hex
/// digest. Creates the two-char shard directory if missing.
pub fn entry_path(sha_hex: &str) -> Option<PathBuf> {
    if sha_hex.len() < 2 {
        return None;
    }
    let dir = version_dir()?.join(&sha_hex[..2]);
    fs::create_dir_all(&dir).ok()?;
    Some(dir.join(format!("{sha_hex}.bin")))
}

/// Read + decompress + decode a cached payload. Returns `None` when
/// the file is missing, unreadable, or fails to deserialise (the
/// last is treated as a cache miss rather than an error — a bad
/// cache file gets overwritten on the next write).
pub fn load<T: serde::de::DeserializeOwned>(sha_hex: &str) -> Option<T> {
    let path = entry_path(sha_hex)?;
    if !path.exists() {
        return None;
    }
    let compressed = fs::read(&path).ok()?;
    let decompressed = zstd::decode_all(compressed.as_slice()).ok()?;
    serde_json::from_slice::<T>(&decompressed).ok()
}

/// Encode + compress + write a payload atomically. Best-effort —
/// disk failures are swallowed; the cache is a performance
/// optimisation, not a source of truth.
pub fn store<T: serde::Serialize>(sha_hex: &str, value: &T) {
    let Some(path) = entry_path(sha_hex) else {
        return;
    };
    let Ok(serialized) = serde_json::to_vec(value) else {
        return;
    };
    let Ok(compressed) = zstd::encode_all(&serialized[..], 3) else {
        return;
    };
    let tmp = path.with_extension("tmp");
    if let Ok(mut f) = fs::File::create(&tmp) {
        if f.write_all(&compressed).is_ok() {
            let _ = fs::rename(&tmp, &path);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }
}

/// Remove cache directories from schema versions earlier than the
/// current one. Best-effort; failures are ignored.
pub fn prune_old_versions() {
    let Some(root) = cache_root() else {
        return;
    };
    prune_old_versions_in(&root);
}

fn prune_old_versions_in(root: &std::path::Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(ver_str) = name_str.strip_prefix('v') else {
            continue;
        };
        let Ok(ver) = ver_str.parse::<u32>() else {
            continue;
        };
        if ver < CACHE_SCHEMA_VERSION {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Delete current-schema entries last modified longer ago than
/// `max_age`. Best-effort; failures are ignored.
///
/// The cache key folds in the [`build_fingerprint`], so every filefacts
/// rebuild (and every release) mints a fresh key space and orphans the
/// previous build's entries. Those orphans are correct to drop but are
/// not pruned by [`prune_old_versions`] (same schema dir); this ages
/// them out so the cache can't grow without bound across many rebuilds.
/// A long-running consumer calls it once at startup.
pub fn prune_stale(max_age: Duration) {
    let Some(dir) = version_dir() else {
        return;
    };
    let Some(cutoff) = SystemTime::now().checked_sub(max_age) else {
        return;
    };
    let Ok(shards) = fs::read_dir(&dir) else {
        return;
    };
    for shard in shards.flatten() {
        let Ok(entries) = fs::read_dir(shard.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|modified| modified < cutoff);
            if stale {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Whether a freshly computed payload may be persisted to disk.
///
/// Content addressing is only sound when the computation is reproducible
/// from the key. Most degradation in optional disassembly is *stable*
/// for a given environment (rizin absent, a specific version, native-arch
/// slicing) and is handled by the [`cache_key`] `variant`. What remains
/// are *transient* conditions — rizin timed out, was killed on the output
/// cap, was muted by a latency-sensitive caller, or skipped by the size
/// gate. A payload produced under one of those is still usable for the
/// current call but must not be written: persisting it would poison the
/// entry, and every later run — whatever its own rizin setup — would
/// reuse the degraded result.
///
/// `compute` returns [`Cacheable`](Self::Cacheable) for a result that is
/// reproducible from the key, and [`Transient`](Self::Transient) for one
/// that should be returned to the caller but never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Computed<T> {
    /// Reproducible from the key — store it and return it.
    Cacheable(T),
    /// Produced under a transient condition — return it, don't store it.
    Transient(T),
}

impl<T> Computed<T> {
    /// The wrapped value, discarding the persistability tag.
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Computed::Cacheable(v) | Computed::Transient(v) => v,
        }
    }
}

/// Open `bytes` through the disk cache: key → lookup → on miss, run
/// `compute` and store the result *if it is [`Computed::Cacheable`]*.
/// Returns the cached or freshly computed value, or `None` when
/// `compute` itself returns `None`.
///
/// `variant` discriminates inputs whose correct analysis depends on the
/// environment — pass [`crate::rizin::cache_fingerprint`], or `""` when
/// the computation never involves rizin. A [`Computed::Transient`]
/// result is returned to the caller but never written, so a degraded
/// rizin run (timeout, output-cap kill, mute, size gate) cannot poison
/// the entry for a later healthy run.
///
/// The cache key includes the schema version implicitly (it lives in
/// a versioned subdirectory). Callers do not need to vary the key on
/// schema bumps.
pub fn open_with_cache<T, F>(bytes: &[u8], variant: &str, compute: F) -> Option<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce(&[u8]) -> Option<Computed<T>>,
{
    let key = cache_key(bytes, variant);
    if let Some(cached) = load::<T>(&key) {
        return Some(cached);
    }
    match compute(bytes)? {
        Computed::Cacheable(value) => {
            store(&key, &value);
            Some(value)
        }
        Computed::Transient(value) => Some(value),
    }
}

/// Best-effort cache-entry path predicate. Returns `true` when a cached
/// entry for the given bytes under `variant` already exists on disk.
pub fn is_cached(bytes: &[u8], variant: &str) -> bool {
    entry_path(&cache_key(bytes, variant)).is_some_and(|p| p.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_bytes(tag: &str) -> Vec<u8> {
        // Embed the test name + process id + a nanosecond timestamp
        // so two parallel test runs (or repeated invocations of the
        // same test) don't collide on the same sha.
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("filefacts-cache-test:{tag}:{}:{ns}", std::process::id()).into_bytes()
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn round_trip_stores_and_loads_payload() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload {
            n: u32,
            name: String,
        }
        let bytes = unique_bytes("round_trip");
        let original = Payload {
            n: 42,
            name: "rizin-out".into(),
        };
        let sha = sha256_hex(&bytes);
        store(&sha, &original);
        let loaded: Payload = load(&sha).expect("cache should hit immediately after store");
        assert_eq!(loaded, original);
    }

    #[test]
    fn open_with_cache_runs_compute_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload(u32);
        let bytes = unique_bytes("open_with_cache");
        let calls = AtomicU32::new(0);
        let first = open_with_cache::<Payload, _>(&bytes, "", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(Computed::Cacheable(Payload(7)))
        });
        assert_eq!(first, Some(Payload(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second call must hit the cache and not invoke compute.
        let second = open_with_cache::<Payload, _>(&bytes, "", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(Computed::Cacheable(Payload(999))) // never observed
        });
        assert_eq!(second, Some(Payload(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "compute must not re-run");
    }

    #[test]
    fn transient_result_is_returned_but_not_persisted() {
        use std::sync::atomic::{AtomicU32, Ordering};
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload(u32);
        let bytes = unique_bytes("transient");
        let calls = AtomicU32::new(0);
        // A degraded run: the value is handed back to the caller...
        let first = open_with_cache::<Payload, _>(&bytes, "", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(Computed::Transient(Payload(1)))
        });
        assert_eq!(first, Some(Payload(1)));
        // ...but nothing was written, so a second call recomputes rather
        // than serving the poisoned (degraded) entry.
        assert!(!is_cached(&bytes, ""), "transient result must not persist");
        let second = open_with_cache::<Payload, _>(&bytes, "", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(Computed::Cacheable(Payload(2)))
        });
        assert_eq!(second, Some(Payload(2)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "compute must re-run after transient"
        );
    }

    #[test]
    fn variant_partitions_the_key() {
        let bytes = unique_bytes("variant");
        // The key always folds in the build fingerprint, so it is never
        // the bare content hash — that is what invalidates stale entries
        // when filefacts itself changes.
        assert_ne!(cache_key(&bytes, ""), sha256_hex(&bytes));
        // Distinct variants (e.g. rizin present vs. absent) yield
        // distinct keys, so one never serves the other's payload.
        let with_rizin = cache_key(&bytes, "rizin=0.7.2");
        let without = cache_key(&bytes, "rizin=none");
        assert_ne!(with_rizin, without);
        assert_ne!(with_rizin, cache_key(&bytes, ""));
        // Stable for a fixed (bytes, variant) pair within a build.
        assert_eq!(with_rizin, cache_key(&bytes, "rizin=0.7.2"));
    }

    #[test]
    fn distinct_variants_do_not_share_entries() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload(u32);
        let bytes = unique_bytes("variant_isolation");
        let a = open_with_cache::<Payload, _>(&bytes, "rizin=none", |_| {
            Some(Computed::Cacheable(Payload(10)))
        });
        assert_eq!(a, Some(Payload(10)));
        // A run under a different fingerprint must miss and recompute,
        // not reuse the no-rizin payload.
        let b = open_with_cache::<Payload, _>(&bytes, "rizin=0.7.2", |_| {
            Some(Computed::Cacheable(Payload(20)))
        });
        assert_eq!(b, Some(Payload(20)));
    }

    #[test]
    fn missing_entry_loads_to_none() {
        // SHA of bytes we never wrote.
        let sha = sha256_hex(&unique_bytes("missing"));
        let v: Option<u32> = load(&sha);
        assert!(v.is_none());
    }

    #[test]
    fn prune_old_versions_removes_lower_versions() {
        // Create a synthetic `v0` directory in a private temp root and
        // confirm prune removes it without mutating process-global env.
        let tmp = tempfile::tempdir().expect("tempdir");
        let old = tmp.path().join("v0");
        fs::create_dir_all(&old).expect("create v0");
        let canary = old.join("canary");
        fs::write(&canary, b"old").expect("write canary");
        assert!(canary.exists());
        prune_old_versions_in(tmp.path());
        assert!(!canary.exists(), "v0 canary should be removed");
    }
}
