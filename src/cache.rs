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
//! version dirs.
//!
//! # Retention
//!
//! Within the current version dir the cache is bounded by entry count:
//! [`enforce_limits`] evicts the oldest entries once the total passes
//! [`DEFAULT_MAX_ITEMS`], down to 90% of the cap. A cache *hit* bumps an
//! entry's mtime ([`load`]), so eviction is least-recently-*used*, not
//! merely oldest-written — the same count+LRU model cleave's analysis
//! cache uses, so the two projects bound their caches consistently.
//! [`cleanup`] runs the sweep on a background thread — the entry point a
//! consumer calls at startup — and an on-write trigger kicks off the same
//! sweep when a store pushes the cache over the ceiling mid-run.
//! Everything here is best-effort: the cache is a performance
//! optimisation, never a source of truth.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI8, AtomicUsize, Ordering};
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

/// Root cache directory for filefacts. Returns the writable OS/user cache dir,
/// or `None` when no user cache directory is available.
pub fn cache_root() -> Option<PathBuf> {
    let c = dirs::cache_dir()?.join("atomdrift").join("filefacts");
    if fs::create_dir_all(&c).is_ok() {
        let probe = c.join(".write-test");
        if fs::write(&probe, b"ok").is_ok() {
            let _ = fs::remove_file(&probe);
            return Some(c);
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
    load_from_path(&path)
}

/// Read one cache entry from an already-resolved path.
fn load_from_path<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    // One open serves both the read and the mtime probe that drives LRU
    // eviction; a missing/unreadable entry is a plain cache miss.
    let mut file = fs::File::open(path).ok()?;
    let mtime = file.metadata().and_then(|m| m.modified()).ok();
    let mut compressed = Vec::new();
    file.read_to_end(&mut compressed).ok()?;
    drop(file);
    // LRU: bump the entry's mtime so `enforce_limits` evicts the
    // least-recently-*used*, not merely the oldest-written. Best-effort
    // and relatime-style — see [`touch_lru`].
    if let Some(mtime) = mtime {
        touch_lru(path, mtime);
    }
    let decompressed = zstd::decode_all(compressed.as_slice()).ok()?;
    serde_json::from_slice::<T>(&decompressed).ok()
}

/// Coarse granularity for the LRU mtime bump in [`load`]. A hit only
/// rewrites the entry's mtime when it is already older than this, so an
/// entry read repeatedly costs at most one metadata write per window
/// rather than one per read. A day is fine enough to order eviction
/// candidates while leaving the common hot-entry hit a pure read.
const LRU_TOUCH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Best-effort relatime-style LRU touch: set `path`'s mtime to now, but
/// only when its current mtime is already at least [`LRU_TOUCH_INTERVAL`]
/// stale. Skips the metadata write for entries used within the window and
/// silently tolerates a read-only cache (the touch simply doesn't happen).
fn touch_lru(path: &Path, current_mtime: SystemTime) {
    let now = SystemTime::now();
    if now
        .duration_since(current_mtime)
        .is_ok_and(|age| age >= LRU_TOUCH_INTERVAL)
    {
        // `write(true)` opens for attribute writes without truncating;
        // `create` is off, so a vanished entry is not resurrected.
        if let Ok(f) = fs::OpenOptions::new().write(true).open(path) {
            let _ = f.set_modified(now);
        }
    }
}

/// Encode + compress + write a payload atomically. Best-effort —
/// disk failures are swallowed; the cache is a performance
/// optimisation, not a source of truth.
pub fn store<T: serde::Serialize>(sha_hex: &str, value: &T) {
    let Some(path) = entry_path(sha_hex) else {
        return;
    };
    store_at_path(&path, value);
}

/// Write one cache entry to an already-resolved path.
fn store_at_path<T: serde::Serialize>(path: &Path, value: &T) {
    let Ok(serialized) = serde_json::to_vec(value) else {
        return;
    };
    let Ok(compressed) = zstd::encode_all(&serialized[..], 3) else {
        return;
    };
    let tmp = path.with_extension("tmp");
    if let Ok(mut f) = fs::File::create(&tmp) {
        if f.write_all(&compressed).is_ok() {
            let _ = fs::rename(&tmp, path);
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

/// Number of two-hex-character shard directories under a version dir.
/// Cache keys are SHA-256 hex, so entries distribute uniformly across
/// these; the count lets a single-shard sample estimate the whole.
const SHARD_COUNT: usize = 256;

/// Default ceiling on retained cache entries. On reaching it, the oldest
/// (least-recently-used) entries are evicted; see [`enforce_limits`].
pub const DEFAULT_MAX_ITEMS: usize = 16_000;

/// Post-eviction target as a fraction of the cap (9/10). Evicting to 90%
/// rather than exactly to the cap stops a cache sitting at the ceiling from
/// re-triggering a sweep on the very next store. Mirrors cleave's analysis
/// cache so the two projects bound their caches identically.
const EVICTION_TARGET_NUM: usize = 9;
const EVICTION_TARGET_DEN: usize = 10;

/// Entries older than this are evicted regardless of the count/byte caps, so
/// nothing lingers forever. Uses mtime, which [`load`] bumps on a hit, so a
/// still-used entry is never dropped for age alone. 30 days.
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Disk ceiling for the cache; over it, the oldest entries are evicted to 90%.
/// The item cap usually binds first — this bounds the pathological case of a
/// few very large entries. 2 GiB.
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// Process-wide item cap, read by both the startup sweep and the on-write
// trigger so a single `set_max_items` reconfigures every cleanup path.
static MAX_ITEMS: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_ITEMS);

/// Set the process-wide cache item cap. A consumer that wants a larger or
/// smaller cache calls this once at startup, before the first [`cleanup`];
/// [`DEFAULT_MAX_ITEMS`] applies otherwise.
pub fn set_max_items(max_items: usize) {
    MAX_ITEMS.store(max_items, Ordering::Relaxed);
}

/// The currently configured item cap.
#[must_use]
pub fn max_items() -> usize {
    MAX_ITEMS.load(Ordering::Relaxed)
}

/// Guards against overlapping sweeps: at most one enforcement pass runs at
/// a time, whether kicked off at startup or by an on-write trigger.
static SWEEP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Prune superseded schema versions and enforce the item cap on a
/// background thread, returning immediately. This is the entry point a
/// consumer calls at startup — one non-blocking call covers all cleanup.
///
/// Best-effort: a short-lived process may exit before the sweep finishes (a
/// detached thread dies with the process), and the next run resumes the
/// work; a long-lived consumer always sees it through. At most one sweep
/// runs at a time, so repeated calls are cheap no-ops while one is in flight.
pub fn cleanup() {
    spawn_sweep(max_items());
    // Also reclaim stng's on-disk caches. filefacts fills stng's string cache
    // during extraction, and — unlike filefacts' own cache — nothing else prunes
    // it in a filefacts- or cleave-only process (cleave routes its startup
    // cleanup through here). Best-effort, self-gated to once a day, non-blocking.
    stng::cache_sweep::spawn(vec![stng::cache_sweep::stng_budget()]);
}

/// Claim the sweep guard and run the cleanup passes on a detached thread.
/// Silent no-op if a sweep is already running or the thread fails to spawn.
fn spawn_sweep(max_items: usize) {
    if SWEEP_RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("filefacts-cache-sweep".into())
        .spawn(move || {
            prune_old_versions();
            enforce_limits(max_items);
            SWEEP_RUNNING.store(false, Ordering::Release);
        });
    if spawned.is_err() {
        SWEEP_RUNNING.store(false, Ordering::Release);
    }
}

/// Cheap on-write trigger: after storing a fresh entry, sample only its
/// own shard directory. A store follows a cache *miss* — i.e. an expensive
/// compute — so one `read_dir` here is negligible, and once a sweep is
/// running the sample is skipped entirely. If this shard alone holds well
/// more than its uniform share of the cap, the whole cache is over the
/// ceiling; hand off to a background sweep, which counts for real before
/// evicting.
fn maybe_trigger_sweep(sha_hex: &str) {
    // Keep filefacts' own test runs from sweeping the developer's real
    // cache as a side effect of a direct `store`/`open_with_cache` call.
    if cfg!(test) || SWEEP_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    let max_items = max_items();
    // 1.5× the per-shard mean: enough slack that a shard crossing it
    // reliably implies the whole cache is over, not just Poisson noise.
    let per_shard_trigger = max_items / SHARD_COUNT * 3 / 2 + 1;
    let (Some(dir), Some(shard)) = (version_dir(), sha_hex.get(..2)) else {
        return;
    };
    let count = fs::read_dir(dir.join(shard)).map_or(0, |it| it.flatten().count());
    if count > per_shard_trigger {
        spawn_sweep(max_items);
    }
}

/// Enforce the cache's bounds synchronously, best-effort (failures ignored):
///
/// 1. Drop entries older than [`MAX_AGE`] (the 30-day TTL). mtime is
///    least-recently-*used* — [`load`] bumps it on a hit — so a still-used
///    entry is never dropped for age alone.
/// 2. If the cache still exceeds `max_items` entries or [`MAX_BYTES`] on disk,
///    evict the oldest until both are within 90% of their caps.
///
/// The cache key folds in the [`build_fingerprint`], so every filefacts rebuild
/// orphans the previous build's entries; because those orphans are never read
/// again their mtime never advances, so they age out and are evicted first.
/// Prefer [`cleanup`], which runs this off the hot path.
pub fn enforce_limits(max_items: usize) {
    let Some(dir) = version_dir() else {
        return;
    };
    enforce_limits_in(&dir, max_items, MAX_BYTES);
}

fn enforce_limits_in(version_dir: &Path, max_items: usize, max_bytes: u64) {
    let Ok(shards) = fs::read_dir(version_dir) else {
        return;
    };
    // One transient (path, mtime, bytes) per live entry — a few MB at the
    // default ceiling, freed as soon as the sweep returns.
    let mut entries: Vec<(PathBuf, SystemTime, u64)> = Vec::new();
    for shard in shards.flatten() {
        let Ok(files) = fs::read_dir(shard.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            // Manage only finished entries; skip in-flight `.tmp` writes
            // and any stray non-entry files.
            if path.extension().is_none_or(|ext| ext != "bin") {
                continue;
            }
            let Ok(meta) = file.metadata() else {
                continue;
            };
            let Ok(mtime) = meta.modified() else {
                continue;
            };
            entries.push((path, mtime, meta.len()));
        }
    }

    // Age pass: drop anything past the TTL outright, whatever the counts.
    let now = SystemTime::now();
    entries.retain(|(path, mtime, _)| {
        if now.duration_since(*mtime).unwrap_or_default() > MAX_AGE {
            let _ = fs::remove_file(path);
            false
        } else {
            true
        }
    });

    // Count/byte pass: over either ceiling → evict oldest to 90% of both.
    let mut total_bytes: u64 = entries.iter().map(|&(_, _, bytes)| bytes).sum();
    if entries.len() > max_items || total_bytes > max_bytes {
        // Oldest (least-recently-used) first.
        entries.sort_unstable_by_key(|&(_, mtime, _)| mtime);
        // Divide before multiplying so a huge `max_items` (e.g. `set_max_items`
        // with `usize::MAX`) can't overflow; mirrors `byte_target` below.
        let count_target = max_items / EVICTION_TARGET_DEN * EVICTION_TARGET_NUM;
        let byte_target = max_bytes / 10 * 9;
        let mut count = entries.len();
        for (path, _, bytes) in &entries {
            if count <= count_target && total_bytes <= byte_target {
                break;
            }
            if fs::remove_file(path).is_ok() {
                count -= 1;
                total_bytes = total_bytes.saturating_sub(*bytes);
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
    open_with_cache_in(bytes, variant, entry_path, maybe_trigger_sweep, compute)
}

fn open_with_cache_in<T, F, P, S>(
    bytes: &[u8],
    variant: &str,
    path_for: P,
    after_store: S,
    compute: F,
) -> Option<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce(&[u8]) -> Option<Computed<T>>,
    P: FnOnce(&str) -> Option<PathBuf>,
    S: FnOnce(&str),
{
    let key = cache_key(bytes, variant);
    let path = path_for(&key);
    if let Some(cached) = path.as_deref().and_then(load_from_path::<T>) {
        return Some(cached);
    }
    match compute(bytes)? {
        Computed::Cacheable(value) => {
            if let Some(path) = path {
                store_at_path(&path, &value);
            }
            // A store means the cache just grew; cheaply check whether it
            // has crossed the item ceiling and, if so, sweep in the
            // background. Kept out of `store` so a direct `store` call
            // (e.g. in tests) has no cleanup side effect.
            after_store(&key);
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

    fn test_entry_path(root: &Path, sha_hex: &str) -> Option<PathBuf> {
        let shard = root.join(sha_hex.get(..2)?);
        fs::create_dir_all(&shard).ok()?;
        Some(shard.join(format!("{sha_hex}.bin")))
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
        let tmp = tempfile::tempdir().expect("tempdir");
        let sha = sha256_hex(&bytes);
        let path = test_entry_path(tmp.path(), &sha).expect("cache path");
        store_at_path(&path, &original);
        let loaded: Payload =
            load_from_path(&path).expect("cache should hit immediately after store");
        assert_eq!(loaded, original);
    }

    #[test]
    fn open_with_cache_runs_compute_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload(u32);
        let bytes = unique_bytes("open_with_cache");
        let tmp = tempfile::tempdir().expect("tempdir");
        let calls = AtomicU32::new(0);
        let first = open_with_cache_in::<Payload, _, _, _>(
            &bytes,
            "",
            |key| test_entry_path(tmp.path(), key),
            |_| {},
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(Computed::Cacheable(Payload(7)))
            },
        );
        assert_eq!(first, Some(Payload(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second call must hit the cache and not invoke compute.
        let second = open_with_cache_in::<Payload, _, _, _>(
            &bytes,
            "",
            |key| test_entry_path(tmp.path(), key),
            |_| {},
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(Computed::Cacheable(Payload(999))) // never observed
            },
        );
        assert_eq!(second, Some(Payload(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "compute must not re-run");
    }

    #[test]
    fn transient_result_is_returned_but_not_persisted() {
        use std::sync::atomic::{AtomicU32, Ordering};
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload(u32);
        let bytes = unique_bytes("transient");
        let tmp = tempfile::tempdir().expect("tempdir");
        let calls = AtomicU32::new(0);
        // A degraded run: the value is handed back to the caller...
        let first = open_with_cache_in::<Payload, _, _, _>(
            &bytes,
            "",
            |key| test_entry_path(tmp.path(), key),
            |_| {},
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(Computed::Transient(Payload(1)))
            },
        );
        assert_eq!(first, Some(Payload(1)));
        // ...but nothing was written, so a second call recomputes rather
        // than serving the poisoned (degraded) entry.
        let path = test_entry_path(tmp.path(), &cache_key(&bytes, "")).expect("cache path");
        assert!(!path.exists(), "transient result must not persist");
        let second = open_with_cache_in::<Payload, _, _, _>(
            &bytes,
            "",
            |key| test_entry_path(tmp.path(), key),
            |_| {},
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(Computed::Cacheable(Payload(2)))
            },
        );
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
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = open_with_cache_in::<Payload, _, _, _>(
            &bytes,
            "rizin=none",
            |key| test_entry_path(tmp.path(), key),
            |_| {},
            |_| Some(Computed::Cacheable(Payload(10))),
        );
        assert_eq!(a, Some(Payload(10)));
        // A run under a different fingerprint must miss and recompute,
        // not reuse the no-rizin payload.
        let b = open_with_cache_in::<Payload, _, _, _>(
            &bytes,
            "rizin=0.7.2",
            |key| test_entry_path(tmp.path(), key),
            |_| {},
            |_| Some(Computed::Cacheable(Payload(20))),
        );
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

    /// Create a `.bin` entry and stamp it with an explicit mtime.
    fn entry_with_mtime(shard: &Path, name: &str, mtime: SystemTime) -> PathBuf {
        let path = shard.join(name);
        fs::write(&path, b"x").expect("write entry");
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for mtime")
            .set_modified(mtime)
            .expect("set mtime");
        path
    }

    #[test]
    fn enforce_limits_evicts_oldest_to_ninety_percent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shard = tmp.path().join("ab");
        fs::create_dir_all(&shard).expect("shard");
        let now = SystemTime::now();
        // Thirteen entries, mtime ascending with index: 00 is the oldest
        // (least-recently-used), 12 the newest.
        let paths: Vec<PathBuf> = (0..13u64)
            .map(|i| {
                entry_with_mtime(
                    &shard,
                    &format!("{i:02}.bin"),
                    now - Duration::from_secs((13 - i) * 3600),
                )
            })
            .collect();
        // Cap 10 → evict down to 90% (9), so the 4 oldest go.
        enforce_limits_in(tmp.path(), 10, MAX_BYTES);
        for (i, p) in paths.iter().enumerate() {
            if i < 4 {
                assert!(!p.exists(), "entry {i:02} (oldest) should be evicted");
            } else {
                assert!(p.exists(), "entry {i:02} (newer) should be kept");
            }
        }
    }

    #[test]
    fn enforce_limits_drops_entries_past_ttl() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shard = tmp.path().join("ab");
        fs::create_dir_all(&shard).expect("shard");
        let now = SystemTime::now();
        // Both well under the item cap, so only the age pass can act.
        let stale = entry_with_mtime(&shard, "stale.bin", now - MAX_AGE - Duration::from_secs(1));
        let fresh = entry_with_mtime(&shard, "fresh.bin", now - Duration::from_secs(3600));
        enforce_limits_in(tmp.path(), 10_000, MAX_BYTES);
        assert!(!stale.exists(), "entry past the 30d TTL is evicted");
        assert!(fresh.exists(), "a recently-used entry is kept");
    }

    #[test]
    fn enforce_limits_evicts_oldest_over_byte_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shard = tmp.path().join("ab");
        fs::create_dir_all(&shard).expect("shard");
        let now = SystemTime::now();
        // Five 400-byte entries (2000 total), all under the item cap and the
        // 30d TTL. Byte cap 1000 → target 900, so the 3 oldest are evicted.
        let paths: Vec<PathBuf> = (0..5u64)
            .map(|i| {
                let path = shard.join(format!("{i}.bin"));
                fs::write(&path, vec![b'x'; 400]).expect("write");
                fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("open")
                    .set_modified(now - Duration::from_secs((5 - i) * 3600))
                    .expect("mtime");
                path
            })
            .collect();
        enforce_limits_in(tmp.path(), 10_000, 1000);
        assert!(!paths[0].exists(), "oldest evicted for byte cap");
        assert!(!paths[1].exists());
        assert!(!paths[2].exists());
        assert!(paths[3].exists(), "newest kept");
        assert!(paths[4].exists());
    }

    #[test]
    fn enforce_limits_noop_under_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shard = tmp.path().join("cd");
        fs::create_dir_all(&shard).expect("shard");
        let now = SystemTime::now();
        let kept: Vec<PathBuf> = (0..5u64)
            .map(|i| entry_with_mtime(&shard, &format!("{i}.bin"), now))
            .collect();
        enforce_limits_in(tmp.path(), 100, MAX_BYTES);
        assert!(kept.iter().all(|p| p.exists()), "nothing evicted under cap");
    }

    #[test]
    fn enforce_limits_ignores_inflight_tmp() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shard = tmp.path().join("ef");
        fs::create_dir_all(&shard).expect("shard");
        // An in-flight write under the most aggressive cap: it is not a
        // finished `.bin`, so it must survive.
        let inflight = entry_with_mtime(&shard, "partial.tmp", SystemTime::now());
        enforce_limits_in(tmp.path(), 0, MAX_BYTES);
        assert!(
            inflight.exists(),
            "a non-.bin in-flight write is never swept"
        );
    }

    #[test]
    fn touch_lru_bumps_a_stale_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let old = SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        let path = entry_with_mtime(tmp.path(), "e.bin", old);
        touch_lru(&path, old);
        let after = fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime");
        assert!(
            after > old + LRU_TOUCH_INTERVAL,
            "a stale entry's mtime is bumped toward now on use"
        );
    }

    #[test]
    fn touch_lru_leaves_a_recent_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let recent = SystemTime::now() - Duration::from_secs(60);
        let path = entry_with_mtime(tmp.path(), "e.bin", recent);
        touch_lru(&path, recent);
        let after = fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime");
        let drift = after.duration_since(recent).unwrap_or_default();
        assert!(
            drift < Duration::from_secs(5),
            "an entry used within the window is not rewritten"
        );
    }
}
