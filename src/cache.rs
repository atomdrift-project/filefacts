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
//! {cache_dir}/atomdrift/filefacts/v{CACHE_SCHEMA_VERSION}/{key[0..2]}/{key}.bin
//! ```
//!
//! On the host platforms this resolves (via [`dirs::cache_dir`]) to the
//! idiomatic per-OS cache root: `~/Library/Caches/atomdrift/filefacts`
//! (macOS), `~/.cache/atomdrift/filefacts` (Linux/XDG),
//! `%LOCALAPPDATA%\atomdrift\filefacts` (Windows). The two-character
//! shard keeps any single directory bounded. Lookups never create
//! directories; a shard appears with the first entry stored in it.
//!
//! # Format
//!
//! `serde_json`-encoded payload, then zstd-compressed at level 3. JSON
//! (not a positional format like bincode) is deliberate: the cached
//! types carry `#[serde(skip_serializing_if)]` fields, which a
//! self-describing format round-trips correctly and a positional one
//! silently corrupts. Writes go through a uniquely named `.tmp*` file in
//! the shard followed by an atomic rename, so two processes hashing the
//! same input cannot corrupt the entry.
//!
//! # Invalidation
//!
//! The cache key is `sha256(content ∥ build_fingerprint ∥ variant)`:
//!
//! * **content** — the input bytes.
//! * **`build_fingerprint`** — filefacts' crate version and a hash of its
//!   source (`src/**` plus `Cargo.lock`), computed by `build.rs` at compile
//!   time. Any change to the extraction logic changes the hash and so
//!   retires every prior entry without a manual bump, however the
//!   consuming binary was built, copied or packaged.
//! * **variant** — what else the extraction depends on: for a
//!   [`crate::ParsedFile`], the detected type, the basename and
//!   [`crate::OpenOptions::rizin_fingerprint`] (whether rizin runs, its
//!   version, native-arch slicing, the size cap).
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
//! sweep when a store pushes the cache over the ceiling mid-run. The
//! sweep also removes temp files orphaned by a writer that died before its
//! rename. Everything here is best-effort: the cache is a performance
//! optimisation, never a source of truth.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

/// The `FILEFACTS_CACHE` environment setting: `Some(false)` for `0` or
/// `false` (any case), `Some(true)` for any other value, `None` when unset.
///
/// The one place filefacts reads its environment for configuration. It feeds
/// [`crate::OpenOptions::new`]'s cache default, so an operator can turn the
/// cache on or off for a library host without a recompile; an explicit
/// [`crate::OpenOptions::cache`] outranks it. A host that wants the cache on
/// unless the operator says otherwise — the `filefacts` CLI — passes
/// `env_override().unwrap_or(true)`. Read once per process: the environment
/// is fixed at start, and this runs once per opened file.
#[must_use]
pub fn env_override() -> Option<bool> {
    static ENV: OnceLock<Option<bool>> = OnceLock::new();
    *ENV.get_or_init(|| {
        std::env::var("FILEFACTS_CACHE")
            .ok()
            .map(|v| parse_env_setting(&v))
    })
}

fn parse_env_setting(value: &str) -> bool {
    !(value == "0" || value.eq_ignore_ascii_case("false"))
}

/// On-disk cache schema version. Bump only on a deliberate, breaking
/// change to the on-disk *format* (not ordinary payload-field additions —
/// the build fingerprint in [`cache_key`] already retires stale entries
/// when extraction logic changes). Version 6 moved the payload from
/// positional bincode to self-describing JSON and folded the build
/// fingerprint into the key.
pub const CACHE_SCHEMA_VERSION: u32 = 6;

/// Build identity mixed into every cache key: `{crate version}+{source
/// hash}`, where `build.rs` hashes the crate's `src/**` and `Cargo.lock`.
///
/// Derived from the source rather than the running executable, so it holds
/// where an mtime would not: an embedding host whose own binary is not
/// filefacts, Nix store paths (mtime 1), `cp -p` and container layers.
const BUILD_FINGERPRINT: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("FILEFACTS_SOURCE_HASH")
);

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
/// * the filefacts build fingerprint — extraction logic changes
///   between builds, so a stale entry from an older filefacts must not be
///   reused;
/// * the caller's `variant` — the detected file type plus
///   [`crate::OpenOptions::rizin_fingerprint`] (whether rizin runs, its
///   version, native-arch slicing, the size cap), since the *same* bytes
///   yield different extraction under different path-assisted types or
///   rizin configurations.
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
    hasher.update(BUILD_FINGERPRINT.as_bytes());
    hasher.update([0u8]);
    hasher.update(variant.as_bytes());
    hex(&hasher.finalize())
}

/// `{cache_dir}/atomdrift/filefacts`, resolved once per process. Pure path
/// computation: nothing is created or probed.
fn root_location() -> Option<&'static Path> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(|| {
        // filefacts' own unit tests that open with `cache(true)` must not
        // read or write the developer's real cache: give each test process
        // a private root, removed by nothing but the OS's temp cleanup.
        if cfg!(test) {
            return Some(
                std::env::temp_dir().join(format!("filefacts-unit-cache-{}", std::process::id())),
            );
        }
        Some(dirs::cache_dir()?.join("atomdrift").join("filefacts"))
    })
    .as_deref()
}

/// Root cache directory for filefacts. Returns the writable OS/user cache dir,
/// or `None` when no user cache directory is available. Created and probed
/// for writability once per process; later calls return the first answer.
pub fn cache_root() -> Option<PathBuf> {
    static WRITABLE: OnceLock<Option<PathBuf>> = OnceLock::new();
    WRITABLE
        .get_or_init(|| {
            let root = root_location()?;
            fs::create_dir_all(root).ok()?;
            // An anonymous temp file: nothing to clean up, and nothing left
            // behind if the process dies mid-probe.
            tempfile::tempfile_in(root).ok()?;
            Some(root.to_path_buf())
        })
        .clone()
}

/// `v{CACHE_SCHEMA_VERSION}` under `root`.
fn version_location(root: &Path) -> PathBuf {
    root.join(format!("v{CACHE_SCHEMA_VERSION}"))
}

/// Where the entry for `sha_hex` lives under `root`. Pure path computation,
/// so a lookup that misses leaves no directories behind; [`store_at_path`]
/// creates the shard when it writes.
fn entry_location(root: &Path, sha_hex: &str) -> Option<PathBuf> {
    let shard = sha_hex.get(..2)?;
    Some(
        version_location(root)
            .join(shard)
            .join(format!("{sha_hex}.bin")),
    )
}

/// Directory holding cache entries for the current schema version, created
/// if missing.
pub fn version_dir() -> Option<PathBuf> {
    let dir = version_location(&cache_root()?);
    fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Full on-disk path for a cache entry with the given SHA-256 hex
/// digest. Creates the two-char shard directory if missing; [`load`] and
/// [`is_cached`] resolve the same path without creating anything.
pub fn entry_path(sha_hex: &str) -> Option<PathBuf> {
    let path = entry_location(&cache_root()?, sha_hex)?;
    fs::create_dir_all(path.parent()?).ok()?;
    Some(path)
}

/// Read + decompress + decode a cached payload. Returns `None` when
/// the file is missing, unreadable, or fails to deserialise (the
/// last is treated as a cache miss rather than an error — a bad
/// cache file gets overwritten on the next write).
pub fn load<T: serde::de::DeserializeOwned>(sha_hex: &str) -> Option<T> {
    load_from_path(&entry_location(root_location()?, sha_hex)?)
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
const LRU_TOUCH_INTERVAL: Duration = Duration::from_hours(24);

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
    let Some(path) = root_location().and_then(|root| entry_location(root, sha_hex)) else {
        return;
    };
    store_at_path(&path, value);
}

/// Name prefix of the temp files [`store_at_path`] writes through. Spelled
/// out (it is also `tempfile`'s default) because the sweep matches on it.
const TEMP_PREFIX: &str = ".tmp";

/// Create the temp file a store writes through, in the entry's shard.
fn temp_in(dir: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(dir)
}

/// Write one cache entry to an already-resolved path, creating its shard
/// directory if needed.
fn store_at_path<T: serde::Serialize>(path: &Path, value: &T) {
    let Ok(serialized) = serde_json::to_vec(value) else {
        return;
    };
    let Ok(compressed) = zstd::encode_all(&serialized[..], 3) else {
        return;
    };
    // A uniquely named sibling, not `path.with_extension("tmp")`: two
    // processes storing the same key would otherwise write through one temp
    // file and could rename a mix of both into place. Dropped unpersisted,
    // the temp file deletes itself.
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(mut tmp) = temp_in(dir) else {
        return;
    };
    if tmp.write_all(&compressed).is_ok() {
        let _ = tmp.persist(path);
    }
}

/// Remove cache directories from schema versions earlier than the
/// current one. Best-effort; failures are ignored.
pub fn prune_old_versions() {
    let Some(root) = root_location() else {
        return;
    };
    prune_old_versions_in(root);
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
///
/// Shared with [`crate::cache_sweep`] and fletch's copy of it, so every atomdrift cache
/// quotes one ceiling.
pub const DEFAULT_MAX_ITEMS: usize = 16_384;

/// Post-eviction target as a fraction of the cap (9/10). Evicting to 90%
/// rather than exactly to the cap stops a cache sitting at the ceiling from
/// re-triggering a sweep on the very next store. Mirrors cleave's analysis
/// cache so the two projects bound their caches identically.
const EVICTION_TARGET_NUM: usize = 9;
const EVICTION_TARGET_DEN: usize = 10;

/// Entries older than this are evicted regardless of the count/byte caps, so
/// nothing lingers forever. Uses mtime, which [`load`] bumps on a hit, so a
/// still-used entry is never dropped for age alone. 30 days.
const MAX_AGE: Duration = Duration::from_hours(30 * 24);

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
    // Age out stng's on-disk string cache. filefacts no longer writes it (the
    // rows live in this cache's snapshots), but earlier builds filled it and
    // nothing else prunes it in a filefacts- or cleave-only process. Drop this
    // once the leftovers have aged out. Best-effort, self-gated to once a day,
    // non-blocking.
    crate::cache_sweep::spawn(vec![crate::cache_sweep::legacy_stng_budget()]);
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
    let (Some(root), Some(shard)) = (root_location(), sha_hex.get(..2)) else {
        return;
    };
    let count =
        fs::read_dir(version_location(root).join(shard)).map_or(0, |it| it.flatten().count());
    if count > per_shard_trigger {
        spawn_sweep(max_items);
    }
}

/// Enforce the cache's bounds synchronously, best-effort (failures ignored):
///
/// 1. Drop entries older than the 30-day TTL. mtime is
///    least-recently-*used* — [`load`] bumps it on a hit — so a still-used
///    entry is never dropped for age alone.
/// 2. If the cache still exceeds `max_items` entries or the on-disk byte cap,
///    evict the oldest until both are within 90% of their caps.
///
/// Temp files older than 15 minutes are removed along the way: they were
/// left by a writer that died before its rename.
///
/// The cache key folds in the build fingerprint, so every change to
/// filefacts' source orphans the previous build's entries; because those
/// orphans are never read again their mtime never advances, so they age out
/// and are evicted first. Prefer [`cleanup`], which runs this off the hot
/// path.
pub fn enforce_limits(max_items: usize) {
    let Some(root) = root_location() else {
        return;
    };
    enforce_limits_in(&version_location(root), max_items, MAX_BYTES);
}

/// A temp file this old was orphaned by a writer that died before its
/// rename: a live store creates, writes and renames it within moments.
const ORPHANED_TEMP_AGE: Duration = Duration::from_mins(15);

/// Whether `name` is a store's temp file: [`TEMP_PREFIX`], or the
/// `{key}.tmp` sibling that builds before the uniquely named temp files
/// wrote into the same version dir.
fn is_temp_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|n| n.starts_with(TEMP_PREFIX) || n.ends_with(".tmp"))
}

fn enforce_limits_in(version_dir: &Path, max_items: usize, max_bytes: u64) {
    let Ok(shards) = fs::read_dir(version_dir) else {
        return;
    };
    let now = SystemTime::now();
    // One transient (path, mtime, bytes) per live entry — a few MB at the
    // default ceiling, freed as soon as the sweep returns.
    let mut entries: Vec<(PathBuf, SystemTime, u64)> = Vec::new();
    for shard in shards.flatten() {
        let Ok(files) = fs::read_dir(shard.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            let is_entry = path.extension().is_some_and(|ext| ext == "bin");
            let is_temp = !is_entry && is_temp_name(&file.file_name());
            // Manage finished entries and temp files; leave any stray
            // non-entry file alone.
            if !is_entry && !is_temp {
                continue;
            }
            let Ok(meta) = file.metadata() else {
                continue;
            };
            let Ok(mtime) = meta.modified() else {
                continue;
            };
            if is_entry {
                entries.push((path, mtime, meta.len()));
            } else if now.duration_since(mtime).unwrap_or_default() > ORPHANED_TEMP_AGE {
                // A recent temp file may be an in-flight write; keep it.
                let _ = fs::remove_file(&path);
            }
        }
    }

    // Age pass: drop anything past the TTL outright, whatever the counts.
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
/// for a given environment and settings (rizin absent or turned off, a
/// specific version, native-arch slicing, the size cap) and is handled by
/// the [`cache_key`] `variant`. What remains are *transient* conditions —
/// rizin timed out, was killed on the output cap, or turned itself off
/// after too many abandoned output readers. A payload produced under one of those is still usable for the
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
/// environment — pass [`crate::OpenOptions::rizin_fingerprint`], or `""` when
/// the computation never involves rizin. A [`Computed::Transient`]
/// result is returned to the caller but never written, so a degraded
/// rizin run (timeout, output-cap kill) cannot poison
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
    open_with_cache_in(
        bytes,
        variant,
        |key| entry_location(root_location()?, key),
        maybe_trigger_sweep,
        compute,
    )
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
/// Read-only: creates nothing.
pub fn is_cached(bytes: &[u8], variant: &str) -> bool {
    root_location()
        .and_then(|root| entry_location(root, &cache_key(bytes, variant)))
        .is_some_and(|p| p.exists())
}

#[cfg(test)]
mod tests;
