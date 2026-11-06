//! Disk cache for filefacts analysis output.
//!
//! The canonical store for an [`crate::ParsedFile`]'s extraction. Its reason
//! to exist is the binform disassembly pass: function recovery on a stripped
//! binary costs real time, and the recovered imports, exports, functions and
//! sections land in the cached payload, so a second `open` of the same bytes
//! never re-runs recovery.
//!
//! The cache is off unless the host turns it on with
//! [`crate::OpenOptions::cache`]. Nothing here reads the environment on its
//! own: [`env_override`] is a helper for a host that chooses to let
//! `FILEFACTS_CACHE` decide.
//!
//! # Layout
//!
//! ```text
//! {base}/filefacts/CACHEDIR.TAG
//! {base}/filefacts/v{CACHE_SCHEMA_VERSION}/{key[0..2]}/{key}.bin
//! ```
//!
//! `base` is the directory the host named with
//! [`crate::OpenOptions::cache_dir`], or by default `atomdrift` under the
//! per-user cache directory: `~/Library/Caches` (macOS), `$XDG_CACHE_HOME`
//! or `~/.cache` (other Unix), `%LOCALAPPDATA%` (Windows). The cache
//! works only inside the `filefacts` directory it creates there, private to
//! the user and marked with a [cache directory tag]; it never prunes, sweeps
//! or writes anywhere else in `base`, and it leaves alone a `filefacts`
//! directory it did not tag. The two-character shard keeps any single
//! directory bounded. Lookups create no directories below the root; a shard
//! appears with the first entry stored in it.
//!
//! [cache directory tag]: https://bford.info/cachedir/
//!
//! # Format
//!
//! `serde_json`-encoded payload, then zstd-compressed at level 3. JSON (not a
//! positional format like bincode) is deliberate: the cached types carry
//! `#[serde(skip_serializing_if)]` fields, which a self-describing format
//! round-trips correctly and a positional one silently corrupts. Writes go
//! through a uniquely named `.tmp*` file in the shard followed by an atomic
//! rename, so two processes hashing the same input cannot corrupt the entry.
//!
//! # Invalidation
//!
//! The cache key is `sha256(content ∥ build_fingerprint ∥ variant)`:
//!
//! * **content** — the input bytes.
//! * **`build_fingerprint`** — filefacts' crate version and a hash of its
//!   source (`src/**`, `Cargo.toml` and filefacts' own `Cargo.lock`),
//!   computed by `build.rs` at compile time. Any change to filefacts'
//!   extraction logic changes the hash and so retires every prior entry
//!   without a manual bump, however the consuming binary was built, copied
//!   or packaged. Dependencies are covered only through that lock: in a
//!   standalone build it pins them, so bumping stng retires every entry.
//!   When filefacts is itself a dependency, the consumer's lock picks the
//!   versions of stng, binform and the grammars, and cargo gives a build
//!   script no reliable way to find that lock, so updating them there does
//!   not change the key. Such a host passes
//!   [`crate::OpenOptions::cache_namespace`], derived from its own lock or
//!   version, to retire entries when it updates them.
//! * **variant** — what else the extraction depends on: for a
//!   [`crate::ParsedFile`], the host's namespace, the detected type, a
//!   content/extension mismatch, the basename and
//!   [`crate::RECOVERY_FINGERPRINT`] (binform's recovery policy, which
//!   `src/functions.rs` bumps with the binform commit in the lock).
//!
//! `CACHE_SCHEMA_VERSION` is the manual lever on top, reserved for deliberate
//! format breaks; a sweep removes superseded version directories.
//!
//! # Retention
//!
//! Each version directory is bounded by entry count, total size and age (see
//! the `sweep` module). A cache hit bumps an entry's mtime, so eviction is
//! least-recently-*used*, not merely oldest-written. [`cleanup`] runs a routine
//! sweep of the default root on a background thread, and [`cleanup_in`] one
//! of a host's own directory: the entry points a host calls at startup. A
//! store that finds its shard over its share of the budget starts the same
//! sweep at once. Everything here is best-effort: the cache is a performance
//! optimisation, never a source of truth.

mod sweep;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use sweep::{Budget, Gate, Sweep};

/// The `FILEFACTS_CACHE` environment setting: `Some(false)` for `0` or
/// `false` (any case), `Some(true)` for any other value, `None` when unset.
///
/// A helper for a host that lets its operator decide whether to pass
/// [`crate::OpenOptions::cache`]: the `filefacts` CLI passes
/// `env_override().unwrap_or(true)`. filefacts itself never calls it.
#[must_use]
pub fn env_override() -> Option<bool> {
    std::env::var("FILEFACTS_CACHE")
        .ok()
        .map(|v| parse_env_setting(&v))
}

fn parse_env_setting(value: &str) -> bool {
    !(value == "0" || value.eq_ignore_ascii_case("false"))
}

/// On-disk cache schema version. Bump only on a deliberate, breaking change
/// to the on-disk *format*, not for payload changes: the build fingerprint in
/// the cache key already retires stale entries when extraction logic changes.
const CACHE_SCHEMA_VERSION: u32 = 6;

/// Build identity mixed into every cache key: `{crate version}+{source
/// hash}`, where `build.rs` hashes the crate's `src/**`, `Cargo.toml` and
/// its own `Cargo.lock` (see the module docs for what that leaves out).
///
/// Derived from the source rather than the running executable, so it holds
/// where an mtime would not: an embedding host whose own binary is not
/// filefacts, Nix store paths (mtime 1), `cp -p` and container layers.
const BUILD_FINGERPRINT: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("FILEFACTS_SOURCE_HASH")
);

/// Default ceiling on retained cache entries. On reaching it, the least
/// recently used entries are evicted down to 90% of it.
///
/// Public so a host bounding a cache of its own can quote the same ceiling.
pub const DEFAULT_MAX_ITEMS: usize = 16_384;

/// The ceilings every cache version directory is kept within: 30 days unused,
/// [`DEFAULT_MAX_ITEMS`] entries, 2 GiB. The entry count usually binds first;
/// the byte cap bounds the case of a few very large entries.
const BUDGET: Budget = Budget {
    max_age: Duration::from_hours(30 * 24),
    max_bytes: 2 * 1024 * 1024 * 1024,
    max_entries: DEFAULT_MAX_ITEMS,
};

/// Number of two-hex-character shard directories under a version dir. Cache
/// keys are SHA-256 hex, so entries distribute uniformly across these; the
/// count lets a single-shard sample estimate the whole.
const SHARD_COUNT: usize = 256;

/// Largest payload, in serialised bytes, the cache stores or decodes. An
/// entry this large is cheaper to recompute than to hold, and the bound keeps
/// a corrupt or planted entry — a few kilobytes of zstd can claim gigabytes —
/// from becoming an allocation the size of its claim.
const MAX_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;

/// Coarse granularity for the LRU mtime bump on a cache hit. A hit only
/// rewrites the entry's mtime when it is already older than this, so an
/// entry read repeatedly costs at most one metadata write per window rather
/// than one per read. A day is fine enough to order eviction candidates
/// while leaving the common hot-entry hit a pure read.
const LRU_TOUCH_INTERVAL: Duration = Duration::from_hours(24);

/// Name prefix of the temp files a store writes through. Spelled out (it is
/// also `tempfile`'s default) because the sweep matches on it.
const TEMP_PREFIX: &str = ".tmp";

/// Disk-cache key for `bytes` analysed under `variant`.
///
/// Content addressing is only sound when the cached payload is a pure
/// function of the key. Two things break that for a bare content hash, and
/// both are folded in here:
///
/// * the filefacts build fingerprint — extraction logic changes between
///   builds, so a stale entry from an older filefacts must not be reused;
/// * the caller's `variant` — the detected file type plus
///   [`crate::RECOVERY_FINGERPRINT`], since the *same* bytes yield
///   different extraction under different path-assisted types or recovery
///   policies.
fn cache_key(bytes: &[u8], variant: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // Domain-separated so no concatenation of (content, build, variant)
    // can collide with a different split of the same bytes.
    hasher.update([0u8]);
    hasher.update(BUILD_FINGERPRINT.as_bytes());
    hasher.update([0u8]);
    hasher.update(variant.as_bytes());
    crate::formats::common::hex_encode(&hasher.finalize())
}

/// The directory the cache owns under its base: the host's
/// [`crate::OpenOptions::cache_dir`], or `atomdrift` under the per-user cache
/// directory.
const ROOT_NAME: &str = "filefacts";

/// The cache directory tag (<https://bford.info/cachedir/>) that marks a root
/// as this cache's. Backup tools skip a tagged directory, and the cache uses,
/// prunes and sweeps only a root that carries one.
const TAG_NAME: &str = "CACHEDIR.TAG";

/// The line a cache directory tag must begin with.
const TAG_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// The default root, `atomdrift/filefacts` under the per-user cache
/// directory, resolved once per process; `None` when there is none or it
/// fails [`root_under`]'s checks.
fn default_root() -> Option<&'static Path> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(|| {
        let Some(base) = user_cache_dir() else {
            tracing::debug!("no per-user cache directory; disk cache off");
            return None;
        };
        // filefacts chose this directory's name, so it adopts one that a
        // build predating the tag created.
        let root = root_under(&base.join("atomdrift"), true);
        if root.is_none() {
            tracing::warn!(
                dir = %base.display(),
                "per-user cache directory is unusable (see the debug log); disk cache off"
            );
        }
        root
    })
    .as_deref()
}

/// The per-user cache directory, from the environment: `%LOCALAPPDATA%` on
/// Windows, `$HOME/Library/Caches` on macOS, and elsewhere `$XDG_CACHE_HOME`
/// or `$HOME/.cache` (XDG Base Directory). A relative or empty value counts
/// as unset, as the XDG specification requires.
fn user_cache_dir() -> Option<PathBuf> {
    let absolute = |var| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    if cfg!(windows) {
        absolute("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        absolute("HOME").map(|home| home.join("Library/Caches"))
    } else {
        absolute("XDG_CACHE_HOME").or_else(|| absolute("HOME").map(|home| home.join(".cache")))
    }
}

/// The cache root for a host's `dir` ([`crate::OpenOptions::cache_dir`]),
/// or the per-user default for `None`.
fn resolve_root(dir: Option<&Path>) -> Option<PathBuf> {
    match dir {
        Some(dir) => root_under(dir, false),
        None => default_root().map(Path::to_path_buf),
    }
}

/// `{base}/filefacts`, created and tagged if missing, when it is safe to
/// cache in. Logs why at debug level when it is not: a host's directory is
/// resolved on every open.
///
/// `base` must pass `sweep::trusted_dir`: an absolute path no other user can
/// change. Entries read from the cache are served as analysis results and
/// its sweep deletes by path, so a root another user could redirect or write
/// into — a relative `HOME`, a cache under a shared directory — would let
/// them plant verdicts or aim deletes at this user's files.
///
/// The cache never works in `base` itself, which may hold the host's own
/// files, and uses the `filefacts` directory below it only when that carries
/// the [`TAG_NAME`] the cache wrote on creating it: a sweep deletes what
/// looks like a superseded version or an expired entry, and nothing the cache
/// did not create may be mistaken for one. An existing untagged directory is
/// adopted only with `adopt`. Any failure leaves the cache off.
fn root_under(base: &Path, adopt: bool) -> Option<PathBuf> {
    // A fresh account may not have its cache directory yet; it has to exist
    // before its ownership can be checked.
    if base.is_absolute() {
        let _ = fs::create_dir_all(base);
    }
    let Some(base) = sweep::trusted_dir(base) else {
        tracing::debug!(
            dir = %base.display(),
            "cache directory is relative, missing or writable by another user; disk cache off"
        );
        return None;
    };
    let root = base.join(ROOT_NAME);
    // Readable and writable by this user alone, whatever the umask.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    let created = match builder.create(&root) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            tracing::debug!(dir = %root.display(), %error, "cannot create cache root; disk cache off");
            return None;
        }
    };
    let Some(root) = sweep::trusted_dir(&root) else {
        tracing::debug!(
            dir = %root.display(),
            "cache root is a symlink or writable by another user; disk cache off"
        );
        return None;
    };
    if created || adopt {
        write_tag(&root);
    }
    if !is_tagged(&root) {
        tracing::debug!(
            dir = %root.display(),
            tag = TAG_NAME,
            "cache root was not created by filefacts; disk cache off"
        );
        return None;
    }
    Some(root)
}

/// Tag `root` as this cache's, unless it already holds a tag. `create_new`
/// never follows a link planted where the tag goes. Best-effort.
fn write_tag(root: &Path) {
    let path = root.join(TAG_NAME);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| {
            file.write_all(TAG_SIGNATURE)?;
            file.write_all(
                b"\n# This file is a cache directory tag created by filefacts.\n\
                  # For information about cache directory tags, see https://bford.info/cachedir/\n",
            )
        });
    match written {
        Ok(()) => tracing::debug!(path = %path.display(), "tagged cache root"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => tracing::debug!(path = %path.display(), %error, "cannot tag cache root"),
    }
}

/// Whether `root` carries a cache directory tag.
fn is_tagged(root: &Path) -> bool {
    let mut head = [0u8; TAG_SIGNATURE.len()];
    fs::File::open(root.join(TAG_NAME))
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok_and(|()| head == *TAG_SIGNATURE)
}

/// `v{CACHE_SCHEMA_VERSION}` under `root`.
fn version_location(root: &Path) -> PathBuf {
    root.join(format!("v{CACHE_SCHEMA_VERSION}"))
}

/// Where the entry for `key` lives under `root`. Pure path computation, so a
/// lookup that misses leaves no directories behind; [`store_at_path`]
/// creates the shard when it writes.
fn entry_location(root: &Path, key: &str) -> Option<PathBuf> {
    let shard = key.get(..2)?;
    Some(
        version_location(root)
            .join(shard)
            .join(format!("{key}.bin")),
    )
}

/// Read one cache entry: decompress and decode it. `None` when it is
/// missing, unreadable, over `max_bytes`, or fails to deserialise: each is
/// a cache miss rather than an error, and a bad entry is overwritten by the
/// next store.
fn load_capped<T: serde::de::DeserializeOwned>(path: &Path, max_bytes: u64) -> Option<T> {
    // One open serves both the read and the mtime probe that drives LRU
    // eviction.
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "cache entry unreadable");
            return None;
        }
    };
    let meta = file.metadata().ok()?;
    if meta.len() > max_bytes {
        tracing::debug!(path = %path.display(), len = meta.len(), "cache entry oversize");
        return None;
    }
    let mtime = meta.modified().ok();
    // Decode straight from the file, stopping one byte past the cap so an
    // over-long payload is told apart from one exactly at it.
    let mut decoded = Vec::new();
    let read = zstd::Decoder::new(file)
        .and_then(|decoder| decoder.take(max_bytes + 1).read_to_end(&mut decoded));
    if let Err(error) = read {
        tracing::debug!(path = %path.display(), %error, "cache entry corrupt");
        return None;
    }
    if decoded.len() as u64 > max_bytes {
        tracing::debug!(path = %path.display(), "cache entry decodes past the size cap");
        return None;
    }
    let value = serde_json::from_slice::<T>(&decoded)
        .inspect_err(|error| tracing::debug!(path = %path.display(), %error, "cache entry corrupt"))
        .ok()?;
    // LRU: bump the entry's mtime so the sweep evicts the
    // least-recently-*used*, not merely the oldest-written.
    if let Some(mtime) = mtime {
        touch_lru(path, mtime);
    }
    Some(value)
}

/// Best-effort relatime-style LRU touch: set `path`'s mtime to now, but only
/// when its current mtime is already at least [`LRU_TOUCH_INTERVAL`] stale.
/// Skips the metadata write for entries used within the window and tolerates
/// a read-only cache (the touch simply doesn't happen).
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

/// Create the temp file a store writes through, in the entry's shard.
fn temp_in(dir: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(dir)
}

/// Why a store did not happen.
#[derive(Debug, thiserror::Error)]
enum StoreError {
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("payload of {0} bytes is over the entry cap")]
    Oversize(usize),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("rename: {0}")]
    Persist(#[from] tempfile::PersistError),
}

/// Encode, compress and write one cache entry atomically to `path`, creating
/// its shard directory if needed. A payload over [`MAX_ENTRY_BYTES`] is not
/// stored, since a load would refuse it.
fn store_at_path<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let serialized = serde_json::to_vec(value)?;
    if serialized.len() as u64 > MAX_ENTRY_BYTES {
        return Err(StoreError::Oversize(serialized.len()));
    }
    let compressed = zstd::encode_all(&serialized[..], 3)?;
    // A uniquely named sibling: two processes storing the same key would
    // otherwise write through one temp file and could rename a mix of both
    // into place. Dropped unpersisted, the temp file deletes itself.
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    fs::create_dir_all(dir)?;
    let mut tmp = temp_in(dir)?;
    tmp.write_all(&compressed)?;
    match tmp.persist(path) {
        Ok(_) => Ok(()),
        // Windows refuses to replace a file another store is renaming into
        // place at the same moment. A key names its content, so the entry
        // that won is as good as this one; the loser's temp file deletes
        // itself when dropped.
        Err(error)
            if error.error.kind() == std::io::ErrorKind::PermissionDenied && path.is_file() =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Remove version directories older than the current one under `root`,
/// provided `root` carries the cache's tag. Best-effort; failures are
/// ignored.
fn prune_old_versions(root: &Path) {
    if !is_tagged(root) {
        tracing::debug!(dir = %root.display(), "untagged cache root; not pruned");
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let superseded = name
            .to_str()
            .and_then(|n| n.strip_prefix('v'))
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|v| v < CACHE_SCHEMA_VERSION);
        if superseded {
            match fs::remove_dir_all(entry.path()) {
                Ok(()) => {
                    tracing::debug!(dir = %entry.path().display(), "removed superseded cache version")
                }
                Err(error) => tracing::debug!(
                    dir = %entry.path().display(),
                    %error,
                    "could not remove superseded cache version"
                ),
            }
        }
    }
}

/// Start a sweep of the default cache root on a background thread, returning
/// immediately: superseded version directories are removed and the current
/// one is brought within its budget. The entry point a host calls at startup.
///
/// Best-effort: a short-lived process may exit before the sweep finishes (the
/// thread dies with the process), and the next run resumes the work. A marker
/// in the cache keeps this to one walk a day, so repeated calls are cheap.
///
/// The host decides whether to call it: one told to leave the cache alone
/// (`FILEFACTS_CACHE=0`, see [`env_override`]) should not delete from it
/// either.
pub fn cleanup() {
    if let Some(root) = default_root() {
        spawn_sweep(root, Gate::Interval);
    }
}

/// [`cleanup`] for a host that keeps the cache under its own `dir`, the one
/// it passes to [`crate::OpenOptions::cache_dir`]. Only the `filefacts`
/// directory the cache created there is swept; nothing else in `dir` is
/// touched.
pub fn cleanup_in(dir: &Path) {
    if let Some(root) = root_under(dir, false) {
        spawn_sweep(&root, Gate::Interval);
    }
}

/// Claim `root`'s current version directory and sweep it on a detached
/// thread. A no-op when this process is already sweeping it.
fn spawn_sweep(root: &Path, gate: Gate) {
    let Some(sweep) = Sweep::claim(&version_location(root)) else {
        return;
    };
    let root = root.to_path_buf();
    // A thread that fails to start drops the closure, and with it the claim.
    let spawned = std::thread::Builder::new()
        .name("filefacts-cache-sweep".into())
        .spawn(move || {
            prune_old_versions(&root);
            sweep.run(&BUDGET, gate);
        });
    if let Err(error) = spawned {
        tracing::debug!(%error, "could not start the cache sweep thread");
    }
}

/// Cheap on-write trigger: after storing an entry, count only its own shard.
/// A store follows a cache *miss*, an expensive compute, so one `read_dir`
/// here is negligible. If this shard alone holds well more than its uniform
/// share of the budget, the whole cache is over it; sweep now rather than
/// wait for the next routine sweep.
fn maybe_trigger_sweep(root: &Path, key: &str) {
    // 1.5× the per-shard mean: enough slack that a shard crossing it
    // reliably implies the whole cache is over, not just Poisson noise.
    let per_shard_trigger = BUDGET.max_entries / SHARD_COUNT * 3 / 2 + 1;
    let Some(shard) = key.get(..2) else {
        return;
    };
    let count =
        fs::read_dir(version_location(root).join(shard)).map_or(0, |it| it.flatten().count());
    if count > per_shard_trigger {
        tracing::debug!(shard, count, "cache shard over its share; sweeping");
        spawn_sweep(root, Gate::Now);
    }
}

/// A freshly computed payload, tagged with whether it may be persisted.
///
/// Content addressing is only sound when the computation is reproducible
/// from the key. Most degradation in disassembly is *stable* for a given
/// recovery policy, which is handled by the cache key's `variant`. What
/// remains are *transient* conditions — a source parse stopped by its
/// wall-clock backstop or cancelled. A payload produced under one of those is still
/// usable for the current call but must not be written: persisting it would
/// poison the entry for every later run.
#[derive(Debug)]
pub(crate) enum Computed<T> {
    /// Reproducible from the key — store it and return it.
    Cacheable(T),
    /// Produced under a transient condition — return it, don't store it.
    Transient(T),
}

/// Open `bytes` through the disk cache: key → lookup → on a miss, run
/// `compute` and store the result if it is [`Computed::Cacheable`].
///
/// `dir` is the host's cache root ([`crate::OpenOptions::cache_dir`]), or
/// `None` for the per-user default. When the root is unusable the cache is
/// skipped and `compute` runs. `variant` discriminates inputs whose correct
/// analysis depends on more than the bytes (see [`cache_key`]).
pub(crate) fn open_with_cache<T, F>(
    dir: Option<&Path>,
    bytes: &[u8],
    variant: &str,
    compute: F,
) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> Computed<T>,
{
    match resolve_root(dir) {
        Some(root) => open_with_cache_in(&root, bytes, variant, compute),
        None => match compute() {
            Computed::Cacheable(value) | Computed::Transient(value) => value,
        },
    }
}

/// [`open_with_cache`] under an already-resolved `root`.
fn open_with_cache_in<T, F>(root: &Path, bytes: &[u8], variant: &str, compute: F) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> Computed<T>,
{
    let key = cache_key(bytes, variant);
    let path = entry_location(root, &key);
    if let Some(cached) = path
        .as_deref()
        .and_then(|path| load_capped::<T>(path, MAX_ENTRY_BYTES))
    {
        tracing::debug!(key, "cache hit");
        return cached;
    }
    tracing::debug!(key, "cache miss");
    match compute() {
        Computed::Cacheable(value) => {
            if let Some(path) = path {
                match store_at_path(&path, &value) {
                    Ok(()) => maybe_trigger_sweep(root, &key),
                    Err(error) => tracing::debug!(key, %error, "cache store failed"),
                }
            }
            value
        }
        Computed::Transient(value) => {
            tracing::debug!(key, "transient result; not stored");
            value
        }
    }
}

#[cfg(test)]
mod tests;
