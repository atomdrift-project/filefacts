//! Eviction for the disk cache: an age, entry-count and byte budget over one
//! cache version directory.
//!
//! Entries live two levels below the root, `{root}/{shard}/{key}.bin`. A sweep
//! deletes every entry older than the age budget, then the least recently used
//! until the directory is within 90% of both the count and the byte budget.
//! Stopping short of the cap keeps a cache sitting at its ceiling from asking
//! for another sweep on the very next store. Temp files orphaned by a store
//! whose process died before its rename go too, once no live store can still
//! own them. Nothing else in the directory is touched.
//!
//! The count budget is the one that usually binds: entries are small, so a byte
//! budget alone lets a directory reach millions of files, which every
//! filesystem tool handles badly and which makes the sweep meant to fix it
//! progressively more expensive.
//!
//! Two properties keep it cheap and safe:
//! - A `.last-sweep` marker gates a routine sweep, so the common case is a
//!   single `stat`, never a walk of the whole cache. The marker records whether
//!   the sweep it names *finished*: a sweep thread dies with its process, and a
//!   sweep cut short that way must not book itself as a full day's work, or a
//!   cache too large to sweep in one short run would never be swept at all.
//! - Every filesystem error is ignored: reclaiming disk must never disturb the
//!   program it runs alongside. Entries are written once and never rewritten,
//!   and on Unix unlinking a file another thread has open leaves that reader's
//!   descriptor valid, so a concurrent reader never sees a torn file.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use super::TEMP_PREFIX;

/// Re-walk a cache at most this often; cheaper runs just read the marker.
const SWEEP_INTERVAL: Duration = Duration::from_hours(24);
/// Re-walk this soon after a sweep that never reported finishing. A sweep still
/// running after this long can be joined by a second process's, which costs a
/// redundant walk but nothing else: eviction is a delete of an entry each
/// process decided was oldest, and a failed delete is already ignored.
const RETRY_INTERVAL: Duration = Duration::from_hours(1);
/// Marker file in the root: its mtime records when the last sweep started and
/// its single byte whether that sweep finished.
const MARKER: &str = ".last-sweep";
/// Marker contents: a sweep is in flight, or died with its process.
const MARK_STARTED: &[u8] = b"s";
/// Marker contents: the sweep that wrote it ran to completion.
const MARK_DONE: &[u8] = b"d";
/// A temp file this old was orphaned by a writer that died before its rename:
/// a live store creates, writes and renames it within moments.
const ORPHANED_TEMP_AGE: Duration = Duration::from_mins(15);

/// The ceilings a cache directory must stay within.
#[derive(Debug, Clone, Copy)]
pub(super) struct Budget {
    /// Delete entries whose mtime is older than this. A cache hit bumps an
    /// entry's mtime, so a still-used entry is never dropped for age alone.
    pub(super) max_age: Duration,
    /// After the age pass, evict the oldest entries until the total size is
    /// at or below 90% of this.
    pub(super) max_bytes: u64,
    /// Likewise for the entry count. Usually the binding ceiling; `max_bytes`
    /// bounds the case of a few very large entries.
    pub(super) max_entries: usize,
}

/// When a sweep walks the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    /// Only when the marker says the last sweep is due again: the routine
    /// sweep a host starts at startup.
    Interval,
    /// Regardless of the marker: a store found the cache over its budget.
    Now,
}

/// Roots this process is sweeping. Two sweeps of one root would only race to
/// delete the same files; sweeps of different roots never interact.
static RUNNING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// The right to sweep one root, held until dropped. A panic in the sweep
/// releases it on unwind, so no root is ever left marked as running.
#[derive(Debug)]
pub(super) struct Sweep {
    root: PathBuf,
}

impl Sweep {
    /// Claim `root`, or `None` when this process is already sweeping it.
    pub(super) fn claim(root: &Path) -> Option<Self> {
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        if running.iter().any(|r| r == root) {
            tracing::debug!(root = %root.display(), "cache sweep already running; skipped");
            return None;
        }
        running.push(root.to_path_buf());
        Some(Self {
            root: root.to_path_buf(),
        })
    }

    /// Bring the claimed root within `budget`, best-effort.
    pub(super) fn run(&self, budget: &Budget, gate: Gate) {
        let Some(root) = trusted_dir(&self.root) else {
            tracing::debug!(
                root = %self.root.display(),
                "cache root missing or writable by another user; not swept"
            );
            return;
        };
        if gate == Gate::Interval && !due(&root) {
            return;
        }
        // Mark the start (mtime = now) so another process sees a fresh marker
        // and skips its routine sweep.
        let marker = root.join(MARKER);
        write_marker(&marker, MARK_STARTED);

        let now = SystemTime::now();
        let (mut entries, orphans) = collect(&root, now);
        let scanned = entries.len();
        let mut freed = 0u64;
        let mut evicted = 0usize;

        // Age pass: drop anything past the retention window outright.
        entries.retain(|e| {
            if now.duration_since(e.modified).unwrap_or_default() > budget.max_age
                && fs::remove_file(&e.path).is_ok()
            {
                freed += e.bytes;
                evicted += 1;
                false
            } else {
                true
            }
        });

        // Count/size pass: over either ceiling, evict the least recently used
        // until under 90% of both. Divide before multiplying so a `u64::MAX` or
        // `usize::MAX` ceiling cannot overflow the target.
        let mut count = entries.len();
        let mut total: u64 = entries.iter().map(|e| e.bytes).sum();
        if total > budget.max_bytes || count > budget.max_entries {
            entries.sort_unstable_by_key(|e| e.modified);
            let byte_target = budget.max_bytes / 10 * 9;
            let count_target = budget.max_entries / 10 * 9;
            for e in &entries {
                if total <= byte_target && count <= count_target {
                    break;
                }
                if fs::remove_file(&e.path).is_ok() {
                    total = total.saturating_sub(e.bytes);
                    count -= 1;
                    freed += e.bytes;
                    evicted += 1;
                }
            }
        }

        // Record completion, so the next routine sweep waits a full interval.
        // Not reached if this thread dies with its process mid-sweep.
        write_marker(&marker, MARK_DONE);
        tracing::debug!(
            root = %root.display(),
            ?gate,
            scanned,
            evicted,
            freed_bytes = freed,
            orphaned_temps_removed = orphans,
            "swept cache"
        );
    }
}

impl Drop for Sweep {
    fn drop(&mut self) {
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = running.iter().position(|r| *r == self.root) {
            running.swap_remove(i);
        }
    }
}

/// A cache entry considered for eviction, with the size and mtime read once
/// and reused by both passes.
struct Entry {
    path: PathBuf,
    modified: SystemTime,
    bytes: u64,
}

/// Gather the `*.bin` entries in every shard below `root`, removing orphaned
/// temp files on the way. Returns the entries and how many temp files went.
fn collect(root: &Path, now: SystemTime) -> (Vec<Entry>, usize) {
    let mut entries = Vec::new();
    let mut orphans = 0;
    let Ok(shards) = fs::read_dir(root) else {
        return (entries, orphans);
    };
    for shard in shards.flatten() {
        // `file_type` does not follow symlinks: a shard that is a link points
        // outside the cache, and the files behind it are not ours to evict.
        if !shard.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(files) = fs::read_dir(shard.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            let is_entry = path.extension().is_some_and(|ext| ext == "bin");
            let is_temp = !is_entry
                && file
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(TEMP_PREFIX));
            if !is_entry && !is_temp {
                continue;
            }
            // `DirEntry::metadata` does not follow symlinks either: a link
            // is evicted as a link.
            let Some((modified, bytes)) = file
                .metadata()
                .ok()
                .and_then(|m| Some((m.modified().ok()?, m.len())))
            else {
                continue;
            };
            if is_entry {
                entries.push(Entry {
                    path,
                    modified,
                    bytes,
                });
            } else if now.duration_since(modified).unwrap_or_default() > ORPHANED_TEMP_AGE
                && fs::remove_file(&path).is_ok()
            {
                orphans += 1;
            }
        }
    }
    (entries, orphans)
}

/// Whether `path` is a directory itself, not a symlink to one.
fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Symlinks followed resolving a root before it is refused, as the kernel's
/// own `ELOOP` limit does.
#[cfg(unix)]
const MAX_LINKS: u32 = 40;

/// `dir`, with any symlinks on the way to it resolved, when the cache may read
/// from and delete in it. Entries are deleted by path, so whoever can change a
/// directory on that path can swap in a symlink between the walk and the
/// delete and aim it at any file this process may remove. Refused: a relative
/// path, which names different files from each working directory (`HOME=.`);
/// a `dir` that is itself a symlink, pointing somewhere this cache does not
/// own; and on unix, a path through a directory or link that another user can
/// change, such as a cache under a shared directory (`HOME=/tmp`, or
/// `XDG_CACHE_HOME` pointed there) whose `.cache` someone else created.
pub(super) fn trusted_dir(dir: &Path) -> Option<PathBuf> {
    if !dir.is_absolute() || !is_real_dir(dir) {
        return None;
    }
    #[cfg(unix)]
    let dir = {
        // SAFETY: neither call has preconditions; each only returns an id.
        #[allow(unsafe_code)]
        let ids = unsafe { (libc::geteuid(), libc::getegid()) };
        let mut resolved = PathBuf::new();
        resolve_trusted(dir, ids, &mut resolved, &mut 0)?;
        resolved
    };
    #[cfg(not(unix))]
    let dir = dir.to_path_buf();
    Some(dir)
}

/// Resolve `path` onto `resolved` one component at a time, following
/// symlinks, and fail on the first step someone other than this user (`ids`
/// is the effective uid and gid) or the superuser could change. A directory
/// passes only if no other user can write it: group-writable just for this
/// user's own group, or world-writable only with the sticky bit (`/tmp`),
/// where no one may rename what they do not own. `resolved` never holds a
/// symlink, so `..` is its lexical parent.
#[cfg(unix)]
fn resolve_trusted(
    path: &Path,
    (uid, gid): (u32, u32),
    resolved: &mut PathBuf,
    links: &mut u32,
) -> Option<()> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    let trusted = |m: &fs::Metadata| {
        let mode = m.mode();
        (m.uid() == uid || m.uid() == 0)
            && (m.is_symlink()
                || mode & 0o1000 != 0
                || (mode & 0o002 == 0 && (mode & 0o020 == 0 || m.gid() == gid)))
    };
    for component in path.components() {
        match component {
            Component::RootDir => {
                *resolved = PathBuf::from("/");
                if !fs::symlink_metadata(&*resolved).is_ok_and(|m| trusted(&m)) {
                    return None;
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                let next = resolved.join(name);
                let meta = fs::symlink_metadata(&next).ok()?;
                if !trusted(&meta) {
                    return None;
                }
                if meta.is_symlink() {
                    *links += 1;
                    if *links > MAX_LINKS {
                        return None;
                    }
                    resolve_trusted(&fs::read_link(&next).ok()?, (uid, gid), resolved, links)?;
                } else {
                    *resolved = next;
                }
            }
            Component::Prefix(_) => return None,
        }
    }
    Some(())
}

/// Write the sweep marker without following a symlink planted in its place:
/// the write would otherwise truncate whatever the link names. Best-effort.
fn write_marker(path: &Path, contents: &[u8]) {
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return;
    }
    if let Ok(mut file) = options.open(path) {
        let _ = file.write_all(contents);
    }
}

/// True unless this root was swept recently: within [`SWEEP_INTERVAL`] for a
/// sweep that finished, or [`RETRY_INTERVAL`] for one that died with its
/// process. A missing or unreadable marker counts as due, so a never-swept
/// cache is handled on the first run.
fn due(root: &Path) -> bool {
    let marker = root.join(MARKER);
    let Ok(started) = fs::symlink_metadata(&marker).and_then(|m| m.modified()) else {
        return true;
    };
    let Ok(elapsed) = started.elapsed() else {
        return true; // marker dated in the future (clock skew): sweep now
    };
    let interval = match fs::read(&marker).as_deref() {
        Ok(MARK_DONE) => SWEEP_INTERVAL,
        _ => RETRY_INTERVAL,
    };
    elapsed >= interval
}

#[cfg(test)]
mod tests;
