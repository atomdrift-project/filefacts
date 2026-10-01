//! Best-effort, non-blocking cache reclamation.
//!
//! A cache here is a directory of entries, each carrying an mtime. A *sweep*
//! deletes the oldest entries until the directory is within an age, count and
//! size budget. The whole thing runs on one detached thread that dies with the
//! process — no daemon, no async runtime, no persistent index.
//!
//! The count ceiling is the one that usually binds: entries are small, so a
//! byte budget alone lets a directory reach millions of files, which every
//! filesystem tool handles badly and which makes the sweep meant to fix it
//! progressively more expensive.
//!
//! Two properties keep it cheap and safe:
//! - A `.last-sweep` marker gates the walk, so the common case is a single
//!   `stat`, never a scan of a million-entry directory. The marker records
//!   whether the sweep it names *finished*: a detached thread dies with its
//!   process, and a sweep cut short that way must not book itself as a full
//!   day's work, or a cache too large to sweep in one short run would never be
//!   swept at all.
//! - Every filesystem error is ignored: reclaiming disk must never disturb the
//!   program it runs alongside. These caches are written once and never
//!   rewritten, and on Unix unlinking a file another thread has open leaves that
//!   reader's descriptor valid, so a concurrent reader never sees a torn file.
//!
//! Moved here from stng, which no longer keeps disk caches: consumers that link
//! filefacts (scan) reuse the mechanism, and fletch keeps its own copy.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// Default retention window: entries older than this are dropped.
const DEFAULT_TTL_DAYS: u64 = 30;
/// Default aggregate ceiling per component: 2 GiB.
const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Default aggregate ceiling per component, in entries: the same ceiling
/// filefacts' own cache uses (see [`crate::cache::DEFAULT_MAX_ITEMS`]).
const DEFAULT_MAX_ENTRIES: usize = crate::cache::DEFAULT_MAX_ITEMS;
/// Re-walk a cache at most this often; cheaper runs just read the marker.
const SWEEP_INTERVAL: Duration = Duration::from_hours(24);
/// Re-walk this soon after a sweep that never reported finishing. A sweep still
/// running after this long can be joined by a second one, which costs a
/// redundant walk but nothing else: eviction is a delete of an entry each
/// process decided was oldest, and a failed delete is already ignored.
const RETRY_INTERVAL: Duration = Duration::from_hours(1);
/// Marker file, written in the primary root: its mtime records when the last
/// sweep started and its single byte whether that sweep finished.
const MARKER: &str = ".last-sweep";
/// Marker contents: a sweep is in flight, or died with its process.
const MARK_STARTED: &[u8] = b"s";
/// Marker contents: the sweep that wrote it ran to completion.
const MARK_DONE: &[u8] = b"d";

/// A cache directory and how deep its entries live below it.
#[derive(Debug)]
pub struct Root {
    /// Directory to sweep.
    pub path: PathBuf,
    /// `1` = direct children are entries (files or dirs); `2` = grandchildren
    /// are entries and each child is a container to descend into.
    pub depth: u8,
}

/// One component's caches and the budget they must collectively stay within.
#[derive(Debug)]
pub struct Budget {
    /// Component name, for a debug log line.
    pub label: &'static str,
    /// One or more directories sharing the `max_bytes` ceiling. The first is
    /// the *primary* root and holds the sweep marker.
    pub roots: Vec<Root>,
    /// Delete entries older than this.
    pub max_age: Duration,
    /// After the age pass, delete oldest entries until the total across all
    /// roots is at or below this.
    pub max_bytes: u64,
    /// Likewise for the entry count across all roots. Usually the binding
    /// ceiling; `max_bytes` bounds the case of a few very large entries.
    pub max_entries: usize,
}

/// One sweep in flight per process; a second [`spawn`] is a no-op until it ends.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Clears [`RUNNING`] on drop, so a panic inside the sweep can never wedge every
/// future [`spawn`] into a permanent no-op.
struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Sweep `budgets` on a detached thread and return immediately. The thread is
/// reaped when the process exits; a sweep interrupted that way leaves the
/// marker unfinished, so the next run retries it within the hour rather than
/// waiting out a full interval.
///
/// For a one-shot CLI, call once at startup — it races the real work. For a
/// long-lived daemon, use [`spawn_periodic`] instead.
pub fn spawn(mut budgets: Vec<Budget>) {
    budgets.retain(|b| !b.roots.is_empty());
    if budgets.is_empty() {
        return;
    }
    if RUNNING.swap(true, Ordering::AcqRel) {
        return; // a sweep is already running
    }
    // `Builder::spawn` returns an error (rather than panicking) if the OS
    // refuses the thread; reset the guard so a later call can retry.
    let started = std::thread::Builder::new()
        .name("cache-sweep".into())
        .spawn(move || {
            let _guard = RunningGuard;
            run_all(&budgets);
        });
    if started.is_err() {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Sweep `budgets` now and every `interval` thereafter, on one detached thread,
/// for the life of the process. For daemons whose process never exits, so a
/// startup-only sweep would never fire again. The daily marker keeps each wake
/// cheap regardless of `interval`.
pub fn spawn_periodic(mut budgets: Vec<Budget>, interval: Duration) {
    budgets.retain(|b| !b.roots.is_empty());
    if budgets.is_empty() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("cache-sweep".into())
        .spawn(move || {
            loop {
                run_all(&budgets);
                std::thread::sleep(interval);
            }
        });
}

/// The caches older stng releases filled for their callers: the string cache
/// (`<cache>/stng/strings`, or `STNG_STRING_CACHE_DIR`) and the rizin cache
/// (`<cache>/stng/r2`), sharing one ceiling. filefacts now keeps extracted
/// strings in its own cache, so nothing refills the first; sweeping it lets the
/// leftovers age out. The stng CLI still uses the second.
#[must_use]
pub fn legacy_stng_budget() -> Budget {
    let base = dirs::cache_dir()
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")));
    let strings = std::env::var_os("STNG_STRING_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| base.as_ref().map(|b| b.join("stng").join("strings")));
    let roots = strings
        .into_iter()
        .chain(base.map(|b| b.join("stng").join("r2")))
        .map(|path| Root { path, depth: 1 })
        .collect();
    Budget {
        label: "stng",
        roots,
        max_age: max_age_from_env("STNG_CACHE_TTL_DAYS"),
        max_bytes: max_bytes_from_env("STNG_CACHE_MAX_BYTES"),
        max_entries: max_entries_from_env("STNG_CACHE_MAX_ENTRIES"),
    }
}

/// Retention window from `var` (in days), or the 30-day default. `saturating_mul`
/// so an absurd env value can't overflow into a panic (debug) or wrap (release).
#[must_use]
pub fn max_age_from_env(var: &str) -> Duration {
    let days = std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&d| d > 0)
        .unwrap_or(DEFAULT_TTL_DAYS);
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
}

/// Byte ceiling from `var`, or the 2 GiB default.
#[must_use]
pub fn max_bytes_from_env(var: &str) -> u64 {
    max_bytes_from_env_or(var, DEFAULT_MAX_BYTES)
}

/// Byte ceiling from `var`, or `default` when unset or invalid. Lets a consumer
/// pick a different default (e.g. fletch's larger artifact cache) while still
/// honoring the same env override.
#[must_use]
pub fn max_bytes_from_env_or(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&b| b > 0)
        .unwrap_or(default)
}

/// Entry ceiling from `var`, or the [`DEFAULT_MAX_ENTRIES`] default.
#[must_use]
pub fn max_entries_from_env(var: &str) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_ENTRIES)
}

fn run_all(budgets: &[Budget]) {
    for b in budgets {
        run(b);
    }
}

/// An entry considered for eviction: its path, whether it is a directory, and
/// the size and mtime read once and reused by both passes.
struct Entry {
    path: PathBuf,
    is_dir: bool,
    modified: SystemTime,
    bytes: u64,
}

fn run(b: &Budget) {
    let Some(primary) = b.roots.first() else {
        return;
    };
    if !due(&primary.path) {
        return;
    }
    // Mark the start (mtime = now) so a racing process sees a fresh marker and
    // skips. Best-effort; if the directory doesn't exist yet, there's nothing
    // to sweep anyway.
    let marker = primary.path.join(MARKER);
    let _ = fs::write(&marker, MARK_STARTED);

    let mut entries = Vec::new();
    for r in &b.roots {
        collect(&r.path, r.depth, &mut entries);
    }

    let now = SystemTime::now();
    let mut freed = 0u64;
    let mut removed = 0usize;

    // Age pass: drop anything past the retention window outright.
    entries.retain(|e| {
        if now.duration_since(e.modified).unwrap_or_default() > b.max_age && remove(e) {
            freed += e.bytes;
            removed += 1;
            false
        } else {
            true
        }
    });

    // Count/size pass: over either ceiling, evict oldest first until under 90%
    // of both. Stopping at 90% rather than exactly at the cap keeps a cache
    // sitting at the ceiling from re-triggering a sweep on the very next write.
    // Divide before multiplying so a caller's `u64::MAX`/`usize::MAX` ceiling
    // can't overflow the target.
    let mut count = entries.len();
    let mut total: u64 = entries.iter().map(|e| e.bytes).sum();
    if total > b.max_bytes || count > b.max_entries {
        entries.sort_by_key(|e| e.modified); // oldest first
        let byte_target = b.max_bytes / 10 * 9;
        let count_target = b.max_entries / 10 * 9;
        for e in &entries {
            if total <= byte_target && count <= count_target {
                break;
            }
            if remove(e) {
                total = total.saturating_sub(e.bytes);
                count -= 1;
                freed += e.bytes;
                removed += 1;
            }
        }
    }

    // Record completion, so the next run waits a full interval rather than
    // retrying. Not reached if this thread dies with its process mid-sweep.
    let _ = fs::write(&marker, MARK_DONE);

    if removed > 0 {
        tracing::debug!(
            target: "cache_sweep",
            component = b.label,
            removed,
            freed_bytes = freed,
            "swept cache"
        );
    }
}

/// True unless this root was swept recently: within [`SWEEP_INTERVAL`] for a
/// sweep that finished, or [`RETRY_INTERVAL`] for one that died with its
/// process. A missing or unreadable marker counts as due, so a never-swept
/// cache is handled on the first run.
fn due(root: &Path) -> bool {
    let marker = root.join(MARKER);
    let Ok(started) = fs::metadata(&marker).and_then(|m| m.modified()) else {
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

/// Gather the cache entries at `depth` below `root` into `out`. At `depth <= 1`
/// each child is an entry; deeper, each directory child is descended into.
fn collect(root: &Path, depth: u8, out: &mut Vec<Entry>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else {
            continue;
        };
        let path = e.path();
        if depth <= 1 {
            if path.file_name().is_some_and(|n| n == MARKER) {
                continue; // never evict our own marker
            }
            if let Some(entry) = stat_entry(path, ft.is_dir()) {
                out.push(entry);
            }
        } else if ft.is_dir() {
            collect(&path, depth - 1, out);
        }
    }
}

fn stat_entry(path: PathBuf, is_dir: bool) -> Option<Entry> {
    let meta = fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let bytes = if is_dir { dir_size(&path) } else { meta.len() };
    Some(Entry {
        path,
        is_dir,
        modified,
        bytes,
    })
}

/// Recursive byte size of a directory entry. Only ever called on the small
/// per-item directories stng's rizin cache uses (a handful of files each).
///
/// Recursion is gated on `file_type()`, which does NOT follow symlinks: a
/// symlink is neither descended nor counted. That keeps a stray symlink loop
/// in the cache dir from spinning this into an (uncatchable) stack-overflow
/// abort, and a symlink to a large tree from inflating the byte total.
fn dir_size(dir: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else {
            continue;
        };
        if ft.is_dir() {
            total += dir_size(&e.path());
        } else if ft.is_file() {
            total += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

fn remove(e: &Entry) -> bool {
    let r = if e.is_dir {
        fs::remove_dir_all(&e.path)
    } else {
        fs::remove_file(&e.path)
    };
    r.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cache-sweep-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_aged(path: &Path, bytes: usize, age: Duration) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(&vec![b'x'; bytes]).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    fn day(n: u64) -> Duration {
        Duration::from_secs(n * 24 * 60 * 60)
    }

    #[test]
    fn age_pass_removes_only_old() {
        let dir = scratch("age");
        write_aged(&dir.join("old.json"), 10, day(40));
        write_aged(&dir.join("fresh.json"), 10, day(1));
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
            max_entries: usize::MAX,
        };
        run(&budget);
        assert!(!dir.join("old.json").exists(), "40-day entry evicted");
        assert!(dir.join("fresh.json").exists(), "1-day entry kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn size_pass_evicts_oldest_first() {
        let dir = scratch("size");
        // Five 400-byte entries, distinct ages newest→oldest; cap 1000 → 90% = 900.
        for (i, age) in [5u64, 4, 3, 2, 1].into_iter().enumerate() {
            write_aged(&dir.join(format!("e{i}.json")), 400, day(age));
        }
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(3650), // age pass inert
            max_bytes: 1000,
            max_entries: usize::MAX,
        };
        run(&budget);
        // 2000 bytes → evict oldest until ≤ 900: remove e0(5d), e1(4d), e2(3d).
        assert!(!dir.join("e0.json").exists(), "oldest evicted");
        assert!(!dir.join("e1.json").exists());
        assert!(!dir.join("e2.json").exists());
        assert!(dir.join("e3.json").exists(), "newest kept");
        assert!(dir.join("e4.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn depth_two_reaches_grandchildren() {
        let dir = scratch("depth2");
        let ver = dir.join("v1");
        fs::create_dir_all(&ver).unwrap();
        write_aged(&ver.join("a.zst"), 10, day(40));
        write_aged(&ver.join("b.zst"), 10, day(1));
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 2,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
            max_entries: usize::MAX,
        };
        run(&budget);
        assert!(!ver.join("a.zst").exists(), "aged grandchild evicted");
        assert!(ver.join("b.zst").exists(), "fresh grandchild kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dir_size_does_not_follow_symlink_loops() {
        let dir = scratch("symloop");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("a.json"), b"1234567890").unwrap(); // 10 bytes
        // A symlink back to the parent: following it would recurse forever and
        // abort the process on stack overflow.
        std::os::unix::fs::symlink(&dir, sub.join("loop")).unwrap();
        // Must return promptly, counting only the real file.
        assert_eq!(
            dir_size(&dir),
            10,
            "the symlink is neither followed nor counted"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn count_pass_evicts_oldest_to_ninety_percent() {
        let dir = scratch("count");
        // Thirteen tiny entries, oldest first; cap 10 → 90% = 9, so the four
        // oldest go. The byte ceiling is inert, isolating the count pass.
        for i in 0..13u64 {
            write_aged(&dir.join(format!("e{i:02}.json")), 1, day(20 - i));
        }
        run(&Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(3650),
            max_bytes: u64::MAX,
            max_entries: 10,
        });
        let kept: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n != MARKER)
            .collect();
        assert_eq!(kept.len(), 9, "evicted down to 90% of the cap");
        assert!(!dir.join("e00.json").exists(), "oldest evicted");
        assert!(!dir.join("e03.json").exists());
        assert!(dir.join("e04.json").exists(), "newest kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unfinished_marker_retries_within_the_hour() {
        let dir = scratch("unfinished");
        let marker = dir.join(MARKER);
        let two_hours = Duration::from_hours(2);

        // A sweep that finished two hours ago holds off for a full day.
        fs::write(&marker, MARK_DONE).unwrap();
        fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(SystemTime::now() - two_hours)
            .unwrap();
        assert!(!due(&dir), "completed sweep gates for SWEEP_INTERVAL");

        // One that died mid-walk is retried instead: without this, a cache too
        // large to sweep inside one short-lived process is never swept at all.
        fs::write(&marker, MARK_STARTED).unwrap();
        fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(SystemTime::now() - two_hours)
            .unwrap();
        assert!(
            due(&dir),
            "unfinished sweep is due again after RETRY_INTERVAL"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn marker_gates_and_survives() {
        let dir = scratch("gate");
        assert!(due(&dir), "no marker ⇒ due");
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
            max_entries: usize::MAX,
        };
        run(&budget);
        assert!(dir.join(MARKER).exists(), "sweep writes the marker");
        assert!(!due(&dir), "fresh marker ⇒ not due");
        let _ = fs::remove_dir_all(&dir);
    }
}
