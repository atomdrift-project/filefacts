use super::*;
use std::io::Write;

fn write_aged(path: &Path, bytes: usize, age: Duration) -> PathBuf {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(&vec![b'x'; bytes]).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
    path.to_path_buf()
}

fn day(n: u64) -> Duration {
    Duration::from_hours(n * 24)
}

/// A shard directory `ab` under `root`, the layout entries live in.
fn shard(root: &Path) -> PathBuf {
    let shard = root.join("ab");
    fs::create_dir_all(&shard).unwrap();
    shard
}

fn budget(max_age: Duration, max_bytes: u64, max_entries: usize) -> Budget {
    Budget {
        max_age,
        max_bytes,
        max_entries,
    }
}

/// Sweep `root` now, under `budget`.
fn sweep(root: &Path, budget: Budget) {
    Sweep::claim(root)
        .expect("no other sweep of this root")
        .run(&budget, Gate::Now);
}

fn evict_all() -> Budget {
    budget(day(30), 0, 0)
}

#[test]
fn age_pass_removes_only_old() {
    let tmp = tempfile::tempdir().unwrap();
    let shard = shard(tmp.path());
    let old = write_aged(&shard.join("old.bin"), 10, day(40));
    let fresh = write_aged(&shard.join("fresh.bin"), 10, day(1));
    sweep(tmp.path(), budget(day(30), u64::MAX, usize::MAX));
    assert!(!old.exists(), "40-day entry evicted");
    assert!(fresh.exists(), "1-day entry kept");
}

#[test]
fn size_pass_evicts_oldest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let shard = shard(tmp.path());
    // Five 400-byte entries, distinct ages newest→oldest; cap 1000 → 90% = 900.
    let paths: Vec<PathBuf> = [5u64, 4, 3, 2, 1]
        .into_iter()
        .enumerate()
        .map(|(i, age)| write_aged(&shard.join(format!("e{i}.bin")), 400, day(age)))
        .collect();
    sweep(tmp.path(), budget(day(3650), 1000, usize::MAX));
    // 2000 bytes → evict oldest until ≤ 900: remove e0(5d), e1(4d), e2(3d).
    assert!(!paths[0].exists(), "oldest evicted");
    assert!(!paths[1].exists());
    assert!(!paths[2].exists());
    assert!(paths[3].exists(), "newest kept");
    assert!(paths[4].exists());
}

#[test]
fn count_pass_evicts_oldest_to_ninety_percent() {
    let tmp = tempfile::tempdir().unwrap();
    let shard = shard(tmp.path());
    // Thirteen tiny entries, oldest first; cap 10 → 90% = 9, so the four
    // oldest go. The byte ceiling is inert, isolating the count pass.
    let paths: Vec<PathBuf> = (0..13u64)
        .map(|i| write_aged(&shard.join(format!("e{i:02}.bin")), 1, day(20 - i)))
        .collect();
    sweep(tmp.path(), budget(day(3650), u64::MAX, 10));
    for (i, p) in paths.iter().enumerate() {
        assert_eq!(p.exists(), i >= 4, "entry {i:02}");
    }
}

#[test]
fn nothing_is_evicted_under_the_caps() {
    let tmp = tempfile::tempdir().unwrap();
    let shard = shard(tmp.path());
    let kept: Vec<PathBuf> = (0..5)
        .map(|i| write_aged(&shard.join(format!("{i}.bin")), 1, Duration::ZERO))
        .collect();
    sweep(tmp.path(), budget(day(30), u64::MAX, 100));
    assert!(kept.iter().all(|p| p.exists()));
}

#[test]
fn in_flight_temp_file_survives_the_tightest_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let shard = shard(tmp.path());
    let inflight = write_aged(&shard.join(".tmpPartial"), 1, Duration::ZERO);
    sweep(tmp.path(), evict_all());
    assert!(inflight.exists(), "a recent temp file may be a live store");
}

#[test]
fn orphaned_temp_files_are_removed_and_strays_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let shard = shard(tmp.path());
    let stale = ORPHANED_TEMP_AGE + Duration::from_mins(1);
    let orphan = write_aged(&shard.join(".tmpXyZ789"), 1, stale);
    let inflight = write_aged(&shard.join(".tmpXyZ123"), 1, Duration::ZERO);
    let stray = write_aged(&shard.join("notes.txt"), 1, stale);
    let entry = write_aged(&shard.join("ab34.bin"), 1, Duration::ZERO);
    sweep(tmp.path(), budget(day(30), u64::MAX, usize::MAX));
    assert!(!orphan.exists(), "an orphaned temp file is swept");
    assert!(inflight.exists(), "a recent temp file may be in flight");
    assert!(stray.exists(), "only entries and temp files are managed");
    assert!(entry.exists(), "entries under the caps are kept");
}

#[cfg(unix)]
#[test]
fn symlinked_shard_is_not_descended() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    // An old entry outside the cache, reachable only through a link that sits
    // where a shard would.
    let victim = write_aged(&outside.path().join("not-ours.bin"), 1, day(400));
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("ab")).unwrap();
    sweep(tmp.path(), evict_all());
    assert!(
        victim.exists(),
        "a file behind a symlinked shard is not evicted"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_root_is_not_swept() {
    let target = tempfile::tempdir().unwrap();
    let precious = write_aged(&shard(target.path()).join("precious.bin"), 10, day(400));
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("cache");
    std::os::unix::fs::symlink(target.path(), &link).unwrap();
    sweep(&link, evict_all());
    assert!(precious.exists(), "nothing behind the link");
    assert!(
        !target.path().join(MARKER).exists(),
        "no marker written through it"
    );
}

#[test]
fn relative_root_is_not_swept() {
    // `HOME=.` makes a cache root relative: it would name whatever tree the
    // process runs in, such as the samples under analysis.
    let tmp = tempfile::tempdir().unwrap();
    let precious = write_aged(&shard(tmp.path()).join("precious.bin"), 10, day(400));
    let cwd = std::env::current_dir().unwrap();
    let relative: PathBuf = cwd
        .components()
        .skip(1)
        .map(|_| std::path::Component::ParentDir)
        .chain(tmp.path().components().skip(1))
        .collect();
    assert!(relative.join("ab").join("precious.bin").exists());
    sweep(&relative, evict_all());
    assert!(precious.exists());
    assert!(!tmp.path().join(MARKER).exists());
}

/// Another user could rename `shared`'s children, so it could aim a delete
/// through any root below it at the sweeping user's own files: a root reached
/// through a symlink planted there is the attack itself.
#[cfg(unix)]
#[test]
fn root_another_user_can_redirect_is_not_swept() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let shared = base.path().join("shared");
    let victim = base.path().join("victim");
    let cache = shared.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let old = write_aged(&shard(&cache).join("old.bin"), 10, day(400));
    let precious = write_aged(&shard(&victim).join("precious.bin"), 10, day(400));
    std::os::unix::fs::symlink(&victim, shared.join("planted")).unwrap();

    let mode = |m| fs::set_permissions(&shared, fs::Permissions::from_mode(m)).unwrap();
    mode(0o777);
    sweep(&cache, evict_all());
    sweep(&shared.join("planted"), evict_all());
    assert!(old.exists(), "world-writable parent");
    assert!(precious.exists());

    // Sticky, like /tmp: others cannot rename what they don't own.
    mode(0o1777);
    sweep(&cache, evict_all());
    assert!(!old.exists(), "sticky parent is swept");
}

#[cfg(unix)]
#[test]
fn marker_write_does_not_follow_a_planted_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim.txt");
    fs::write(&victim, b"keep me").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join(MARKER)).unwrap();
    write_marker(&dir.path().join(MARKER), MARK_DONE);
    assert_eq!(fs::read(&victim).unwrap(), b"keep me");
}

#[test]
fn unfinished_marker_retries_within_the_hour() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join(MARKER);
    let two_hours = Duration::from_hours(2);
    let stamp = |contents: &[u8]| {
        fs::write(&marker, contents).unwrap();
        fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(SystemTime::now() - two_hours)
            .unwrap();
    };

    // A sweep that finished two hours ago holds off for a full day.
    stamp(MARK_DONE);
    assert!(!due(dir.path()), "completed sweep gates for SWEEP_INTERVAL");

    // One that died mid-walk is retried instead: without this, a cache too
    // large to sweep inside one short-lived process is never swept at all.
    stamp(MARK_STARTED);
    assert!(
        due(dir.path()),
        "unfinished sweep is due again after RETRY_INTERVAL"
    );
}

#[test]
fn marker_gates_a_routine_sweep_but_not_a_forced_one() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(due(tmp.path()), "no marker ⇒ due");
    let keep = budget(day(30), u64::MAX, usize::MAX);
    Sweep::claim(tmp.path()).unwrap().run(&keep, Gate::Interval);
    assert!(tmp.path().join(MARKER).exists(), "sweep writes the marker");
    assert!(!due(tmp.path()), "fresh marker ⇒ not due");

    let old = write_aged(&shard(tmp.path()).join("old.bin"), 1, day(400));
    Sweep::claim(tmp.path()).unwrap().run(&keep, Gate::Interval);
    assert!(old.exists(), "a routine sweep waits out the interval");
    Sweep::claim(tmp.path()).unwrap().run(&keep, Gate::Now);
    assert!(!old.exists(), "a forced sweep does not");
}

#[test]
fn one_sweep_per_root_at_a_time() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let first = Sweep::claim(a.path()).expect("unclaimed");
    assert!(Sweep::claim(a.path()).is_none(), "the root is taken");
    assert!(Sweep::claim(b.path()).is_some(), "other roots are not");
    drop(first);
    assert!(Sweep::claim(a.path()).is_some(), "released on drop");
}

#[test]
fn a_panicking_sweep_releases_its_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let caught = std::panic::catch_unwind(|| {
        let _sweep = Sweep::claim(&root).expect("unclaimed");
        panic!("sweep failed");
    });
    assert!(caught.is_err());
    assert!(Sweep::claim(tmp.path()).is_some());
}
