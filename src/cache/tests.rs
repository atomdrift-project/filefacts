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
fn env_setting_disables_only_on_zero_or_false() {
    assert!(!parse_env_setting("0"));
    assert!(!parse_env_setting("false"));
    assert!(!parse_env_setting("FALSE"));
    assert!(parse_env_setting("1"));
    assert!(parse_env_setting("yes"));
    assert!(parse_env_setting(""));
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
    let loaded: Payload = load_from_path(&path).expect("cache should hit immediately after store");
    assert_eq!(loaded, original);
}

#[test]
fn concurrent_stores_of_one_key_leave_a_whole_entry() {
    let bytes = unique_bytes("concurrent_store");
    let tmp = tempfile::tempdir().expect("tempdir");
    let sha = sha256_hex(&bytes);
    let path = test_entry_path(tmp.path(), &sha).expect("cache path");
    let payloads: Vec<Vec<u32>> = (0..8).map(|i| vec![i; 64 * 1024]).collect();
    std::thread::scope(|scope| {
        for payload in &payloads {
            scope.spawn(|| store_at_path(&path, payload));
        }
    });
    let loaded: Vec<u32> = load_from_path(&path).expect("entry must decode");
    assert!(payloads.contains(&loaded));
    let files = fs::read_dir(path.parent().unwrap()).unwrap().count();
    assert_eq!(files, 1, "temp files must not be left behind");
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
    // SHA of bytes we never wrote, in a private root rather than the
    // developer's real cache.
    let tmp = tempfile::tempdir().expect("tempdir");
    let sha = sha256_hex(&unique_bytes("missing"));
    let path = entry_location(tmp.path(), &sha).expect("cache path");
    let v: Option<u32> = load_from_path(&path);
    assert!(v.is_none());
}

#[test]
fn lookups_do_not_create_directories() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("filefacts");
    let bytes = unique_bytes("lookup_no_mkdir");
    let path_for = |key: &str| entry_location(&root, key);
    // A miss whose result is not persisted, and a plain load, both
    // leave the cache root untouched.
    let transient = open_with_cache_in::<u32, _, _, _>(
        &bytes,
        "",
        path_for,
        |_| {},
        |_| Some(Computed::Transient(1)),
    );
    assert_eq!(transient, Some(1));
    let path = path_for(&cache_key(&bytes, "")).expect("cache path");
    assert_eq!(load_from_path::<u32>(&path), None);
    assert!(!root.exists(), "a lookup must not create directories");
    // The first store creates the shard it writes into.
    let stored = open_with_cache_in::<u32, _, _, _>(
        &bytes,
        "",
        path_for,
        |_| {},
        |_| Some(Computed::Cacheable(2)),
    );
    assert_eq!(stored, Some(2));
    assert_eq!(load_from_path::<u32>(&path), Some(2));
}

#[test]
fn stng_is_pinned_so_its_commit_keys_the_cache() {
    // Cached snapshots hold stng's output, and the key covers Cargo.toml
    // (see build.rs) but not stng's source. Pinning stng to an exact commit
    // or version is what retires entries when stng changes; a branch or a
    // version range would let a stng update serve stale strings.
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let stng = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("stng "))
        .expect("stng dependency in Cargo.toml");
    assert!(
        stng.contains("rev = \"") || stng.contains("version = \"="),
        "stng must be pinned by rev or exact version: {stng}"
    );
}

#[test]
fn build_fingerprint_is_a_source_hash() {
    // Not the executable's mtime: a fixed-width hash of the source that
    // `build.rs` computes, so it changes exactly when the code does.
    let (version, hash) = BUILD_FINGERPRINT.split_once('+').expect("version+hash");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(hash.len(), 16, "{hash}");
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{hash}");
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
fn enforce_limits_removes_orphaned_temp_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let shard = tmp.path().join("ab");
    fs::create_dir_all(&shard).expect("shard");
    let now = SystemTime::now();
    let stale = now - ORPHANED_TEMP_AGE - Duration::from_secs(60);
    // A temp file named the way `store_at_path` names it, left behind as
    // if its writer died before the rename.
    let (_, orphan) = temp_in(&shard)
        .expect("temp file")
        .keep()
        .expect("keep temp file");
    fs::OpenOptions::new()
        .write(true)
        .open(&orphan)
        .expect("open for mtime")
        .set_modified(stale)
        .expect("set mtime");
    // The `{key}.tmp` sibling older builds wrote through.
    let legacy = entry_with_mtime(&shard, "ab12.tmp", stale);
    let inflight = entry_with_mtime(&shard, ".tmpXyZ123", now);
    let stray = entry_with_mtime(&shard, "notes.txt", stale);
    let entry = entry_with_mtime(&shard, "ab34.bin", now);
    enforce_limits_in(tmp.path(), 10_000, MAX_BYTES);
    assert!(!orphan.exists(), "an orphaned temp file is swept");
    assert!(!legacy.exists(), "a legacy orphaned temp file is swept");
    assert!(inflight.exists(), "a recent temp file may be in flight");
    assert!(stray.exists(), "only temp files are swept");
    assert!(entry.exists(), "entries under the caps are kept");
}

#[test]
fn touch_lru_bumps_a_stale_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let old = SystemTime::now() - Duration::from_hours(3 * 24);
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
