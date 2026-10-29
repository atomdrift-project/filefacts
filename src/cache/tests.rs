use super::*;

/// SHA-256 a byte slice, returning the lowercase hex digest.
fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

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

fn entry_path(root: &Path, bytes: &[u8], variant: &str) -> PathBuf {
    entry_location(root, &cache_key(bytes, variant)).expect("cache path")
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
    let original = Payload {
        n: 42,
        name: "rizin-out".into(),
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = entry_path(tmp.path(), &unique_bytes("round_trip"), "");
    store_at_path(&path, &original).expect("store");
    let loaded: Payload =
        load_capped(&path, MAX_ENTRY_BYTES).expect("cache should hit immediately after store");
    assert_eq!(loaded, original);
}

#[test]
fn concurrent_stores_of_one_key_leave_a_whole_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = entry_path(tmp.path(), &unique_bytes("concurrent_store"), "");
    let payloads: Vec<Vec<u32>> = (0..8).map(|i| vec![i; 64 * 1024]).collect();
    std::thread::scope(|scope| {
        for payload in &payloads {
            scope.spawn(|| store_at_path(&path, payload).expect("store"));
        }
    });
    let loaded: Vec<u32> = load_capped(&path, MAX_ENTRY_BYTES).expect("entry must decode");
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
    let first = open_with_cache_in(tmp.path(), &bytes, "", || {
        calls.fetch_add(1, Ordering::SeqCst);
        Computed::Cacheable(Payload(7))
    });
    assert_eq!(first, Payload(7));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Second call must hit the cache and not invoke compute.
    let second = open_with_cache_in(tmp.path(), &bytes, "", || {
        calls.fetch_add(1, Ordering::SeqCst);
        Computed::Cacheable(Payload(999)) // never observed
    });
    assert_eq!(second, Payload(7));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "compute must not re-run");
}

#[test]
fn host_cache_dir_is_used_and_untrusted_dir_is_skipped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bytes = unique_bytes("host_dir");
    let stored = open_with_cache(Some(tmp.path()), &bytes, "", || Computed::Cacheable(3u32));
    assert_eq!(stored, 3);
    assert!(entry_path(tmp.path(), &bytes, "").exists());
    let hit = open_with_cache(Some(tmp.path()), &bytes, "", || Computed::Cacheable(4u32));
    assert_eq!(hit, 3, "served from the host's directory");

    // A relative directory names different files from each working
    // directory; the cache is skipped and nothing is written there.
    let relative = Path::new("filefacts-relative-cache-dir-test");
    let computed = open_with_cache(Some(relative), &bytes, "", || Computed::Cacheable(5u32));
    assert_eq!(computed, 5);
    assert!(!relative.exists());
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
    let first = open_with_cache_in(tmp.path(), &bytes, "", || {
        calls.fetch_add(1, Ordering::SeqCst);
        Computed::Transient(Payload(1))
    });
    assert_eq!(first, Payload(1));
    // ...but nothing was written, so a second call recomputes rather
    // than serving the poisoned (degraded) entry.
    assert!(
        !entry_path(tmp.path(), &bytes, "").exists(),
        "transient result must not persist"
    );
    let second = open_with_cache_in(tmp.path(), &bytes, "", || {
        calls.fetch_add(1, Ordering::SeqCst);
        Computed::Cacheable(Payload(2))
    });
    assert_eq!(second, Payload(2));
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
    let a = open_with_cache_in(tmp.path(), &bytes, "rizin=none", || {
        Computed::Cacheable(Payload(10))
    });
    assert_eq!(a, Payload(10));
    // A run under a different fingerprint must miss and recompute,
    // not reuse the no-rizin payload.
    let b = open_with_cache_in(tmp.path(), &bytes, "rizin=0.7.2", || {
        Computed::Cacheable(Payload(20))
    });
    assert_eq!(b, Payload(20));
}

#[test]
fn missing_entry_loads_to_none() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = entry_path(tmp.path(), &unique_bytes("missing"), "");
    assert_eq!(load_capped::<u32>(&path, MAX_ENTRY_BYTES), None);
}

#[test]
fn lookups_do_not_create_directories() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("filefacts");
    let bytes = unique_bytes("lookup_no_mkdir");
    // A miss whose result is not persisted, and a plain load, both
    // leave the cache root untouched.
    let transient = open_with_cache_in(&root, &bytes, "", || Computed::Transient(1u32));
    assert_eq!(transient, 1);
    let path = entry_path(&root, &bytes, "");
    assert_eq!(load_capped::<u32>(&path, MAX_ENTRY_BYTES), None);
    assert!(!root.exists(), "a lookup must not create directories");
    // The first store creates the shard it writes into.
    let stored = open_with_cache_in(&root, &bytes, "", || Computed::Cacheable(2u32));
    assert_eq!(stored, 2);
    assert_eq!(load_capped::<u32>(&path, MAX_ENTRY_BYTES), Some(2));
}

#[test]
fn stng_is_locked_so_its_commit_keys_the_cache() {
    // Cached snapshots hold stng's output, and the key covers Cargo.lock
    // (see build.rs) but not stng's source. stng is a bare git dependency,
    // so the lock's `#<commit>` is what retires entries when stng changes;
    // a path override would record no commit and serve stale strings.
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"));
    let source = lock
        .split("[[package]]")
        .find(|entry| entry.contains("\nname = \"stng\"\n"))
        .and_then(|entry| entry.lines().find(|line| line.starts_with("source = ")))
        .expect("stng source in Cargo.lock");
    let commit = source
        .trim_end_matches('"')
        .rsplit_once('#')
        .map_or("", |(_, commit)| commit);
    assert!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "stng must be locked to a git commit: {source}"
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
    let tmp = tempfile::tempdir().expect("tempdir");
    let old = tmp.path().join("v0");
    fs::create_dir_all(&old).expect("create v0");
    let canary = old.join("canary");
    fs::write(&canary, b"old").expect("write canary");
    let current = version_location(tmp.path());
    fs::create_dir_all(&current).expect("create current");
    prune_old_versions(tmp.path());
    assert!(!canary.exists(), "v0 canary should be removed");
    assert!(current.exists(), "the current version is kept");
}

/// Create a file and stamp it with an explicit mtime.
fn file_with_mtime(dir: &Path, name: &str, mtime: SystemTime) -> PathBuf {
    let path = dir.join(name);
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
fn orphaned_store_temp_file_is_swept() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let shard = version_location(tmp.path()).join("ab");
    fs::create_dir_all(&shard).expect("shard");
    // A temp file named the way `store_at_path` names it, left behind as if
    // its writer died before the rename.
    let (_, orphan) = temp_in(&shard)
        .expect("temp file")
        .keep()
        .expect("keep temp file");
    fs::OpenOptions::new()
        .write(true)
        .open(&orphan)
        .expect("open for mtime")
        .set_modified(SystemTime::now() - Duration::from_hours(1))
        .expect("set mtime");
    Sweep::claim(&version_location(tmp.path()))
        .expect("unclaimed")
        .run(&BUDGET, Gate::Now);
    assert!(!orphan.exists(), "an orphaned temp file is swept");
}

#[test]
fn touch_lru_bumps_a_stale_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let old = SystemTime::now() - Duration::from_hours(3 * 24);
    let path = file_with_mtime(tmp.path(), "e.bin", old);
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
    let path = file_with_mtime(tmp.path(), "e.bin", recent);
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

#[test]
fn load_refuses_an_entry_that_decodes_past_the_cap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("bomb.bin");
    // A few hundred bytes of zstd that expand to 1 MiB of JSON.
    let json = serde_json::to_vec(&"a".repeat(1 << 20)).expect("json");
    fs::write(&path, zstd::encode_all(&json[..], 19).expect("zstd")).expect("write");
    assert!(fs::metadata(&path).expect("meta").len() < 64 * 1024);
    assert_eq!(load_capped::<String>(&path, 64 * 1024), None);
    // The same entry decodes when the cap allows it.
    assert_eq!(
        load_capped::<String>(&path, 2 << 20).map(|s| s.len()),
        Some(1 << 20)
    );
}

#[test]
fn corrupt_entry_is_a_miss() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bytes = unique_bytes("corrupt");
    let path = entry_path(tmp.path(), &bytes, "");
    fs::create_dir_all(path.parent().unwrap()).expect("shard");
    fs::write(&path, b"not zstd").expect("write");
    let value = open_with_cache_in(tmp.path(), &bytes, "", || Computed::Cacheable(9u32));
    assert_eq!(value, 9, "recomputed rather than served");
    assert_eq!(
        load_capped::<u32>(&path, MAX_ENTRY_BYTES),
        Some(9),
        "and overwritten"
    );
}
