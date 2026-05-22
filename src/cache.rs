//! Disk cache for expose analysis output.
//!
//! Mirrors cleave's `~/.cache/cleave/re/` cache shape but lives under
//! a separate expose-owned directory so the two caches can evolve
//! independently during the cleave→expose rizin migration. After Wave
//! D the cleave cache goes away and this is the canonical store.
//!
//! # Layout
//!
//! ```text
//! {cache_dir}/expose/v{SCHEMA_VERSION}/{sha[0..2]}/{sha}.bin
//! ```
//!
//! The two-character shard keeps any single directory bounded; the
//! schema-version directory ensures cached bytes from an older
//! binary are not silently reused when fields are added.
//!
//! # Format
//!
//! `bincode`-encoded payload, then zstd-compressed at level 3. Writes
//! go through a `.tmp` file followed by an atomic rename so two
//! processes hashing the same input cannot corrupt the entry.
//!
//! # Schema version
//!
//! Bumped whenever `expose::Function`, `Sections`, `Imports`,
//! `Exports`, `Strings` schema changes meaningfully. Field
//! additions (e.g. the CFG fields added in Wave A) bump the cache
//! version even when the JSON `SCHEMA_VERSION` constant stays the
//! same — cache bytes serialised through bincode are positionally
//! sensitive in a way the JSON view is not.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// On-disk cache schema version. Bump on any meaningful change to
/// the cached payload's bincode shape. Wave A introduces the cache
/// at version 1 with the CFG-enriched `Function` and the
/// section/encoding-enriched `ExtractedString`.
pub const CACHE_SCHEMA_VERSION: u32 = 1;

/// SHA-256 a byte slice, returning the lowercase hex digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Root cache directory for expose. Returns the first writable
/// candidate from (OS cache dir + `expose`) → temp dir + `expose-cache`.
pub fn cache_root() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(base) = dirs::cache_dir() {
        candidates.push(base.join("expose"));
    }
    candidates.push(std::env::temp_dir().join("expose-cache"));
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
    bincode::deserialize(&decompressed).ok()
}

/// Encode + compress + write a payload atomically. Best-effort —
/// disk failures are swallowed; the cache is a performance
/// optimisation, not a source of truth.
pub fn store<T: serde::Serialize>(sha_hex: &str, value: &T) {
    let Some(path) = entry_path(sha_hex) else {
        return;
    };
    let Ok(serialized) = bincode::serialize(value) else {
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
    let Ok(entries) = fs::read_dir(&root) else {
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

/// Open `bytes` through the disk cache: hash → lookup → on miss,
/// run `compute` and store the result. Returns the cached or freshly
/// computed value. Returns `None` if `compute` itself returns `None`.
///
/// The cache key includes the schema version implicitly (it lives in
/// a versioned subdirectory). Callers do not need to vary the key on
/// schema bumps.
pub fn open_with_cache<T, F>(bytes: &[u8], compute: F) -> Option<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce(&[u8]) -> Option<T>,
{
    let sha = sha256_hex(bytes);
    if let Some(cached) = load::<T>(&sha) {
        return Some(cached);
    }
    let value = compute(bytes)?;
    store(&sha, &value);
    Some(value)
}

/// Best-effort cache-entry path predicate. Returns `true` when a
/// cached entry for the given bytes already exists on disk.
pub fn is_cached(bytes: &[u8]) -> bool {
    let sha = sha256_hex(bytes);
    entry_path(&sha).is_some_and(|p| p.exists())
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
        format!("expose-cache-test:{tag}:{}:{ns}", std::process::id()).into_bytes()
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
        let first = open_with_cache::<Payload, _>(&bytes, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(Payload(7))
        });
        assert_eq!(first, Some(Payload(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second call must hit the cache and not invoke compute.
        let second = open_with_cache::<Payload, _>(&bytes, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(Payload(999)) // never observed
        });
        assert_eq!(second, Some(Payload(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "compute must not re-run");
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
        // Create a synthetic `v0` directory next to the live one and
        // confirm prune removes it. Use a private temp root via
        // XDG_CACHE_HOME so this test doesn't fight the real cache.
        let tmp = tempfile::tempdir().expect("tempdir");
        // SAFETY: setting an env var is not thread-safe but the cache
        // root is read on every call, so isolating via env on a
        // per-test temp is fine for serial tests. If this becomes
        // flaky under parallel runs, switch to a `version_dir` param.
        let prev = std::env::var_os("XDG_CACHE_HOME");
        // SAFETY: same caveat as above.
        // SAFETY-justified env mutation kept tightly scoped.
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", tmp.path());
        }
        let root = cache_root().expect("cache root with overridden XDG_CACHE_HOME");
        let old = root.join("v0");
        fs::create_dir_all(&old).expect("create v0");
        let canary = old.join("canary");
        fs::write(&canary, b"old").expect("write canary");
        assert!(canary.exists());
        prune_old_versions();
        assert!(!canary.exists(), "v0 canary should be removed");
        // Restore env.
        // SAFETY: same caveat.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
        }
    }
}
