//! Fingerprints the crate's source for the disk cache key.
//!
//! `cache::cache_key` mixes `FILEFACTS_SOURCE_HASH` into every key, so an
//! entry written by a build with different extraction code is never reused.
//! Hashing the source, rather than reading the running executable's mtime,
//! keeps that true for embedding hosts, Nix store paths, `cp -p` and
//! container layers, and works the same when filefacts is a git or
//! crates.io dependency (both ship `src/`).
//!
//! The parsers filefacts calls (goblin, zip, tree-sitter, …) change its
//! output as much as its own source does, and when filefacts is a dependency
//! their versions come from the *consumer's* `Cargo.lock`, not ours. Cargo
//! does not tell a build script where that lock is, so it is found the way
//! cargo lays out a build (see [`consumer_lock`]). A host whose target
//! directory lives elsewhere, or that wants its own invalidation, adds a
//! namespace to every key with `OpenOptions::cache_namespace`.

use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let mut files = Vec::new();
    collect_files(&root.join("src"), &mut files);
    files.sort();
    // The manifest pins `stng` by rev, so it records that bump everywhere.
    files.push(root.join("Cargo.toml"));
    println!("cargo:rerun-if-changed=Cargo.toml");
    let own_lock = root.join("Cargo.lock");
    if own_lock.is_file() {
        files.push(own_lock.clone());
        println!("cargo:rerun-if-changed=Cargo.lock");
    }
    if let Some(lock) = consumer_lock(&own_lock) {
        println!("cargo:rerun-if-changed={}", lock.display());
        files.push(lock);
    }

    let mut hash = Fnv1a::default();
    for path in &files {
        let contents = fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        // The relative path too, so a rename or move changes the hash. The
        // consumer's lock is the one file outside the package; name it by
        // role, so where the consumer is checked out doesn't change the key.
        let relative = path.strip_prefix(&root).map_or_else(
            |_| "<consumer>/Cargo.lock".into(),
            |relative| relative.to_string_lossy(),
        );
        hash.write(relative.as_bytes());
        hash.write(&[0]);
        hash.write(&(contents.len() as u64).to_le_bytes());
        hash.write(&contents);
    }
    println!("cargo:rustc-env=FILEFACTS_SOURCE_HASH={:016x}", hash.0);
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
}

/// The `Cargo.lock` of the workspace this build belongs to, when it is not
/// filefacts' own. `OUT_DIR` is `<target>/<profile>/build/<pkg>-<hash>/out`,
/// and a workspace keeps its lock beside `<target>` unless
/// `CARGO_TARGET_DIR` moved it, so the nearest ancestor holding a
/// `Cargo.lock` is that workspace. Finding none (a relocated target dir)
/// leaves the key on filefacts' own source and lock.
fn consumer_lock(own_lock: &Path) -> Option<PathBuf> {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR")?);
    let lock = out_dir
        .ancestors()
        .map(|dir| dir.join("Cargo.lock"))
        .find(|lock| lock.is_file())?;
    let same = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    (!same(&lock, own_lock)).then_some(lock)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// 64-bit FNV-1a. Not collision-resistant, and doesn't need to be: it only
/// has to change when the source does.
struct Fnv1a(u64);

impl Default for Fnv1a {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv1a {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}
