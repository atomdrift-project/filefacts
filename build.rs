//! Fingerprints the crate's source for the disk cache key.
//!
//! `cache::cache_key` mixes `FILEFACTS_SOURCE_HASH` into every key, so an
//! entry written by a build with different extraction code is never reused.
//! Hashing the source, rather than reading the running executable's mtime,
//! keeps that true for embedding hosts, Nix store paths, `cp -p` and
//! container layers, and works the same when filefacts is a git or
//! crates.io dependency (both ship `src/`).

use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let mut files = Vec::new();
    collect_files(&root.join("src"), &mut files);
    files.sort();
    // The manifest pins `stng` by rev, and a consumer's build resolves
    // dependencies from its own lock, so the manifest is what records a
    // dependency bump there. The lock adds exact versions when the package
    // carries one.
    files.push(root.join("Cargo.toml"));
    println!("cargo:rerun-if-changed=Cargo.toml");
    let lock = root.join("Cargo.lock");
    if lock.is_file() {
        files.push(lock);
        println!("cargo:rerun-if-changed=Cargo.lock");
    }

    let mut hash = Fnv1a::default();
    for path in &files {
        let contents = fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        // The relative path too, so a rename or move changes the hash.
        let relative = path.strip_prefix(&root).unwrap_or(path);
        hash.write(relative.to_string_lossy().as_bytes());
        hash.write(&[0]);
        hash.write(&(contents.len() as u64).to_le_bytes());
        hash.write(&contents);
    }
    println!("cargo:rustc-env=FILEFACTS_SOURCE_HASH={:016x}", hash.0);
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
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
