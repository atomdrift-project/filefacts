//! Fingerprints the crate's source for the disk cache key.
//!
//! `cache::cache_key` mixes `FILEFACTS_SOURCE_HASH` into every key, so an
//! entry written by a build with different extraction code is never reused.
//! Hashing the source, rather than reading the running executable's mtime,
//! keeps that true for embedding hosts, Nix store paths, `cp -p` and
//! container layers, and works the same when filefacts is a git or
//! crates.io dependency (both ship `src/`).
//!
//! The hash covers only files inside this package: everything under `src/`
//! (the Rust source and the data it embeds, such as trust anchors) except
//! test fixtures and hidden files, plus `Cargo.toml` and `Cargo.lock`. The
//! lock records which commit of the git `stng` dependency a standalone build
//! uses. When filefacts is a dependency, its parsers' versions come from the
//! consumer's lock, which this script deliberately does not read; a host that
//! wants entries retired on its own dependency updates adds a namespace with
//! `OpenOptions::cache_namespace`.

use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let mut files = Vec::new();
    collect_files(&root.join("src"), &mut files);
    files.sort();
    for name in ["Cargo.toml", "Cargo.lock"] {
        let path = root.join(name);
        if path.is_file() {
            println!("cargo:rerun-if-changed={name}");
            files.push(path);
        }
    }

    let mut hash = Fnv1a::default();
    for path in &files {
        let contents = fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        // The relative path too, so a rename or move changes the hash.
        let relative = path.strip_prefix(&root).unwrap_or(path).to_string_lossy();
        hash.write(relative.as_bytes());
        hash.write(&[0]);
        hash.write(&(contents.len() as u64).to_le_bytes());
        hash.write(&contents);
    }
    println!("cargo:rustc-env=FILEFACTS_SOURCE_HASH={:016x}", hash.0);
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
}

/// Appends every file under `dir` to `out`, skipping hidden entries (editor
/// and Finder droppings would make the key depend on the checkout) and
/// `testdata` directories (fixtures are test inputs, not extraction code, and
/// a build must not depend on reading them).
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            if name != "testdata" {
                collect_files(&path, out);
            }
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
