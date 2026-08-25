//! Cached external-tool resolution with platform fallbacks.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static RESOLUTIONS: OnceLock<Mutex<HashMap<String, Option<PathBuf>>>> = OnceLock::new();

/// Resolve an external executable once per process.
///
/// PATH is checked before platform fallback locations, and the resulting
/// absolute path—or a miss—is cached. Callers should pass the returned path to
/// `Command::new` instead of relying on a child process to repeat resolution.
#[must_use]
pub fn resolve(name: &str) -> Option<PathBuf> {
    let cache = RESOLUTIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut cache) = cache.lock() else {
        return resolve_uncached(name);
    };
    if let Some(resolution) = cache.get(name) {
        return resolution.clone();
    }
    let resolution = resolve_uncached(name);
    cache.insert(name.to_string(), resolution.clone());
    resolution
}

fn resolve_uncached(name: &str) -> Option<PathBuf> {
    binary_in_path(name).or_else(|| fallback_binary(name))
}

fn binary_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        candidate_names(name)
            .iter()
            .map(|candidate| dir.join(candidate))
            .find(|candidate| candidate.is_file())
    })
}

fn fallback_binary(name: &str) -> Option<PathBuf> {
    let names = candidate_names(name);
    for root in fallback_roots() {
        if let Some(binary) = names
            .iter()
            .map(|candidate| root.join(candidate))
            .find(|candidate| candidate.is_file())
        {
            return Some(binary);
        }
    }

    #[cfg(windows)]
    {
        let packages = windows_env_path("LOCALAPPDATA")?.join("Microsoft/WinGet/Packages");
        return find_in_tree(&packages, &names, 5);
    }

    None
}

fn candidate_names(name: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let mut names = vec![name.to_string()];
        if std::path::Path::new(name).extension().is_none() {
            names.extend([
                format!("{name}.exe"),
                format!("{name}.cmd"),
                format!("{name}.bat"),
            ]);
        }
        names
    }
    #[cfg(not(windows))]
    {
        vec![name.to_string()]
    }
}

fn fallback_roots() -> Vec<PathBuf> {
    let roots = vec![
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ];

    #[cfg(any(target_os = "macos", windows))]
    let mut roots = roots;

    #[cfg(target_os = "macos")]
    roots.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/opt/local/bin"),
    ]);

    #[cfg(windows)]
    {
        for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(base) = windows_env_path(variable) {
                roots.extend([
                    base.join("7-Zip"),
                    base.join("Rizin"),
                    base.join("Rizin/bin"),
                    base.join("UPX"),
                    base.join("upx"),
                    base.join("innoextract"),
                    base.join("InnoExtract"),
                ]);
            }
        }
        if let Some(local) = windows_env_path("LOCALAPPDATA") {
            roots.extend([
                local.join("Programs/7-Zip"),
                local.join("Programs/Rizin"),
                local.join("Programs/Rizin/bin"),
                local.join("Programs/UPX"),
                local.join("Programs/upx"),
                local.join("Programs/innoextract"),
                local.join("Programs/InnoExtract"),
                local.join("Microsoft/WinGet/Links"),
                local.join("Microsoft/WinGet/Packages"),
            ]);
        }
    }

    roots
}

#[cfg(windows)]
fn windows_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

#[cfg(windows)]
fn find_in_tree(root: &std::path::Path, names: &[String], depth: usize) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path.file_name().is_some_and(|file_name| {
                names
                    .iter()
                    .any(|name| file_name.eq_ignore_ascii_case(name))
            })
        {
            return Some(path);
        }
        if entry.file_type().is_ok_and(|kind| kind.is_dir())
            && let Some(binary) = find_in_tree(&path, names, depth - 1)
        {
            return Some(binary);
        }
    }
    None
}
