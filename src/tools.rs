//! Cached external-tool resolution with platform fallbacks.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static RESOLUTIONS: OnceLock<Mutex<HashMap<String, Option<PathBuf>>>> = OnceLock::new();

/// Resolve an external executable once per process.
///
/// PATH is checked before platform fallback locations, and the resulting
/// absolute path—or a miss—is cached. Only absolute PATH entries are
/// searched, and on unix only files with an execute bit match. Callers
/// should pass the returned path to `Command::new` instead of relying on a
/// child process to repeat resolution.
#[must_use]
pub fn resolve(name: &str) -> Option<PathBuf> {
    let cache = RESOLUTIONS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock()
        && let Some(resolution) = cache.get(name)
    {
        return resolution.clone();
    }
    // Probe without the lock, so one slow filesystem walk doesn't stall
    // every other lookup. Racing callers may both probe; the first answer
    // stored is the one everyone gets.
    let resolution = resolve_uncached(name);
    match cache.lock() {
        Ok(mut cache) => cache.entry(name.to_string()).or_insert(resolution).clone(),
        Err(_) => resolution,
    }
}

fn resolve_uncached(name: &str) -> Option<PathBuf> {
    binary_in_path(name).or_else(|| fallback_binary(name))
}

fn binary_in_path(name: &str) -> Option<PathBuf> {
    binary_in(&std::env::var_os("PATH")?, name)
}

/// Search the directories of a `PATH`-style list for `name`.
fn binary_in(path_list: &OsStr, name: &str) -> Option<PathBuf> {
    let names = candidate_names(name);
    std::env::split_paths(path_list)
        // An empty or relative entry resolves against the working
        // directory, which for a scanner is often the sample tree itself:
        // a planted `./rizin` must not be what runs.
        .filter(|dir| dir.is_absolute())
        .find_map(|dir| {
            names
                .iter()
                .map(|candidate| dir.join(candidate))
                .find(|candidate| is_executable(candidate))
        })
}

/// A regular file with an execute bit set. Windows has no execute bit, so
/// there it is any regular file.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn fallback_binary(name: &str) -> Option<PathBuf> {
    let names = candidate_names(name);
    for root in fallback_roots() {
        if let Some(binary) = names
            .iter()
            .map(|candidate| root.join(candidate))
            .find(|candidate| is_executable(candidate))
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
        if is_executable(&path)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Component;

    const TOOL: &str = "filefacts-test-tool";

    fn tool_in(dir: &Path, mode: u32) -> PathBuf {
        let tool = dir.join(TOOL);
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write tool");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(mode)).expect("chmod");
        tool
    }

    #[test]
    fn relative_path_entries_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tool = tool_in(tmp.path(), 0o755);
        // The same directory, spelled relative to the working directory.
        let cwd = std::env::current_dir().expect("cwd");
        let relative: PathBuf = cwd
            .components()
            .skip(1)
            .map(|_| Component::ParentDir)
            .chain(tmp.path().components().skip(1))
            .collect();
        assert!(relative.join(TOOL).is_file(), "{}", relative.display());
        assert_eq!(binary_in(relative.as_os_str(), TOOL), None);
        assert_eq!(binary_in(OsStr::new(""), TOOL), None);
        assert_eq!(binary_in(tmp.path().as_os_str(), TOOL), Some(tool));
    }

    #[test]
    fn non_executable_files_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tool = tool_in(tmp.path(), 0o644);
        assert_eq!(binary_in(tmp.path().as_os_str(), TOOL), None);
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(binary_in(tmp.path().as_os_str(), TOOL), Some(tool));
    }
}
