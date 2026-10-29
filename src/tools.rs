//! Resolving the external tools rizin integration runs, and the environment
//! such a tool may inherit.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

static RESOLUTIONS: OnceLock<Mutex<HashMap<String, Option<PathBuf>>>> = OnceLock::new();

/// The environment variables a tool parsing untrusted input may inherit: what
/// it needs to find helpers, temp space, and a locale, plus the variables a
/// Windows process needs to start.
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
];

/// Replace `cmd`'s environment with the allowlisted subset of this process's.
///
/// A tool that parses sample bytes can be taken over by them, so it must not
/// inherit secrets such as API tokens and service keys from its caller. Apply
/// this to every such tool before spawning it.
pub(crate) fn scrub_env(cmd: &mut Command) {
    cmd.env_clear();
    for key in ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

/// Resolve an external executable once per process.
///
/// PATH is checked before platform fallback locations, and the resulting
/// absolute path—or a miss—is cached. Only absolute PATH entries are
/// searched, and on unix only files with an execute bit match. Callers
/// should pass the returned path to `Command::new` instead of relying on a
/// child process to repeat resolution.
#[must_use]
pub(crate) fn resolve(name: &str) -> Option<PathBuf> {
    let cache = RESOLUTIONS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock()
        && let Some(resolution) = cache.get(name)
    {
        return resolution.clone();
    }
    // Probe without the lock, so one slow filesystem walk doesn't stall
    // every other lookup. Racing callers may both probe; the first answer
    // stored is the one everyone gets.
    let resolution = std::env::var_os("PATH")
        .and_then(|path| binary_in(&path, name))
        .or_else(|| fallback_binary(name));
    match cache.lock() {
        Ok(mut cache) => cache.entry(name.to_string()).or_insert(resolution).clone(),
        Err(_) => resolution,
    }
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

/// The first executable `name` in the platform's conventional install
/// locations, for a host whose `PATH` omits them.
fn fallback_binary(name: &str) -> Option<PathBuf> {
    let names = candidate_names(name);
    fallback_roots().into_iter().find_map(|root| {
        names
            .iter()
            .map(|candidate| root.join(candidate))
            .find(|candidate| is_executable(candidate))
    })
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
                roots.extend([base.join("Rizin"), base.join("Rizin/bin")]);
            }
        }
        if let Some(local) = windows_env_path("LOCALAPPDATA") {
            roots.extend([
                local.join("Programs/Rizin"),
                local.join("Programs/Rizin/bin"),
                local.join("Microsoft/WinGet/Links"),
            ]);
        }
    }

    roots
}

#[cfg(windows)]
fn windows_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

#[cfg(all(test, unix))]
mod tests;
