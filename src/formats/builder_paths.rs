//! Builder paths: the build host's home directory and username, leaked
//! into a compiled binary.
//!
//! Binaries carry the developer workstation's filesystem layout in ways
//! no parser pass is needed to recover: Go's `pclntab` keeps every source
//! path unless built with `-trimpath`, DWARF's `DW_AT_comp_dir` is an
//! absolute path, `__FILE__` expansions survive `strip` in `.rodata`, and
//! a PE's PDB path names the build directory. All of them start at a home
//! directory, so one byte scan for `/home/`, `/Users/` and `C:\Users\`
//! finds them across formats.
//!
//! Emits:
//! - `build.source_paths[]` — builder-anchored paths in discovery order.
//! - `build.username` — the one person the paths name. Names that are not a
//!   person (`root`, CI accounts such as `runner` or `circleci`) don't count,
//!   and several distinct people mean no single answer. A username in the
//!   PE's PDB path (`C:\Users\<user>\…`) is one canonical reference rather
//!   than a scan, so it wins.
//! - `build.user_home` — that person's home directory, or, when no person is
//!   named, the only home directory the paths share. A CI runner's home
//!   (`/home/runner`) is exactly what attributes a pipeline build.

use std::collections::BTreeSet;

use serde_json::Value as JsonValue;

use crate::formats::common::put_str;
use crate::output::Values;
use crate::value_key;

/// Paths kept for `build.source_paths`.
const MAX_SOURCE_PATHS: usize = 32;
/// Longest path kept: real workstation paths run 60–120 bytes, and a much
/// longer run is usually scan noise.
const MAX_PATH_LEN: usize = 256;
/// Bytes scanned: real binaries leak their builder paths early, and the cap
/// bounds the work an adversarial input can demand.
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;

/// Account names that are not a person: system defaults, distro images and
/// CI runners. Their home directories are still reported.
const GENERIC_USERNAMES: &[&str] = &[
    "root",
    "user",
    "ubuntu",
    "debian",
    "alpine",
    "fedora",
    "runner",  // GitHub Actions
    "builder", // GitLab / generic CI
    "build",
    "circleci",
    "travis",
    "jenkins",
    "buildkite",
    "gitlab-runner",
    "vsts",
    "vstsadmin",
    "azpcontainer",
    "agent", // Azure Pipelines
    "container",
    "docker",
    "Administrator",
    "DefaultAccount",
    "Public",
];

/// Home-directory prefixes and the separator their paths use.
const PREFIXES: &[(&[u8], u8)] = &[
    (b"/home/", b'/'),
    (b"/Users/", b'/'),
    (b"C:\\Users\\", b'\\'),
    (b"C:/Users/", b'/'),
    (b"D:\\Users\\", b'\\'),
];

/// Scan `bytes` for builder paths and emit `build.*`. `pdb_path` is the PE
/// debug directory's PDB path, when the binary has one.
pub(super) fn emit(bytes: &[u8], pdb_path: Option<&str>, values: &mut Values) {
    let scan = bytes.get(..MAX_SCAN_BYTES).unwrap_or(bytes);
    let mut people = BTreeSet::new();
    let mut homes: BTreeSet<(String, String)> = BTreeSet::new();
    let mut paths: Vec<String> = Vec::new();

    for &(prefix, separator) in PREFIXES {
        let mut start = 0;
        while let Some(rest) = scan.get(start..)
            && let Some(pos) = memchr::memmem::find(rest, prefix)
        {
            let at = start + pos;
            let run = rest.get(pos..).unwrap_or_default();
            let len = run
                .iter()
                .position(|&b| !is_path_byte(b, separator))
                .unwrap_or(run.len());
            start = at + len.max(prefix.len());
            if len <= prefix.len() {
                continue;
            }
            let path = String::from_utf8_lossy(run.get(..len.min(MAX_PATH_LEN)).unwrap_or(run))
                .into_owned();
            let user = path
                .get(prefix.len()..)
                .and_then(|tail| first_component(tail, char::from(separator)));
            if let Some(user) = user.filter(|u| is_valid_username(u)) {
                if !is_generic_username(user) {
                    people.insert(user.to_owned());
                }
                homes.insert((
                    user.to_owned(),
                    format!("{}{user}", String::from_utf8_lossy(prefix)),
                ));
            }
            if paths.len() < MAX_SOURCE_PATHS && !paths.contains(&path) {
                paths.push(path);
            }
        }
    }

    let scanned = (people.len() == 1).then(|| people.pop_first()).flatten();
    let username = pdb_path.and_then(username_from_pdb).or(scanned);
    let user_home = match username.as_deref() {
        Some(user) => homes
            .iter()
            .find(|(u, _)| u == user)
            .map(|(_, h)| h.clone()),
        None if homes.len() == 1 => homes.pop_first().map(|(_, home)| home),
        None => None,
    };

    if let Some(user) = &username {
        put_str(values, value_key!("build.username"), user.as_str());
    }
    if let Some(home) = user_home {
        put_str(values, value_key!("build.user_home"), home);
    }
    if !paths.is_empty() {
        values.insert_key(
            value_key!("build.source_paths"),
            JsonValue::Array(paths.into_iter().map(JsonValue::String).collect()),
        );
    }
}

/// The username in a PDB path anchored at `<drive>:\Users\<user>\…` (either
/// separator), unless it is not a person.
fn username_from_pdb(pdb_path: &str) -> Option<String> {
    let path = pdb_path.trim();
    let lower = path.to_ascii_lowercase();
    let (start, separator) = lower
        .find(":\\users\\")
        .map(|i| (i + ":\\users\\".len(), '\\'))
        .or_else(|| lower.find(":/users/").map(|i| (i + ":/users/".len(), '/')))?;
    first_component(path.get(start..)?, separator)
        .filter(|user| is_valid_username(user) && !is_generic_username(user))
        .map(str::to_owned)
}

/// Path bytes: alphanumerics, the punctuation real paths use, and the path's
/// own separator. Whitespace and quotes end a path; a path with a space
/// is rare in builder directories, and allowing one tends to glue two
/// unrelated strings together.
fn is_path_byte(b: u8, separator: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'_' | b'-' | b'+' | b'@' | b'~' | b'%' | b'$' | b':'
        )
        || b == separator
}

/// The first `separator`-delimited component of `s`, which may be all of it
/// (`/home/alice` with nothing after the name).
fn first_component(s: &str, separator: char) -> Option<&str> {
    let first = s.split(separator).next()?;
    (!first.is_empty()).then_some(first)
}

/// Whether `s` looks like an account name rather than a fragment of some
/// other string (`%`, `$`).
fn is_valid_username(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@'))
}

fn is_generic_username(s: &str) -> bool {
    GENERIC_USERNAMES.iter().any(|g| g.eq_ignore_ascii_case(s))
}

#[cfg(test)]
mod tests;
