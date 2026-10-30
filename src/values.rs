//! Typed reads of the [`Values`] facts that consumers act on.
//!
//! Read by path, the values tree gives a consumer no warning when a key
//! moves or a field changes type. Each function here reads one fact family
//! through the same declaration filefacts writes it with, so the reader and
//! the writer cannot drift apart.
//!
//! Every function takes a bare [`Values`], so it reads a tree retained from an
//! earlier analysis (rebuilt with [`Values::from`], or deserialized) exactly
//! as it reads [`crate::ParsedFile::values`]. Results borrow from the tree and
//! nothing is copied. A retained tree may not have come from filefacts at all:
//! an entry of the wrong shape is skipped, never guessed at.
//!
//! ```
//! let parsed = filefacts::OpenOptions::new()
//!     .path(std::path::Path::new("package.json"))
//!     .rizin(false)
//!     .open(br#"{"name": "x", "scripts": {"postinstall": "node setup.js"}}"#);
//! let retained = serde_json::to_string(parsed.values()).unwrap();
//! let values: filefacts::Values = serde_json::from_str(&retained).unwrap();
//! let hooks: Vec<_> = filefacts::values::npm_install_hooks(&values).collect();
//! assert_eq!(hooks, [("postinstall", "node setup.js")]);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ValueKey, Values, value_key};

/// The file's name without its directory (`file.basename`), present when the
/// caller gave filefacts a path ([`crate::OpenOptions::path`]).
pub fn basename(values: &Values) -> Option<&str> {
    values.get_key(value_key!("file.basename"))?.as_str()
}

/// The npm lifecycle hooks that run when a package is installed, in the order
/// npm runs them, each with the key its command is written to.
pub(crate) const NPM_INSTALL_HOOKS: [(&str, ValueKey); 3] = [
    ("preinstall", value_key!("npm.scripts.preinstall")),
    ("install", value_key!("npm.scripts.install")),
    ("postinstall", value_key!("npm.scripts.postinstall")),
];

/// The install-time lifecycle hooks an npm manifest declares, as
/// `(hook, command)` in the order npm runs them: `preinstall`, `install`,
/// `postinstall`. The command is the script text npm hands to a shell; other
/// scripts never run on install and are not listed.
pub fn npm_install_hooks(values: &Values) -> impl Iterator<Item = (&'static str, &str)> {
    NPM_INSTALL_HOOKS
        .into_iter()
        .filter_map(|(hook, key)| Some((hook, values.get_key(key)?.as_str()?)))
}

/// One Batch command as it appears in the source (`source.batch.command_sites[]`).
///
/// This is source text, not argv: CMD quoting and `%` / `!` expansion are not
/// applied, so a consumer recognizing a command must treat what it cannot
/// read literally as a runtime value. Offsets are byte offsets into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BatchCommandSite<'a> {
    /// The command word as written (`@MSHTA.EXE`, `C:\Windows\mshta`).
    pub name: &'a str,
    /// The whole command, from its first byte to its last.
    pub text: &'a str,
    /// Where `text` starts.
    pub offset: u64,
    /// Where `name` starts.
    pub name_offset: u64,
    /// Where `name` ends.
    pub name_end: u64,
}

/// The command sites of a Batch file, in source order.
///
/// filefacts records a bounded number of sites; when it stops early,
/// [`batch_command_sites_truncated`] says so. A tree from elsewhere is not
/// bounded, so a consumer should cap how many it reads.
pub fn batch_command_sites(values: &Values) -> impl Iterator<Item = BatchCommandSite<'_>> {
    values
        .get_key(value_key!("source.batch.command_sites"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|site| BatchCommandSite::deserialize(site).ok())
}

/// Whether filefacts stopped recording Batch command sites at its budget, so
/// [`batch_command_sites`] is missing later ones.
pub fn batch_command_sites_truncated(values: &Values) -> bool {
    values
        .get_key(value_key!("source.batch.command_sites_truncated"))
        .and_then(Value::as_bool)
        == Some(true)
}

#[cfg(test)]
mod tests;
