//! Debian package (`.deb`) metadata extractor.
//!
//! A `.deb` is a Unix `ar` archive with three members: `debian-binary` (a
//! version marker), `control.tar.*` (the package metadata), and `data.tar.*`
//! (the installed files). The package's *identity* — name, version,
//! architecture, maintainer, dependencies — lives in `control.tar`'s
//! `./control` file, outside the installed file tree. This extractor walks the
//! `ar` member table, decompresses only the small `control.tar`, reads its
//! `control` member, and surfaces the RFC822 fields as `deb.*` facts.
//!
//! Emitted keys:
//!
//! - `deb.name`, `deb.version`, `deb.arch` — core identity.
//! - `deb.maintainers` (`Maintainer` and `Uploaders`), `deb.section`,
//!   `deb.priority` — provenance / category.
//! - `deb.description` — the `Description` synopsis (first line).
//! - `deb.dependencies[]` — runtime dependency package names (bounded).
//! - `deb.installed_size_kib` — declared installed size in KiB.
//! - `deb.limits[]` — `{stage, reason}` when the control archive was left
//!   unread or read short by design: a compression `dpkg` does not write for
//!   `control.tar` (it writes none, gzip, xz or zstd), an archive that
//!   inflates past the size cap, or a `control` file past its own cap. A
//!   control archive that fails to decompress, or an `ar` table that breaks
//!   off before reaching it, is a parse failure and is recorded in `errors`
//!   instead.

use super::people::{self, Person};
use crate::metric;
use std::io::Read;

use serde_json::Value as JsonValue;

use super::bounded::{Limits, MemberPrefix, inflate_capped, xz_decoder, zstd_decoder};
use crate::error::Error;
use crate::output::{Errors, Metrics, Stage, ValueKey, Values};
use crate::value_key;

const AR_MAGIC: &[u8] = b"!<arch>\n";
/// `ar` member headers are a fixed 60 bytes.
const AR_HEADER_LEN: usize = 60;
/// Cap on the inflated `control.tar` walked for its `control` file.
const MAX_CONTROL_TAR: u64 = 4 << 20; // 4 MiB
/// Cap on the decompressed `control` file (guards a decompression bomb).
const MAX_CONTROL_FILE: u64 = 1 << 20; // 1 MiB
/// Cap on the dependency-name list retained.
const MAX_DEPENDS: usize = 256;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) -> Result<(), Error> {
    if !bytes.starts_with(AR_MAGIC) {
        return Err(Error::malformed("deb", "missing ar archive magic"));
    }

    // Walk the `ar` member table to find `control.tar*`. Members are laid out
    // as [60-byte header][data, 2-byte aligned].
    let mut pos = AR_MAGIC.len();
    while let Some(header) = bytes
        .get(pos..)
        .and_then(<[u8]>::first_chunk::<AR_HEADER_LEN>)
    {
        let name = ar_member_name(&header[0..16]);
        // A header that does not parse, or a member running past the end of
        // the file, ends the walk before `control.tar` was reached: the
        // package identity is unreadable, not absent.
        let Some(size) = ar_member_size(&header[48..58]) else {
            errors.record_malformed(
                Stage::FormatExtract,
                format!("ar member {name:?} at offset {pos}: unparseable size field"),
            );
            break;
        };
        let data_start = pos + AR_HEADER_LEN;
        let Some(member) = data_start
            .checked_add(size)
            .and_then(|data_end| bytes.get(data_start..data_end))
        else {
            errors.record_malformed(
                Stage::FormatExtract,
                format!(
                    "ar member {name:?} at offset {pos}: {size} bytes run past the end of the file"
                ),
            );
            break;
        };

        if name.starts_with("control.tar") {
            let mut limits = Limits::default();
            match read_control_file(&name, member) {
                Ok(Some(control)) => {
                    if control.truncated {
                        limits.push(
                            "control-file",
                            format!("control over the {MAX_CONTROL_FILE}-byte cap; read short"),
                        );
                    }
                    parse_control(&control.bytes, values, metrics);
                }
                // No `control` file inside: nothing to read, nothing failed.
                Ok(None) => {}
                Err(ControlError::Unread(reason)) => limits.push("control-archive", reason),
                Err(ControlError::Malformed(why)) => {
                    errors.record_malformed(Stage::TarParse, format!("{name}: {why}"));
                }
            }
            limits.emit(values, value_key!("deb.limits"));
            return Ok(());
        }

        // ar member data is padded to an even byte boundary.
        let data_end = data_start + member.len();
        pos = data_end + (data_end & 1);
    }
    Ok(())
}

/// The member name is a 16-byte field, space-padded, sometimes `/`-terminated.
fn ar_member_name(field: &[u8]) -> String {
    String::from_utf8_lossy(field)
        .trim_end()
        .trim_end_matches('/')
        .to_string()
}

/// The size field is a 10-byte ASCII decimal, space-padded.
fn ar_member_size(field: &[u8]) -> Option<usize> {
    std::str::from_utf8(field).ok()?.trim().parse().ok()
}

/// Why the `control` file could not be read out of `control.tar*`.
#[derive(Debug)]
enum ControlError {
    /// Left unread by design (no decoder for the compression, or the size
    /// cap): a coverage limit for `deb.limits`.
    Unread(String),
    /// The archive failed to decompress or its tar headers are corrupt.
    Malformed(String),
}

/// Decompress `control.tar*` (by suffix) and return the start of its
/// `control` member, `Ok(None)` when the archive holds no `control` file.
fn read_control_file(name: &str, member: &[u8]) -> Result<Option<MemberPrefix>, ControlError> {
    let has = |suffix| super::common::ends_with_ci(name, suffix);
    let reader: Box<dyn Read + '_> = if has(".gz") {
        Box::new(flate2::read::GzDecoder::new(member))
    } else if has(".xz") {
        Box::new(xz_decoder(member))
    } else if has(".zst") {
        Box::new(zstd_decoder(member).map_err(|e| ControlError::Malformed(e.to_string()))?)
    } else if has(".tar") {
        Box::new(member)
    } else {
        return Err(ControlError::Unread(format!(
            "{name}: no decoder for this compression; control fields not read"
        )));
    };

    let mut archive = tar::Archive::new(reader.take(MAX_CONTROL_TAR));
    let outcome = find_control(&mut archive);
    // Past the cap the tar stream is cut short, which can surface as a
    // truncation error or as a clean end with no `control` seen. Either way
    // that is the cap speaking, not the archive.
    if archive.into_inner().limit() == 0 && !matches!(outcome, Ok(Some(_))) {
        return Err(ControlError::Unread(format!(
            "{name}: inflates past the {MAX_CONTROL_TAR}-byte cap before a control file"
        )));
    }
    outcome.map_err(|e| ControlError::Malformed(e.to_string()))
}

/// Walk a decompressed `control.tar` for its `./control` member.
fn find_control<R: Read>(archive: &mut tar::Archive<R>) -> std::io::Result<Option<MemberPrefix>> {
    for entry in archive.entries()? {
        let entry = entry?;
        // `path()` borrows the entry immutably; resolve the match before the
        // read consumes it.
        let is_control = entry
            .path()
            .is_ok_and(|p| matches!(p.to_string_lossy().as_ref(), "./control" | "control"));
        if is_control {
            return inflate_capped(entry, MAX_CONTROL_FILE).map(Some);
        }
    }
    Ok(None)
}

/// Parse the RFC822 `control` file. Continuation lines (leading whitespace)
/// extend the previous field; we only need the single-line fields here.
fn parse_control(control: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let text = String::from_utf8_lossy(control);
    // `Maintainer` and the co-maintainers in `Uploaders`, each a
    // `"Name <email>"` person (Debian Policy §5.6.2, §5.6.3).
    let mut maintainers = Vec::new();
    for line in text.lines() {
        // Field values are `Key: value`; skip continuation/blank lines.
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "Package" => insert_str(values, value_key!("deb.name"), value),
            "Version" => insert_str(values, value_key!("deb.version"), value),
            "Architecture" => insert_str(values, value_key!("deb.arch"), value),
            "Maintainer" => maintainers.push(Person::parse(value)),
            "Uploaders" => maintainers.extend(value.split(',').map(Person::parse)),
            "Section" => insert_str(values, value_key!("deb.section"), value),
            "Priority" => insert_str(values, value_key!("deb.priority"), value),
            // `Description`'s first line is the synopsis; the indented
            // continuation lines (the long description) are skipped above.
            "Description" => insert_str(values, value_key!("deb.description"), value),
            "Installed-Size" => {
                if let Ok(kib) = value.parse::<f64>() {
                    metrics.insert(metric!("deb.installed_size_kib"), kib);
                }
            }
            "Depends" => {
                let names = dependency_names(value);
                if !names.is_empty() {
                    metrics.insert(metric!("deb.dependency_count"), names.len() as f64);
                    values.insert_key(
                        value_key!("deb.dependencies"),
                        JsonValue::Array(names.into_iter().map(JsonValue::String).collect()),
                    );
                }
            }
            _ => {}
        }
    }
    people::put(values, value_key!("deb.maintainers"), maintainers);
}

/// Extract the bare package names from a `Depends` field, dropping version
/// constraints (`libc6 (>= 2.34)`) and alternatives (`a | b` → both). Bounded.
fn dependency_names(field: &str) -> Vec<String> {
    let mut names = Vec::new();
    for clause in field.split(',') {
        for alt in clause.split('|') {
            // The package name is the leading token, before any whitespace or
            // version-constraint parenthesis.
            let name = alt
                .trim()
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() && names.len() < MAX_DEPENDS {
                names.push(name.to_string());
            }
        }
    }
    names
}

fn insert_str(values: &mut Values, key: ValueKey, value: &str) {
    values.insert_key(key, JsonValue::String(value.to_string()));
}

#[cfg(test)]
mod tests;
