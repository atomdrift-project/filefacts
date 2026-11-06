//! Python Core Metadata (`PKG-INFO`, a wheel's `METADATA`): the RFC 822
//! header block every Python package format carries, and the people it
//! names.

use super::people::{self, Person};
use crate::output::{ValueKey, Values};

/// The people a Core Metadata block names in its `<role>` and
/// `<role>-email` headers. PEP 621 writes several as comma-separated lists,
/// `"A <a@x>, B <b@x>"` in the email header, so the two lists pair up when
/// they are the same length; otherwise each entry stands alone. `UNKNOWN`,
/// setuptools' placeholder for a field the author left out, names nobody.
fn core_metadata_people(headers: &CoreMetadata, role: &str) -> Vec<Person> {
    let list = |field: &str| -> Vec<&str> {
        headers
            .first(field)
            .into_iter()
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "UNKNOWN")
            .collect()
    };
    let names = list(role);
    let emails = list(&format!("{role}-email"));
    if names.len() == emails.len() {
        return names
            .iter()
            .zip(&emails)
            .map(|(name, email)| Person::from_fields(Some(name), Some(email)))
            .collect();
    }
    names
        .iter()
        .map(|name| Person::from_fields(Some(name), None))
        .chain(
            emails
                .iter()
                .map(|email| Person::from_fields(None, Some(email))),
        )
        .collect()
}

/// Publish a Core Metadata block's authors and maintainers under `authors`
/// and `maintainers`, recording a cut list under `limits`.
pub(super) fn emit_people(
    headers: &CoreMetadata,
    values: &mut Values,
    authors: ValueKey,
    maintainers: ValueKey,
    limits: ValueKey,
) {
    people::put_list(
        values,
        authors,
        core_metadata_people(headers, "author"),
        limits,
    );
    people::put_list(
        values,
        maintainers,
        core_metadata_people(headers, "maintainer"),
        limits,
    );
}

/// A Python Core Metadata header block (`PKG-INFO`, a wheel's `METADATA`):
/// RFC 822 fields in file order, names lowercased, a field repeated once per
/// occurrence. A folded (continuation) line joins the field before it on a
/// newline; the block ends at the first blank line, which begins the long
/// description. The one parser for every Core Metadata reader.
pub(super) struct CoreMetadata {
    pub(super) fields: Vec<(String, String)>,
}

impl CoreMetadata {
    pub(super) fn parse(text: &str) -> Self {
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                break; // end of headers; body follows
            }
            if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = fields.last_mut() {
                    if !value.is_empty() {
                        value.push('\n');
                    }
                    value.push_str(line.trim());
                }
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                fields.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Self { fields }
    }

    /// The value of the first `field` (a lowercase name), unless it is
    /// empty.
    pub(super) fn first(&self, field: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}
