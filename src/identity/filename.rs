//! Name and version from the artifact's own filename, the weakest claim
//! there is.

use super::str_value;
use crate::output::{Claim, Identity, Values};
use crate::value_key;

/// Archive extensions whose stems conventionally encode `<name><sep><version>`.
/// Deliberately scoped to source/archive containers: package formats (rpm,
/// whl, nupkg, gem, …) carry real metadata their extractors already surface,
/// and a filename guess must never shadow it. Longest form first so
/// `.tar.gz` wins over `.tar`; matched case-insensitively for the era's
/// `.tar.Z` (compress) spelling.
const ARCHIVE_EXTS: &[&str] = &[
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.z", ".tgz", ".tbz2", ".txz", ".taz",
    ".tar", ".zip",
];

/// Fill `name`/`version` from the artifact's own filename when no embedded
/// source claimed them. `file.basename` is recorded by extraction whenever
/// the caller supplied a path.
pub(super) fn filename_fallback(values: &Values, id: &mut Identity) {
    if id.name.is_some() {
        return;
    }
    let Some(base) = str_value(values, value_key!("file.basename")) else {
        return;
    };
    let Some((name, version)) = split_name_version(base) else {
        return;
    };
    id.name = Some(Claim::claimed(name, "file.basename"));
    if id.version.is_none() {
        id.version = Some(Claim::claimed(version, "file.basename"));
    }
}

/// Split an archive filename into its conventional `(name, version)`:
/// `wuftpd-10.9.2.tgz` → ("wuftpd", "10.9.2"), covering the hyphen,
/// underscore (`apache_1.3.9`), and dotted (`sendmail.8.9.1`) separators of
/// thirty years of source releases. Conservative by construction: the stem
/// must end in a known archive extension and the boundary is the first
/// separator whose remainder is version-shaped (digit-led after an optional
/// `v`); anything else returns `None` rather than guessing. A leading
/// `YYYY-MM-DD-` disclosure stamp (threat-feed dataset naming) is stripped
/// first.
fn split_name_version(base: &str) -> Option<(&str, &str)> {
    // Case-insensitive suffix match without lowercasing the whole name — the
    // era's `.tar.Z` folds onto `.tar.z` here.
    let ext_len = ARCHIVE_EXTS.iter().find_map(|ext| {
        let start = base.len().checked_sub(ext.len())?;
        base.get(start..)?
            .eq_ignore_ascii_case(ext)
            .then_some(ext.len())
    })?;
    let stem = strip_date_prefix(&base[..base.len() - ext_len]);
    // The boundary is the first separator whose remainder is version-shaped:
    // digit-led (after an optional `v`), then the usual version alphabet. A
    // separator at position 0 would leave no name, and one at the end leaves
    // an empty remainder, which is not digit-led.
    for (i, _) in stem.match_indices(['-', '_', '.']).filter(|&(i, _)| i > 0) {
        let rest = &stem[i + 1..];
        let mut tail = rest.strip_prefix('v').unwrap_or(rest).chars();
        if tail.next().is_some_and(|c| c.is_ascii_digit())
            && tail.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-'))
        {
            return Some((&stem[..i], rest));
        }
    }
    None
}

/// Strip a leading `YYYY-MM-DD-` date stamp, digit-bounded so version-like
/// names ("2020-vision") survive intact.
fn strip_date_prefix(stem: &str) -> &str {
    let Some((date, rest)) = stem.as_bytes().split_first_chunk::<11>() else {
        return stem;
    };
    // Shape first — digits where digits belong, dashes at 4, 7 and 10 — then
    // the cheap plausibility bounds: a 1000s/2000s year, month < 20, day < 40.
    let stamped = !rest.is_empty()
        && date.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 | 10 => c == b'-',
            _ => c.is_ascii_digit(),
        })
        && matches!(date[0], b'1' | b'2')
        && date[5] <= b'1'
        && date[8] <= b'3';
    if stamped {
        stem.get(11..).unwrap_or(stem)
    } else {
        stem
    }
}

#[cfg(test)]
mod tests;
