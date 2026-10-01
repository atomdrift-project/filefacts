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
//! - `deb.package`, `deb.version`, `deb.architecture` — core identity.
//! - `deb.maintainer`, `deb.section`, `deb.priority` — provenance / category.
//! - `deb.summary` — the `Description` synopsis (first line).
//! - `deb.depends[]` — runtime dependency package names (bounded).
//! - `deb.installed_size` — declared installed size in KiB.
//! - `deb.limits[]` — `{stage, reason}` when the control archive was left
//!   unread by design: an `xz` (or other undecodable) `control.tar`, or one
//!   that inflates past the size cap. A control archive that fails to
//!   decompress, or an `ar` table that breaks off before reaching it, is a
//!   parse failure and is recorded in `errors` instead.

use crate::metric;
use std::io::{Cursor, Read};

use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::output::{Errors, Metrics, Stage, Values};

const AR_MAGIC: &[u8] = b"!<arch>\n";
/// `ar` member headers are a fixed 60 bytes.
const AR_HEADER_LEN: usize = 60;
/// Cap on the compressed `control.tar` member we decompress.
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
            match read_control_file(&name, member) {
                Ok(Some(control)) => parse_control(&control, values, metrics),
                // No `control` file inside: nothing to read, nothing failed.
                Ok(None) => {}
                Err(ControlError::Unread(reason)) => values.insert(
                    "deb.limits",
                    serde_json::json!([{ "stage": "control-archive", "reason": reason }]),
                ),
                Err(ControlError::Malformed(why)) => {
                    errors.record_malformed(Stage::TarParse, format!("{name}: {why}"));
                }
            }
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

/// Decompress `control.tar*` (by suffix) and return the `control` member's
/// bytes, `Ok(None)` when the archive holds no `control` file.
fn read_control_file(name: &str, member: &[u8]) -> Result<Option<Vec<u8>>, ControlError> {
    let reader: Box<dyn Read> = if name.ends_with(".gz") {
        Box::new(flate2::read::GzDecoder::new(member))
    } else if name.ends_with(".zst") {
        Box::new(
            zstd::stream::read::Decoder::new(member)
                .map_err(|e| ControlError::Malformed(e.to_string()))?,
        )
    } else if name.ends_with(".tar") {
        Box::new(Cursor::new(member))
    } else {
        // .xz / unknown compression: no decompressor available.
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
fn find_control<R: Read>(archive: &mut tar::Archive<R>) -> std::io::Result<Option<Vec<u8>>> {
    for entry in archive.entries()? {
        let entry = entry?;
        // `path()` borrows the entry immutably; resolve the match before the
        // `read_to_end` consumes it.
        let is_control = entry
            .path()
            .is_ok_and(|p| matches!(p.to_string_lossy().as_ref(), "./control" | "control"));
        if is_control {
            let mut buf = Vec::new();
            entry.take(MAX_CONTROL_FILE).read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

/// Parse the RFC822 `control` file. Continuation lines (leading whitespace)
/// extend the previous field; we only need the single-line fields here.
fn parse_control(control: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let text = String::from_utf8_lossy(control);
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
            "Package" => insert_str(values, "deb.package", value),
            "Version" => insert_str(values, "deb.version", value),
            "Architecture" => insert_str(values, "deb.architecture", value),
            "Maintainer" => insert_str(values, "deb.maintainer", value),
            "Section" => insert_str(values, "deb.section", value),
            "Priority" => insert_str(values, "deb.priority", value),
            // `Description`'s first line is the synopsis; the indented
            // continuation lines (the long description) are skipped above.
            "Description" => insert_str(values, "deb.summary", value),
            "Installed-Size" => {
                if let Ok(kib) = value.parse::<f64>() {
                    metrics.insert(metric!("deb.installed_size"), kib);
                }
            }
            "Depends" => {
                let names = dependency_names(value);
                if !names.is_empty() {
                    metrics.insert(metric!("deb.depends_count"), names.len() as f64);
                    values.insert(
                        "deb.depends",
                        JsonValue::Array(names.into_iter().map(JsonValue::String).collect()),
                    );
                }
            }
            _ => {}
        }
    }
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

fn insert_str(values: &mut Values, key: &str, value: &str) {
    values.insert(key, JsonValue::String(value.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal `.deb`: an `ar` archive with `debian-binary` and a
    /// gzip `control.tar` containing `./control`.
    fn build_deb(control: &str) -> Vec<u8> {
        deb_with_control_member("control.tar.gz", &control_tar_gz(control))
    }

    /// A `.deb` whose control member has the given name and raw bytes.
    fn deb_with_control_member(name: &str, member: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(AR_MAGIC);
        append_ar_member(&mut out, "debian-binary", b"2.0\n");
        append_ar_member(&mut out, name, member);
        append_ar_member(&mut out, "data.tar.gz", b"");
        out
    }

    fn control_tar_gz(control: &str) -> Vec<u8> {
        // control.tar.gz holding ./control
        let mut control_tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut control_tar);
            let mut h = tar::Header::new_ustar();
            h.set_path("./control").unwrap();
            h.set_size(control.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, control.as_bytes()).unwrap();
            b.finish().unwrap();
        }
        let mut control_gz = Vec::new();
        {
            let mut enc =
                flate2::write::GzEncoder::new(&mut control_gz, flate2::Compression::default());
            enc.write_all(&control_tar).unwrap();
            enc.finish().unwrap();
        }
        control_gz
    }

    fn run(deb: &[u8]) -> (Values, Metrics, Errors) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut e = Errors::new();
        extract(deb, &mut v, &mut m, &mut e).unwrap();
        (v, m, e)
    }

    /// The one recorded error's stage and kind.
    fn only_error(errors: &Errors) -> (Stage, crate::ErrorKind) {
        assert_eq!(errors.len(), 1, "{errors:?}");
        (errors.as_slice()[0].stage, errors.as_slice()[0].kind)
    }

    fn append_ar_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
        let mut header = [b' '; AR_HEADER_LEN];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = data.len().to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58] = b'`';
        header[59] = b'\n';
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        if data.len() & 1 == 1 {
            out.push(b'\n');
        }
    }

    const CONTROL: &str = "Package: demo-pkg\n\
Version: 1.2.3-1\n\
Architecture: amd64\n\
Maintainer: Jane Doe <jane@example.com>\n\
Section: utils\n\
Priority: optional\n\
Installed-Size: 512\n\
Depends: libc6 (>= 2.34), libssl3 (>= 3.0.0) | libssl1.1\n\
Description: A demo package\n\
 Long description line that should be ignored.\n";

    #[test]
    fn extracts_core_identity() {
        let deb = build_deb(CONTROL);
        let (v, m, e) = run(&deb);
        assert!(e.is_empty(), "{e:?}");
        assert!(v.get("deb.limits").is_none());

        assert_eq!(
            v.get("deb.package").and_then(|x| x.as_str()),
            Some("demo-pkg")
        );
        assert_eq!(
            v.get("deb.version").and_then(|x| x.as_str()),
            Some("1.2.3-1")
        );
        assert_eq!(
            v.get("deb.architecture").and_then(|x| x.as_str()),
            Some("amd64")
        );
        assert_eq!(
            v.get("deb.summary").and_then(|x| x.as_str()),
            Some("A demo package")
        );
        assert_eq!(m.get("deb.installed_size"), Some(512.0));
    }

    #[test]
    fn parses_dependencies_without_constraints() {
        let deb = build_deb(CONTROL);
        let (v, _, _) = run(&deb);

        let deps: Vec<&str> = v
            .get("deb.depends")
            .and_then(|x| x.as_array())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert_eq!(deps, vec!["libc6", "libssl3", "libssl1.1"]);
    }

    #[test]
    fn non_deb_bytes_error() {
        let mut v = Values::new();
        let mut m = Metrics::new();
        let mut e = Errors::new();
        assert!(extract(b"not a deb", &mut v, &mut m, &mut e).is_err());
    }

    #[test]
    fn corrupt_gzip_control_archive_records_one_tar_parse_error() {
        let mut gz = control_tar_gz(CONTROL);
        // Keep the gzip header, garble the deflate stream behind it.
        for b in &mut gz[10..] {
            *b ^= 0x5a;
        }
        let (v, _, e) = run(&deb_with_control_member("control.tar.gz", &gz));
        assert_eq!(
            only_error(&e),
            (Stage::TarParse, crate::ErrorKind::Malformed)
        );
        assert!(e.as_slice()[0].message.starts_with("control.tar.gz:"));
        assert!(v.get("deb.package").is_none());
        assert!(v.get("deb.limits").is_none());
    }

    #[test]
    fn corrupt_zstd_control_archive_records_one_tar_parse_error() {
        let (v, _, e) = run(&deb_with_control_member(
            "control.tar.zst",
            b"\x28\xb5\x2f\xfd garbage",
        ));
        assert_eq!(
            only_error(&e),
            (Stage::TarParse, crate::ErrorKind::Malformed)
        );
        assert!(v.get("deb.limits").is_none());
    }

    /// An xz control archive is undecodable by design (no xz decoder): a
    /// coverage limit, not a parse failure.
    #[test]
    fn xz_control_archive_is_a_limit_not_an_error() {
        let (v, _, e) = run(&deb_with_control_member(
            "control.tar.xz",
            b"\xfd7zXZ\0 opaque",
        ));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("deb.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits.len(), 1);
        assert_eq!(limits[0]["stage"], "control-archive");
        assert!(
            limits[0]["reason"]
                .as_str()
                .unwrap()
                .starts_with("control.tar.xz:")
        );
    }

    #[test]
    fn control_archive_past_the_inflate_cap_is_a_limit_not_an_error() {
        // A tar whose first member alone inflates past the cap, with the
        // `control` file behind it.
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            let mut pad = tar::Header::new_ustar();
            pad.set_path("./md5sums").unwrap();
            pad.set_size(MAX_CONTROL_TAR + 1);
            pad.set_cksum();
            b.append(&pad, std::io::repeat(0).take(MAX_CONTROL_TAR + 1))
                .unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_path("./control").unwrap();
            h.set_size(CONTROL.len() as u64);
            h.set_cksum();
            b.append(&h, CONTROL.as_bytes()).unwrap();
            b.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&tar).unwrap();
            enc.finish().unwrap();
        }
        let (v, _, e) = run(&deb_with_control_member("control.tar.gz", &gz));
        assert!(e.is_empty(), "{e:?}");
        let limits = v.get("deb.limits").and_then(|x| x.as_array()).unwrap();
        assert_eq!(limits[0]["stage"], "control-archive");
        assert!(limits[0]["reason"].as_str().unwrap().contains("cap"));
    }

    #[test]
    fn control_member_cut_short_records_one_malformed_error() {
        let deb = build_deb(CONTROL);
        // Cut inside the control.tar.gz member's data.
        let cut = AR_MAGIC.len() + 2 * AR_HEADER_LEN + 4 + 20;
        let (v, _, e) = run(&deb[..cut]);
        assert_eq!(
            only_error(&e),
            (Stage::FormatExtract, crate::ErrorKind::Malformed)
        );
        assert!(e.as_slice()[0].message.contains("past the end of the file"));
        assert!(v.get("deb.package").is_none());
    }

    #[test]
    fn deb_without_a_control_file_records_nothing() {
        // A readable control.tar with no `control` in it: absent, not broken.
        let mut tar = Vec::new();
        tar::Builder::new(&mut tar).finish().unwrap();
        let (v, _, e) = run(&deb_with_control_member("control.tar", &tar));
        assert!(e.is_empty(), "{e:?}");
        assert!(v.get("deb.limits").is_none());
        assert!(v.get("deb.package").is_none());
    }
}
