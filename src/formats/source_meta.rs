//! Interior identity for source archives and source files.
//!
//! Most artifacts announce themselves in a manifest an ecosystem extractor
//! already reads (`package.json`, `*.nuspec`, `PKG-INFO`). Source releases
//! predate that convention, but they still carry identity *inside* — a
//! WordPress plugin header in the main PHP file, an autoconf `AC_INIT`, a
//! generated `configure`'s `PACKAGE_*` variables. This module reads those,
//! for both a bare source file (a standalone `.php`) and the top of a
//! source archive (`wp-1-slider-1.2.9.zip`, `sendmail-8.9.1.tar.gz`).
//!
//! Every field lands as a `source.*` value the identity normalizer folds in
//! as an unverified claim — a filename says what an artifact is *called*,
//! this says what its own contents *declare*, and a disagreement between the
//! two is the signal.

use std::io::Read;

use flate2::read::GzDecoder;

use crate::fileid::FileType;
use crate::output::Values;

/// WordPress reads plugin/theme headers from the first 8 KiB of a file; so
/// do we. Also the cap on how much of any candidate member we inflate.
const HEADER_SCAN: usize = 8 << 10;

/// Members whose content we inflate to probe for identity. Cheap to read,
/// and the cap bounds a hostile archive stuffed with matching names.
const MAX_PROBED_MEMBERS: usize = 24;

/// Cap on decompressed bytes drawn from a gzip tar.
///
/// Load-bearing: the tar walker must inflate every member it *skips* to reach
/// the next header, so the per-member [`HEADER_SCAN`] cap bounds only what we
/// keep, not what the stream costs. Without this, a small crafted `.tar.gz`
/// with no candidate members inflates without limit — and an honest 200 MB
/// release is inflated in full whenever one of the two header kinds is absent,
/// which for any non-WordPress tarball is always. Identity files sit at the top
/// of a source tree, so the cap costs no real detection; an archive that keeps
/// them past it falls back to the filename, as with any container we can't read.
const MAX_INFLATE: u64 = 16 << 20;

/// Longest archive directory accepted as a distribution slug. WordPress.org
/// slugs are short and a filesystem path component stops at 255; a zip name
/// field carries 64 KiB, so without this a crafted archive names the package.
const MAX_SLUG: usize = 255;

// ---------------------------------------------------------------------
// WordPress plugin / theme headers.
// ---------------------------------------------------------------------

/// A WordPress header line is `Field: value`, inside a PHP comment (plugin)
/// or a CSS comment (theme). `text` is the caller-bounded header window (the
/// first [`HEADER_SCAN`] bytes). Returns whether a plugin/theme header was
/// found, emitting `source.wordpress.*` for what it saw.
fn wordpress_header(text: &str, values: &mut Values) -> bool {
    let mut plugin = None;
    let mut theme = None;
    let mut version = None;
    let mut text_domain = None;
    for line in text.lines() {
        // Strip a leading comment sigil (`*`, `#`, `//`) and whitespace so
        // both the PHP `* Version:` and CSS `Version:` forms parse.
        let line = line.trim_start().trim_start_matches(['*', '#', '/']).trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        // WordPress matches header fields case-insensitively; the first
        // occurrence of each wins.
        let field = match key.trim().to_ascii_lowercase().as_str() {
            "plugin name" => &mut plugin,
            "theme name" => &mut theme,
            "version" => &mut version,
            "text domain" => &mut text_domain,
            _ => continue,
        };
        field.get_or_insert(value);
    }
    match (plugin, theme) {
        (Some(p), _) => values.insert("source.wordpress.plugin_name", p.into()),
        (None, Some(t)) => values.insert("source.wordpress.theme_name", t.into()),
        (None, None) => return false, // Version alone is not a WP header.
    }
    if let Some(td) = text_domain {
        values.insert("source.wordpress.text_domain", td.into());
    }
    if let Some(v) = version {
        values.insert("source.wordpress.version", v.into());
    }
    true
}

// ---------------------------------------------------------------------
// Autotools: configure.ac AC_INIT, generated configure PACKAGE_*.
// ---------------------------------------------------------------------

/// Parse `AC_INIT(name, version, …)` from a `configure.ac`/`configure.in`.
/// Autoconf accepts `[quoted]`, `unquoted`, and whitespace/newlines between
/// args; we take the first two positional args. Empty/macro-valued args
/// (e.g. `AC_INIT` with no parens, or `m4_esyscmd` version) yield nothing.
fn autoconf_ac_init(text: &str, values: &mut Values) -> bool {
    let Some(open) = text.find("AC_INIT") else {
        return false;
    };
    let after = text[open + "AC_INIT".len()..].trim_start();
    let Some(inner) = after.strip_prefix('(') else {
        return false;
    };
    let Some(end) = inner.find(')') else {
        return false;
    };
    // Autoconf/m4 quoting: `[value]`, with whitespace anywhere around it.
    let mut args = inner[..end]
        .split(',')
        .map(|arg| arg.trim().trim_matches(['[', ']']).trim());
    let name = args.next().unwrap_or("");
    let version = args.next().unwrap_or("");
    // Autoconf 2.13 and earlier used `AC_INIT(unique-source-file)` — a single
    // filename to sanity-check the source dir, NOT a package name. The modern
    // `AC_INIT(package, version, …)` form always carries a version. So reject
    // a lone arg that looks like a source file (dsniff/fragrouter/fragroute
    // all do `AC_INIT(dsniff.c)`); require the modern form to trust the name.
    if name.is_empty()
        || name.contains('$')
        || name.starts_with("m4_")
        || looks_like_source_file(name)
    {
        return false;
    }
    values.insert("source.autoconf.name", name.into());
    if !version.is_empty() && !version.contains('$') && !version.starts_with("m4_") {
        values.insert("source.autoconf.version", version.into());
    }
    true
}

/// Whether an `AC_INIT` first argument is a source-file sanity-check target
/// (legacy form) rather than a package name — a path, or a bare filename
/// with a build/source extension.
fn looks_like_source_file(arg: &str) -> bool {
    // `rsplit_once` so a dotless package name is never read as a bare
    // extension — GNU `m4` names itself, it is not a `.m4` file.
    let ext = arg.rsplit_once('.').map_or("", |(_, ext)| ext);
    arg.contains('/')
        || matches!(
            ext,
            "c" | "h" | "cc" | "cpp" | "cxx" | "in" | "sh" | "am" | "ac" | "m4"
        )
}

/// Read `PACKAGE_TARNAME=`/`PACKAGE_VERSION=` from a generated `configure`'s
/// header window — the assignments sit in the preamble, well inside the
/// first [`HEADER_SCAN`] bytes. Only emits when non-empty: old autoconf
/// (openssh 3.x) leaves them blank and keeps the version in `version.h`,
/// which we don't guess at.
fn configure_package_vars(text: &str, values: &mut Values) -> bool {
    let mut found = false;
    for line in text.lines() {
        if let Some(v) = configure_var(line, "PACKAGE_TARNAME") {
            values.insert("source.autoconf.name", v.into());
            found = true;
        } else if let Some(v) = configure_var(line, "PACKAGE_VERSION") {
            values.insert("source.autoconf.version", v.into());
            found = true;
        }
    }
    found
}

/// Match `KEY='value'` / `KEY="value"` / `KEY=value` at the start of a
/// shell line, returning a non-empty value.
fn configure_var<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(key)?.strip_prefix('=')?;
    let v = rest.trim().trim_matches(['\'', '"']).trim();
    (!v.is_empty()).then_some(v)
}

// ---------------------------------------------------------------------
// Dispatch: bare file and archive.
// ---------------------------------------------------------------------

/// Probe a file for interior source identity, dispatched by type. A source
/// archive (`.zip`/`.tar.gz`/`.tar`) is walked for a WordPress plugin header
/// or an autoconf `AC_INIT`; a bare `.php` may itself be a plugin's main
/// file (the AccessPress backdoor samples are lone plugin PHPs). Every other
/// type — already covered by an ecosystem manifest, or not source — no-ops.
/// Best-effort throughout: a container we can't open yields nothing and the
/// filename fallback still applies.
pub(super) fn extract(bytes: &[u8], file_type: FileType, values: &mut Values) {
    match file_type {
        FileType::Zip => probe_zip(bytes, values),
        // Gzip and plain tar only: bz2/xz would need decompressors filefacts
        // doesn't carry — cleave hands it the decompressed bytes instead. Plain
        // tar needs no inflation cap; its own length is the bound.
        FileType::TarGz => {
            probe_tar(
                tar::Archive::new(GzDecoder::new(bytes).take(MAX_INFLATE)),
                values,
            );
        }
        FileType::Tar => probe_tar(tar::Archive::new(bytes), values),
        FileType::Php => {
            let head = bytes.get(..HEADER_SCAN).unwrap_or(bytes);
            wordpress_header(&String::from_utf8_lossy(head), values);
        }
        _ => {}
    }
}

/// Try the WordPress and autoconf parsers over a source archive's candidate
/// members (already read from the container, bounded by
/// [`MAX_PROBED_MEMBERS`]). The first member yielding each kind of header
/// wins; the rest are skipped once both kinds are found.
fn probe_members(members: &[(String, Vec<u8>)], values: &mut Values) {
    let mut wp_done = false;
    let mut ac_done = false;
    for (path, content) in members {
        let text = String::from_utf8_lossy(content);
        let base = path.rsplit('/').next().unwrap_or(path);
        if !wp_done && (base.ends_with(".php") || base == "style.css") {
            wp_done = wordpress_header(&text, values);
            // The archive's top-level directory is the WordPress.org
            // distribution slug (`apex-notification-bar-lite/`) — the
            // canonical package identity, which a plugin's interior text
            // domain (`apexnb-lite`) often differs from. Capture it as the
            // name; the divergence between slug and text domain is itself
            // recorded, not collapsed.
            // Rejected rather than truncated past the cap: a cut slug is a
            // wrong claim, while no slug falls through to the text domain and
            // then the filename, which are still right. Archive member names
            // are attacker-chosen and become `identity.name`.
            if wp_done
                && let Some((dir, _)) = path.split_once('/')
                && !dir.is_empty()
                && dir.len() <= MAX_SLUG
            {
                values.insert("source.wordpress.slug", dir.into());
            }
        }
        if !ac_done {
            ac_done = match base {
                "configure.ac" | "configure.in" => autoconf_ac_init(&text, values),
                "configure" => configure_package_vars(&text, values),
                _ => false,
            };
        }
        if wp_done && ac_done {
            break;
        }
    }
}

fn probe_zip(bytes: &[u8], values: &mut Values) {
    let Ok(mut archive) = super::zip::open_archive(bytes) else {
        return;
    };
    let mut members = Vec::new();
    for i in 0..archive.len() {
        if members.len() >= MAX_PROBED_MEMBERS {
            break;
        }
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        let path = entry.name().to_string();
        if !entry.is_file() || !identity_candidate(&path) {
            continue;
        }
        let mut buf = Vec::new();
        if entry.take(HEADER_SCAN as u64).read_to_end(&mut buf).is_ok() {
            members.push((path, buf));
        }
    }
    probe_members(&members, values);
}

fn probe_tar<R: Read>(mut archive: tar::Archive<R>, values: &mut Values) {
    let Ok(entries) = archive.entries() else {
        return;
    };
    let mut members = Vec::new();
    for entry in entries {
        if members.len() >= MAX_PROBED_MEMBERS {
            break;
        }
        let Ok(entry) = entry else { continue };
        let Ok(path) = entry.path() else { continue };
        let path = path.to_string_lossy().into_owned();
        if !identity_candidate(&path) {
            continue;
        }
        let mut buf = Vec::new();
        if entry.take(HEADER_SCAN as u64).read_to_end(&mut buf).is_ok() {
            members.push((path, buf));
        }
    }
    probe_members(&members, values);
}

/// Whether a member path is worth inflating: a plugin PHP, a theme
/// `style.css`, or an autotools identity file, and shallow (a source
/// release keeps these at the root or one directory down, so this skips the
/// deep tree cheaply).
fn identity_candidate(path: &str) -> bool {
    if path.matches('/').count() > 1 {
        return false;
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    base.ends_with(".php")
        || base == "style.css"
        || base == "configure.ac"
        || base == "configure.in"
        || base == "configure"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Values;

    fn vs(text: &str) -> Values {
        let mut v = Values::default();
        wordpress_header(text, &mut v);
        v
    }

    #[test]
    fn wordpress_plugin_header() {
        let v = vs(
            "<?php\n/**\n * Plugin Name: WP 1 Slider\n * Version:     1.2.9\n * Text Domain: wp-1-slider\n */",
        );
        assert_eq!(
            v.get("source.wordpress.text_domain")
                .and_then(|x| x.as_str()),
            Some("wp-1-slider")
        );
        assert_eq!(
            v.get("source.wordpress.version").and_then(|x| x.as_str()),
            Some("1.2.9")
        );
        assert_eq!(
            v.get("source.wordpress.plugin_name")
                .and_then(|x| x.as_str()),
            Some("WP 1 Slider")
        );
    }

    #[test]
    fn theme_header_via_css() {
        let v = vs("/*\nTheme Name: Twenty Twenty\nVersion: 1.5\nText Domain: twentytwenty\n*/");
        assert_eq!(
            v.get("source.wordpress.theme_name")
                .and_then(|x| x.as_str()),
            Some("Twenty Twenty")
        );
        assert_eq!(
            v.get("source.wordpress.version").and_then(|x| x.as_str()),
            Some("1.5")
        );
    }

    #[test]
    fn version_without_wp_header_is_not_a_match() {
        let mut v = Values::default();
        assert!(!wordpress_header(
            "<?php\n// Version: 9.9.9\n$x = 1;",
            &mut v
        ));
        assert!(v.get("source.wordpress.version").is_none());
    }

    #[test]
    fn ac_init_quoted_and_unquoted() {
        for text in [
            "AC_INIT([wget], [1.21.4], [bug@gnu.org])",
            "AC_INIT(wget, 1.21.4)",
            "AC_INIT([wget],\n        [1.21.4])",
        ] {
            let mut v = Values::default();
            assert!(autoconf_ac_init(text, &mut v), "{text:?}");
            assert_eq!(
                v.get("source.autoconf.name").and_then(|x| x.as_str()),
                Some("wget")
            );
            assert_eq!(
                v.get("source.autoconf.version").and_then(|x| x.as_str()),
                Some("1.21.4")
            );
        }
    }

    #[test]
    fn ac_init_legacy_single_file_form_is_rejected() {
        // autoconf 2.13: AC_INIT(unique-file) is a srcdir check, not a name.
        for text in [
            "AC_INIT(fragrouter.c)",
            "AC_INIT([dsniff.c])",
            "AC_INIT(src/main.c)",
        ] {
            let mut v = Values::default();
            assert!(!autoconf_ac_init(text, &mut v), "{text:?}");
            assert!(v.get("source.autoconf.name").is_none(), "{text:?}");
        }
    }

    #[test]
    fn ac_init_macro_version_is_rejected() {
        let mut v = Values::default();
        // A computed version (git describe) is not a usable claim.
        assert!(autoconf_ac_init(
            "AC_INIT([foo], m4_esyscmd([git describe]))",
            &mut v
        ));
        assert_eq!(
            v.get("source.autoconf.name").and_then(|x| x.as_str()),
            Some("foo")
        );
        assert!(v.get("source.autoconf.version").is_none());
    }

    #[test]
    fn configure_package_vars_only_when_populated() {
        let mut v = Values::default();
        assert!(configure_package_vars(
            "PACKAGE_TARNAME='wget'\nPACKAGE_VERSION='1.21.4'\n",
            &mut v
        ));
        assert_eq!(
            v.get("source.autoconf.name").and_then(|x| x.as_str()),
            Some("wget")
        );

        // openssh 3.x: empty PACKAGE_*; we must not emit a blank identity.
        let mut v2 = Values::default();
        assert!(!configure_package_vars(
            "PACKAGE_NAME=\nPACKAGE_TARNAME=\nPACKAGE_VERSION=\n",
            &mut v2
        ));
        assert!(v2.get("source.autoconf.name").is_none());
    }

    /// One-member `.tar.gz`, laid out as a source release: everything under a
    /// single top-level directory.
    fn source_targz(path: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, body).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn gzip_tar_yields_interior_autoconf_identity() {
        let gz = source_targz("wget-1.21.4/configure.ac", b"AC_INIT([wget], [1.21.4])\n");
        let mut v = Values::default();
        extract(&gz, FileType::TarGz, &mut v);
        assert_eq!(
            v.get("source.autoconf.name").and_then(|x| x.as_str()),
            Some("wget")
        );
        assert_eq!(
            v.get("source.autoconf.version").and_then(|x| x.as_str()),
            Some("1.21.4")
        );
    }

    #[test]
    fn gzip_tar_stops_at_the_inflation_cap() {
        // A candidate parked past MAX_INFLATE must not be reached: the walker
        // has to inflate everything before it, which is the whole hazard.
        let mut body = vec![b'\n'; MAX_INFLATE as usize + (1 << 10)];
        body.extend_from_slice(b"AC_INIT([wget], [1.21.4])\n");
        let gz = source_targz("wget-1.21.4/configure.ac", &body);
        let mut v = Values::default();
        extract(&gz, FileType::TarGz, &mut v);
        assert!(
            v.get("source.autoconf.name").is_none(),
            "must not inflate past the cap"
        );
    }

    #[test]
    fn zip_plugin_takes_slug_from_the_top_level_directory() {
        use std::io::Write;
        let mut buf = Vec::new();
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        zw.start_file(
            "apex-notification-bar-lite/apexnb.php",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zw.write_all(b"<?php\n/**\n * Plugin Name: Apex Bar\n * Text Domain: apexnb-lite\n */")
            .unwrap();
        zw.finish().unwrap();

        let mut v = Values::default();
        extract(&buf, FileType::Zip, &mut v);
        // The WordPress.org distribution slug is the archive directory, which
        // the interior text domain is free to disagree with — both are kept.
        assert_eq!(
            v.get("source.wordpress.slug").and_then(|x| x.as_str()),
            Some("apex-notification-bar-lite")
        );
        assert_eq!(
            v.get("source.wordpress.text_domain")
                .and_then(|x| x.as_str()),
            Some("apexnb-lite")
        );
    }
}
