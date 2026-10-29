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
use crate::value_key;

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

/// Largest zstd window accepted, as a power of two. The decoder allocates the
/// window a frame declares before producing any output, so without this a
/// few-byte frame claiming a 2 GiB window costs 2 GiB. 16 MiB covers every
/// standard compression level and matches [`MAX_INFLATE`]: a larger window
/// cannot reach anything the inflation cap would let us read.
const ZSTD_WINDOW_LOG_MAX: u32 = 24;

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
        (Some(p), _) => values.insert_key(value_key!("source.wordpress.plugin_name"), p.into()),
        (None, Some(t)) => values.insert_key(value_key!("source.wordpress.theme_name"), t.into()),
        (None, None) => return false, // Version alone is not a WP header.
    }
    if let Some(td) = text_domain {
        values.insert_key(value_key!("source.wordpress.text_domain"), td.into());
    }
    if let Some(v) = version {
        values.insert_key(value_key!("source.wordpress.version"), v.into());
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
    // a lone arg that looks like a source file (`AC_INIT(main.c)`); require
    // the modern form to trust the name.
    if name.is_empty()
        || name.contains('$')
        || name.starts_with("m4_")
        || looks_like_source_file(name)
    {
        return false;
    }
    values.insert_key(value_key!("source.autoconf.name"), name.into());
    if !version.is_empty() && !version.contains('$') && !version.starts_with("m4_") {
        values.insert_key(value_key!("source.autoconf.version"), version.into());
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
/// leaves them blank and the project keeps its version elsewhere (often a
/// `version.h`), which we don't guess at.
fn configure_package_vars(text: &str, values: &mut Values) -> bool {
    let mut found = false;
    for line in text.lines() {
        if let Some(v) = configure_var(line, "PACKAGE_TARNAME") {
            values.insert_key(value_key!("source.autoconf.name"), v.into());
            found = true;
        } else if let Some(v) = configure_var(line, "PACKAGE_VERSION") {
            values.insert_key(value_key!("source.autoconf.version"), v.into());
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
/// file, since a plugin can be distributed or dropped as one PHP file. Every other
/// type — already covered by an ecosystem manifest, or not source — no-ops.
/// Best-effort throughout: a container we can't open yields nothing and the
/// filename fallback still applies.
pub(super) fn extract(bytes: &[u8], file_type: FileType, values: &mut Values) {
    match file_type {
        // A zip is probed from the archive walk (see [`probe_zip`]). bzip2
        // tarballs are not inflated, filefacts carrying no bzip2 decoder, so
        // their identity falls back to the filename. Plain tar needs no
        // inflation cap; its own length is the bound.
        FileType::TarGz => {
            probe_tar(
                tar::Archive::new(GzDecoder::new(bytes).take(MAX_INFLATE)),
                values,
            );
        }
        FileType::TarZst => {
            let decoder = zstd::stream::read::Decoder::with_buffer(bytes).and_then(|mut d| {
                d.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                Ok(d)
            });
            match decoder {
                Ok(decoder) => probe_tar(tar::Archive::new(decoder.take(MAX_INFLATE)), values),
                Err(error) => tracing::debug!(
                    target: "filefacts::source_meta",
                    format = "tar.zst",
                    stage = "open",
                    %error,
                    "zstd decoder setup failed; no interior identity",
                ),
            }
        }
        FileType::TarXz => probe_tar(
            tar::Archive::new(super::bounded::xz_decoder(bytes).take(MAX_INFLATE)),
            values,
        ),
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
        if !wp_done && (super::common::ends_with_ci(base, ".php") || base == "style.css") {
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
                values.insert_key(value_key!("source.wordpress.slug"), dir.into());
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

/// Probe a source zip the archive walk already opened. Members are chosen by
/// name before any is opened, so an archive of thousands of members costs one
/// read per candidate, not a decompressor per member.
pub(super) fn probe_zip(archive: &mut super::zip::Archive<'_>, values: &mut Values) {
    let candidates: Vec<usize> = (0..archive.len())
        .filter(|&i| {
            archive
                .name_for_index(i)
                .and_then(Result::ok)
                .is_some_and(|name| identity_candidate(&name))
        })
        .collect();
    let mut members = Vec::new();
    for i in candidates {
        if members.len() >= MAX_PROBED_MEMBERS {
            tracing::debug!(
                target: "filefacts::source_meta",
                format = "zip",
                stage = "members",
                cap = MAX_PROBED_MEMBERS,
                "probed-member cap reached; later candidates skipped",
            );
            break;
        }
        let entry = match archive.by_index(i) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(
                    target: "filefacts::source_meta",
                    format = "zip",
                    stage = "member",
                    index = i,
                    %error,
                    "member unreadable; skipped",
                );
                continue;
            }
        };
        if !entry.is_file() {
            continue;
        }
        let Ok(path) = entry.name().map(std::borrow::Cow::into_owned) else {
            continue;
        };
        let mut buf = Vec::new();
        if entry.take(HEADER_SCAN as u64).read_to_end(&mut buf).is_ok() {
            members.push((path, buf));
        }
    }
    probe_members(&members, values);
}

fn probe_tar<R: Read>(mut archive: tar::Archive<R>, values: &mut Values) {
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            tracing::debug!(
                target: "filefacts::source_meta",
                format = "tar",
                stage = "open",
                %error,
                "tar stream does not open; no interior identity",
            );
            return;
        }
    };
    let mut members = Vec::new();
    for entry in entries {
        if members.len() >= MAX_PROBED_MEMBERS {
            tracing::debug!(
                target: "filefacts::source_meta",
                format = "tar",
                stage = "members",
                cap = MAX_PROBED_MEMBERS,
                "probed-member cap reached; later candidates skipped",
            );
            break;
        }
        // A read error here is usually the inflation cap cutting the stream
        // short; the walk cannot resynchronize after it.
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(
                    target: "filefacts::source_meta",
                    format = "tar",
                    stage = "member",
                    cap = MAX_INFLATE,
                    %error,
                    "tar walk stopped",
                );
                break;
            }
        };
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
    super::common::ends_with_ci(base, ".php")
        || base == "style.css"
        || base == "configure.ac"
        || base == "configure.in"
        || base == "configure"
}

#[cfg(test)]
mod tests;
