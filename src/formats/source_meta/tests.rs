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
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&source_tar(path, body)).unwrap();
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

/// One-member `.tar` holding `body` at `path`.
fn source_tar(path: &str, body: &[u8]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, body).unwrap();
    tar.into_inner().unwrap()
}

#[test]
fn zstd_tar_yields_interior_autoconf_identity() {
    let tar = source_tar("wget-1.21.4/configure.ac", b"AC_INIT([wget], [1.21.4])\n");
    let zst = zstd::encode_all(&tar[..], 3).unwrap();
    let mut v = Values::default();
    extract(&zst, FileType::TarZst, &mut v);
    assert_eq!(
        v.get("source.autoconf.name").and_then(|x| x.as_str()),
        Some("wget")
    );
}

#[test]
fn xz_tar_yields_interior_autoconf_identity() {
    use std::io::Write;
    let tar = source_tar("wget-1.21.4/configure.ac", b"AC_INIT([wget], [1.21.4])\n");
    let mut xz =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    xz.write_all(&tar).unwrap();
    let xz = xz.finish().unwrap();
    let mut v = Values::default();
    extract(&xz, FileType::TarXz, &mut v);
    assert_eq!(
        v.get("source.autoconf.name").and_then(|x| x.as_str()),
        Some("wget")
    );
}

/// A frame that declares a window past [`ZSTD_WINDOW_LOG_MAX`] is refused
/// before the decoder allocates it.
#[test]
fn zstd_tar_refuses_oversized_windows() {
    let tar = source_tar("wget-1.21.4/configure.ac", b"AC_INIT([wget], [1.21.4])\n");
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
    encoder.long_distance_matching(true).unwrap();
    encoder.window_log(ZSTD_WINDOW_LOG_MAX + 2).unwrap();
    encoder.include_contentsize(false).unwrap();
    std::io::Write::write_all(&mut encoder, &tar).unwrap();
    let zst = encoder.finish().unwrap();
    let mut v = Values::default();
    extract(&zst, FileType::TarZst, &mut v);
    assert!(v.get("source.autoconf.name").is_none());
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

    // Probed from the archive the zip walk opened.
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("apex-notification-bar-lite.zip"))
        .rizin(false)
        .open(&buf);
    let v = parsed.values();
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
