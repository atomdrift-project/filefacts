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
fn only_error(errors: &Errors) -> (Stage, crate::DiagnosticKind) {
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

    assert_eq!(v.get("deb.name").and_then(|x| x.as_str()), Some("demo-pkg"));
    assert_eq!(
        v.get("deb.version").and_then(|x| x.as_str()),
        Some("1.2.3-1")
    );
    assert_eq!(v.get("deb.arch").and_then(|x| x.as_str()), Some("amd64"));
    assert_eq!(
        v.get("deb.description").and_then(|x| x.as_str()),
        Some("A demo package")
    );
    assert_eq!(m.get("deb.installed_size_kib"), Some(512.0));
}

#[test]
fn parses_dependencies_without_constraints() {
    let deb = build_deb(CONTROL);
    let (v, _, _) = run(&deb);

    let deps: Vec<&str> = v
        .get("deb.dependencies")
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
        (Stage::TarParse, crate::DiagnosticKind::Malformed)
    );
    assert!(e.as_slice()[0].message.starts_with("control.tar.gz:"));
    assert!(v.get("deb.name").is_none());
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
        (Stage::TarParse, crate::DiagnosticKind::Malformed)
    );
    assert!(v.get("deb.limits").is_none());
}

/// A zstd frame declaring a window past the dictionary cap is refused
/// before the decoder allocates that window.
#[test]
fn zstd_control_archive_with_a_huge_window_is_refused() {
    // No content size, a 2^31-byte window, then one raw block.
    let frame = [
        0x28,
        0xb5,
        0x2f,
        0xfd,
        0x00,
        21 << 3,
        1 | (5 << 3),
        0,
        0,
        b'h',
        b'e',
        b'l',
        b'l',
        b'o',
    ];
    let (v, _, e) = run(&deb_with_control_member("control.tar.zst", &frame));
    assert_eq!(
        only_error(&e),
        (Stage::TarParse, crate::DiagnosticKind::Malformed)
    );
    assert!(v.get("deb.name").is_none());
}

/// `control.tar.xz`, dpkg's default, is read like the gzip form.
#[test]
fn xz_control_archive_is_read() {
    let gz = control_tar_gz(CONTROL);
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut tar)
        .unwrap();
    let mut xz =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
    xz.write_all(&tar).unwrap();
    let (v, _, e) = run(&deb_with_control_member(
        "control.tar.xz",
        &xz.finish().unwrap(),
    ));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(v.get("deb.name").and_then(|x| x.as_str()), Some("demo-pkg"));
}

/// An xz control archive that will not decode is a parse failure.
#[test]
fn corrupt_xz_control_archive_records_one_tar_parse_error() {
    let (v, _, e) = run(&deb_with_control_member(
        "control.tar.xz",
        b"\xfd7zXZ\0 opaque",
    ));
    assert_eq!(
        only_error(&e),
        (Stage::TarParse, crate::DiagnosticKind::Malformed)
    );
    assert!(v.get("deb.limits").is_none());
}

/// A compression dpkg does not write for the control archive is a
/// coverage limit, not a parse failure.
#[test]
fn unknown_control_compression_is_a_limit_not_an_error() {
    let (v, _, e) = run(&deb_with_control_member("control.tar.bz2", b"BZh9 opaque"));
    assert!(e.is_empty(), "{e:?}");
    let limits = v.get("deb.limits").and_then(|x| x.as_array()).unwrap();
    assert_eq!(limits.len(), 1);
    assert_eq!(limits[0]["stage"], "control-archive");
    assert!(
        limits[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("control.tar.bz2:")
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
        (Stage::FormatExtract, crate::DiagnosticKind::Malformed)
    );
    assert!(e.as_slice()[0].message.contains("past the end of the file"));
    assert!(v.get("deb.name").is_none());
}

#[test]
fn deb_without_a_control_file_records_nothing() {
    // A readable control.tar with no `control` in it: absent, not broken.
    let mut tar = Vec::new();
    tar::Builder::new(&mut tar).finish().unwrap();
    let (v, _, e) = run(&deb_with_control_member("control.tar", &tar));
    assert!(e.is_empty(), "{e:?}");
    assert!(v.get("deb.limits").is_none());
    assert!(v.get("deb.name").is_none());
}

/// `Maintainer` and the co-maintainers `Uploaders` lists are all people.
#[test]
fn maintainer_and_uploaders_are_maintainers() {
    let control = b"Package: hello\nMaintainer: Ada <ada@example.org>\nUploaders: Grace <grace@example.org>, Linus <linus@example.org>\n";
    let mut values = Values::new();
    parse_control(control, &mut values, &mut Metrics::new());
    assert_eq!(
        values.get("deb.maintainers"),
        Some(&serde_json::json!([
            {"name": "Ada", "email": "ada@example.org"},
            {"name": "Grace", "email": "grace@example.org"},
            {"name": "Linus", "email": "linus@example.org"},
        ]))
    );
}
