use super::*;

#[test]
fn era_conventions_split() {
    // (filename, name, version) — real release names spanning the eras.
    for (base, name, version) in [
        ("wuftpd-10.9.2.tgz", "wuftpd", "10.9.2"),
        ("sendmail-8.9.1.tgz", "sendmail", "8.9.1"),
        ("sendmail.8.9.1.tar.gz", "sendmail", "8.9.1"),
        ("apache_1.3.9.tar.gz", "apache", "1.3.9"),
        ("bind-4.9.5-P1.tar.gz", "bind", "4.9.5-P1"),
        ("ncompress-4.2.4.tar.Z", "ncompress", "4.2.4"),
        ("elm-2.5.8.tar.gz", "elm", "2.5.8"),
        ("R-4.0.0.tar.gz", "R", "4.0.0"),
        ("Template-Toolkit-3.102.tar.gz", "Template-Toolkit", "3.102"),
        ("lodash-4.17.21.tgz", "lodash", "4.17.21"),
        (
            "github.com-gorilla-mux-v1.8.1.zip",
            "github.com-gorilla-mux",
            "v1.8.1",
        ),
        ("2020-vision-1.0.0.tgz", "2020-vision", "1.0.0"),
    ] {
        let got = split_name_version(base);
        assert_eq!(got, Some((name, version)), "split_name_version({base:?})");
    }
}

#[test]
fn date_stamped_dataset_names_shed_the_stamp() {
    assert_eq!(
        split_name_version("2026-03-18-big-nunber-v5.0.5.zip"),
        Some(("big-nunber", "v5.0.5")),
    );
}

#[test]
fn non_conforming_names_yield_nothing() {
    for base in [
        "evil.exe",        // not an archive extension
        "MetaStealer.zip", // no version tail
        "notes.tar",       // no separator+digit boundary
        "60d11b7004c80ae17a900094bbddd0a92273167af2b15f7597b9749d1b5edaa2",
        "backup.tar.gz", // versionless
    ] {
        assert_eq!(split_name_version(base), None, "{base:?} must not split");
    }
}
