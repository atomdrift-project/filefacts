use super::*;
use crate::output::{ArchiveCompression, ArchiveOffsets, ArchiveOwnership};

fn member(path: &str, entry_type: &str, size: u64) -> ArchiveMember {
    ArchiveMember {
        path: path.into(),
        size_bytes: size,
        entry_type: Some(entry_type.into()),
        mtime_unix: None,
        linkname: None,
        host_os: None,
        crc32: None,
        encrypted: false,
        compression: None,
        ownership: None,
        offsets: ArchiveOffsets::default(),
    }
}

fn stamped(path: &str, mtime: Option<i64>) -> ArchiveMember {
    ArchiveMember {
        mtime_unix: mtime,
        ..member(path, "regular", 1)
    }
}

fn run(aggs: &'static [Agg], members: &[ArchiveMember]) -> (Values, Metrics) {
    let mut stats = ArchiveStats::new(aggs);
    for m in members {
        stats.observe(m, &Reading::of(m));
    }
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    stats.emit(&mut values, &mut metrics);
    (values, metrics)
}

#[test]
fn only_the_requested_aggregates_are_written() {
    let members = [member("a.exe", "regular", 3), member("d", "directory", 0)];
    let (values, metrics) = run(&[Agg::MemberCount, Agg::Executables], &members);
    assert_eq!(metrics.get("archive.member_count"), Some(2.0));
    assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
    assert_eq!(metrics.len(), 2);
    assert_eq!(values.as_json(), &serde_json::json!({}));
}

#[test]
fn scope_separates_files_from_every_member() {
    // A directory carrying a size and a traversal name counts under
    // Scope::All only.
    let members = [member("../up/", "directory", 7), member("f", "regular", 5)];
    let (_, all) = run(
        &[
            Agg::UncompressedSize(Scope::All),
            Agg::PathTraversal(Scope::All),
        ],
        &members,
    );
    let (_, files) = run(
        &[
            Agg::UncompressedSize(Scope::Files),
            Agg::PathTraversal(Scope::Files),
        ],
        &members,
    );
    assert_eq!(all.get("archive.uncompressed_size"), Some(12.0));
    assert_eq!(all.get("archive.path_traversal_count"), Some(1.0));
    assert_eq!(files.get("archive.uncompressed_size"), Some(5.0));
    assert_eq!(files.get("archive.path_traversal_count"), Some(0.0));
}

#[test]
fn sizes_saturate_instead_of_overflowing() {
    let huge = member("a", "regular", u64::MAX);
    let (_, metrics) = run(&[Agg::UncompressedSize(Scope::All)], &[huge.clone(), huge]);
    assert_eq!(
        metrics.get("archive.uncompressed_size"),
        Some(u64::MAX as f64)
    );
}

#[test]
fn reading_overrides_name_based_defaults() {
    let m = member("payload", "regular", 1);
    let mut stats = ArchiveStats::new(&[Agg::HiddenFiles, Agg::Executables, Agg::FileCount]);
    let mut reading = Reading::of(&m);
    reading.hidden = true;
    reading.exec_mode = true;
    stats.observe(&m, &reading);
    // An opaque member is a member, but its name and kind say nothing.
    stats.observe(&member(".x/run.exe", "slack", 1), &Reading::opaque());
    let mut metrics = Metrics::new();
    stats.emit(&mut Values::new(), &mut metrics);
    assert_eq!(metrics.get("archive.hidden_file_count"), Some(1.0));
    assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
    assert_eq!(metrics.get("archive.file_count"), Some(1.0));
}

#[test]
fn mode_bits_symlinks_and_escapes_come_from_the_typed_member() {
    let with_mode = |path: &str, kind: &str, mode: u32, link: Option<&str>| ArchiveMember {
        linkname: link.map(str::to_string),
        ownership: Some(ArchiveOwnership {
            mode_octal: Some(mode),
            ..Default::default()
        }),
        ..member(path, kind, 0)
    };
    let members = [
        with_mode("s", "regular", 0o4755, None),
        with_mode("w", "regular", 0o666, None),
        with_mode("l1", "symlink", 0o777, Some("../../etc/passwd")),
        with_mode("l2", "symlink", 0o777, Some("sibling")),
    ];
    let (_, metrics) = run(
        &[Agg::ModeBits, Agg::SymlinkCount, Agg::SymlinkEscapes],
        &members,
    );
    assert_eq!(metrics.get("archive.security.setuid_count"), Some(1.0));
    // The 0o666 file and both 0o777 symlinks.
    assert_eq!(
        metrics.get("archive.security.world_writable_count"),
        Some(3.0)
    );
    assert_eq!(metrics.get("archive.security.symlink_count"), Some(2.0));
    assert_eq!(metrics.get("archive.symlink_escape_count"), Some(1.0));
}

#[test]
fn methods_list_is_written_when_empty_only_if_asked() {
    let (always, _) = run(&[Agg::Methods { always: true }], &[]);
    let (if_any, _) = run(&[Agg::Methods { always: false }], &[]);
    assert_eq!(
        always.get("archive.compression.methods"),
        Some(&serde_json::json!([]))
    );
    assert!(if_any.get("archive.compression.methods").is_none());

    let packed = ArchiveMember {
        compression: Some(ArchiveCompression {
            compressed_size: Some(1),
            method: Some("lzma".into()),
        }),
        ..member("a", "regular", 10)
    };
    let (values, metrics) = run(
        &[
            Agg::Methods { always: false },
            Agg::ZipBombRatio(Scope::All),
        ],
        &[packed],
    );
    assert_eq!(
        values.get("archive.compression.methods"),
        Some(&serde_json::json!(["lzma"]))
    );
    assert_eq!(
        metrics.get("archive.compression.method_counts.lzma"),
        Some(1.0)
    );
    assert_eq!(metrics.get("archive.zip_bomb_ratio"), Some(10.0));
}

#[test]
fn duplicate_paths_are_counted_after_the_first() {
    let members = [
        member("same", "regular", 1),
        member("same", "regular", 1),
        member("same", "regular", 1),
        member("other", "regular", 1),
    ];
    let (_, metrics) = run(&[Agg::DuplicateMembers], &members);
    assert_eq!(metrics.get("archive.duplicate_member_count"), Some(2.0));
}

#[test]
fn untimed_group_can_dominate_and_lists_stamped_outliers() {
    let members = [
        stamped("a", None),
        stamped("b", None),
        stamped("c", None),
        stamped("dropped", Some(1_750_000_000)),
    ];
    let (values, metrics) = run(
        &[
            Agg::SentinelMtimes,
            Agg::MtimeAnomalies(Dominance::UntimedGroup),
        ],
        &members,
    );
    assert_eq!(
        metrics.get("archive.timing.sentinel_mtime_count"),
        Some(3.0)
    );
    assert_eq!(
        metrics.get("archive.timing.mtime_dominant_count"),
        Some(3.0)
    );
    assert_eq!(
        metrics.get("archive.timing.mtime_dominant_ratio"),
        Some(0.75)
    );
    assert_eq!(metrics.get("archive.timing.mtime_outlier_count"), Some(1.0));
    assert_eq!(
        values.get("archive.timing.mtime_outlier_members"),
        Some(&serde_json::json!(["dropped"]))
    );
}

#[test]
fn timed_only_dominance_ignores_unstamped_members() {
    let members = [
        stamped("a", Some(100)),
        stamped("b", Some(100)),
        stamped("c", Some(100)),
        stamped("late", Some(4_200_000_000)),
        stamped("none", None),
    ];
    let (values, metrics) = run(
        &[Agg::MtimeRange, Agg::MtimeAnomalies(Dominance::TimedOnly)],
        &members,
    );
    assert_eq!(
        metrics.get("archive.timing.mtime_dominant_count"),
        Some(3.0)
    );
    assert_eq!(
        metrics.get("archive.timing.mtime_dominant_ratio"),
        Some(0.6)
    );
    // The unstamped member counts toward the total but is never listed.
    assert_eq!(metrics.get("archive.timing.mtime_outlier_count"), Some(2.0));
    assert_eq!(
        values.get("archive.timing.mtime_outlier_members"),
        Some(&serde_json::json!(["late"]))
    );
    assert_eq!(metrics.get("archive.timing.future_mtime_count"), Some(1.0));
    assert_eq!(metrics.get("archive.timing.mtime_unique_count"), Some(2.0));
    assert_eq!(metrics.get("archive.timing.mtime_unique_ratio"), Some(0.5));
}

#[test]
fn mtime_spread_survives_the_full_i64_range() {
    let members = [stamped("a", Some(i64::MIN)), stamped("b", Some(i64::MAX))];
    let (values, metrics) = run(&[Agg::MtimeRange], &members);
    assert_eq!(
        metrics.get("archive.timing.mtime_spread_seconds"),
        Some(u64::MAX as f64)
    );
    assert_eq!(
        values.get("archive.timing.mtime_min"),
        Some(&serde_json::json!(i64::MIN))
    );
}

#[test]
fn member_value_maps_typed_fields_and_honours_the_shape() {
    let m = ArchiveMember {
        mtime_unix: Some(5),
        crc32: Some(7),
        compression: Some(ArchiveCompression {
            compressed_size: Some(2),
            method: Some("deflate".into()),
        }),
        ownership: Some(ArchiveOwnership {
            mode_octal: Some(0o644),
            uid: Some(1),
            ..Default::default()
        }),
        offsets: ArchiveOffsets {
            header: Some(0),
            data: Some(30),
            central_header: None,
        },
        ..member("a.txt", "regular", 4)
    };
    assert_eq!(
        JsonValue::Object(member_value(&m, Shape::FULL)),
        serde_json::json!({
            "path": "a.txt",
            "size_bytes": 4,
            "entry_type": "regular",
            "mtime_unix": 5,
            "crc32": 7,
            "compressed_size": 2,
            "compression_method": "deflate",
            "mode_octal": 0o644,
            "uid": 1,
            "header_offset": 0,
            "data_offset": 30,
        })
    );
    let bare = member_value(
        &ArchiveMember {
            encrypted: true,
            ..m
        },
        Shape {
            offsets: false,
            compression: false,
        },
    );
    assert_eq!(bare.get("encrypted"), Some(&JsonValue::Bool(true)));
    for absent in [
        "compressed_size",
        "compression_method",
        "header_offset",
        "data_offset",
    ] {
        assert!(!bare.contains_key(absent), "{absent}");
    }
}

#[test]
fn classify_filename_flags() {
    let c = classify_filename("photos/invoice.pdf.exe");
    assert!(c.is_executable && c.has_double_extension && c.is_misplaced_executable);
    assert!(!classify_filename("bin/tool.exe").is_misplaced_executable);
    assert!(classify_filename("C:\\evil.dll").has_path_traversal);
    assert!(!classify_filename("é:\\x").has_path_traversal);
    assert!(classify_filename("a/.git/config").is_hidden);
    assert!(!classify_filename("./a/../b").is_hidden);
    assert!(classify_filename("r\u{0435}sume.doc").has_homoglyph);
    assert!(classify_filename("x\u{202e}gpj.exe").has_rtlo);
    assert!(classify_filename("pkg.tar.gz").is_nested_archive);
    assert!(classify_filename("run.PS1").is_script);
}

#[test]
fn is_noise_filename_helper() {
    assert!(is_noise_filename("__MACOSX/anything"));
    assert!(is_noise_filename(".DS_Store"));
    assert!(is_noise_filename("nested/path/.DS_Store"));
    assert!(is_noise_filename("Thumbs.db"));
    assert!(is_noise_filename("desktop.ini"));
    assert!(!is_noise_filename("ok.txt"));
    assert!(!is_noise_filename("a/b/c.txt"));
    // Case-sensitive — exact Windows / macOS conventions only.
    assert!(!is_noise_filename("THUMBS.DB"));
}
