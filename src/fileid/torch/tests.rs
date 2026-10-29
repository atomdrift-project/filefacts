use super::*;
use crate::fileid::{self, FileType};
use std::path::Path;

fn recognized_bytes(data: &[u8]) -> bool {
    recognized(&Sniff::new(Path::new(""), data))
}

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    crate::fileid::testutil::zip(files)
}

#[test]
fn canonical_torchscript_fixture_keeps_zip_type_without_suffix_mismatch() {
    let data = include_bytes!("../testdata/tiny-torchscript.pt");
    assert!(recognized_bytes(data));
    for name in ["model.pt", "model.pth", "model.ckpt", "MODEL.PT"] {
        let detected = fileid::detect(Path::new(name), data).unwrap();
        assert_eq!(detected.file_type, FileType::Zip);
        assert!(!detected.extension_mismatch());
    }
    assert!(
        fileid::detect(Path::new("model.py"), data)
            .unwrap()
            .extension_mismatch()
    );
}

#[test]
fn serialization_framing_does_not_exempt_arbitrary_or_malformed_zip() {
    for files in [
        vec![("model/data.pkl", &b"\x80\x02}."[..])],
        vec![("model/version", &b"3\n"[..])],
        vec![
            ("model/version", &b"3\n"[..]),
            ("other/data.pkl", &b"\x80\x02}."[..]),
        ],
        vec![
            ("model/version", &b"three"[..]),
            ("model/data.pkl", &b"\x80\x02}."[..]),
        ],
        vec![
            ("model/version", &b"11"[..]),
            ("model/data.pkl", &b"\x80\x02}."[..]),
        ],
        vec![
            ("model/version", &b"3\n"[..]),
            ("model/data.pkl", &b"MZprogram"[..]),
        ],
        vec![
            ("model/version", &b"3\n"[..]),
            ("model/data.pkl", &b"\x80\x06}."[..]),
        ],
        vec![
            ("model/version", &b"3\n"[..]),
            ("model/data.pkl", &b"\x80\x02}."[..]),
            ("model/../payload", &b"code"[..]),
        ],
    ] {
        let data = archive(&files);
        assert!(!recognized_bytes(&data));
        assert!(
            fileid::detect(Path::new("model.pt"), &data)
                .unwrap()
                .extension_mismatch()
        );
    }
    let data = archive(&[("model/version", b"3\n"), ("model/data.pkl", b"\x80\x02}.")]);
    assert!(recognized_bytes(&data));
    assert!(!recognized_bytes(&data[..data.len() - 12]));
}

#[test]
fn executable_members_receive_no_trust_from_the_carrier_convention() {
    let data = archive(&[
        ("model/version", b"3\n"),
        ("model/data.pkl", b"\x80\x02}."),
        ("model/code/evil.py", b"import os; os.system('payload')"),
    ]);
    assert!(recognized_bytes(&data));
    // Recognition preserves archive classification and child extraction;
    // it only describes the suffix's established serialization convention.
    assert_eq!(
        fileid::detect(Path::new("model.pt"), &data)
            .unwrap()
            .file_type,
        FileType::Zip
    );
}

#[test]
fn torchscript_debug_pickle_suffix_dispatches_to_pickle_without_executing_it() {
    let data = include_bytes!("../testdata/tiny-torchscript.debug_pkl");
    let detected = fileid::detect(Path::new("__torch__.py.debug_pkl"), data).unwrap();
    assert_eq!(detected.file_type, FileType::Pickle);
    assert!(!detected.extension_mismatch());
    // This adds a serialization suffix; it grants no exception to a
    // body whose magic says it is an executable or another format.
    let executable = include_bytes!("../testdata/tiny-torchscript.pt");
    let detected = fileid::detect(Path::new("code.debug_pkl"), executable).unwrap();
    assert_eq!(detected.file_type, FileType::Zip);
    assert!(detected.extension_mismatch());
}

/// A `version` member that declares two bytes but inflates to megabytes
/// is refused rather than read whole: the declared size is only the
/// archive's claim.
#[test]
fn version_member_inflating_past_its_declared_size_is_refused() {
    let mut version = b"3".to_vec();
    version.resize(1 << 20, b' ');
    let mut data = archive(&[
        ("model/version", &version),
        ("model/data.pkl", b"\x80\x02}."),
    ]);
    // Rewrite the declared uncompressed size in the local header (+22)
    // and the central-directory record (+24) of `model/version`.
    let declared = (1_u32 << 20).to_le_bytes();
    let mut at = 0;
    let mut patched = 0;
    while let Some(off) = data[at..].windows(4).position(|w| w == declared) {
        let pos = at + off;
        data[pos..pos + 4].copy_from_slice(&2_u32.to_le_bytes());
        patched += 1;
        at = pos + 4;
    }
    assert_eq!(patched, 2);
    assert!(!recognized_bytes(&data));
}

/// End-of-central-directory candidates that each fail make the `zip` crate
/// rescan the file once per candidate; the probe's read budget bounds that.
#[test]
#[ignore = "wall-clock bound; run with --ignored"]
fn failing_end_record_candidates_are_refused_promptly() {
    let mut record = [0_u8; 22];
    record[..4].copy_from_slice(b"PK\x05\x06");
    record[8..10].copy_from_slice(&1_u16.to_le_bytes());
    record[10..12].copy_from_slice(&1_u16.to_le_bytes());
    let data = record.repeat((512 << 10) / record.len());
    let start = std::time::Instant::now();
    assert!(!recognized_bytes(&data));
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}
