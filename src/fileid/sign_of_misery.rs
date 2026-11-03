//! Narrow recognition of a serialized Sign of Misery script header.
//!
//! The data format is routed to generic binary analysis; this does not assert
//! that a script's commands are malicious or that it was executed.

pub(super) fn looks_like_script(data: &[u8]) -> bool {
    const HEADER: &[u8] = b"Program: \0Protection: \0Cracker: \0Group: \0Released: \0";
    const MAGIC: &[u8] = b"\x0a\x01\0\0";
    const RECORD: &[u8] = b"\xff\x93\x01\0\0\0\x7e\0\0\0\0";
    if !data.starts_with(MAGIC) || data.get(8..8 + HEADER.len()) != Some(HEADER) {
        return false;
    }
    // Some observed producers leave the stored length inconsistent, so do not
    // use it as an offset. Require the bounded command-record prefix instead.
    let tail = data
        .get(8 + HEADER.len()..data.len().min(512))
        .unwrap_or_default();
    tail.windows(RECORD.len()).any(|window| window == RECORD)
}

#[cfg(test)]
mod tests {
    use super::looks_like_script;
    use crate::FileType;
    use std::path::Path;

    fn sample() -> Vec<u8> {
        let mut bytes = b"\x0a\x01\0\0\x49\0\0\0Program: \0Protection: \0Cracker: \0Group: \0Released: \0Title\0\xff\x93\x01\0\0\0\x7e\0\0\0\0".to_vec();
        bytes.extend_from_slice(b"\x81sample command\0");
        bytes
    }

    #[test]
    fn recognizes_header_and_routes_renamed_scripts_to_data() {
        let bytes = sample();
        assert!(looks_like_script(&bytes));
        for name in ["demo.s0m", "renamed", "renamed.bin"] {
            let result = super::super::detect(Path::new(name), &bytes).unwrap();
            assert_eq!(result.file_type, FileType::Data, "{name}");
        }
    }

    #[test]
    fn rejects_truncated_and_unrelated_binary() {
        let bytes = sample();
        assert!(!looks_like_script(&bytes[..50]));
        for (at, value) in [(0, 0), (8, b'X'), (58, b'X')] {
            let mut altered = bytes.clone();
            altered[at] = value;
            assert!(!looks_like_script(&altered), "offset {at}");
        }
    }
}
