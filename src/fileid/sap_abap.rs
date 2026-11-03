//! Conservative recognition of extensionless ABAP report source.

use super::text::{self, Controls};

pub(super) fn looks_like_report(data: &[u8]) -> bool {
    let data = data.get(..data.len().min(128 * 1024)).unwrap_or(data);
    if text::is_binary(data, Controls::Text) {
        return false;
    }
    let mut report = false;
    let mut read_report = false;
    let mut loop_at = false;
    let mut endloop = false;
    for line in data.split(|&b| b == b'\n') {
        // In ABAP, '*' starts a comment only in column one. The patterns
        // below do not search string operands, so strip end-of-line comments.
        if line.starts_with(b"*") {
            continue;
        }
        let code = line.split(|&b| b == b'"').next().unwrap_or_default();
        let upper = code.to_ascii_uppercase();
        let s = upper.trim_ascii();
        report |= s.starts_with(b"REPORT ") && s.contains(&b'.');
        read_report |= s.starts_with(b"READ REPORT ") && text::contains(s, b" INTO ");
        loop_at |= s.starts_with(b"LOOP AT ");
        endloop |= s.starts_with(b"ENDLOOP.");
    }
    report && read_report && loop_at && endloop
}

#[cfg(test)]
mod tests {
    use super::looks_like_report;

    #[test]
    fn recognizes_report_but_not_comment_only_or_binary() {
        let source = b"REPORT demo.\nREAD REPORT name INTO src.\nLOOP AT src INTO row.\nENDLOOP.\n";
        assert!(looks_like_report(source));
        assert!(!looks_like_report(
            b"*REPORT demo.\n*READ REPORT name INTO src.\n*LOOP AT src INTO row.\n*ENDLOOP.\n"
        ));
        assert!(!looks_like_report(
            b"REPORT demo.\nLOOP AT src INTO row.\nENDLOOP.\n"
        ));
        let mut binary = source.to_vec();
        binary.extend_from_slice(&[0; 32]);
        assert!(!looks_like_report(&binary));
    }
}
