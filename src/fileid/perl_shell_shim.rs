//! A shell prologue that immediately re-execs this same file through Perl.
//! This identifies the documented dual-language launch convention, not the
//! provenance or safety of the interpreter or the rest of the program.

use regex::Regex;
use std::sync::LazyLock;

pub(super) fn recognized(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data.get(..32 * 1024).unwrap_or(data)) else {
        return false;
    };
    // The caller has already identified a shell shebang. Only comments and
    // blank lines may precede the shim: an earlier shell command is not this
    // immediate handoff convention.
    let mut lines = text.lines().filter_map(|line| {
        let line = line.trim();
        (!line.is_empty() && !line.starts_with('#')).then_some(line)
    });
    let Some(eval) = lines.next() else {
        return false;
    };
    let Some(guard) = lines.next() else {
        return false;
    };
    let guard = guard.split_once('#').map_or(guard, |(code, _)| code).trim();
    if guard != "if 0;" {
        return false;
    }
    static SHIM: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"^eval 'exec (?:perl|/[A-Za-z0-9_./-]+/perl|\$\{PERL:=/[A-Za-z0-9_./-]+/perl\})(?: -[wWSxTt]+)* \$0 \$\{1\+"\$@"\}'$"#,
        ).expect("fixed Perl self-exec shim grammar")
    });
    SHIM.is_match(eval)
}

#[cfg(test)]
mod tests {
    use super::recognized;
    use crate::fileid::{DetectionSource, FileType, detect};
    use std::path::Path;

    #[test]
    fn documented_shims_identify_perl_without_a_false_juke() {
        let corpus = include_bytes!("testdata/tiny-perl-shell-shim.pl");
        assert!(recognized(corpus));
        let detection = detect(Path::new("check.pl"), corpus).unwrap();
        assert_eq!(detection.file_type, FileType::Perl);
        assert!(!detection.extension_mismatch());
        for interpreter in ["perl", "/usr/bin/perl", "${PERL:=/usr/dist/exe/perl}"] {
            let body = format!(
                "#!/bin/sh --\n# license notice\n\neval 'exec {interpreter} -wS $0 ${{1+\"$@\"}}'\nif 0; # only the shell executes the handoff\nuse strict;\n"
            );
            assert!(recognized(body.as_bytes()));
            let detection = detect(Path::new("renamed.pl"), body.as_bytes()).unwrap();
            assert_eq!(detection.file_type, FileType::Perl);
            assert_eq!(detection.source, DetectionSource::Heuristic);
            assert!(!detection.extension_mismatch());
        }
    }

    #[test]
    fn altered_or_non_immediate_handoffs_keep_mismatch_detection() {
        let valid = "#!/bin/sh\neval 'exec perl -S $0 ${1+\"$@\"}'\nif 0;\nuse strict;\n";
        for body in [
            valid.replace("if 0;", "if 1;"),
            valid.replace("if 0;", "if $enabled;"),
            valid.replace("exec perl", "echo hello; exec perl"),
            valid.replace("-S", "-e"),
            valid.replace("$0", "other.pl"),
            valid.replace("}'", "}; curl https://example.test'"),
            valid.replace("eval '", "echo earlier\neval '"),
            valid.replace("eval '", "# eval '"),
        ] {
            assert!(!recognized(body.as_bytes()), "{body}");
            let detection = detect(Path::new("altered.pl"), body.as_bytes()).unwrap();
            assert!(detection.extension_mismatch(), "{body}");
        }
        for end in 0..valid.find("if 0;").unwrap() + 5 {
            assert!(!recognized(&valid.as_bytes()[..end]));
        }
    }
}
