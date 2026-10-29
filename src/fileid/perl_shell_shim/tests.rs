use super::recognized;
use crate::fileid::{DetectionSource, FileType, detect};
use std::path::Path;

#[test]
fn documented_shims_identify_perl_without_a_false_juke() {
    let corpus = include_bytes!("../testdata/tiny-perl-shell-shim.pl");
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
