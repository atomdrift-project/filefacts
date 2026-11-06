use super::*;
use std::collections::BTreeSet;

/// Parse `words` as a command line on which only `existing` names files.
fn parse(words: &[&str], existing: &[&str]) -> Result<Args, String> {
    let words = words.iter().map(OsString::from);
    match parse_args(words, |p| existing.iter().any(|e| Path::new(e) == p))? {
        ParseOutcome::Run(args) => Ok(args),
        other => panic!("expected a run, got {other:?}"),
    }
}

fn paths(args: &Args) -> Vec<&str> {
    args.paths.iter().map(|p| p.to_str().unwrap()).collect()
}

#[test]
fn every_view_is_reachable_by_name_and_flag() {
    let help = usage();
    let mut names = BTreeSet::new();
    for &view in View::ALL {
        let name = view.name();
        assert!(names.insert(name), "{name} is listed twice");
        assert!(
            help.contains(&format!("\n  {name} ")),
            "{name} not in usage"
        );
        let flag = format!("--{name}");
        for words in [[name, "x"], ["x", name], [flag.as_str(), "x"]] {
            let args = parse(&words, &[]).unwrap();
            assert_eq!(args.view, Some(view), "{words:?}");
            assert_eq!(paths(&args), ["x"], "{words:?}");
        }
    }
}

#[test]
fn usage_documents_every_environment_variable_and_exit_status() {
    let help = usage();
    for name in [
        "FILEFACTS_CACHE",
        "FILEFACTS_DEBUG",
        "NO_COLOR",
        "COLUMNS",
        "--no-cache",
    ] {
        assert!(help.contains(name), "{name} not in usage");
    }
    for code in [EXIT_FAILURE, EXIT_USAGE] {
        assert!(
            help.contains(&format!("\n  {code} ")),
            "exit {code} not in usage"
        );
    }
    assert!(!help.contains("--pretty"));
}

#[test]
fn only_explicit_on_values_enable_debug_output() {
    assert!(debug_requested(Some(OsStr::new("1"))));
    assert!(debug_requested(Some(OsStr::new("yes"))));
    for off in ["", "0", "false", "FALSE"] {
        assert!(!debug_requested(Some(OsStr::new(off))), "{off:?}");
    }
    assert!(!debug_requested(None));
}

#[test]
fn several_paths_are_analysed_in_order() {
    let args = parse(&["a", "metrics", "b", "c"], &[]).unwrap();
    assert_eq!(args.view, Some(View::Metrics));
    assert_eq!(paths(&args), ["a", "b", "c"]);
    // After `--` a view name is a path, so it shadows nothing.
    let args = parse(&["--", "metrics", "b"], &["metrics"]).unwrap();
    assert_eq!(args.view, None);
    assert_eq!(paths(&args), ["metrics", "b"]);
    assert!(parse(&[], &[]).unwrap_err().contains("no path"));
}

#[test]
fn options_flags_parse_and_reach_the_open_options() {
    let args = parse(&["--no-cache", "x"], &[]).unwrap();
    assert!(args.no_cache);
    let err = parse(&["--no-such-flag", "x"], &[]).unwrap_err();
    assert!(err.contains("--no-such-flag"), "{err}");
}

#[test]
fn existing_file_wins_over_a_positional_view_name() {
    let args = parse(&["metrics", "x"], &[]).unwrap();
    assert_eq!(args.view, Some(View::Metrics));
    assert_eq!(paths(&args), ["x"]);

    let args = parse(&["metrics"], &["metrics"]).unwrap();
    assert_eq!(args.view, None);
    assert_eq!(paths(&args), ["metrics"]);

    let args = parse(&["--metrics", "metrics"], &["metrics"]).unwrap();
    assert_eq!(args.view, Some(View::Metrics));
    assert_eq!(paths(&args), ["metrics"]);

    let err = parse(&["metrics", "x"], &["metrics"]).unwrap_err();
    assert!(err.contains("--metrics"), "{err}");
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_is_a_path() {
    use std::os::unix::ffi::OsStrExt;
    let raw = OsStr::from_bytes(b"sample-\xff.py").to_os_string();
    let words = ["--format".into(), "json".into(), raw.clone()];
    let Ok(ParseOutcome::Run(args)) = parse_args(words, |_| false) else {
        panic!("non-UTF-8 path rejected");
    };
    assert_eq!(args.paths, [PathBuf::from(raw)]);
    assert_eq!(args.format, Format::Json);
}

#[test]
fn serialisation_failure_is_reported_and_output_failure_ends_the_run() {
    let path = Path::new("x");
    let data = serde_json::to_value(std::collections::HashMap::from([((1, 2), 3)]));
    assert!(!report_serialisation(path, data.map(drop)).unwrap());

    let closed = serde_json::Error::io(io::ErrorKind::BrokenPipe.into());
    let err = report_serialisation(path, Err(closed)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(exit_code(Err(err)), ExitCode::SUCCESS);
    let full = io::Error::from(io::ErrorKind::StorageFull);
    assert_eq!(exit_code(Err(full)), ExitCode::from(EXIT_FAILURE));
}

/// Output that the reader has stopped consuming.
struct ClosedPipe;

impl Write for ClosedPipe {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hermetic() -> OpenOptions<'static> {
    OpenOptions::new().cache(false)
}

const PLAIN: Style = Style {
    color: false,
    width: 100,
};

#[test]
fn closed_output_ends_the_run_in_every_format() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/markdown"));
    for format in [Format::Terminal, Format::Json] {
        let args = Args {
            format,
            ..Args::default()
        };
        let err = run(&mut ClosedPipe, dir, &args, PLAIN, &hermetic()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{format:?}");
    }
}

/// A walk visits files in path order, descending into each directory at
/// its place in that order, and skips symlinks.
#[test]
fn directory_walk_is_sorted_and_skips_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    for sub in ["b", "a/z", "c"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    for file in ["b/2.txt", "a/z/1.txt", "a/0.txt", "c/3.txt", "d.txt"] {
        std::fs::write(dir.join(file), b"x\n").unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join("d.txt"), dir.join("a/link.txt")).unwrap();
    let args = Args {
        view: Some(View::Fileid),
        ..Args::default()
    };
    let mut out = Vec::new();
    assert!(run(&mut out, dir, &args, PLAIN, &hermetic()).unwrap());
    // Each file's terminal output opens with its path.
    let out = String::from_utf8(out).unwrap();
    let root = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);
    let visited: Vec<String> = out
        .lines()
        .filter_map(|line| line.strip_prefix(&root))
        .map(|rest| rest.split("  ").next().unwrap().replace('\\', "/"))
        .collect();
    assert_eq!(
        visited,
        ["a/0.txt", "a/z/1.txt", "b/2.txt", "c/3.txt", "d.txt"]
    );
}

/// What `EscapeJsonTerminalControls` makes of `text` written in one piece.
fn json_escaped(text: &str) -> String {
    let mut out = Vec::new();
    EscapeJsonTerminalControls(&mut out)
        .write_all(text.as_bytes())
        .unwrap();
    String::from_utf8(out).unwrap()
}

/// JSON output escapes what the terminal renderer escapes, invisible
/// characters included, as JSON `\u` escapes that decode to the same text;
/// JSON's own newlines and indentation pass through.
#[test]
fn json_escapes_invisible_and_terminal_characters() {
    let raw = "{\n  \"k\": \"\u{7f}\u{9b}\u{202e}a\u{200b}b\u{2028}\u{feff}\u{e0041}\"\n}";
    let escaped = json_escaped(raw);
    assert_eq!(
        escaped,
        "{\n  \"k\": \"\\u007f\\u009b\\u202ea\\u200bb\\u2028\\ufeff\\udb40\\udc41\"\n}"
    );
    let value: serde_json::Value = serde_json::from_str(&escaped).unwrap();
    assert_eq!(
        value["k"],
        "\u{7f}\u{9b}\u{202e}a\u{200b}b\u{2028}\u{feff}\u{e0041}"
    );
    for kept in ["naïve", "\u{1f468}\u{200d}\u{1f469}", "\u{0645}"] {
        assert_eq!(json_escaped(kept), kept);
    }
}
