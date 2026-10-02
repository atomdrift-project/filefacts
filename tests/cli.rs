//! Command-line behaviour of the `filefacts` binary: argument handling,
//! output plumbing, and the bundle's coverage of the views.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const SOURCE: &[u8] = b"import os  # fetch\nos.system('curl http://example.invalid/x')\n";

/// A fresh, empty directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cli")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The binary, kept away from the user's caches: the extraction cache is
/// off, and every directory a cache path is derived from — `HOME` (macOS
/// puts caches in `~/Library/Caches`, ignoring `XDG_CACHE_HOME`) and
/// `XDG_CACHE_HOME` — points into a private directory. Variables that steer
/// stng's old caches or the debug output are cleared, whatever the
/// developer's shell has set.
fn filefacts() -> Command {
    let home = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-home");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_filefacts"));
    cmd.env("FILEFACTS_CACHE", "0")
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("NO_COLOR", "1");
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|n| n.starts_with("STNG_")) {
            cmd.env_remove(&name);
        }
    }
    cmd.env_remove("FILEFACTS_DEBUG");
    cmd
}

fn json(out: &Output) -> Value {
    assert!(
        out.status.success(),
        "{:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Malware samples often carry names that are not valid UTF-8; they are
/// analysed like any other path, given directly or found by a walk.
#[cfg(unix)]
#[test]
fn non_utf8_path_is_analysed() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("non-utf8");
    let file = dir.join(std::ffi::OsStr::from_bytes(b"sample-\xff\xfe.py"));
    fs::write(&file, SOURCE).unwrap();
    for target in [&file, &dir] {
        let out = filefacts()
            .args(["--format", "json"])
            .arg(target)
            .output()
            .unwrap();
        assert_eq!(json(&out)["fileid"]["file_type"], "python");

        let out = filefacts().arg(target).output().unwrap();
        assert!(out.status.success(), "{:?}", out.status);
        assert!(String::from_utf8_lossy(&out.stdout).contains("sample-\u{fffd}\u{fffd}.py"));
    }
}

/// `filefacts dir | head`: once the reader goes away the walk stops
/// quietly and succeeds, rather than panicking or reporting every
/// remaining file as a failure.
#[test]
fn closed_pipe_ends_the_walk_quietly() {
    let dir = scratch("closed-pipe");
    // Far more output than a pipe buffers, so the binary is still writing
    // when the reader closes.
    for i in 0..300 {
        fs::write(dir.join(format!("s{i:03}.py")), SOURCE).unwrap();
    }
    for format in ["terminal", "json"] {
        let mut child = filefacts()
            .args(["--format", format])
            .arg(&dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        stdout.read_exact(&mut [0; 1]).unwrap();
        drop(stdout);
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{format}: {:?}: {stderr}", out.status);
        assert!(stderr.is_empty(), "{format}: {stderr}");
    }
}

/// A positional word that names a view is only the view when no file of
/// that name exists; an existing file is never silently taken for a view.
#[test]
fn existing_file_named_like_a_view_is_read_as_the_file() {
    let dir = scratch("view-named-file");
    fs::write(dir.join("metrics"), SOURCE).unwrap();
    fs::write(dir.join("other.py"), SOURCE).unwrap();
    let run = |args: &[&str]| {
        filefacts()
            .current_dir(&dir)
            .args(["--format", "json"])
            .args(args)
            .output()
            .unwrap()
    };

    let bundle = json(&run(&["metrics"]));
    assert_eq!(bundle["values"]["file"]["basename"], "metrics");

    let metrics = json(&run(&["--metrics", "metrics"]));
    assert!(metrics.get("schema_version").is_none());
    assert!(metrics.get("file.size").is_some());

    // No file is named `errors`, so the word selects the view.
    assert!(json(&run(&["errors", "other.py"])).is_array());

    let out = run(&["metrics", "other.py"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--metrics"));
}

/// The default bundle holds every view but the opt-in flow, and each one
/// is also selectable on its own.
#[test]
fn bundle_holds_every_view() {
    let dir = scratch("bundle");
    let file = dir.join("sample.py");
    fs::write(&file, SOURCE).unwrap();
    let run = |args: &[&str]| {
        let out = filefacts()
            .current_dir(&dir)
            .args(["--format", "json"])
            .args(args)
            .arg(&file)
            .output()
            .unwrap();
        json(&out)
    };

    let bundle = run(&[]);
    let keys: Vec<&str> = bundle
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for key in [
        "schema_version",
        "fileid",
        "identity",
        "values",
        "text",
        "literals",
        "comments",
        "metrics",
        "sections",
        "symbols",
        "references",
        "archive_members",
        "errors",
    ] {
        assert!(keys.contains(&key), "{key} missing from {keys:?}");
    }
    for key in keys.iter().filter(|k| **k != "schema_version") {
        assert_eq!(run(&[&format!("--{key}")]), bundle[key], "{key}");
        assert_eq!(run(&[key]), bundle[key], "{key}");
    }
    assert!(run(&["--flow"]).is_object());
}

/// Terminal output with colour off: any control character other than a
/// newline came from the file and would reach the user's terminal raw.
fn terminal_text(args: &[&str], target: &Path) -> String {
    let out = filefacts().args(args).arg(target).output().unwrap();
    assert!(out.status.success(), "{:?}", out.status);
    String::from_utf8(out.stdout).unwrap()
}

/// Names, strings and paths from the file are printed with control
/// characters escaped, so a sample cannot drive the analyst's terminal.
#[test]
fn control_sequences_from_the_file_are_escaped() {
    let dir = scratch("control-sequences");
    fs::write(
        dir.join("evil\x1b[2J.py"),
        b"# \x1b]0;pwned\x07\nimport os\nos.system(\"\x1b[2J\")\n",
    )
    .unwrap();
    fs::write(dir.join("evil.json"), br#"{"k\u001b[2J": ["\u009b31m"]}"#).unwrap();
    for view in [
        "--fileid",
        "--values",
        "--text",
        "--literals",
        "--comments",
        "--symbols",
        "--calls",
    ] {
        let text = terminal_text(&[view], &dir.join("evil\x1b[2J.py"));
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{view}: {text:?}"
        );
    }
    let text = terminal_text(&[], &dir);
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "{text:?}"
    );
    assert!(text.contains("evil\\x1b[2J.py"), "{text}");
    assert!(text.contains("\\x9b31m"), "{text}");
}

/// JSON escapes C0 controls itself; DEL and the C1 controls (the 8-bit CSI
/// among them) must not reach a terminal raw either, yet still round-trip.
#[test]
fn json_output_escapes_del_and_c1_controls() {
    let dir = scratch("json-c1");
    let file = dir.join("c1.json");
    fs::write(&file, "{\"k\": [\"\u{9b}31m\u{7f}\"]}").unwrap();
    let out = filefacts()
        .args(["--format", "json", "values"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out.status);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "{text:?}"
    );
    assert!(text.contains("\\u009b31m\\u007f"), "{text}");
    let value: Value = serde_json::from_str(&text).unwrap();
    assert!(value.to_string().contains("\u{9b}31m\u{7f}"), "{value}");
}

/// A FIFO named on the command line is refused at once: reading it would
/// block until a writer appears, then stream without bound.
#[cfg(unix)]
#[test]
fn fifo_argument_is_refused_not_read() {
    let dir = scratch("fifo");
    let fifo = dir.join("pipe");
    let made = Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|s| s.success()) {
        return; // no mkfifo on this host
    }
    let mut child = filefacts()
        .arg(&fifo)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(20) {
            let _ = child.kill();
            panic!("filefacts blocked reading a FIFO");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("not a regular file"), "{stderr}");
}

/// A call's arguments are typed values, not strings; they print as they
/// read in source.
#[test]
fn call_arguments_render() {
    let dir = scratch("call-arguments");
    let file = dir.join("args.py");
    fs::write(
        &file,
        b"import os\nos.system(\"curl x\", 3, name, f(), True)\n",
    )
    .unwrap();
    let text = terminal_text(&["calls"], &file);
    assert!(
        text.contains(r#"os.system  "curl x", 3, name, <call>, true"#),
        "{text}"
    );
}
