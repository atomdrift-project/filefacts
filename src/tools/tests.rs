use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Component;

const TOOL: &str = "filefacts-test-tool";

fn tool_in(dir: &Path, mode: u32) -> PathBuf {
    let tool = dir.join(TOOL);
    std::fs::write(&tool, b"#!/bin/sh\n").expect("write tool");
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(mode)).expect("chmod");
    tool
}

#[test]
fn relative_path_entries_are_skipped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let tool = tool_in(tmp.path(), 0o755);
    // The same directory, spelled relative to the working directory.
    let cwd = std::env::current_dir().expect("cwd");
    let relative: PathBuf = cwd
        .components()
        .skip(1)
        .map(|_| Component::ParentDir)
        .chain(tmp.path().components().skip(1))
        .collect();
    assert!(relative.join(TOOL).is_file(), "{}", relative.display());
    assert_eq!(binary_in(relative.as_os_str(), TOOL), None);
    assert_eq!(binary_in(OsStr::new(""), TOOL), None);
    assert_eq!(binary_in(tmp.path().as_os_str(), TOOL), Some(tool));
}

#[test]
fn scrubbed_tool_sees_only_allowlisted_env() {
    let mut cmd = Command::new("env");
    cmd.env("FILEFACTS_TEST_SECRET", "hunter2");
    scrub_env(&mut cmd);
    let output = cmd.output().expect("run env");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 env");
    assert!(!stdout.contains("FILEFACTS_TEST_SECRET"), "{stdout}");
    for line in stdout.lines() {
        let key = line.split('=').next().unwrap_or_default();
        assert!(ENV_ALLOWLIST.contains(&key), "unexpected variable {key}");
    }
    if std::env::var_os("PATH").is_some() {
        assert!(stdout.lines().any(|line| line.starts_with("PATH=")));
    }
}

#[test]
fn non_executable_files_are_skipped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let tool = tool_in(tmp.path(), 0o644);
    assert_eq!(binary_in(tmp.path().as_os_str(), TOOL), None);
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(binary_in(tmp.path().as_os_str(), TOOL), Some(tool));
}
