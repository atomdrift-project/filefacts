//! Declared source units, separate from arbitrary strings or encoded payloads.
use crate::{FileType, Values};
use serde_json::Value;

/// A script explicitly declared by a container format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EmbeddedSource<'a> {
    /// JSON Pointer into the original structured values. Not a byte offset:
    /// YAML folding and escapes can make the decoded body non-contiguous.
    pub pointer: String,
    /// Decoded script body, borrowed from the existing values tree.
    pub source: &'a str,
    /// Known declared interpreter, or None for missing/dynamic/custom shells.
    /// None is an analysis limitation, not evidence that the body is benign.
    pub file_type: Option<FileType>,
}

/// Interpreter for a declared `shell:` value: a GitHub built-in name, or a
/// custom `command [options] {0}` template whose command is one of them
/// (`bash -e {0}`, `/bin/sh -x {0}`).
fn shell_type(shell: &Value) -> Option<FileType> {
    let shell = shell.as_str()?;
    let mut words = shell.split_whitespace();
    let command = words.next()?;
    // A dynamic expression is resolved at run time. A multi-word value that
    // is not a `{0}` template is not a shell GitHub would accept.
    if shell.contains("${{") || (words.next().is_some() && !shell.contains("{0}")) {
        return None;
    }
    match command.rsplit('/').next()? {
        "bash" | "sh" => Some(FileType::Shell),
        "pwsh" | "powershell" => Some(FileType::PowerShell),
        "python" | "python3" => Some(FileType::Python),
        // `cmd` and other custom interpreters stay explicit unknowns.
        _ => None,
    }
}

/// Whether any string anywhere in `value` satisfies `pred`.
fn any_string(value: &Value, pred: &dyn Fn(&str) -> bool) -> bool {
    match value {
        Value::String(s) => pred(s),
        Value::Array(items) => items.iter().any(|v| any_string(v, pred)),
        Value::Object(map) => map.values().any(|v| any_string(v, pred)),
        _ => false,
    }
}

/// GitHub's shell for a workflow step that declares none: `bash` on Linux
/// and macOS runners, `pwsh` on Windows. Runner labels are AND-ed, so any
/// Windows label selects Windows. A dynamic `runs-on` is resolved to bash
/// only when neither it nor the job's matrix names Windows; with no
/// `runs-on` at all the job is malformed and the shell stays unknown.
fn runner_default(job: &Value) -> Option<FileType> {
    let windows = |s: &str| s.to_ascii_lowercase().contains("windows");
    let runs_on = job.get("runs-on")?;
    if any_string(runs_on, &windows) {
        return Some(FileType::PowerShell);
    }
    let dynamic = any_string(runs_on, &|s: &str| s.contains("${{"));
    if dynamic && job.get("strategy").is_some_and(|s| any_string(s, &windows)) {
        return None;
    }
    Some(FileType::Shell)
}

fn steps<'a>(
    value: Option<&'a Value>,
    prefix: String,
    default_shell: Option<FileType>,
) -> impl Iterator<Item = EmbeddedSource<'a>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(move |(index, step)| {
            // `uses` and `run` are mutually exclusive. Do not reinterpret
            // action inputs, descriptions, env values or malformed mixed steps.
            if step.get("uses").is_some() {
                return None;
            }
            let source = step.get("run")?.as_str()?;
            Some(EmbeddedSource {
                pointer: format!("{prefix}/{index}/run"),
                source,
                file_type: step.get("shell").map_or(default_shell, shell_type),
            })
        })
}

pub(crate) fn github_actions(values: Option<&Values>) -> impl Iterator<Item = EmbeddedSource<'_>> {
    values.into_iter().flat_map(|values| {
        let root = values.as_json();
        let action_steps = root
            .get("runs")
            .filter(|runs| runs.get("using").and_then(Value::as_str) == Some("composite"))
            .and_then(|runs| runs.get("steps"));
        let workflow_default = root.pointer("/defaults/run/shell");
        let jobs = root.get("jobs").and_then(Value::as_object);
        steps(action_steps, "/runs/steps".to_owned(), None).chain(
            jobs.into_iter().flatten().flat_map(move |(name, job)| {
                let escaped = name.replace('~', "~0").replace('/', "~1");
                let default = job
                    .pointer("/defaults/run/shell")
                    .or(workflow_default)
                    .map_or_else(|| runner_default(job), shell_type);
                steps(job.get("steps"), format!("/jobs/{escaped}/steps"), default)
            }),
        )
    })
}

fn rpm_interpreter(script: &Value) -> Option<FileType> {
    // Runtime macro/queryformat expansion is intentionally not evaluated.
    // Conservatively retain flagged bodies as unknown source units.
    if let Some(flags) = script.get("flags")
        && flags.as_u64()? != 0
    {
        return None;
    }
    let executable = match script.get("program") {
        None => "/bin/sh",
        Some(program) => {
            let [argv0] = program.as_array()?.as_slice() else {
                return None;
            };
            argv0.as_str()?
        }
    };
    match executable {
        "/bin/sh" | "/usr/bin/sh" | "/bin/bash" | "/usr/bin/bash" | "/bin/dash"
        | "/usr/bin/dash" | "/bin/zsh" | "/usr/bin/zsh" => Some(FileType::Shell),
        "/usr/bin/python" | "/usr/bin/python3" => Some(FileType::Python),
        "/usr/bin/perl" => Some(FileType::Perl),
        "/usr/bin/ruby" => Some(FileType::Ruby),
        "<lua>" | "/usr/bin/lua" => Some(FileType::Lua),
        _ => None,
    }
}

pub(crate) fn rpm(values: Option<&Values>) -> impl Iterator<Item = EmbeddedSource<'_>> {
    values
        .and_then(|v| v.get_key(crate::value_key!("rpm.scriptlets")))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, script)| {
            Some(EmbeddedSource {
                pointer: format!("/rpm/scriptlets/{name}/body"),
                source: script.get("body")?.as_str()?,
                file_type: rpm_interpreter(script),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(yaml: &[u8]) -> Vec<(String, String, Option<FileType>)> {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("action.yml"))
            .open(yaml);
        parsed
            .embedded_sources()
            .map(|s| (s.pointer, s.source.to_owned(), s.file_type))
            .collect()
    }

    #[test]
    fn composite_bodies_are_decoded_separate_and_not_arbitrary_strings() {
        let actual = sources(
            br#"
description: 'echo documentation'
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        echo first
        echo second
    - shell: pwsh
      run: >-
        Write-Output
        ready
    - uses: example/action@v1
      with: {run: echo input}
    - shell: python
      run: "print('ok')\n"
"#,
        );
        assert_eq!(
            actual,
            vec![
                (
                    "/runs/steps/0/run".into(),
                    "echo first\necho second\n".into(),
                    Some(FileType::Shell)
                ),
                (
                    "/runs/steps/1/run".into(),
                    "Write-Output ready".into(),
                    Some(FileType::PowerShell)
                ),
                (
                    "/runs/steps/3/run".into(),
                    "print('ok')\n".into(),
                    Some(FileType::Python)
                ),
            ]
        );
    }

    #[test]
    fn workflow_shell_precedence_and_unknowns() {
        let actual = sources(
            br#"
defaults: {run: {shell: bash}}
jobs:
  build:
    defaults: {run: {shell: pwsh}}
    steps:
      - run: Write-Output inherited
      - shell: python
        run: print('override')
      - shell: '${{ matrix.shell }}'
        run: echo unknown
      - shell: 'bash -x {0}'
        run: echo custom
      - shell: null
        run: echo invalid
  test:
    steps:
      - run: echo workflow-default
"#,
        );
        assert_eq!(
            actual.iter().map(|s| s.2).collect::<Vec<_>>(),
            vec![
                Some(FileType::PowerShell),
                Some(FileType::Python),
                None,
                Some(FileType::Shell),
                None,
                Some(FileType::Shell),
            ]
        );
    }

    #[test]
    fn shell_templates_name_their_interpreter() {
        let shell = |s: &str| shell_type(&Value::from(s));
        assert_eq!(shell("bash"), Some(FileType::Shell));
        assert_eq!(shell("bash -e {0}"), Some(FileType::Shell));
        assert_eq!(
            shell("bash --noprofile --norc -eo pipefail {0}"),
            Some(FileType::Shell)
        );
        assert_eq!(shell("/bin/sh -x {0}"), Some(FileType::Shell));
        assert_eq!(
            shell("pwsh -command \". '{0}'\""),
            Some(FileType::PowerShell)
        );
        assert_eq!(shell("python3 {0}"), Some(FileType::Python));
        // Not a template, a dynamic value, or an interpreter we do not type.
        assert_eq!(shell("bash -e"), None);
        assert_eq!(shell("${{ matrix.shell }} {0}"), None);
        assert_eq!(shell("cmd"), None);
        assert_eq!(shell("perl {0}"), None);
        assert_eq!(shell(""), None);
    }

    #[test]
    fn undeclared_workflow_shell_follows_the_runner() {
        let actual = sources(
            br#"
on: push
jobs:
  linux:
    runs-on: ubuntu-latest
    steps: [{run: echo linux}]
  labels:
    runs-on: [self-hosted, linux, x64]
    steps: [{run: echo labels}]
  windows:
    runs-on: windows-2022
    steps: [{run: Write-Output windows}]
  group:
    runs-on: {group: ci, labels: [Windows]}
    steps: [{run: Write-Output group}]
  matrix:
    runs-on: ${{ matrix.os }}
    strategy: {matrix: {os: [ubuntu-latest, windows-latest]}}
    steps: [{run: echo ambiguous}]
  dynamic:
    runs-on: ${{ matrix.os }}
    strategy: {matrix: {os: [ubuntu-latest, macos-latest]}}
    steps: [{run: echo unix}, {shell: pwsh, run: Write-Output explicit}]
"#,
        );
        assert_eq!(
            actual
                .iter()
                .map(|s| (s.0.as_str(), s.2))
                .collect::<Vec<_>>(),
            // Jobs are visited in key order.
            vec![
                ("/jobs/dynamic/steps/0/run", Some(FileType::Shell)),
                ("/jobs/dynamic/steps/1/run", Some(FileType::PowerShell)),
                ("/jobs/group/steps/0/run", Some(FileType::PowerShell)),
                ("/jobs/labels/steps/0/run", Some(FileType::Shell)),
                ("/jobs/linux/steps/0/run", Some(FileType::Shell)),
                ("/jobs/matrix/steps/0/run", None),
                ("/jobs/windows/steps/0/run", Some(FileType::PowerShell)),
            ]
        );
    }

    #[test]
    fn unknown_default_is_retained_but_nonscript_fields_are_not() {
        let actual = sources(
            br#"
runs:
  using: node20
  main: index.js
  steps: [{shell: bash, run: echo not-composite}]
jobs:
  test:
    steps:
      - run: echo unknown-default
      - run: [not, a, string]
      - uses: example/action@v1
        run: echo invalid-mixed-step
"#,
        );
        assert_eq!(
            actual,
            vec![(
                "/jobs/test/steps/0/run".into(),
                "echo unknown-default".into(),
                None
            )]
        );
    }

    #[test]
    fn plain_yaml_is_not_promoted_to_executable_source() {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("config.yaml"))
            .open(b"runs:\n  using: composite\n  steps: [{shell: bash, run: echo example}]\n");
        assert_eq!(parsed.fileid().file_type(), FileType::Yaml);
        assert_eq!(parsed.embedded_sources().count(), 0);
    }
}
