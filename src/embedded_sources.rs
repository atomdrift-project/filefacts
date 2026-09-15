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

fn shell_type(shell: Option<&Value>) -> Option<FileType> {
    match shell?.as_str()? {
        "bash" | "sh" => Some(FileType::Shell),
        "pwsh" | "powershell" => Some(FileType::PowerShell),
        "python" => Some(FileType::Python),
        // Do not guess custom command templates, dynamic expressions, or the
        // OS-dependent default shell. Consumers can surface these omissions.
        _ => None,
    }
}

fn steps<'a>(
    value: Option<&'a Value>,
    prefix: String,
    default_shell: Option<&'a Value>,
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
                file_type: shell_type(step.get("shell").or(default_shell)),
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
                let default = job.pointer("/defaults/run/shell").or(workflow_default);
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
            let argv = program.as_array()?;
            if argv.len() != 1 {
                return None;
            }
            argv[0].as_str()?
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
        .and_then(|v| v.as_json().pointer("/rpm/scriptlets"))
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
        let parsed = crate::open_with_path(std::path::Path::new("action.yml"), yaml).unwrap();
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
                None,
                None,
                Some(FileType::Shell),
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
        let parsed = crate::open_with_path(
            std::path::Path::new("config.yaml"),
            b"runs:\n  using: composite\n  steps: [{shell: bash, run: echo example}]\n",
        )
        .unwrap();
        assert_eq!(parsed.fileid().file_type(), FileType::Yaml);
        assert_eq!(parsed.embedded_sources().count(), 0);
    }
}
