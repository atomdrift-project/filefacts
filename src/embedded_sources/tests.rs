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
