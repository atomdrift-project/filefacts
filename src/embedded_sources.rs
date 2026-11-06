//! Declared source units, separate from arbitrary strings or encoded payloads.
use crate::{FileType, Values};
use serde_json::Value;
use std::borrow::Cow;

pub(crate) mod html;

/// A script explicitly declared by a container format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EmbeddedSource<'a> {
    /// Where the body was found. For [`Origin::Value`] a JSON Pointer into
    /// the file's [`Values`]; for [`Origin::Script`] the name
    /// `/html/scripts/<n>`, where `n` counts the page's `<script>` elements
    /// from zero, which points into nothing.
    pub pointer: String,
    /// Decoded script body: borrowed from the values tree or the host bytes,
    /// or owned when decoding changed it.
    pub source: Cow<'a, str>,
    /// Known declared interpreter, or None for missing/dynamic/custom shells.
    /// None is an analysis limitation, not evidence that the body is benign.
    pub file_type: Option<FileType>,
    /// How the body relates to its host file.
    pub origin: Origin,
}

/// How an [`EmbeddedSource`] relates to the file that declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// An independent program held in a structured value, such as one
    /// workflow step among others: its own offsets, lines and scope. Not a
    /// byte range of the host: YAML folding and escapes can make the decoded
    /// body non-contiguous.
    Value,
    /// A script in the host's own markup (a page's inline `<script>`): part
    /// of the host, to be analysed as a layer of it, but parsed on its own as
    /// the browser parses it.
    Script {
        /// Byte offset in the host of the body's first byte.
        offset: usize,
        /// Which scope the script runs in.
        scope: ScriptScope,
        /// Byte `i` of the source is byte `offset + i` of the host, so the
        /// host's offsets and line breaks apply. `false` when decoding (an
        /// SVG script's character references) changed widths; offsets past
        /// the first decoded reference are then approximate.
        aligned: bool,
    },
}

/// The scope a page script runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptScope {
    /// A classic script: its top-level declarations are globals that every
    /// other classic script of the page sees.
    Classic,
    /// A module script (`type="module"`): its own module scope.
    Module,
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
                source: Cow::Borrowed(source),
                file_type: step.get("shell").map_or(default_shell, shell_type),
                origin: Origin::Value,
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
        .and_then(|v| v.lookup(crate::value_key!("rpm.scriptlets")))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, script)| {
            Some(EmbeddedSource {
                pointer: format!("/rpm/scriptlets/{name}/body"),
                source: Cow::Borrowed(script.get("body")?.as_str()?),
                file_type: rpm_interpreter(script),
                origin: Origin::Value,
            })
        })
}

pub(crate) fn rpyc(values: Option<&Values>) -> impl Iterator<Item = EmbeddedSource<'_>> {
    values
        .and_then(|v| v.lookup(crate::value_key!("rpyc")))
        .and_then(|v| v.get("python_sources"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, item)| {
            Some(EmbeddedSource {
                pointer: format!("/rpyc/python_sources/{index}/source"),
                source: Cow::Borrowed(item.get("source")?.as_str()?),
                file_type: Some(FileType::Python),
                origin: Origin::Value,
            })
        })
}

#[cfg(test)]
mod tests;
