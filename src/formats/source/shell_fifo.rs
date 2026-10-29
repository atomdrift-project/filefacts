//! FIFO relations in shell source: the FIFOs a script creates, and the
//! feedback loops that read a shell's stdin from a path a network client's
//! stdout is redirected to. Each loop is reported wherever it is written,
//! directly or in a literal `sh -c` argument, with the creation of its FIFO
//! when the script has one; rules combine the relations.
//!
//! These are source relationships, not observed execution, successful FIFO
//! creation or a reachable caller.
use super::visit::Visit;
use super::{TreeCache, named_children, text};
use crate::{FileType, Values, value_key};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

/// Largest `sh -c` argument parsed for loops.
const MAX_BODY_BYTES: usize = 4096;
/// Loops and FIFO creations each kept per file.
const MAX_FACTS: usize = 64;

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node).filter(|n| !n.is_extra()).collect()
}

fn word<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    matches!(node.kind(), "word" | "number")
        .then(|| text(node, source))
        .filter(|s| !s.is_empty() && !s.contains(['$', '`', '\\']))
}

/// The literal command name and argument nodes of a simple command.
fn command<'t, 's>(node: Node<'t>, source: &'s str) -> Option<(&'s str, Vec<Node<'t>>)> {
    if node.kind() != "command" {
        return None;
    }
    let name = node.child_by_field_name("name")?;
    let name_children = children(name);
    let [token] = name_children.as_slice() else {
        return None;
    };
    let program = word(*token, source)?;
    let mut args = Vec::new();
    for child in children(node) {
        if child != name {
            // Assignment prefixes, substitutions and redirects are not argv.
            if !matches!(child.kind(), "word" | "number" | "raw_string" | "string") {
                return None;
            }
            args.push(child);
        }
    }
    Some((program, args))
}

/// `name` without a leading `/bin/` or `/usr/bin/`, the directories a
/// script names system programs by.
fn program(name: &str) -> &str {
    name.strip_prefix("/usr/bin/")
        .or_else(|| name.strip_prefix("/bin/"))
        .unwrap_or(name)
}

fn shell(name: &str) -> bool {
    matches!(program(name), "sh" | "bash" | "dash")
}

/// Return the requested stream's sole literal path. Other redirects may only
/// discard stderr; a second redirect or changed descriptor invalidates binding.
fn redirected<'t, 's>(
    node: Node<'t>,
    source: &'s str,
    stream: u8,
) -> Option<(Node<'t>, &'s str, Option<Node<'t>>)> {
    if node.kind() != "redirected_statement" {
        return None;
    }
    let body = node.child_by_field_name("body")?;
    let mut path = None;
    let mut inline_descriptor = None;
    for redirect in children(node).into_iter().filter(|n| *n != body) {
        if redirect.kind() != "file_redirect" {
            return None;
        }
        let descriptor = redirect.child_by_field_name("descriptor");
        let destination = word(redirect.child_by_field_name("destination")?, source)?;
        let operator = (0..redirect.child_count())
            .filter_map(|i| redirect.child(i))
            .find(|n| !n.is_named())?;
        let operator = text(operator, source);
        let default = if operator == "<" { 0 } else { 1 };
        // The Bash grammar can attach an adjacent input descriptor to the
        // command as a numeric argument (sh 0<path). Whitespace separates a
        // real argv value (sh 0 <path), which must remain an argument.
        let adjacent = if descriptor.is_none() && operator == "<" && body.kind() == "command" {
            children(body)
                .last()
                .copied()
                .filter(|arg| arg.kind() == "number" && arg.end_byte() == redirect.start_byte())
        } else {
            None
        };
        let descriptor = descriptor
            .or(adjacent)
            .map_or(Some(default), |n| text(n, source).parse::<u8>().ok())?;
        if descriptor == stream
            && ((stream == 0 && operator == "<") || (stream == 1 && operator == ">"))
        {
            if path.replace(destination).is_some() {
                return None;
            }
            inline_descriptor = adjacent;
        } else if !(descriptor == 2 && operator == ">" && destination == "/dev/null") {
            return None;
        }
    }
    Some((body, path?, inline_descriptor))
}

/// The body of a quoted `sh -c` argument, when it holds only bare command
/// words and redirections: no expansion, quoting or compound syntax for the
/// nested parse to disagree with the shell about.
fn literal_body<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    let raw = text(node, source);
    let body = match node.kind() {
        "raw_string" => raw.strip_prefix('\'')?.strip_suffix('\'')?,
        "string" => raw.strip_prefix('"')?.strip_suffix('"')?,
        _ => return None,
    };
    (body.len() <= MAX_BODY_BYTES
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.:<>| \t\r\n".contains(&b)))
    .then_some(body)
}

fn host_name(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
}

/// One feedback loop: `<shell> <fifo | <client> <host> <port> >fifo`.
struct Loop<'s> {
    fifo: &'s str,
    interpreter: &'s str,
    network_client: &'s str,
    host: &'s str,
    port: u16,
}

/// The feedback loop `node` is, if it is one.
fn feedback<'s>(node: Node<'_>, source: &'s str) -> Option<Loop<'s>> {
    if node.has_error() {
        return None;
    }
    let (pipeline, fifo, _) = redirected(node, source, 1)?;
    if pipeline.kind() != "pipeline" {
        return None;
    }
    let stages = children(pipeline);
    let [left, right] = stages.as_slice() else {
        return None;
    };
    let mut operators = (0..pipeline.child_count())
        .filter_map(|i| pipeline.child(i))
        .filter(|n| !n.is_named());
    if operators.next().map(|n| text(n, source)) != Some("|") || operators.next().is_some() {
        return None;
    }
    let (input, input_path, descriptor_arg) = redirected(*left, source, 0)?;
    let (interpreter, mut args) = command(input, source)?;
    if let Some(arg) = descriptor_arg {
        args.retain(|n| *n != arg);
    }
    if input_path != fifo || !shell(interpreter) || !args.is_empty() {
        return None;
    }
    let (network_client, args) = command(*right, source)?;
    if !matches!(program(network_client), "nc" | "netcat" | "ncat") {
        return None;
    }
    let [host, port] = args.as_slice() else {
        return None;
    };
    let host = word(*host, source).filter(|host| host_name(host))?;
    let port = word(*port, source)?
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)?;
    Some(Loop {
        fifo,
        interpreter,
        network_client,
        host,
        port,
    })
}

/// Loops and FIFO creations the shared walk ([`super::visit`]) reaches.
#[derive(Default)]
pub(super) struct Collector {
    loops: Vec<Value>,
    /// FIFO path → offset of the first `mkfifo` creating it.
    fifos: BTreeMap<String, usize>,
    /// Names the script defines as functions, which shadow programs.
    functions: BTreeSet<String>,
    limited: bool,
}

impl Collector {
    pub(super) fn enter(&mut self, visit: &Visit<'_>, source: &str) {
        let node = visit.node;
        match node.kind() {
            "function_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.functions.insert(text(name, source).to_string());
                }
            }
            "redirected_statement" => {
                if let Some(found) = feedback(node, source) {
                    self.push(&found, node.start_byte(), None);
                }
            }
            "command" if !node.has_error() => self.command(node, source),
            _ => {}
        }
    }

    fn command(&mut self, node: Node<'_>, source: &str) {
        let Some((name, args)) = command(node, source) else {
            return;
        };
        if program(name) == "mkfifo" {
            for path in args.iter().filter_map(|arg| word(*arg, source)) {
                if path.starts_with('/') && self.fifos.len() < MAX_FACTS {
                    self.fifos
                        .entry(path.to_string())
                        .or_insert(node.start_byte());
                }
            }
            return;
        }
        let [option, payload] = args.as_slice() else {
            return;
        };
        if !shell(name) || !matches!(word(*option, source), Some("-c" | "-lc")) {
            return;
        }
        let Some(body) = literal_body(*payload, source) else {
            return;
        };
        if ![b'|', b'<', b'>']
            .into_iter()
            .all(|b| body.as_bytes().contains(&b))
        {
            return;
        }
        let parsed = TreeCache::parse(body.as_bytes(), FileType::Shell, None);
        let Some(cache) = parsed.cache() else {
            tracing::debug!(
                target: "filefacts::source",
                format = "shell",
                offset = payload.start_byte(),
                len = body.len(),
                error = parsed.diagnostic().map_or("", |d| d.message.as_str()),
                "shell fifo: `sh -c` argument did not parse"
            );
            return;
        };
        // The body starts one byte into the quoted argument.
        let payload_offset = payload.start_byte() + 1;
        for statement in children(cache.tree().root_node()) {
            if let Some(found) = feedback(statement, cache.source()) {
                self.push(
                    &found,
                    payload_offset + statement.start_byte(),
                    Some((node.start_byte(), payload_offset)),
                );
            }
        }
    }

    /// Record a loop at `offset`, inside the `sh -c` command and argument
    /// at `nested` when it is in one.
    fn push(&mut self, found: &Loop<'_>, offset: usize, nested: Option<(usize, usize)>) {
        if self.loops.len() >= MAX_FACTS {
            self.limited = true;
            return;
        }
        self.loops.push(json!({
            "fifo": found.fifo,
            "interpreter": found.interpreter,
            "network_client": found.network_client,
            "host": found.host,
            "port": found.port,
            "offset": offset,
            "shell_command_offset": nested.map(|(command, _)| command),
            "payload_offset": nested.map(|(_, payload)| payload),
        }));
    }

    /// Write `source.shell.fifos` and `source.shell.fifo_network_loops`.
    pub(super) fn emit(mut self, values: &mut Values) {
        if self.limited {
            tracing::debug!(
                target: "filefacts::source",
                format = "shell",
                max = MAX_FACTS,
                "shell fifo: loop budget reached; later loops omitted"
            );
        }
        // A function named like the shell or the client replaces the
        // program, so the loop is not the program's.
        let functions = &self.functions;
        self.loops.retain(|row| {
            ["interpreter", "network_client"].iter().all(|field| {
                row[field]
                    .as_str()
                    .is_none_or(|name| !functions.contains(name))
            })
        });
        for row in &mut self.loops {
            let created = row["fifo"]
                .as_str()
                .and_then(|fifo| self.fifos.get(fifo))
                .copied();
            row["fifo_created_offset"] = json!(created);
        }
        if !self.fifos.is_empty() {
            values.insert_key(
                value_key!("source.shell.fifos"),
                Value::Array(
                    self.fifos
                        .iter()
                        .map(|(path, offset)| json!({"path": path, "offset": offset}))
                        .collect(),
                ),
            );
        }
        if !self.loops.is_empty() {
            values.insert_key(
                value_key!("source.shell.fifo_network_loops"),
                Value::Array(self.loops),
            );
        }
    }
}

#[cfg(test)]
mod tests;
