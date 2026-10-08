//! Desktop Entry fields migrated from cleave's structured-value parser.
use crate::output::Values;
use serde_json::Value;

pub(crate) fn extract(bytes: &[u8], values: &mut Values) {
    if bytes.len() > 16 * 1024 * 1024 {
        return;
    }
    if let Some(root) = parse_desktop_entry(bytes) {
        *values = Values::from_json(root);
        let command = values.get("desktop_entry.exec").cloned();
        let commands: Vec<&str> = match command.as_ref() {
            Some(Value::String(s)) => vec![s],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let flows: Vec<Value> = commands
            .iter()
            .flat_map(|s| super::systemd::literal_shell_flows(s))
            .collect();
        values.insert_key(
            crate::value_key!("shell.literal_command_flows"),
            Value::Array(flows),
        );
    }
}

fn parse_desktop_entry(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    let mut root: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut current_section: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim_start();

        // Desktop entry spec: blank lines and `#` comments are ignored.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(section) = parse_desktop_section_header(trimmed) {
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

        // Drop localized variants (`Name[cs]=...`): the canonical unlocalized key
        // is enough for detection, and exposing per-locale keys makes trait authoring
        // unwieldy.
        if raw_key.contains('[') {
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

        if is_desktop_list_key(&key) {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            let items = split_desktop_list(&raw_value);
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

fn parse_desktop_section_header(line: &str) -> Option<String> {
    if line.starts_with('[') && line.ends_with(']') && line.len() >= 3 {
        let inner = &line[1..line.len() - 1];
        let normalized = normalize_systemd_key(inner);
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    } else {
        None
    }
}

fn is_desktop_list_key(key: &str) -> bool {
    matches!(
        key,
        "only_show_in"
            | "not_show_in"
            | "actions"
            | "mime_type"
            | "categories"
            | "implements"
            | "keywords"
    )
}

fn split_desktop_list(input: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('s') => current.push(' '),
                Some('n') => current.push('\n'),
                Some('r') => current.push('\r'),
                Some('t') => current.push('\t'),
                Some(';') => current.push(';'),
                Some('\\') | None => current.push('\\'),
                Some(other) => {
                    current.push('\\');
                    current.push(other);
                }
            }
        } else if ch == ';' {
            if !current.is_empty() {
                items.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        items.push(current);
    }

    items
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
