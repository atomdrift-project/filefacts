//! Freedesktop Desktop Entry fields, and the shell flows their `Exec` lines
//! carry.
use super::systemd::{
    append_string_items, append_string_occurrence, append_systemd_raw, ensure_json_object,
    literal_shell_flows, normalize_systemd_key,
};
use crate::output::{Errors, Values};
use serde_json::Value;

pub(crate) fn extract(bytes: &[u8], values: &mut Values, errors: &mut Errors) {
    if bytes.len() > 16 * 1024 * 1024 {
        return;
    }
    let Some(root) = parse_desktop_entry(bytes) else {
        return;
    };
    super::structured::merge_document(root, values, errors);
    let flows = match values.get("desktop_entry.exec") {
        Some(Value::String(s)) => literal_shell_flows(s),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .flat_map(literal_shell_flows)
            .collect(),
        _ => Vec::new(),
    };
    values.insert_key(
        crate::value_key!("shell.literal_command_flows"),
        Value::Array(flows),
    );
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

        // A `[Group Name]` header; one whose name normalizes to nothing
        // opens no section.
        if let Some(inner) = trimmed.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let section = normalize_systemd_key(inner);
            if !section.is_empty() {
                current_section = Some(section);
            }
            continue;
        }

        let Some(section_name) = current_section.as_deref() else {
            continue;
        };
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let raw_key = raw_key.trim();
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

        let raw_value = raw_value.trim().to_string();
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

    (!root.is_empty()).then_some(Value::Object(root))
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
    let mut chars = input.chars();

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
