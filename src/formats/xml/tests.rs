use super::*;

fn tree_bytes(bytes: &[u8]) -> serde_json::Value {
    let mut values = Values::new();
    let mut errors = Errors::default();
    extract(bytes, &mut values, &mut errors);
    assert_eq!(errors, Errors::default());
    values.into_json()
}

fn tree(xml: &str) -> serde_json::Value {
    tree_bytes(xml.as_bytes())
}

#[test]
fn element_tree_addresses_an_inline_task() {
    let doc = tree(
        r#"<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- a comment is not text -->
  <UsingTask TaskName="T" TaskFactory="CodeTaskFactory">
    <Task><Code Type="Fragment" Language="cs"><![CDATA[ Console.WriteLine(1); ]]></Code></Task>
  </UsingTask>
  <Target Name="A"><Exec Command="one"/></Target>
  <Target Name="B"><Exec Command="two"/><Exec Command="three"/></Target>
  <PropertyGroup><Plain>value</Plain></PropertyGroup>
</Project>"#,
    );
    let project = &doc["Project"];
    assert_eq!(project["@ToolsVersion"], "4.0");
    assert_eq!(
        project["@xmlns"],
        "http://schemas.microsoft.com/developer/msbuild/2003"
    );
    assert_eq!(project["UsingTask"]["@TaskFactory"], "CodeTaskFactory");
    assert_eq!(project["UsingTask"]["Task"]["Code"]["@Language"], "cs");
    assert_eq!(
        project["UsingTask"]["Task"]["Code"]["_text"],
        "Console.WriteLine(1);"
    );
    // A shared namespace is declared once, not inherited into children.
    assert!(project["UsingTask"].get("@xmlns").is_none());
    // Repeated siblings become an array in document order.
    assert_eq!(project["Target"][0]["Exec"]["@Command"], "one");
    assert_eq!(project["Target"][1]["Exec"][1]["@Command"], "three");
    // Text alone is the element's value.
    assert_eq!(project["PropertyGroup"]["Plain"], "value");
}

#[test]
fn project_downloads_are_still_read() {
    let doc = tree(
        r#"<Project><Target Name="T" BeforeTargets="Build"><DownloadFile SourceUrl="https://example.test/a"/></Target></Project>"#,
    );
    assert_eq!(
        doc["msbuild"]["downloads"][0]["source_url"],
        "https://example.test/a"
    );
}

#[test]
fn element_tree_is_depth_capped() {
    let depth = 2 * MAX_TREE_DEPTH;
    let xml = format!(
        "<Project>{}{}</Project>",
        "<g>".repeat(depth),
        "</g>".repeat(depth)
    );
    let doc = tree(&xml);
    let mut node = &doc["Project"];
    let mut levels = 0;
    while let Some(child) = node.get("g") {
        node = child;
        levels += 1;
    }
    assert_eq!(levels, MAX_TREE_DEPTH);
    assert!(node.is_null());
}

#[test]
fn element_tree_only_for_windows_document_roots() {
    let empty = tree("");
    assert_eq!(tree("<configuration><a/></configuration>"), empty);
    assert_eq!(tree("<Projects><a/></Projects>"), empty);
    assert_ne!(tree("<Task><a/></Task>"), empty);
}

/// The APT-C-09 `.pdf.SettingContent-ms` shape: PDF syntax in leading
/// comments, and a comment after every character of the DeepLink command.
#[test]
fn comments_do_not_split_element_text() {
    let command = "rundll32 url.dll,FileProtocolHandler \"https://x.test/a\"";
    let split: String = command
        .chars()
        .map(|c| format!("{c}<!-- 1 0 obj -->"))
        .collect();
    let doc = tree(&format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- %PDF-1.7 -->
<PCSettings>
  <SearchableContent xmlns="http://schemas.microsoft.com/Search/2013/SettingContent">
    <ApplicationInformation><DeepLink>{split}</DeepLink></ApplicationInformation>
  </SearchableContent>
</PCSettings>"#
    ));
    let content = &doc["PCSettings"]["SearchableContent"];
    assert_eq!(
        content["@xmlns"],
        "http://schemas.microsoft.com/Search/2013/SettingContent"
    );
    assert_eq!(content["ApplicationInformation"]["DeepLink"], command);
}

#[test]
fn text_runs_between_elements_join_with_spaces() {
    let doc = tree("<Task> one <a/> t<?pi x?>wo <b/> </Task>");
    assert_eq!(doc["Task"]["_text"], "one two");
}

#[test]
fn shell_documents_keep_their_namespaces() {
    let doc = tree(
        r#"<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library"><name>Documents</name></libraryDescription>"#,
    );
    assert_eq!(
        doc["libraryDescription"]["@xmlns"],
        "http://schemas.microsoft.com/windows/2009/library"
    );
    let doc = tree(r#"<c:contact xmlns:c="http://schemas.microsoft.com/Contact"/>"#);
    assert_eq!(
        doc["contact"]["@xmlns:c"],
        "http://schemas.microsoft.com/Contact"
    );
}

#[test]
fn utf16_documents_are_decoded() {
    let xml = r#"<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"/>"#;
    let le: Vec<u8> = b"\xFF\xFE"
        .iter()
        .copied()
        .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let be: Vec<u8> = b"\xFE\xFF"
        .iter()
        .copied()
        .chain(xml.encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    for bytes in [le, be] {
        assert_eq!(
            tree_bytes(&bytes)["Task"]["@xmlns"],
            "http://schemas.microsoft.com/windows/2004/02/mit/task"
        );
    }
    assert_eq!(tree_bytes(b"\xFF\xFE\x00\xD8"), tree(""));
}

#[test]
fn root_is_read_from_the_prolog() {
    assert_eq!(root_name("<Project Sdk=\"x\">"), Some("Project"));
    assert_eq!(
        root_name(
            "<?xml version=\"1.0\"?>\n<!-- build -->\n<!DOCTYPE p>\n<msb:Project xmlns:msb=\"u\"/>"
        ),
        Some("Project")
    );
    assert_eq!(root_name("<PCSettings/>"), Some("PCSettings"));
    assert_eq!(root_name("<!-- never closed <Project>"), None);
    assert_eq!(root_name("text"), None);
}
