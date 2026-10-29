use super::*;

fn parse(body: &str) -> (Vec<Value>, Vec<Value>) {
    let (mut rows, mut gaps) = (Vec::new(), Vec::new());
    dependencies(
        &format!("<project xmlns='http://maven.apache.org/POM/4.0.0'>{body}</project>"),
        "META-INF/maven/g/app/pom.xml",
        &mut rows,
        &mut gaps,
    );
    (rows, gaps)
}

#[test]
fn direct_only_and_properties_keep_each_model_scope() {
    let (rows, gaps) = parse(
        "<properties><v>2.0.20</v></properties><dependencies><dependency><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId><version>${v}</version></dependency></dependencies><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>not-installed</artifactId><version>1</version></dependency></dependencies></dependencyManagement><profiles><profile><dependencies><dependency><groupId>g</groupId><artifactId>inactive</artifactId><version>1</version></dependency></dependencies></profile></profiles>",
    );
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    assert!(
        gaps[0]["reason"]
            .as_str()
            .unwrap()
            .contains("Profile-dependent")
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["purl"],
        "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.0.20"
    );
    let (other, gaps) = parse(
        "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency></dependencies>",
    );
    assert!(other.is_empty());
    assert_eq!(gaps.len(), 1);
}

#[test]
fn unresolved_fields_ranges_and_repositories_never_guess() {
    for field in ["version", "scope", "classifier", "type", "optional"] {
        let extra = if field == "version" {
            String::new()
        } else {
            "<version>1</version>".into()
        };
        let (rows, gaps) = parse(&format!(
            "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>{extra}<{field}>${{missing}}</{field}></dependency></dependencies>"
        ));
        assert!(rows.is_empty(), "{field}: {rows:?}");
        assert_eq!(gaps.len(), 1, "{field}: {gaps:?}");
    }
    for extra in [
        "<repositories><repository><url>https://private.invalid</url></repository></repositories>",
        "",
    ] {
        let version = if extra.is_empty() { "[1,2)" } else { "1" };
        let (rows, gaps) = parse(&format!(
            "{extra}<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>{version}</version></dependency></dependencies>"
        ));
        assert!(rows.is_empty());
        assert_eq!(gaps.len(), 1);
    }
}

#[test]
fn scope_optional_and_artifact_qualifiers_survive() {
    let (rows, gaps) = parse(
        "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version><scope>test</scope><optional>true</optional><classifier>tests</classifier><type>zip</type></dependency></dependencies>",
    );
    assert!(gaps.is_empty());
    assert_eq!(rows[0]["purl"], "pkg:maven/g/a@1?classifier=tests&type=zip");
    assert_eq!(rows[0]["scope"], "test");
    assert_eq!(rows[0]["optional"], true);
}

#[test]
fn malformed_xml_dtd_and_foreign_namespace_are_not_dependencies() {
    for xml in [
        "<project>",
        "<!DOCTYPE project [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><project>&x;</project>",
        "<project xmlns='https://unrelated.invalid'><dependencies/></project>",
    ] {
        let (mut rows, mut gaps) = (Vec::new(), Vec::new());
        dependencies(xml, "pom.xml", &mut rows, &mut gaps);
        assert!(rows.is_empty());
        assert_eq!(gaps.len(), 1);
    }
    let (rows, gaps) = parse(
        "<dependencies xmlns='https://unrelated.invalid'><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies>",
    );
    assert!(rows.is_empty());
    assert!(gaps.is_empty());
}
