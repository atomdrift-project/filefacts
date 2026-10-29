use super::*;
use crate::FileType;
use crate::formats::references::derive;

#[test]
fn pkginfo_requires_dist_preserves_pins_ranges_and_markers() {
    let bytes = b"Metadata-Version: 2.4\nName: demo\nRequires-Dist: Requests==2.32.3\nRequires-Dist: boto3<2,>=1.0\nRequires-Dist: pytest>=9; extra == \"dev\"\n\nRequires-Dist: body-example==1.0\n";
    let facts = crate::OpenOptions::new()
        .path(std::path::Path::new("METADATA"))
        .open(bytes);
    let refs = facts.references();
    assert_eq!(refs.len(), 3);
    let pinned = refs
        .iter()
        .find(|r| r.evidence.starts_with("Requests"))
        .unwrap();
    assert_eq!(
        pinned.locator,
        RefLocator::Purl("pkg:pypi/requests@2.32.3".into())
    );
    assert!(!pinned.context.as_ref().unwrap().optional);
    let range = refs
        .iter()
        .find(|r| r.evidence.starts_with("boto3"))
        .unwrap();
    assert!(matches!(&range.locator, RefLocator::Purl(p) if p.contains("version_requirement=")));
    let extra = refs
        .iter()
        .find(|r| r.evidence.starts_with("pytest"))
        .unwrap();
    assert!(extra.context.as_ref().unwrap().optional);
    assert!(matches!(&extra.locator, RefLocator::Purl(p) if p.contains("environment_marker=")));
    assert!(refs.iter().all(|r| r.offset.is_some()));
}
#[test]
fn cargo_roles_aliases_ranges_workspace_and_disabled_build() {
    let values = Values::from_json(
        serde_json::json!({"package":{"name":"x","build":false},"dependencies":{"json":{"package":"serde_json","version":"=1.0.1"},"serde":"1.0","anyhow":"*","log":{"optional":true}},"build-dependencies":{"cc":{"workspace":true}},"workspace":{"dependencies":{"cc":"=1.0.99"}},"target":{"cfg(unix)":{"build-dependencies":{"bindgen":"0.69"}}},"dev-dependencies":{"tempfile":"3"}}),
    );
    let refs = derive(FileType::CargoToml, &[], &values);
    assert!(
        refs.iter()
            .any(|r| r.locator == RefLocator::Purl("pkg:cargo/serde_json@1.0.1".into()))
    );
    assert!(
        refs.iter()
            .any(|r| r.source.contains("build-dependencies.cc")
                && r.locator == RefLocator::Purl("pkg:cargo/cc@1.0.99".into()))
    );
    // A range rides along as a qualifier; a wildcard or missing
    // requirement is the bare coordinate.
    let purls: Vec<&str> = refs
        .iter()
        .filter_map(|r| match &r.locator {
            RefLocator::Purl(p) => Some(p.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        purls.contains(&"pkg:cargo/serde?version_requirement=1.0"),
        "{purls:?}"
    );
    assert!(purls.contains(&"pkg:cargo/anyhow"), "{purls:?}");
    assert!(purls.contains(&"pkg:cargo/log"), "{purls:?}");
    assert!(
        refs.iter()
            .any(|r| r.source.contains("cfg(unix)") && r.is_fetch_target())
    );
    assert!(
        refs.iter()
            .any(|r| r.source.contains("dev-dependencies") && !r.is_fetch_target())
    );
    assert!(!refs.iter().any(|r| r.source.contains("package.build")));
}
#[test]
fn python_backend_and_runtime_requirements() {
    let values = Values::from_json(
        serde_json::json!({"build-system":{"requires":["setuptools>=70","wheel"],"build-backend":"backend","backend-path":["."]},"project":{"dependencies":["Requests==2.32.3","httpx>=0.27; python_version >= '3.9'"]}}),
    );
    let refs = derive(FileType::PyProjectToml, &[], &values);
    assert!(
        refs.iter()
            .any(|r| r.locator == RefLocator::Purl("pkg:pypi/requests@2.32.3".into()))
    );
    assert!(
        refs.iter()
            .any(|r| r.source.ends_with("build-system.requires") && r.is_fetch_target())
    );
    assert!(
        refs.iter()
            .any(|r| r.locator == RefLocator::Path("./backend.py".into()))
    );
}
