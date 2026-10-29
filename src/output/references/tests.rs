use super::*;

#[test]
fn references_without_context_or_resolution_deserialize() {
    let reference: Reference = serde_json::from_str(r#"{"locator":{"purl":"pkg:npm/a@1.0.0"},"kind":"dependency","source":"package.json","evidence":"a"}"#).unwrap();
    assert!(reference.context.is_none());
    assert!(reference.resolution.is_none());
    let json = serde_json::to_string(&reference).unwrap();
    assert!(!json.contains("context"));
    assert!(!json.contains("resolution"));
}

#[test]
fn resolution_serializes_kebab_case_and_unresolved_is_not_fetched() {
    let mut reference = Reference::new(
        RefLocator::Purl("pkg:golang/example.test/lib@v1.0.0".into()),
        RefKind::Dependency,
        "go.mod",
        "require example.test/lib v1.0.0",
    );
    assert!(reference.is_fetch_target());
    reference.resolution = Some(Resolution::DeclaredMinimum);
    assert!(reference.is_fetch_target());
    assert_eq!(
        serde_json::to_value(reference.resolution).unwrap(),
        "declared-minimum"
    );
    reference.resolution = Some(Resolution::Unresolved(UnresolvedReason::ChecksumConflict));
    assert!(!reference.is_fetch_target());
    assert_eq!(
        serde_json::to_value(reference.resolution).unwrap(),
        serde_json::json!({"unresolved": "checksum-conflict"})
    );
    let back: Reference =
        serde_json::from_str(&serde_json::to_string(&reference).unwrap()).unwrap();
    assert_eq!(back, reference);
}
