use super::*;

#[test]
fn rt_name_known() {
    assert_eq!(rt_name(16), "RT_VERSION");
    assert_eq!(rt_name(24), "RT_MANIFEST");
    assert_eq!(rt_name(3), "RT_ICON");
    assert_eq!(rt_name(99), "RT_UNKNOWN");
}

#[test]
fn rt_name_covers_canonical_resource_types() {
    assert_eq!(rt_name(1), "RT_CURSOR");
    assert_eq!(rt_name(2), "RT_BITMAP");
    assert_eq!(rt_name(14), "RT_GROUP_ICON");
}

/// The resource facts are derived from ids drained out of goblin's walker,
/// outside its panic guard: counts, icons, and the deduplicated type list.
#[test]
fn resource_types_derive_from_drained_ids() {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    resource_types(
        &[Some(16), Some(3), None, Some(14), Some(3), Some(999)],
        &mut values,
        &mut metrics,
    );
    assert_eq!(metrics.get("pe.resource_count"), Some(6.0));
    assert_eq!(metrics.get("pe.icon_count"), Some(3.0));
    assert_eq!(
        values.get("pe.resource_types"),
        Some(&serde_json::json!([
            "RT_ICON",
            "RT_GROUP_ICON",
            "RT_VERSION",
            "RT_UNKNOWN"
        ]))
    );

    let mut values = Values::new();
    let mut metrics = Metrics::new();
    resource_types(&[], &mut values, &mut metrics);
    assert_eq!(metrics.get("pe.resource_count"), Some(0.0));
    assert!(metrics.get("pe.icon_count").is_none());
    assert!(values.get("pe.resource_types").is_none());
}
