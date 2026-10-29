use super::*;

/// A layer reads through to what lies under it but records only what it
/// changes itself, so a layer per helper or branch costs nothing for the
/// bindings it does not touch.
#[test]
fn layers_record_only_their_own_changes() {
    let base: BTreeMap<String, u32> = (0..1_000).map(|i| (format!("g{i}"), i)).collect();
    let mut module = Scope::over(&base);
    module.insert("m".into(), 7);
    let mut branch = Scope::under(&module);
    assert_eq!(branch.get("g999"), Some(999));
    assert_eq!(branch.get("m"), Some(7));
    branch.insert("b".into(), 1);
    branch.remove("g0");
    assert_eq!(branch.get("g0"), None);
    assert_eq!(module.get("g0"), Some(0));
    assert_eq!(branch.names().collect::<Vec<_>>(), ["b", "g0"]);
    assert_eq!(branch.bound().collect::<Vec<_>>(), [(&"b".to_string(), 1)]);
    let flat = module.into_map();
    assert_eq!(flat.len(), 1_001);
}
