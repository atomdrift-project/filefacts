use super::*;

#[test]
fn set_hash_sorts_dedups_and_skips_the_empty_set() {
    let set = |names: &[&str]| md5_of_set(names.iter().map(|s| (*s).to_string()).collect());
    // MD5("a,b,c"): the comma-joined sorted set.
    assert_eq!(
        set(&["a", "b", "c"]).as_deref(),
        Some("a44c56c8177e32d3613988f4dba7962e")
    );
    assert_eq!(
        set(&["c", "a", "b", "a"]).as_deref(),
        Some("a44c56c8177e32d3613988f4dba7962e")
    );
    assert_eq!(set(&[]), None);
}
