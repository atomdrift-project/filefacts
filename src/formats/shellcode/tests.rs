use super::*;

#[test]
fn records_getpc_facts() {
    let mut bytes = vec![0x90u8; 64];
    bytes[..6].copy_from_slice(&[0xE8, 0, 0, 0, 0, 0x5B]);
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    extract(&bytes, &mut values, &mut metrics);
    assert_eq!(
        values.get("shellcode.getpc"),
        Some(&serde_json::json!("call_pop"))
    );
    assert_eq!(
        values.get("shellcode.arch"),
        Some(&serde_json::json!("x86"))
    );
    assert_eq!(metrics.get("shellcode.getpc_offset"), Some(5.0));
}

#[test]
fn silent_without_getpc() {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    extract(&[0u8; 64], &mut values, &mut metrics);
    assert!(values.get("shellcode.getpc").is_none());
}
