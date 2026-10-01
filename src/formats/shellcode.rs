//! Headerless x86 / x86-64 shellcode facts.
//!
//! Identification already found the GetPC idiom (see `fileid::shellcode`);
//! this records what it found:
//!
//! - value `shellcode.getpc` — `call_pop`, `jmp_call_pop` or `fpu_env`.
//! - value `shellcode.arch` — `x86` or `x86_64`, a guess from REX prefixes.
//! - metric `shellcode.getpc_offset` — offset of the `pop` that receives the
//!   code's own address.
//!
//! Strings, entropy and the rest come from the shared generic pass.

use crate::fileid::shellcode;
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

pub(super) fn extract(bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(sc) = shellcode::detect(bytes) else {
        return;
    };
    values.insert_key(
        value_key!("shellcode.getpc"),
        serde_json::json!(sc.getpc.label()),
    );
    values.insert_key(
        value_key!("shellcode.arch"),
        serde_json::json!(sc.arch.label()),
    );
    metrics.insert(metric!("shellcode.getpc_offset"), sc.pop_offset as f64);
}

#[cfg(test)]
mod tests {
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
}
