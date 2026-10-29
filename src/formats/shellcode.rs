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
mod tests;
