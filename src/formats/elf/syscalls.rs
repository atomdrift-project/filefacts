//! ELF syscall inventory, projected from binform's call sites.
//!
//! binform walks each recovered function tracking register and stack values,
//! so a raw `syscall`/`svc` instruction yields its number and arguments even
//! when the number is built across several instructions or an earlier block,
//! where a scan of a fixed window before the instruction finds none. A libc
//! `syscall(number, …)` call with a constant number comes through as a site
//! with `via = "syscall"`.
//!
//! This module turns those facts into the `elf.syscalls_direct` value: a file
//! offset and the constant arguments at each site, with pointer arguments that
//! hold a `sockaddr` decoded into an IP and port. Trait rules supply the
//! behavioral meaning; the number-to-name table lives in binform
//! (`binform::Binary::syscall`), keyed by architecture.

use serde_json::Value as JsonValue;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::functions::SyscallFact;
use crate::output::{Metrics, Values};
use crate::{metric, value_key};

/// Cap on emitted sites per binary; binform already bounds its walk.
const MAX_SITES: usize = 4096;

/// `AF_INET` and `AF_INET6`, the address families filefacts decodes.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Emit the syscall inventory from binform's facts. `indirect` says the binary
/// imports the libc `syscall()` wrapper (it may issue runtime-numbered calls).
pub(super) fn emit(
    facts: &[SyscallFact],
    arch: Option<binform::Arch>,
    indirect: bool,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    // A syscall address can be walked from more than one overlapping function;
    // keep one record per offset, in address order.
    let mut unique: Vec<&SyscallFact> = Vec::new();
    for fact in facts {
        match unique.binary_search_by_key(&fact.addr, |f| f.addr) {
            Ok(_) => {}
            Err(index) => unique.insert(index, fact),
        }
        if unique.len() >= MAX_SITES {
            break;
        }
    }

    if !unique.is_empty() {
        let direct = unique.iter().filter(|f| f.via.is_none()).count();
        let arr = unique.iter().map(|f| site_json(f)).collect();
        values.insert_key(value_key!("elf.syscalls_direct"), JsonValue::Array(arr));
        if let Some(label) = arch.and_then(arch_label) {
            values.insert_key(value_key!("elf.syscalls_arch"), label.into());
        }
        if direct > 0 {
            metrics.insert(metric!("elf.direct_syscall_count"), direct as f64);
        }
        let endpoints = endpoints(&unique);
        if !endpoints.is_empty() {
            let count = endpoints.len();
            values.insert_key(
                value_key!("elf.network_endpoints"),
                JsonValue::Array(endpoints),
            );
            metrics.insert(metric!("elf.network_endpoint_count"), count as f64);
        }
    }
    if indirect {
        metrics.insert(metric!("elf.has_indirect_syscall"), 1.0);
    }
}

/// The network destinations the binary builds: every `sockaddr` a `connect`
/// (or any syscall carrying one) points at, decoded to an IP and port. This
/// is the IOC a consumer matches on; `offset` ties it back to the call site
/// and `via` says whether it came from a libc wrapper.
fn endpoints(facts: &[&SyscallFact]) -> Vec<JsonValue> {
    let mut out = Vec::new();
    for fact in facts {
        for arg in &fact.args {
            let Some(JsonValue::Object(mut decoded)) = decode_sockaddr(0, arg) else {
                continue;
            };
            decoded.remove("arg");
            decoded.insert("offset".into(), fact.addr.into());
            decoded.insert("syscall".into(), fact.name.unwrap_or("unknown").into());
            if let Some(via) = fact.via {
                decoded.insert("via".into(), via.into());
            }
            out.push(JsonValue::Object(decoded));
        }
    }
    out
}

/// The label for the syscall table a number was resolved against.
fn arch_label(arch: binform::Arch) -> Option<&'static str> {
    Some(match arch {
        binform::Arch::X86_64 => "x86_64",
        binform::Arch::X86 => "x86",
        binform::Arch::Arm64 => "aarch64",
        binform::Arch::Arm => "arm",
        _ => return None,
    })
}

/// `{ "name", "number", "offset", "args": [<u64|null>, …] }`, plus `"via"` for
/// a libc-wrapper call and `"decoded"` for a `sockaddr` argument. Consumers
/// index `args` positionally (arg 0 = the first syscall argument), read
/// `number` against `elf.syscalls_arch`, and treat `offset` as a file offset.
fn site_json(fact: &SyscallFact) -> JsonValue {
    // Each argument's integer: a constant, or the fixed address a pointer
    // holds (its bytes ride in `decoded`). A stack pointer has no address,
    // so it is null.
    let ints: Vec<Option<u64>> = fact
        .args
        .iter()
        .map(|value| match value {
            binform::Value::Int(n) => Some(*n),
            binform::Value::Mem { addr, .. } => *addr,
            _ => None,
        })
        .collect();
    let end = ints.iter().rposition(Option::is_some).map_or(0, |i| i + 1);
    let args: Vec<JsonValue> = ints
        .iter()
        .take(end)
        .map(|a| a.map_or(JsonValue::Null, JsonValue::from))
        .collect();
    let mut record = serde_json::json!({
        "name": fact.name.unwrap_or("unknown"),
        "number": fact.number,
        "offset": fact.addr,
        "args": args,
    });
    let Some(object) = record.as_object_mut() else {
        return record;
    };
    if let Some(via) = fact.via {
        object.insert("via".into(), via.into());
    }
    let decoded: Vec<JsonValue> = fact
        .args
        .iter()
        .enumerate()
        .filter_map(|(i, arg)| decode_sockaddr(i, arg))
        .collect();
    if !decoded.is_empty() {
        object.insert("decoded".into(), JsonValue::Array(decoded));
    }
    record
}

/// Decode a `sockaddr_in` or `sockaddr_in6` behind a pointer argument into
/// `{ "arg", "kind", "ip", "port" }`.
fn decode_sockaddr(index: usize, value: &binform::Value) -> Option<JsonValue> {
    let binform::Value::Mem { bytes, .. } = value else {
        return None;
    };
    // The family is a 16-bit host-order field; only its low byte varies here.
    let family = byte(bytes, 0)?;
    if byte(bytes, 1)? != 0 {
        return None;
    }
    // The port is network (big-endian) order in both structures.
    let port = u16::from_be_bytes([byte(bytes, 2)?, byte(bytes, 3)?]);
    let (kind, ip) = match family {
        AF_INET => {
            let octets = [
                byte(bytes, 4)?,
                byte(bytes, 5)?,
                byte(bytes, 6)?,
                byte(bytes, 7)?,
            ];
            ("sockaddr_in", Ipv4Addr::from(octets).to_string())
        }
        AF_INET6 => {
            // The address is bytes 8..24, after the 4-byte flowinfo.
            let mut octets = [0u8; 16];
            for (i, slot) in octets.iter_mut().enumerate() {
                *slot = byte(bytes, 8 + i)?;
            }
            ("sockaddr_in6", Ipv6Addr::from(octets).to_string())
        }
        _ => return None,
    };
    Some(serde_json::json!({
        "arg": index,
        "kind": kind,
        "ip": ip,
        "port": port,
    }))
}

/// A known byte of a pointer's contents; `None` if past the end or unknown.
fn byte(bytes: &[Option<u8>], index: usize) -> Option<u8> {
    bytes.get(index).copied().flatten()
}

#[cfg(test)]
mod tests;
