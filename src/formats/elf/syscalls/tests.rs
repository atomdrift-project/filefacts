use super::*;
use crate::output::Metrics;
use binform::Value;

fn fact(addr: u64, number: u64, name: Option<&'static str>, args: Vec<Value>) -> SyscallFact {
    SyscallFact {
        addr,
        number,
        name,
        via: None,
        args,
    }
}

fn mem(bytes: &[u8]) -> Value {
    Value::Mem {
        addr: None,
        bytes: bytes.iter().map(|&b| Some(b)).collect(),
    }
}

/// The bytes kimwolf builds on the stack: `AF_INET`, port 8082 (big-endian),
/// 45.139.197.87.
const KIMWOLF_SOCKADDR: &[u8] = &[0x02, 0x00, 0x1f, 0x92, 0x2d, 0x8b, 0xc5, 0x57];

#[test]
fn site_json_carries_fields_and_trims_trailing_unknown_args() {
    // mprotect(null, null, PROT_RWX): the first two args unresolved.
    let site = fact(
        0x4a,
        10,
        Some("mprotect"),
        vec![
            Value::Unknown,
            Value::Unknown,
            Value::Int(7),
            Value::Unknown,
        ],
    );
    let json = site_json(&site);
    assert_eq!(json["name"], "mprotect");
    assert_eq!(json["number"], 10);
    assert_eq!(json["offset"], 0x4a);
    assert_eq!(json["args"], serde_json::json!([null, null, 7]));
    assert!(json.get("via").is_none());
    assert!(json.get("decoded").is_none());
}

#[test]
fn unknown_number_is_named_unknown() {
    assert_eq!(site_json(&fact(0, 9999, None, vec![]))["name"], "unknown");
}

#[test]
fn wrapper_call_carries_via() {
    let mut site = fact(0x10, 203, Some("connect"), vec![]);
    site.via = Some("syscall");
    assert_eq!(site_json(&site)["via"], "syscall");
}

#[test]
fn decodes_sockaddr_in_ip_and_port() {
    // connect(fd, &sockaddr, 16): the pointer is arg 1.
    let site = fact(
        0x80f8,
        203,
        Some("connect"),
        vec![Value::Unknown, mem(KIMWOLF_SOCKADDR), Value::Int(16)],
    );
    let decoded = &site_json(&site)["decoded"];
    assert_eq!(
        decoded,
        &serde_json::json!([{ "arg": 1, "kind": "sockaddr_in", "ip": "45.139.197.87", "port": 8082 }])
    );
}

#[test]
fn decodes_sockaddr_in6_ip_and_port() {
    // AF_INET6 (10), port 443, flowinfo 0, then the 16-byte address ::1.
    let mut sa = vec![10, 0, 0x01, 0xbb, 0, 0, 0, 0];
    sa.extend([0u8; 15]);
    sa.push(1); // ::1
    let site = fact(0x100, 203, Some("connect"), vec![Value::Unknown, mem(&sa)]);
    let decoded = &site_json(&site)["decoded"];
    assert_eq!(
        decoded,
        &serde_json::json!([{ "arg": 1, "kind": "sockaddr_in6", "ip": "::1", "port": 443 }])
    );
}

#[test]
fn a_pointer_with_an_unknown_family_byte_is_not_decoded() {
    let site = fact(0, 203, Some("connect"), vec![mem(&[0x02])]); // too short
    assert!(site_json(&site).get("decoded").is_none());
}

#[test]
fn emit_publishes_sites_with_arch_and_counts_direct() {
    let facts = vec![
        fact(0x20, 41, Some("socket"), vec![Value::Int(2)]),
        fact(
            0x30,
            203,
            Some("connect"),
            vec![Value::Unknown, mem(KIMWOLF_SOCKADDR)],
        ),
    ];
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(
        &facts,
        Some(binform::Arch::Arm),
        false,
        &mut values,
        &mut metrics,
    );

    let sites = values
        .get("elf.syscalls_direct")
        .and_then(|v| v.as_array())
        .expect("sites published");
    assert_eq!(sites.len(), 2);
    assert_eq!(
        values.get("elf.syscalls_arch").and_then(|v| v.as_str()),
        Some("arm")
    );
    assert_eq!(metrics.get("elf.direct_syscall_count"), Some(2.0));
    assert_eq!(metrics.get("elf.has_indirect_syscall"), None);
}

#[test]
fn emit_dedupes_by_offset_and_sorts() {
    let facts = vec![
        fact(0x30, 1, Some("write"), vec![]),
        fact(0x10, 2, Some("read"), vec![]),
        fact(0x30, 1, Some("write"), vec![]), // same offset as the first
    ];
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(
        &facts,
        Some(binform::Arch::X86_64),
        true,
        &mut values,
        &mut metrics,
    );

    let sites = values
        .get("elf.syscalls_direct")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(sites.len(), 2, "the repeated offset collapses");
    assert_eq!(sites[0]["offset"], 0x10);
    assert_eq!(sites[1]["offset"], 0x30);
    assert_eq!(metrics.get("elf.has_indirect_syscall"), Some(1.0));
}

#[test]
fn emit_publishes_decoded_destinations_as_network_endpoints() {
    let mut site = fact(
        0x80f8,
        203,
        Some("connect"),
        vec![Value::Unknown, mem(KIMWOLF_SOCKADDR)],
    );
    site.via = Some("connect");
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(
        &[site],
        Some(binform::Arch::Arm),
        false,
        &mut values,
        &mut metrics,
    );

    let endpoints = values
        .get("elf.network_endpoints")
        .and_then(|v| v.as_array())
        .expect("endpoints published");
    assert_eq!(
        endpoints,
        &vec![serde_json::json!({
            "kind": "sockaddr_in",
            "ip": "45.139.197.87",
            "port": 8082,
            "offset": 0x80f8,
            "syscall": "connect",
            "via": "connect",
        })]
    );
    assert_eq!(metrics.get("elf.network_endpoint_count"), Some(1.0));
}

#[test]
fn a_site_with_no_sockaddr_publishes_no_endpoints() {
    let facts = vec![fact(0x20, 41, Some("socket"), vec![Value::Int(2)])];
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(
        &facts,
        Some(binform::Arch::Arm),
        false,
        &mut values,
        &mut metrics,
    );
    assert!(values.get("elf.network_endpoints").is_none());
    assert_eq!(metrics.get("elf.network_endpoint_count"), None);
}

#[test]
fn nothing_published_without_sites() {
    let mut values = Values::default();
    let mut metrics = Metrics::default();
    emit(
        &[],
        Some(binform::Arch::X86_64),
        false,
        &mut values,
        &mut metrics,
    );
    assert!(values.get("elf.syscalls_direct").is_none());
    assert!(values.get("elf.syscalls_arch").is_none());
}
