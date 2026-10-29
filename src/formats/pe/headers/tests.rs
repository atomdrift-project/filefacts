use super::*;

#[test]
fn machine_string_known_values() {
    assert_eq!(machine_string(0x8664), "x86_64");
    assert_eq!(machine_string(0x014c), "i386");
    assert_eq!(machine_string(0xaa64), "arm64");
    assert_eq!(machine_string(0xffff), "unknown");
}

#[test]
fn dll_characteristics_bit_decomposition() {
    // dynamic_base | nx_compat | high_entropy_va
    let flags = 0x0040 | 0x0100 | 0x0020;
    let chars = dll_characteristics(flags);
    assert!(chars.contains(&"dynamic_base"));
    assert!(chars.contains(&"nx_compat"));
    assert!(chars.contains(&"high_entropy_va"));
}

#[test]
fn subsystem_string_known_values() {
    assert_eq!(subsystem_string(2), "windows_gui");
    assert_eq!(subsystem_string(3), "windows_cui");
    assert_eq!(subsystem_string(1), "native");
}

#[test]
fn dll_characteristics_empty_when_zero() {
    let chars = dll_characteristics(0);
    assert!(chars.is_empty());
}

#[test]
fn dll_characteristics_picks_up_force_integrity_and_aslr() {
    // force_integrity (0x80) | dynamic_base (0x40) | guard_cf (0x4000)
    let chars = dll_characteristics(0x80 | 0x40 | 0x4000);
    assert!(chars.contains(&"force_integrity"));
    assert!(chars.contains(&"dynamic_base"));
    assert!(chars.contains(&"guard_cf"));
}

#[test]
fn subsystem_string_unknown_fallback() {
    assert_eq!(subsystem_string(99), "unknown");
}
