use super::*;

/// `head` followed by NOP padding to `len` bytes.
fn blob(head: &[u8], len: usize) -> Vec<u8> {
    let mut v = head.to_vec();
    v.resize(len, 0x90);
    v
}

#[test]
fn call_pop_next_instruction() {
    // call $+5; pop eax
    let sc = detect(&blob(&[0xE8, 0, 0, 0, 0, 0x58], 64)).expect("call/pop");
    assert_eq!(sc.getpc, GetPc::CallPop);
    assert_eq!(sc.pop_offset, 5);
    assert_eq!(sc.arch, Arch::X86);
}

#[test]
fn call_pop_far_target_rex_pop_is_x86_64() {
    let mut data = blob(&[0xE8, 0x2B, 0, 0, 0], 64);
    data[0x30] = 0x41; // pop r10
    data[0x31] = 0x5A;
    let sc = detect(&data).expect("call/pop");
    assert_eq!(sc.pop_offset, 0x30);
    assert_eq!(sc.arch, Arch::X86_64);
}

#[test]
fn call_pop_rex_w_body_is_x86_64() {
    // call → pop rdx; body at 5 opens with `not rax` (48 F7 D0).
    let mut data = blob(&[0xE8, 0x2B, 0, 0, 0, 0x48, 0xF7, 0xD0], 64);
    data[0x30] = 0x5A;
    assert_eq!(detect(&data).expect("call/pop").arch, Arch::X86_64);
}

#[test]
fn call_pop_rejects_bad_targets() {
    // Target is not a pop.
    assert_eq!(detect(&blob(&[0xE8, 0, 0, 0, 0, 0x90], 64)), None);
    // Target past end of file.
    let mut data = blob(&[0xE8, 0x40, 0, 0, 0], 64);
    data[63] = 0x58;
    assert_eq!(detect(&data), None);
    // Pop is the last byte: nothing follows it.
    let mut data = blob(&[0xE8, 0x3A, 0, 0, 0], 64);
    data[63] = 0x58;
    assert_eq!(detect(&data), None);
    // Backward call from offset 0 leaves the file.
    assert_eq!(detect(&blob(&[0xE8, 0xF0, 0xFF, 0xFF, 0xFF], 64)), None);
}

#[test]
fn jmp_call_pop() {
    // jmp +0x10 → call back to offset 2, where pop esi sits.
    let mut data = blob(&[0xEB, 0x10, 0x5E], 64);
    let call = 0x12;
    data[call] = 0xE8;
    let back = -((call + 5 - 2) as i32);
    data[call + 1..call + 5].copy_from_slice(&back.to_le_bytes());
    let sc = detect(&data).expect("jmp/call/pop");
    assert_eq!(sc.getpc, GetPc::JmpCallPop);
    assert_eq!(sc.pop_offset, 2);
}

#[test]
fn jmp_call_pop_rejects_mismatches() {
    let mut data = blob(&[0xEB, 0x10, 0x5E], 64);
    data[0x12] = 0xE8;
    // Forward call instead of back.
    data[0x13..0x17].copy_from_slice(&4i32.to_le_bytes());
    assert_eq!(detect(&data), None);
    // Backward call past the jmp.
    data[0x13..0x17].copy_from_slice(&(-0x20i32).to_le_bytes());
    assert_eq!(detect(&data), None);
    // Backward jmp.
    assert_eq!(detect(&blob(&[0xEB, 0xFE, 0x5E], 64)), None);
}

#[test]
fn fpu_env() {
    // fcmovbe st,st1; mov edx,imm32; fnstenv [esp-0Ch]; pop esi
    let head = [0xDA, 0xC1, 0xBA, 1, 2, 3, 4, 0xD9, 0x74, 0x24, 0xF4, 0x5E];
    let sc = detect(&blob(&head, 64)).expect("fpu");
    assert_eq!(sc.getpc, GetPc::FpuEnv);
    assert_eq!(sc.pop_offset, 11);
    assert_eq!(sc.arch, Arch::X86);
}

#[test]
fn fpu_env_needs_x87_op_and_pop() {
    // No preceding x87 instruction.
    let head = [0xBA, 1, 2, 3, 4, 0xD9, 0x74, 0x24, 0xF4, 0x5E];
    assert_eq!(detect(&blob(&head, 64)), None);
    // No pop within reach.
    let head = [0xDA, 0xC1, 0xD9, 0x74, 0x24, 0xF4];
    assert_eq!(detect(&blob(&head, 64)), None);
}

#[test]
fn too_small() {
    assert_eq!(detect(&blob(&[0xE8, 0, 0, 0, 0, 0x58], MIN_SIZE - 1)), None);
    assert!(detect(&blob(&[0xE8, 0, 0, 0, 0, 0x58], MIN_SIZE)).is_some());
}

#[test]
fn utf8_text_is_not_call_pop() {
    // A CJK character's E8 lead is followed by continuation bytes.
    let text = "译文译文译文译文译文译文译文译文译文译文".as_bytes();
    assert_eq!(detect(text), None);
}
