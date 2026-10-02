//! Headerless x86 / x86-64 position-independent code.
//!
//! Raw code carved out of a loader or dropped as a stage has no magic, so
//! without this it is [`FileType::Unknown`](super::FileType::Unknown), which no
//! rule walks. Position-independent code must learn its own address before it
//! can decode or relocate itself, and the idioms that do so ("GetPC") sit at
//! the very first bytes. Three are recognised, each by a handful of byte reads:
//!
//! - **call/pop** — `E8 rel32` at offset 0 whose target, inside the file,
//!   is `pop reg`. The pushed return address is the blob's own base.
//! - **jmp/call/pop** — `EB rel8` forward onto `E8 rel32` that calls back
//!   to just past the `jmp`, where `pop reg` collects the address after the
//!   call.
//! - **FPU environment** — an x87 instruction, then `fnstenv [esp-0Ch]`
//!   (`D9 74 24 F4`), then `pop reg`: the saved FPU instruction pointer
//!   lands on the stack top.
//!
//! False-positive budget, for uniformly random bytes of length `L` (the worst
//! realistic case: ciphertext and compressed data are what reach this stage):
//!
//! - call/pop: `P(E8) · P(0 ≤ rel32 < L) · P(pop)` = `1/256 · L/2³² · ~1/32`
//!   ≈ `L / 3.5·10¹³`. A 4 MiB blob: 1.2·10⁻⁷; a 64 KiB one: 1.8·10⁻⁹.
//! - jmp/call/pop: `1/256 · 1/2 · 1/256 · ≤130/2³² · ~1/32` ≈ 10⁻¹⁵.
//! - FPU: the four-byte anchor alone is `29 / 2³²` ≈ 7·10⁻⁹ before the x87
//!   and `pop` requirements.
//!
//! Requiring a trailing `jmp reg` (common in SGN output) would buy little
//! against those odds and would miss every encoder that does not end that way,
//! so it is not required. Structured files are safer still: this runs only
//! when magic, names and text heuristics have all declined, and text cannot
//! pass the call/pop test — a UTF-8 lead `E8` is followed by continuation
//! bytes that put rel32 far past any real file size.

/// Smaller blobs are left alone: at this size a GetPC stub would have almost
/// nothing to locate, and tiny sidecar files are the likeliest chance matches.
const MIN_SIZE: usize = 32;

/// Window at the head of the file searched for the FPU idiom. Encoders put a
/// key load and a counter setup around it, never much more.
const FPU_WINDOW: usize = 32;

/// How far past `fnstenv` the `pop` may sit (a counter setup can intervene).
const FPU_POP_REACH: usize = 8;

/// `fnstenv [esp-0Ch]`.
const FNSTENV_ESP_M12: [u8; 4] = [0xD9, 0x74, 0x24, 0xF4];

/// The GetPC idiom a blob opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GetPc {
    CallPop,
    JmpCallPop,
    FpuEnv,
}

impl GetPc {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CallPop => "call_pop",
            Self::JmpCallPop => "jmp_call_pop",
            Self::FpuEnv => "fpu_env",
        }
    }
}

/// Best guess at the instruction set. A guess: 32- and 64-bit x86 share most
/// encodings, and only a REX prefix settles it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arch {
    X86,
    X86_64,
}

impl Arch {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
        }
    }
}

/// A recognised blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shellcode {
    pub(crate) getpc: GetPc,
    /// Offset of the `pop` that receives the address.
    pub(crate) pop_offset: usize,
    pub(crate) arch: Arch,
}

/// Recognise headerless x86 / x86-64 code by its opening GetPC idiom.
pub(crate) fn detect(data: &[u8]) -> Option<Shellcode> {
    if data.len() < MIN_SIZE {
        return None;
    }
    call_pop(data)
        .or_else(|| jmp_call_pop(data))
        .or_else(|| fpu_env(data))
}

/// `E8 rel32` at 0 onto an in-file `pop reg` with code after it.
fn call_pop(data: &[u8]) -> Option<Shellcode> {
    let [0xE8, ..] = data else {
        return None;
    };
    let rel = usize::try_from(rel32(data, 1)?).ok()?;
    let target = rel.checked_add(5)?;
    let rex = pop_at(data, target)?;
    Some(Shellcode {
        getpc: GetPc::CallPop,
        pop_offset: target,
        arch: arch(data, rex, &[5, target]),
    })
}

/// `EB rel8` forward onto `E8 rel32` that calls back between the two, where
/// `pop reg` sits.
fn jmp_call_pop(data: &[u8]) -> Option<Shellcode> {
    let &[0xEB, rel8, ..] = data else {
        return None;
    };
    let call = 2 + usize::try_from(rel8.cast_signed()).ok()?;
    if *data.get(call)? != 0xE8 {
        return None;
    }
    let back = usize::try_from(rel32(data, call + 1)?.checked_neg()?).ok()?;
    let target = (call + 5).checked_sub(back)?;
    if !(2..call).contains(&target) {
        return None;
    }
    let rex = pop_at(data, target)?;
    Some(Shellcode {
        getpc: GetPc::JmpCallPop,
        pop_offset: target,
        arch: arch(data, rex, &[target]),
    })
}

/// An x87 instruction, `fnstenv [esp-0Ch]`, then `pop reg`, all near the head.
/// The idiom is 32-bit: the saved instruction pointer is four bytes wide.
fn fpu_env(data: &[u8]) -> Option<Shellcode> {
    let head = data.get(..FPU_WINDOW)?;
    let env = head.windows(4).position(|w| w == FNSTENV_ESP_M12)?;
    // Register-form x87 op (escape D8–DF, ModRM ≥ C0) before the store, so
    // the FPU instruction pointer it saves is set.
    let fpu_set = head
        .get(..env)?
        .windows(2)
        .any(|w| matches!(w, &[0xD8..=0xDF, 0xC0..=0xFF]));
    if !fpu_set {
        return None;
    }
    let after = env + FNSTENV_ESP_M12.len();
    let pop = after
        + data
            .get(after..)?
            .iter()
            .take(FPU_POP_REACH)
            .position(|b| (0x58..=0x5F).contains(b))?;
    Some(Shellcode {
        getpc: GetPc::FpuEnv,
        pop_offset: pop,
        arch: Arch::X86,
    })
}

/// Little-endian signed 32-bit displacement at `at`.
fn rel32(data: &[u8], at: usize) -> Option<i32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
}

/// `pop reg` at `at` with at least one byte of code after it. Returns whether
/// it carried a REX prefix (`41 58`–`41 5F`, `pop r8`–`pop r15`), which only
/// 64-bit code can mean.
fn pop_at(data: &[u8], at: usize) -> Option<bool> {
    let is_pop = |b: &u8| (0x58..=0x5F).contains(b);
    let (rex, len) = match data.get(at..)? {
        [0x41, b, ..] if is_pop(b) => (true, 2),
        [b, ..] if is_pop(b) => (false, 1),
        _ => return None,
    };
    (at + len < data.len()).then_some(rex)
}

/// 64-bit when the `pop` is REX-prefixed, or when a REX.W instruction opens
/// the code at any of `starts`, decoded a few instructions in 64-bit mode.
/// In 64-bit mode `48`–`4F` can only be a REX.W prefix; 32-bit code rarely
/// opens an instruction with `dec` on those registers.
fn arch(data: &[u8], pop_rex: bool, starts: &[usize]) -> Arch {
    use iced_x86::{Decoder, DecoderOptions};
    const INSTRUCTIONS: usize = 8;
    const REACH: usize = 64;
    let rex_w = |start: usize| {
        let code = data.get(start..).unwrap_or_default();
        let code = code.get(..REACH).unwrap_or(code);
        Decoder::new(64, code, DecoderOptions::NONE)
            .iter()
            .take(INSTRUCTIONS)
            .take_while(|ins| !ins.is_invalid())
            .any(|ins| {
                code.get(crate::bytes::sat_usize(ins.ip()))
                    .is_some_and(|b| (0x48..=0x4F).contains(b))
            })
    };
    if pop_rex || starts.iter().any(|&s| rex_w(s)) {
        Arch::X86_64
    } else {
        Arch::X86
    }
}

#[cfg(test)]
mod tests {
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
}
