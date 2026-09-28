//! Narrow decoders for compact DOS COM XOR stubs.

const COM_LOAD_BASE: u16 = 0x100;
const STUB_WINDOW: usize = 32;
pub(super) const DOS_COM_MAX_SIZE: usize = 0xFF00;

/// One decoded byte range from a DOS COM fixed-key XOR decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDosComPayload {
    /// Bytes recovered from the encrypted COM body.
    pub bytes: Vec<u8>,
    /// Offset of the encrypted body in the original COM file.
    pub source_offset: usize,
    /// Fixed XOR key used by the decoder.
    pub xor_key: u8,
    /// Instruction offset of the decoder stub in the original COM file.
    pub stub_offset: usize,
    /// Decoder family used to recover this range.
    pub method: DosComXorMethod,
}

/// Recognized fixed-key DOS COM XOR decoder loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosComXorMethod {
    /// MOV AH,[SI]; XOR AH,imm8; MOV [SI],AH; INC SI; LOOP.
    InPlaceSi,
    /// LODSB; XOR AL,[absolute key]; STOSB; LOOP, with SI == DI.
    CopySiDi,
}

#[derive(Debug, Clone, Copy)]
enum Plan {
    InPlaceSi {
        stub_offset: usize,
        source_offset: usize,
        length: usize,
        key: u8,
    },
    CopySiDi {
        stub_offset: usize,
        source_offset: usize,
        length: usize,
        key_offset: usize,
    },
}

/// Recover a body described by a supported fixed-key DOS COM decoder stub.
///
/// This is deliberately limited to two short, instruction-shaped 8086 loops
/// and to bodies wholly contained in one COM image. It does not brute-force
/// arbitrary files or guess a key from ciphertext.
#[must_use]
pub fn decode_dos_com_xor_payload(data: &[u8]) -> Option<DecodedDosComPayload> {
    let plan = decoder_plan(data)?;
    match plan {
        Plan::InPlaceSi {
            stub_offset,
            source_offset,
            length,
            key,
        } => {
            let bytes = data[source_offset..source_offset + length]
                .iter()
                .map(|byte| byte ^ key)
                .collect();
            Some(DecodedDosComPayload {
                bytes,
                source_offset,
                xor_key: key,
                stub_offset,
                method: DosComXorMethod::InPlaceSi,
            })
        }
        Plan::CopySiDi {
            stub_offset,
            source_offset,
            length,
            key_offset,
        } => {
            let key = data[key_offset];
            let bytes = data[source_offset..source_offset + length]
                .iter()
                .map(|byte| byte ^ key)
                .collect();
            Some(DecodedDosComPayload {
                bytes,
                source_offset,
                xor_key: key,
                stub_offset,
                method: DosComXorMethod::CopySiDi,
            })
        }
    }
}

/// The type detector and payload decoder share the same narrow signatures.
pub(super) fn looks_like_xor_stub(data: &[u8]) -> bool {
    decoder_plan(data).is_some()
}

fn decoder_plan(data: &[u8]) -> Option<Plan> {
    if !(16..=DOS_COM_MAX_SIZE).contains(&data.len()) {
        return None;
    }
    let head = &data[..data.len().min(STUB_WINDOW)];

    for (stub_offset, window) in head.windows(16).enumerate() {
        // MOV CX,length; MOV SI,offset; MOV AH,[SI]; XOR AH,imm8;
        // MOV [SI],AH; INC SI; LOOP rel8.
        if window[0] == 0xB9
            && window[3] == 0xBE
            && window[6..10] == [0x8A, 0x24, 0x80, 0xF4]
            && window[11..15] == [0x88, 0x24, 0x46, 0xE2]
        {
            let length = u16::from_le_bytes([window[1], window[2]]) as usize;
            let source = u16::from_le_bytes([window[4], window[5]]);
            let source_offset = usize::from(source.checked_sub(COM_LOAD_BASE)?);
            if valid_range(data, source_offset, length) {
                return Some(Plan::InPlaceSi {
                    stub_offset,
                    source_offset,
                    length,
                    key: window[10],
                });
            }
        }

        // MOV SI,offset; MOV DI,SI; MOV CX,length; LODSB;
        // XOR AL,[absolute key]; STOSB; LOOP rel8.
        if window[0] == 0xBE
            && window[3..5] == [0x8B, 0xFE]
            && window[5] == 0xB9
            && window[8..11] == [0xAC, 0x32, 0x06]
            && window[13..15] == [0xAA, 0xE2]
        {
            let source = u16::from_le_bytes([window[1], window[2]]);
            let source_offset = usize::from(source.checked_sub(COM_LOAD_BASE)?);
            let length = u16::from_le_bytes([window[6], window[7]]) as usize;
            let key_address = u16::from_le_bytes([window[11], window[12]]);
            let key_offset = usize::from(key_address.checked_sub(COM_LOAD_BASE)?);
            if valid_range(data, source_offset, length)
                && key_offset < data.len()
                && !(source_offset..source_offset + length).contains(&key_offset)
            {
                return Some(Plan::CopySiDi {
                    stub_offset,
                    source_offset,
                    length,
                    key_offset,
                });
            }
        }
    }
    None
}

fn valid_range(data: &[u8], start: usize, length: usize) -> bool {
    length >= 32
        && start
            .checked_add(length)
            .is_some_and(|end| end <= data.len())
}
