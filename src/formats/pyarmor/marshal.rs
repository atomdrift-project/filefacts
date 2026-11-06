//! Bounded marshal normalization for PyArmor analysis snapshots: the
//! metadata PyArmor appends to a code object is removed, its flag cleared,
//! and the instruction regions it describes decrypted, over the shared
//! [`marshal`] walk.
use super::{RecoveredPyc, ctr};
use crate::formats::marshal::{self, CodeObject, Value, Walker};
use std::ops::Range;

/// Instruction bytes decrypted and rewritten across one marshal stream.
const MAX_EDITED_BYTES: usize = 16 << 20;
/// The `co_flags` bit PyArmor sets on a code object it appended metadata to.
const PYARMOR_FLAG: u32 = 0x2000_0000;

/// What normalizing one stream found and changed.
struct Normalizer<'a> {
    minor: u8,
    key: &'a [u8; 16],
    edits: Vec<(Range<usize>, Vec<u8>)>,
    code_objects: usize,
    edited_bytes: usize,
    decrypted_regions: usize,
    limitations: Vec<&'static str>,
}

impl Normalizer<'_> {
    /// Strip the metadata PyArmor appended after one code object's fields,
    /// clear its flag and decrypt the instruction regions it describes.
    fn code(
        &mut self,
        walker: &mut Walker<'_>,
        data: &[u8],
        code: &CodeObject,
    ) -> Result<(), &'static str> {
        self.code_objects += 1;
        if code.flags & PYARMOR_FLAG == 0 {
            return Ok(());
        }
        let trailer_start = walker.pos();
        let length = usize::from(walker.byte()?);
        let extra = walker.take(length)?;
        if extra.len() < 4 {
            return Err("truncated PyArmor code metadata");
        }
        let metadata = *extra.first().ok_or("missing metadata flags")?;
        let functions = metadata & 3;
        let descriptors = (metadata >> 2) & 3;
        if metadata & 0x10 != 0 {
            self.limitations
                .push("native/BCC code requires native analysis");
        }
        let mut position = 4usize;
        for _ in 0..functions {
            let size =
                usize::from(*extra.get(position).ok_or("truncated function metadata")? >> 6) + 2;
            position = position.checked_add(size).ok_or("metadata overflow")?;
            if position > extra.len() {
                return Err("invalid function metadata span");
            }
        }
        let range = walker.bytes(code.code)?;
        self.edited_bytes = self
            .edited_bytes
            .checked_add(range.len())
            .ok_or("edit size overflow")?;
        if self.edited_bytes > MAX_EDITED_BYTES {
            return Err("instruction edit budget exceeded");
        }
        let mut instructions = data
            .get(range.clone())
            .ok_or("invalid instruction span")?
            .to_vec();
        for _ in 0..descriptors {
            let size =
                usize::from(*extra.get(position).ok_or("truncated descriptor metadata")? >> 6) + 2;
            let end = position.checked_add(size).ok_or("descriptor overflow")?;
            let item = extra
                .get(position + 1..end)
                .ok_or("invalid descriptor metadata span")?;
            let mut index = 0usize;
            for byte in item {
                index = index
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(usize::from(*byte)))
                    .ok_or("descriptor index overflow")?;
            }
            let Some(Value::Sequence(items)) = walker.values.get(code.constants) else {
                return Err("missing constants");
            };
            let node = *items
                .get(index)
                .ok_or("descriptor constant out of bounds")?;
            let descriptor = data
                .get(walker.bytes(node)?)
                .ok_or("invalid descriptor span")?;
            if self.decrypt(&mut instructions, descriptor)? {
                self.decrypted_regions += 1;
            }
            position = end;
        }
        if descriptors != 0 {
            self.edits.push((range, instructions));
        }
        self.edits.push((
            code.flags_at..code.flags_at + 4,
            (code.flags & !PYARMOR_FLAG).to_le_bytes().to_vec(),
        ));
        self.edits.push((trailer_start..walker.pos(), Vec::new()));
        Ok(())
    }

    fn decrypt(&mut self, code: &mut [u8], descriptor: &[u8]) -> Result<bool, &'static str> {
        let flags = *descriptor.get(8).ok_or("short PyArmor code descriptor")?;
        let short_nonce = usize::from(*descriptor.get(9).ok_or("short code descriptor")?);
        let begin = usize::from(*descriptor.get(11).ok_or("short code descriptor")?);
        let length = crate::bytes::sat_usize(
            crate::bytes::u32_le(descriptor, 12).ok_or("short code descriptor")?,
        );
        if descriptor.len() < 20 {
            return Err("short code descriptor");
        }
        let end = begin
            .checked_add(length)
            .ok_or("instruction range overflow")?;
        let nonce_at = if flags & 2 != 0 {
            short_nonce
        } else {
            end.checked_add(short_nonce).ok_or("nonce range overflow")?
        };
        let nonce_end = nonce_at.checked_add(12).ok_or("nonce overflow")?;
        let nonce: [u8; 12] = code
            .get(nonce_at..nonce_end)
            .ok_or("nonce outside instructions")?
            .try_into()
            .map_err(|_| "invalid nonce")?;
        if code.get(begin..end).is_none() {
            return Err("encrypted region outside instructions");
        }
        if flags & 4 != 0 {
            self.limitations
                .push("instruction nonce-XOR protection remains encrypted");
            return Ok(false);
        }
        let region = code.get_mut(begin..end).ok_or("invalid encrypted region")?;
        let decrypted = ctr(region, self.key, &nonce).ok_or("instruction cipher failed")?;
        region.copy_from_slice(&decrypted);
        if flags & 8 != 0 {
            let tail = length.checked_add(begin).ok_or("prologue overflow")?;
            if tail > code.len() {
                return Err("prologue outside instructions");
            }
            code.copy_within(length..tail, 0);
            // Preserve wordcode offsets, using each version's NOP opcode.
            let nop = match self.minor {
                13 => 30,
                14 => 27,
                _ => 9,
            };
            for pair in code
                .get_mut(length..tail)
                .ok_or("invalid prologue span")?
                .chunks_mut(2)
            {
                if let Some(opcode) = pair.first_mut() {
                    *opcode = nop;
                }
                if let Some(argument) = pair.get_mut(1) {
                    *argument = 0;
                }
            }
        }
        Ok(true)
    }
}

pub(super) fn normalize(
    body: &[u8],
    minor: u8,
    key: &[u8; 16],
) -> Result<RecoveredPyc, &'static str> {
    let mut normalizer = Normalizer {
        minor,
        key,
        edits: Vec::new(),
        code_objects: 0,
        edited_bytes: 0,
        decrypted_regions: 0,
        limitations: Vec::new(),
    };
    let walker = marshal::walk(body, minor, |walker, code| {
        normalizer.code(walker, body, code)
    })?;
    if walker.values.iter().any(|value| {
        matches!(value, Value::Bytes(range)
            if body.get(range.start).is_some_and(|b| matches!(b, 0x81..=0x84)))
    }) {
        normalizer
            .limitations
            .push("possible mixed-string protection requires further decoding");
    }
    let Normalizer {
        mut edits,
        code_objects,
        decrypted_regions,
        mut limitations,
        ..
    } = normalizer;
    edits.sort_by_key(|(range, _)| range.start);
    let mut data = Vec::with_capacity(body.len());
    let mut end = 0;
    for (range, replacement) in edits {
        if range.start < end {
            return Err("overlapping code-object edits");
        }
        data.extend_from_slice(body.get(end..range.start).ok_or("invalid edit gap")?);
        data.extend_from_slice(&replacement);
        end = range.end;
    }
    data.extend_from_slice(body.get(end..).ok_or("invalid edit tail")?);
    limitations.sort_unstable();
    limitations.dedup();
    Ok(RecoveredPyc {
        data,
        code_objects,
        decrypted_regions,
        limitations,
    })
}
