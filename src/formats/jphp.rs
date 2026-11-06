//! Bounded framing of the Java class files stored in a JPHP compiled module.
use crate::bytes::Reader;

/// Take one table entry from `steps`; `None` once none are left.
fn step(steps: &mut usize) -> Option<()> {
    *steps = steps.checked_sub(1)?;
    Some(())
}

/// The length of the class file at the start of `data`, spending one of
/// `steps` per constant, field and attribute read.
fn class_len(data: &[u8], steps: &mut usize) -> Option<usize> {
    let mut r = Reader::new(data);
    if r.u32_be()? != 0xcafebabe {
        return None;
    }
    r.skip(2)?;
    if r.u16_be()? < 45 {
        return None;
    }
    let count = r.u16_be()?;
    if count < 2 {
        return None;
    }
    let mut slot = 1;
    while slot < count {
        step(steps)?;
        match r.u8()? {
            1 => {
                let len = r.u16_be()?;
                r.skip(usize::from(len))?;
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => r.skip(4)?,
            5 | 6 => {
                r.skip(8)?;
                slot += 1;
                if slot >= count {
                    return None;
                }
            }
            7 | 8 | 16 | 19 | 20 => r.skip(2)?,
            15 => r.skip(3)?,
            _ => return None,
        }
        slot += 1;
    }
    r.skip(6)?;
    let interfaces = r.u16_be()?;
    r.skip(usize::from(interfaces).checked_mul(2)?)?;
    fn attributes(r: &mut Reader<'_>, steps: &mut usize) -> Option<()> {
        for _ in 0..r.u16_be()? {
            step(steps)?;
            r.skip(2)?;
            let len = usize::try_from(r.u32_be()?).ok()?;
            r.skip(len)?;
        }
        Some(())
    }
    for _ in 0..2 {
        // fields, then methods
        for _ in 0..r.u16_be()? {
            step(steps)?;
            r.skip(6)?;
            attributes(&mut r, steps)?;
        }
    }
    attributes(&mut r, steps)?;
    Some(r.pos())
}

/// Return non-overlapping, structurally framed classes in a compiled JPHP
/// module. No bytecode runs. Only the JPHP module magic admits a carrier;
/// embedded class attributes are skipped by length rather than magic-scanned.
/// The caller retains the original module as well as any decoded children.
pub fn class_frames(data: &[u8]) -> (Vec<(usize, usize)>, bool) {
    if !data.starts_with(&[0x1c, 0x9a, 0x4a, 0x92]) {
        return (Vec::new(), false);
    }
    let original_len = data.len();
    let data = data
        .get(..data.len().min(64 * 1024 * 1024))
        .unwrap_or_default();
    let mut frames = Vec::new();
    // Entries every candidate together may read. An honest class spends at
    // least three bytes on each, so a module's real classes never run out;
    // without the shared budget, a thousand candidates whose tables all run
    // into one long tail of fields each re-read the whole tail.
    let mut steps = data.len();
    let mut attempts = 0;
    let mut malformed = false;
    let mut offset = 4;
    while offset + 4 <= data.len() && frames.len() < 256 && attempts < 1024 {
        attempts += 1;
        let Some(relative) = data
            .get(offset..)
            .unwrap_or_default()
            .windows(4)
            .position(|b| b == [0xca, 0xfe, 0xba, 0xbe])
        else {
            break;
        };
        offset += relative;
        if let Some(len) = class_len(data.get(offset..).unwrap_or_default(), &mut steps) {
            frames.push((offset, len));
            offset += len;
        } else {
            malformed = true;
            if steps == 0 {
                tracing::debug!(target: "filefacts::jphp", stage = "class-frames", offset, "class table budget spent; later candidates not framed");
                break;
            }
            offset += 4;
        }
    }
    let incomplete = malformed
        || original_len > data.len()
        || ((frames.len() == 256 || attempts == 1024) && offset < data.len());
    (frames, incomplete)
}

#[cfg(test)]
mod tests;
