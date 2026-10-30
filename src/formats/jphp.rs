//! Bounded framing of the Java class files stored in a JPHP compiled module.
use crate::bytes::Reader;

fn class_len(data: &[u8]) -> Option<usize> {
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
    fn attributes(r: &mut Reader<'_>) -> Option<()> {
        for _ in 0..r.u16_be()? {
            r.skip(2)?;
            let len = usize::try_from(r.u32_be()?).ok()?;
            r.skip(len)?;
        }
        Some(())
    }
    for _ in 0..2 {
        // fields, then methods
        for _ in 0..r.u16_be()? {
            r.skip(6)?;
            attributes(&mut r)?;
        }
    }
    attributes(&mut r)?;
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
        if let Some(len) = class_len(data.get(offset..).unwrap_or_default()) {
            frames.push((offset, len));
            offset += len;
        } else {
            malformed = true;
            offset += 4;
        }
    }
    let incomplete = malformed
        || original_len > data.len()
        || ((frames.len() == 256 || attempts == 1024) && offset < data.len());
    (frames, incomplete)
}

#[cfg(test)]
mod tests {
    use super::class_frames;
    fn class() -> Vec<u8> {
        let mut b = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 5];
        for (tag, bytes) in [
            (1u8, b"\0\x07Example".as_slice()),
            (7, b"\0\x01"),
            (1, b"\0\x10java/lang/Object"),
            (7, b"\0\x03"),
        ] {
            b.push(tag);
            b.extend_from_slice(bytes);
        }
        b.extend_from_slice(&[0, 0x21, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        b
    }
    #[test]
    fn skips_magic_in_attributes_and_reports_resource_limits() {
        let c = class();
        let mut outer = c.clone();
        let n = outer.len();
        outer[n - 1] = 1; // one class-level attribute
        outer.extend_from_slice(&[0, 1]);
        outer.extend_from_slice(&(c.len() as u32).to_be_bytes());
        outer.extend_from_slice(&c);
        let mut carrier = vec![0x1c, 0x9a, 0x4a, 0x92];
        carrier.extend_from_slice(&outer);
        assert_eq!(class_frames(&carrier), (vec![(4, outer.len())], false));
        let mut many = vec![0x1c, 0x9a, 0x4a, 0x92];
        for _ in 0..257 {
            many.extend_from_slice(&c);
        }
        let (frames, incomplete) = class_frames(&many);
        assert_eq!(frames.len(), 256);
        assert!(incomplete);
    }
    #[test]
    fn frames_multiple_classes_and_ignores_truncated_candidates() {
        let c = class();
        let mut carrier = vec![0x1c, 0x9a, 0x4a, 0x92, 0, 0, 0];
        let first = carrier.len();
        carrier.extend_from_slice(&c);
        carrier.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0]);
        let second = carrier.len();
        carrier.extend_from_slice(&c);
        assert_eq!(
            class_frames(&carrier),
            (vec![(first, c.len()), (second, c.len())], true)
        );
        assert!(class_frames(&c).0.is_empty());
        carrier.truncate(first + c.len() - 1);
        assert!(class_frames(&carrier).0.is_empty());
    }
}
