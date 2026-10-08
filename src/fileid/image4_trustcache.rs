//! Bounded Image4 trca payload carrying a version-2 trust-cache table.
//! This reports declarations, never signature validity or executable trust.

pub(crate) struct Parsed<'a> {
    pub(crate) description: &'a str,
    pub(crate) uuid: &'a [u8],
    pub(crate) entries: &'a [u8],
}

fn element<'a>(input: &mut &'a [u8], expected: u8) -> Option<&'a [u8]> {
    if input.first().copied()? != expected {
        return None;
    }
    *input = input.get(1..)?;
    let first = *input.first()?;
    *input = input.get(1..)?;
    let size = if first & 128 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        if !(1..=4).contains(&count) || input.first().copied()? == 0 {
            return None;
        }
        let mut size = 0usize;
        for byte in input.get(..count)? {
            size = size.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        if size < 128 {
            return None;
        }
        *input = input.get(count..)?;
        size
    };
    let body = input.get(..size)?;
    *input = input.get(size..)?;
    Some(body)
}

pub(crate) fn parse(data: &[u8]) -> Option<Parsed<'_>> {
    if data.len() > 16 * 1024 * 1024 {
        return None;
    }
    let mut outer = data;
    let mut sequence = element(&mut outer, 0x30)?;
    if !outer.is_empty()
        || element(&mut sequence, 0x16)? != b"IM4P"
        || element(&mut sequence, 0x16)? != b"trca"
    {
        return None;
    }
    let description = element(&mut sequence, 0x16)?;
    if description.len() > 4096 || !description.iter().all(|b| b.is_ascii()) {
        return None;
    }
    let description = std::str::from_utf8(description).ok()?;
    let payload = element(&mut sequence, 4)?;
    if !sequence.is_empty() || payload.get(..4)? != 2u32.to_le_bytes() {
        return None;
    }
    let count = u32::from_le_bytes(payload.get(20..24)?.try_into().ok()?) as usize;
    if count > 100_000 || payload.len() != 24usize.checked_add(count.checked_mul(24)?)? {
        return None;
    }
    let entries = payload.get(24..)?;
    let mut previous: Option<&[u8]> = None;
    for entry in entries.as_chunks::<24>().0 {
        if entry[23] != 0 || previous.is_some_and(|p| p > &entry[..20]) {
            return None;
        }
        previous = Some(&entry[..20]);
    }
    Some(Parsed {
        description,
        uuid: payload.get(4..20)?,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fileid::{FileType, detect};
    use std::path::Path;

    const SAMPLE: &[u8] = include_bytes!("testdata/tiny-image4-trustcache.im4p");

    #[test]
    fn full_trca_table_identification_is_independent_of_collected_name() {
        let parsed = parse(SAMPLE).unwrap();
        assert_eq!(parsed.description, "1");
        assert_eq!(parsed.entries.len() / 24, 83);
        for name in ["", "hash", "firmware.trustcache", "firmware.im4p"] {
            let detected = detect(Path::new(name), SAMPLE).unwrap();
            assert_eq!(detected.file_type, FileType::Data);
            assert!(!detected.extension_mismatch());
        }
        assert!(
            detect(Path::new("program.exe"), SAMPLE)
                .unwrap()
                .extension_mismatch()
        );
    }

    #[test]
    fn framing_count_version_order_and_reserved_bytes_are_required() {
        for cut in 0..SAMPLE.len() {
            assert!(parse(&SAMPLE[..cut]).is_none(), "cut {cut}");
        }
        for (offset, value) in [(8, b'X'), (15, b'i'), (23, 3), (43, 84), (70, 1)] {
            let mut corrupt = SAMPLE.to_vec();
            corrupt[offset] = value;
            assert!(parse(&corrupt).is_none(), "offset {offset}");
        }
        let mut trailing = SAMPLE.to_vec();
        trailing.push(0);
        assert!(parse(&trailing).is_none());
        let mut unordered = SAMPLE.to_vec();
        unordered[47..67].fill(255);
        assert!(parse(&unordered).is_none());
        let mut bad_der = SAMPLE.to_vec();
        bad_der[1] = 0x80;
        assert!(parse(&bad_der).is_none());
    }
}
