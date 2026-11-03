//! Conservative recognition of a Commodore 64 BASIC `SYS` loader.
//!
//! PRG files have no magic: the first word is a load address. Require a
//! self-consistent first BASIC line, a literal SYS destination inside the
//! file, and a bounded address range. This is a format hint, not a malware
//! verdict or a complete C64 program detector.
pub(super) fn has_basic_sys_loader(data: &[u8]) -> bool {
    const LOAD: usize = 0x0801;
    if data.len() < 20 || data.len() > 65537 - LOAD || data.get(..2) != Some(&[0x01, 0x08]) {
        return false;
    }
    let Some(&[link_lo, link_hi]) = data.get(2..4) else {
        return false;
    };
    let next_line = u16::from_le_bytes([link_lo, link_hi]) as usize;
    let Some(&[number_lo, number_hi]) = data.get(4..6) else {
        return false;
    };
    if u16::from_le_bytes([number_lo, number_hi]) > 63999 || data.get(6) != Some(&0x9e) {
        return false;
    }
    let mut p = 7;
    while data.get(p) == Some(&b' ') {
        p += 1;
    }
    let start = p;
    let mut entry = 0usize;
    while let Some(b @ b'0'..=b'9') = data.get(p).copied() {
        let Some(v) = entry
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as usize))
        else {
            return false;
        };
        if v > u16::MAX as usize {
            return false;
        }
        entry = v;
        p += 1;
    }
    if p == start || p - start > 5 {
        return false;
    }
    while data.get(p) == Some(&b' ') {
        p += 1;
    }
    if data.get(p) != Some(&0) {
        return false;
    }
    let Some(expected_next) = LOAD.checked_add(p + 1 - 2) else {
        return false;
    };
    if next_line != expected_next || entry < next_line || entry > next_line + 32 {
        return false;
    }
    let Some(offset) = entry.checked_sub(LOAD).and_then(|n| n.checked_add(2)) else {
        return false;
    };
    data.len().saturating_sub(offset) >= 8
}

#[cfg(test)]
mod tests {
    use super::has_basic_sys_loader;
    fn sample() -> Vec<u8> {
        let mut b = b"\x01\x08\x0b\x08\xc8\x07\x9e2059\0".to_vec();
        b.extend([0xa9, 1, 0x8d, 0x20, 0xd0, 0x4c, 0x0b, 8]);
        b
    }
    #[test]
    fn recognizes_consistent_sys_entry() {
        assert!(has_basic_sys_loader(&sample()));
        let detected = super::super::detect(std::path::Path::new("unnamed"), &sample())
            .expect("C64 loader gets a generic analysis type");
        assert_eq!(detected.file_type, crate::FileType::Data);
    }
    #[test]
    fn rejects_inconsistent_or_truncated_headers() {
        let s = sample();
        assert!(!has_basic_sys_loader(&s[..12]));
        for (at, value) in [(0, 2), (2, 0), (6, 0x80), (7, b'9'), (11, b'!')] {
            let mut b = s.clone();
            b[at] = value;
            assert!(!has_basic_sys_loader(&b), "offset {at}");
        }
        let mut b = s;
        b.resize(65538, 0);
        assert!(!has_basic_sys_loader(&b));
    }
}
