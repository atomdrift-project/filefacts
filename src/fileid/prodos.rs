//! Conservative recognition of headerless Apple II ProDOS system code.
//!
//! A SYS program conventionally loads at $2000. A bounded initial absolute
//! jump into its own bytes and several complete ProDOS MLI call records make
//! generic data analysis worthwhile; they do not imply malicious behavior.
pub(super) fn has_prodos_system_code(data: &[u8]) -> bool {
    const LOAD: usize = 0x2000;
    if data.len() < 512 || data.len() > 0x10000 - LOAD || data.first() != Some(&0x4c) {
        return false;
    }
    let Some(&[lo, hi]) = data.get(1..3) else {
        return false;
    };
    let target = usize::from(u16::from_le_bytes([lo, hi]));
    if target < LOAD || target >= LOAD + data.len() {
        return false;
    }
    // JSR $BF00 is followed by one command byte and a two-byte pointer.
    // Require open, close, and read/write calls; every call must be complete.
    let mut open = false;
    let mut close = false;
    let mut io = false;
    for window in data.windows(6) {
        let &[0x20, 0x00, 0xbf, command, lo, hi] = window else {
            continue;
        };
        let pointer = u16::from_le_bytes([lo, hi]);
        if !(0x0200..=0xbfff).contains(&pointer) {
            continue;
        }
        match command {
            0xc8 => open = true,
            0xc9 | 0xca => io = true,
            0xcc => close = true,
            _ => {}
        }
    }
    open && io && close
}

#[cfg(test)]
mod tests {
    use super::has_prodos_system_code;

    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..3].copy_from_slice(&[0x4c, 0x30, 0x20]);
        b[24..42].copy_from_slice(&[
            0x20, 0x00, 0xbf, 0xc8, 0x00, 0x30, 0x20, 0x00, 0xbf, 0xca, 0x10, 0x30, 0x20, 0x00,
            0xbf, 0xcc, 0x20, 0x30,
        ]);
        b
    }

    #[test]
    fn recognizes_bounded_entry_and_complete_mli_calls() {
        let data = sample();
        assert!(has_prodos_system_code(&data));
        assert_eq!(
            super::super::detect(std::path::Path::new("unnamed"), &data)
                .expect("ProDOS code routes to generic analysis")
                .file_type,
            crate::FileType::Data
        );
    }

    #[test]
    fn rejects_missing_calls_invalid_entry_and_truncation() {
        let data = sample();
        for (at, value) in [
            (0, 0xea),
            (2, 0x40),
            (27, 0xc9),
            (33, 0xc5),
            (39, 0xcd),
            (29, 0x00),
        ] {
            let mut changed = data.clone();
            changed[at] = value;
            assert!(!has_prodos_system_code(&changed), "offset {at}");
        }
        assert!(!has_prodos_system_code(&data[..100]));
    }
}
