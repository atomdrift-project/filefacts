//! A narrow, structurally checked 16-bit Unix impure a.out image.
//!
//! The shared 0407 magic is not sufficient to identify an instruction set.
//! Route consistent images to generic data analysis without guessing a CPU.

pub(super) fn looks_like_image(data: &[u8]) -> bool {
    let word = |at: usize| -> Option<usize> {
        let bytes: [u8; 2] = data.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(usize::from(u16::from_le_bytes(bytes)))
    };
    let Some((magic, text, initialized, symbols, entry, flags)) =
        (|| Some((word(0)?, word(2)?, word(4)?, word(8)?, word(10)?, word(14)?)))()
    else {
        return false;
    };
    if magic != 0o407 || flags != 1 || text < 2 || text % 2 != 0 || entry % 2 != 0 || entry >= text
    {
        return false;
    }
    let Some(image_size) = text.checked_add(initialized) else {
        return false;
    };
    if image_size > 65_536 {
        return false;
    }
    16usize
        .checked_add(image_size)
        .and_then(|n| n.checked_add(symbols))
        .is_some_and(|n| n <= data.len())
}

#[cfg(test)]
mod tests {
    use super::looks_like_image;
    use crate::FileType;
    use std::path::Path;

    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; 48];
        for (at, val) in [
            (0, 0o407u16),
            (2, 16),
            (4, 8),
            (6, 4),
            (8, 8),
            (10, 0),
            (14, 1),
        ] {
            b[at..at + 2].copy_from_slice(&val.to_le_bytes());
        }
        b
    }
    #[test]
    fn accepts_consistent_image_without_assuming_a_cpu() {
        let b = sample();
        assert!(looks_like_image(&b));
        assert_eq!(
            super::super::detect(Path::new("unnamed"), &b)
                .unwrap()
                .file_type,
            FileType::Data
        );
    }
    #[test]
    fn rejects_truncation_and_inconsistent_geometry() {
        let b = sample();
        assert!(!looks_like_image(&b[..47]));
        for (at, value) in [(0, 0), (2, 15), (4, 80), (10, 16), (14, 0)] {
            let mut changed = b.clone();
            changed[at] = value;
            assert!(!looks_like_image(&changed), "offset {at}");
        }
    }
}
