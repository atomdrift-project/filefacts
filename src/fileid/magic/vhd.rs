//! Virtual Hard Disk footers.

use crate::bytes;

/// A legacy VHD v1 image: its 512-byte `conectix` footer with a valid
/// checksum, and a fixed image's size or a dynamic image's `cxsparse` header
/// agreeing with it. The different VHDX format is not identified.
/// <https://www.microsoft.com/en-us/download/details.aspx?id=23850>
pub(super) fn looks_like_vhd(data: &[u8]) -> Option<()> {
    let footer = data.last_chunk::<512>()?;
    if !footer.starts_with(b"conectix") || bytes::u32_be(footer, 12) != Some(0x0001_0000) {
        return None;
    }
    let checksum = !footer
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .map(|(_, b)| u32::from(*b))
        .sum::<u32>();
    if bytes::u32_be(footer, 64) != Some(checksum) {
        return None;
    }
    let size = bytes::u64_be(footer, 48)?;
    if size == 0 || !size.is_multiple_of(512) {
        return None;
    }
    match bytes::u32_be(footer, 60)? {
        2 => {
            if bytes::u64_be(footer, 16) != Some(u64::MAX)
                || size.checked_add(512)? != data.len() as u64
            {
                return None;
            }
        }
        3 | 4 => {
            let offset = usize::try_from(bytes::u64_be(footer, 16)?).ok()?;
            let header = data.get(offset..offset.checked_add(1024)?)?;
            if !header.starts_with(b"cxsparse") || bytes::u32_be(header, 24) != Some(0x0001_0000) {
                return None;
            }
        }
        _ => return None,
    }
    Some(())
}
