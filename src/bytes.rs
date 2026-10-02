//! Panic-free fixed-width reads over untrusted bytes.
//!
//! Each reader returns `None` when the value would run past the end of the
//! buffer, or its offset would overflow, so a parser can `?` through a
//! structure without indexing. The free functions read at an offset;
//! [`Reader`] is the sequential form for a structure laid out field after
//! field.

/// A file-supplied size or offset as a `usize`, saturating at `usize::MAX`.
///
/// On 64-bit hosts this is the identity for `u32`/`u64`. On 32-bit hosts a
/// value past the address space becomes `usize::MAX`, so the bounds check or
/// `checked_add` that follows fails, instead of a truncating `as` cast
/// wrapping a hostile 64-bit offset into a small, valid-looking one. A
/// negative signed value also saturates: it is never a valid size.
#[inline]
pub(crate) fn sat_usize<T: TryInto<usize>>(v: T) -> usize {
    v.try_into().unwrap_or(usize::MAX)
}

/// A length or count as a `u32` metric field, saturating at `u32::MAX`
/// rather than wrapping.
#[inline]
pub(crate) fn sat_u32<T: TryInto<u32>>(v: T) -> u32 {
    v.try_into().unwrap_or(u32::MAX)
}

/// Read the `N` bytes at `off`.
#[inline]
fn array_at<const N: usize>(b: &[u8], off: usize) -> Option<[u8; N]> {
    b.get(off..)?.first_chunk().copied()
}

/// Read a little-endian `u16` at `off`.
#[inline]
pub(crate) fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    array_at(b, off).map(u16::from_le_bytes)
}

/// Read a little-endian `u32` at `off`.
#[inline]
pub(crate) fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    array_at(b, off).map(u32::from_le_bytes)
}

/// Read a big-endian `u32` at `off`.
#[inline]
pub(crate) fn u32_be(b: &[u8], off: usize) -> Option<u32> {
    array_at(b, off).map(u32::from_be_bytes)
}

/// Read a little-endian `u64` at `off`.
#[inline]
pub(crate) fn u64_le(b: &[u8], off: usize) -> Option<u64> {
    array_at(b, off).map(u64::from_le_bytes)
}

/// Read a big-endian `u64` at `off`.
#[inline]
pub(crate) fn u64_be(b: &[u8], off: usize) -> Option<u64> {
    array_at(b, off).map(u64::from_be_bytes)
}

/// Byte order of the code units in a UTF-16 run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Endian {
    Little,
    Big,
}

/// The UTF-16 code units of `buf` in `endian` order. A trailing odd byte is
/// not a whole unit and is ignored.
pub(crate) fn utf16_units(buf: &[u8], endian: Endian) -> impl Iterator<Item = u16> + '_ {
    buf.as_chunks::<2>()
        .0
        .iter()
        .map(move |&pair| match endian {
            Endian::Little => u16::from_le_bytes(pair),
            Endian::Big => u16::from_be_bytes(pair),
        })
}

/// Decode `buf` as UTF-16, replacing each unpaired surrogate with U+FFFD.
/// A trailing odd byte is ignored.
pub(crate) fn utf16_lossy(buf: &[u8], endian: Endian) -> String {
    char::decode_utf16(utf16_units(buf, endian))
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decode `buf` as UTF-16, or `None` if it holds an unpaired surrogate.
/// A trailing odd byte is ignored.
pub(crate) fn utf16_strict(buf: &[u8], endian: Endian) -> Option<String> {
    char::decode_utf16(utf16_units(buf, endian))
        .collect::<Result<_, _>>()
        .ok()
}

/// The whole UTF-16 units of `buf` before the first NUL unit; all of them
/// when there is none. A NUL unit is two zero bytes in either byte order.
pub(crate) fn utf16_until_nul(buf: &[u8]) -> &[u8] {
    let units = buf.as_chunks::<2>().0;
    let len = units
        .iter()
        .position(|u| *u == [0, 0])
        .unwrap_or(units.len());
    buf.get(..len * 2).unwrap_or_default()
}

/// A forward cursor over untrusted bytes.
///
/// A read either succeeds and moves past what it read, or returns `None`
/// and leaves the position where it was, so a failed read never strands the
/// cursor partway through a field.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `buf`.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// A reader over `buf` positioned at `pos`. A position past the end is
    /// allowed; every read from it fails, even an empty one.
    pub(crate) fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    /// The offset of the next read within the buffer.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// The bytes left to read; zero at or past the end.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Step over `n` bytes.
    #[inline]
    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(drop)
    }

    /// Read the next `n` bytes.
    #[inline]
    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..)?.get(..n)?;
        self.pos += n;
        Some(s)
    }

    /// Read the next `N` bytes as an array.
    #[inline]
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let a = array_at(self.buf, self.pos)?;
        self.pos += N;
        Some(a)
    }

    /// Read one byte.
    #[inline]
    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array().map(|[b]| b)
    }

    /// Read a little-endian `u16`.
    #[inline]
    pub(crate) fn u16_le(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    /// Read a big-endian `u16`.
    #[inline]
    pub(crate) fn u16_be(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    /// Read a little-endian `u32`.
    #[inline]
    pub(crate) fn u32_le(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// Read a big-endian `u32`.
    #[inline]
    pub(crate) fn u32_be(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    /// Read a little-endian `u64`.
    #[inline]
    pub(crate) fn u64_le(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    /// Read a big-endian `u64`.
    #[inline]
    pub(crate) fn u64_be(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUF: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    #[test]
    fn utf16_decodes_both_byte_orders_and_ignores_an_odd_tail() {
        assert_eq!(utf16_lossy(b"h\0i\0!", Endian::Little), "hi");
        assert_eq!(utf16_lossy(b"\0h\0i", Endian::Big), "hi");
        assert_eq!(
            utf16_strict(b"h\0i\0", Endian::Little).as_deref(),
            Some("hi")
        );
        assert_eq!(utf16_lossy(b"", Endian::Big), "");
        // U+1F600 as a surrogate pair.
        assert_eq!(
            utf16_lossy(&[0x3d, 0xd8, 0x00, 0xde], Endian::Little),
            "\u{1F600}"
        );
    }

    #[test]
    fn utf16_lossy_replaces_unpaired_surrogates_and_strict_rejects_them() {
        let lone = [b'a', 0, 0x00, 0xd8, b'b', 0];
        assert_eq!(utf16_lossy(&lone, Endian::Little), "a\u{FFFD}b");
        assert_eq!(utf16_strict(&lone, Endian::Little), None);
        // Identical to the std decoders they replace.
        let units: Vec<u16> = utf16_units(&lone, Endian::Little).collect();
        assert_eq!(
            utf16_lossy(&lone, Endian::Little),
            String::from_utf16_lossy(&units)
        );
    }

    #[test]
    fn utf16_until_nul_stops_at_a_whole_zero_unit() {
        assert_eq!(utf16_until_nul(b"a\0b\0\0\0c\0"), b"a\0b\0");
        // The zero bytes straddling two units are not a NUL unit.
        assert_eq!(utf16_until_nul(b"a\0\0b"), b"a\0\0b");
        assert_eq!(utf16_until_nul(b"a\0b"), b"a\0");
        assert_eq!(utf16_until_nul(b"\0\0a\0"), b"");
    }

    #[test]
    fn offset_reads_decode_both_byte_orders() {
        assert_eq!(u16_le(&BUF, 1), Some(0x0302));
        assert_eq!(u32_le(&BUF, 4), Some(0x0807_0605));
        assert_eq!(u32_be(&BUF, 4), Some(0x0506_0708));
        assert_eq!(u64_le(&BUF, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(u64_be(&BUF, 0), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn offset_reads_fail_at_the_end_of_the_buffer() {
        assert_eq!(u16_le(&BUF, 6), Some(0x0807));
        assert_eq!(u16_le(&BUF, 7), None);
        assert_eq!(u32_le(&BUF, 5), None);
        assert_eq!(u32_be(&BUF, 5), None);
        assert_eq!(u64_le(&BUF, 1), None);
        assert_eq!(u64_be(&BUF, 1), None);
        assert_eq!(u16_le(&BUF, 8), None);
        assert_eq!(u16_le(&[], 0), None);
    }

    #[test]
    fn offset_reads_reject_overflowing_offsets() {
        for off in [9, usize::MAX - 1, usize::MAX] {
            assert_eq!(u16_le(&BUF, off), None);
            assert_eq!(u32_le(&BUF, off), None);
            assert_eq!(u32_be(&BUF, off), None);
            assert_eq!(u64_le(&BUF, off), None);
            assert_eq!(u64_be(&BUF, off), None);
        }
    }

    #[test]
    fn new_starts_at_zero_and_at_starts_where_told() {
        let r = Reader::new(&BUF);
        assert_eq!((r.pos(), r.remaining()), (0, 8));
        let r = Reader::at(&BUF, 3);
        assert_eq!((r.pos(), r.remaining()), (3, 5));
        let r = Reader::at(&BUF, 8);
        assert_eq!((r.pos(), r.remaining()), (8, 0));
    }

    #[test]
    fn a_reader_past_the_end_fails_every_read() {
        let mut r = Reader::at(&BUF, 9);
        assert_eq!((r.pos(), r.remaining()), (9, 0));
        assert_eq!(r.skip(0), None);
        assert_eq!(r.bytes(0), None);
        assert_eq!(r.array::<0>(), None);
        assert_eq!(r.u8(), None);
        let mut r = Reader::at(&BUF, usize::MAX);
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.bytes(1), None);
        assert_eq!(r.u64_le(), None);
        assert_eq!(r.pos(), usize::MAX);
    }

    #[test]
    fn skip_and_bytes_advance_by_what_they_consume() {
        let mut r = Reader::new(&BUF);
        assert_eq!(r.skip(2), Some(()));
        assert_eq!(r.pos(), 2);
        assert_eq!(r.bytes(3), Some(&BUF[2..5]));
        assert_eq!((r.pos(), r.remaining()), (5, 3));
        assert_eq!(r.skip(0), Some(()));
        assert_eq!(r.bytes(3), Some(&BUF[5..]));
        // At the end, an empty read still succeeds.
        assert_eq!(r.bytes(0), Some(&[][..]));
        assert_eq!(r.skip(0), Some(()));
        assert_eq!(r.pos(), 8);
    }

    #[test]
    fn skip_and_bytes_do_not_advance_on_failure() {
        let mut r = Reader::at(&BUF, 6);
        assert_eq!(r.skip(3), None);
        assert_eq!(r.bytes(3), None);
        assert_eq!(r.skip(usize::MAX), None);
        assert_eq!(r.bytes(usize::MAX), None);
        assert_eq!(r.pos(), 6);
        assert_eq!(r.bytes(2), Some(&BUF[6..]));
    }

    #[test]
    fn array_and_u8_read_in_sequence() {
        let mut r = Reader::new(&BUF);
        assert_eq!(r.u8(), Some(0x01));
        assert_eq!(r.array::<3>(), Some([0x02, 0x03, 0x04]));
        assert_eq!(r.array::<0>(), Some([]));
        assert_eq!(r.pos(), 4);
        assert_eq!(r.array::<5>(), None);
        assert_eq!(r.pos(), 4);
        assert_eq!(r.array::<4>(), Some([0x05, 0x06, 0x07, 0x08]));
        assert_eq!(r.u8(), None);
        assert_eq!(r.pos(), 8);
    }

    #[test]
    fn integer_reads_decode_both_byte_orders() {
        let mut r = Reader::new(&BUF);
        assert_eq!(r.u16_le(), Some(0x0201));
        assert_eq!(r.u16_be(), Some(0x0304));
        assert_eq!(r.u32_le(), Some(0x0807_0605));
        let mut r = Reader::new(&BUF);
        assert_eq!(r.u32_be(), Some(0x0102_0304));
        let mut r = Reader::new(&BUF);
        assert_eq!(r.u64_le(), Some(0x0807_0605_0403_0201));
        let mut r = Reader::new(&BUF);
        assert_eq!(r.u64_be(), Some(0x0102_0304_0506_0708));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn integer_reads_do_not_advance_on_failure() {
        let mut r = Reader::at(&BUF, 7);
        assert_eq!(r.u16_le(), None);
        assert_eq!(r.u16_be(), None);
        assert_eq!(r.pos(), 7);
        let mut r = Reader::at(&BUF, 5);
        assert_eq!(r.u32_le(), None);
        assert_eq!(r.u32_be(), None);
        assert_eq!(r.pos(), 5);
        let mut r = Reader::at(&BUF, 1);
        assert_eq!(r.u64_le(), None);
        assert_eq!(r.u64_be(), None);
        assert_eq!(r.pos(), 1);
        // The failed reads left the cursor on the bytes they could not take.
        assert_eq!(r.u8(), Some(0x02));
    }

    #[test]
    fn sat_usize_saturates_instead_of_truncating() {
        assert_eq!(sat_usize(0), 0);
        assert_eq!(sat_usize(4096), 4096);
        assert_eq!(sat_usize(u64::MAX), usize::MAX);
        assert_eq!(sat_usize(7_u32), 7);
        assert_eq!(sat_usize(-1_i64), usize::MAX);
        assert_eq!(sat_u32(12_usize), 12);
        assert_eq!(sat_u32(u64::MAX), u32::MAX);
    }
}
