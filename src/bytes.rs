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
mod tests;
