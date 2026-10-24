//! Bounded ZIP opening for file-type probes.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// Bound failed end-of-directory searches as well as successful reads. The ZIP
/// reader otherwise rescans its input for every false EOCD signature.
pub(super) struct Budgeted<'a> {
    inner: Cursor<&'a [u8]>,
    left: usize,
}

impl Read for Budgeted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 && !buf.is_empty() {
            return Err(io::Error::other("ZIP probe read budget exhausted"));
        }
        let max = buf.len().min(self.left);
        let n = self.inner.read(buf.get_mut(..max).unwrap_or_default())?;
        self.left -= n;
        Ok(n)
    }
}

impl Seek for Budgeted<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub(super) fn open(data: &[u8]) -> zip::result::ZipResult<zip::ZipArchive<Budgeted<'_>>> {
    zip::ZipArchive::new(Budgeted {
        inner: Cursor::new(data),
        left: data.len().saturating_mul(4).saturating_add(1 << 20),
    })
}
