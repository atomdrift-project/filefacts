//! Bounded ZIP opening for file-type probes.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// Bytes the `zip` crate may read while a probe opens an archive and reads
/// small members, per input byte, on top of a fixed 1 MiB. A well-formed
/// archive needs well under two passes, but the crate rescans its input for
/// every failing end-of-central-directory candidate, so one packed with them
/// would otherwise take quadratic time to refuse.
const READS_PER_BYTE: usize = 4;

/// A reader that fails once its byte budget is spent, so failed end-of-
/// directory searches are bounded as well as successful reads.
#[derive(Clone)]
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

/// A zip opened for probing. Each clone reads under its own budget.
pub(super) type Archive<'a> = zip::ZipArchive<Budgeted<'a>>;

/// `data` opened as a zip, or `None` when its central directory does not
/// parse within the budget.
pub(super) fn open(data: &[u8]) -> Option<Archive<'_>> {
    let archive = zip::ZipArchive::new(Budgeted {
        inner: Cursor::new(data),
        left: data
            .len()
            .saturating_mul(READS_PER_BYTE)
            .saturating_add(1 << 20),
    });
    if let Err(error) = &archive {
        tracing::debug!(
            target: "filefacts::fileid",
            len = data.len(),
            %error,
            "zip probe: central directory unreadable"
        );
    }
    archive.ok()
}

/// The member names in central-directory order. A name the archive cannot
/// decode is skipped: identification reads names as evidence, and an
/// undecodable one is evidence of nothing.
pub(super) fn names<'z>(
    archive: &'z Archive<'_>,
) -> impl Iterator<Item = std::borrow::Cow<'z, str>> {
    archive.file_names().filter_map(Result::ok)
}
