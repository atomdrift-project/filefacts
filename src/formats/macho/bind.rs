//! The dyld bind-opcode streams, checked against the image they bind.
//!
//! binform reads each imported symbol once, whatever the streams repeat, so
//! the streams are not walked for imports. They are walked as dyld walks them
//! for what dyld would refuse, and for what no linker emits: a dylib ordinal
//! past the image's `LC_LOAD_DYLIB` commands, a segment index past its
//! segments, or a repeat count binding more slots than any real image has.
//! Each is a forged stream, a fact about the sample.

use std::fmt;

use goblin::mach::MachO;
use goblin::mach::bind_opcodes::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_MASK,
    BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    BIND_OPCODE_SET_TYPE_IMM,
};
use goblin::mach::load_command::CommandVariant;

use crate::formats::common::read_uleb128;

/// Slots the bind and lazy-bind streams together may bind. The largest
/// frameworks bind tens of thousands; past this the count is a forgery.
pub(super) const MAX_BINDS: u64 = 256 * 1024;

/// `BIND_OPCODE_THREADED`, whose immediate selects a sub-opcode.
const BIND_OPCODE_THREADED: u8 = 0xd0;
/// `BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB`.
const THREADED_SET_TABLE_SIZE: u8 = 0x00;
/// The most negative special ordinal dyld knows,
/// `BIND_SPECIAL_DYLIB_WEAK_LOOKUP` (-3).
const MIN_SPECIAL_ORDINAL: i8 = -3;

/// A bind stream dyld would refuse, or no linker emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Anomaly {
    /// The streams bind more than [`MAX_BINDS`] slots.
    Oversized { stream: &'static str, binds: u64 },
    /// A dylib ordinal past the image's dylibs, numbered from 1 as dyld
    /// numbers them; `len` is how many the image loads.
    DylibOutOfRange {
        stream: &'static str,
        ordinal: u64,
        len: usize,
    },
    /// A special dylib ordinal dyld does not define.
    UnknownSpecialOrdinal { stream: &'static str, ordinal: i8 },
    /// A segment index past the image's segments.
    SegmentOutOfRange {
        stream: &'static str,
        index: u8,
        len: usize,
    },
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Oversized { stream, binds } => write!(
                f,
                "{stream} bind opcodes declare at least {binds} imports, past {MAX_BINDS}"
            ),
            Self::DylibOutOfRange {
                stream,
                ordinal,
                len,
            } => write!(
                f,
                "{stream} bind opcodes bind through dylib ordinal {ordinal} of {len}"
            ),
            Self::UnknownSpecialOrdinal { stream, ordinal } => write!(
                f,
                "{stream} bind opcodes bind through special dylib ordinal {ordinal}"
            ),
            Self::SegmentOutOfRange { stream, index, len } => {
                write!(
                    f,
                    "{stream} bind opcodes bind through segment {index} of {len}"
                )
            }
        }
    }
}

/// The first anomaly in `macho`'s bind and lazy-bind streams, read from
/// `bytes`, the image's own bytes. The last `LC_DYLD_INFO` or
/// `LC_DYLD_INFO_ONLY` names the streams, as for dyld.
pub(super) fn check(macho: &MachO<'_>, bytes: &[u8]) -> Option<Anomaly> {
    let mut streams = None;
    for lc in &macho.load_commands {
        if let CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) = &lc.command {
            streams = Some([
                ("bind", c.bind_off, c.bind_size),
                ("lazy", c.lazy_bind_off, c.lazy_bind_size),
            ]);
        }
    }
    let tables = Tables {
        // goblin lists the image itself first, as ordinal 0.
        dylibs: macho.libs.len().saturating_sub(1),
        segments: macho.segments.len(),
    };
    let mut binds = 0;
    for (stream, offset, size) in streams.into_iter().flatten() {
        let start = crate::bytes::sat_usize(offset);
        let end = start.saturating_add(crate::bytes::sat_usize(size));
        let code = bytes.get(start..end.min(bytes.len())).unwrap_or_default();
        binds = match walk(code, stream, tables, binds) {
            Ok(binds) => binds,
            Err(anomaly) => return Some(anomaly),
        };
    }
    None
}

/// How many dylibs and segments the image has.
#[derive(Clone, Copy, Debug)]
struct Tables {
    dylibs: usize,
    segments: usize,
}

/// Walk one stream, adding the slots it binds to `binds`. The bind stream
/// ends at its first `DONE`; the lazy stream is a run of entries, each ended
/// by a `DONE` and starting from fresh state. A truncated operand or an
/// opcode dyld does not know ends the walk, as it ends dyld's.
fn walk(code: &[u8], stream: &'static str, tables: Tables, mut binds: u64) -> Result<u64, Anomaly> {
    let lazy = stream == "lazy";
    let mut at = 0;
    let uleb = |at: &mut usize| read_uleb128(code, at);
    while let Some(&byte) = code.get(at) {
        at += 1;
        let immediate = byte & BIND_IMMEDIATE_MASK;
        let mut bound = 0;
        let read = match byte & BIND_OPCODE_MASK {
            BIND_OPCODE_DONE if lazy => Some(()),
            BIND_OPCODE_DONE => break,
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => dylib(stream, u64::from(immediate), tables)?,
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => match uleb(&mut at) {
                Some(ordinal) => dylib(stream, ordinal, tables)?,
                None => None,
            },
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                // The immediate is the low nibble of a negative ordinal.
                let ordinal = if immediate == 0 {
                    0
                } else {
                    (immediate | BIND_OPCODE_MASK).cast_signed()
                };
                if ordinal < MIN_SPECIAL_ORDINAL {
                    return Err(Anomaly::UnknownSpecialOrdinal { stream, ordinal });
                }
                Some(())
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => code
                .get(at..)
                .and_then(|rest| memchr::memchr(0, rest))
                .map(|len| at += len + 1),
            BIND_OPCODE_SET_TYPE_IMM => Some(()),
            // SLEB and ULEB share the continuation-bit framing.
            BIND_OPCODE_SET_ADDEND_SLEB | BIND_OPCODE_ADD_ADDR_ULEB => uleb(&mut at).map(drop),
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                if usize::from(immediate) >= tables.segments {
                    return Err(Anomaly::SegmentOutOfRange {
                        stream,
                        index: immediate,
                        len: tables.segments,
                    });
                }
                uleb(&mut at).map(drop)
            }
            BIND_OPCODE_DO_BIND | BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                bound = 1;
                Some(())
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                bound = 1;
                uleb(&mut at).map(drop)
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                uleb(&mut at).zip(uleb(&mut at)).map(|(count, _skip)| {
                    bound = count;
                })
            }
            BIND_OPCODE_THREADED if immediate == THREADED_SET_TABLE_SIZE => uleb(&mut at).map(drop),
            BIND_OPCODE_THREADED => Some(()),
            _ => None,
        };
        if read.is_none() {
            break;
        }
        binds = binds.saturating_add(bound);
        if binds > MAX_BINDS {
            return Err(Anomaly::Oversized { stream, binds });
        }
    }
    Ok(binds)
}

/// Check a dylib ordinal set by the stream: 0 is the image itself, 1 and up
/// its dylibs in load-command order.
fn dylib(stream: &'static str, ordinal: u64, tables: Tables) -> Result<Option<()>, Anomaly> {
    if usize::try_from(ordinal).is_ok_and(|ordinal| ordinal <= tables.dylibs) {
        Ok(Some(()))
    } else {
        Err(Anomaly::DylibOutOfRange {
            stream,
            ordinal,
            len: tables.dylibs,
        })
    }
}

#[cfg(test)]
mod tests;
