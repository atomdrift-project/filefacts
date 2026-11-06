//! Identifiers from the `co_names` tables of a `.pyc`'s code objects.
//!
//! Names in `co_consts` are data, not identifiers, and are not read.
use crate::formats::marshal::{self, CodeObject, Value, Walker};
use crate::output::{Symbol, Symbols};

/// Identifiers kept from one stream.
const MAX_NAMES: usize = 20_000;
/// Longest identifier kept.
const MAX_NAME_BYTES: usize = 1024;

/// The names one code object lists, with their stream offsets, appended to
/// `names`.
fn code_names(
    walker: &Walker<'_>,
    data: &[u8],
    code: &CodeObject,
    names: &mut Vec<(String, usize)>,
) -> Result<(), &'static str> {
    let Some(Value::Sequence(ids)) = walker.values.get(code.names) else {
        return Err("code-object names are not a tuple");
    };
    for id in ids {
        let Some(Value::Text(range)) = walker.values.get(*id) else {
            return Err("code-object name is not a string");
        };
        let bytes = data.get(range.clone()).ok_or("invalid marshal string")?;
        let name = std::str::from_utf8(bytes).map_err(|_| "invalid UTF-8 code-object name")?;
        if name.len() > MAX_NAME_BYTES {
            return Err("marshal identifier length budget exceeded");
        }
        if names.len() >= MAX_NAMES {
            return Err("marshal identifier budget exceeded");
        }
        if !name.is_empty() {
            names.push((name.to_owned(), range.start));
        }
    }
    Ok(())
}

pub(super) fn extract(body: &[u8], minor: u8, symbols: &mut Symbols) -> Result<(), &'static str> {
    let mut names = Vec::new();
    marshal::walk(body, minor, |walker, code| {
        code_names(walker, body, code, &mut names)
    })?;
    // Commit only a completely parsed stream. A truncated stream must not
    // leave partial identifiers that could satisfy an attack composite.
    names.sort_unstable();
    names.dedup();
    for (name, offset) in names {
        symbols.push(Symbol::Identifier {
            name,
            offset: Some((offset + 16) as u64),
        });
    }
    Ok(())
}
