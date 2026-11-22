//! Identifiers and string constants from a `.pyc`'s code objects.
//!
//! A code object's `co_names` are the identifiers it uses; its `co_consts`
//! hold the values its source spelled, so their `str` constants are the
//! module's string literals, as a parser would recover them from the source.
//! Constants never become identifiers.
use crate::formats::marshal::{self, CodeObject, Value, Version, Walker};
use crate::output::{Literal, Literals, Symbol, Symbols};

/// Identifiers kept from one stream.
const MAX_NAMES: usize = 20_000;
/// Longest identifier kept.
const MAX_NAME_BYTES: usize = 1024;
/// String constants kept from one stream, and their bytes in all; past
/// either, the rest are left out.
const MAX_LITERALS: usize = 20_000;
const MAX_LITERAL_BYTES: usize = 4 << 20;
/// Tuple nesting followed inside a constant table.
const MAX_CONST_DEPTH: usize = 4;

/// What the walk keeps, each with its offset in the marshal stream.
#[derive(Default)]
struct Found {
    names: Vec<(String, usize)>,
    literals: Vec<(String, usize)>,
    literal_bytes: usize,
}

/// The names one code object lists, appended to `found`.
fn code_names(
    walker: &Walker<'_>,
    data: &[u8],
    code: &CodeObject,
    found: &mut Found,
) -> Result<(), &'static str> {
    let Some(Value::Sequence(ids)) = walker.values.get(code.names) else {
        return Err("code-object names are not a tuple");
    };
    for id in ids {
        // A Python 2 name is a byte string.
        let (Some(Value::Text(range)) | Some(Value::Bytes(range))) = walker.values.get(*id) else {
            return Err("code-object name is not a string");
        };
        let bytes = data.get(range.clone()).ok_or("invalid marshal string")?;
        let name = std::str::from_utf8(bytes).map_err(|_| "invalid UTF-8 code-object name")?;
        if name.len() > MAX_NAME_BYTES {
            return Err("marshal identifier length budget exceeded");
        }
        if found.names.len() >= MAX_NAMES {
            return Err("marshal identifier budget exceeded");
        }
        if !name.is_empty() {
            found.names.push((name.to_owned(), range.start));
        }
    }
    Ok(())
}

/// The string constants of the constant table at arena slot `slot`, and of
/// the tuples in it, appended to `found`: `str` constants, and `bytes` ones
/// that are UTF-8 text, as a source `b"..."` literal is (and a Python 2
/// `str` is bytes). Nested code objects are visited by the walk on their
/// own; other constants are not strings.
fn code_constants(walker: &Walker<'_>, data: &[u8], slot: usize, depth: usize, found: &mut Found) {
    match walker.values.get(slot) {
        Some(Value::Text(range) | Value::Bytes(range)) => {
            let Some(text) = data
                .get(range.clone())
                .and_then(|b| std::str::from_utf8(b).ok())
            else {
                return;
            };
            if found.literals.len() < MAX_LITERALS
                && found.literal_bytes + text.len() <= MAX_LITERAL_BYTES
            {
                found.literal_bytes += text.len();
                found.literals.push((text.to_owned(), range.start));
            }
        }
        Some(Value::Sequence(items)) if depth < MAX_CONST_DEPTH => {
            for &item in items {
                code_constants(walker, data, item, depth + 1, found);
            }
        }
        _ => {}
    }
}

/// Add the identifiers and string constants of the `version` marshal stream
/// `body`, which starts `header_len` bytes into the file. Only a completely
/// parsed stream contributes: a truncated one must not leave partial facts
/// that could satisfy an attack composite.
pub(super) fn extract(
    body: &[u8],
    version: Version,
    header_len: usize,
    symbols: &mut Symbols,
    literals: &mut Literals,
) -> Result<(), &'static str> {
    let mut found = Found::default();
    marshal::walk(body, version, |walker, code| {
        code_names(walker, body, code, &mut found)?;
        code_constants(walker, body, code.constants, 0, &mut found);
        Ok(())
    })?;
    found.names.sort_unstable();
    found.names.dedup();
    for (name, offset) in found.names {
        symbols.push(Symbol::Identifier {
            name,
            offset: Some((offset + header_len) as u64),
        });
    }
    tracing::debug!(
        target: "filefacts::pyc",
        literals = found.literals.len(),
        bytes = found.literal_bytes,
        "pyc string constants recovered as literals"
    );
    for (value, offset) in found.literals {
        literals.push(Literal::new(value, (offset + header_len) as u64));
    }
    Ok(())
}
