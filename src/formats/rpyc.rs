//! Ren'Py compiled scripts: bounded RPC2 slot and inert pickle inspection.
use std::collections::HashSet;

use flate2::bufread::ZlibDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::bounded::{OnError, inflate_capped};
use crate::error::Error;
use crate::output::{Metrics, Values};
use crate::{metric, value_key};

const MAGIC: &[u8] = b"RENPY RPC2";
const MAX_SLOTS: usize = 128;
const MAX_SLOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_DECODED_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Slot {
    number: u32,
    offset: usize,
    length: usize,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn u32_at(bytes: &[u8], pos: usize) -> Result<u32, Error> {
    crate::bytes::u32_le(bytes, pos).ok_or_else(|| Error::malformed("rpyc", "truncated slot table"))
}

fn slots(bytes: &[u8]) -> Result<(u8, Vec<Slot>, usize), Error> {
    if !bytes.starts_with(MAGIC) {
        return Ok((
            1,
            vec![Slot {
                number: 1,
                offset: 0,
                length: bytes.len(),
            }],
            0,
        ));
    }
    let mut pos = MAGIC.len();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if out.len() >= MAX_SLOTS {
            return Err(Error::malformed("rpyc", "slot limit exceeded"));
        }
        let number = u32_at(bytes, pos)?;
        let offset = usize::try_from(u32_at(bytes, pos + 4)?)
            .map_err(|_| Error::malformed("rpyc", "slot offset overflow"))?;
        let length = usize::try_from(u32_at(bytes, pos + 8)?)
            .map_err(|_| Error::malformed("rpyc", "slot length overflow"))?;
        pos += 12;
        if number == 0 {
            if offset != 0 || length != 0 || out.is_empty() {
                return Err(Error::malformed("rpyc", "invalid slot terminator"));
            }
            break;
        }
        if !seen.insert(number) || length == 0 {
            return Err(Error::malformed("rpyc", "duplicate or empty slot"));
        }
        out.push(Slot {
            number,
            offset,
            length,
        });
    }
    for slot in &out {
        if slot.offset < pos
            || slot
                .offset
                .checked_add(slot.length)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(Error::malformed("rpyc", "slot extent outside payload"));
        }
    }
    Ok((2, out, pos))
}

/// Inflate one slot to at most `cap` bytes. `Err` carries why it was not
/// read and the inflated bytes the attempt may have cost, which count toward
/// the file's total as much as a decoded slot does.
fn decompress(bytes: &[u8], cap: usize) -> Result<Vec<u8>, (String, usize)> {
    if bytes.len() > MAX_SLOT_BYTES {
        return Err(("compressed slot limit exceeded".into(), 0));
    }
    let output = inflate_capped(ZlibDecoder::new(bytes), cap as u64, OnError::Discard)
        .map_err(|error| (format!("zlib decode failed: {error}"), cap))?;
    if output.truncated {
        let why = if cap < MAX_SLOT_BYTES {
            "total decompressed slot limit exceeded"
        } else {
            "decompressed slot limit exceeded"
        };
        return Err((why.into(), cap));
    }
    Ok(output.bytes)
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let (version, slots, table_size) = slots(bytes)?;
    let mut slot_facts = Vec::with_capacity(slots.len());
    let mut selected_sources = Vec::new();
    let mut selected_slot = None;
    let mut total_decoded = 0usize;
    // Bytes inflated, decoded or refused: what the total cap bounds.
    let mut total_spent = 0usize;
    let mut source_bytes = 0usize;
    let mut decoded_slots = Vec::new();
    for slot in &slots {
        let raw = bytes
            .get(slot.offset..slot.offset + slot.length)
            .ok_or_else(|| Error::malformed("rpyc", "slot extent outside payload"))?;
        let mut fact = serde_json::Map::new();
        fact.insert("number".into(), json!(slot.number));
        fact.insert("offset".into(), json!(slot.offset));
        fact.insert("compressed_size".into(), json!(slot.length));
        fact.insert("compressed_sha256".into(), json!(hash(raw)));
        fact.insert("compression".into(), json!("zlib"));
        // Slots may overlap, so every one may name the same small stream
        // that inflates past the cap: refused slots spend the budget too.
        let cap = MAX_SLOT_BYTES.min(MAX_TOTAL_DECODED_BYTES - total_spent);
        match decompress(raw, cap) {
            Ok(decoded) => {
                total_decoded += decoded.len();
                total_spent += decoded.len();
                fact.insert("decompressed_size".into(), json!(decoded.len()));
                fact.insert("decompressed_sha256".into(), json!(hash(&decoded)));
                if decoded.starts_with(&[0x80])
                    && let Some(protocol) = decoded.get(1)
                {
                    fact.insert("pickle_protocol".into(), json!(protocol));
                }
                let sources = super::pickle::renpy_pycode_sources(&decoded);
                fact.insert("python_source_count".into(), json!(sources.len()));
                decoded_slots.push((slot.number, sources));
            }
            Err((error, spent)) => {
                total_spent += spent;
                fact.insert("error".into(), json!(error));
            }
        }
        slot_facts.push(Value::Object(fact));
    }
    // Ren'Py loads transformed slot 2 first and falls back to slot 1 only
    // when slot 2 is absent or unreadable. An empty source list in a valid
    // slot is not permission to analyze stale slot-1 code as runtime code.
    if let Some((number, sources)) = decoded_slots
        .iter()
        .find(|(number, _)| *number == 2)
        .or_else(|| decoded_slots.iter().find(|(number, _)| *number == 1))
    {
        selected_slot = Some(*number);
        for source in sources {
            if source_bytes + source.len() > MAX_SOURCE_BYTES {
                break;
            }
            source_bytes += source.len();
            selected_sources.push(json!({
                "slot": number,
                "sha256": hash(source.as_bytes()),
                "bytes": source.len(),
                "source": source,
            }));
        }
    }
    let max_end = slots
        .iter()
        .map(|slot| slot.offset + slot.length)
        .max()
        .unwrap_or(table_size);
    let trailer = bytes.get(max_end..).unwrap_or_default();
    let trailing = trailer.len();
    let source_digest_md5_hex =
        (version == 2 && trailing == 16).then(|| super::common::hex_encode(trailer));
    let slot_decode_complete = slot_facts.iter().all(|slot| slot.get("error").is_none());
    let source_count = selected_sources.len();
    values.insert_key(
        value_key!("rpyc"),
        json!({
            "version": version,
            "header_size": table_size,
            "slot_count": slots.len(),
            "slots": slot_facts,
            "selected_slot": selected_slot,
            "slot_decode_complete": slot_decode_complete,
            "python_source_count": source_count,
            "python_source_bytes": source_bytes,
            "python_sources": selected_sources,
            "trailing_bytes": trailing,
            "trailing_sha256": (trailing != 0).then(|| hash(trailer)),
            "source_digest_md5_hex": source_digest_md5_hex,
        }),
    );
    metrics.insert(metric!("rpyc.slot_count"), slots.len() as f64);
    metrics.insert(metric!("rpyc.decompressed_bytes"), total_decoded as f64);
    metrics.insert(metric!("rpyc.python_source_count"), source_count as f64);
    metrics.insert(metric!("rpyc.python_source_bytes"), source_bytes as f64);
    metrics.insert(metric!("rpyc.trailing_bytes"), trailing as f64);
    Ok(())
}

#[cfg(test)]
mod tests;
