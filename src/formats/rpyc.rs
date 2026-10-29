//! Ren'Py compiled scripts: bounded RPC2 slot and inert pickle inspection.
use std::collections::HashSet;
use std::io::{Cursor, Read};

use flate2::bufread::ZlibDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

fn set_fact(fact: &mut Value, key: &str, value: Value) {
    if let Some(object) = fact.as_object_mut() {
        object.insert(key.to_owned(), value);
    }
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

fn decompress(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_SLOT_BYTES {
        return Err("compressed slot limit exceeded".into());
    }
    let decoder = ZlibDecoder::new(Cursor::new(bytes));
    let mut bounded = decoder.take((MAX_SLOT_BYTES + 1) as u64);
    let mut output = Vec::new();
    bounded
        .read_to_end(&mut output)
        .map_err(|error| format!("zlib decode failed: {error}"))?;
    if output.len() > MAX_SLOT_BYTES {
        return Err("decompressed slot limit exceeded".into());
    }
    Ok(output)
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
    let mut source_bytes = 0usize;
    let mut decoded_slots = Vec::new();
    for slot in &slots {
        let raw = bytes
            .get(slot.offset..slot.offset + slot.length)
            .ok_or_else(|| Error::malformed("rpyc", "slot extent outside payload"))?;
        let mut fact = json!({
            "number": slot.number,
            "offset": slot.offset,
            "compressed_size": slot.length,
            "compressed_sha256": hash(raw),
            "compression": "zlib",
        });
        match decompress(raw) {
            Ok(decoded) if decoded.len() <= MAX_TOTAL_DECODED_BYTES - total_decoded => {
                total_decoded += decoded.len();
                set_fact(&mut fact, "decompressed_size", json!(decoded.len()));
                set_fact(&mut fact, "decompressed_sha256", json!(hash(&decoded)));
                if decoded.starts_with(&[0x80])
                    && let Some(protocol) = decoded.get(1)
                {
                    set_fact(&mut fact, "pickle_protocol", json!(protocol));
                }
                let sources = super::pickle::renpy_pycode_sources(&decoded);
                set_fact(&mut fact, "python_source_count", json!(sources.len()));
                decoded_slots.push((slot.number, sources));
            }
            Ok(_) => set_fact(
                &mut fact,
                "error",
                json!("total decompressed slot limit exceeded"),
            ),
            Err(error) => set_fact(&mut fact, "error", json!(error)),
        }
        slot_facts.push(fact);
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
    let source_digest_md5_hex = if version == 2 && trailing == 16 {
        Some(
            trailer
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    } else {
        None
    };
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
            "trailing_sha256": if trailing == 0 { None } else { Some(hash(trailer)) },
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
