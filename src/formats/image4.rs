//! Image4 trust-cache payloads: the table of code-directory hashes Apple
//! platforms trust without a signature check. The payload is located and
//! validated by identification ([`crate::fileid::image4_trustcache`]); this
//! publishes its entries.

use serde_json::json;

use super::common::hex_encode;
use crate::output::Values;
use crate::value_key;

/// Publish `image4.trustcache`: the header fields and one record per entry
/// (20-byte cdhash, hash type, flags, constraint category).
pub(super) fn extract(bytes: &[u8], values: &mut Values) {
    let Some(table) = crate::fileid::image4_trustcache::parse(bytes) else {
        tracing::debug!(
            target: "filefacts::image4",
            len = bytes.len(),
            "identified as a trust cache but the table does not parse"
        );
        return;
    };
    let entries: Vec<_> = table
        .entries
        .as_chunks::<24>()
        .0
        .iter()
        .map(|entry| {
            json!({
                "cdhash": hex_encode(&entry[..20]),
                "hash_type": entry[20], "flags": entry[21],
                "constraint_category": entry[22], "reserved": entry[23]
            })
        })
        .collect();
    values.insert_key(
        value_key!("image4.trustcache"),
        json!({
            "payload_type": "trca", "description": table.description,
            "version": 2, "uuid": hex_encode(table.uuid),
            "entry_count": entries.len(), "entries": entries
        }),
    );
}
