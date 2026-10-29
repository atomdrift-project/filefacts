//! Bounded syntax facts for Batch command sites. These are source text, not
//! expanded argv: CMD quoting, percent expansion and program-specific parsing
//! must not be guessed by the producer. Consumers can recognize fixed recipes.
use super::visit::{NodeIds, Visit};
use crate::{Values, value_key};

const MAX_SITES: usize = 128;
const MAX_SITE_BYTES: usize = 65_536;
const MAX_BYTES: usize = 1024 * 1024;

/// Every well-formed `cmd` node the shared walk ([`super::visit`]) reaches,
/// in source order.
#[derive(Default)]
pub(super) struct Collector {
    sites: Vec<serde_json::Value>,
    bytes: usize,
    truncated: bool,
}

impl Collector {
    pub(super) fn enter(&mut self, visit: &Visit<'_>, source: &str, ids: &NodeIds) {
        let node = visit.node;
        if !ids.batch_command.contains(visit.kind_id) || node.has_error() {
            return;
        }
        let Some(name) = node.named_child(0).filter(|n| n.kind() == "command_name") else {
            return;
        };
        let (Some(name_text), Some(text)) =
            (source.get(name.byte_range()), source.get(node.byte_range()))
        else {
            return;
        };
        if self.sites.len() == MAX_SITES
            || text.len() > MAX_SITE_BYTES
            || self.bytes.saturating_add(text.len()) > MAX_BYTES
        {
            if !self.truncated {
                tracing::debug!(
                    target: "filefacts::source",
                    format = "batch",
                    offset = node.start_byte(),
                    len = text.len(),
                    "batch command sites: budget reached; later sites omitted"
                );
            }
            self.truncated = true;
            return;
        }
        self.bytes += text.len();
        self.sites.push(serde_json::json!({"name": name_text, "text": text,
            "offset": node.start_byte(), "name_offset": name.start_byte(), "name_end": name.end_byte()}));
    }

    /// Write `source.batch.command_sites*`.
    pub(super) fn emit(self, values: &mut Values) {
        if !self.sites.is_empty() || self.truncated {
            values.insert_key(value_key!("source.batch.command_sites"), self.sites.into());
        }
        if self.truncated {
            values.insert_key(
                value_key!("source.batch.command_sites_truncated"),
                true.into(),
            );
        }
    }
}

#[cfg(test)]
mod tests;
