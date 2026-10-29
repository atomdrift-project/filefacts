//! PE side-by-side manifest (RT_MANIFEST) extractor.
//!
//! Win32 binaries embed an XML manifest in the `RT_MANIFEST` resource
//! that declares the OS / DPI / privilege requirements the loader
//! applies before transferring control. The forensically interesting
//! values:
//!
//! - `requestedExecutionLevel` (`asInvoker`, `requireAdministrator`,
//!   `highestAvailable`) — privilege the binary expects.
//! - `uiAccess` — UI-automation bypass capability.
//! - `supportedOS@Id` GUID list — Windows versions the binary
//!   declares support for.
//! - `dpiAware` / `dpiAwareness` — high-DPI handling.
//!
//! The manifest is parsed as XML, as the loader parses it: a comment, CDATA
//! section or attribute value that merely *contains* `requestedExecutionLevel`
//! is not one, so a decoy placed before the real element cannot hide it.
//! Elements match by local name, whatever namespace prefix (`asmv3:`) they
//! carry. A manifest that is not well-formed XML is one the loader rejects;
//! it yields `pe.manifest.parse_error` instead of guessed values.

use roxmltree::{Document, Node, ParsingOptions};
use serde_json::Value as JsonValue;

use crate::formats::common::put_str;
use crate::output::{ValueKey, Values};
use crate::value_key;

/// Nodes one manifest may hold. Real manifests have tens; the cap bounds the
/// tree a hostile resource can make the parser build.
const MAX_NODES: u32 = 64 * 1024;

/// Extract the manifest facts. `file_offset` is where the resource's bytes
/// start in the file, when known, so each value is located exactly.
pub(super) fn extract(manifest_bytes: &[u8], file_offset: Option<u64>, values: &mut Values) {
    let Ok(text) = std::str::from_utf8(manifest_bytes) else {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "manifest",
            len = manifest_bytes.len(),
            "manifest is not UTF-8; not parsed"
        );
        return;
    };
    // Offsets stay relative to the resource, so a byte-order mark is
    // stepped over rather than sliced away.
    let bom = if text.starts_with('\u{FEFF}') { 3 } else { 0 };
    let options = ParsingOptions {
        nodes_limit: MAX_NODES,
        ..ParsingOptions::default()
    };
    let doc = match Document::parse_with_options(&text[bom..], options) {
        Ok(doc) => doc,
        Err(e) => {
            tracing::debug!(
                target: "filefacts::pe",
                format = "pe",
                stage = "manifest",
                len = manifest_bytes.len(),
                error = %e,
                "manifest is not well-formed XML"
            );
            put_str(values, value_key!("pe.manifest.parse_error"), e.to_string());
            return;
        }
    };
    let mut out = Located {
        values,
        base: file_offset.map(|base| base.saturating_add(bom as u64)),
    };
    let first = |name: &str| doc.descendants().find(|n| n.has_tag_name(name));

    if let Some(level) = first("requestedExecutionLevel") {
        out.attribute(
            level,
            "level",
            value_key!("pe.manifest.requested_execution_level"),
            value_key!("pe.manifest.requested_execution_level_offset"),
        );
        out.attribute(
            level,
            "uiAccess",
            value_key!("pe.manifest.ui_access"),
            value_key!("pe.manifest.ui_access_offset"),
        );
    }

    // Manifests can carry several `<assemblyIdentity>` nodes — one at the
    // root and one inside each `<dependentAssembly>`. The first in document
    // order is the canonical "this assembly" record; later ones are
    // dependency declarations.
    if let Some(identity) = first("assemblyIdentity") {
        out.attribute(
            identity,
            "name",
            value_key!("pe.manifest.assembly_identity.name"),
            value_key!("pe.manifest.assembly_identity.name_offset"),
        );
        out.attribute(
            identity,
            "version",
            value_key!("pe.manifest.assembly_identity.version"),
            value_key!("pe.manifest.assembly_identity.version_offset"),
        );
    }

    // `<dependentAssembly><assemblyIdentity name="…" version="…"/>`, each as
    // `"name@version"` to mirror the `elf.needed_versions` shape.
    let deps: Vec<JsonValue> = doc
        .descendants()
        .filter(|n| n.has_tag_name("dependentAssembly"))
        .filter_map(|dep| {
            let identity = dep
                .descendants()
                .find(|n| n.has_tag_name("assemblyIdentity"))?;
            let name = identity.attribute("name").filter(|n| !n.is_empty())?;
            Some(JsonValue::String(match identity.attribute("version") {
                Some(version) if !version.is_empty() => format!("{name}@{version}"),
                _ => name.to_string(),
            }))
        })
        .collect();
    if !deps.is_empty() {
        out.values.insert_key(
            value_key!("pe.manifest.dependencies"),
            JsonValue::Array(deps),
        );
    }

    // Windows OS GUIDs, e.g. `{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}` for
    // Windows 10/11.
    let supported: Vec<JsonValue> = doc
        .descendants()
        .filter(|n| n.has_tag_name("supportedOS"))
        .filter_map(|n| n.attribute("Id"))
        .map(|id| JsonValue::String(id.to_string()))
        .collect();
    if !supported.is_empty() {
        out.values.insert_key(
            value_key!("pe.manifest.supported_os"),
            JsonValue::Array(supported),
        );
    }

    // Free-text `<description>`, and the `<windowsSettings>` switches,
    // which are element text rather than attributes.
    for (name, key, offset_key) in [
        (
            "description",
            value_key!("pe.manifest.description"),
            value_key!("pe.manifest.description_offset"),
        ),
        (
            "dpiAware",
            value_key!("pe.manifest.dpi_aware"),
            value_key!("pe.manifest.dpi_aware_offset"),
        ),
        (
            "dpiAwareness",
            value_key!("pe.manifest.dpi_awareness"),
            value_key!("pe.manifest.dpi_awareness_offset"),
        ),
        (
            "longPathAware",
            value_key!("pe.manifest.long_path_aware"),
            value_key!("pe.manifest.long_path_aware_offset"),
        ),
        (
            "autoElevate",
            value_key!("pe.manifest.auto_elevate"),
            value_key!("pe.manifest.auto_elevate_offset"),
        ),
    ] {
        if let Some(node) = first(name) {
            out.text(node, key, offset_key);
        }
    }
}

/// The values sink, with the resource's file offset for locating each value.
struct Located<'v> {
    values: &'v mut Values,
    base: Option<u64>,
}

impl Located<'_> {
    /// Store `value` at `key` and, when the resource's file offset is known,
    /// the file offset of the value's first byte at `offset_key`. The offset
    /// is omitted when the resource could not be mapped back to the file: no
    /// location is safer than a guessed one.
    fn put(&mut self, key: ValueKey, offset_key: ValueKey, value: &str, at: usize) {
        put_str(self.values, key, value);
        if let Some(base) = self.base {
            self.values.insert_key(
                offset_key,
                JsonValue::Number(base.saturating_add(at as u64).into()),
            );
        }
    }

    /// The element's attribute `name`.
    fn attribute(&mut self, node: Node<'_, '_>, name: &str, key: ValueKey, offset_key: ValueKey) {
        if let Some(attr) = node.attributes().find(|a| a.name() == name) {
            self.put(key, offset_key, attr.value(), attr.range_value().start);
        }
    }

    /// The element's text, trimmed, located at its first non-blank byte.
    fn text(&mut self, node: Node<'_, '_>, key: ValueKey, offset_key: ValueKey) {
        let Some(child) = node.children().find(Node::is_text) else {
            return;
        };
        let raw = child.text().unwrap_or_default();
        let value = raw.trim();
        if !value.is_empty() {
            let leading = raw.len() - raw.trim_start().len();
            self.put(key, offset_key, value, child.range().start + leading);
        }
    }
}

#[cfg(test)]
mod tests;
