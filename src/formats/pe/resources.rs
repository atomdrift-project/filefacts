//! The resource directory: its type inventory, and the version-info and
//! manifest resources inside it.

use goblin::pe::PE;
use serde_json::Value as JsonValue;

use crate::formats::common::put_u64;
use crate::metric;
use crate::output::{Errors, Metrics, Values};
use crate::value_key;

pub(super) fn extract(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    let Some(rd) = pe.resource_data.as_ref() else {
        return;
    };
    // The resource walker is lazy and slices with unchecked header offsets —
    // packed Windows malware regularly panics inside `entries()`. Only that
    // walk runs under the guard: it is drained into plain ids, and everything
    // derived from them runs outside, so a panic in our own code is never
    // blamed on goblin and a goblin panic cannot leave the resource facts
    // half-written.
    match crate::panic_guard::catch_infallible(|| {
        rd.entries()
            .flatten()
            .map(|e| e.id())
            .collect::<Vec<Option<u16>>>()
    }) {
        Ok(ids) => resource_types(&ids, values, metrics),
        Err(msg) => {
            tracing::debug!(
                target: "filefacts::pe",
                format = "pe",
                stage = "resource-walk",
                error = %msg,
                "resource directory walk panicked"
            );
            errors.record_panic(crate::Stage::PeResourceWalk, msg);
            metrics.insert(metric!("pe.resource_walk_panicked"), 1.0);
        }
    }
    // The rest reads fields goblin parsed eagerly, so it survives a walker
    // panic. The resource directory's TimeDateStamp is set by the resource
    // compiler at link time and is often stable across rebuilds, so a change
    // between releases of an otherwise-stable binary is a tampering signal.
    let ts = rd.image_resource_directory.time_date_stamp;
    if ts != 0 {
        put_u64(values, value_key!("pe.resource_timestamp"), u64::from(ts));
    }
    // Presence comes from the directory itself, distinct from whether the
    // version or manifest decoders below found anything in a malformed one.
    if let Some(ref vi) = rd.version_info {
        metrics.insert(metric!("pe.has_version_info"), 1.0);
        super::version_info::extract(vi, bytes, values, metrics);
    }
    if let Some(ref md) = rd.manifest_data {
        metrics.insert(metric!("pe.has_manifest"), 1.0);
        // goblin's resource parser returns slices borrowed from the PE
        // buffer, so the pointer difference maps the manifest back to its
        // bytes on disk; a slice from anywhere else gets no offset rather
        // than an invalid one.
        let (base, start) = (bytes.as_ptr().addr(), md.data.as_ptr().addr());
        let offset = (start >= base && start + md.data.len() <= base + bytes.len())
            .then(|| (start - base) as u64);
        super::manifest::extract(md.data, offset, values);
    }
}

/// Resource-directory facts from the top-level entry ids (`None` for a
/// named entry), as drained from goblin's walker.
fn resource_types(ids: &[Option<u16>], values: &mut Values, metrics: &mut Metrics) {
    // Resource count is the raw entry total — duplicates allowed.
    metrics.insert(metric!("pe.resource_count"), ids.len() as f64);

    // RT_ICON (3) and RT_GROUP_ICON (14), counted apart from the total so
    // icon presence reads on its own.
    let icon_count = ids.iter().filter(|id| matches!(id, Some(3 | 14))).count();
    if icon_count > 0 {
        metrics.insert(metric!("pe.icon_count"), icon_count as f64);
    }

    // `pe.resource_types[]` is the deduplicated list of canonical `RT_*`
    // names, sorted by numeric id rather than name, so the order is stable
    // although many ids collapse to "RT_UNKNOWN".
    let type_ids: std::collections::BTreeSet<u16> = ids.iter().flatten().copied().collect();
    if !type_ids.is_empty() {
        let names: Vec<JsonValue> = type_ids
            .iter()
            .map(|&id| JsonValue::String(rt_name(id).to_string()))
            .collect();
        values.insert_key(value_key!("pe.resource_types"), JsonValue::Array(names));
    }
}

/// Map a top-level resource directory `id` to its `RT_*` constant
/// name. Unknown / vendor-private types collapse to `RT_UNKNOWN`.
fn rt_name(id: u16) -> &'static str {
    // From winuser.h `RT_*` and verrsrc.h.
    match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => "RT_UNKNOWN",
    }
}

#[cfg(test)]
mod tests;
