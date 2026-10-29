//! AcroForm fields and the metrics derived from them.

use std::collections::HashMap;
use std::hash::Hash;

use serde_json::{Value as JsonValue, json};

use super::lex::{find_info_value, has_name, skip_while, truncate};
use super::objects::DictRegion;
use crate::metric;
use crate::output::Metrics;

/// Upper bound on how many form-field rects we run the O(n²)
/// overlap check across. Real PDFs hold a handful per page; with
/// thousands of widgets the pairwise pass dominates parse time.
const MAX_OVERLAP_RECTS: usize = 2_000;

/// One AcroForm field: `/T` name, `/FT` type (`Tx` text, `Btn` button,
/// `Ch` choice, `Sig` signature), `/Rect` bounding box and `/V` value.
#[derive(Debug, Default)]
pub(super) struct FormField {
    object_id: Option<u32>,
    name: Option<String>,
    field_type: Option<String>,
    rect: Option<String>,
    value: Option<String>,
}

impl FormField {
    pub(super) fn to_json(&self) -> JsonValue {
        let mut entry = serde_json::Map::new();
        if let Some(id) = self.object_id {
            entry.insert("object_id".into(), json!(id));
        }
        for (key, field) in [
            ("name", &self.name),
            ("field_type", &self.field_type),
            ("rect", &self.rect),
            ("value", &self.value),
        ] {
            if let Some(text) = field {
                entry.insert(key.into(), JsonValue::String(text.clone()));
            }
        }
        JsonValue::Object(entry)
    }
}

/// Collect AcroForm fields: `/Subtype /Widget` dictionaries, and field
/// dictionaries that carry `/FT` without being widgets themselves (the
/// parent of a widget). Indirect `/V` references are not followed.
pub(super) fn scan_form_fields(bytes: &[u8], dict_regions: &[DictRegion]) -> Vec<FormField> {
    let mut out = Vec::new();
    for region in dict_regions {
        let dict = region.dict(bytes);
        let field_type = find_info_value(dict, b"/FT");
        if field_type.is_none() && !has_name(dict, b"Subtype", b"Widget") {
            continue;
        }
        out.push(FormField {
            object_id: region.obj_id,
            name: find_info_value(dict, b"/T"),
            field_type: field_type.map(|ft| ft.trim_start_matches('/').to_string()),
            rect: find_rect_value(dict, b"/Rect"),
            value: find_info_value(dict, b"/V").map(|v| truncate(&v, 200)),
        });
    }
    out
}

/// Read a `/Rect [a b c d]` array as a single space-joined
/// string. Numbers can be int or float; we don't reformat them.
fn find_rect_value(bytes: &[u8], key: &[u8]) -> Option<String> {
    let after_idx = memchr::memmem::find(bytes, key)? + key.len();
    if bytes
        .get(after_idx)
        .is_some_and(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let cursor = skip_while(bytes, after_idx, u8::is_ascii_whitespace);
    let array = bytes.get(cursor..)?.strip_prefix(b"[")?;
    let end = array.iter().position(|&b| b == b']')?;
    let inner = std::str::from_utf8(array.get(..end)?).ok()?;
    Some(inner.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The rect's four numbers, normalized to `[x_lo, y_lo, x_hi, y_hi]`:
/// some producers swap the pairs.
fn parse_rect(s: &str) -> Option<[f64; 4]> {
    let parts: Vec<f64> = s
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let [x0, y0, x1, y1] = parts.as_slice() else {
        return None;
    };
    Some([x0.min(*x1), y0.min(*y1), x0.max(*x1), y0.max(*y1)])
}

/// Occurrences beyond the first, summed over every key.
fn extra_occurrences<K: Eq + Hash>(counts: &HashMap<K, usize>) -> f64 {
    counts.values().map(|&c| c.saturating_sub(1)).sum::<usize>() as f64
}

/// Hidden-zero-rect, duplicate-name / duplicate-rect /
/// duplicate-name-and-rect, overlapping-pair and longest-value metrics
/// over the form fields.
pub(super) fn derive_form_field_metrics(fields: &[FormField], metrics: &mut Metrics) {
    if fields.is_empty() {
        return;
    }
    let mut by_name: HashMap<&str, usize> = HashMap::new();
    let mut by_rect: HashMap<&str, usize> = HashMap::new();
    let mut by_name_rect: HashMap<(&str, &str), usize> = HashMap::new();
    let mut hidden_zero_rect = 0_usize;
    let mut max_value_len = 0_usize;
    let mut rects: Vec<[f64; 4]> = Vec::with_capacity(fields.len());

    for f in fields {
        let name = f.name.as_deref().filter(|n| !n.is_empty());
        let rect = f.rect.as_deref().filter(|r| !r.is_empty());
        if let Some(name) = name {
            *by_name.entry(name).or_default() += 1;
        }
        if let Some(rect) = rect {
            *by_rect.entry(rect).or_default() += 1;
        }
        if let (Some(name), Some(rect)) = (name, rect) {
            *by_name_rect.entry((name, rect)).or_default() += 1;
        }
        if let Some(r) = rect.and_then(parse_rect) {
            // A signature widget with no appearance box is how an invisible
            // certification is stored. It is not a hidden payload field.
            let signature = f
                .field_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("Sig"));
            if r == [0.0, 0.0, 0.0, 0.0] && !signature {
                hidden_zero_rect += 1;
            }
            rects.push(r);
        }
        max_value_len = max_value_len.max(f.value.as_deref().map_or(0, str::len));
    }

    metrics.insert(
        metric!("pdf.duplicate_form_name_count"),
        extra_occurrences(&by_name),
    );
    metrics.insert(
        metric!("pdf.duplicate_form_rect_count"),
        extra_occurrences(&by_rect),
    );
    metrics.insert(
        metric!("pdf.duplicate_form_name_rect_count"),
        extra_occurrences(&by_name_rect),
    );
    metrics.insert(
        metric!("pdf.hidden_zero_rect_field_count"),
        hidden_zero_rect as f64,
    );
    metrics.insert(
        metric!("pdf.decoded_form_value_max_length"),
        max_value_len as f64,
    );

    // Overlapping-pair count: an O(n²) intersection check, capped at
    // `MAX_OVERLAP_RECTS` widgets so an adversarial AcroForm with
    // hundreds of thousands of fields can't dominate parse time —
    // anything beyond the cap is itself the forensic signal.
    let window = rects.get(..MAX_OVERLAP_RECTS).unwrap_or(&rects);
    let mut overlapping = 0_usize;
    for (i, a) in window.iter().enumerate() {
        for b in window.iter().skip(i + 1) {
            if a[0] < b[2] && b[0] < a[2] && a[1] < b[3] && b[1] < a[3] {
                overlapping += 1;
            }
        }
    }
    metrics.insert(
        metric!("pdf.overlapping_form_field_pair_count"),
        overlapping as f64,
    );
    if rects.len() > MAX_OVERLAP_RECTS {
        tracing::debug!(
            target: "filefacts::pdf",
            stage = "form-fields",
            rects = rects.len(),
            cap = MAX_OVERLAP_RECTS,
            "overlap check limited to the first rects"
        );
        metrics.insert(metric!("pdf.overlap_check_truncated"), 1.0);
    }
}
