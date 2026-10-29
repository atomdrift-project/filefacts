//! .NET / CLR metadata: the COR20 header, the metadata root's streams, the
//! managed resources, and the IL behind every method.

mod il;
mod operands;

use goblin::pe::PE;
use serde_json::Value as JsonValue;

use super::layout::rva_to_file_offset;
use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::formats::common::{format_guid, put_str, put_u64};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::scan::entropy;
use crate::value_key;

pub(super) fn extract(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols: &mut crate::Symbols,
) {
    clr_metadata(pe, bytes, values, metrics);
    clr_resources(pe, bytes, metrics);
    clr_il_facts(pe, bytes, values, metrics, symbols);
}

/// .NET / CLR metadata extracted from the COR20 header and metadata root.
/// The presence of `pe.clr` (or any sub-key) IS the "is this a managed
/// binary?" signal — distinct from PE Authenticode signing, which a managed
/// binary may or may not carry.
///
/// The fields answer the *who / what* of a managed build and are chosen to be
/// stable diff anchors: version-to-version differential analysis surfaces a
/// changed strong-name state, MVID, metadata version, or stream set, which is
/// how a trojanized release is told apart from a genuine rebuild.
///
/// Values (raw structural reads — strings, raw words, identities):
/// - `pe.clr.runtime_version`      — COR20 `"<major>.<minor>"` runtime version
/// - `pe.clr.metadata_version`     — metadata-root version string (e.g. `v4.0.30319`)
/// - `pe.clr.flags`                — raw COR20 flags word
/// - `pe.clr.entry_point_token`    — managed entry-point token (absent for a DLL)
/// - `pe.clr.mvid`                 — Module Version ID GUID; a build-unique
///   identity anchor for correlating and diffing releases (WHO / WHAT)
/// - `pe.clr.streams`              — metadata stream-name inventory. A shipped
///   release carrying `#-` (uncompressed / edit-and-continue tables) or
///   `#Schema` instead of the normal `#~` is a post-compile IL-patch tell.
///
/// Metrics (decoded flag bits / sizes — typed for comparison matching):
/// - `pe.clr.is_il_only`, `pe.clr.is_native_entrypoint`,
///   `pe.clr.is_32bit_required`, `pe.clr.is_32bit_preferred` — 0/1 COR20 bits
/// - `pe.clr.strong_name_signed`   — 0/1 COMIMAGE_FLAGS_STRONGNAMESIGNED (WHO /
///   integrity). A genuine vendor SDK is strong-name signed; a source-rebuilt
///   clone that never had the private key is not, so `0` under a vendor brand
///   is a forgery / publisher-hijack tell — and a `1 -> 0` transition across
///   versions is a strong differential signal.
/// - `pe.clr.strong_name_signature_size` — strong-name signature blob size (>0 with
///   `strong_name_signed=0` = delay-signed or signature stripped)
fn clr_metadata(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(clr) = pe.clr_data.as_ref() else {
        return;
    };
    let hdr = &clr.cor20_header;
    // Raw structural reads (strings, raw words, identities) -> values.
    put_str(
        values,
        value_key!("pe.clr.runtime_version"),
        format!(
            "{}.{}",
            hdr.major_runtime_version, hdr.minor_runtime_version
        ),
    );
    let mdver = clr.metadata_header.version.trim_matches('\0').trim();
    if !mdver.is_empty() {
        put_str(values, value_key!("pe.clr.metadata_version"), mdver);
    }
    put_u64(values, value_key!("pe.clr.flags"), u64::from(hdr.flags));
    if hdr.entry_point_token_or_rva != 0 {
        put_u64(
            values,
            value_key!("pe.clr.entry_point_token"),
            u64::from(hdr.entry_point_token_or_rva),
        );
    }
    // Decoded flag bits and sizes are typed numbers -> metrics, so traits can
    // match them by comparison (e.g. `strong_name_signed max: 0`).
    let mut bit = |name: crate::MetricKey, v: bool| metrics.insert(name, f64::from(u8::from(v)));
    bit(metric!("pe.clr.is_il_only"), hdr.is_il_only());
    bit(
        metric!("pe.clr.is_native_entrypoint"),
        hdr.is_native_entrypoint(),
    );
    bit(metric!("pe.clr.is_32bit_required"), hdr.is_32bit_required());
    bit(
        metric!("pe.clr.is_32bit_preferred"),
        hdr.is_32bit_preferred(),
    );
    bit(
        metric!("pe.clr.strong_name_signed"),
        hdr.is_strong_name_signed(),
    );
    if hdr.strong_name_signature.size > 0 {
        metrics.insert(
            metric!("pe.clr.strong_name_signature_size"),
            f64::from(hdr.strong_name_signature.size),
        );
    }
    // Parse the ECMA-335 metadata root directly. goblin 0.10's CLR stream
    // helpers (`sections()`/`mvid()`/`storage_header`) mis-seed the walk, and
    // its `metadata_data` is sliced from file offset 0 (the MZ header) rather
    // than the metadata RVA — both unusable — so resolve the metadata directory
    // ourselves and parse from the `BSJB` root.
    let mdir = hdr.metadata;
    let md = rva_to_file_offset(pe, mdir.virtual_address).and_then(|base| {
        let end = base.saturating_add(mdir.size as usize).min(bytes.len());
        bytes.get(base..end)
    });
    if let Some((names, guid_stream)) = md.and_then(parse_clr_streams) {
        if !names.is_empty() {
            let arr = names.into_iter().map(JsonValue::String).collect();
            values.insert_key(value_key!("pe.clr.streams"), JsonValue::Array(arr));
        }
        // The module MVID is the first GUID in the `#GUID` heap (Module.Mvid == 1).
        if let (Some((goff, gsize)), Some(md)) = (guid_stream, md) {
            if gsize >= 16 {
                if let Some(mvid) = md
                    .get(goff..goff.saturating_add(16))
                    .and_then(|g| <&[u8; 16]>::try_from(g).ok())
                {
                    put_str(values, value_key!("pe.clr.mvid"), format_guid(mvid));
                }
            }
        }
    }
}

/// Managed references and IL are parsed as inert bytes, never through the CLR.
fn clr_il_facts(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols: &mut crate::output::Symbols,
) {
    let Some(clr) = pe.clr_data.as_ref() else {
        return;
    };
    let dir = clr.cor20_header.metadata;
    let Some(base) = rva_to_file_offset(pe, dir.virtual_address) else {
        return;
    };
    let Some(root) = base
        .checked_add(dir.size as usize)
        .and_then(|end| bytes.get(base..end))
    else {
        return;
    };
    let Some(result) = il::analyze(root, base, bytes, |rva| rva_to_file_offset(pe, rva)) else {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "clr-metadata",
            offset = base,
            len = root.len(),
            "CLR metadata tables did not parse; no IL facts"
        );
        return;
    };
    metrics.insert(metric!("pe.clr.method_count"), result.method_count as f64);
    metrics.insert(
        metric!("pe.clr.il_instruction_count"),
        result.instruction_count as f64,
    );
    metrics.insert(metric!("pe.clr.calli_count"), result.calli_count as f64);
    metrics.insert(
        metric!("pe.clr.calli_method_count"),
        result.calli_methods as f64,
    );
    metrics.insert(
        metric!("pe.clr.resolver_pointer_method_count"),
        result.resolver_pointer_methods as f64,
    );
    metrics.insert(
        metric!("pe.clr.resource_xor_method_count"),
        result.resource_xor_methods as f64,
    );
    values.insert_key(
        value_key!("pe.clr.il_scan"),
        serde_json::json!({
            "invalid_methods": result.invalid_methods,
            "truncated": result.truncated,
        }),
    );
    for reference in result.references {
        symbols.push(crate::Symbol::Import {
            name: reference.name,
            alias: None,
            library: reference.library,
            offset: Some(reference.offset as u64),
            ordinal: None,
        });
    }
    for method in result.methods {
        symbols.push(crate::Symbol::Function {
            name: method.name,
            offset: Some(method.offset as u64),
            complexity: None,
            callees: method.callees,
        });
    }
    for call in result.calls {
        // An arity comes from the metadata signature. Actual argument values
        // remain unknown: do not invent constants or value-flow relationships.
        if let Some(arity) = call.arity {
            symbols.push(crate::Symbol::Call {
                target: Some(call.name),
                args: vec![crate::Arg::Expression; arity],
                offset: Some(call.offset as u64),
            });
        }
    }
}

/// `(offset, size)` of a metadata heap, relative to the metadata blob.
type HeapRange = (usize, usize);

/// Parse the .NET metadata-root stream directory (ECMA-335 II.24.2.1) from the
/// blob beginning at the `BSJB` signature. Returns the stream names in order
/// and the `(offset, size)` of the `#GUID` heap (offsets relative to the blob
/// start). Returns `None` when the signature or layout is malformed.
fn parse_clr_streams(md: &[u8]) -> Option<(Vec<String>, Option<HeapRange>)> {
    let rd_u32 = |p: usize| u32_le(md, p).map(|v| v as usize);
    if md.get(0..4)? != b"BSJB" {
        return None;
    }
    let version_len = rd_u32(12)?;
    // Flags (u16) + Streams (u16) follow the 4-byte-padded version string.
    let mut p = 16usize.checked_add(version_len.checked_add(3)? & !3)?;
    let n_streams = u16_le(md, p + 2)?;
    p += 4;
    let mut names = Vec::new();
    let mut guid_stream = None;
    for _ in 0..n_streams {
        let s_off = rd_u32(p)?;
        let s_size = rd_u32(p + 4)?;
        p += 8;
        // Name: null-terminated ASCII, whole field padded to a 4-byte boundary.
        let start = p;
        while *md.get(p)? != 0 {
            p += 1;
        }
        let name = std::str::from_utf8(md.get(start..p)?).ok()?.to_string();
        if name == "#GUID" {
            guid_stream = Some((s_off, s_size));
        }
        names.push(name);
        p = start.checked_add(((p - start) + 1 + 3) & !3)?;
    }
    Some((names, guid_stream))
}

/// Measure the embedded managed (CLR) resources that the Win32 resource walk
/// never sees. The cor20 header's `Resources` directory points at a blob of
/// `[u32 little-endian length][bytes]` chunks (ECMA-335 II.25.3.3), one per
/// embedded resource, each starting at an 8-byte-aligned offset in the blob. We don't need the `ManifestResource`
/// metadata table — names aside, the bytes are all here — so we skip the whole
/// table/heap machinery and just walk the blob. The forensic point is entropy:
/// .NET crypters stash an encrypted second stage as a managed resource, which
/// shows up as a high-entropy chunk among the low-entropy `.resources` streams.
///
/// Emits `pe.clr.managed_resource_{count, max_entropy, max_size}`.
fn clr_resources(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    let Some(clr) = pe.clr_data.as_ref() else {
        return;
    };
    let dir = clr.cor20_header.resources;
    if dir.size == 0 {
        return;
    }
    let Some(base) = rva_to_file_offset(pe, dir.virtual_address) else {
        return;
    };
    let end = base.saturating_add(dir.size as usize).min(bytes.len());
    let Some(blob) = bytes.get(base..end) else {
        return;
    };

    let (count, max_entropy, max_size, entropy_span, size_span) = scan_resource_blob(blob);
    if count == 0 {
        return;
    }
    metrics.insert(metric!("pe.clr.managed_resource_count"), count as f64);
    if let Some(span) = entropy_span {
        let span = crate::output::Span::new(base as u64 + span.offset, span.len);
        metrics.insert_located(
            metric!("pe.clr.managed_resource_max_entropy"),
            max_entropy,
            [span],
        );
    } else {
        metrics.insert(metric!("pe.clr.managed_resource_max_entropy"), max_entropy);
    }
    if let Some(span) = size_span {
        let span = crate::output::Span::new(base as u64 + span.offset, span.len);
        metrics.insert_located(
            metric!("pe.clr.managed_resource_max_size"),
            max_size as f64,
            [span],
        );
    } else {
        metrics.insert(metric!("pe.clr.managed_resource_max_size"), max_size as f64);
    }
}

/// Walk a CLR resources blob (`[u32 len][bytes]` chunks) and return
/// `(count, max_entropy, max_size, entropy_span, size_span)`. A length that
/// runs past the blob stops the walk — a corrupt or non-consecutive layout
/// yields a short count, never a panic or over-read.
fn scan_resource_blob(
    blob: &[u8],
) -> (
    u64,
    f64,
    u64,
    Option<crate::output::Span>,
    Option<crate::output::Span>,
) {
    let (mut count, mut max_entropy, mut max_size, mut entropy_span, mut size_span, mut p) =
        (0u64, 0.0f64, 0u64, None, None, 0usize);
    while p + 4 <= blob.len() {
        let Some(len) = u32_le(blob, p) else {
            break;
        };
        let len = len as usize;
        p += 4;
        if len == 0 {
            break;
        }
        let Some(chunk) = blob.get(p..p + len) else {
            break;
        };
        let chunk_entropy = entropy::shannon(chunk);
        if chunk_entropy > max_entropy {
            max_entropy = chunk_entropy;
            entropy_span = Some(crate::output::Span::new(p as u64, len as u64));
        }
        if len as u64 > max_size {
            max_size = len as u64;
            size_span = Some(crate::output::Span::new(p as u64, len as u64));
        }
        count += 1;
        // Managed resource offsets are aligned to eight bytes. Reading the
        // padding as the next length terminates early (zero padding) or
        // invents a malformed length, hiding subsequent resource streams.
        p = (p + len + 7) & !7;
    }
    (count, max_entropy, max_size, entropy_span, size_span)
}

#[cfg(test)]
mod tests;
