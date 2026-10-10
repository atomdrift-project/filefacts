use super::*;

fn extract_pdf(bytes: &[u8]) -> (Values, Metrics) {
    let mut v = Values::new();
    let mut s = Strings::default();
    let mut m = Metrics::new();
    extract(bytes, &mut v, &mut s, &mut m);
    (v, m)
}

#[test]
fn parses_version_from_header() {
    let pdf = b"%PDF-1.7\n%%EOF\n";
    let (v, m) = extract_pdf(pdf);
    assert_eq!(
        v.get("pdf.header.version").and_then(|x| x.as_str()),
        Some("1.7")
    );
    assert_eq!(m.get("pdf.header_count"), Some(1.0));
    assert_eq!(m.get("pdf.eof_count"), Some(1.0));
}

#[test]
fn extracts_info_title() {
    let pdf = b"%PDF-1.4\n4 0 obj << /Title (Hello World) /Producer (test) >> endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    assert_eq!(
        v.get("pdf.info.title").and_then(|x| x.as_str()),
        Some("Hello World")
    );
    assert_eq!(
        v.get("pdf.info.producer").and_then(|x| x.as_str()),
        Some("test")
    );
}

#[test]
fn detects_javascript_action_count() {
    let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS (app.alert('hi')) >> endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    // The filefacts extractor reports the count via metrics —
    // the action-detail array stays with cleave's PDF parser.
    assert_eq!(m.get("pdf.action_count"), Some(1.0));
}

/// Inline-string `/JS (literal)` surfaces in `pdf.javascript[]`
/// with the literal as its full content — downstream consumers
/// extract this as a virtual JS sub-file.
#[test]
fn javascript_payload_inline_literal() {
    let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS (app.alert('hi')) >> endobj\n%%EOF";
    let (v, m) = extract_pdf(pdf);
    let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
    assert_eq!(js.len(), 1);
    assert_eq!(js[0]["source"].as_str(), Some("object:5"));
    assert_eq!(js[0]["content"].as_str(), Some("app.alert('hi')"));
    assert_eq!(js[0]["content_bytes"].as_u64(), Some(15));
    assert!(js[0].get("target_object_id").is_none());
    assert_eq!(m.get("pdf.javascript_count"), Some(1.0));
    assert_eq!(m.get("pdf.javascript_total_bytes"), Some(15.0));
}

/// `/JS <hex>` surfaces with the decoded hex string as its
/// content. Hex strings are how some authoring tools encode
/// non-ASCII JS or obfuscate the payload past simple grep scans.
#[test]
fn javascript_payload_hex_string() {
    // <6170703D31> = "app=1" — trailing-whitespace trimming in
    // read_hex_string drops the canonical "app " sample, so we
    // pick a no-trailing-space string for the assertion.
    let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS <6170703D31> >> endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
    assert_eq!(js[0]["content"].as_str(), Some("app=1"));
}

/// `/JS N N R` follows the indirect reference into a string-
/// object body and surfaces its content — the target object id
/// is recorded so analysts can map JS back to a specific obj.
#[test]
fn javascript_payload_indirect_string_object() {
    let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript /JS 7 0 R >> endobj\n7 0 obj (var x = 1;) endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
    assert_eq!(js.len(), 1);
    assert_eq!(js[0]["target_object_id"].as_u64(), Some(7));
    assert_eq!(js[0]["content"].as_str(), Some("var x = 1;"));
}

/// Bare `/JSON` / `/JavaScript` name tokens (the action-type
/// declaration, not the key form) must not produce a payload.
#[test]
fn javascript_payload_ignores_name_only_tokens() {
    // `/JavaScript` is a name value here, not a `/JS` key.
    let pdf = b"%PDF-1.5\n5 0 obj << /S /JavaScript >> endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    assert!(v.get("pdf.javascript").is_none());
}

#[test]
fn flags_encrypt_and_linearized() {
    let pdf = b"%PDF-1.7\n<< /Linearized 1 /Encrypt 7 0 R >>\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let flags = v.get("pdf.shape.flags").and_then(|x| x.as_array()).unwrap();
    let strings: Vec<&str> = flags.iter().filter_map(|x| x.as_str()).collect();
    assert!(strings.contains(&"encrypted"));
    assert!(strings.contains(&"linearized"));
}

#[test]
fn catalog_acroform_xfa() {
    let pdf = b"%PDF-1.4\n<< /AcroForm << /XFA [1 0 R] >> >>\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let features = v
        .get("pdf.catalog.features")
        .and_then(|x| x.as_array())
        .unwrap();
    let strings: Vec<&str> = features.iter().filter_map(|x| x.as_str()).collect();
    assert!(strings.contains(&"acroform"));
    assert!(strings.contains(&"xfa"));
}

#[test]
fn stacked_pdf_headers_counted() {
    let pdf = b"%PDF-1.4\nfoo\n%PDF-1.7\nbar\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.header_count"), Some(2.0));
}

#[test]
fn extracts_filter_chain() {
    let pdf = b"%PDF-1.4\n7 0 obj << /Filter /FlateDecode /Length 0 >> stream\nendstream endobj\n8 0 obj << /Filter [/ASCIIHexDecode /FlateDecode] /Length 0 >> stream\nendstream endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let chains = v
        .get("pdf.filter_chains")
        .and_then(|x| x.as_array())
        .unwrap();
    let strings: Vec<&str> = chains.iter().filter_map(|x| x.as_str()).collect();
    assert!(strings.contains(&"FlateDecode"));
    assert!(strings.contains(&"ASCIIHexDecode,FlateDecode"));
}

#[test]
fn extracts_form_field() {
    let pdf = b"%PDF-1.4\n9 0 obj << /Type /Annot /Subtype /Widget /T (username) /FT /Tx /Rect [10 20 100 40] /V (alice) >> endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let fields = v.get("pdf.form_fields").and_then(|x| x.as_array()).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["name"].as_str(), Some("username"));
    assert_eq!(fields[0]["field_type"].as_str(), Some("Tx"));
    assert_eq!(fields[0]["rect"].as_str(), Some("10 20 100 40"));
    assert_eq!(fields[0]["value"].as_str(), Some("alice"));
}

#[test]
fn extracts_embedded_file_with_size() {
    // Filespec object references stream object 11; stream object
    // declares `/Length 42`.
    let pdf = b"%PDF-1.4\n10 0 obj << /Type /Filespec /F (attachment.txt) /EF << /F 11 0 R >> >> endobj\n11 0 obj << /Length 42 /Type /EmbeddedFile >> stream\nXXX endstream endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    let files = v
        .get("pdf.embedded_files")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["filename"].as_str(), Some("attachment.txt"));
    assert_eq!(files[0]["size"].as_u64(), Some(42));
}

#[test]
fn no_header_is_silent() {
    let bytes = b"not a PDF";
    let (v, m) = extract_pdf(bytes);
    assert!(v.get("pdf.header.version").is_none());
    assert!(m.get("pdf.header_count").is_none());
}

// ------------------------------------------------------------------
// Phase 1B derived-metric tests
// ------------------------------------------------------------------

#[test]
fn leading_bytes_before_header_counted() {
    let pdf = b"GARBAGE_LEADING_NOISE_%PDF-1.7\n%%EOF\n";
    let (_, m) = extract_pdf(pdf);
    // `GARBAGE_LEADING_NOISE_` is 22 bytes; `%PDF-` starts at 22.
    assert_eq!(m.get("pdf.leading_bytes"), Some(22.0));
}

#[test]
fn signature_object_counted() {
    let pdf = b"%PDF-1.7\n5 0 obj << /Type /Sig /Filter /Adobe.PPKLite >> endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert!(m.get("pdf.signature_object_count").unwrap() >= 1.0);
}

#[test]
fn signed_incremental_update_counted() {
    // Two %%EOF markers + a signature object → 1 incremental update.
    let pdf = b"%PDF-1.7\n5 0 obj << /Type /Sig >> endobj\n%%EOF\n6 0 obj << >> endobj\n%%EOF\n";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.signed_incremental_update_count"), Some(1.0));
}

#[test]
fn duplicate_form_name_counted() {
    let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (name1) /FT /Tx /Rect [0 0 10 10] >> endobj\n\
            11 0 obj << /Subtype /Widget /T (name1) /FT /Tx /Rect [50 50 60 60] >> endobj\n\
            12 0 obj << /Subtype /Widget /T (name2) /FT /Tx /Rect [100 100 110 110] >> endobj\n\
            %%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.duplicate_form_name_count"), Some(1.0));
}

#[test]
fn duplicate_form_rect_counted() {
    let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (a) /FT /Tx /Rect [0 0 10 10] >> endobj\n\
            11 0 obj << /Subtype /Widget /T (b) /FT /Tx /Rect [0 0 10 10] >> endobj\n\
            %%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.duplicate_form_rect_count"), Some(1.0));
}

#[test]
fn signature_zero_rect_is_not_a_hidden_field() {
    let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (Signature1) /FT /Sig /Rect [0 0 0 0] >> endobj\n\
            %%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.hidden_zero_rect_field_count"), Some(0.0));
}

#[test]
fn upload_directory_uris_counted() {
    let pdf = b"%PDF-1.7\n\
3 0 obj << /S /URI /URI (https://events.example/wp-content/uploads/2017/12/slides.pdf) >> endobj\n\
4 0 obj << /S /URI /URI (https://example.invalid/system/files/webform/x) >> endobj\n\
5 0 obj << /S /URI /URI (https://kernel.org/doc/html/latest/bpf/verifier.html) >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.upload_directory_uri_count"), Some(2.0));
}

#[test]
fn hidden_zero_rect_field_counted() {
    let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (hidden) /FT /Tx /Rect [0 0 0 0] /V (secret) >> endobj\n\
            11 0 obj << /Subtype /Widget /T (visible) /FT /Tx /Rect [10 10 100 100] /V (x) >> endobj\n\
            %%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.hidden_zero_rect_field_count"), Some(1.0));
}

#[test]
fn decoded_form_value_max_len_reported() {
    let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (short) /FT /Tx /Rect [0 0 10 10] /V (hi) >> endobj\n\
            11 0 obj << /Subtype /Widget /T (long) /FT /Tx /Rect [0 0 10 10] /V (this is a longer value) >> endobj\n\
            %%EOF";
    let (_, m) = extract_pdf(pdf);
    assert!(m.get("pdf.decoded_form_value_max_length").unwrap() >= 22.0);
}

#[test]
fn overlapping_form_field_pair_counted() {
    // Two rects that overlap, one non-overlapping → 1 pair.
    let pdf = b"%PDF-1.4\n\
            10 0 obj << /Subtype /Widget /T (a) /FT /Tx /Rect [0 0 50 50] >> endobj\n\
            11 0 obj << /Subtype /Widget /T (b) /FT /Tx /Rect [25 25 75 75] >> endobj\n\
            12 0 obj << /Subtype /Widget /T (c) /FT /Tx /Rect [200 200 250 250] >> endobj\n\
            %%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.overlapping_form_field_pair_count"), Some(1.0));
}

#[test]
fn risky_feature_score_aggregates_signals() {
    let pdf = b"%PDF-1.4\n<< /AcroForm << /XFA [1 0 R] >> /OpenAction << /JS (app.alert(1)) >> >>\n5 0 obj << /S /JavaScript /JS (app.alert('x')) >> endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    let score = m.get("pdf.risky_feature_score").unwrap();
    // openaction (20) + xfa (20) + acroform (5) + 1 action (1)
    // — exact arithmetic depends on action attribution; the
    // floor is 40 for the catalog features alone.
    assert!(score >= 40.0, "risky_feature_score = {score}");
}

#[test]
fn stream_metrics_count_anomalies() {
    // Stream with no /Length declared → missing_length.
    let pdf = b"%PDF-1.5\n5 0 obj << /Filter /FlateDecode >> stream\nXYZ\nendstream endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.stream_missing_length_count"), Some(1.0));
}

#[test]
fn additional_actions_needs_a_real_dictionary_key() {
    // `/AA` inside compressed image data is two letters, not an action.
    let mut pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n".to_vec();
    pdf.extend_from_slice(
        b"2 0 obj << /Length 8 >> stream\n\xb5\x89/AA\x95\x1cv\nendstream endobj\n",
    );
    let (v, _) = extract_pdf(&pdf);
    let features = v
        .get("pdf.catalog")
        .and_then(|c| c.get("features"))
        .and_then(|f| f.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(!features.contains(&"additional_actions"), "{features:?}");

    // The real key still registers.
    let real = b"%PDF-1.4\n1 0 obj << /Type /Catalog /AA << /O 3 0 R >> >> endobj\n";
    let (v2, _) = extract_pdf(real);
    let f2 = v2
        .get("pdf.catalog")
        .and_then(|c| c.get("features"))
        .and_then(|f| f.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(f2.contains(&"additional_actions"), "{f2:?}");
}

#[test]
fn stream_length_mismatch_detected() {
    // /Length declares 10 bytes but body is 3 bytes.
    let pdf = b"%PDF-1.5\n5 0 obj << /Length 10 /Filter /FlateDecode >> stream\nXYZ\nendstream endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert!(m.get("pdf.stream_length_mismatch_count").unwrap() >= 1.0);
}

#[test]
fn direct_length_allows_adjacent_endstream_marker() {
    // The body ends with `s`, yielding raw bytes `sendstream`.
    // Direct /Length still identifies the stream boundary exactly.
    let pdf = b"%PDF-1.5\n5 0 obj << /Length 4 /Filter /FlateDecode >> stream\nABCsendstream endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.stream_length_mismatch_count"), Some(0.0));
}

/// A tagged PDF ends with thousands of stream-less structure objects.
/// Each one used to search for a `stream` token to end-of-file, which
/// made region collection quadratic: 5 MB manuals took 80–400 s on the
/// fleet (2026-09-06). The search is bounded by the object's own
/// `endobj` now, and the walk is linear.
#[test]
fn dict_regions_are_linear_in_stream_less_objects() {
    let mut pdf =
        b"%PDF-1.7\n1 0 obj\n<< /Length 5 >>\nstream\nhello\nendstream\nendobj\n".to_vec();
    let objects = 20_000;
    for id in 2..2 + objects {
        let parent = id - 1;
        pdf.extend_from_slice(
            format!("{id} 0 obj\n<< /Type /StructElem /P {parent} 0 R >>\nendobj\n").as_bytes(),
        );
    }
    pdf.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let started = std::time::Instant::now();
    let regions = collect_dict_regions(&pdf);
    let elapsed = started.elapsed();
    assert_eq!(regions.len(), 1 + objects);
    assert_eq!(regions[0].obj_id, Some(1));
    assert_eq!(regions[0].stream_range, Some((40, 45)));
    assert_eq!(regions[1].obj_id, Some(2));
    assert!(regions[1..].iter().all(|r| r.stream_range.is_none()));
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "region walk is quadratic again: {elapsed:?}"
    );
}

/// The bound confines the match, not the token test: a `stream` that
/// runs into the bound is judged by the byte after it as before.
#[test]
fn token_between_respects_the_bound() {
    let bytes = b"<< >> stream\nendobj stream endobj";
    assert_eq!(
        find_token_between(bytes, 0, bytes.len(), b"stream"),
        Some(6)
    );
    assert_eq!(
        find_token_between(bytes, 7, bytes.len(), b"stream"),
        Some(20)
    );
    assert_eq!(find_token_between(bytes, 7, 20, b"stream"), None);
    assert_eq!(find_token_between(bytes, 7, 7, b"stream"), None);
    assert_eq!(find_token_after(b"streams stream", 0, b"stream"), Some(8));
}

// ------------------------------------------------------------------
// Malformed / robustness tests
// ------------------------------------------------------------------

#[test]
fn truncated_header_is_silent() {
    // `%PDF-` truncated mid-version stamp.
    let pdf = b"%PDF-";
    let (v, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.header_count"), Some(1.0));
    // No version parsed, but header_count remains.
    assert!(v.get("pdf.header").and_then(|h| h.get("version")).is_none());
}

#[test]
fn malformed_obj_block_doesnt_crash() {
    let pdf = b"%PDF-1.5\nNNNN 0 obj << bad dict\n%%EOF";
    let (_v, _m) = extract_pdf(pdf);
    // Just confirm we don't panic; correctness of recovery is
    // best-effort.
}

// ------------------------------------------------------------------
// Metrics ported from cleave's pdf_kv module
// ------------------------------------------------------------------

#[test]
fn javascript_and_uri_action_counts_split() {
    let pdf = b"%PDF-1.7\n\
1 0 obj << /S /JavaScript /JS (a) >> endobj\n\
2 0 obj << /S /JavaScript /JS (b) >> endobj\n\
3 0 obj << /S /URI /URI (https://example.invalid) >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.javascript_action_count"), Some(2.0));
    assert_eq!(m.get("pdf.uri_action_count"), Some(1.0));
}

/// A PDF whose objects live in one Flate-compressed `/Type /ObjStm`.
fn pdf_with_object_stream(inner: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(inner).unwrap();
    let body = enc.finish().unwrap();
    let mut pdf =
        b"%PDF-1.5\n7 0 obj << /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode >> stream\n"
            .to_vec();
    pdf.extend_from_slice(&body);
    pdf.extend_from_slice(b"\nendstream endobj\n");
    pdf
}

/// Object streams share one inflate budget: once it is spent the rest are
/// skipped and counted, rather than each keeping up to 1 MiB for as many
/// streams as the file holds.
#[test]
fn object_streams_share_one_inflate_budget() {
    let mut pdf = Vec::new();
    for _ in 0..4 {
        pdf.extend(pdf_with_object_stream(&[b' '; 100]));
    }
    let regions = collect_dict_regions(&pdf);
    let streams = decode_object_streams(&pdf, &regions, 250);
    let sizes: Vec<usize> = streams.decoded.iter().map(|(_, t)| t.len()).collect();
    assert_eq!(sizes, [100, 100, 50]);
    assert_eq!(streams.skipped, 1);

    // Under the budget nothing is skipped or reported.
    let (values, _) = extract_pdf(&pdf);
    assert!(values.get("pdf.limits").is_none());

    // Past it, the skip is a recorded limit, not a parse error.
    let mut big = Vec::new();
    for _ in 0..17 {
        big.extend(pdf_with_object_stream(&vec![b' '; 1 << 20]));
    }
    let (values, _) = extract_pdf(&big);
    let limits = values.get("pdf.limits").and_then(|l| l.as_array()).unwrap();
    assert_eq!(limits[0]["stage"].as_str(), Some("object-stream-budget"));
}

/// The scan keeps the search semantics: name-character boundaries,
/// every candidate for `/AA`, and the last `%%EOF`.
#[test]
fn token_and_type_searches_respect_boundaries() {
    let scan = TokenScan::run(b"obj objstm endobj 1 0 obj");
    assert_eq!(scan.get(Tok::Obj).accepted, 2);
    assert!(!TokenScan::run(b"objstm").has(Tok::Obj));
    let pages = TokenScan::run(b"/Type /Page /Type/Pages /Type/Page>>");
    assert_eq!(pages.type_count(TypeName::Page), 2);
    assert!(TokenScan::run(b"x/AA <</AA 3 0 R>>").has(Tok::AdditionalActions));
    assert!(!TokenScan::run(b"/AAA").has(Tok::AdditionalActions));
    assert_eq!(
        TokenScan::run(b"%%EOF\n%%EOFxyz").get(Tok::Eof).last,
        Some(6)
    );
    assert_eq!(TokenScan::run(b"no marker").get(Tok::Eof).last, None);
}

/// Pattern ids are positions in `Tok::ALL`, and `Tok` casts to them.
#[test]
fn token_ids_follow_declaration_order() {
    for (i, tok) in Tok::ALL.iter().enumerate() {
        assert_eq!(*tok as usize, i, "{tok:?}");
    }
}

/// The single pass counts what the per-token `memmem` passes it replaced
/// counted. The expected values were produced by those passes (and a
/// differential run over 200k random token soups agreed with them)
/// before they were deleted.
#[test]
fn one_pass_matches_the_per_token_passes_on_overlapping_tokens() {
    let bytes = OVERLAPPING_TOKENS;
    let s = TokenScan::run(bytes);
    // Plain substring counts: one occurrence may not start inside the
    // previous one, whatever surrounds it.
    for (tok, want) in [
        (Tok::Header, 3),
        (Tok::Eof, 3),
        (Tok::Trailer, 3),
        (Tok::StartXref, 2),
        (Tok::ByteRange, 2),
        (Tok::Jbig2Decode, 2),
        (Tok::FlateDecode, 3),
        (Tok::TypeSigSpaced, 2),
    ] {
        assert_eq!(s.get(tok).all, want, "{tok:?}");
    }
    assert_eq!(
        s.get(Tok::Subtype3dSpaced).all + s.get(Tok::Subtype3dJoined).all,
        5
    );
    // Whole tokens: `objobj`, `endobjobj`, `objstm`, `xobj` and
    // `streams` do not count.
    for (tok, want) in [(Tok::Obj, 10), (Tok::EndObj, 10), (Tok::Stream, 1)] {
        assert_eq!(s.get(tok).accepted, want, "{tok:?}");
    }
    // Feature keys: `/AcroForm` only appears glued to a name character.
    for (tok, want) in [
        (Tok::AcroForm, false),
        (Tok::Xfa, true),
        (Tok::OpenAction, false),
        (Tok::AdditionalActions, true),
        (Tok::JavaScript, true),
        (Tok::RichMedia, false),
        (Tok::Encrypt, false),
        (Tok::Linearized, false),
    ] {
        assert_eq!(s.has(tok), want, "{tok:?}");
    }
    // `/Type /<Name>` in both spellings, never `/Pages` or `/SigRef`.
    for (name, want) in [
        (TypeName::Page, 3),
        (TypeName::Annot, 2),
        (TypeName::XObject, 1),
        (TypeName::Font, 2),
        (TypeName::Metadata, 1),
        (TypeName::ObjStm, 2),
        (TypeName::XRef, 1),
        (TypeName::Sig, 2),
    ] {
        assert_eq!(s.type_count(name), want, "{name:?}");
    }
    // The header that leads is `%PDF-%PDF-`, which carries no version.
    assert_eq!(s.get(Tok::Header).first, Some(13));
    assert_eq!(header_version(bytes, 13), None);
    // `/Trapped` follows the last `%%EOF`.
    assert_eq!(
        s.get(Tok::Eof).last.map(|at| bytes.len() - (at + 5)),
        Some(8)
    );
    // DocumentInfo: the first key not followed by a letter or `_`, so
    // `/Titles`, `/Authors` and `/Subject_` are passed over.
    let info: Vec<(&str, Option<String>)> = INFO_KEYS
        .iter()
        .map(|&(tok, key)| {
            let value = s
                .get(tok)
                .first_accepted
                .and_then(|at| value_after_key(bytes, at + tok.pattern().0.len()));
            (key, value)
        })
        .collect();
    let want = [
        ("title", Some("first")),
        ("author", Some("/Name")),
        ("creator", Some("42")),
        ("producer", Some("ABC")),
        ("subject", Some("s")),
        ("keywords", Some("/Trapped")),
        ("creation_date", Some("-1.5")),
        ("mod_date", Some("D:1")),
        ("trapped", Some("/CreationDate")),
    ];
    for ((key, got), (want_key, want_value)) in info.iter().zip(want) {
        assert_eq!(*key, want_key);
        assert_eq!(got.as_deref(), want_value, "{key}");
    }
    // Through `extract`, the same counts land in the output.
    let (v, m) = extract_pdf(bytes);
    assert_eq!(m.get("pdf.object_count"), Some(10.0));
    assert_eq!(m.get("pdf.three_d_object_count"), Some(5.0));
    assert_eq!(m.get("pdf.signature_object_count"), Some(2.0));
    assert_eq!(m.get("pdf.trailing_bytes"), Some(8.0));
    assert_eq!(
        v.get("pdf.catalog.features"),
        Some(&json!([
            "xfa",
            "additional_actions",
            "names_javascript",
            "3d"
        ]))
    );
}

/// Repeats of one pattern never overlap themselves, and a key at the
/// very end of the input has no value.
#[test]
fn single_pattern_runs_and_input_edges() {
    let s = TokenScan::run(b"%%EOF%%EOF%%EOF");
    assert_eq!(s.get(Tok::Eof).all, 3);
    assert_eq!(s.get(Tok::Eof).last, Some(10));
    let s = TokenScan::run(b"/Type/Sig/Type /Sig/Type /SigX/Type/Sig_");
    assert_eq!(s.type_count(TypeName::Sig), 2);
    assert_eq!(s.get(Tok::TypeSigSpaced).all, 2);
    let s = TokenScan::run(b"/Title");
    assert_eq!(s.get(Tok::InfoTitle).first_accepted, Some(0));
    assert_eq!(value_after_key(b"/Title", 6), None);
    assert!(TokenScan::run(b"/AA").has(Tok::AdditionalActions));
    assert!(TokenScan::run(b"obj").has(Tok::Obj));
    assert_eq!(TokenScan::run(b"").get(Tok::Header), Hits::default());
}

/// Adjacent and overlapping tokens: patterns that are prefixes,
/// suffixes and substrings of one another, keys touching both ends of
/// the input, and boundaries made of every delimiter class.
const OVERLAPPING_TOKENS: &[u8] = b"/Title(first)%PDF-%PDF-1.4%PDF-\n\
1 0 obj<</Type/Page/Type/Pages/Type /Page/Type/Pages/Type/Page>>endobj\n\
2 0 obj<</Type/Annot/Type/Annots/Type /Annot/Type /AnnotX/Type/Annot_x>>endobj\n\
3 0 objobj endobjobj endobj obj objstm xobj obj_ obj1 stream streams streamstream endstream\n\
4 0 obj<</AA/AA /AA/AAA [/AA] (/AA) <</AA>>/AA1 x/AA /AA_ /AA\n/AA\t>>endobj\n\
5 0 obj<</JavaScript/JavaScriptX /JavaScript_ x/JavaScript /JavaScript>>endobj\n\
6 0 obj<</Subtype /3D/Subtype/3D/Subtype /3D/Subtype/3DX/Subtype /Subtype/3D>>endobj\n\
%%EOF%%EOF\ntrailer\ntrailer\n\ntrailerstartxrefstartxref\n\
7 0 obj<</XFA/XFAx/AcroForm/AcroForms/OpenAction/OpenActions/RichMedia/Encrypt/Linearized>>endobj\n\
8 0 obj<</Type/ObjStm/Type /ObjStm/Type/XRef/Type /XRefStm/Type/Metadata/Type/Sig/Type /Sig\
/Type /SigRef/Type/Font/Type/FontDescriptor/Type/XObject/Type /Type /Font>>endobj\n\
9 0 obj<</ByteRange/ByteRange/JBIG2Decode/JBIG2Decode/FlateDecode/FlateDecode/FlateDecodeX>>endobj\n\
10 0 obj<</Titles(no)/Title(yes)/Authors(no)/Author/Name/Creator 42/ModDate(D:1)/Producer<414243>\
/Subject_(no)/Subject(s)/Keywords/Trapped/CreationDate -1.5>>endobj\n\
%%EOF/Trapped";

#[test]
fn type_counts_include_objects_inside_object_streams() {
    // A cross-reference-stream PDF keeps its annotations and pages in a
    // compressed ObjStm. Counting only the bytes as written reported a
    // document with no annotations in it, which is what a full-page link
    // to an executable hides behind.
    let pdf = pdf_with_object_stream(
        b"31 0 44 60 <</Subtype/Link/Type/Annot>><</Type/Page>><</Type/Annot>>",
    );
    let (_, m) = extract_pdf(&pdf);
    assert_eq!(m.get("pdf.annotation_count"), Some(2.0));
    assert_eq!(m.get("pdf.page_count"), Some(1.0));
}

#[test]
fn uncompressed_object_streams_are_not_double_counted() {
    // The same key written plainly must still count exactly once.
    let pdf = b"%PDF-1.4\n1 0 obj << /Type /Annot >> endobj\n";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.annotation_count"), Some(1.0));
}

#[test]
fn actions_inside_object_streams_are_found() {
    // A cross-reference-stream PDF keeps its annotations inside a
    // compressed ObjStm. Scanning only the bytes as written reports a
    // document with no links in it.
    let inner = b"31 0 44 60 <</S/URI/URI(https://example.invalid/setup.exe)>>";
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    enc.write_all(inner).unwrap();
    let body = enc.finish().unwrap();
    let mut pdf =
        b"%PDF-1.5\n7 0 obj << /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode >> stream\n"
            .to_vec();
    pdf.extend_from_slice(&body);
    pdf.extend_from_slice(b"\nendstream endobj\n");
    let (v, m) = extract_pdf(&pdf);
    let actions = v.get("pdf.actions").and_then(|x| x.as_array()).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["kind"], "uri");
    assert_eq!(actions[0]["source"], "objstm:7");
    assert!(
        actions[0]["snippet"]
            .as_str()
            .unwrap()
            .contains("setup.exe")
    );
    assert_eq!(m.get("pdf.uri_action_count"), Some(1.0));
}

#[test]
fn metadata_and_objstm_counts_emitted() {
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Metadata /Length 0 >> endobj\n\
2 0 obj << /Type /ObjStm /N 3 /First 0 /Length 0 >> stream\nendstream endobj\n\
3 0 obj << /Type /XRef /Length 0 >> stream\nendstream endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.metadata_count"), Some(1.0));
    assert_eq!(m.get("pdf.objstm_count"), Some(1.0));
    assert_eq!(m.get("pdf.xref_stream_count"), Some(1.0));
    assert_eq!(m.get("pdf.object_stream_inner_object_count"), Some(3.0));
}

#[test]
fn three_d_object_count_emitted() {
    let pdf =
        b"%PDF-1.7\n1 0 obj << /Subtype /3D /Type /Annot >> endobj\n2 0 obj << /Subtype/3D >> endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert!(m.get("pdf.three_d_object_count").unwrap() >= 2.0);
}

#[test]
fn trailing_bytes_after_eof_counted() {
    // `\n` + `GARBAGE_TAIL_PAYLOAD` (20 bytes) = 21 trailing bytes.
    let pdf = b"%PDF-1.7\n%%EOF\nGARBAGE_TAIL_PAYLOAD";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.trailing_bytes"), Some(21.0));
}

#[test]
fn annotations_per_page_ratio() {
    // 2 pages, 4 annotations → 2.0 annotations/page.
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Page >> endobj\n\
2 0 obj << /Type /Page >> endobj\n\
3 0 obj << /Type /Annot >> endobj\n\
4 0 obj << /Type /Annot >> endobj\n\
5 0 obj << /Type /Annot >> endobj\n\
6 0 obj << /Type /Annot >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.annotations_per_page"), Some(2.0));
}

#[test]
fn uri_actions_per_page_ratio() {
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Page >> endobj\n\
2 0 obj << /S /URI /URI (https://a.invalid) >> endobj\n\
3 0 obj << /S /URI /URI (https://b.invalid) >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.uri_actions_per_page"), Some(2.0));
}

#[test]
fn unreferenced_object_count_reported() {
    // Three objects, none referenced from any other dict.
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Page >> endobj\n\
2 0 obj << /Type /Annot >> endobj\n\
3 0 obj << /Type /Font >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert!(m.get("pdf.unreferenced_object_count").unwrap() >= 3.0);
}

#[test]
fn unreferenced_objects_drop_when_referenced() {
    // Object 2 is referenced from object 1's /Kids array.
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Pages /Kids [2 0 R] >> endobj\n\
2 0 obj << /Type /Page >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    // Only object 1 is unreferenced (no /Root ref scan here).
    assert_eq!(m.get("pdf.unreferenced_object_count"), Some(1.0));
}

#[test]
fn unusual_filter_count_jbig2() {
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Filter /JBIG2Decode /Length 0 >> stream\nendstream endobj\n\
2 0 obj << /Filter /FlateDecode /Length 0 >> stream\nendstream endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.streams_with_unusual_filter_count"), Some(1.0));
}

#[test]
fn stream_invalid_length_counted() {
    // `/Length not_a_number` — neither decimal nor indirect ref.
    let pdf = b"%PDF-1.7\n1 0 obj << /Length junk >> stream\nXYZ\nendstream endobj\n%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.stream_invalid_length_count"), Some(1.0));
}

#[test]
fn form_field_count_reported() {
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Subtype /Widget /T (a) /FT /Tx /Rect [0 0 1 1] >> endobj\n\
2 0 obj << /Subtype /Widget /T (b) /FT /Tx /Rect [0 0 1 1] >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    assert_eq!(m.get("pdf.form_field_count"), Some(2.0));
}

#[test]
fn visible_object_count_mirrors_object_count() {
    let pdf = b"%PDF-1.7\n\
1 0 obj << >> endobj\n\
2 0 obj << >> endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    let oc = m.get("pdf.object_count").unwrap();
    assert_eq!(m.get("pdf.visible_object_count"), Some(oc));
}

#[test]
fn known_fixture_emits_expected_metric_keys() {
    // Lock the per-format metric surface against drift. If a
    // metric is renamed or removed this assertion fires.
    let pdf = b"%PDF-1.7\n\
1 0 obj << /Type /Catalog /OpenAction 2 0 R /AcroForm << /XFA 3 0 R >> >> endobj\n\
2 0 obj << /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >> endobj\n\
3 0 obj << /Type /Font >> endobj\n\
4 0 obj << /Type /Page >> endobj\n\
5 0 obj << /Type /Annot /Subtype /Widget /T (n) /FT /Tx /Rect [0 0 1 1] /V (v) >> endobj\n\
6 0 obj << /Type /ObjStm /N 2 /First 0 /Length 0 >> stream\nendstream endobj\n\
%%EOF";
    let (_, m) = extract_pdf(pdf);
    let want: &[&str] = &[
        "pdf.action_count",
        "pdf.annotation_count",
        "pdf.eof_count",
        "pdf.font_count",
        "pdf.form_field_count",
        "pdf.header_count",
        "pdf.javascript_action_count",
        "pdf.object_count",
        "pdf.object_stream_inner_object_count",
        "pdf.objstm_count",
        "pdf.page_count",
        "pdf.risky_feature_score",
        "pdf.stream_count",
        "pdf.visible_object_count",
    ];
    for key in want {
        assert!(m.get(key).is_some(), "missing metric: {key}");
    }
}

#[test]
fn extracts_info_title_utf16_bom() {
    // `<feff>` BOM marks the Title as UTF-16BE encoded — see
    // PDF 1.7 §7.9.2.2 ("Text Strings").
    let pdf = b"%PDF-1.4\n4 0 obj << /Title <FEFF0048006900210020> >> endobj\n%%EOF";
    let (v, _) = extract_pdf(pdf);
    assert_eq!(
        v.get("pdf.info.title").and_then(|x| x.as_str()),
        Some("Hi!")
    );
}

/// One Flate stream object `id` holding `content`.
fn flate_stream_object(id: u32, content: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(content).unwrap();
    let body = enc.finish().unwrap();
    let mut out = format!(
        "{id} 0 obj << /Filter /FlateDecode /Length {} >> stream\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out.extend_from_slice(b"\nendstream endobj\n");
    out
}

/// A dict repeating `/JS 2 0 R` used to inflate the same 1 MiB stream once
/// per repeat, so a few KB of input reached hundreds of MB. The target is
/// decoded once; the repeats are listed without its content.
#[test]
fn repeated_js_reference_is_decoded_once() {
    let mut pdf = b"%PDF-1.5\n1 0 obj << /S /JavaScript ".to_vec();
    for _ in 0..400 {
        pdf.extend_from_slice(b"/JS 2 0 R ");
    }
    pdf.extend_from_slice(b">> endobj\n");
    pdf.extend(flate_stream_object(2, &vec![b'a'; 1 << 20]));
    pdf.extend_from_slice(b"%%EOF\n");

    let (v, m) = extract_pdf(&pdf);
    let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
    assert_eq!(js.len(), 400);
    let with_content = js.iter().filter(|e| e.get("content").is_some()).count();
    assert_eq!(with_content, 1);
    assert!(js.iter().all(|e| e["target_object_id"].as_u64() == Some(2)));
    assert!(
        js.iter()
            .all(|e| e["content_bytes"].as_u64() == Some(1 << 20))
    );
    assert_eq!(m.get("pdf.javascript_count"), Some(400.0));
    assert_eq!(m.get("pdf.javascript_total_bytes"), Some((1 << 20) as f64));
}

/// Distinct targets share one decode budget; past it the scan stops and
/// says so in `pdf.limits`.
#[test]
fn js_payloads_share_one_decode_budget() {
    let targets = (MAX_JS_TOTAL / MAX_INFLATED) as u32 + 2;
    let mut pdf = b"%PDF-1.5\n1 0 obj << /S /JavaScript ".to_vec();
    for id in 0..targets {
        pdf.extend_from_slice(format!("/JS {} 0 R ", id + 10).as_bytes());
    }
    pdf.extend_from_slice(b">> endobj\n");
    for id in 0..targets {
        pdf.extend(flate_stream_object(id + 10, &vec![b'b'; MAX_INFLATED]));
    }
    pdf.extend_from_slice(b"%%EOF\n");

    let (v, m) = extract_pdf(&pdf);
    let total = m.get("pdf.javascript_total_bytes").unwrap();
    assert!(total <= MAX_JS_TOTAL as f64, "{total}");
    let limits = v.get("pdf.limits").and_then(|l| l.as_array()).unwrap();
    assert!(
        limits
            .iter()
            .any(|l| l["stage"].as_str() == Some("javascript-budget"))
    );
}

/// An unfiltered stream is read through the same cap as an inflated one,
/// rather than copied whole.
#[test]
fn unfiltered_js_stream_is_capped() {
    let body = vec![b'c'; MAX_INFLATED + 100];
    let mut pdf = b"%PDF-1.5\n1 0 obj << /S /JavaScript /JS 2 0 R >> endobj\n".to_vec();
    pdf.extend_from_slice(format!("2 0 obj << /Length {} >> stream\n", body.len()).as_bytes());
    pdf.extend_from_slice(&body);
    pdf.extend_from_slice(b"\nendstream endobj\n%%EOF\n");
    let (v, _) = extract_pdf(&pdf);
    let js = v.get("pdf.javascript").and_then(|x| x.as_array()).unwrap();
    assert_eq!(js[0]["content_bytes"].as_u64(), Some(MAX_INFLATED as u64));
}

/// A zlib stream cut short still yields what decoded before the cut.
#[test]
fn truncated_flate_stream_keeps_its_prefix() {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(&vec![b'x'; 64 << 10]).unwrap();
    let full = enc.finish().unwrap();
    let cut = &full[..full.len() - 8];
    let partial = inflate_capped(cut, MAX_INFLATED).unwrap();
    assert!(!partial.is_empty());
    assert!(partial.iter().all(|&b| b == b'x'));
    assert!(inflate_capped(b"not zlib at all", MAX_INFLATED).is_none());
}

/// Objects that open a `stream` but never close with `endobj` (or never
/// write `endstream`) made every object search to end-of-file for the
/// missing token: thousands of them ahead of a megabyte of padding took
/// minutes. Each search now resumes where the last one left off.
#[test]
fn dict_regions_are_linear_without_closing_tokens() {
    for object in [
        "{id} 0 obj\n<< >>\nstream\n",
        "{id} 0 obj\n<< >>\nstream\nendobj\n",
    ] {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        for id in 1..=5_000 {
            pdf.extend_from_slice(object.replace("{id}", &id.to_string()).as_bytes());
        }
        pdf.extend(vec![b' '; 4 << 20]);
        let started = std::time::Instant::now();
        let regions = collect_dict_regions(&pdf);
        let elapsed = started.elapsed();
        assert_eq!(regions.len(), 5_000);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "region walk is quadratic: {elapsed:?}"
        );
    }
}

/// A token found ahead is reused only while it still lies ahead, so the
/// cached searches find exactly what fresh ones would.
#[test]
fn closing_token_search_matches_a_fresh_search() {
    let pdf = b"%PDF-1.7\n1 0 obj << >> stream\nab\nendstream endobj\n\
                2 0 obj << >> stream\ncd\nendstream\nendobj\n\
                3 0 obj << /Length 2 >> stream\nef\nendstream endobj\n%%EOF\n";
    let regions = collect_dict_regions(pdf);
    let bodies: Vec<&[u8]> = regions
        .iter()
        .filter_map(|r| r.stream_range)
        .map(|(s, e)| &pdf[s..e])
        .collect();
    assert_eq!(bodies, [b"ab", b"cd", b"ef"]);
}

/// A hex string is read only as far as its hex digits go. Reading to the
/// next `>` regardless made every `/URI <` in a dictionary scan the rest
/// of it: quadratic in the number of sites.
#[test]
fn hex_value_scan_is_linear_in_sites() {
    let mut pdf = b"%PDF-1.7\n1 0 obj\n<< ".to_vec();
    pdf.extend(b"/URI <".repeat(50_000));
    pdf.extend_from_slice(b"/URI <68 74 74 70> >>\nendobj\n%%EOF\n");
    let started = std::time::Instant::now();
    let (v, _) = extract_pdf(&pdf);
    let elapsed = started.elapsed();
    let actions = v.get("pdf.actions").and_then(|a| a.as_array()).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["snippet"].as_str(), Some("http"));
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "hex scan is quadratic: {elapsed:?}"
    );
    assert_eq!(read_hex_string(b"<4 1 4>", 1).as_deref(), Some("A@"));
    assert_eq!(read_hex_string(b"<41", 1), None);
    assert_eq!(read_hex_string(b"<4x>", 1), None);
    assert_eq!(read_hex_string(b"<>", 1), None);
}

/// Every action site became a ~1 KB JSON entry from as little as six
/// input bytes, so a dictionary packed with `/URI(` grew the values tree
/// a hundredfold. Sites past the cap are not recorded, and that is said.
#[test]
fn action_sites_are_capped() {
    let mut pdf = b"%PDF-1.7\n1 0 obj\n<< ".to_vec();
    pdf.extend(b"/URI (a) ".repeat(MAX_ACTIONS + 10));
    pdf.extend_from_slice(b">>\nendobj\n%%EOF\n");
    let (v, m) = extract_pdf(&pdf);
    let actions = v.get("pdf.actions").and_then(|a| a.as_array()).unwrap();
    assert_eq!(actions.len(), MAX_ACTIONS);
    assert_eq!(m.get("pdf.action_count"), Some(MAX_ACTIONS as f64));
    let limits = v.get("pdf.limits").and_then(|l| l.as_array()).unwrap();
    assert!(
        limits
            .iter()
            .any(|l| l["stage"].as_str() == Some("action-cap"))
    );
}

/// A literal string reads a bounded span of input: line continuations
/// produce no output, so the 1 KB output cap alone let one site walk the
/// whole dictionary.
#[test]
fn literal_string_span_is_bounded() {
    let mut text = b"(".to_vec();
    text.extend(b"\\\n".repeat(100_000));
    text.extend_from_slice(b"tail)");
    assert_eq!(read_literal_string(&text, 1), None);
    assert_eq!(read_literal_string(b"(a\\\nb)", 1).as_deref(), Some("ab"));
}
