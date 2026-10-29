use super::*;

#[test]
fn hash_labels_known() {
    assert_eq!(hash_label(1), "sha1");
    assert_eq!(hash_label(2), "sha256");
    assert_eq!(hash_label(0), "unknown");
}

#[test]
fn flags_decompose() {
    let f = code_signature_flags(0x2 | 0x2000 | 0x1_0000);
    assert!(f.contains(&"ad_hoc"));
    assert!(f.contains(&"library_validation"));
    assert!(f.contains(&"runtime"));
}

#[test]
fn cstr_terminates_at_null() {
    let buf = b"hello\0world";
    assert_eq!(read_cstr(buf, 0).unwrap(), "hello");
    assert_eq!(read_cstr(buf, 6).unwrap(), "world");
}

#[test]
fn flags_use_ad_hoc_separator() {
    // The CS_ADHOC flag — ad-hoc signing — is two-words in
    // English; the emitted name uses an underscore to match the
    // rest of the Pike-style flag taxonomy.
    let f = code_signature_flags(0x2);
    assert!(f.contains(&"ad_hoc"));
    assert!(!f.contains(&"adhoc"));
}

#[test]
fn flags_empty_when_zero() {
    assert!(code_signature_flags(0).is_empty());
}

#[test]
fn flags_decompose_full_set() {
    // Sum of every documented CS_* flag the parser handles.
    let all = 0x0000_0001
        | 0x0000_0002
        | 0x0000_0004
        | 0x0000_0008
        | 0x0000_0100
        | 0x0000_0200
        | 0x0000_0400
        | 0x0000_0800
        | 0x0000_1000
        | 0x0000_2000
        | 0x0001_0000
        | 0x0002_0000;
    let f = code_signature_flags(all);
    assert_eq!(f.len(), 12);
    // Spot-check ordering matches the bit ordering in code_signature_flags.
    assert_eq!(f[0], "valid");
    assert_eq!(f[1], "ad_hoc");
    assert_eq!(f.last().copied(), Some("linker_signed"));
}

#[test]
fn hash_label_covers_canonical_digest_set() {
    assert_eq!(hash_label(3), "sha256_truncated");
    assert_eq!(hash_label(4), "sha384");
    assert_eq!(hash_label(5), "sha512");
    assert_eq!(hash_label(99), "unknown");
}

#[test]
fn cstr_handles_offset_beyond_terminator() {
    // After the second NUL the read should still terminate at the
    // next NUL we encounter, returning whatever's between.
    let buf = b"a\0b\0c";
    assert_eq!(read_cstr(buf, 2).unwrap(), "b");
    assert_eq!(read_cstr(buf, 4).unwrap(), "c");
}

#[test]
fn cstr_empty_when_first_byte_is_null() {
    let buf = b"\0afterward";
    let s = read_cstr(buf, 0).unwrap();
    assert!(s.is_empty());
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// A SuperBlob holding `blobs` at the given slot types, plus `extra`
/// index entries that all point at the first blob.
fn super_blob(blobs: &[(u32, &[u8])], extra: usize) -> Vec<u8> {
    let count = blobs.len() + extra;
    let mut offset = 12 + 8 * count;
    let mut index = Vec::new();
    let mut body = Vec::new();
    let first = offset;
    for (slot, blob) in blobs {
        index.extend(words(&[*slot, offset as u32]));
        body.extend_from_slice(blob);
        offset += blob.len();
    }
    for i in 0..extra {
        index.extend(words(&[0x2000 + i as u32, first as u32]));
    }
    let mut sig = words(&[CSMAGIC_EMBEDDED_SIGNATURE, offset as u32, count as u32]);
    sig.extend(index);
    sig.extend(body);
    sig
}

fn wrapper(cms: &[u8]) -> Vec<u8> {
    let mut blob = words(&[CSMAGIC_BLOBWRAPPER, (cms.len() + 8) as u32]);
    blob.extend_from_slice(cms);
    blob
}

fn signature_values(sig: &[u8]) -> Values {
    let mut values = Values::new();
    parse(sig, 0, sig.len(), &mut values);
    values
}

const BER_DETACHED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/ber-detached.der"
));
const BER_CONTENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chains/ber-content.bin"
));

/// Apple's CMS is BER and detached: it signs the primary CodeDirectory
/// beside it. Verified means the signature binds that CodeDirectory.
#[test]
fn cms_signature_is_verified_against_the_code_directory() {
    let sig = super_blob(
        &[
            (CSSLOT_CODEDIRECTORY, BER_CONTENT),
            (0x1_0000, &wrapper(BER_DETACHED)),
        ],
        0,
    );
    let values = signature_values(&sig);
    assert_eq!(
        values.get("macho.code_signature.cms.verified"),
        Some(&JsonValue::Bool(true))
    );
}

/// The same signature beside a different CodeDirectory — a genuine CMS
/// blob transplanted onto another binary — must not verify.
#[test]
fn cms_signature_transplanted_onto_another_code_directory_fails() {
    let mut other = BER_CONTENT.to_vec();
    *other.last_mut().unwrap() ^= 0x01;
    let sig = super_blob(
        &[
            (CSSLOT_CODEDIRECTORY, &other),
            (0x1_0000, &wrapper(BER_DETACHED)),
        ],
        0,
    );
    let values = signature_values(&sig);
    assert_eq!(
        values.get("macho.code_signature.cms.verified"),
        Some(&JsonValue::Bool(false))
    );
    assert_eq!(
        values
            .get("macho.code_signature.cms.verification_failure")
            .and_then(JsonValue::as_str),
        Some("message_digest_mismatch")
    );
}

/// A CodeDirectory (v20200) over `code` with SHA-256 slots, `page_log2`
/// pages, and `specials` bound in the slots below the code slots.
fn code_directory(code: &[u8], page_log2: u8, ident: &str, specials: &[(u32, &[u8])]) -> Vec<u8> {
    let page = if page_log2 == 0 {
        code.len().max(1)
    } else {
        1 << page_log2
    };
    let code_slots: Vec<[u8; 32]> = code
        .chunks(page)
        .map(|p| Sha256::digest(p).into())
        .collect();
    let n_special = specials.iter().map(|&(slot, _)| slot).max().unwrap_or(0) as usize;
    let mut special = vec![[0u8; 32]; n_special];
    for &(slot, blob) in specials {
        special[n_special - slot as usize] = Sha256::digest(blob).into();
    }
    let mut ident_bytes = ident.as_bytes().to_vec();
    ident_bytes.push(0);
    let ident_offset = 0x34;
    let hash_offset = ident_offset + ident_bytes.len() + 32 * n_special;
    let length = hash_offset + 32 * code_slots.len();
    let mut cd = words(&[
        CSMAGIC_CODEDIRECTORY,
        length as u32,
        0x0002_0200,
        0,
        hash_offset as u32,
        ident_offset as u32,
        n_special as u32,
        code_slots.len() as u32,
        code.len() as u32,
    ]);
    cd.extend([32, CS_HASHTYPE_SHA256, 0, page_log2]);
    cd.extend(words(&[0, 0, 0]));
    cd.extend(ident_bytes);
    for hash in special.iter().chain(&code_slots) {
        cd.extend(hash);
    }
    cd
}

/// `code` followed by a signature holding `blobs`, as parsed.
fn signed(code: &[u8], blobs: &[(u32, &[u8])]) -> Values {
    let mut file = code.to_vec();
    file.extend(super_blob(blobs, 0));
    let mut values = Values::new();
    parse(&file, code.len(), file.len() - code.len(), &mut values);
    values
}

fn page_values(values: &Values) -> (Option<bool>, Option<u64>, Option<u64>) {
    (
        values
            .get("macho.code_signature.code_pages_verified")
            .and_then(JsonValue::as_bool),
        values
            .get("macho.code_signature.code_page_mismatches")
            .and_then(JsonValue::as_u64),
        values
            .get("macho.code_signature.code_page_first_mismatch_offset")
            .and_then(JsonValue::as_u64),
    )
}

fn sample_code() -> Vec<u8> {
    (0..10_000u32).map(|i| (i * 7 % 251) as u8).collect()
}

/// The CodeDirectory's slots hold the hash of each page of the code
/// before the signature, and are recomputed from those bytes.
#[test]
fn code_pages_hash_to_their_slots() {
    let code = sample_code();
    let cd = code_directory(&code, 12, "com.example.tool", &[]);
    let values = signed(&code, &[(CSSLOT_CODEDIRECTORY, &cd)]);
    assert_eq!(page_values(&values), (Some(true), None, None));
    // Page size 0: one slot for the whole image.
    let whole = code_directory(&code, 0, "com.example.tool", &[]);
    assert_eq!(page_values(&signed(&code, &[(0, &whole)])).0, Some(true));
}

/// Code changed after signing no longer hashes to its slot, and the page
/// is named.
#[test]
fn modified_code_page_is_reported() {
    let code = sample_code();
    let cd = code_directory(&code, 12, "com.example.tool", &[]);
    let mut tampered = code.clone();
    tampered[2 * 4096 + 17] ^= 0x80;
    let values = signed(&tampered, &[(CSSLOT_CODEDIRECTORY, &cd)]);
    assert_eq!(page_values(&values), (Some(false), Some(1), Some(2 * 4096)));
}

/// A CodeDirectory that does not cover exactly the code it claims, or
/// that uses a hash this cannot compute, verifies nothing.
#[test]
fn code_directories_that_cannot_be_checked_are_unverified() {
    let code = sample_code();
    let mut cases = Vec::new();
    // codeLimit past the end of the file.
    let mut long = code_directory(&code, 12, "x", &[]);
    long[0x20..0x24].copy_from_slice(&(code.len() as u32 * 2).to_be_bytes());
    cases.push(long);
    // One code slot fewer than the pages under codeLimit.
    let mut short = code_directory(&code, 12, "x", &[]);
    short[0x1c..0x20].copy_from_slice(&2u32.to_be_bytes());
    cases.push(short);
    // An unknown hash type.
    let mut unknown = code_directory(&code, 12, "x", &[]);
    unknown[0x25] = 9;
    cases.push(unknown);
    for cd in cases {
        assert_eq!(page_values(&signed(&code, &[(0, &cd)])).0, Some(false));
    }
}

/// An embedded blob is bound by its special slot: entitlements edited
/// after signing, or never hashed in, do not verify.
#[test]
fn embedded_blobs_must_hash_to_their_special_slots() {
    let code = sample_code();
    let mut entitlements = words(&[CSMAGIC_EMBEDDED_ENTITLEMENTS, 16]);
    entitlements.extend(b"<plist/>");
    let special = |cd: &[u8], blob: &[u8]| {
        signed(&code, &[(0, cd), (5, blob)])
            .get("macho.code_signature.special_slots_verified")
            .and_then(JsonValue::as_bool)
    };
    let bound = code_directory(&code, 12, "x", &[(5, &entitlements)]);
    assert_eq!(special(&bound, &entitlements), Some(true));
    let mut edited = entitlements.clone();
    *edited.last_mut().unwrap() ^= 1;
    assert_eq!(special(&bound, &edited), Some(false));
    // A slot left zero does not bind the blob beside it.
    let unbound = code_directory(&code, 12, "x", &[(5, &[])]);
    let unbound = {
        let mut cd = unbound;
        let hash_offset = u32::from_be_bytes(cd[0x10..0x14].try_into().unwrap()) as usize;
        cd[hash_offset - 5 * 32..hash_offset - 4 * 32].fill(0);
        cd
    };
    assert_eq!(special(&unbound, &entitlements), Some(false));
}

/// Only the primary CodeDirectory is under the signature; an alternate
/// must assert the same identity, and its pages must hold too.
#[test]
fn alternate_code_directories_must_match_the_primary() {
    let code = sample_code();
    let primary = code_directory(&code, 12, "com.example.tool", &[]);
    let consistent = |alternate: &[u8]| {
        let values = signed(&code, &[(0, &primary), (0x1000, alternate)]);
        (
            values
                .get("macho.code_signature.code_directories_consistent")
                .and_then(JsonValue::as_bool),
            page_values(&values).0,
        )
    };
    let same = code_directory(&code, 14, "com.example.tool", &[]);
    assert_eq!(consistent(&same), (Some(true), Some(true)));
    let other = code_directory(&code, 12, "com.apple.security", &[]);
    assert_eq!(consistent(&other).0, Some(false));
    let mut stale = same.clone();
    let last = stale.len() - 1;
    stale[last] ^= 1;
    assert_eq!(consistent(&stale), (Some(true), Some(false)));
}

/// A genuine CodeDirectory and its CMS signature moved out of slot 0
/// into a slot the kernel never reads vouch for nothing: no pages were
/// checked, and the signature binds no CodeDirectory the OS would use.
#[test]
fn code_directory_outside_honoured_slots_verifies_nothing() {
    let code = sample_code();
    let cd = code_directory(&code, 12, "com.apple.ls", &[]);
    let cms = wrapper(BER_DETACHED);
    let values = signed(&code, &[(0x2000, &cd), (CSSLOT_SIGNATURESLOT, &cms)]);
    assert_eq!(page_values(&values).0, Some(false));
    let sig = super_blob(&[(0x2000, BER_CONTENT), (CSSLOT_SIGNATURESLOT, &cms)], 0);
    let values = signature_values(&sig);
    assert_ne!(
        values.get("macho.code_signature.cms.verified"),
        Some(&JsonValue::Bool(true))
    );
    // Nor does that CodeDirectory lend the file its cdhash.
    assert!(values.get("macho.code_signature.cdhash").is_none());
}

/// Entitlements are read from their own slot, as the kernel reads them:
/// a decoy in another slot neither hides nor replaces the real ones, and
/// a blob in a special slot the CodeDirectory does not hash is unbound.
#[test]
fn entitlements_come_from_their_slot_and_must_be_hashed() {
    let code = sample_code();
    let plist = |key: &str| {
        let xml = format!("<plist><dict><key>{key}</key><true/></dict></plist>");
        let mut blob = words(&[CSMAGIC_EMBEDDED_ENTITLEMENTS, (xml.len() + 8) as u32]);
        blob.extend(xml.as_bytes());
        blob
    };
    let (real, decoy) = (plist("com.apple.private.tcc"), plist("benign"));
    let cd = code_directory(&code, 12, "x", &[(5, &real)]);
    let values = signed(&code, &[(0, &cd), (5, &real), (0x2000, &decoy)]);
    let entitlements = values.get("macho.code_signature.entitlements").unwrap();
    assert!(entitlements.get("com.apple.private.tcc").is_some());
    assert!(entitlements.get("benign").is_none());
    // No special slots at all: the entitlements beside it are unbound.
    let unhashed = code_directory(&code, 12, "x", &[]);
    let values = signed(&code, &[(0, &unhashed), (5, &real)]);
    assert_eq!(
        values
            .get("macho.code_signature.special_slots_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

/// Thousands of index entries naming one blob read it once; the walk
/// is capped and de-duplicated by offset.
#[test]
fn repeated_index_entries_are_read_once() {
    let sig = super_blob(&[(CSSLOT_CODEDIRECTORY, BER_CONTENT)], 10_000);
    let entries = super_blob_entries(&sig, sig.len()).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        signature_values(&sig)
            .get("macho.code_signature.cdhash")
            .is_some()
    );
}

/// The Requirements set gets the same treatment.
#[test]
fn repeated_requirement_entries_are_decoded_once() {
    // One requirement (`always`), then 5,000 index entries naming it.
    let expr = words(&[1]);
    let mut req = words(&[0xfade_0c00, (12 + expr.len()) as u32, 1]);
    req.extend(expr);
    let count = 5_000_u32;
    let req_off = 12 + 8 * count;
    let mut set = words(&[0xfade_0c01, req_off + req.len() as u32, count]);
    for slot in 0..count {
        set.extend(words(&[slot, req_off]));
    }
    set.extend(req);
    let mut values = Values::new();
    parse_requirements_set(&set, &mut values);
    let requirements = values.get("macho.code_signature.requirements").unwrap();
    assert_eq!(requirements.as_object().unwrap().len(), 1);
}

#[test]
fn requirement_expression_decodes_to_csreq_text() {
    // `and`, then `identifier` with a 5-byte string padded to 8.
    let mut expr = words(&[6, 2, 5]);
    expr.extend(b"com.x\0\0\0");
    expr.extend(words(&[15]));
    let decode = |b: &[u8]| decode_expression(&mut Reader::new(b), 0);
    assert_eq!(
        decode(&expr).as_deref(),
        Some("(identifier \"com.x\" and anchor apple generic)")
    );
    // A truncated operand fails the whole expression.
    assert_eq!(decode(&expr[..14]), None);
    assert_eq!(decode(&expr[..20]), None);
    // An operand that ends inside its padding still decodes.
    let mut tail = words(&[2, 1]);
    tail.push(b'a');
    assert_eq!(decode(&tail).as_deref(), Some("identifier \"a\""));
}

/// Entitlements are an XML plist from the binary; a deep nest is
/// dropped without walking it on a worker-sized stack.
#[test]
fn deep_entitlements_plist_is_refused() {
    let values = crate::formats::plist_guard::on_small_stack(|| {
        let mut blob = vec![0u8; 8];
        blob.extend(crate::formats::plist_guard::nested_xml(20_000));
        let mut values = Values::new();
        parse_entitlements(&blob, &mut values);
        values
    });
    assert!(values.get("macho.code_signature.entitlements").is_none());
}
