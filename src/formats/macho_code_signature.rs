//! Mach-O embedded code-signature parser.
//!
//! Mach-O binaries reference a code-signature blob from the
//! `LC_CODE_SIGNATURE` load command. The blob is a **SuperBlob** —
//! a magic-prefixed container of typed sub-blobs identified by their
//! own magic numbers. The forensically valuable contents:
//!
//! - **CodeDirectory** (`CSMAGIC_CODEDIRECTORY` = `0xfade0c02`):
//!   identifier, team_id, hash algorithm, hash slots, flags. The
//!   SHA-256 of the entire CodeDirectory blob is itself a unique
//!   per-binary fingerprint (the "cdhash" macOS uses for `codesign
//!   --verify` lookups).
//! - **Embedded Entitlements** (`CSMAGIC_EMBEDDED_ENTITLEMENTS` =
//!   `0xfade7171`): the application's plist entitlements — what
//!   capabilities the app claims.
//! - **CMS Signature wrapper** (`CSMAGIC_BLOBWRAPPER` = `0xfade0b01`):
//!   PKCS#7 SignedData with the Apple Developer cert chain. We hand
//!   this to the same parser the Authenticode code path uses.
//!
//! All multi-byte fields inside the code signature are stored
//! **big-endian** — uniquely among Mach-O structures, which are
//! otherwise host-endian.

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::bytes::{self, Reader};
use crate::formats::common::{hex_encode, plist_to_json, put_str, put_u64};
use crate::output::Values;
use crate::value_key;

/// Outer wrapper magic. Every embedded code signature starts here.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
/// `Detached` signature, sometimes seen in `__cs_blob` sections.
const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
/// Per-blob magics we care about.
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_DER_ENTITLEMENTS: u32 = 0xfade_7172;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
/// Slot type of the primary CodeDirectory, the one the CMS signature covers.
const CSSLOT_CODEDIRECTORY: u32 = 0;

/// SuperBlob index entries read. Real signatures carry fewer than a dozen
/// (CodeDirectory, up to five alternates, requirements, entitlements,
/// launch constraints, CMS); the cap bounds the index walk.
const MAX_BLOB_INDEX: usize = 64;

/// Maximum recursion depth honoured when decoding Apple Requirement
/// expressions. Real-world expressions are shallow (a handful of
/// AND/OR/NOT operators); the cap bounds stack usage on adversarial
/// blobs that chain operators arbitrarily deep.
const MAX_REQUIREMENT_DEPTH: u8 = 32;

/// Upper bound on the XML plist payload we hand to `plist_guard::parse`
/// in `parse_entitlements`. Real entitlements blobs are at most a few
/// KiB; capping prevents an oversized payload from forcing the plist
/// parser through megabytes of attacker XML.
const MAX_ENTITLEMENT_XML_BYTES: usize = 1 << 20;

/// Parse the code-signature blob at offset `sig_off..sig_off+sig_size`
/// in `bytes` and populate the `macho.code_signature.*` subtree.
pub(super) fn parse(bytes: &[u8], sig_off: usize, sig_size: usize, values: &mut Values) {
    if sig_size < 12 {
        return;
    }
    let Some(sig) = bytes.get(sig_off..sig_off.saturating_add(sig_size)) else {
        return;
    };

    let (Some(magic), Some(total_len)) = (bytes::u32_be(sig, 0), bytes::u32_be(sig, 4)) else {
        return;
    };
    let total_len = total_len as usize;
    if total_len < 12 || total_len > sig.len() {
        return;
    }
    if magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_DETACHED_SIGNATURE {
        return;
    }

    let Some(entries) = super_blob_entries(sig, total_len) else {
        return;
    };
    // The CMS signature covers the primary CodeDirectory (slot 0); the
    // alternate CodeDirectories are bound through its cdhashes attribute.
    let primary_cd = entries
        .iter()
        .find(|e| e.slot == CSSLOT_CODEDIRECTORY && e.magic == CSMAGIC_CODEDIRECTORY)
        .or_else(|| entries.iter().find(|e| e.magic == CSMAGIC_CODEDIRECTORY))
        .map(|e| e.blob);

    for &BlobEntry {
        offset: blob_off,
        magic: blob_magic,
        blob,
        ..
    } in &entries
    {
        match blob_magic {
            // `sig_off + blob_off` is the CodeDirectory's absolute offset in
            // `bytes`; pass it so interior fields (the identifier string) can
            // be reported in the same coordinate space as the signature blob.
            CSMAGIC_CODEDIRECTORY => {
                parse_code_directory(blob, sig_off + blob_off, values);
            }
            CSMAGIC_REQUIREMENTS => {
                put_u64(
                    values,
                    value_key!("macho.code_signature.requirements_size"),
                    (blob.len() - 8) as u64,
                );
                parse_requirements_set(blob, values);
            }
            CSMAGIC_EMBEDDED_ENTITLEMENTS => parse_entitlements(blob, values),
            CSMAGIC_DER_ENTITLEMENTS => {
                // Same pattern: presence of `der_entitlements_size`
                // signals a DER-encoded entitlements blob was found.
                put_u64(
                    values,
                    value_key!("macho.code_signature.der_entitlements_size"),
                    (blob.len() - 8) as u64,
                );
            }
            CSMAGIC_BLOBWRAPPER => parse_cms(blob, primary_cd, values),
            _ => {}
        }
    }
    check_code_directories(bytes, &entries, primary_cd, values);
}

/// CodeDirectory hash types (`CS_HASHTYPE_*`).
const CS_HASHTYPE_SHA1: u8 = 1;
const CS_HASHTYPE_SHA256: u8 = 2;
const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
const CS_HASHTYPE_SHA384: u8 = 4;

/// First slot type of the alternate CodeDirectories; special slots number
/// below it.
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
/// Alternate CodeDirectory slots the kernel honours (`CSSLOT_ALTERNATE_
/// CODEDIRECTORY_MAX`). A CodeDirectory elsewhere is never used to validate
/// pages, so its pages are not hashed: that caps the image hashing at six
/// passes however many CodeDirectories a signature lists.
const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;

/// The digest a CodeDirectory of `hash_type` stores for `data`, and the slot
/// length such a CodeDirectory must declare. `None` for a hash type this
/// cannot compute.
fn slot_digest(hash_type: u8, data: &[u8]) -> Option<(Vec<u8>, usize)> {
    use sha1::Sha1;
    use sha2::Sha384;
    Some(match hash_type {
        CS_HASHTYPE_SHA1 => (Sha1::digest(data).to_vec(), 20),
        CS_HASHTYPE_SHA256 => (Sha256::digest(data).to_vec(), 32),
        CS_HASHTYPE_SHA256_TRUNCATED => (Sha256::digest(data).to_vec(), 20),
        CS_HASHTYPE_SHA384 => (Sha384::digest(data).to_vec(), 48),
        _ => return None,
    })
}

/// The parts of a CodeDirectory that bind code to it: where its hash slots
/// sit, how many there are, and what they cover.
struct CdSlots<'a> {
    blob: &'a [u8],
    hash_offset: usize,
    n_special_slots: usize,
    n_code_slots: usize,
    code_limit: usize,
    hash_size: usize,
    hash_type: u8,
    page_size_log2: u8,
}

impl<'a> CdSlots<'a> {
    /// `None` for a header too short to read, or one using scatter vectors,
    /// which split the image into ranges this does not walk.
    fn read(blob: &'a [u8]) -> Option<Self> {
        let version = bytes::u32_be(blob, 0x08)?;
        if version >= 0x0002_0100 && bytes::u32_be(blob, 0x2c).is_some_and(|scatter| scatter != 0) {
            return None;
        }
        let mut code_limit = u64::from(bytes::u32_be(blob, 0x20)?);
        // `codeLimit64` replaces the 32-bit limit when set (v20300+).
        if version >= 0x0002_0300
            && let Some(limit64) = bytes::u64_be(blob, 0x38)
            && limit64 != 0
        {
            code_limit = limit64;
        }
        let [hash_size, hash_type, _platform, page_size_log2] =
            *blob.get(0x24..0x28)?.first_chunk::<4>()?;
        Some(Self {
            blob,
            hash_offset: bytes::u32_be(blob, 0x10)? as usize,
            n_special_slots: bytes::u32_be(blob, 0x18)? as usize,
            n_code_slots: bytes::u32_be(blob, 0x1c)? as usize,
            code_limit: usize::try_from(code_limit).ok()?,
            hash_size: usize::from(hash_size),
            hash_type,
            page_size_log2,
        })
    }

    /// The stored hash in slot `index`: a code slot from 0 up, a special
    /// slot (counted from 1) below `hash_offset`.
    fn slot(&self, index: isize) -> Option<&'a [u8]> {
        let start = if index >= 0 {
            self.hash_offset
                .checked_add(index.unsigned_abs().checked_mul(self.hash_size)?)?
        } else {
            self.hash_offset
                .checked_sub(index.unsigned_abs().checked_mul(self.hash_size)?)?
        };
        self.blob.get(start..start.checked_add(self.hash_size)?)
    }

    /// Fields that must agree across a signature's CodeDirectories: only
    /// the primary is under the CMS signature, and Apple writes the same
    /// identity into each alternate.
    fn identity(&self) -> Option<CdIdentity> {
        let version = bytes::u32_be(self.blob, 0x08)?;
        let team = (version >= 0x0002_0200)
            .then(|| bytes::u32_be(self.blob, 0x30))
            .flatten()
            .filter(|&off| off != 0)
            .and_then(|off| read_cstr(self.blob, off as usize));
        Some(CdIdentity {
            identifier: read_cstr(self.blob, bytes::u32_be(self.blob, 0x14)? as usize),
            team,
            flags: bytes::u32_be(self.blob, 0x0c)?,
            platform: *self.blob.get(0x26)?,
            exec_segment: (version >= 0x0002_0400)
                .then(|| self.blob.get(0x40..0x58)?.first_chunk::<24>().copied())
                .flatten(),
        })
    }
}

/// The identity a CodeDirectory asserts, compared across alternates.
#[derive(PartialEq, Eq)]
struct CdIdentity {
    identifier: Option<String>,
    team: Option<String>,
    flags: u32,
    platform: u8,
    exec_segment: Option<[u8; 24]>,
}

/// What one CodeDirectory's hash slots say about the image beside them.
struct CdCheck {
    /// Every code page hashes to its slot, and the slot count covers
    /// exactly `codeLimit`.
    pages_ok: bool,
    mismatched_pages: u64,
    first_mismatch: Option<u64>,
    /// Every embedded blob in a special slot hashes to that slot. `None`
    /// when no embedded blob falls in one.
    special_ok: Option<bool>,
}

/// Page digests already computed, keyed by what determines them, so a
/// signature listing the same CodeDirectory shape many times hashes the
/// image once per shape.
type PageDigests = Vec<((u8, u8, usize), Vec<Vec<u8>>)>;

fn check_code_directory(
    cd: &CdSlots<'_>,
    image: &[u8],
    entries: &[BlobEntry<'_>],
    memo: &mut PageDigests,
) -> Option<CdCheck> {
    let (_, digest_len) = slot_digest(cd.hash_type, &[])?;
    if cd.hash_size != digest_len {
        return None;
    }
    let page_size = match cd.page_size_log2 {
        0 => None,
        log2 if log2 < 32 => Some(1usize << log2),
        _ => return None,
    };
    let expected_slots = match page_size {
        // Page size 0: one slot covers the whole of `codeLimit`.
        None => usize::from(cd.code_limit > 0),
        Some(page) => cd.code_limit.div_ceil(page),
    };
    let covered = cd.code_limit <= image.len()
        && cd.n_code_slots == expected_slots
        && cd
            .n_special_slots
            .checked_mul(cd.hash_size)
            .is_some_and(|below| below <= cd.hash_offset)
        && cd
            .n_code_slots
            .checked_mul(cd.hash_size)
            .and_then(|above| above.checked_add(cd.hash_offset))
            .is_some_and(|end| end <= cd.blob.len());
    let mut check = CdCheck {
        pages_ok: covered,
        mismatched_pages: 0,
        first_mismatch: None,
        special_ok: None,
    };
    if covered {
        let key = (cd.hash_type, cd.page_size_log2, cd.code_limit);
        let digests = match memo.iter().position(|(k, _)| *k == key) {
            Some(i) => &memo.get(i)?.1,
            None => {
                let code = image.get(..cd.code_limit)?;
                // Page size 0 makes the whole of `codeLimit` one page.
                let page = page_size.unwrap_or(code.len()).max(1);
                let pages = code
                    .chunks(page)
                    .map(|page| slot_digest(cd.hash_type, page).map(|(d, _)| d))
                    .collect::<Option<Vec<_>>>()?;
                memo.push((key, pages));
                &memo.last()?.1
            }
        };
        let page = page_size.unwrap_or(cd.code_limit);
        for (i, digest) in digests.iter().enumerate() {
            let stored = cd.slot(isize::try_from(i).ok()?)?;
            if digest.get(..cd.hash_size) != Some(stored) {
                check.pages_ok = false;
                check.mismatched_pages += 1;
                check
                    .first_mismatch
                    .get_or_insert(u64::try_from(i.saturating_mul(page)).ok()?);
            }
        }
    }
    for entry in entries {
        let Ok(slot) = usize::try_from(entry.slot) else {
            continue;
        };
        if entry.slot == CSSLOT_CODEDIRECTORY
            || entry.slot >= CSSLOT_ALTERNATE_CODEDIRECTORIES
            || slot > cd.n_special_slots
        {
            continue;
        }
        let (digest, _) = slot_digest(cd.hash_type, entry.blob)?;
        let bound = cd
            .slot(-isize::try_from(slot).ok()?)
            .is_some_and(|stored| digest.get(..cd.hash_size) == Some(stored));
        check.special_ok = Some(check.special_ok.unwrap_or(true) && bound);
    }
    Some(check)
}

/// Recompute every CodeDirectory's hash slots from the image they sign.
///
/// A CMS signature covers the primary CodeDirectory, and a CodeDirectory
/// covers the code only through its hash slots: one digest per page of the
/// image up to `codeLimit`, and one per embedded blob (requirements,
/// entitlements) in the special slots. Unless those are recomputed here, a
/// genuine CodeDirectory and signature lifted from another binary vouch for
/// whatever code sits beside them. The kernel checks pages against the
/// strongest CodeDirectory, so each one present must hold, and since only the
/// primary is under the signature, each alternate must repeat its identity.
///
/// A CodeDirectory this cannot check (unknown hash type, scatter vectors, a
/// malformed header) reads as unverified: `code_pages_verified` is `false`.
fn check_code_directories(
    image: &[u8],
    entries: &[BlobEntry<'_>],
    primary: Option<&[u8]>,
    values: &mut Values,
) {
    let directories: Vec<&BlobEntry<'_>> = entries
        .iter()
        .filter(|e| e.magic == CSMAGIC_CODEDIRECTORY)
        .collect();
    if directories.is_empty() {
        return;
    }
    let alternates = CSSLOT_ALTERNATE_CODEDIRECTORIES
        ..CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX;
    let mut memo = PageDigests::new();
    let mut pages_ok = true;
    let mut special: Option<bool> = None;
    let mut mismatch: Option<(u64, Option<u64>)> = None;
    for blob in directories
        .iter()
        .filter(|e| e.slot == CSSLOT_CODEDIRECTORY || alternates.contains(&e.slot))
        .map(|e| e.blob)
    {
        let check =
            CdSlots::read(blob).and_then(|cd| check_code_directory(&cd, image, entries, &mut memo));
        let Some(check) = check else {
            pages_ok = false;
            continue;
        };
        pages_ok &= check.pages_ok;
        if check.mismatched_pages > 0 && mismatch.is_none() {
            mismatch = Some((check.mismatched_pages, check.first_mismatch));
        }
        if let Some(ok) = check.special_ok {
            special = Some(special.unwrap_or(true) && ok);
        }
    }
    values.insert_key(
        value_key!("macho.code_signature.code_pages_verified"),
        JsonValue::Bool(pages_ok),
    );
    if let Some((pages, first)) = mismatch {
        put_u64(
            values,
            value_key!("macho.code_signature.code_page_mismatches"),
            pages,
        );
        if let Some(first) = first {
            put_u64(
                values,
                value_key!("macho.code_signature.code_page_first_mismatch_offset"),
                first,
            );
        }
    }
    if let Some(ok) = special {
        values.insert_key(
            value_key!("macho.code_signature.special_slots_verified"),
            JsonValue::Bool(ok),
        );
    }
    if directories.len() > 1 {
        let identity = |blob: &[u8]| CdSlots::read(blob).and_then(|cd| cd.identity());
        let primary = primary.and_then(identity);
        // Every CodeDirectory blob, honoured slot or not: any of them can
        // supply the fields reported above.
        let consistent =
            primary.is_some() && directories.iter().all(|e| identity(e.blob) == primary);
        values.insert_key(
            value_key!("macho.code_signature.code_directories_consistent"),
            JsonValue::Bool(consistent),
        );
    }
}

/// One SuperBlob index entry and the blob it points at.
struct BlobEntry<'a> {
    slot: u32,
    offset: usize,
    magic: u32,
    blob: &'a [u8],
}

/// The SuperBlob's index entries, each pointing inside the signature.
///
/// The index count is attacker-chosen and every entry may name the same
/// multi-megabyte blob, so walking it naively hashes or CMS-parses that blob
/// once per entry. Like xnu's `csblob_find_blob`, only the first entry per
/// slot type counts, an offset already claimed by an earlier entry is
/// skipped, and at most [`MAX_BLOB_INDEX`] entries are read.
fn super_blob_entries(sig: &[u8], total_len: usize) -> Option<Vec<BlobEntry<'_>>> {
    let count = bytes::u32_be(sig, 8)? as usize;
    // Each BlobIndex: u32 type, u32 offset (12 bytes header + 8 * count
    // for the index table).
    let index_end = count.checked_mul(8)?.checked_add(12)?;
    if index_end > total_len {
        return None;
    }
    let mut entries: Vec<BlobEntry<'_>> = Vec::new();
    for i in 0..count.min(MAX_BLOB_INDEX) {
        let (Some(slot), Some(blob_off)) = (
            bytes::u32_be(sig, 12 + i * 8),
            bytes::u32_be(sig, 12 + i * 8 + 4).map(|n| n as usize),
        ) else {
            continue;
        };
        if entries
            .iter()
            .any(|e| e.slot == slot || e.offset == blob_off)
        {
            continue;
        }
        if blob_off + 8 > total_len {
            continue;
        }
        let (Some(magic), Some(blob_len)) = (
            bytes::u32_be(sig, blob_off),
            bytes::u32_be(sig, blob_off + 4),
        ) else {
            continue;
        };
        let blob_len = blob_len as usize;
        if blob_len < 8 || blob_off.saturating_add(blob_len) > total_len {
            continue;
        }
        let Some(blob) = sig.get(blob_off..blob_off + blob_len) else {
            continue;
        };
        entries.push(BlobEntry {
            slot,
            offset: blob_off,
            magic,
            blob,
        });
    }
    Some(entries)
}

/// CodeDirectory layout (excerpt — fields through v20400 are stable).
/// `cd_base` is the blob's absolute offset in the file, used to anchor
/// interior strings (the identifier) at their true byte position rather
/// than at the enclosing signature blob.
fn parse_code_directory(blob: &[u8], cd_base: usize, values: &mut Values) -> Option<()> {
    // Header layout (big-endian):
    //   u32 magic            (already validated)
    //   u32 length
    //   u32 version
    //   u32 flags
    //   u32 hashOffset
    //   u32 identOffset
    //   u32 nSpecialSlots
    //   u32 nCodeSlots
    //   u32 codeLimit
    //   u8  hashSize
    //   u8  hashType
    //   u8  platform
    //   u8  pageSize         (log2 — actual page size is 1 << pageSize)
    //   u32 spare2
    //   // v20100+:
    //   u32 scatterOffset
    //   // v20200+:
    //   u32 teamOffset       (at offset 0x30)
    //   // v20300+:
    //   u32 spare3
    //   u64 codeLimit64
    //   // v20400+:
    //   u64 execSegBase
    //   u64 execSegLimit
    //   u64 execSegFlags
    if blob.len() < 0x2c {
        return None;
    }
    let mut cd = Reader::at(blob, 8);
    let version = cd.u32_be()?;
    let flags = cd.u32_be()?;
    cd.skip(4)?; // hashOffset
    let ident_offset = cd.u32_be()? as usize;
    let n_special_slots = cd.u32_be()?;
    let n_code_slots = cd.u32_be()?;
    let code_limit = cd.u32_be()?;
    let [hash_size, hash_type, platform, page_size_log2] = cd.array()?;

    if let Some(ident) = read_cstr(blob, ident_offset) {
        put_str(values, value_key!("macho.code_signature.identifier"), ident);
        // Absolute file offset of the identifier C-string, so consumers can
        // anchor it at the string itself rather than at the CodeDirectory or
        // signature blob. Same coordinate space as the signature offset.
        put_u64(
            values,
            value_key!("macho.code_signature.identifier_offset"),
            (cd_base + ident_offset) as u64,
        );
    }

    // The team_offset field landed in version 0x20200.
    if version >= 0x0002_0200
        && let Some(team_offset) = bytes::u32_be(blob, 48)
        && team_offset != 0
        && let Some(team) = read_cstr(blob, team_offset as usize)
        && !team.is_empty()
    {
        put_str(values, value_key!("macho.code_signature.team_id"), team);
    }

    // Executable-segment descriptor — present from version 0x20400
    // onward. The three u64 fields sit at 0x40, 0x48, 0x50 inside the
    // CodeDirectory blob. Forensically meaningful as a per-binary
    // bound on which bytes the kernel will enforce as executable.
    if version >= 0x0002_0400
        && let (Some(exec_base), Some(exec_limit), Some(exec_flags)) = (
            bytes::u64_be(blob, 0x40),
            bytes::u64_be(blob, 0x48),
            bytes::u64_be(blob, 0x50),
        )
    {
        put_u64(
            values,
            value_key!("macho.code_signature.exec_segment_base"),
            exec_base,
        );
        put_u64(
            values,
            value_key!("macho.code_signature.exec_segment_limit"),
            exec_limit,
        );
        // CS_EXECSEG_* flags: 0x1 main binary, 0x10 allow unsigned,
        // 0x20 debugger, 0x40 jit, 0x80 skip library validation,
        // 0x100 can load CDHash, 0x200 can exec CDHash, 0x10000
        // allow_root.
        put_u64(
            values,
            value_key!("macho.code_signature.exec_segment_flags"),
            exec_flags,
        );
    }

    put_str(
        values,
        value_key!("macho.code_signature.hash"),
        hash_label(hash_type),
    );
    put_u64(
        values,
        value_key!("macho.code_signature.hash_size"),
        u64::from(hash_size),
    );
    put_u64(
        values,
        value_key!("macho.code_signature.platform"),
        u64::from(platform),
    );
    put_u64(
        values,
        value_key!("macho.code_signature.version"),
        u64::from(version),
    );
    put_u64(
        values,
        value_key!("macho.code_signature.special_slots"),
        u64::from(n_special_slots),
    );
    put_u64(
        values,
        value_key!("macho.code_signature.code_slots"),
        u64::from(n_code_slots),
    );
    put_u64(
        values,
        value_key!("macho.code_signature.code_limit"),
        u64::from(code_limit),
    );
    if page_size_log2 > 0 && page_size_log2 < 32 {
        put_u64(
            values,
            value_key!("macho.code_signature.page_size"),
            1u64 << page_size_log2,
        );
    }

    // Decompose the flag bitfield into named strings. The `adhoc` flag
    // sits in this array — trait authors check it via `exact: adhoc`
    // on `macho.code_signature.flags`, so a separate `is_ad_hoc`
    // boolean would only restate the array's contents.
    let flag_names = code_signature_flags(flags);
    values.insert_key(
        value_key!("macho.code_signature.flags"),
        JsonValue::Array(flag_names.into_iter().map(JsonValue::String).collect()),
    );

    // cdhash: SHA-256 of the entire CodeDirectory blob. This is the
    // value macOS reports in `codesign -dv --verbose=4` and the one
    // used for notarisation lookups.
    let digest = Sha256::digest(blob);
    put_str(
        values,
        value_key!("macho.code_signature.cdhash"),
        hex_encode(&digest),
    );
    Some(())
}

/// Walk a Requirements SuperBlob and decode each requirement's
/// expression tree to its canonical textual form (e.g.
/// `identifier "com.apple.ls" and anchor apple`). Each requirement is
/// keyed by its slot type — the *designated* requirement is the one
/// `codesign -d -r-` prints and the one Gatekeeper actually checks.
///
/// Apple's requirement expressions are documented in
/// `<Security/SecCode.h>` and Apple's Technical Note TN2206. The
/// expression opcodes are a stack machine encoded big-endian with
/// length-prefixed strings padded to 4-byte alignment.
fn parse_requirements_set(blob: &[u8], values: &mut Values) {
    // SuperBlob header is already validated by the caller.
    let Some(count) = bytes::u32_be(blob, 8).map(|n| n as usize) else {
        return;
    };
    let index_end = 12_usize.saturating_add(count.saturating_mul(8));
    if index_end > blob.len() {
        return;
    }
    let mut requirements = serde_json::Map::new();
    // Same rule as the outer SuperBlob: the first entry per slot type, each
    // offset decoded once, so a count of thousands pointing at one deep
    // expression costs one decode.
    let mut seen: Vec<(u32, u32)> = Vec::new();
    for i in 0..count.min(MAX_BLOB_INDEX) {
        let entry_off = 12 + i * 8;
        let (Some(slot_type), Some(req_off)) = (
            bytes::u32_be(blob, entry_off),
            bytes::u32_be(blob, entry_off + 4),
        ) else {
            continue;
        };
        if seen
            .iter()
            .any(|&(slot, off)| slot == slot_type || off == req_off)
        {
            continue;
        }
        seen.push((slot_type, req_off));
        let req_off = req_off as usize;
        if req_off + 12 > blob.len() {
            continue;
        }
        let (Some(req_magic), Some(req_len)) = (
            bytes::u32_be(blob, req_off),
            bytes::u32_be(blob, req_off + 4),
        ) else {
            continue;
        };
        let req_len = req_len as usize;
        // CSMAGIC_REQUIREMENT = 0xfade_0c00.
        if req_magic != 0xfade_0c00 || req_len < 12 || req_off.saturating_add(req_len) > blob.len()
        {
            continue;
        }
        // Expression tree starts after the 12-byte requirement
        // header (magic + length + kind). The trailing kind isn't
        // forensically interesting (always 1 = expression in
        // practice); we ignore it and parse the expression tree.
        let Some(expr) = blob.get(req_off + 12..req_off + req_len) else {
            continue;
        };
        let text = decode_expression(&mut Reader::new(expr), 0).unwrap_or_else(|| "?".into());
        let key = requirement_slot_name(slot_type);
        requirements.insert(key.to_string(), JsonValue::String(text));
    }
    if !requirements.is_empty() {
        values.insert_key(
            value_key!("macho.code_signature.requirements"),
            JsonValue::Object(requirements),
        );
    }
}

/// Map a Requirements-SuperBlob slot type to the canonical short
/// name `codesign -d -r-` uses (`designated`, `host`, `guest`,
/// `library`, `plugin`).
fn requirement_slot_name(slot: u32) -> &'static str {
    match slot {
        1 => "host",
        2 => "guest",
        3 => "designated",
        4 => "library",
        5 => "plugin",
        _ => "unknown",
    }
}

/// Recursive descent through the Apple Requirement expression tree.
/// Opcodes are u32 big-endian; strings, data blobs, and integers
/// follow inline with 4-byte alignment between fields. The textual
/// output matches what Apple's `csreq` / `codesign -d -r-` emit so
/// values can be diffed directly against those tools' output.
///
/// `depth` is the recursion level (start at 0). Adversarial blobs can
/// chain AND/OR/NOT operators to arbitrary depth — cap at
/// [`MAX_REQUIREMENT_DEPTH`] to keep stack usage bounded.
fn decode_expression(r: &mut Reader<'_>, depth: u8) -> Option<String> {
    if depth > MAX_REQUIREMENT_DEPTH {
        return None;
    }
    let op = r.u32_be()?;
    // Match-flags live in the top byte of the opcode on certain
    // string-match instructions; the low 24 bits hold the actual
    // opcode. The match-flag handling matters only for `info`/
    // `entitlement` ops which we render without flag annotations.
    let op_low = op & 0x00ff_ffff;
    Some(match op_low {
        0 => "never".into(),
        1 => "always".into(),
        2 => format!("identifier \"{}\"", read_expr_string(r)?),
        3 => "anchor apple".into(),
        4 => {
            let slot = r.u32_be()?;
            let hash = read_expr_data(r)?;
            format!("certificate {slot} = H\"{}\"", hex_encode(hash))
        }
        5 => {
            let key = read_expr_string(r)?;
            let val = read_expr_string(r)?;
            format!("info[{key}] = \"{val}\"")
        }
        6 => {
            let left = decode_expression(r, depth + 1)?;
            let right = decode_expression(r, depth + 1)?;
            format!("({left} and {right})")
        }
        7 => {
            let left = decode_expression(r, depth + 1)?;
            let right = decode_expression(r, depth + 1)?;
            format!("({left} or {right})")
        }
        8 => format!("cdhash H\"{}\"", hex_encode(read_expr_data(r)?)),
        9 => {
            let inner = decode_expression(r, depth + 1)?;
            format!("!({inner})")
        }
        10 => {
            let key = read_expr_string(r)?;
            let m = read_match(r)?;
            format!("info[{key}] {m}")
        }
        11 => {
            let slot = r.u32_be()?;
            let field = read_expr_string(r)?;
            let m = read_match(r)?;
            format!("certificate {slot}[{field}] {m}")
        }
        12 => format!("certificate {} trusted", r.u32_be()?),
        13 => "anchor trusted".into(),
        14 => {
            let slot = r.u32_be()?;
            let oid = read_expr_data(r)?;
            let m = read_match(r)?;
            format!("certificate {slot}[field.{}] {m}", hex_encode(oid))
        }
        15 => "anchor apple generic".into(),
        16 => {
            let key = read_expr_string(r)?;
            let m = read_match(r)?;
            format!("entitlement[{key}] {m}")
        }
        17 => {
            let slot = r.u32_be()?;
            let oid = read_expr_data(r)?;
            let m = read_match(r)?;
            format!("certificate {slot}[policy.{}] {m}", hex_encode(oid))
        }
        18 => format!("anchor apple {}", read_expr_string(r)?),
        19 => format!("anchor named \"{}\"", read_expr_string(r)?),
        20 => format!("platform = {}", r.u32_be()?),
        21 => "notarized".into(),
        22 => {
            let slot = r.u32_be()?;
            let field = read_expr_string(r)?;
            let m = read_match(r)?;
            format!("certificate {slot}[{field}.date] {m}")
        }
        23 => "legacy".into(),
        _ => format!("op({op_low:#x})"),
    })
}

/// Match-suffix operator. The opcode tag advances the cursor; for
/// every flavour except `exists` a string operand follows.
fn read_match(r: &mut Reader<'_>) -> Option<String> {
    let op = r.u32_be()?;
    Some(match op {
        0 => "exists".into(),
        1 => format!("= \"{}\"", read_expr_string(r)?),
        2 => format!("~ \"*{}*\"", read_expr_string(r)?),
        3 => format!("~ \"{}*\"", read_expr_string(r)?),
        4 => format!("~ \"*{}\"", read_expr_string(r)?),
        5 => format!("< \"{}\"", read_expr_string(r)?),
        6 => format!("> \"{}\"", read_expr_string(r)?),
        7 => format!("<= \"{}\"", read_expr_string(r)?),
        8 => format!(">= \"{}\"", read_expr_string(r)?),
        _ => format!("match({op:#x})"),
    })
}

/// Length-prefixed UTF-8 string. Strings are padded with NULs to the
/// next 4-byte boundary.
fn read_expr_string(r: &mut Reader<'_>) -> Option<String> {
    std::str::from_utf8(read_expr_data(r)?)
        .ok()
        .map(str::to_owned)
}

/// Length-prefixed binary blob (certificate hashes, OIDs). Padded to
/// the next 4-byte boundary just like strings.
fn read_expr_data<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let len = r.u32_be()? as usize;
    let data = r.bytes(len)?;
    // A blob that ends inside the padding still yields this operand; the
    // next read fails either way, as every operand opens with a `u32`.
    let _ = r.skip((4 - (len & 3)) & 3);
    Some(data)
}

fn parse_entitlements(blob: &[u8], values: &mut Values) {
    // 8-byte header (magic + length); the rest is XML plist.
    let Some(xml_bytes) = blob.get(8..).filter(|xml| !xml.is_empty()) else {
        return;
    };
    if xml_bytes.len() > MAX_ENTITLEMENT_XML_BYTES {
        return;
    }
    let Ok(parsed) = super::plist_guard::parse(xml_bytes) else {
        // Surface raw text as a fallback so the consumer at least sees
        // what was claimed.
        if let Ok(s) = std::str::from_utf8(xml_bytes) {
            put_str(
                values,
                value_key!("macho.code_signature.entitlements_xml"),
                s,
            );
        }
        return;
    };
    let json = plist_to_json(parsed, 0);
    values.insert_key(value_key!("macho.code_signature.entitlements"), json);
}

/// `code_directory` is the blob the signature covers; without one the
/// signature binds nothing and reads as unverifiable.
fn parse_cms(blob: &[u8], code_directory: Option<&[u8]>, values: &mut Values) {
    if blob.len() <= 8 {
        return;
    }
    // Record the CMS blob's byte size. The CMS sub-object below
    // signals presence on its own when the strict-DER parse succeeds;
    // the explicit size field carries forensic value (unusually small
    // or large CMS payloads are a malware-signing red flag) and
    // doubles as a presence marker for the BER-encoded majority where
    // the deep parse can't decode the SignedData.
    put_u64(
        values,
        value_key!("macho.code_signature.cms_size"),
        (blob.len() - 8) as u64,
    );
    // Apple emits the inner SignedData with BER indefinite-length
    // encoding; the CMS parser normalizes it to DER before decoding.
    // The signature is detached: it covers the CodeDirectory, which
    // `verified` checks it against.
    let Some(der) = blob.get(8..) else {
        return;
    };
    let sig = match code_directory {
        Some(cd) => super::pe_authenticode::parse_detached_cms_blob(der, cd),
        None => super::pe_authenticode::parse_cms_blob(der),
    };
    if let Some(sig) = sig {
        values.insert_key(value_key!("macho.code_signature.cms"), sig);
    }
}

fn read_cstr(b: &[u8], off: usize) -> Option<String> {
    if off >= b.len() {
        return None;
    }
    let slice = b.get(off..)?;
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    std::str::from_utf8(slice.get(..end)?)
        .ok()
        .map(str::to_string)
}

fn hash_label(t: u8) -> &'static str {
    // Constants from `CS_HASHTYPE_*` in xnu's `cs_blobs.h`.
    match t {
        1 => "sha1",
        2 => "sha256",
        3 => "sha256_truncated",
        4 => "sha384",
        5 => "sha512",
        _ => "unknown",
    }
}

fn code_signature_flags(flags: u32) -> Vec<String> {
    // From xnu `CS_*` flags. Forensically relevant subset.
    let mut out = Vec::new();
    if flags & 0x0000_0001 != 0 {
        out.push("valid".to_string());
    }
    if flags & 0x0000_0002 != 0 {
        out.push("ad_hoc".to_string());
    }
    if flags & 0x0000_0004 != 0 {
        out.push("get_task_allow".to_string());
    }
    if flags & 0x0000_0008 != 0 {
        out.push("installer".to_string());
    }
    if flags & 0x0000_0100 != 0 {
        out.push("hard".to_string());
    }
    if flags & 0x0000_0200 != 0 {
        out.push("kill".to_string());
    }
    if flags & 0x0000_0400 != 0 {
        out.push("check_expiration".to_string());
    }
    if flags & 0x0000_0800 != 0 {
        out.push("restrict".to_string());
    }
    if flags & 0x0000_1000 != 0 {
        out.push("enforcement".to_string());
    }
    if flags & 0x0000_2000 != 0 {
        out.push("library_validation".to_string());
    }
    if flags & 0x0001_0000 != 0 {
        out.push("runtime".to_string());
    }
    if flags & 0x0002_0000 != 0 {
        out.push("linker_signed".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
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
        assert!(f.contains(&"ad_hoc".to_string()));
        assert!(f.contains(&"library_validation".to_string()));
        assert!(f.contains(&"runtime".to_string()));
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
        assert!(f.contains(&"ad_hoc".to_string()));
        assert!(!f.contains(&"adhoc".to_string()));
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
        assert_eq!(f.last().map(String::as_str), Some("linker_signed"));
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
    fn code_directory(
        code: &[u8],
        page_log2: u8,
        ident: &str,
        specials: &[(u32, &[u8])],
    ) -> Vec<u8> {
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
}
