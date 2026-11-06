//! APK v1 (JAR) signature binding: whether a signature block that verified
//! over its `.SF` signature file reaches the members.
//!
//! The block signs only the `.SF`. The `.SF` digests `META-INF/MANIFEST.MF`,
//! as a whole (`<alg>-Digest-Manifest`) or, when that digest is absent or
//! does not match, section by section (`<alg>-Digest` of each manifest
//! section it lists), and the manifest digests each member. A block and `.SF`
//! lifted from another app verify perfectly over that app, so a signature
//! is bound to this archive only when every link holds and every member
//! that needs a digest (all but directories and the signing files under
//! `META-INF/`) is listed in the manifest and in the `.SF`, as apksig
//! requires. Every algorithm a section names must match, at least one of
//! SHA-1, SHA-256, SHA-384 and SHA-512 (the ones Android checks).
//!
//! Members are hashed as the `zip` crate inflates them, CRC-checked, against
//! a byte budget shared by every signature in the archive; a check the
//! budget, a size cap or an unreadable member stops is unverifiable, never
//! bound. Android refuses an archive naming a member twice, so such an
//! archive binds nothing: which copy a reader keeps is the reader's choice.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::ops::Range;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::formats::cms::Failure;
use crate::formats::zip::{MemberError, read_member};

/// The JAR manifest, by the exact name Android reads it under.
const MANIFEST: &str = "META-INF/MANIFEST.MF";
/// Manifest bytes read. The manifest holds a section per member, so it grows
/// with the archive; this is well past what the member cap allows for.
const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
/// Bytes hashed, per algorithm, to check every signature in one archive:
/// the members, the manifest and its sections. Past it, a signature is
/// unverifiable.
pub(super) const MAX_HASHED_BYTES: u64 = 256 * 1024 * 1024;
/// Member bytes read per call while hashing.
const CHUNK: usize = 64 * 1024;

/// How far a v1 signature reaches into its archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Binding {
    /// The `.SF` binds the manifest, and the manifest every member.
    Bound,
    /// A link fails: the signature does not cover this archive.
    Broken(Failure),
    /// The check could not finish, for the stated reason.
    Unverifiable(&'static str),
}

/// Checks v1 signature files against one archive, reading and hashing its
/// manifest and members once for all of them.
pub(super) struct Verifier {
    budget: u64,
    archive: Option<Result<Archive, Binding>>,
}

impl Verifier {
    /// A verifier that hashes at most `budget` bytes per algorithm.
    pub(super) fn new(budget: u64) -> Self {
        Self {
            budget,
            archive: None,
        }
    }

    /// Whether `signature_file`, whose block verified over it, binds `zip`.
    pub(super) fn bind<R: Read + Seek>(
        &mut self,
        zip: &mut ::zip::ZipArchive<R>,
        signature_file: &[u8],
    ) -> Binding {
        let Self { budget, archive } = self;
        match archive.get_or_insert_with(|| Archive::read(zip, budget)) {
            Ok(archive) => match archive.binds(signature_file, budget) {
                Binding::Bound => archive.members,
                broken => broken,
            },
            Err(binding) => *binding,
        }
    }
}

/// The archive's manifest, and whether it binds the members.
struct Archive {
    manifest: Vec<u8>,
    /// The manifest's member sections; the main section is left out.
    sections: Vec<Section>,
    /// Index into `sections` by member name.
    by_name: HashMap<Vec<u8>, usize>,
    /// Members the manifest must digest and every `.SF` must list.
    needed: Vec<String>,
    /// Whether the manifest's digests match every member in `needed`.
    members: Binding,
}

impl Archive {
    fn read<R: Read + Seek>(
        zip: &mut ::zip::ZipArchive<R>,
        budget: &mut u64,
    ) -> Result<Self, Binding> {
        let manifest_broken = Binding::Broken(Failure::JarManifestMismatch);
        if zip.has_duplicate_names() {
            return Err(Binding::Broken(Failure::JarMemberMismatch));
        }
        let manifest = match read_member(zip, MANIFEST, MAX_MANIFEST_BYTES) {
            Ok(Some(manifest)) => manifest,
            Ok(None) => return Err(manifest_broken),
            Err(MemberError::TooLarge { .. }) => {
                return Err(Binding::Unverifiable("manifest over the read cap"));
            }
            Err(MemberError::Zip(_)) => return Err(Binding::Unverifiable("manifest unreadable")),
        };
        let mut sections = sections(&manifest).ok_or(manifest_broken)?;
        if !sections.is_empty() {
            sections.remove(0);
        }
        let mut by_name = HashMap::with_capacity(sections.len());
        for (index, section) in sections.iter().enumerate() {
            let name = section.name().ok_or(manifest_broken)?;
            if by_name.insert(name.to_vec(), index).is_some() {
                return Err(manifest_broken);
            }
        }
        let needed: Vec<String> = zip
            .file_names()
            .filter_map(Result::ok)
            .filter(|name| needs_digest(name))
            .map(|name| name.to_string())
            .collect();
        let mut archive = Self {
            manifest,
            sections,
            by_name,
            needed,
            members: Binding::Bound,
        };
        archive.members = archive.members_bound(zip, budget);
        Ok(archive)
    }

    /// The manifest section naming member `name`.
    fn section(&self, name: &[u8]) -> Option<&Section> {
        self.sections.get(*self.by_name.get(name)?)
    }

    /// Whether every needed member's manifest digests match its bytes.
    /// Each must have a digest before any member is hashed.
    fn members_bound<R: Read + Seek>(
        &self,
        zip: &mut ::zip::ZipArchive<R>,
        budget: &mut u64,
    ) -> Binding {
        let unsigned = Binding::Broken(Failure::JarMemberMismatch);
        if self.needed.iter().any(|name| {
            self.section(name.as_bytes())
                .is_none_or(|section| Digests::of(section, "-Digest").is_empty())
        }) {
            return unsigned;
        }
        let mut buf = vec![0; CHUNK];
        for name in &self.needed {
            let Some(section) = self.section(name.as_bytes()) else {
                return unsigned;
            };
            let mut digests = Digests::of(section, "-Digest");
            if let Err(reason) = hash_member(zip, name, &mut digests, &mut buf, budget) {
                return Binding::Unverifiable(reason);
            }
            if !digests.matches() {
                return unsigned;
            }
        }
        Binding::Bound
    }

    /// Whether `signature_file` binds this manifest and lists every needed
    /// member.
    fn binds(&self, signature_file: &[u8], budget: &mut u64) -> Binding {
        let broken = Binding::Broken(Failure::JarManifestMismatch);
        let Some(mut entries) = sections(signature_file) else {
            return broken;
        };
        let main = (!entries.is_empty()).then(|| entries.remove(0));
        let mut listed = HashSet::with_capacity(entries.len());
        for entry in &entries {
            match entry.name() {
                Some(name) if listed.insert(name) => {}
                _ => return broken,
            }
        }
        let whole = main.map_or(Check::Absent, |main| {
            check(&main, "-Digest-Manifest", &self.manifest, budget)
        });
        match whole {
            Check::Match => {}
            Check::OverBudget => return Binding::Unverifiable("hash budget spent"),
            // Android and apksig fall back to the per-section digests.
            Check::Absent | Check::Mismatch => {
                for entry in &entries {
                    let raw = entry
                        .name()
                        .and_then(|name| self.section(name))
                        .and_then(|section| self.manifest.get(section.raw.clone()));
                    match raw.map(|raw| check(entry, "-Digest", raw, budget)) {
                        Some(Check::Match) => {}
                        Some(Check::OverBudget) => {
                            return Binding::Unverifiable("hash budget spent");
                        }
                        _ => return broken,
                    }
                }
            }
        }
        if self
            .needed
            .iter()
            .any(|name| !listed.contains(name.as_bytes()))
        {
            return Binding::Broken(Failure::JarMemberMismatch);
        }
        Binding::Bound
    }
}

/// Whether member `name` must be digested in the manifest: everything but
/// directories and the signing files directly under `META-INF/` (apksig's
/// rule).
fn needs_digest(name: &str) -> bool {
    if name.ends_with('/') {
        return false;
    }
    let Some(file) = name.strip_prefix("META-INF/") else {
        return true;
    };
    if file.contains('/') {
        return true;
    }
    let file = file.to_ascii_lowercase();
    !(file == "manifest.mf"
        || file.starts_with("sig-")
        || [".sf", ".rsa", ".dsa", ".ec"]
            .iter()
            .any(|ext| file.ends_with(ext)))
}

/// Feed member `name`'s inflated bytes to `digests`. `Err` names why the
/// hash could not finish.
fn hash_member<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    name: &str,
    digests: &mut Digests<'_>,
    buf: &mut [u8],
    budget: &mut u64,
) -> Result<(), &'static str> {
    let mut entry = zip.by_name(name).map_err(|e| {
        tracing::debug!(target: "filefacts::apk_android", stage = "v1-binding", member = name, error = %e, "member will not open");
        "member unreadable"
    })?;
    loop {
        let n = entry.read(buf).map_err(|e| {
            tracing::debug!(target: "filefacts::apk_android", stage = "v1-binding", member = name, error = %e, "member will not inflate");
            "member unreadable"
        })?;
        if n == 0 {
            return Ok(());
        }
        if !digests.update(buf.get(..n).unwrap_or_default(), budget) {
            return Err("hash budget spent");
        }
    }
}

/// One section of a manifest or signature file.
struct Section {
    /// Its bytes, the blank line ending it included: what a section digest
    /// covers.
    raw: Range<usize>,
    /// Attributes in order, continuation lines joined.
    attrs: Vec<(String, Vec<u8>)>,
}

impl Section {
    /// The value of its single `Name` attribute.
    fn name(&self) -> Option<&[u8]> {
        let mut names = self
            .attrs
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("Name"));
        let (_, name) = names.next()?;
        names.next().is_none().then_some(name.as_slice())
    }
}

/// Split a manifest or signature file into sections: runs of `Key: value`
/// lines ended by a blank line, a line starting with a space continuing the
/// value before it. Lines end in CR LF, LF or CR. `None` when a line is
/// neither an attribute nor a continuation of one.
fn sections(text: &[u8]) -> Option<Vec<Section>> {
    let mut out = Vec::new();
    let mut current: Option<Section> = None;
    let mut pos = 0;
    while let Some(rest) = text.get(pos..).filter(|rest| !rest.is_empty()) {
        let (len, ending) = match memchr::memchr2(b'\r', b'\n', rest) {
            Some(at) if rest.get(at..at + 2) == Some(b"\r\n") => (at, 2),
            Some(at) => (at, 1),
            None => (rest.len(), 0),
        };
        let line = rest.get(..len)?;
        let end = pos + len + ending;
        if line.is_empty() {
            if let Some(mut section) = current.take() {
                section.raw.end = end;
                out.push(section);
            }
        } else {
            let section = current.get_or_insert_with(|| Section {
                raw: pos..pos,
                attrs: Vec::new(),
            });
            if let Some(more) = line.strip_prefix(b" ") {
                section.attrs.last_mut()?.1.extend_from_slice(more);
            } else {
                let at = memchr::memmem::find(line, b": ")?;
                let key = std::str::from_utf8(line.get(..at)?).ok()?;
                section
                    .attrs
                    .push((key.to_string(), line.get(at + 2..)?.to_vec()));
            }
        }
        pos = end;
    }
    if let Some(mut section) = current {
        section.raw.end = text.len();
        out.push(section);
    }
    Some(out)
}

/// A digest algorithm a JAR manifest or signature file names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    /// The algorithm an attribute prefix names, as Android and apksig spell
    /// them; MD5 and the rest are not checked.
    fn named(name: &str) -> Option<Self> {
        Some(match name.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" | "SHA" => Self::Sha1,
            "SHA-256" => Self::Sha256,
            "SHA-384" => Self::Sha384,
            "SHA-512" => Self::Sha512,
            _ => return None,
        })
    }

    fn hasher(self) -> Box<dyn DynDigest> {
        match self {
            Self::Sha1 => Box::new(Sha1::new()),
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha384 => Box::new(Sha384::new()),
            Self::Sha512 => Box::new(Sha512::new()),
        }
    }
}

/// The digests a section states under `<alg><suffix>` attributes, and the
/// running hashes, one per algorithm, that check them.
struct Digests<'a> {
    claims: Vec<(Alg, &'a [u8])>,
    hashers: Vec<(Alg, Box<dyn DynDigest>)>,
}

impl<'a> Digests<'a> {
    fn of(section: &'a Section, suffix: &str) -> Self {
        let claims: Vec<(Alg, &[u8])> = section
            .attrs
            .iter()
            .filter_map(|(key, value)| {
                let at = key.len().checked_sub(suffix.len())?;
                let alg = key.get(..at)?;
                let tail = key.get(at..)?;
                tail.eq_ignore_ascii_case(suffix)
                    .then(|| Alg::named(alg))
                    .flatten()
                    .map(|alg| (alg, value.as_slice()))
            })
            .collect();
        let mut hashers: Vec<(Alg, Box<dyn DynDigest>)> = Vec::new();
        for &(alg, _) in &claims {
            if !hashers.iter().any(|(have, _)| *have == alg) {
                hashers.push((alg, alg.hasher()));
            }
        }
        Self { claims, hashers }
    }

    fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Hash `data` under every algorithm, charging `budget`; `false`, with
    /// nothing hashed, when it would overspend it.
    fn update(&mut self, data: &[u8], budget: &mut u64) -> bool {
        let cost = (data.len() as u64).saturating_mul(self.hashers.len() as u64);
        let Some(left) = budget.checked_sub(cost) else {
            return false;
        };
        *budget = left;
        for (_, hasher) in &mut self.hashers {
            hasher.update(data);
        }
        true
    }

    /// Whether there is a claim and every claim equals its digest.
    fn matches(self) -> bool {
        let digests: Vec<(Alg, Box<[u8]>)> = self
            .hashers
            .into_iter()
            .map(|(alg, hasher)| (alg, hasher.finalize()))
            .collect();
        !self.claims.is_empty()
            && self.claims.iter().all(|&(alg, claim)| {
                digests.iter().any(|(have, digest)| {
                    *have == alg && STANDARD.decode(claim).is_ok_and(|c| *c == **digest)
                })
            })
    }
}

/// The outcome of checking a section's digests over some bytes.
enum Check {
    /// The section names no digest under the suffix.
    Absent,
    Match,
    Mismatch,
    OverBudget,
}

fn check(section: &Section, suffix: &str, data: &[u8], budget: &mut u64) -> Check {
    let mut digests = Digests::of(section, suffix);
    if digests.is_empty() {
        Check::Absent
    } else if !digests.update(data, budget) {
        Check::OverBudget
    } else if digests.matches() {
        Check::Match
    } else {
        Check::Mismatch
    }
}

#[cfg(test)]
mod tests;
