//! Fast file format identification by magic bytes, shebangs, and extensions.
//!
//! `fileid` identifies file formats with a content-first pipeline, an
//! ordered table of rules where the first that claims the file decides:
//!
//! 1. **Signatures** — magic bytes, shebangs and structural markers. Most sit
//!    in the first few bytes; some are read further in (a tar header at 257, an
//!    ISO volume descriptor at 32 KiB, a DMG trailer at the end), and archives
//!    are walked far enough to see which package layout they carry
//! 2. **Content rules** — document shapes, unmistakable marks and the language
//!    scorer, over a bounded window (a few KiB, plus the tail of a padded file;
//!    no tree-sitter)
//! 3. **Filename and extension fallback** — used only when content does not
//!    identify a stronger type
//!
//! How far a name is believed against content is one column of the
//! [`FileType`] table, its extension strength: weak names and container names
//! whose signature is absent yield to content, a language name yields only to
//! a binary or plainly foreign body, and a name for a format defined by its
//! magic is wrong once the magic is absent. If no rule yields a result,
//! `detect` returns `None`.
//!
//! # Example
//!
//! ```
//! use filefacts::{FileId, FileType};
//!
//! let data = b"\x7fELF\x02\x01\x01\x00";
//! let id = FileId::from_bytes(data);
//! assert_eq!(id.file_type(), FileType::Elf);
//! ```

pub mod container;
mod dos;
mod ext;
mod file_type;
mod go_module;
mod heuristics;
pub(crate) mod image4_trustcache;
mod magic;
mod markdown;
mod marks;
mod package_layout;
mod perl_shell_shim;
pub(crate) mod phar;
mod restructuredtext;
mod scripts;
pub(crate) mod shellcode;
mod sniff;
mod text;
mod torch;
mod zip_probe;

pub use container::{ArchiveFormat, Compression, Container, container_of};
pub use file_type::{FileType, Group};
pub(crate) use magic::looks_like_obfuscated_rtf;
pub(crate) use torch::legacy_header as torch_protocol2_legacy_header;

use std::path::Path;

use serde::Serialize;
use sniff::Sniff;
use stng::{RepeatingXorKey, recover_repeating_xor_pe};
use text::strip_utf8_bom;

/// Result of file-format identification.
///
/// `FileId` is the public face of file detection: it carries the
/// identified [`FileType`], the [`DetectionSource`] that determined it,
/// and a flag for cases where the file's extension disagrees with its
/// content. The detection pipeline never returns "unknown plus an
/// error" — failures collapse to [`FileType::Unknown`].
///
/// Access state through the accessor methods ([`Self::file_type`],
/// [`Self::source`], [`Self::extension_mismatch`]); the fields stay
/// crate-private so new state can be added without breaking
/// downstream consumers.
///
/// Serialized as `file_type`, `source`, `extension_mismatch` and
/// `mismatch_ext_type`; the last two are derived from how the extension
/// relates to the content.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FileId {
    pub(crate) file_type: FileType,
    pub(crate) source: DetectionSource,
    /// How the extension relates to the content, benign conventions already
    /// excused. [`Self::extension_mismatch`] and the extension's type are
    /// read from it, so the two cannot disagree.
    pub(crate) ext_match: ExtensionMatch,
    /// The key of a PE under a repeating XOR key; see [`identify`].
    pub(crate) xor_pe_key: Option<RepeatingXorKey>,
}

impl Serialize for FileId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileId", 4)?;
        state.serialize_field("file_type", &self.file_type)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("extension_mismatch", &self.extension_mismatch())?;
        state.serialize_field("mismatch_ext_type", &self.mismatch_ext_type())?;
        state.end()
    }
}

impl FileId {
    /// Identify a byte slice without reference to any filename.
    ///
    /// Equivalent to passing an empty path to [`Self::from_path_and_bytes`].
    /// Always succeeds; unidentifiable input is reported as
    /// `FileType::Unknown` rather than as an error.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_path_and_bytes(Path::new(""), bytes)
    }

    /// Identify a byte slice with the original filename / extension
    /// available. Extensions inform the result only as a tiebreaker —
    /// content always wins when magic bytes are conclusive.
    #[must_use]
    pub fn from_path_and_bytes(path: &Path, bytes: &[u8]) -> Self {
        // Detection runs many hand-written heuristics over untrusted bytes; a
        // panic in one must not take the caller down with it.
        let identified = crate::panic_guard::catch_infallible(|| identify(path, bytes)).ok();
        let Some((detection, xor_pe_key)) = identified else {
            tracing::debug!(
                target: "filefacts::fileid",
                path = %path.display(),
                len = bytes.len(),
                "identification panicked; reporting unknown"
            );
            return Self {
                source: DetectionSource::Failed,
                ..Self::forced(FileType::Unknown)
            };
        };
        match detection {
            // `identify` has already excused the benign format conventions,
            // so this is the same answer `detect` gives.
            Some(d) => Self {
                file_type: d.file_type,
                source: d.source,
                ext_match: d.ext_match,
                xor_pe_key,
            },
            None => Self {
                file_type: FileType::Unknown,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Consistent,
                xor_pe_key: None,
            },
        }
    }

    /// Construct a `FileId` for a caller-known type, bypassing the
    /// detection pipeline entirely.
    ///
    /// Use when the language is established by surrounding context that the
    /// bytes themselves don't carry: the inner body of an interpreter
    /// inline-code invocation (`python3 -c "<code>"`, `node -e '<code>'`)
    /// has no shebang, extension, or magic, so [`from_path_and_bytes`]
    /// would fall back to [`FileType::Unknown`] and skip source parsing.
    /// The reported [`source`](Self::source) is [`DetectionSource::Forced`];
    /// no extension comparison is made, so `extension_mismatch` is `false`.
    ///
    /// [`from_path_and_bytes`]: Self::from_path_and_bytes
    #[must_use]
    pub fn forced(file_type: FileType) -> Self {
        Self {
            file_type,
            source: DetectionSource::Forced,
            ext_match: ExtensionMatch::Consistent,
            xor_pe_key: None,
        }
    }

    /// The identified file type.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// For opaque data that is a PE under a repeating XOR key, the key that
    /// decodes it. Recovered once, during identification.
    #[must_use]
    pub fn xor_pe_key(&self) -> Option<RepeatingXorKey> {
        self.xor_pe_key
    }

    /// How the type was determined.
    #[must_use]
    pub fn source(&self) -> DetectionSource {
        self.source
    }

    /// `true` when content-based detection disagrees with the file's
    /// extension. Useful as a low-friction evasion signal. Benign format
    /// conventions (AppleDouble sidecars, Android APK, XHTML, FreeBSD pkg)
    /// are excluded.
    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        self.ext_match.is_mismatch(self.source)
    }

    /// When [`Self::extension_mismatch`] holds, the type the *extension*
    /// implied (`None` when the extension is unrecognized). Lets callers
    /// describe the mismatch as a content-group→extension-group transition
    /// without deciding, here, whether that transition is dangerous.
    fn mismatch_ext_type(&self) -> Option<FileType> {
        if self.extension_mismatch() {
            self.ext_match.extension_type(self.file_type)
        } else {
            None
        }
    }

    /// When [`Self::extension_mismatch`] holds, the coarse
    /// `(content_group, extension_group)` transition — e.g. `("binary",
    /// "image")` for a PE named `.png`. The extension group is `"unknown"`
    /// when the extension is unrecognized (e.g. `.woff2` carrying a PE).
    ///
    /// This deliberately reports *what kind* of mismatch occurred and leaves
    /// the severity call to the consumer: a `.docx` named `.doc`
    /// (`document`→`document`) is mundane, while a PE named `.jpeg`
    /// (`binary`→`image`) is a masquerade. Returns `None` when there is no
    /// genuine mismatch.
    #[must_use]
    pub fn extension_mismatch_transition(&self) -> Option<(&'static str, &'static str)> {
        if !self.extension_mismatch() {
            return None;
        }
        let content = self.file_type.group().label();
        let ext = self
            .mismatch_ext_type()
            .map_or("unknown", |ft| ft.group().label());
        Some((content, ext))
    }
}

/// How the file type was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// Magic bytes at the start of the file.
    Magic,
    /// Shebang line (`#!...`).
    Shebang,
    /// Well-known filename (e.g. `package.json`, `action.yml`).
    Filename,
    /// File extension mapping.
    Extension,
    /// Lightweight content heuristics (pattern matching).
    Heuristic,
    /// Extension overrode a shebang juke (e.g. `.js` file with `#!/bin/bash`).
    /// `extension_type()` returns the type the shebang claimed.
    ExtensionOverridesShebang,
    /// Type asserted by the caller via [`FileId::forced`] /
    /// [`crate::OpenOptions::file_type`], bypassing detection. Used when the language is
    /// already known from context the bytes alone don't carry — e.g. the
    /// inner source of a `python3 -c "<code>"` payload, whose extracted
    /// body has no shebang, extension, or magic to detect.
    Forced,
    /// Detection panicked on these bytes, so the type is
    /// [`FileType::Unknown`]. [`crate::ParsedFile::errors`] records it under
    /// [`crate::Stage::Identify`].
    Failed,
}

/// What the file extension implies about the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionMatch {
    /// Extension maps to the same type as content detection, or no extension present.
    Consistent,
    /// Extension maps to a different known type.
    Different(FileType),
    /// Extension is present but not recognized by fileid.
    Unknown,
    /// The extension was believed over a shebang naming another scripting
    /// language (see [`is_shebang_juke`]), so the detected type is the
    /// extension's. Holds the type the shebang claimed.
    ShebangClaimed(FileType),
    /// The extension disagrees with the content by a known format convention
    /// (see [`CONVENTIONS`]), so it is not reported as a mismatch. Holds the
    /// type the extension implies, when it is known.
    Conventional(Option<FileType>),
}

impl ExtensionMatch {
    /// How the type the name of `sniff` implies relates to `detected`, the
    /// type the content was identified as. An extension fileid does not know
    /// is `Unknown` only when it names something; see [`has_named_extension`].
    fn of(sniff: &Sniff<'_>, detected: FileType) -> Self {
        match sniff.ext_type() {
            Some(e) if e != detected => Self::Different(e),
            None if has_named_extension(sniff.path) => Self::Unknown,
            Some(_) | None => Self::Consistent,
        }
    }

    /// Whether this disagreement is reported as a mismatch for a type that
    /// was found by `source`. A type taken from the name has nothing to
    /// disagree with.
    fn is_mismatch(self, source: DetectionSource) -> bool {
        matches!(
            source,
            DetectionSource::Magic
                | DetectionSource::Shebang
                | DetectionSource::Heuristic
                | DetectionSource::ExtensionOverridesShebang
        ) && matches!(
            self,
            Self::Different(_) | Self::Unknown | Self::ShebangClaimed(_)
        )
    }

    /// The type the extension implies, where it differs from the content
    /// or was believed over a shebang; `detected` is the type identified.
    fn extension_type(self, detected: FileType) -> Option<FileType> {
        match self {
            Self::Different(ft) | Self::Conventional(Some(ft)) => Some(ft),
            Self::ShebangClaimed(_) => Some(detected),
            Self::Consistent | Self::Unknown | Self::Conventional(None) => None,
        }
    }
}

/// Result of file format identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// The identified file type.
    pub file_type: FileType,
    /// How we identified it.
    pub source: DetectionSource,
    /// Relationship between detected type and file extension.
    ext_match: ExtensionMatch,
}

impl Detection {
    /// `file_type`, found by `source`, set against what the name of `sniff`
    /// implies.
    fn found(sniff: &Sniff<'_>, file_type: FileType, source: DetectionSource) -> Self {
        Self {
            file_type,
            source,
            ext_match: ExtensionMatch::of(sniff, file_type),
        }
    }

    /// `file_type`, found by content heuristics.
    fn heuristic(sniff: &Sniff<'_>, file_type: FileType) -> Self {
        Self::found(sniff, file_type, DetectionSource::Heuristic)
    }

    /// A type the name agrees with: the name's own claim, or one content
    /// established with nothing in the name to contradict it.
    fn named(file_type: FileType, source: DetectionSource) -> Self {
        Self {
            file_type,
            source,
            ext_match: ExtensionMatch::Consistent,
        }
    }

    /// True when content-based detection identified a different type than
    /// the file's extension implies.
    ///
    /// This covers two cases:
    /// - Extension maps to a *different* known type than content detected
    /// - Extension is present but *unknown* to fileid (e.g. `.woff2` containing PE)
    ///
    /// Returns false when:
    /// - Detection was extension/filename-based (no conflict possible)
    /// - The file has no extension
    /// - The extension maps to the same type as content detection
    /// - The disagreement is a known format convention (AppleDouble sidecars,
    ///   Android/Alpine APK, package-specific archives, XHTML), as for
    ///   [`FileId::extension_mismatch`]
    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        self.ext_match.is_mismatch(self.source)
    }

    /// True when content was identified as a script language but the
    /// shebang juked toward a different scripting language. Callers can
    /// use this to label the mismatch as "shebang juke" rather than the
    /// generic extension/content disagreement.
    #[must_use]
    pub fn is_shebang_juke(&self) -> bool {
        self.source == DetectionSource::ExtensionOverridesShebang
    }

    /// The file type implied by the extension, if any.
    /// `None` when the extension is absent, unrecognized, or matches the
    /// detected type. After a shebang juke ([`Self::is_shebang_juke`]) the
    /// extension was believed, so its type is the detected type.
    #[must_use]
    pub fn extension_type(&self) -> Option<FileType> {
        self.ext_match.extension_type(self.file_type)
    }

    /// The scripting language a shebang claimed when the extension was
    /// believed over it ([`Self::is_shebang_juke`]).
    #[must_use]
    pub fn shebang_type(&self) -> Option<FileType> {
        match self.ext_match {
            ExtensionMatch::ShebangClaimed(ft) => Some(ft),
            _ => None,
        }
    }

    /// `self`, with a mismatch that is a known format convention no longer
    /// reported as one.
    fn excuse_convention(mut self, sniff: &Sniff<'_>) -> Self {
        if !self.extension_mismatch() {
            return self;
        }
        let ext = self.extension_type();
        let case = Convention {
            sniff,
            ext,
            content: self.file_type,
        };
        if let Some(&(name, _)) = CONVENTIONS.iter().find(|(_, holds)| holds(&case)) {
            tracing::debug!(
                target: "filefacts::fileid",
                convention = name,
                file_type = %self.file_type,
                extension = ?ext,
                "extension mismatch excused by format convention"
            );
            self.ext_match = ExtensionMatch::Conventional(ext);
        }
        self
    }
}

/// True when a shebang→extension mismatch should be treated as evasion.
///
/// Specifically: a shell shebang on a file whose extension claims a different
/// scripting language. We treat the extension as authoritative in this case.
/// We deliberately do NOT generalise to all script-vs-script mismatches —
/// `#!/usr/bin/env python3` on a `.py` file with no other indicators is fine.
fn is_shebang_juke(detected: FileType, ext_type: FileType) -> bool {
    matches!(detected, FileType::Shell)
        && matches!(
            ext_type,
            FileType::JavaScript
                | FileType::TypeScript
                | FileType::Python
                | FileType::Ruby
                | FileType::Php
                | FileType::Perl
                | FileType::Lua
        )
}

/// An extension/content disagreement weighed against the known conventions.
struct Convention<'s, 'a> {
    sniff: &'s Sniff<'a>,
    /// The type the extension implies, when fileid knows it.
    ext: Option<FileType>,
    /// The type the content was identified as.
    content: FileType,
}

impl Convention<'_, '_> {
    fn name_ends_ci(&self, suffix: &str) -> bool {
        self.sniff
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| ext::ends_with_ci(n.as_bytes(), suffix.as_bytes()))
    }

    /// The legacy PyTorch and `torch.save` model suffixes.
    fn torch_model_name(&self) -> bool {
        [".pt", ".pth", ".ckpt"]
            .iter()
            .any(|suffix| self.name_ends_ci(suffix))
    }
}

/// Whether a convention holds for a disagreement.
type Holds = fn(&Convention<'_, '_>) -> bool;

/// The format conventions under which an extension and the content disagree
/// benignly, so the disagreement is not an evasion signal. The first that
/// holds excuses the mismatch; the name is logged.
const CONVENTIONS: &[(&str, Holds)] = &[
    // macOS AppleDouble sidecars (`._name`) carry resource-fork bytes whose
    // type intentionally differs from the extension.
    ("appledouble_sidecar", |c| {
        c.sniff
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("._"))
    }),
    // Apple localized `.strings` files use either binary or XML property
    // lists. This says nothing about code disguised under that suffix.
    ("apple_strings_plist", |c| {
        c.content == FileType::Plist && c.name_ends_ci(".strings")
    }),
    // Legacy PyTorch uses pickle plus raw storage under its model suffixes.
    // Its native magic and version framing are required; the suffix grants
    // no trust.
    ("torch_legacy_pickle", |c| {
        c.content == FileType::Pickle && c.torch_model_name() && torch::legacy_header(c.sniff.data)
    }),
    // Modern torch.save and TorchScript keep those suffixes around a ZIP
    // carrier. Central-directory and serialization-role framing is required;
    // an arbitrary ZIP renamed `.pt` still disagrees with its suffix.
    ("torch_zip_carrier", |c| {
        c.content == FileType::Zip && c.torch_model_name() && torch::recognized(c.sniff)
    }),
    // Formats written in YAML or JSON: refining the generic document type to
    // the specific one is agreement about the same file.
    ("yaml_dialect", |c| {
        c.ext == Some(FileType::Yaml)
            && matches!(c.content, FileType::GithubActions | FileType::PnpmLock)
    }),
    ("npm_lockfile_json", |c| {
        c.ext == Some(FileType::Json) && c.content == FileType::PackageLockJson
    }),
    // A phar is also written as a plain tar or zip archive.
    ("phar_container", |c| {
        c.ext == Some(FileType::Phar) && matches!(c.content, FileType::Tar | FileType::Zip)
    }),
    // An XML plist is an XML document. A binary plist named `.xml` still
    // disagrees with that serialization and is not excused.
    ("xml_plist", |c| {
        let head = c.sniff.data.trim_ascii_start();
        c.ext == Some(FileType::Xml)
            && c.content == FileType::Plist
            && (head.starts_with(b"<?xml") || head.starts_with(b"<plist"))
    }),
    // `.sig` is shared by OpenPGP and certificate-bearing signature
    // containers; both are detached signatures.
    ("signature_sidecar", |c| {
        c.ext == Some(FileType::PgpSignature)
            && c.content == FileType::CertificateSignature
            && (c.name_ends_ci(".sig") || c.name_ends_ci(".sign"))
    }),
    // An Image4 payload name agrees with the trust cache it carries.
    ("image4_payload", |c| {
        c.content == FileType::Image4TrustCache
            && (c.name_ends_ci(".im4p") || c.name_ends_ci(".trustcache"))
    }),
    // `.exe` is shared by the older 16-bit Windows NE format and PE.
    ("ne_executable", |c| {
        c.ext == Some(FileType::Pe) && c.content == FileType::Ne && c.name_ends_ci(".exe")
    }),
    // `.apk` names Android's zip and Alpine's gzip tar; the container
    // decides which, and `.pkg` names macOS, FreeBSD and Arch packages.
    ("shared_package_suffix", |c| {
        (c.name_ends_ci(".apk") && matches!(c.content, FileType::ApkAndroid | FileType::ApkAlpine))
            || (c.name_ends_ci(".pkg")
                && matches!(c.content, FileType::PkgFreebsd | FileType::PkgArch))
    }),
    // The content refined a generic archive name to the package it holds
    // (an npm `.tgz`, a Go module `.zip`, an OCI `.tar`): same container,
    // same compression, so the name and the bytes agree on the archive.
    ("package_in_generic_archive", |c| {
        let data = c.sniff.data;
        c.ext.is_some_and(|ext| {
            let named = container_of(ext, data).or_else(|| {
                // A bare codec name wraps whatever tar the content holds.
                let codec = codec_of(ext)?;
                container_of(c.content, data).filter(|inner| inner.compression == codec)
            });
            named.is_some() && named == container_of(c.content, data)
        })
    }),
    // A Windows Script Host job or component declares its own language, and
    // JScript is as much at home in a `.wsf` / `.wsc` as VBScript.
    ("script_host_language", |c| {
        c.ext == Some(FileType::Vbs)
            && c.content == FileType::JavaScript
            && (c.name_ends_ci(".wsf") || c.name_ends_ci(".wsc"))
    }),
    // XHTML served with a `.html` extension but parsed as XML.
    ("xhtml", |c| {
        let head = c.sniff.data.get(..4096).unwrap_or(c.sniff.data);
        c.ext == Some(FileType::Html)
            && c.content == FileType::Xml
            && (text::contains_ci(head, b"<!doctype html") || text::contains_ci(head, b"<html"))
    }),
];

/// The codec a single-file compression type names.
const fn codec_of(ft: FileType) -> Option<Compression> {
    match ft {
        FileType::Gz => Some(Compression::Gzip),
        FileType::Bz2 => Some(Compression::Bzip2),
        FileType::Xz => Some(Compression::Xz),
        FileType::Zst => Some(Compression::Zstd),
        _ => None,
    }
}

/// Detect file type from content + path. Content is trusted first, extension as fallback.
///
/// Returns `None` if the file format cannot be identified. This is the same
/// detection [`FileId::from_path_and_bytes`] makes, benign extension
/// conventions included; only the XOR key of [`FileId::xor_pe_key`] is not
/// carried.
#[must_use]
pub fn detect(path: &Path, data: &[u8]) -> Option<Detection> {
    identify(path, data).0
}

/// [`detect`], plus the key when the file is a PE under a repeating XOR key,
/// as droppers ship their payload inside a jar or package (`hvnc.enc`,
/// `payload.bin`). Magic cannot see such a file; as Data it reaches the
/// generic analyzer, and the key lets the consumer decode the image. It is
/// recovered from known plaintext and checked against the PE header, so this
/// cannot claim random bytes. Only opaque outcomes (Data, or nothing
/// recognised) and GIF-signature carriers are tried. A GIF header can front an
/// encoded PE without changing its bytes; retain the carrier identity and
/// expose the independently validated key.
pub(crate) fn identify(path: &Path, data: &[u8]) -> (Option<Detection>, Option<RepeatingXorKey>) {
    let sniff = Sniff::new(path, data);
    let (detection, key) = match detect_known(&sniff) {
        Some(d) if matches!(d.file_type, FileType::Data | FileType::Gif) => {
            (Some(d), recover_repeating_xor_pe(data))
        }
        Some(d) => (Some(d), None),
        None => match recover_repeating_xor_pe(data) {
            // An unrecognised extension (`.enc`) says nothing that opaque
            // data contradicts.
            Some(key) => (
                Some(Detection::named(FileType::Data, DetectionSource::Heuristic)),
                Some(key),
            ),
            // Nothing recognised the file. A DOS COM in a store that names
            // files by hash has no `.com` to go on, and carved shellcode has
            // no name at all; Unknown is not analyzed, so the program shape
            // is the last word.
            None => (
                headerless_program(data).map(|ft| Detection::heuristic(&sniff, ft)),
                None,
            ),
        },
    };
    if let Some(key) = key {
        tracing::debug!(
            target: "filefacts::fileid",
            key_len = key.bytes().len(),
            pe_offset = key.pe_offset(),
            "repeating-XOR PE key recovered"
        );
    }
    (detection.map(|d| d.excuse_convention(&sniff)), key)
}

/// One identification rule: the verdict it reaches on the sniffed input, or
/// `None` to pass to the next.
type Rule = fn(&Sniff<'_>) -> Option<Detection>;

/// The rules [`identify`] tries, in priority order; the first verdict wins.
/// Each is named for the decision log.
const RULES: &[(&str, Rule)] = &[
    ("signature", signature),
    ("fat_boot_sector", fat_boot_sector),
    ("jest_snapshot", jest_snapshot),
    ("gcc_specs", gcc_specs),
    ("git_config", git_config),
    ("batch_polyglot", batch_polyglot),
    ("restructuredtext_document", restructuredtext_document),
    ("markdown_document", markdown_document),
    ("unmistakable_mark", unmistakable_mark),
    ("powershell_named_postscript", powershell_named_postscript),
    ("cmake", cmake),
    ("pyproject", pyproject),
    ("language_score", language_score),
    ("filename", filename),
    ("named_text", named_text),
    ("foreign_body", foreign_body),
    ("binary_unit_file", binary_unit_file),
    ("extension", extension),
];

/// Everything [`identify`] recognises without key recovery.
fn detect_known(sniff: &Sniff<'_>) -> Option<Detection> {
    let (rule, detection) = RULES
        .iter()
        .find_map(|&(name, rule)| rule(sniff).map(|d| (name, d)))?;
    tracing::debug!(
        target: "filefacts::fileid",
        rule,
        path = %sniff.path.display(),
        len = sniff.data.len(),
        file_type = %detection.file_type,
        source = ?detection.source,
        extension = ?sniff.ext_type(),
        mismatch = detection.extension_mismatch(),
        "identified"
    );
    Some(detection)
}

/// Magic bytes, shebangs and structural markers, settled against the name
/// where the two are known to meet.
fn signature(sniff: &Sniff<'_>) -> Option<Detection> {
    let (file_type, source) = magic::detect_from_sniff(sniff)?;
    let ext_ft = sniff.ext_type();
    if file_type == FileType::Html {
        if scripts::html_prefixed_batch(sniff.data) {
            return Some(Detection::heuristic(sniff, FileType::Batch));
        }
        // A `.jsp` / `.asp` / `.cfm` page often opens with an HTML prologue.
        // That prologue is magic for HTML, but the extension is what the
        // server executes. Prefer it; the prologue is not a different type.
        if let Some(ext_type) = ext_ft.filter(|ft| is_server_page(*ft)) {
            return Some(Detection::named(ext_type, DetectionSource::Extension));
        }
        // A saved page can open with a doctype and still be the server
        // page a few lines later. The mark replaces that HTML prologue
        // the same way it replaces a `.txt` name.
        if let Some(marked) = sniff.unmistakable().filter(|ft| is_server_page(*ft)) {
            return Some(Detection::heuristic(sniff, marked));
        }
    }
    if source == DetectionSource::Shebang {
        // A Perl script that re-executes itself under Perl from a shell
        // shebang is Perl, as its name says.
        if file_type == FileType::Shell
            && ext_ft == Some(FileType::Perl)
            && perl_shell_shim::recognized(sniff.data)
        {
            return Some(Detection::named(FileType::Perl, DetectionSource::Heuristic));
        }
        // Shebang juke: the shebang is a 12-byte string an attacker can
        // prepend to any file; the extension is what the user or loader
        // treats the file as. JavaScript `.js` carrying `#!/bin/bash` is a
        // textbook static-analysis evasion, so the extension is believed
        // and the shebang's claim is kept beside it.
        if let Some(ext_type) =
            ext_ft.filter(|&ext| ext != file_type && is_shebang_juke(file_type, ext))
        {
            return Some(Detection {
                file_type: ext_type,
                source: DetectionSource::ExtensionOverridesShebang,
                ext_match: ExtensionMatch::ShebangClaimed(file_type),
            });
        }
        // Node, Deno and Bun all run TypeScript, so a JavaScript-runtime
        // shebang on a `.ts` file names the runtime, not another language.
        if file_type == FileType::JavaScript && ext_ft == Some(FileType::TypeScript) {
            return Some(Detection::found(sniff, FileType::TypeScript, source));
        }
    }
    Some(Detection::found(sniff, file_type, source))
}

/// The server-page types, whose sources open with HTML by design.
const fn is_server_page(ft: FileType) -> bool {
    matches!(ft, FileType::Jsp | FileType::Asp | FileType::Cfml)
}

/// A standalone FAT volume boot sector has no container magic, so its
/// validated BPB identifies it before an opaque name can leave it unscanned.
fn fat_boot_sector(sniff: &Sniff<'_>) -> Option<Detection> {
    dos::looks_like_fat_boot_sector(sniff.data)
        .then(|| Detection::heuristic(sniff, FileType::FatBootSector))
}

/// Jest's `.snap` files are CommonJS exports of template strings. The
/// strings often contain HTML, which must not make the wrapper a page or
/// send a text snapshot to the SquashFS extractor. Real filesystem
/// signatures have already won.
fn jest_snapshot(sniff: &Sniff<'_>) -> Option<Detection> {
    let body = sniff.data.trim_ascii_start();
    (matches!(sniff.ext_type(), Some(FileType::Snap | FileType::SquashFs))
        && body.starts_with(b"// Jest Snapshot v")
        && body
            .split(|b| *b == b'\n')
            .skip(1)
            .find(|line| !line.trim_ascii().is_empty())
            .is_some_and(|line| line.trim_ascii_start().starts_with(b"exports[")))
    .then(|| Detection::heuristic(sniff, FileType::JavaScript))
}

/// GCC's extensionless specs files contain named `*spec:` sections. A name
/// alone is ambiguous, so both the filename and a section header are
/// required, and binary magic and executable shebangs have already won.
fn gcc_specs(sniff: &Sniff<'_>) -> Option<Detection> {
    let data = sniff.data;
    (sniff.path.file_name().is_some_and(|name| name == "specs")
        && magic::content_is_text(data)
        && data.split(|b| *b == b'\n').any(|line| {
            line.trim_ascii()
                .strip_prefix(b"*")
                .and_then(|s| s.strip_suffix(b":"))
                .is_some_and(|name| {
                    !name.is_empty() && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                })
        }))
    .then(|| Detection::heuristic(sniff, FileType::Text))
}

/// `.git/config` is normally extensionless. Its section/key structure is a
/// strong content signature, and may correct even a misleading filename
/// before source-language or exact-name fallbacks get a chance to win.
fn git_config(sniff: &Sniff<'_>) -> Option<Detection> {
    sniff
        .looks_like_git_config()
        .then(|| Detection::heuristic(sniff, FileType::Text))
}

/// A real batch prologue precedes the binary body in BAT/COM hybrids.
/// Registered suffixes must not discard the same content evidence that
/// identifies the hybrid under an unknown or prose suffix.
fn batch_polyglot(sniff: &Sniff<'_>) -> Option<Detection> {
    ((sniff.binary_not_source() || dos::looks_like_dos_com(sniff.data))
        && scripts::binary_batch_prologue(sniff))
    .then(|| Detection::heuristic(sniff, FileType::Batch))
}

/// ReStructuredText documents often contain executable-looking examples. A
/// sectioned document with directives or literal blocks is a document by its
/// content, even when those examples happen to score as a language or carry
/// another format's mark.
fn restructuredtext_document(sniff: &Sniff<'_>) -> Option<Detection> {
    (sniff.ext_type() == Some(FileType::Text)
        && sniff
            .path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rst"))
        && restructuredtext::document_structure(sniff.data))
    .then(|| Detection::named(FileType::Text, DetectionSource::Heuristic))
}

/// A document's fenced examples are not its execution language. Content
/// stays first for scripts renamed `.md`; actual Markdown needs both a
/// leading heading and a complete fenced block before this applies.
fn markdown_document(sniff: &Sniff<'_>) -> Option<Detection> {
    (sniff.ext_type() == Some(FileType::Markdown) && markdown::document_structure(sniff.data))
        .then(|| Detection::named(FileType::Markdown, DetectionSource::Heuristic))
}

/// One unmistakable mark beats the language scorer. It replaces a name that
/// yields to it (`.txt`, `.dat`, a container without its signature, a page),
/// no name at all, and a language name whose body carries not one token of
/// that language. A language the scorer cannot read cannot be shown absent,
/// so its name stays what it says.
fn unmistakable_mark(sniff: &Sniff<'_>) -> Option<Detection> {
    let marked = sniff.unmistakable()?;
    sniff
        .claim()
        .is_none_or(|c| {
            c.file_type == marked
                || c.yields_to_mark()
                || (c.claims_language() && heuristics::lacks_language_evidence(c.file_type, sniff))
        })
        .then(|| Detection::heuristic(sniff, marked))
}

/// `.ps` is shared by PostScript and PowerShell. A strong PowerShell content
/// score disambiguates script payloads, while the `%!PS` magic keeps real
/// PostScript authoritative.
fn powershell_named_postscript(sniff: &Sniff<'_>) -> Option<Detection> {
    let data = sniff.data;
    (sniff.ext_type() == Some(FileType::PostScript)
        && !data.trim_ascii_start().starts_with(b"%!PS")
        && (sniff.scored_type() == Some(FileType::PowerShell)
            || heuristics::has_powershell_char_code_array(data)))
    .then(|| Detection::heuristic(sniff, FileType::PowerShell))
}

/// CMake embeds compiler probes and arbitrary quoted strings, which can
/// outscore its command syntax as Lua or C. When its mandated entry point or
/// module extension carries recognizable CMake commands, the interpreter's
/// type stands.
fn cmake(sniff: &Sniff<'_>) -> Option<Detection> {
    const COMMANDS: [&[u8]; 9] = [
        b"cmake_minimum_required",
        b"cmake_policy",
        b"project",
        b"add_library",
        b"add_executable",
        b"target_link_libraries",
        b"find_package",
        b"configure_file",
        b"add_custom_command",
    ];
    if sniff.ext_type() != Some(FileType::Cmake) {
        return None;
    }
    let data = sniff.data;
    data.get(..16384)
        .unwrap_or(data)
        .split(|b| *b == b'\n')
        .any(|line| {
            let line = line.trim_ascii_start();
            line.iter()
                .position(|b| *b == b'(')
                .and_then(|open| line.get(..open))
                .is_some_and(|name| {
                    let name = name.trim_ascii_end();
                    COMMANDS
                        .iter()
                        .any(|command| name.eq_ignore_ascii_case(command))
                })
        })
        .then(|| Detection::named(FileType::Cmake, DetectionSource::Heuristic))
}

/// Python project declarations re-collected without their mandated name.
/// The document is parsed and PEP 621-specific fields are required; a
/// generic `[project]` table or a quoted example is insufficient.
fn pyproject(sniff: &Sniff<'_>) -> Option<Detection> {
    let data = sniff.data;
    if !sniff
        .ext_type()
        .is_none_or(|ft| matches!(ft, FileType::Text | FileType::PyProjectToml))
        || data.len() > 1024 * 1024
        || memchr::memmem::find(data, b"[project]").is_none()
    {
        return None;
    }
    let table: toml::Table = std::str::from_utf8(data).ok()?.parse().ok()?;
    let project = table.get("project")?.as_table()?;
    (project.get("name").is_some_and(toml::Value::is_str)
        && project
            .get("requires-python")
            .is_some_and(toml::Value::is_str)
        && project
            .get("dependencies")
            .is_some_and(toml::Value::is_array))
    .then(|| Detection::heuristic(sniff, FileType::PyProjectToml))
}

/// The language scorer replaces a name that yields to it, or none.
/// Ordinary source extensions stay authoritative: keyword scoring is too
/// weak to override `.go`, `.js`, `.swift`.
fn language_score(sniff: &Sniff<'_>) -> Option<Detection> {
    if !sniff.claim().is_none_or(|c| c.yields_to_scorer()) {
        return None;
    }
    let file_type = sniff.scored_type()?;
    Some(Detection::heuristic(sniff, file_type))
}

/// Content has had the first chance to identify the body. An exact filename
/// is the fallback when its bytes carry no stronger evidence.
fn filename(sniff: &Sniff<'_>) -> Option<Detection> {
    let claim = sniff.claim().filter(|c| c.by_name)?;
    Some(Detection::named(claim.file_type, DetectionSource::Filename))
}

/// Text under a named suffix fileid does not know (`.conf.local`). An
/// extensionless file is left unclassified unless a stronger rule
/// recognized it: plenty of opaque files are named without one.
fn named_text(sniff: &Sniff<'_>) -> Option<Detection> {
    (sniff.claim().is_none()
        && has_named_extension(sniff.path)
        && !sniff.data.is_empty()
        && magic::content_is_text(sniff.data))
    .then_some(Detection {
        file_type: FileType::Text,
        source: DetectionSource::Heuristic,
        ext_match: ExtensionMatch::Unknown,
    })
}

/// A language name on a body that is not that language: object code, a
/// page, or another language the line grammars and the scorer are sure of
/// while finding nothing of the claimed one. UTF-16 source is text here.
fn foreign_body(sniff: &Sniff<'_>) -> Option<Detection> {
    let ext = sniff.claim().filter(|c| c.claims_language())?.file_type;
    let found = if sniff.binary_not_source() {
        headerless_program(sniff.data).unwrap_or(FileType::Data)
    } else {
        heuristics::contradicts_extension(ext, sniff)?
    };
    Some(Detection {
        file_type: found,
        source: DetectionSource::Heuristic,
        ext_match: ExtensionMatch::Different(ext),
    })
}

/// A unit file and a desktop entry are text; a binary body under either
/// name is opaque data.
fn binary_unit_file(sniff: &Sniff<'_>) -> Option<Detection> {
    let ext = sniff
        .ext_type()
        .filter(|ft| matches!(ft, FileType::SystemdService | FileType::DesktopEntry))?;
    sniff.binary_not_source().then_some(Detection {
        file_type: FileType::Data,
        source: DetectionSource::Heuristic,
        ext_match: ExtensionMatch::Different(ext),
    })
}

/// The extension fallback, once no content rule resolved and the name was
/// not a well-known one.
fn extension(sniff: &Sniff<'_>) -> Option<Detection> {
    let file_type = sniff.ext_type()?;
    let data = sniff.data;
    let misnamed = || {
        Some(Detection {
            file_type: unclaimed_body_type(sniff),
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(file_type),
        })
    };
    // A format defined by its magic, whose magic the signature stage did not
    // find. The name is the only thing claiming it, and the bytes have
    // already said no.
    if !data.is_empty() && file_type.strength() == file_type::Strength::MagicDefined {
        return misnamed();
    }
    // `.m` is shared by Objective-C, MATLAB and Mercury. Objective-C carries
    // directives the scorer knows (`#import`, `@interface`) or at least C
    // statement structure; text with neither is not Objective-C because of
    // its suffix.
    if file_type == FileType::ObjectiveC
        && !data.is_empty()
        && !heuristics::has_language_evidence(file_type, sniff)
        && !heuristics::looks_like_c_family(data)
        && !heuristics::is_utf16_text(data)
    {
        return misnamed();
    }
    // A bitmap's header is decided by its signature. A `.dib` may leave out
    // the 14-byte file header and start at the info header; anything else
    // named `.bmp` is whatever its bytes are.
    if file_type == FileType::Bmp && !data.is_empty() && !magic::looks_like_dib_header(data) {
        return misnamed();
    }
    // Reaching this fallback means the body has no `<svg>` root, so the name
    // is not a reason to call it an image: `logo.svg` holding a script is the
    // script.
    if file_type == FileType::Svg {
        return misnamed();
    }
    // An HTML name requires markup in the body. The whole body is read: the
    // name is what licenses looking past a short prefix, so front-padding
    // cannot hide the page.
    if file_type == FileType::Html && !heuristics::looks_like_html(sniff.text()) {
        return None;
    }
    // A variant suffix after a dotted family name stands only when the
    // content names nothing; markup names a page.
    if sniff
        .claim()
        .is_some_and(|c| c.strength == file_type::Strength::Weak && c.claims_language())
        && heuristics::looks_like_html(sniff.text())
    {
        return Some(Detection {
            file_type: FileType::Html,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(file_type),
        });
    }
    // `.bin`/`.dat`/`.raw` say nothing about the content, and carved
    // programs routinely carry them. A program-shaped body under a generic
    // data name is the program.
    if file_type == FileType::Data
        && let Some(program) = headerless_program(data)
    {
        return Some(Detection {
            file_type: program,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(FileType::Data),
        });
    }
    Some(Detection::named(file_type, DetectionSource::Extension))
}

/// True when a path's trailing dot-segment is a named extension rather than
/// a version number or the final component of a dotted executable name.
///
/// `Path::extension` splits on the last dot, so `keyvault-keys@4.8.0` reports
/// an extension of `"0"`, `react-redux@7.1.25` reports `"25"`, and `python3.11`
/// reports `"11"`. Registry artifacts are routinely named this way — npm, crates
/// and gem tarballs are stored as `<name>@<semver>` with no suffix at all.
/// A run of digits claims nothing about a file's format, so it is not
/// something content can disagree with. The `.so.1.1` case has its own
/// handling in `ext::has_versioned_so_suffix`, which assigns the type.
///
/// An unregistered UpperCamelCase tail after a dotted stem is often a module
/// or executable name, such as `org.example.MyModule` or `us.zoom.ZoomDaemon`,
/// rather than a claim that the file has an unknown suffix. Known extensions
/// are resolved separately and still take precedence.
fn has_named_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if ext.is_empty() || ext.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let dotted_camel_case_tail =
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| {
                stem.contains('.')
                    && ext.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && ext.chars().any(|c| c.is_ascii_lowercase())
            });
    !dotted_camel_case_tail
}

/// A program with no header of its own: a DOS COM, else x86 code that opens
/// with a GetPC idiom.
fn headerless_program(data: &[u8]) -> Option<FileType> {
    if dos::looks_like_dos_com(data) {
        Some(FileType::DosCom)
    } else if shellcode::detect(data).is_some() {
        Some(FileType::Shellcode)
    } else {
        None
    }
}

/// What a body is once its name has been ruled out: binary, a page, a
/// language the scorer recognises, or plain text.
fn unclaimed_body_type(sniff: &Sniff<'_>) -> FileType {
    let data = sniff.data;
    if sniff.binary_not_source() || dos::looks_like_dos_com(data) {
        headerless_program(data).unwrap_or(FileType::Data)
    } else if let Some(marked) = sniff.unmistakable() {
        marked
    } else if heuristics::looks_like_html(sniff.text()) {
        FileType::Html
    } else {
        sniff.scored_type().unwrap_or(FileType::Text)
    }
}

/// Detect file type from content alone: the signature stage (magic bytes,
/// shebangs and structural markers such as a `go.mod` directive).
///
/// Does not consider file extensions or the language heuristics.
#[must_use]
pub fn detect_content(data: &[u8]) -> Option<Detection> {
    let sniff = Sniff::new(Path::new(""), data);
    magic::detect_from_sniff(&sniff).map(|(file_type, source)| Detection::named(file_type, source))
}

/// Detect file type from path/extension alone.
///
/// Does not examine file content.
#[must_use]
pub fn detect_path(path: &Path) -> Option<Detection> {
    ext::claim(path).map(|claim| {
        let source = if claim.by_name {
            DetectionSource::Filename
        } else {
            DetectionSource::Extension
        };
        Detection::named(claim.file_type, source)
    })
}

#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests;
