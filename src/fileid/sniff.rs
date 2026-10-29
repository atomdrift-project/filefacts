//! One identification's input, and what has been derived from it so far.
//!
//! The rules of [`super::identify`] ask the same questions of the same bytes:
//! what the name claims, whether a format's mark is present, what the line
//! grammars and the language scorer make of the body, whether the bytes open
//! as a zip, and the UTF-16 decode behind several of those. A [`Sniff`]
//! answers each the first time it is asked and keeps the answer, so every
//! derivation runs at most once per call however many rules consult it.
//! Nothing here decides a type; the rules still run in their own order and
//! the first match still wins.

use std::{borrow::Cow, cell::OnceCell, path::Path};

use super::{
    FileType,
    ext::{self, Claim},
    heuristics::{self, Scores},
    marks,
    scripts::{self, Evidence},
    strip_utf8_bom, zip_probe,
};

/// The path and bytes being identified, with lazily computed derivations.
pub(super) struct Sniff<'a> {
    /// The name the bytes arrived under.
    pub(super) path: &'a Path,
    /// The bytes, as given.
    pub(super) data: &'a [u8],
    /// `data` without a leading UTF-8 byte-order mark.
    pub(super) body: &'a [u8],
    /// [`ext::claim`].
    claim: OnceCell<Option<Claim>>,
    /// [`heuristics::decoded_text`]: UTF-16 narrowed for the byte scorers.
    decoded: OnceCell<Option<Cow<'a, [u8]>>>,
    /// [`scripts::evidence`] of [`Self::text`] past its leading whitespace.
    evidence: OnceCell<Evidence>,
    /// [`heuristics::head_scores`] of [`Self::text`].
    scores: OnceCell<Scores>,
    /// [`heuristics::scored_type`].
    scored: OnceCell<Option<FileType>>,
    /// [`marks::unmistakable`].
    marked: OnceCell<Option<FileType>>,
    /// [`marks::looks_like_git_config`].
    git_config: OnceCell<bool>,
    /// [`heuristics::binary_not_source`].
    binary_not_source: OnceCell<bool>,
    /// The bytes opened as a zip, when they are one.
    zip: OnceCell<Option<zip_probe::Archive<'a>>>,
}

impl<'a> Sniff<'a> {
    pub(super) fn new(path: &'a Path, data: &'a [u8]) -> Self {
        Self {
            path,
            data,
            body: strip_utf8_bom(data),
            claim: OnceCell::new(),
            decoded: OnceCell::new(),
            evidence: OnceCell::new(),
            scores: OnceCell::new(),
            scored: OnceCell::new(),
            marked: OnceCell::new(),
            git_config: OnceCell::new(),
            binary_not_source: OnceCell::new(),
            zip: OnceCell::new(),
        }
    }

    /// What the path's name or extension claims.
    pub(super) fn claim(&self) -> Option<Claim> {
        *self.claim.get_or_init(|| ext::claim(self.path))
    }

    /// The type the path's name or extension implies.
    pub(super) fn ext_type(&self) -> Option<FileType> {
        self.claim().map(|c| c.file_type)
    }

    /// The UTF-16 text behind the bytes, narrowed to 8 bits, when they are
    /// UTF-16 or carry a UTF-16 byte-order mark.
    pub(super) fn decoded(&self) -> Option<&[u8]> {
        self.decoded
            .get_or_init(|| heuristics::decoded_text(self.data))
            .as_deref()
    }

    /// The text the scorers and line grammars read: [`Self::decoded`], or
    /// the bytes themselves, without a UTF-8 byte-order mark.
    pub(super) fn text(&self) -> &[u8] {
        self.decoded().map_or(self.body, strip_utf8_bom)
    }

    /// What the line grammars make of [`Self::text`].
    pub(super) fn evidence(&self) -> &Evidence {
        self.evidence
            .get_or_init(|| scripts::evidence(self.text().trim_ascii_start()))
    }

    /// The language scorer's table for the head of [`Self::text`].
    pub(super) fn head_scores(&self) -> &Scores {
        self.scores
            .get_or_init(|| heuristics::head_scores(self.text().trim_ascii_start()))
    }

    /// The language the content scorer finds in the body.
    pub(super) fn scored_type(&self) -> Option<FileType> {
        *self.scored.get_or_init(|| heuristics::scored_type(self))
    }

    /// A mark that belongs to one format and almost nothing else.
    pub(super) fn unmistakable(&self) -> Option<FileType> {
        *self.marked.get_or_init(|| marks::unmistakable(self))
    }

    /// Git's config syntax in the head.
    pub(super) fn looks_like_git_config(&self) -> bool {
        *self
            .git_config
            .get_or_init(|| marks::looks_like_git_config(self.data))
    }

    /// Object code, not text in any encoding.
    pub(super) fn binary_not_source(&self) -> bool {
        *self
            .binary_not_source
            .get_or_init(|| heuristics::binary_not_source(self.data))
    }

    /// The bytes opened as a zip archive, each caller with its own read
    /// budget over the one parsed central directory.
    pub(super) fn zip(&self) -> Option<zip_probe::Archive<'a>> {
        self.zip.get_or_init(|| zip_probe::open(self.data)).clone()
    }
}
