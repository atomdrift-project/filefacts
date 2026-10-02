//! One identification's input, and what has been derived from it so far.
//!
//! The stages of [`super::identify`] ask the same questions of the same bytes:
//! what the name implies, whether a format's mark is present, what the
//! language scorer makes of the body, and the UTF-16 decode behind the last
//! two. A [`Sniff`] answers each the first time it is asked and keeps the
//! answer, so every derivation runs at most once per call however many stages
//! consult it. Nothing here decides a type; the stages still run in their own
//! order and the first match still wins.

use std::{borrow::Cow, cell::OnceCell, path::Path};

use super::{FileType, ext, heuristics, strip_utf8_bom};

/// The path and bytes being identified, with lazily computed derivations.
pub(super) struct Sniff<'a> {
    /// The name the bytes arrived under.
    pub(super) path: &'a Path,
    /// The bytes, as given.
    pub(super) data: &'a [u8],
    /// `data` without a leading UTF-8 byte-order mark.
    pub(super) body: &'a [u8],
    /// [`ext::detect_from_path`].
    ext_type: OnceCell<Option<FileType>>,
    /// [`ext::is_filename_match`].
    filename_match: OnceCell<bool>,
    /// [`heuristics::decoded_text`]: UTF-16 narrowed for the byte scorers.
    decoded: OnceCell<Option<Cow<'a, [u8]>>>,
    /// [`heuristics::detect_from_content`].
    scored: OnceCell<Option<FileType>>,
    /// [`heuristics::unmistakable`].
    marked: OnceCell<Option<FileType>>,
    /// [`heuristics::looks_like_git_config`].
    git_config: OnceCell<bool>,
    /// [`heuristics::binary_not_source`].
    binary_not_source: OnceCell<bool>,
}

impl<'a> Sniff<'a> {
    pub(super) fn new(path: &'a Path, data: &'a [u8]) -> Self {
        Self {
            path,
            data,
            body: strip_utf8_bom(data),
            ext_type: OnceCell::new(),
            filename_match: OnceCell::new(),
            decoded: OnceCell::new(),
            scored: OnceCell::new(),
            marked: OnceCell::new(),
            git_config: OnceCell::new(),
            binary_not_source: OnceCell::new(),
        }
    }

    /// The type the path's name or extension implies.
    pub(super) fn ext_type(&self) -> Option<FileType> {
        *self
            .ext_type
            .get_or_init(|| ext::detect_from_path(self.path))
    }

    /// Whether [`Self::ext_type`] came from a well-known filename rather
    /// than an extension.
    pub(super) fn is_filename_match(&self) -> bool {
        *self
            .filename_match
            .get_or_init(|| ext::is_filename_match(self.path))
    }

    /// The text the byte scorers read instead of `data`, when that differs.
    pub(super) fn decoded(&self) -> Option<&[u8]> {
        self.decoded
            .get_or_init(|| heuristics::decoded_text(self.data))
            .as_deref()
    }

    /// The language the content scorer finds in the body.
    pub(super) fn scored_type(&self) -> Option<FileType> {
        *self
            .scored
            .get_or_init(|| heuristics::detect_from_decoded(self.data, || self.decoded()))
    }

    /// A mark that belongs to one format and almost nothing else.
    pub(super) fn unmistakable(&self) -> Option<FileType> {
        *self.marked.get_or_init(|| {
            let head = self
                .body
                .get(..heuristics::MARK_WINDOW)
                .unwrap_or(self.body);
            // The mark window is narrower than the git config check's own, so
            // the two agree only when the whole body fits in the mark window.
            // A body that opens with a second mark is stripped once more there.
            let git_config = if head.len() == self.body.len() && !head.starts_with(super::UTF8_BOM)
            {
                self.looks_like_git_config()
            } else {
                heuristics::looks_like_git_config(head)
            };
            if git_config {
                Some(FileType::Text)
            } else {
                heuristics::unmistakable_beyond_git_config(self.body)
            }
        })
    }

    /// Git's config syntax in the head.
    pub(super) fn looks_like_git_config(&self) -> bool {
        *self
            .git_config
            .get_or_init(|| heuristics::looks_like_git_config(self.data))
    }

    /// Object code, not text in any encoding.
    pub(super) fn binary_not_source(&self) -> bool {
        *self
            .binary_not_source
            .get_or_init(|| heuristics::binary_not_source(self.data))
    }
}
