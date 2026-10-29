//! The whole-file token scan: every fixed byte pattern the extractor counts
//! or locates, found in one pass.

use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

use super::lex::{byte_before, is_name_char};

/// PDF whitespace and the delimiters that can sit next to a name key.
fn is_delim(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'/')
}

/// What has to surround an occurrence of a fixed pattern for it to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    /// Every occurrence counts.
    Any,
    /// No name character on either side, so `obj` matches neither `objstm`
    /// nor the tail of `endobj`.
    Token,
    /// A delimiter or whitespace before, and a delimiter, whitespace or digit
    /// after. `/AA` is two letters: checking only the trailing byte lets them
    /// through when they fall inside compressed image data, which would
    /// report additional actions on every other scanned document.
    Keyword,
    /// No letter or `_` after, so `/Title` does not match `/Titles`.
    KeyEnd,
}

impl Boundary {
    fn accepts(self, bytes: &[u8], start: usize, end: usize) -> bool {
        let before = byte_before(bytes, start);
        let after = bytes.get(end).copied();
        match self {
            Self::Any => true,
            Self::Token => !is_name_char(before) && !after.is_some_and(is_name_char),
            Self::Keyword => {
                let after = after.unwrap_or(b' ');
                is_delim(before) && (is_delim(after) || after.is_ascii_digit())
            }
            Self::KeyEnd => !after.is_some_and(|b| b.is_ascii_alphabetic() || b == b'_'),
        }
    }

    /// Whether every occurrence is a candidate. The other kinds take
    /// occurrences the way `memmem::find_iter` does: one may not start
    /// inside the previous one, whether or not that one counted.
    fn overlapping(self) -> bool {
        self == Self::Keyword
    }
}

/// Every fixed byte pattern the whole-file scan looks for. A variant's
/// position in [`Tok::ALL`] is its pattern id in [`TOKEN_SCANNER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tok {
    Header,
    Eof,
    Trailer,
    StartXref,
    Obj,
    EndObj,
    Stream,
    AcroForm,
    Xfa,
    OpenAction,
    AdditionalActions,
    JavaScript,
    RichMedia,
    Subtype3dSpaced,
    Subtype3dJoined,
    Encrypt,
    Linearized,
    ByteRange,
    Jbig2Decode,
    FlateDecode,
    InfoTitle,
    InfoAuthor,
    InfoCreator,
    InfoProducer,
    InfoSubject,
    InfoKeywords,
    InfoCreationDate,
    InfoModDate,
    InfoTrapped,
}

impl Tok {
    pub(super) const ALL: [Self; 29] = [
        Self::Header,
        Self::Eof,
        Self::Trailer,
        Self::StartXref,
        Self::Obj,
        Self::EndObj,
        Self::Stream,
        Self::AcroForm,
        Self::Xfa,
        Self::OpenAction,
        Self::AdditionalActions,
        Self::JavaScript,
        Self::RichMedia,
        Self::Subtype3dSpaced,
        Self::Subtype3dJoined,
        Self::Encrypt,
        Self::Linearized,
        Self::ByteRange,
        Self::Jbig2Decode,
        Self::FlateDecode,
        Self::InfoTitle,
        Self::InfoAuthor,
        Self::InfoCreator,
        Self::InfoProducer,
        Self::InfoSubject,
        Self::InfoKeywords,
        Self::InfoCreationDate,
        Self::InfoModDate,
        Self::InfoTrapped,
    ];

    /// The bytes to find.
    pub(super) fn bytes(self) -> &'static [u8] {
        self.pattern().0
    }

    /// The bytes to find and what must surround them.
    fn pattern(self) -> (&'static [u8], Boundary) {
        use Boundary::{Any, KeyEnd, Keyword, Token};
        match self {
            Self::Header => (b"%PDF-", Any),
            Self::Eof => (b"%%EOF", Any),
            Self::Trailer => (b"\ntrailer", Any),
            Self::StartXref => (b"startxref", Any),
            Self::Obj => (b"obj", Token),
            Self::EndObj => (b"endobj", Token),
            Self::Stream => (b"stream", Token),
            Self::AcroForm => (b"/AcroForm", Token),
            Self::Xfa => (b"/XFA", Token),
            Self::OpenAction => (b"/OpenAction", Token),
            Self::AdditionalActions => (b"/AA", Keyword),
            Self::JavaScript => (b"/JavaScript", Token),
            Self::RichMedia => (b"/RichMedia", Token),
            Self::Subtype3dSpaced => (b"/Subtype /3D", Any),
            Self::Subtype3dJoined => (b"/Subtype/3D", Any),
            Self::Encrypt => (b"/Encrypt", Token),
            Self::Linearized => (b"/Linearized", Token),
            Self::ByteRange => (b"/ByteRange", Any),
            Self::Jbig2Decode => (b"/JBIG2Decode", Any),
            Self::FlateDecode => (b"/FlateDecode", Any),
            Self::InfoTitle => (b"/Title", KeyEnd),
            Self::InfoAuthor => (b"/Author", KeyEnd),
            Self::InfoCreator => (b"/Creator", KeyEnd),
            Self::InfoProducer => (b"/Producer", KeyEnd),
            Self::InfoSubject => (b"/Subject", KeyEnd),
            Self::InfoKeywords => (b"/Keywords", KeyEnd),
            Self::InfoCreationDate => (b"/CreationDate", KeyEnd),
            Self::InfoModDate => (b"/ModDate", KeyEnd),
            Self::InfoTrapped => (b"/Trapped", KeyEnd),
        }
    }
}

/// DocumentInfo keys, surfaced as `pdf.info.<name>`.
pub(super) const INFO_KEYS: [(Tok, &str); 9] = [
    (Tok::InfoTitle, "title"),
    (Tok::InfoAuthor, "author"),
    (Tok::InfoCreator, "creator"),
    (Tok::InfoProducer, "producer"),
    (Tok::InfoSubject, "subject"),
    (Tok::InfoKeywords, "keywords"),
    (Tok::InfoCreationDate, "creation_date"),
    (Tok::InfoModDate, "mod_date"),
    (Tok::InfoTrapped, "trapped"),
];

/// One automaton over every [`Tok`] pattern, and what it cannot see.
///
/// [`TokenScan`] needs every occurrence of every pattern, however they
/// overlap one another: `obj` inside `endobj`, and the `endobj` that shares
/// its `e` with a preceding `/FlateDecode`. Standard semantics with
/// overlapping iteration reports all of them, but walks the input a byte at
/// a time. A leftmost-first search takes the SIMD prefilter path instead; it
/// resumes after each match, so the occurrences that start inside a match
/// are recovered from [`Self::starts_inside`].
struct TokenScanner {
    automaton: AhoCorasick,
    /// For each pattern id, the `(pattern id, offset)` pairs that can start
    /// inside an occurrence of it: the patterns whose bytes agree with it
    /// from that offset on (offset 0 for a different pattern that shares its
    /// start). Every occurrence either is a match of the search or starts
    /// inside one, so checking these after each match finds exactly the
    /// occurrences the search stepped over.
    starts_inside: Vec<Vec<(usize, usize)>>,
}

impl TokenScanner {
    fn new() -> Option<Self> {
        let patterns = Tok::ALL.map(Tok::bytes);
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build(patterns)
            .inspect_err(|e| {
                tracing::error!(
                    target: "filefacts::pdf",
                    stage = "token-scan",
                    error = %e,
                    "token automaton did not build; PDF token facts unavailable"
                );
            })
            .ok()?;
        let starts_inside = patterns
            .iter()
            .enumerate()
            .map(|(outer, outer_bytes)| {
                let mut inside = Vec::new();
                for offset in 0..outer_bytes.len() {
                    let tail = outer_bytes.get(offset..).unwrap_or_default();
                    for (inner, inner_bytes) in patterns.iter().enumerate() {
                        if inner == outer && offset == 0 {
                            continue;
                        }
                        let n = tail.len().min(inner_bytes.len());
                        if tail.get(..n) == inner_bytes.get(..n) {
                            inside.push((inner, offset));
                        }
                    }
                }
                inside
            })
            .collect();
        Some(Self {
            automaton,
            starts_inside,
        })
    }
}

static TOKEN_SCANNER: LazyLock<Option<TokenScanner>> = LazyLock::new(TokenScanner::new);

/// What the scan saw of one pattern.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Hits {
    /// Occurrences, counted the way `memmem::find_iter` counts them (or
    /// every one, for an overlapping [`Boundary`]).
    pub(super) all: usize,
    /// Those that pass the pattern's [`Boundary`].
    pub(super) accepted: usize,
    /// Start of the first occurrence.
    pub(super) first: Option<usize>,
    /// Start of the last occurrence.
    pub(super) last: Option<usize>,
    /// Start of the first occurrence that passes the boundary test.
    pub(super) first_accepted: Option<usize>,
}

/// Counts and positions of every fixed token, from one pass over the bytes.
pub(super) struct TokenScan([Hits; Tok::ALL.len()]);

impl TokenScan {
    pub(super) fn run(bytes: &[u8]) -> Self {
        let mut scan = Self([Hits::default(); Tok::ALL.len()]);
        let Some(scanner) = TOKEN_SCANNER.as_ref() else {
            return scan;
        };
        // Where each pattern's next counted occurrence may start.
        let mut resume = [0usize; Tok::ALL.len()];
        for m in scanner.automaton.find_iter(bytes) {
            let (id, start) = (m.pattern().as_usize(), m.start());
            scan.record(bytes, &mut resume, id, start);
            // Occurrences inside this match, in offset order, so each
            // pattern still sees its occurrences in input order: the next
            // match starts at or after this one's end.
            for &(inner, offset) in scanner.starts_inside.get(id).into_iter().flatten() {
                let at = start + offset;
                let Some(inner_bytes) = Tok::ALL.get(inner).map(|t| t.bytes()) else {
                    continue;
                };
                if bytes.get(at..at + inner_bytes.len()) == Some(inner_bytes) {
                    scan.record(bytes, &mut resume, inner, at);
                }
            }
        }
        scan
    }

    /// Count one occurrence of pattern `id` at `start`. Occurrences of one
    /// pattern arrive in input order.
    fn record(&mut self, bytes: &[u8], resume: &mut [usize], id: usize, start: usize) {
        let (Some(tok), Some(h), Some(resume)) =
            (Tok::ALL.get(id), self.0.get_mut(id), resume.get_mut(id))
        else {
            return;
        };
        let (pattern, boundary) = tok.pattern();
        let end = start + pattern.len();
        h.first.get_or_insert(start);
        h.last = Some(start);
        if !boundary.overlapping() {
            if start < *resume {
                return;
            }
            *resume = end;
        }
        h.all += 1;
        if boundary.accepts(bytes, start, end) {
            h.accepted += 1;
            h.first_accepted.get_or_insert(start);
        }
    }

    pub(super) fn get(&self, tok: Tok) -> Hits {
        self.0.get(tok as usize).copied().unwrap_or_default()
    }

    /// Whether `tok` occurs at least once with its boundary satisfied.
    pub(super) fn has(&self, tok: Tok) -> bool {
        self.get(tok).accepted > 0
    }
}
