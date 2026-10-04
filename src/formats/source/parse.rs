//! Shared tree-sitter parse cache.
//!
//! Built lazily on first source-driven extraction and shared across
//! every source-derived view of the same `ParsedFile`.
//!
//! The cache owns the [`tree_sitter::Tree`] and a borrowed reference to
//! the source bytes (as a `&str`); the tree-sitter API references the
//! source by offset, not by reference, so the `&str` lifetime is what
//! ties this cache to the parent `ParsedFile<'a>`.

use crate::fileid::FileType;
use crate::formats::source::ast_walk;
use crate::formats::source::langs::{self, LangConfig};
use crate::metric;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::ops::ControlFlow;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Tree-sitter's external scanners serialize their state into a fixed
/// 1024-byte buffer (`TREE_SITTER_SERIALIZATION_BUFFER_SIZE` in
/// `parser.c`). On overflow `ts_parser__external_scanner_serialize`
/// hits `ts_assert(length <= 1024)` and calls `abort()` — the upstream
/// build does not define `NDEBUG`, so the assertion fires in release
/// builds. We can't catch a C `abort` from Rust, so the only safe
/// option is to refuse parses that are likely to trip it.
///
/// 32 MiB bounds parser memory and CPU for grammars whose external scanner
/// state is proven bounded or self-guarded, while admitting large ordinary
/// bundles such as packaged webviews. Grammars with modeled scanner state keep
/// a tighter cap. The work budget and wall-clock backstop below bound
/// pathological parser behavior.
const MAX_AST_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_MODELED_AST_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Work budget for one parse, counted in progress polls. tree-sitter polls the
/// progress callback once per 100 parser operations
/// (`OP_COUNT_PER_PARSER_CALLBACK_CHECK` in `parser.c`), so counting polls
/// measures work, not time: the same bytes stop at the same point however
/// loaded the machine is. The wall-clock budget this replaced fired on
/// ordinary files under load, and the content-keyed disk cache then kept the
/// shallower facts.
///
/// The budget is [`PARSE_WORK_BASE`] polls plus one per
/// [`PARSE_BYTES_PER_POLL`] bytes of input. Since the tree-sitter fork counts
/// the work of walking and freeing ambiguous parse stacks as operations, a poll
/// stands for roughly the same CPU time whatever the input; before, a grammar
/// ambiguity could make each poll a hundred times dearer than usual, and a
/// 249 KB mutated C header spent 13 s inside a budget of 224k polls while
/// using only 2,335.
///
/// Calibrated on about 68k real source files and generated 1–30 MiB sources
/// (densest 0.057 polls per byte; largest total 585k polls, a 30 MiB minified
/// bundle), then rechecked with stack work counted on 40k real parses
/// (registry crates, `/usr/include`): the densest large file used 0.022 polls
/// per byte, counting stack work raised poll counts by at most 1.35× at the
/// 99th percentile, and no file used more than an eighth of its budget (a
/// 4 MiB minified bundle, about 0.02 polls per byte, uses 84k of 1.07M).
/// Input that keeps the parser ambiguous, like that C header, now stops after
/// about 82k polls, in about 5 s.
const PARSE_WORK_BASE: u64 = 20_000;
const PARSE_BYTES_PER_POLL: u64 = 4;

/// Wall-clock backstop for one parse, separate from the work budget.
/// Ordinary files never reach it — the slowest ordinary corpus parse took
/// about 7 s on a loaded machine, a 30 MiB bundle — so their facts never
/// depend on load.
///
/// It exists because the work budget counts operations, not their cost, and
/// some inputs make single operations expensive: GLR error recovery over a
/// deep stack of unclosed brackets (token soup, badly concatenated bundles),
/// and external scanners that re-scan a long line for its column on every
/// token (single-line Perl). Such input can run for minutes on a few hundred
/// KiB while using a small fraction of its work budget. Only this backstop
/// stops it, so whether it does can depend on load.
const SOURCE_PARSE_WALL_BACKSTOP: Duration = Duration::from_secs(60);

#[cfg(test)]
thread_local! {
    /// Work budget override in progress polls; `0` means the calibrated
    /// [`parse_work_budget`]. Lets a test exhaust the budget on ordinary
    /// input instead of needing an adversarial fixture.
    ///
    /// Thread-local, not a global: parses run on the caller's thread, and a
    /// process-wide knob would let one test's shortened budget cut short a
    /// parse in another test running in parallel.
    static PARSE_WORK_OVERRIDE: Cell<u64> = const { Cell::new(0) };
}

fn parse_work_budget(bytes: usize) -> u64 {
    #[cfg(test)]
    if let polls @ 1.. = PARSE_WORK_OVERRIDE.get() {
        return polls;
    }
    PARSE_WORK_BASE.saturating_add(bytes as u64 / PARSE_BYTES_PER_POLL)
}

/// Bytes handed to the lexer per read. The parser reads its input through
/// a callback and fetches again whenever the lexer moves outside the bytes it
/// last received, so bounded chunks make the bytes fetched measure how far
/// the lexer travels, re-scans included. Small, so a backward jump that
/// re-lexes one token costs little; sequential reading still needs only one
/// call per chunk. Chunking never changes the tree: tree-sitter lexes across
/// chunk boundaries the way it does across the pieces of an editor's rope.
const LEXER_CHUNK_BYTES: usize = 64;

/// Lexer fetch budget: [`LEXER_FETCH_BASE`] bytes plus [`LEXER_FETCH_FACTOR`]
/// per input byte. Like the work budget it counts work, not time, so the same
/// bytes stop at the same point however loaded the machine is.
///
/// It stops what the work budget cannot see: scanners that re-read a line on
/// every token, each read one cheap operation. The Perl scanner asks for the
/// column at each statement start, which rescans the line from its start: a
/// 200 KB one-line Perl file fetched 4.2 GB and took 53 s on 8k polls. The
/// Bash scanner looks ahead to the end of the line while recovering inside
/// `$((…))`, and the Lua scanner looks for the end of a long bracket from
/// every `[[`.
///
/// Calibrated on about 49k real source files: the most any of them fetched
/// was 25.8 bytes per input byte (a 28 KB Python file; Perl assembler
/// generators reach 23), no file over 3 MB fetched more than 2.1, and the
/// largest total was 57 MB, for a 28 MB C file. A pathological input stops
/// within half a second of re-scanning.
const LEXER_FETCH_BASE: u64 = 64 << 20;
const LEXER_FETCH_FACTOR: u64 = 16;

#[cfg(test)]
thread_local! {
    /// Lexer fetch budget override in bytes; `0` means
    /// [`lexer_fetch_budget`]. Thread-local for the same reason as
    /// [`PARSE_WORK_OVERRIDE`].
    static LEXER_FETCH_OVERRIDE: Cell<u64> = const { Cell::new(0) };
}

fn lexer_fetch_budget(bytes: usize) -> u64 {
    #[cfg(test)]
    if let budget @ 1.. = LEXER_FETCH_OVERRIDE.get() {
        return budget;
    }
    LEXER_FETCH_BASE.saturating_add((bytes as u64).saturating_mul(LEXER_FETCH_FACTOR))
}

/// Consecutive progress polls the parser may spend with every stack version
/// in error recovery before the parse is abandoned. Recovery work is not all
/// counted as operations, and when recovery cannot get back to a healthy
/// state each poll gets dearer: 2 MB of TypeScript token soup took 43 s on
/// 22.7k polls, nearly all in one run, and 10 MB of malformed TypeScript more
/// than five minutes on 52k. At this cap the soup stops after 1.4 s.
///
/// Real source recovers within a few polls. Across about 49k real files the
/// longest run outside C was 32 polls (Batch), and at most 12 in JavaScript,
/// TypeScript, Go, Rust, Python and Perl; JSX saved as `.ts`, Flow-typed
/// JavaScript, JSON saved as `.js` and Python 2 stayed under 4. Files
/// concatenated without regard for syntax can stay in recovery for good, and
/// are cut off here too. C and Objective-C are exempt; see
/// [`error_recovery_cap`].
///
/// Polls at the end of the input are not counted against this cap but against
/// [`EOF_RECOVERY_FLOOR`]: see [`RecoveryWatch`].
const ERROR_RECOVERY_POLL_CAP: u64 = 256;

/// The fewest error-recovery polls the parser may spend at the end of the
/// input, wrapping up a tree with constructs it never recovered.
///
/// That wrap-up is one long run of error polls even for valid source: a
/// 550 KB TypeScript declaration file that the grammar half-understands spends
/// 1,968 polls there after 4,946 reaching the end, and the run cap would throw
/// its whole tree away. So the wrap-up is bounded by the work that came before
/// it instead — at most as many recovery polls as the polls taken to reach the
/// end, and at least this many — which keeps the parse to roughly twice the cost
/// of reading its input. Token soup that recovers nowhere spends several times
/// its reading cost there (about 9,700 polls after 680 for 2 MB of random
/// TypeScript tokens) and is still cut off.
const EOF_RECOVERY_FLOOR: u64 = 1024;

/// The consecutive error-recovery polls allowed for `file_type`, or `None`
/// for no cap. C and Objective-C share `.h` headers with C++, which their
/// grammars cannot parse: C++ headers spend long stretches in recovery
/// (simdjson's single header, 29.8k polls in one run) while staying cheap per
/// poll, so a cap there would drop ordinary headers.
fn error_recovery_cap(file_type: FileType) -> Option<u64> {
    match file_type {
        FileType::C | FileType::ObjectiveC => None,
        _ => Some(ERROR_RECOVERY_POLL_CAP),
    }
}

/// Anonymous-token runs shorter than this are not counted by
/// [`anonymous_run_cost`]: what they cost a query is linear in the file.
const ANONYMOUS_RUN_MIN: u64 = 16;

/// Largest [`anonymous_run_cost`] a tree may have before its AST is refused.
/// A query cursor step asks whether the current node has a later *named*
/// sibling, scanning the siblings after it until one is, so a run of `n`
/// anonymous tokens costs about `n²/2` sibling checks per query. Error
/// recovery over unclosed brackets leaves such runs (100k `(` took 5–8 s per
/// query, in every grammar), and the Perl grammar hangs every nested
/// parenthesis of an expression off one visible node (10k nested took 2.6 s
/// per query, 41 nests 2,400 deep 3.9 s).
///
/// The most any of about 49k real source files reached was 164k (simdjson's
/// single header; the longest run anywhere was 135 tokens), a hundredth of
/// the cap. At the cap a Perl query takes about 0.3 s, other grammars far
/// less.
const ANONYMOUS_RUN_COST_CAP: u64 = 1 << 24;

/// Tracks error recovery across a parse's progress polls and says when it has
/// gone on too long: [`ERROR_RECOVERY_POLL_CAP`] consecutive polls before the
/// end of the input, or [`EOF_RECOVERY_FLOOR`]-or-more polls at it. Every input
/// is a poll count, so the same bytes always stop at the same poll.
#[derive(Debug)]
struct RecoveryWatch {
    /// The consecutive-poll cap, or `None` when recovery is not limited.
    cap: Option<u64>,
    /// Consecutive polls with every stack version recovering, before the end.
    run: u64,
    /// Polls it took to reach the end of the input, once it has.
    reached_end: Option<u64>,
    /// Polls in error recovery since reaching the end.
    end_run: u64,
}

impl RecoveryWatch {
    fn new(cap: Option<u64>) -> Self {
        Self {
            cap,
            run: 0,
            reached_end: None,
            end_run: 0,
        }
    }

    /// Record poll number `poll` (counted from 1), and return why the parse
    /// must stop, if it must. `recovering` is whether every stack version is in
    /// error recovery; `at_end` whether the parser has reached the end of the
    /// input.
    fn poll(&mut self, poll: u64, recovering: bool, at_end: bool, at: usize) -> Option<ParseStop> {
        let cap = self.cap?;
        if at_end && self.reached_end.is_none() {
            self.reached_end = Some(poll.saturating_sub(1));
        }
        if let Some(reached) = self.reached_end {
            self.end_run += u64::from(recovering);
            let allowed = reached.max(EOF_RECOVERY_FLOOR);
            return (self.end_run > allowed).then_some(ParseStop::EofRecovery {
                polls: self.end_run,
                allowed,
            });
        }
        self.run = if recovering { self.run + 1 } else { 0 };
        (self.run > cap).then_some(ParseStop::ErrorRecovery {
            polls: self.run,
            at,
        })
    }
}

/// Why the progress callback abandoned a parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseStop {
    /// The caller raised its cancellation flag.
    Cancelled,
    /// The work budget ran out with the parser at byte `at`.
    Budget { budget: u64, at: usize },
    /// The lexer fetched more than its budget of input bytes.
    LexerBudget { budget: u64, at: usize },
    /// Every stack version stayed in error recovery for `polls` consecutive
    /// polls, the parser having reached byte `at`.
    ErrorRecovery { polls: u64, at: usize },
    /// Wrapping up at the end of the input took more than `allowed`
    /// error-recovery polls.
    EofRecovery { polls: u64, allowed: u64 },
    /// [`SOURCE_PARSE_WALL_BACKSTOP`] elapsed first.
    Backstop,
}

/// Conservative cap for grammars whose scanner has not been audited
/// for the 1024-byte overflow. New or freshly-bumped grammar crates
/// land here automatically — when an entry is missing from
/// [`scanner_audit`], we'd rather drop AST analysis on the rare
/// 64+ KB source than risk a C-level abort on the whole worker.
const UNAUDITED_GRAMMAR_CAP_BYTES: usize = 64 * 1024;

/// Size at which a parse is worth a per-call diagnostic line. Below
/// this most scanners can't have accumulated enough state to reach
/// the 1024-byte serialization boundary, so the breadcrumb would
/// only add log noise. Above it, an abort is plausible and the
/// breadcrumb names the grammar + size for the next post-mortem.
const PARSE_BREADCRUMB_THRESHOLD_BYTES: usize = 64 * 1024;

/// Budget for the **combined** Python scanner state. Layout per
/// `tree_sitter_python_external_scanner_serialize` (`scanner.c`):
///
/// ```text
/// 1 byte   inside_interpolated_string
/// 1 byte   delimiter_count (clamped to UINT8_MAX = 255)
/// N bytes  delimiters (N = clamped count)
/// 2*M B    indent stack (M = indents.size - 1, since indents[0] is
///          always 0 and the serializer's loop starts at iter = 1)
/// ```
///
/// The upstream serializer has an off-by-one: its loop guard is
/// `size < 1024`, but each iteration writes 2 bytes, so the final
/// returned size can reach 1025 (the assert is `length <= 1024`).
/// Pick 1020 as the budget to stay clear of the boundary with one
/// indent of slack.
const PYTHON_SCANNER_BUDGET_BYTES: usize = 1020;

/// Per-string-literal byte cost in the delimiter portion of the
/// scanner state.
const PYTHON_DELIMITER_BYTES: usize = 1;

/// Per-indent-level byte cost in the indent portion of the scanner
/// state.
const PYTHON_INDENT_BYTES_PER_LEVEL: usize = 2;

/// `bytes` as UTF-8 text for the parser, with the number of bytes that were
/// not UTF-8. Each invalid byte becomes one `_`, so every byte offset in the
/// tree still addresses the same byte of the input.
///
/// Refusing such input outright, as filefacts once did, dropped every AST
/// fact for a Latin-1 source file, and let anyone hide a script's calls and
/// imports with one stray byte in a comment. `_` keeps an identifier spelled
/// with Latin-1 letters in one piece (PHP accepts bytes 0x80-0xff in names)
/// and is inert in strings and comments; those keep the substitute, not the
/// original byte.
fn utf8_source(bytes: &[u8]) -> (Cow<'_, str>, usize) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return (Cow::Borrowed(text), 0);
    }
    let mut text = String::with_capacity(bytes.len());
    let mut invalid = 0;
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        let bad = chunk.invalid().len();
        invalid += bad;
        text.extend(std::iter::repeat_n('_', bad));
    }
    (Cow::Owned(text), invalid)
}

thread_local! {
    /// One tree-sitter parser per worker thread, reused across files.
    /// Constructing a fresh `Parser` on every call allocates internal
    /// state tables; reusing the same instance lets tree-sitter keep
    /// its scratch arenas warm across files in the same archive.
    static THREAD_PARSER: RefCell<tree_sitter::Parser> = RefCell::new(tree_sitter::Parser::new());
}

/// A cached parse for a source file.
pub(crate) struct TreeCache<'a> {
    /// The input as parsed: borrowed when it is UTF-8, otherwise repaired by
    /// [`utf8_source`], byte for byte.
    source: Cow<'a, str>,
    /// Input bytes that were not UTF-8, each parsed as `_`.
    invalid_utf8_bytes: usize,
    tree: tree_sitter::Tree,
    file_type: FileType,
    config: &'static LangConfig,
    /// The symbol walk's state, collected by the extraction walk and taken
    /// by `build_symbols`, which runs after it.
    ast_walk: Mutex<Option<Box<ast_walk::State>>>,
}

/// Source parsing outcome cached by [`crate::ParsedFile`].
pub(crate) enum TreeParse<'a> {
    Parsed(TreeCache<'a>),
    Unavailable(TreeSitterDiagnostic),
}

impl<'a> TreeParse<'a> {
    pub(crate) fn cache(&self) -> Option<&TreeCache<'a>> {
        match self {
            Self::Parsed(cache) => Some(cache),
            Self::Unavailable(_) => None,
        }
    }

    pub(crate) fn diagnostic(&self) -> Option<&TreeSitterDiagnostic> {
        match self {
            Self::Parsed(_) => None,
            Self::Unavailable(diagnostic) => Some(diagnostic),
        }
    }
}

/// Recoverable source-AST diagnostic emitted when filefacts refuses or fails
/// a Tree-sitter parse but can still return generic/text facts.
pub(crate) struct TreeSitterDiagnostic {
    pub(crate) metric: crate::MetricKey,
    pub(crate) message: String,
    /// The outcome depends on the run rather than on the input bytes: see
    /// [`Self::is_transient`].
    transient: bool,
}

impl TreeSitterDiagnostic {
    /// Whether another run over the same bytes could parse: true for the
    /// wall-clock backstop, which depends on load, and for cancellation. A
    /// caller that caches facts by content must not keep a transient
    /// outcome. Every other diagnostic follows from the bytes alone.
    pub(crate) fn is_transient(&self) -> bool {
        self.transient
    }

    fn tree_sitter_guard(language: &'static str, bytes: usize, audit: ScannerAudit) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.tree_sitter_guard"),
            message: format!(
                "tree-sitter parse skipped for {language}: {bytes} bytes exceeds source-size or scanner-state safety guard ({audit:?})"
            ),
            transient: false,
        }
    }

    /// The tree parsed, but [`anonymous_run_cost`] puts it past
    /// [`ANONYMOUS_RUN_COST_CAP`]: queries over it would take quadratic time.
    /// Same metric as the up-front guards, which also refuse an AST that
    /// would be unsafe to work with.
    fn anonymous_run_guard(language: &'static str, bytes: usize, cost: u64) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.tree_sitter_guard"),
            message: format!(
                "tree-sitter tree for {language} discarded: runs of anonymous tokens in {bytes} bytes cost over {cost} sibling checks per query (cap {ANONYMOUS_RUN_COST_CAP})"
            ),
            transient: false,
        }
    }

    pub(crate) fn parse_failed(message: impl Into<String>) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_failed"),
            message: message.into(),
            transient: false,
        }
    }

    /// `source.ast_unavailable.parse_timeout` means the parse exhausted its
    /// work budget or, for input that makes single operations expensive, hit
    /// the wall-clock backstop. The metric keeps its historical name because
    /// rules key on it; the message names the limit. This message is
    /// deterministic, so it carries the offset where the budget ran out.
    fn parse_work_exhausted(language: &'static str, bytes: usize, budget: u64, at: usize) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_timeout"),
            message: format!(
                "tree-sitter parse for {language} exhausted its work budget of {budget} progress polls at byte {at} of {bytes}"
            ),
            transient: false,
        }
    }

    /// Same metric as [`Self::parse_work_exhausted`]: the lexer exhausted its
    /// fetch budget ([`lexer_fetch_budget`]), which is just as deterministic.
    fn lexer_work_exhausted(language: &'static str, bytes: usize, budget: u64, at: usize) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_timeout"),
            message: format!(
                "tree-sitter parse for {language} exhausted its lexer budget of {budget} fetched bytes at byte {at} of {bytes}; a scanner kept re-reading the input"
            ),
            transient: false,
        }
    }

    /// Same metric as [`Self::parse_work_exhausted`]: error recovery ran for
    /// [`ERROR_RECOVERY_POLL_CAP`] polls without a healthy stack version.
    fn error_recovery_exhausted(
        language: &'static str,
        bytes: usize,
        polls: u64,
        at: usize,
    ) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_timeout"),
            message: format!(
                "tree-sitter parse for {language} abandoned at byte {at} of {bytes}: error recovery ran {polls} consecutive progress polls without recovering"
            ),
            transient: false,
        }
    }

    fn eof_recovery_exhausted(
        language: &'static str,
        bytes: usize,
        polls: u64,
        allowed: u64,
    ) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_timeout"),
            message: format!(
                "tree-sitter parse for {language} abandoned at the end of its {bytes} bytes: error recovery there ran {polls} progress polls, more than the {allowed} allowed"
            ),
            transient: false,
        }
    }

    /// Same metric as [`Self::parse_work_exhausted`], for the
    /// [`SOURCE_PARSE_WALL_BACKSTOP`]; whether this fires can depend on load.
    fn parse_backstop(language: &'static str, bytes: usize) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_timeout"),
            message: format!(
                "tree-sitter parse for {language} hit the {SOURCE_PARSE_WALL_BACKSTOP:?} wall-clock backstop on {bytes} bytes"
            ),
            transient: true,
        }
    }

    /// Kept distinct from the `parse_timeout` metric: a cancelled parse is
    /// the caller shutting down and is expected, while a timed-out one means
    /// the input exhausted a budget and is worth investigating. Folding them
    /// into one metric would bury the second under the first on every Ctrl-C.
    fn parse_cancelled(language: &'static str, bytes: usize) -> Self {
        Self {
            metric: metric!("source.ast_unavailable.parse_cancelled"),
            message: format!("tree-sitter parse for {language} cancelled at {bytes} bytes"),
            transient: true,
        }
    }
}

impl<'a> TreeCache<'a> {
    /// Parse `bytes` as `file_type` source. Returns [`TreeParse::Unavailable`]
    /// when filefacts deliberately refuses the parse or cannot build a
    /// Tree-sitter tree, so callers can still emit generic/text facts plus a
    /// recoverable diagnostic.
    pub(crate) fn parse(
        bytes: &'a [u8],
        file_type: FileType,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> TreeParse<'a> {
        let Some(config) = langs::config_for(file_type) else {
            return TreeParse::Unavailable(TreeSitterDiagnostic::parse_failed(
                "no tree-sitter grammar registered for source file type",
            ));
        };
        let (text, invalid_utf8_bytes) = utf8_source(bytes);
        let source: &str = &text;
        if would_overflow_scanner_state(file_type, source) {
            let diagnostic = TreeSitterDiagnostic::tree_sitter_guard(
                config.name(),
                source.len(),
                scanner_audit(file_type),
            );
            tracing::warn!(
                language = config.name(),
                bytes = source.len(),
                audit = ?scanner_audit(file_type),
                "skipping tree-sitter parse due to source-size or scanner-state safety guard"
            );
            return TreeParse::Unavailable(diagnostic);
        }
        let language = (config.language)();
        // Breadcrumb for sources large enough to plausibly overflow the
        // scanner. Flushed before `parse` so the line survives a C-level
        // abort and names the offending grammar.
        if source.len() >= PARSE_BREADCRUMB_THRESHOLD_BYTES {
            tracing::info!(
                language = config.name(),
                bytes = source.len(),
                "tree-sitter parse begin"
            );
            let _ = std::io::stderr().flush();
            let _ = std::io::stdout().flush();
        }
        let budget = parse_work_budget(source.len());
        let fetch_budget = lexer_fetch_budget(source.len());
        // Whatever the parse has to report comes back as a [`ParseFailure`],
        // turned into a diagnostic (and logged) below.
        let parsed: Result<tree_sitter::Tree, ParseFailure> = THREAD_PARSER.with(|cell| {
            let mut parser = cell.borrow_mut();
            if let Err(e) = parser.set_language(&language) {
                return Err(ParseFailure::LanguageSetup(e.to_string()));
            }
            // The C core polls this once per 100 parse operations; `Break`
            // unwinds it cleanly and yields `None`, so neither limit needs a
            // thread kill.
            let deadline = Instant::now() + SOURCE_PARSE_WALL_BACKSTOP;
            let polls = Cell::new(0u64);
            let stop = Cell::new(None);
            let mut recovery = RecoveryWatch::new(error_recovery_cap(file_type));
            let fetched = Cell::new(0u64);
            let mut progress = |state: &tree_sitter::ParseState| -> ControlFlow<()> {
                // The read callback below already gave up on the input.
                if matches!(stop.get(), Some(ParseStop::LexerBudget { .. })) {
                    return ControlFlow::Break(());
                }
                // Cancellation first: it is a plain atomic load, and when the
                // caller is shutting down there is no point counting work.
                // `Relaxed` is right for a poll — the flag is a hint, and the
                // worst a stale read costs is one more progress interval.
                if cancel.is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed)) {
                    stop.set(Some(ParseStop::Cancelled));
                    return ControlFlow::Break(());
                }
                polls.set(polls.get() + 1);
                if polls.get() > budget {
                    let at = state.current_byte_offset();
                    stop.set(Some(ParseStop::Budget { budget, at }));
                    return ControlFlow::Break(());
                }
                // `has_error` is set only while every stack version is
                // recovering; any healthy version resets the run.
                let at = state.current_byte_offset();
                if let Some(why) =
                    recovery.poll(polls.get(), state.has_error(), at >= source.len(), at)
                {
                    stop.set(Some(why));
                    return ControlFlow::Break(());
                }
                if Instant::now() >= deadline {
                    stop.set(Some(ParseStop::Backstop));
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            };
            // tree-sitter-bash 0.25 does not know Bash 5.3's `~`/`~~` case
            // inversion operators. Normalize their spelling to the grammar's
            // existing `^`/`^^` case-modification productions. Replacements
            // are length-preserving, so AST ranges still address the original
            // source retained by TreeCache. This is syntax-only: FileFacts
            // does not evaluate the expansion, and source-backed facts keep
            // seeing the exact original operator bytes.
            let normalized_shell = (file_type == FileType::Shell)
                .then(|| normalize_bash_case_modification(source))
                .flatten();
            let parser_source = normalized_shell.as_deref().unwrap_or(source);
            let mut read = |offset: usize, _: tree_sitter::Point| -> &[u8] {
                // Past the budget the lexer sees end of input, so a scanner
                // mid-way through a long scan stops at once, and the next
                // poll abandons the parse.
                if fetched.get() > fetch_budget {
                    return &[];
                }
                let chunk = lexer_chunk(parser_source, offset);
                fetched.set(fetched.get() + chunk.len() as u64);
                if fetched.get() > fetch_budget {
                    stop.set(Some(ParseStop::LexerBudget {
                        budget: fetch_budget,
                        at: offset,
                    }));
                    return &[];
                }
                chunk
            };
            let parsed = parser.parse_with_options(
                &mut read,
                None,
                Some(tree_sitter::ParseOptions::default().progress_callback(&mut progress)),
            );
            // A parse that hit the lexer budget may still have finished
            // before the next poll, on a tree cut short at the false end of
            // input. Such a tree must not be used.
            let parsed =
                parsed.filter(|_| !matches!(stop.get(), Some(ParseStop::LexerBudget { .. })));
            let Some(tree) = parsed else {
                return Err(ParseFailure::Stopped(stop.get()));
            };
            let cost = anonymous_run_cost(tree.root_node(), ANONYMOUS_RUN_COST_CAP);
            if cost > ANONYMOUS_RUN_COST_CAP {
                return Err(ParseFailure::AnonymousRuns(cost));
            }
            Ok(tree)
        });
        match parsed.map_err(|failure| failure.diagnostic(config.name(), source.len())) {
            Ok(tree) => TreeParse::Parsed(Self {
                source: text,
                invalid_utf8_bytes,
                tree,
                file_type,
                config,
                ast_walk: Mutex::new(None),
            }),
            Err(diagnostic) => TreeParse::Unavailable(diagnostic),
        }
    }

    /// Input bytes that were not UTF-8 and were parsed as `_`.
    pub(crate) fn invalid_utf8_bytes(&self) -> usize {
        self.invalid_utf8_bytes
    }

    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    pub(crate) fn tree(&self) -> &tree_sitter::Tree {
        &self.tree
    }

    pub(crate) fn file_type(&self) -> FileType {
        self.file_type
    }

    /// The language configuration the tree was parsed with.
    pub(super) fn config(&self) -> &'static LangConfig {
        self.config
    }

    /// Keep the symbol walk's state for [`Self::take_ast_walk`].
    pub(super) fn stash_ast_walk(&self, state: ast_walk::State) {
        *self.ast_walk.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(state));
    }

    /// The symbol walk's state, if extraction collected it and nothing took
    /// it yet.
    pub(super) fn take_ast_walk(&self) -> Option<ast_walk::State> {
        self.ast_walk
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(|state| *state)
    }
}

/// The next chunk of `source` for the lexer, starting at `offset`: at most
/// [`LEXER_CHUNK_BYTES`], extended to the end of a UTF-8 character so the
/// lexer never has to stitch one together across reads.
fn lexer_chunk(source: &str, offset: usize) -> &[u8] {
    if offset >= source.len() {
        return &[];
    }
    let mut end = (offset + LEXER_CHUNK_BYTES).min(source.len());
    while !source.is_char_boundary(end) {
        end += 1;
    }
    source.as_bytes().get(offset..end).unwrap_or_default()
}

/// Sum of `n²` over every run of `n` ≥ [`ANONYMOUS_RUN_MIN`] consecutive
/// anonymous children of one node, the quadratic part of what a query pays to
/// look for later named siblings ([`ANONYMOUS_RUN_COST_CAP`]). Stops counting
/// once past `cap`.
///
/// Queries only visit nodes that start within their byte range
/// ([`super::SOURCE_QUERY_BYTE_LIMIT`]), though they check the later
/// siblings of those wherever they lie, so this counts the children of every
/// node that starts in range and descends no further. One cursor pass over at
/// most that much of the tree, no allocation per node.
fn anonymous_run_cost(root: tree_sitter::Node<'_>, cap: u64) -> u64 {
    fn close(run: u64, cost: &mut u64) {
        if run >= ANONYMOUS_RUN_MIN {
            *cost = cost.saturating_add(run.saturating_mul(run));
        }
    }
    let mut cost = 0u64;
    let mut cursor = root.walk();
    // `runs[i]`: the current run among the children of the cursor's
    // ancestor at depth `i`.
    let mut runs: Vec<u64> = vec![0];
    if !cursor.goto_first_child() {
        return 0;
    }
    loop {
        let run = runs.last_mut().expect("one run per open level");
        if cursor.node().is_named() {
            close(std::mem::take(run), &mut cost);
        } else {
            *run += 1;
        }
        if cursor.node().start_byte() < super::SOURCE_QUERY_BYTE_LIMIT && cursor.goto_first_child()
        {
            runs.push(0);
            continue;
        }
        while !cursor.goto_next_sibling() {
            close(runs.pop().unwrap_or(0), &mut cost);
            if cost > cap || !cursor.goto_parent() || runs.is_empty() {
                return cost;
            }
        }
    }
}

/// Normalize Bash 5.3 `${parameter~pattern}` and `${parameter~~pattern}`
/// operators for the older tree-sitter-bash grammar while preserving every
/// byte offset. The original source remains authoritative for source-backed
/// facts. Only simple Bash parameter names and special parameters are
/// recognized; unsupported or malformed forms are left untouched and follow
/// the normal parser recovery path.
fn normalize_bash_case_modification(source: &str) -> Option<String> {
    let bytes = source.as_bytes();
    if !source.contains('~') {
        return None;
    }
    // Every operator needs a `}` after it. Comparing against the last `}`
    // keeps that check O(1) rather than rescanning the tail per `${`.
    let last_close = memchr::memrchr(b'}', bytes)?;

    let mut search_from = 0;
    let mut normalized = None;
    while let Some(relative) = source[search_from..].find("${") {
        let brace = search_from + relative;
        let Some((operator, operator_len)) =
            bash_case_modification_operator(bytes, brace, last_close)
        else {
            search_from = brace + 2;
            continue;
        };
        let output = normalized.get_or_insert_with(|| bytes.to_vec());
        if let Some(spelling) = output.get_mut(operator..operator + operator_len) {
            spelling.copy_from_slice(if operator_len == 2 { b"^^" } else { b"^" });
        }
        search_from = operator + operator_len;
    }
    let normalized = normalized?;
    // Replacements are ASCII and length-preserving, so valid UTF-8 stays valid.
    Some(String::from_utf8(normalized).expect("ASCII replacement preserves UTF-8"))
}

/// Longest `name[subscript]` scanned for its closing `]`. Unbounded, a run of
/// unterminated `${a[` openers would each rescan the rest of the file.
const MAX_BASH_SUBSCRIPT: usize = 1024;

fn bash_case_modification_operator(
    bytes: &[u8],
    brace: usize,
    last_close: usize,
) -> Option<(usize, usize)> {
    let mut index = brace.checked_add(2)?;
    // `${!name~~}` is indirect expansion, while `${!~~}` applies case
    // inversion to Bash's special `!` parameter.
    if bytes.get(index) == Some(&b'!') && bytes.get(index + 1..index + 2) != Some(b"~") {
        index += 1;
    }

    match *bytes.get(index)? {
        b'@' | b'*' | b'#' | b'?' | b'$' | b'!' | b'-' => index += 1,
        b'0'..=b'9' => {
            while matches!(bytes.get(index), Some(b'0'..=b'9')) {
                index += 1;
            }
        }
        b'A'..=b'Z' | b'a'..=b'z' | b'_' => {
            index += 1;
            while matches!(
                bytes.get(index),
                Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
            ) {
                index += 1;
            }
            if bytes.get(index) == Some(&b'[') {
                let mut subscript = bytes.get(index..)?.iter().take(MAX_BASH_SUBSCRIPT);
                let mut depth = 0usize;
                let close = subscript.position(|&byte| {
                    match byte {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            return depth == 0;
                        }
                        _ => {}
                    }
                    false
                })?;
                index += close + 1;
            }
        }
        _ => return None,
    }

    if bytes.get(index) != Some(&b'~') {
        return None;
    }
    let operator_len = if bytes.get(index + 1) == Some(&b'~') {
        2
    } else {
        1
    };
    // Require a closing brace after the operator. The optional pattern may
    // contain nested expansions; this check only rejects obviously truncated
    // input and does not parse that pattern.
    (last_close >= index + operator_len).then_some((index, operator_len))
}

/// Pre-check input that could overflow a tree-sitter external scanner's
/// 1024-byte serialization buffer. Returning `true` causes `parse` to
/// skip the parse rather than risk the C-level abort.
fn would_overflow_scanner_state(file_type: FileType, source: &str) -> bool {
    let audit = scanner_audit(file_type);
    if source.len() > parse_cap_bytes(audit) {
        return true;
    }
    if matches!(audit, ScannerAudit::Modeled) && matches!(file_type, FileType::Python) {
        if estimated_python_scanner_bytes(source) > PYTHON_SCANNER_BUDGET_BYTES {
            return true;
        }
    }
    false
}

/// What we've verified about a grammar's external scanner overflow
/// behavior, against the locked crate version in this workspace.
///
/// The serialization buffer is a fixed 1024 bytes (`parser.c`
/// `TREE_SITTER_SERIALIZATION_BUFFER_SIZE`). When the C scanner's
/// `serialize()` returns more than that, the tree-sitter runtime
/// aborts. The audit categorizes how each grammar handles overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScannerAudit {
    /// Scanner serializes a fixed, small amount of state regardless of
    /// input (e.g. no external scanner, or a single counter, or a
    /// `return 0`). Cannot reach the 1024-byte limit.
    Bounded,
    /// Scanner has a self-guard in `serialize()` that returns 0 when
    /// the next write would exceed the buffer. Safe at any input size.
    SelfGuarded,
    /// Scanner can overflow, but filefacts pre-models its worst-case
    /// serialized size and rejects inputs likely to trip it. Currently
    /// only Python.
    Modeled,
    /// Grammar has not been audited at the currently-locked version —
    /// or `file_type` is one this module doesn't recognize. Apply the
    /// tight [`UNAUDITED_GRAMMAR_CAP_BYTES`] cap until audited.
    Unaudited,
}

/// Audit table for the grammars wired up in [`langs::config_for`].
///
/// When bumping a `tree-sitter-*` crate, re-inspect that crate's
/// `scanner.c` (or `.cc`) and confirm the audit category still holds
/// — in particular, check whether `external_scanner_serialize` still
/// either returns a small constant size, or guards each write against
/// `TREE_SITTER_SERIALIZATION_BUFFER_SIZE`. If neither, downgrade to
/// `Unaudited` or add a model like Python's.
fn scanner_audit(file_type: FileType) -> ScannerAudit {
    use ScannerAudit::{Bounded, Modeled, SelfGuarded, Unaudited};
    match file_type {
        // No external scanner in the locked grammar crate.
        FileType::C
        | FileType::Go
        | FileType::Groovy
        | FileType::Java
        | FileType::Makefile
        | FileType::ObjectiveC
        | FileType::TypeScript
        | FileType::Zig => Bounded,

        // External scanner present, but `serialize()` returns a fixed
        // small size independent of input.
        FileType::Elixir
        | FileType::JavaScript
        | FileType::Kotlin
        | FileType::Lua
        | FileType::PowerShell
        | FileType::Rust
        | FileType::Swift => Bounded,

        // `serialize()` early-returns 0 when the next write would
        // overflow the 1024-byte buffer.
        FileType::CSharp | FileType::Php | FileType::Ruby | FileType::Scala | FileType::Shell => {
            SelfGuarded
        }

        // Can overflow; modeled in [`estimated_python_scanner_bytes`].
        FileType::Python => Modeled,

        // `ts-parser-perl` 1.2.1 caps the quote stack to the remaining
        // serialization buffer, bounds its heredoc queue to eight entries,
        // and clamps that queue again during deserialization.
        FileType::Perl => SelfGuarded,

        _ => Unaudited,
    }
}

/// Maximum source size we'll hand to the tree-sitter parser for a
/// grammar with the given audit category.
/// Why a parse produced no usable tree, as the parse reports it. The caller
/// turns it into a [`TreeSitterDiagnostic`] and logs it.
#[derive(Debug)]
enum ParseFailure {
    /// The grammar would not load.
    LanguageSetup(String),
    /// The progress callback stopped the parse (`Some`), or tree-sitter
    /// returned no tree on its own (`None`).
    Stopped(Option<ParseStop>),
    /// The tree is too costly to query; see [`ANONYMOUS_RUN_COST_CAP`].
    AnonymousRuns(u64),
}

impl ParseFailure {
    /// The diagnostic for a parse of `bytes` of `language` that failed this
    /// way. An abandoned parse degrades like the scanner-risk guard: generic
    /// and text facts still flow, with a diagnostic naming why the AST is
    /// missing. Cancelling gets its own metric, or a Ctrl-C would look like a
    /// corrupt sample.
    fn diagnostic(self, language: &'static str, bytes: usize) -> TreeSitterDiagnostic {
        match self {
            Self::LanguageSetup(e) => TreeSitterDiagnostic::parse_failed(format!(
                "malformed source: tree-sitter language setup failed: {e}"
            )),
            Self::Stopped(Some(ParseStop::Cancelled)) => {
                TreeSitterDiagnostic::parse_cancelled(language, bytes)
            }
            Self::Stopped(Some(ParseStop::Budget { budget, at })) => {
                tracing::warn!(
                    language,
                    bytes,
                    budget,
                    at,
                    "tree-sitter parse exhausted its work budget; AST facts dropped"
                );
                TreeSitterDiagnostic::parse_work_exhausted(language, bytes, budget, at)
            }
            Self::Stopped(Some(ParseStop::LexerBudget { budget, at })) => {
                tracing::warn!(
                    language,
                    bytes,
                    budget,
                    at,
                    "tree-sitter parse exhausted its lexer budget; AST facts dropped"
                );
                TreeSitterDiagnostic::lexer_work_exhausted(language, bytes, budget, at)
            }
            Self::Stopped(Some(ParseStop::ErrorRecovery { polls, at })) => {
                tracing::warn!(
                    language,
                    bytes,
                    polls,
                    at,
                    "tree-sitter error recovery did not recover; AST facts dropped"
                );
                TreeSitterDiagnostic::error_recovery_exhausted(language, bytes, polls, at)
            }
            Self::Stopped(Some(ParseStop::EofRecovery { polls, allowed })) => {
                tracing::warn!(
                    language,
                    bytes,
                    polls,
                    allowed,
                    "tree-sitter error recovery at end of input ran too long; AST facts dropped"
                );
                TreeSitterDiagnostic::eof_recovery_exhausted(language, bytes, polls, allowed)
            }
            Self::Stopped(Some(ParseStop::Backstop)) => {
                tracing::warn!(
                    language,
                    bytes,
                    backstop_s = SOURCE_PARSE_WALL_BACKSTOP.as_secs(),
                    "tree-sitter parse hit its wall-clock backstop; AST facts dropped"
                );
                TreeSitterDiagnostic::parse_backstop(language, bytes)
            }
            Self::Stopped(None) => TreeSitterDiagnostic::parse_failed(
                "malformed source: tree-sitter parse returned None",
            ),
            Self::AnonymousRuns(cost) => {
                tracing::warn!(
                    language,
                    bytes,
                    cost,
                    "tree-sitter tree has anonymous-token runs too costly to query; AST facts dropped"
                );
                TreeSitterDiagnostic::anonymous_run_guard(language, bytes, cost)
            }
        }
    }
}

fn parse_cap_bytes(audit: ScannerAudit) -> usize {
    match audit {
        ScannerAudit::Bounded | ScannerAudit::SelfGuarded => MAX_AST_FILE_BYTES,
        ScannerAudit::Modeled => MAX_MODELED_AST_FILE_BYTES,
        ScannerAudit::Unaudited => UNAUDITED_GRAMMAR_CAP_BYTES,
    }
}

/// Worst-case Python scanner serialization size. Models both the
/// **indent stack** and the **delimiter stack** the scanner persists,
/// since either one alone — or the two together — can exceed the
/// 1024-byte buffer and trip `ts_parser__external_scanner_serialize`.
/// Computed without invoking the parser so it stays cheap on hostile
/// input.
///
/// Returned value is in bytes and includes the 2-byte header that
/// the serializer emits before either stack.
fn estimated_python_scanner_bytes(source: &str) -> usize {
    // 1 byte `inside_interpolated_string` + 1 byte `delimiter_count`.
    const HEADER_BYTES: usize = 2;
    let indent_levels = estimated_python_indent_stack_depth(source);
    let delim_levels = estimated_python_delimiter_depth(source);
    // The serializer's `iter = 1` start skips `indents[0]` (always 0),
    // so the persisted indent count is `indent_levels.saturating_sub(1)`.
    let indent_bytes = indent_levels.saturating_sub(1) * PYTHON_INDENT_BYTES_PER_LEVEL;
    // Delimiter count is clamped to UINT8_MAX inside the serializer.
    let delim_bytes = delim_levels.min(u8::MAX as usize) * PYTHON_DELIMITER_BYTES;
    HEADER_BYTES + delim_bytes + indent_bytes
}

/// Worst-case depth of Python's indent stack — one of the two stacks
/// the tree-sitter external scanner persists.
fn estimated_python_indent_stack_depth(source: &str) -> usize {
    let mut stack: Vec<usize> = vec![0];
    let mut max_depth: usize = 1;

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line
            .bytes()
            .take_while(|b| matches!(b, b' ' | b'\t'))
            .fold(0usize, |col, b| if b == b'\t' { col + 8 } else { col + 1 });
        while stack.last().is_some_and(|last| indent < *last) {
            stack.pop();
        }
        if stack.last().is_some_and(|last| indent > *last) {
            stack.push(indent);
            max_depth = max_depth.max(stack.len());
        }
    }
    max_depth
}

/// Worst-case depth of Python's delimiter stack — the other stack the
/// scanner persists. The scanner pushes one entry per open string
/// literal that hasn't closed yet; the only path that grows it beyond
/// a single entry is f-string interpolation, where `f"{ ... }"` may
/// itself contain another `f"..."`.
///
/// We can't parse Python here without running tree-sitter, so we use
/// the simplest correct upper bound: every `f"`, `f'`, `F"`, or `F'`
/// found in the source is a potential push. Brackets that an f-string
/// might close (`}`) are accounted for by walking the bytes and
/// tracking the maximum unmatched `f`-prefix count between the
/// surrounding `{` and `}` boundaries. Triple-quoted f-strings count
/// once each (they consume a single delimiter slot).
fn estimated_python_delimiter_depth(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut max_depth: usize = 0;
    let mut depth: usize = 0;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            // Skip past a hash-line comment — `f"` inside a comment is
            // not a delimiter push.
            b'#' => {
                while bytes.get(i).is_some_and(|&b| b != b'\n') {
                    i += 1;
                }
            }
            // An `f`/`F` immediately followed by a quote opens an
            // f-string. Plain (non-f) strings never *nest*, so we
            // only need to count f-string openers.
            b'f' | b'F' => {
                let next = bytes.get(i + 1).copied().unwrap_or(0);
                if next == b'"' || next == b'\'' {
                    depth = depth.saturating_add(1);
                    max_depth = max_depth.max(depth);
                    i += 2;
                    continue;
                }
                i += 1;
            }
            // A closing brace inside interpolation drops one level of
            // f-string nesting. Worst-case heuristic: every `}` could
            // close an f-string interpolation, so decrement.
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    max_depth
}

#[cfg(test)]
mod tests;
