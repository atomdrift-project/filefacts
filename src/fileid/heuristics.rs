//! The language scorer: lightweight content heuristics for files where
//! neither a signature nor a name settled the type.
//!
//! One Aho-Corasick automaton over [`PATTERNS`], built once, scans a bounded
//! window in a single leftmost-longest pass, so a pattern inside a longer one
//! (`pairs(` in `ipairs(`, `let ` in `(let [`) is not counted twice. Hits are
//! bucketed by language and weighted: a conclusive token (weight 10) almost
//! never appears outside its language, a supporting one (weight 5) needs a
//! second hit to confirm, and a language needs [`THRESHOLD`] to be named.
//! Every language in the table has at least one conclusive token.

use std::{borrow::Cow, path::Path, sync::LazyLock};

use aho_corasick::{AhoCorasick, MatchKind};

use super::{
    FileType,
    magic::WSH_SCRIPT_WINDOW,
    scripts,
    sniff::Sniff,
    text::{Controls, contains, is_binary, strip_utf8_bom},
};

/// Minimum bytes of non-whitespace content required before we trust heuristics.
const MIN_CONTENT_BYTES: usize = 16;

/// Maximum bytes to scan for heuristics.
pub(super) const SCAN_LIMIT: usize = 4096;

/// How many bytes from the end to check when the head is mostly whitespace.
const TAIL_SIZE: usize = 2048;

/// Minimum score to consider a language match.
const THRESHOLD: u16 = 10;

/// A head scoring this much is two conclusive tokens, or a handful of
/// supporting ones: it already looks like a real unit, so the window after it
/// may not replace it.
const SETTLED_HEAD_SCORE: u16 = 40;

/// How close, as a percentage of the best score, a runner-up may come before
/// the two are too close to call.
const AMBIGUOUS_PERCENT: u32 = 60;

/// How much of a UTF-16 file's head is narrowed for the scorers: the widest
/// window any of them reads from the top, the script-host document's.
const DECODE_HEAD: usize = WSH_SCRIPT_WINDOW;

/// How much of a UTF-16 file's tail is narrowed: the line grammars' tail
/// window, which is wider than the scorer's.
const DECODE_TAIL: usize = scripts::WINDOW;

/// Furthest a leading quoted assignment is followed to its closing quote.
const ASSIGNMENT_SCAN_LIMIT: usize = 4 << 20;

/// Significant lines a document needs before its shape is judged as YAML. Short
/// fragments carry too little structure to separate a mapping from prose.
const MIN_YAML_LINES: usize = 5;

#[derive(Clone, Copy)]
struct PatternEntry {
    lang: Lang,
    weight: u8,
}

/// Declares [`Lang`], [`LANGS`] and [`Lang::to_file_type`] from one list, so
/// a language's score index, its place in `LANGS` and the [`FileType`] it
/// reports cannot drift apart. Each name is also the `FileType` it reports.
macro_rules! scored_languages {
    ($($lang:ident),+ $(,)?) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Lang {
            $($lang),+
        }

        /// All languages in score-index order, which is also the order a tie
        /// for the best score is broken in.
        const LANGS: &[Lang] = &[$(Lang::$lang),+];

        impl Lang {
            fn to_file_type(self) -> FileType {
                match self {
                    $(Self::$lang => FileType::$lang),+
                }
            }
        }
    };
}

scored_languages! {
    Shell,
    Python,
    PowerShell,
    Perl,
    Php,
    Batch,
    Vbs,
    Lua,
    JavaScript,
    C,
    Kotlin,
    Dockerfile,
    Clojure,
    AppleScript,
    ObjectiveC,
}

const LANG_COUNT: usize = LANGS.len();

impl Lang {
    /// Index into the scores array: the declaration order of [`LANGS`].
    const fn idx(self) -> usize {
        self as usize
    }

    /// This language's entry in a score table. Every `Lang` has one, since
    /// the table is [`LANG_COUNT`] long.
    fn score(self, scores: &Scores) -> u16 {
        scores.0.get(self.idx()).copied().unwrap_or(0)
    }

    /// The scored language a file type names, if the table scores it.
    fn from_file_type(ft: FileType) -> Option<Self> {
        LANGS.iter().copied().find(|l| l.to_file_type() == ft)
    }
}

/// Per-language scores, indexed by [`Lang`].
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Scores([u16; LANG_COUNT]);

impl Scores {
    /// The best score of any language.
    fn best(&self) -> u16 {
        self.0.iter().copied().max().unwrap_or(0)
    }
}

// High-signal patterns only. Each language needs >=10 points to match.
// Conclusive (10) = almost never appears outside this language.
// Strong (5)      = common idiom, needs a second hit to confirm.
const PATTERNS: &[(&[u8], Lang, u8)] = &[
    // ── Shell ──
    (b"export ", Lang::Shell, 5),
    (b"set -e", Lang::Shell, 5),
    (b"if [", Lang::Shell, 5),
    (b"case $", Lang::Shell, 5),
    (b"; then\n", Lang::Shell, 5),
    (b"; then\r", Lang::Shell, 5),
    (b"; do\n", Lang::Shell, 5),
    (b"; do\r", Lang::Shell, 5),
    (b" && curl ", Lang::Shell, 10),
    (b" && chmod +x ", Lang::Shell, 10),
    (b"cd $", Lang::Shell, 5),
    (b"curl -O http", Lang::Shell, 5),
    // Shell's own control syntax and path idioms: supporting weight, so prose
    // that mentions one command does not type itself.
    (b"cd /", Lang::Shell, 5),
    (b" || /", Lang::Shell, 5),
    (b"wget http", Lang::Shell, 5),
    // Detaching a command and piping a download into an interpreter are
    // shell's own syntax, not words prose strings together.
    (b"nohup ", Lang::Shell, 5),
    (b"| bash", Lang::Shell, 5),
    (b"| sh\n", Lang::Shell, 5),
    // pacman/AUR `.install` scriptlet hook functions. These are shell function
    // definitions (`name() {`) with names reserved by pacman's install-scriptlet
    // convention, so the `() {` definition form keyed to a pacman hook name is
    // conclusive shell — it never appears in other languages. Detecting these by
    // content (not by the `.install` extension) avoids mis-typing Debian
    // `debian/*.install` files, which share the extension but are plain
    // newline-separated path lists with no scriptlet functions. Content-based
    // detection also recovers scriptlets shipped with a renamed or absent
    // extension.
    (b"post_install() {", Lang::Shell, 10),
    (b"pre_install() {", Lang::Shell, 10),
    (b"post_upgrade() {", Lang::Shell, 10),
    (b"pre_upgrade() {", Lang::Shell, 10),
    (b"post_remove() {", Lang::Shell, 10),
    (b"pre_remove() {", Lang::Shell, 10),
    // ── Python ──
    (b"if __name__", Lang::Python, 10),
    (b"import os", Lang::Python, 10),
    (b"base64.b64decode", Lang::Python, 10),
    (b"def ", Lang::Python, 5),
    (b"except ", Lang::Python, 5),
    (b"exec(", Lang::Python, 5),
    (b"subprocess.", Lang::Python, 5),
    (b"self.", Lang::Python, 5),
    // ── PowerShell ──
    (b"$ErrorActionPreference", Lang::PowerShell, 10),
    (b"[System.Convert]", Lang::PowerShell, 10),
    (b" -bxor ", Lang::PowerShell, 10),
    (b"Write-Host", Lang::PowerShell, 5),
    (b"Invoke-", Lang::PowerShell, 5),
    (b"New-Object", Lang::PowerShell, 5),
    // Advanced-function and assembly-loading syntax. Neither form exists
    // outside PowerShell: C# cmdlets declare `[Cmdlet(...)]`, and `$env:` is
    // the PowerShell environment drive (`%X%` in batch, `$X` in shell).
    (b"[CmdletBinding(", Lang::PowerShell, 10),
    (b"Add-Type -", Lang::PowerShell, 10),
    (b"$env:", Lang::PowerShell, 5),
    (b"[Byte[]]", Lang::PowerShell, 10),
    // ── Perl ──
    (b"use strict;", Lang::Perl, 10),
    (b"use warnings;", Lang::Perl, 10),
    (b"use strict\n", Lang::Perl, 10),
    (b"use strict\r", Lang::Perl, 10),
    (b"use warnings\n", Lang::Perl, 10),
    (b"use warnings\r", Lang::Perl, 10),
    (b"my $", Lang::Perl, 5),
    (b"chomp", Lang::Perl, 5),
    // ── PHP ──
    // PHP fragments and PHP+HTML hybrids may lack a leading `<?php` tag.
    // Score PHP-specific globals and WordPress hook idioms so `elseif ` in
    // those files does not win as Lua.
    (b"<?php", Lang::Php, 10),
    // A short open tag at a line break (`<?` then whitespace). `<?php` is
    // scored above, and this form does not match `<?xml`.
    (b"<?\n", Lang::Php, 10),
    (b"<?\r", Lang::Php, 10),
    (b"<? ", Lang::Php, 10),
    (b"$_SERVER", Lang::Php, 10),
    // PHP 4 class properties are `var $name`. The same `var ` prefix is a
    // JavaScript declaration; the longer match wins, so `var $pwd` scores for
    // PHP alone.
    (b"var $", Lang::Php, 10),
    // Posted-command webshells unescape with stripslashes(). No other
    // language spells that function.
    (b"stripslashes(", Lang::Php, 10),
    (b"$_POST", Lang::Php, 10),
    (b"$_GET", Lang::Php, 10),
    (b"add_filter(", Lang::Php, 10),
    (b"add_action(", Lang::Php, 10),
    (b"esc_html(", Lang::Php, 5),
    (b"preg_replace(", Lang::Php, 5),
    // ── Batch ──
    (b"@echo", Lang::Batch, 10),
    (b"@ECHO", Lang::Batch, 10),
    (b"%~dp0", Lang::Batch, 10),
    (b"SETLOCAL", Lang::Batch, 5),
    (b"GOTO ", Lang::Batch, 5),
    (b"IF EXIST", Lang::Batch, 5),
    // The three above are upper-case only, and batch is a case-insensitive
    // language that people write in lower case. Lower-case `goto`/`if exist`
    // would collide with C and Go; these four are spelled the same way
    // nowhere else.
    (b"errorlevel", Lang::Batch, 10),
    (b"ERRORLEVEL", Lang::Batch, 10),
    (b"ctty ", Lang::Batch, 10),
    (b"attrib +", Lang::Batch, 5),
    // `@` before a command suppresses its echo, and `if exist` is the batch
    // file test. Scripts that never say `@echo off` still write
    // `@if exist C:\x del C:\x` on every line. SCSS has `@if` but never
    // `@if exist`.
    (b"@if exist ", Lang::Batch, 10),
    // The doubled `%%` is how a batch file spells a loop variable.
    (b"for %%", Lang::Batch, 10),
    (b"@if not exist ", Lang::Batch, 10),
    (b"@deltree ", Lang::Batch, 10),
    (b"@del ", Lang::Batch, 5),
    (b"@copy ", Lang::Batch, 5),
    // ── VBScript ──
    (b"WScript.", Lang::Vbs, 10),
    (b"Option Explicit", Lang::Vbs, 10),
    (b"CreateObject(", Lang::Vbs, 5),
    (b"End Sub", Lang::Vbs, 5),
    (b"End Function", Lang::Vbs, 5),
    // ── Lua ──
    (b"setmetatable", Lang::Lua, 10),
    (b"getmetatable", Lang::Lua, 10),
    (b"getfenv", Lang::Lua, 10),
    (b"setfenv", Lang::Lua, 10),
    (b"ipairs(", Lang::Lua, 5),
    (b"pairs(", Lang::Lua, 5),
    (b"elseif ", Lang::Lua, 5),
    // Obfuscated Lua (Prometheus, Luraph and kin) ships as one minified line,
    // and the environment calls above sit at its far end, past every window.
    // A bare `...` parameter list is Lua's vararg -- JavaScript's rest
    // parameter needs a name -- and `local function` is spelled nowhere else.
    // Minifiers glue `end` to the preceding bracket; no other scored language
    // closes a block that way.
    (b"function(...)", Lang::Lua, 10),
    // The same vararg function wrapped in parentheses, as minifiers write
    // an immediately invoked one; longer than JavaScript's `(function(`, so
    // it is the one counted.
    (b"(function(...)", Lang::Lua, 10),
    (b"local function ", Lang::Lua, 10),
    (b"]end ", Lang::Lua, 5),
    (b")end ", Lang::Lua, 5),
    // ── JavaScript ──
    (b"module.exports", Lang::JavaScript, 10),
    (b"(function(", Lang::JavaScript, 5),
    (b"===", Lang::JavaScript, 5),
    // `console.log(` (the JS call), not bare `console.` — the latter matches
    // source filenames like `console.cpp` / `reporter_console.cpp` listed in
    // build files, mis-typing them as JavaScript.
    (b"console.log(", Lang::JavaScript, 5),
    (b"document.", Lang::JavaScript, 5),
    (b"window.", Lang::JavaScript, 5),
    (b"addEventListener", Lang::JavaScript, 5),
    // Forms that appear in modern JS with none of the tokens above: an arrow
    // function with a block body, JSON serialization, and CommonJS require.
    (b"=> {", Lang::JavaScript, 5),
    (b"JSON.stringify", Lang::JavaScript, 10),
    (b"require(\"", Lang::JavaScript, 10),
    (b"require('", Lang::JavaScript, 10),
    // `var `/`let `/`const ` are JS variable declarations. `var ` especially is
    // dense in obfuscated/minified JS (every renamed local), so it must score
    // for JS — not only Kotlin (which prefers `val`). Supporting weight: a
    // single decl word isn't conclusive on its own.
    (b"var ", Lang::JavaScript, 5),
    (b"let ", Lang::JavaScript, 5),
    (b"const ", Lang::JavaScript, 5),
    // ── C/C++/ASM ──
    (b"#include <", Lang::C, 10),
    (b"#include \"", Lang::C, 10),
    (b"section .text", Lang::C, 10),
    (b"[BITS 32]", Lang::C, 10),
    // ── Kotlin ──
    // `package ` is NOT conclusive: it appears in English prose ("a package
    // for…"), Java, and package-manifest text, so it stays a supporting weight
    // and must be corroborated by a second Kotlin hit. The Kotlin-exclusive
    // tokens (`import kotlin`, `suspend fun `) carry the conclusive weight.
    (b"package ", Lang::Kotlin, 5),
    (b"import kotlin", Lang::Kotlin, 10),
    (b"fun main(", Lang::Kotlin, 5),
    // `val ` is Kotlin-characteristic (Kotlin prefers immutable `val`); `var `
    // was removed here because it is a core JavaScript keyword and dominates
    // obfuscated JS, mis-scoring var-heavy scripts as Kotlin. Kotlin still has
    // conclusive markers (`import kotlin`, `suspend fun `) plus `val `.
    (b"val ", Lang::Kotlin, 5),
    (b"suspend fun ", Lang::Kotlin, 10),
    // ── Dockerfile ──
    (b"\nFROM ", Lang::Dockerfile, 10),
    (b"FROM scratch", Lang::Dockerfile, 10),
    (b"\nRUN ", Lang::Dockerfile, 5),
    (b"\nCMD [", Lang::Dockerfile, 10),
    (b"\nENTRYPOINT", Lang::Dockerfile, 10),
    (b"\nWORKDIR ", Lang::Dockerfile, 5),
    (b"\nCOPY ", Lang::Dockerfile, 5),
    (b"\nEXPOSE ", Lang::Dockerfile, 5),
    (b"\nVOLUME ", Lang::Dockerfile, 5),
    (b"\nHEALTHCHECK", Lang::Dockerfile, 10),
    // ── Clojure / ClojureScript / EDN ──
    // Clojure source heavily shares tokens with the Python pattern list
    // (`def `, `exec(`, `self.`) so its conclusive patterns are weighted high
    // enough to win even when Python scores on incidental hits.
    (b"(defn ", Lang::Clojure, 10),
    (b"(defn- ", Lang::Clojure, 10),
    (b"(defmacro ", Lang::Clojure, 10),
    (b"(defprotocol ", Lang::Clojure, 10),
    (b"(defmethod ", Lang::Clojure, 10),
    (b"(defmulti ", Lang::Clojure, 10),
    (b"(defrecord ", Lang::Clojure, 10),
    (b"(deftype ", Lang::Clojure, 10),
    (b"(ns ", Lang::Clojure, 10),
    (b":require ", Lang::Clojure, 10),
    (b":require\n", Lang::Clojure, 10),
    (b":require\r", Lang::Clojure, 10),
    (b"#?(:clj", Lang::Clojure, 10),
    (b"#?(:cljs", Lang::Clojure, 10),
    (b"(let [", Lang::Clojure, 5),
    (b"(if-let [", Lang::Clojure, 5),
    (b"(when-let [", Lang::Clojure, 5),
    (b"(fn [", Lang::Clojure, 5),
    // ── AppleScript ──
    // AMOS/Shub-family stealers are routinely delivered as plaintext AppleScript
    // with a random or `.unknown` extension, so content sniffing matters. These
    // idioms are AppleScript-exclusive (no other scripting language uses them):
    // `do shell script`, `tell application "`, `quoted form of`, `POSIX path of`,
    // and the `on <handler>(` / `end <handler>` block form.
    (b"do shell script", Lang::AppleScript, 10),
    (b"tell application \"", Lang::AppleScript, 10),
    (b"quoted form of", Lang::AppleScript, 10),
    (b"POSIX path of", Lang::AppleScript, 10),
    (b"end tell", Lang::AppleScript, 5),
    (b"end repeat", Lang::AppleScript, 5),
    (b"on run", Lang::AppleScript, 5),
    (b"with hidden answer", Lang::AppleScript, 10),
    // ── Objective-C ──
    // The compiler directives no C, C++ or Swift file spells. Objective-C is
    // a superset of C, so a real `.m` also scores for C on every `#include`;
    // `detect_from_content` resolves that pairing toward Objective-C. Without
    // these a genuine `.m` scored only as C and lost its type.
    // `@property` alone is a Python decorator, so only the attribute form.
    (b"@interface ", Lang::ObjectiveC, 10),
    (b"@implementation ", Lang::ObjectiveC, 10),
    (b"@autoreleasepool", Lang::ObjectiveC, 10),
    (b"@selector(", Lang::ObjectiveC, 10),
    (b"@synthesize ", Lang::ObjectiveC, 10),
    (b"@property (", Lang::ObjectiveC, 10),
    (b"@property(", Lang::ObjectiveC, 10),
    (b"#import <", Lang::ObjectiveC, 10),
    (b"#import \"", Lang::ObjectiveC, 10),
    (b"NSLog(@\"", Lang::ObjectiveC, 10),
    (b"alloc] init", Lang::ObjectiveC, 10),
    (b"@end\n", Lang::ObjectiveC, 5),
    (b"@end\r", Lang::ObjectiveC, 5),
];

struct AcScanner {
    ac: AhoCorasick,
    entries: Vec<PatternEntry>,
}

/// The automaton over [`PATTERNS`]. The patterns are fixed at compile time,
/// so a build failure is a bug in this file, not something an input can cause;
/// it panics on first use rather than quietly disabling every language.
static SCANNER: LazyLock<AcScanner> = LazyLock::new(|| AcScanner {
    ac: AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(PATTERNS.iter().map(|(pattern, _, _)| pattern))
        .expect("heuristic patterns are a valid Aho-Corasick set"),
    entries: PATTERNS
        .iter()
        .map(|&(_, lang, weight)| PatternEntry { lang, weight })
        .collect(),
});

/// Check if the first `limit` bytes are mostly whitespace.
fn is_mostly_whitespace(data: &[u8], limit: usize) -> bool {
    let head = data.get(..limit).unwrap_or(data);
    let non_ws = head.iter().filter(|&&b| !b.is_ascii_whitespace()).count();
    non_ws < MIN_CONTENT_BYTES
}

/// Single-pass scan using Aho-Corasick. Returns per-language scores.
fn scan_scores(data: &[u8]) -> Scores {
    let s = &*SCANNER;
    let mut scores = Scores::default();

    for mat in s.ac.find_iter(data) {
        // The match, the byte before it and everything after it. The
        // automaton only reports spans inside `data`.
        let Some((before, from)) = data.split_at_checked(mat.start()) else {
            continue;
        };
        let Some((m, rest)) = from.split_at_checked(mat.len()) else {
            continue;
        };
        let prev = before.last().copied();
        // `===` (JS strict-equality) must not score when it is part of a
        // longer run of '=' — e.g. "=========" separator lines or reST/
        // Markdown header rules.
        if m == b"===" && (prev == Some(b'=') || rest.first() == Some(&b'=')) {
            continue;
        }
        // `document.`/`window.` are JS DOM-global accesses only when a member
        // name follows (document.getElementById, window.location). English
        // prose ends sentences with "…this document." / "…the window.", where
        // the dot is followed by whitespace/EOL/an uppercase next sentence —
        // never a lowercase member. Require a lowercase member char so a
        // license, README, or changelog does not score as JavaScript.
        if (m == b"document." || m == b"window.")
            && !rest.first().is_some_and(u8::is_ascii_lowercase)
        {
            continue;
        }
        // `start WScript.exe x.vbs` is a batch file launching the host, not
        // VBScript calling it; the object model is `WScript.Echo`,
        // `WScript.CreateObject`, never `.exe`.
        if m == b"WScript."
            && rest
                .get(..3)
                .is_some_and(|x| x.eq_ignore_ascii_case(b"exe"))
        {
            continue;
        }
        // "itself." contains `self.`, "Applet " contains `let `, and
        // "eval " contains `val `. A declaration sits on a token boundary;
        // `let ` followed by a function word is prose.
        if matches!(
            m,
            b"let " | b"var " | b"const " | b"def " | b"except " | b"self." | b"val "
        ) && prev.is_some_and(|b| b.is_ascii_alphanumeric())
        {
            continue;
        }
        if m == b"let " {
            const PROSE: &[&[u8]] = &[
                b"the ", b"the\n", b"a ", b"an ", b"us ", b"me ", b"it ", b"you ", b"them ",
                b"this ", b"that ", b"your ", b"there ", b"him ", b"her ",
            ];
            if PROSE.iter().any(|word| rest.starts_with(word)) {
                continue;
            }
        }
        let Some(entry) = s.entries.get(mat.pattern().as_usize()) else {
            continue;
        };
        if let Some(score) = scores.0.get_mut(entry.lang.idx()) {
            *score = score.saturating_add(u16::from(entry.weight));
        }
    }

    scores
}

/// Recognize a leading PowerShell here-string assignment even when a large
/// literal hides all command tokens from the usual 4 KiB scoring window.
/// Only blank/comment lines may precede it; require the matching terminator
/// and conclusive PowerShell evidence in the following bounded source window.
fn leading_powershell_here_string(data: &[u8]) -> bool {
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    let mut offset = 0;
    for line in head.split_inclusive(|&b| b == b'\n') {
        offset += line.len();
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some(rest) = line.strip_prefix(b"$") else {
            return false;
        };
        let name_len = rest
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count();
        if name_len == 0 || rest.first().is_some_and(u8::is_ascii_digit) {
            return false;
        }
        let Some(value) = rest
            .get(name_len..)
            .unwrap_or_default()
            .trim_ascii_start()
            .strip_prefix(b"=")
        else {
            return false;
        };
        let value = value.trim_ascii();
        if !matches!(value, b"@'" | b"@\"") {
            return false;
        }
        let Some(&quote) = value.get(1) else {
            return false;
        };
        let body = data
            .get(offset..data.len().min(32 * 1024 * 1024))
            .unwrap_or_default();
        let mut consumed = offset;
        for literal_line in body.split_inclusive(|&b| b == b'\n') {
            consumed += literal_line.len();
            // PowerShell closing delimiters begin in column zero.
            if literal_line.trim_ascii_end() == [quote, b'@'] {
                let after = data
                    .get(consumed..data.len().min(consumed + SCAN_LIMIT))
                    .unwrap_or_default();
                return Lang::PowerShell.score(&scan_scores(after)) >= THRESHOLD;
            }
        }
        return false;
    }
    false
}

/// The language the scorer finds in `data`, read as [`Sniff::scored_type`]
/// reads it. A caller with a [`Sniff`] of its own asks it instead, so the
/// work is kept.
pub(super) fn detect_from_content(data: &[u8]) -> Option<FileType> {
    Sniff::new(Path::new(""), data).scored_type()
}

/// The scorer's head window of `body`, the text past its leading
/// whitespace.
pub(super) fn head_scores(body: &[u8]) -> Scores {
    scan_scores(body.get(..SCAN_LIMIT).unwrap_or(body))
}

/// The language the content scorer finds in [`Sniff::text`]: the bytes, or
/// their UTF-16 decode, since Windows scripts are routinely saved as UTF-16
/// and every scorer here reads bytes.
pub(super) fn scored_type(sniff: &Sniff<'_>) -> Option<FileType> {
    let data = sniff.text();
    if data.len() < 4 {
        return None;
    }

    // Sectioned key/value configs can quote source tokens in comments or
    // values. Treat their document shape as text before language scoring.
    if looks_like_ini_config(data) {
        return Some(FileType::Text);
    }

    // Detection rules, CI configuration, and package manifests quote the very
    // tokens this table scores: a rule pack hunting Python stagers contains
    // `import os`, one hunting macOS stealers contains `do shell script`. The
    // document is data about a language, not the language. Names normally
    // settle this, but a renamed, disabled, or extensionless copy reaches
    // content sniffing, so the document shape has to decide. Structured data
    // is never one of the scored languages.
    if looks_like_structured_data(data) {
        return None;
    }

    // Take the scan window from the first byte that carries content. Padding
    // a one-line payload off the left margin with several hundred spaces
    // pushes enough scoring tokens out of a fixed-size head window to drop
    // the file below THRESHOLD; skipping the run makes the window measure
    // content rather than indentation.
    let body = data.trim_ascii_start();
    let head = body.get(..SCAN_LIMIT).unwrap_or(body);
    // Batch, VBScript, mIRC and ircII are read line by line, verb first. That
    // runs ahead of the binary and prose guards on purpose: batch files carry
    // ANSI escapes and `echo` whole paragraphs, and the line grammar is what
    // tells a script that talks from prose that mentions a command.
    let script = sniff.evidence();
    // A Dockerfile's `COPY src /dst` reads as a Windows `copy` with a switch;
    // one that opens with `FROM` or `ARG` is left to the token table.
    let verdict = script
        .verdict()
        .filter(|_| !starts_with_dockerfile_instruction(body));
    if let Some(ft) = verdict {
        return Some(ft);
    }

    // Every scored language is text. Object code is not, and two chance
    // occurrences of a two-byte token (`#'`) in a kilobyte of x86 reach
    // THRESHOLD on their own; an unparseable "source" file is worth less than
    // an unidentified one.
    if is_binary(head, Controls::Text) {
        return None;
    }

    if leading_powershell_here_string(body) {
        return Some(FileType::PowerShell);
    }

    // Natural-language prose is never one of the scored languages either, but
    // it does quote their keywords: a novel has `const`, `let `, `var ` and
    // `new ` in every chapter, and a megabyte of it typed as JavaScript sends
    // tree-sitter's error recovery on a long walk. Code carries punctuation
    // prose does not, and the head alone tells them apart.
    if data.len() >= PROSE_GUARD_MIN_BYTES && looks_like_prose(head) {
        return None;
    }

    // If the head is mostly whitespace, also scan the tail
    let scores = if is_mostly_whitespace(body, SCAN_LIMIT) && body.len() > SCAN_LIMIT {
        let tail_start = body.len().saturating_sub(TAIL_SIZE);
        let tail = body.get(tail_start..).unwrap_or(body);
        let mut merged = *sniff.head_scores();
        for (score, tail_score) in merged.0.iter_mut().zip(scan_scores(tail).0) {
            *score = (*score).max(tail_score);
        }
        merged
    } else {
        *sniff.head_scores()
    };
    // A preface can push the real language just past the first window: an ASP
    // one-liner list, then `<?php` shells a few hundred bytes later. Only the
    // next window may replace a head that never became conclusive.
    let scores = if !is_mostly_whitespace(body, SCAN_LIMIT) && body.len() > SCAN_LIMIT {
        let head_best = scores.best();
        // A preface of `var ` / `eval ` scores too, and hides `<?php` a few
        // hundred bytes later. A head that already looks like a real unit
        // stays as it is.
        if head_best < SETTLED_HEAD_SCORE {
            let next = body
                .get(SCAN_LIMIT..body.len().min(SCAN_LIMIT * 2))
                .unwrap_or_default();
            let next_scores = scan_scores(next);
            let next_best = next_scores.best();
            if next_best >= THRESHOLD
                && next_best > head_best
                && (head_best == 0 || !too_close(head_best, next_best))
            {
                next_scores
            } else {
                scores
            }
        } else {
            scores
        }
    } else {
        scores
    };

    // A long leading string assignment can cover both prefix windows. Read
    // the following source after its lexical closing quote, then use the same
    // language scorer; never infer a language from encoded payload contents.
    let scores = if scores.best() < SETTLED_HEAD_SCORE {
        match after_leading_string_assignment(body) {
            Some(tail) if tail.len() >= MIN_CONTENT_BYTES => {
                let candidate = scan_scores(tail.get(..SCAN_LIMIT).unwrap_or(tail));
                if candidate.best() >= THRESHOLD {
                    candidate
                } else {
                    scores
                }
            }
            _ => scores,
        }
    } else {
        scores
    };

    // Batch's and VBScript's tokens are quoted by everything that drops or
    // launches them: a VBScript writing `@echo off` into a `.bat`, a makefile
    // recipe's `@echo`, JScript's `new ActiveXObject("WScript.Shell")`. Their
    // score only stands when some line is actually written in the language.
    let mut scores = scores;
    for (lang, ft) in [(Lang::Batch, FileType::Batch), (Lang::Vbs, FileType::Vbs)] {
        if script.has_lines()
            && (!script.supports(ft) || script.rules_out(ft))
            && let Some(score) = scores.0.get_mut(lang.idx())
        {
            *score = 0;
        }
    }

    // Find the best and second-best scoring languages
    let mut best_lang: Option<Lang> = None;
    let mut best_score: u16 = 0;
    let mut second_score: u16 = 0;

    for (&lang, &score) in LANGS.iter().zip(&scores.0) {
        if score > best_score {
            second_score = best_score;
            best_score = score;
            best_lang = Some(lang);
        } else if score > second_score {
            second_score = score;
        }
    }

    let mut lang = best_lang?;

    // Must meet threshold
    if best_score < THRESHOLD {
        return None;
    }

    // Objective-C is C plus directives C never has, so every `#include` in a
    // `.m` scores for C and a large file drowns the handful of `@interface`
    // lines. Any conclusive Objective-C directive settles it.
    let objc = Lang::ObjectiveC.score(&scores);
    if lang == Lang::C && objc >= THRESHOLD {
        lang = Lang::ObjectiveC;
        best_score = objc;
        // Still ambiguous against any language other than its own C base.
        second_score = LANGS
            .iter()
            .filter(|l| !matches!(l, Lang::C | Lang::ObjectiveC))
            .map(|l| l.score(&scores))
            .max()
            .unwrap_or(0);
    }

    // Ambiguity: if the second-best is close, bail
    if second_score > 0 && too_close(second_score, best_score) {
        return None;
    }

    // JavaScript's supporting tokens (`var `/`let `/`const `/`document.`…) are
    // short and accumulate in English prose — a license that mentions "tablet"
    // and "outlet" hits `let ` twice (= THRESHOLD), and a README ending
    // sentences with "this document." scores too. Real JavaScript also carries
    // structural syntax: statement terminators and block braces. Require that
    // structure so keyword hits alone never type prose as JavaScript. (Only the
    // heuristic stage is gated — files with a real `.js` extension are resolved
    // earlier by extension and never reach here.)
    if lang == Lang::JavaScript {
        let has_structure = |b: &[u8]| b.iter().any(|&c| matches!(c, b';' | b'{' | b'}'));
        let tail = data.get(data.len().saturating_sub(TAIL_SIZE)..);
        let structured = has_structure(data.get(..SCAN_LIMIT).unwrap_or(data))
            || (is_mostly_whitespace(data, SCAN_LIMIT)
                && data.len() > SCAN_LIMIT
                && tail.is_some_and(has_structure))
            || after_leading_string_assignment(data)
                .is_some_and(|tail| has_structure(tail.get(..SCAN_LIMIT).unwrap_or(tail)));
        if !structured {
            return None;
        }
    }

    // A Dockerfile must begin with FROM (ARG may precede it). `\nFROM ` alone is
    // not enough: uppercase SQL puts `FROM` at the start of a line too, and a
    // `SELECT … FROM users` query would otherwise type as a Dockerfile.
    if lang == Lang::Dockerfile && !starts_with_dockerfile_instruction(data) {
        return None;
    }

    // PHP is tag-delimited: code only runs between `<?`/`<?php`/`<?=` and `?>`.
    // Without a tag there is no PHP, however many superglobals or WordPress hook
    // names the bytes contain — and those names are ordinary text elsewhere.
    // Detection rules, WAF patterns, changelogs, and log lines quote `$_POST`
    // without being PHP, and a YAML rule file whose regexes match PHP stagers
    // quotes little else. Requiring a delimiter keeps such references from
    // typing data as PHP, while still admitting the tagless fragments this table
    // targets: a fragment cut from a larger file loses its opening tag but keeps
    // the closing one.
    if lang == Lang::Php {
        let tail = data.get(data.len().saturating_sub(TAIL_SIZE)..);
        let tagged = has_php_tag(data.get(..SCAN_LIMIT * 2).unwrap_or(data))
            || (is_mostly_whitespace(data, SCAN_LIMIT)
                && data.len() > SCAN_LIMIT
                && tail.is_some_and(has_php_tag));
        if !tagged {
            return None;
        }
    }

    Some(lang.to_file_type())
}

/// Whether `runner_up` scores within [`AMBIGUOUS_PERCENT`] of `best`, which
/// must be non-zero. Widened first: a saturated score times 100 overflows
/// `u16`.
fn too_close(runner_up: u16, best: u16) -> bool {
    u32::from(runner_up) * 100 / u32::from(best) > AMBIGUOUS_PERCENT
}

/// PowerShell droppers sometimes conceal commands in a decimal byte array:
/// `$name = @(83,116,97,114,116,...)`. The ordinary keyword scorer cannot see
/// any of the commands until that array is decoded. This shape is distinctive
/// enough to disambiguate an otherwise ambiguous `.ps` suffix when no PostScript
/// header is present.
pub(super) fn has_powershell_char_code_array(data: &[u8]) -> bool {
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    let Some(start) = head.windows(2).position(|w| w == b"@(") else {
        return false;
    };
    // Require an assignment immediately before the array, allowing whitespace.
    let prefix = head.get(..start).unwrap_or_default();
    if prefix.iter().rev().find(|b| !b.is_ascii_whitespace()) != Some(&b'=') {
        return false;
    }

    let mut i = start + 2;
    let mut count = 0;
    loop {
        while head.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        let digits = i;
        let mut value = 0u16;
        while let Some(b @ b'0'..=b'9') = head.get(i).copied() {
            value = value * 10 + u16::from(b - b'0');
            if value > 255 {
                return false;
            }
            i += 1;
        }
        let width = i - digits;
        if width == 0 || width > 3 {
            return false;
        }
        count += 1;
        while head.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        match head.get(i) {
            Some(b',') => i += 1,
            Some(b')') => return count >= 8,
            _ => return false,
        }
    }
}

/// Only inputs at least this large are screened by [`looks_like_prose`]: a
/// tiny script (`echo hi`) can legitimately have no code punctuation at all,
/// and a mis-typed tiny file costs nothing to parse.
const PROSE_GUARD_MIN_BYTES: usize = 1024;

/// Bytes that appear in essentially every programming language and essentially
/// never in running prose: brackets, statement/assignment/comparison operators,
/// and the shell/comment sigils.
const CODE_PUNCT: &[u8] = b"{}[]();=<>$#@\\|&*";

fn is_code_punct(b: u8) -> bool {
    1u128
        .checked_shl(u32::from(b))
        .is_some_and(|bit| CODE_PUNCT_MASK & bit != 0)
}

/// [`CODE_PUNCT`] as a bitmask over ASCII: prose screening reads every byte of
/// the head, and a mask test is a shift where a slice search is a call. Every
/// mark is ASCII, so a byte above 0x7F shifts out and is never punctuation.
const CODE_PUNCT_MASK: u128 = {
    let mut mask = 0u128;
    let mut rest = CODE_PUNCT;
    while let [b, tail @ ..] = rest {
        mask |= 1 << *b;
        rest = tail;
    }
    mask
};

/// Return the source following a long, leading quoted assignment. The prefix
/// must be an identifier assignment, optionally introduced by a declaration.
/// Work is bounded and escaped quotes are skipped without decoding the string.
fn after_leading_string_assignment(body: &[u8]) -> Option<&[u8]> {
    let quote = body
        .iter()
        .take(256)
        .position(|b| matches!(b, b'\'' | b'"'))?;
    let prefix = std::str::from_utf8(body.get(..quote)?).ok()?.trim();
    let prefix = prefix.strip_suffix('=')?.trim_end();
    let fields: Vec<&str> = prefix.split_whitespace().collect();
    let name = match fields.as_slice() {
        [name] => *name,
        ["local" | "const" | "let" | "var", name] => *name,
        _ => return None,
    };
    if !name
        .bytes()
        .enumerate()
        .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        || name.is_empty()
    {
        return None;
    }
    let delimiter = *body.get(quote)?;
    let mut cursor = quote + 1;
    while cursor < body.len().min(ASSIGNMENT_SCAN_LIMIT) {
        match *body.get(cursor)? {
            b'\\' => cursor += 2,
            b if b == delimiter => {
                return (cursor > SCAN_LIMIT * 2)
                    .then(|| body.get(cursor + 1..))
                    .flatten();
            }
            _ => cursor += 1,
        }
    }
    None
}

/// Object code, not text in any encoding. UTF-16 text is mostly NULs and
/// would otherwise look the same; a BOM or a lane of NULs keeps that as text.
pub(super) fn binary_not_source(data: &[u8]) -> bool {
    let body = strip_utf8_bom(data);
    let head = body.get(..SCAN_LIMIT).unwrap_or(body);
    is_binary(head, Controls::Text) && !looks_like_utf16_text(head)
}

/// UTF-16 text, which the byte-oriented scorer cannot read. Content cannot
/// judge it, so the extension stays the word on it.
pub(super) fn is_utf16_text(data: &[u8]) -> bool {
    looks_like_utf16_text(data.get(..SCAN_LIMIT).unwrap_or(data))
}

fn looks_like_utf16_text(head: &[u8]) -> bool {
    head.starts_with(&[0xFF, 0xFE])
        || head.starts_with(&[0xFE, 0xFF])
        || utf16_lanes(head).is_some()
}

/// The byte order of UTF-16 text without a byte-order mark: `Some(true)` for
/// little-endian, whose ASCII leaves the odd bytes NUL.
fn utf16_lanes(head: &[u8]) -> Option<bool> {
    if head.len() < 64 {
        return None;
    }
    let pairs = head.len() / 2;
    let nul_even = head.iter().step_by(2).filter(|&&b| b == 0).count();
    let nul_odd = head.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    // One lane of NULs beside a lane of characters. A zero-filled header
    // (an Access database, a boot sector's padding) is NUL in both lanes and
    // is not text.
    let mostly = |n: usize| n * 5 > pairs * 4;
    let sparse = |n: usize| n * 5 < pairs;
    if mostly(nul_odd) && sparse(nul_even) {
        Some(true)
    } else if mostly(nul_even) && sparse(nul_odd) {
        Some(false)
    } else {
        None
    }
}

/// The text the scorers should read instead of `data`, when that differs:
/// UTF-16 narrowed to UTF-8, or a UTF-16 byte-order mark dropped from the
/// 8-bit text behind it. The mark in front of plain ASCII is a batch trick --
/// editors render the script as CJK, and cmd.exe runs it anyway.
///
/// Only what a scorer reads is narrowed: the first [`DECODE_HEAD`] and last
/// [`DECODE_TAIL`] bytes of text, joined by a line break when the file is
/// longer than both.
pub(super) fn decoded_text(data: &[u8]) -> Option<Cow<'_, [u8]>> {
    // UTF-16 spells a line of ASCII with a NUL in every other byte; text
    // without a byte-order mark or an early NUL is not UTF-16.
    if !matches!(data, [0xFF, 0xFE, ..] | [0xFE, 0xFF, ..])
        && memchr::memchr(0, data.get(..64).unwrap_or(data)).is_none()
    {
        return None;
    }
    let (bom, body) = match data {
        [0xFF, 0xFE, rest @ ..] => (Some(true), rest),
        [0xFE, 0xFF, rest @ ..] => (Some(false), rest),
        _ => (None, data),
    };
    let probe = body.get(..SCAN_LIMIT).unwrap_or(body);
    // UTF-16 spells ASCII with every other byte NUL. 8-bit text behind the
    // mark has next to none -- a stray one at the end is not an encoding.
    let nuls = probe.iter().filter(|&&b| b == 0).count();
    let little_endian = match (bom, utf16_lanes(probe)) {
        (_, Some(le)) => le,
        (Some(_), None) if nuls * 10 < probe.len() => return Some(Cow::Borrowed(body)),
        (Some(le), None) => le,
        (None, None) => return None,
    };
    let narrow = |units: &[u8]| {
        let units = units.as_chunks::<2>().0.iter().map(|&pair| {
            if little_endian {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        });
        char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
    };
    let (head_len, tail_len) = (2 * DECODE_HEAD, 2 * DECODE_TAIL);
    let text = match (body.get(..head_len), body.len().checked_sub(tail_len)) {
        (Some(head), Some(tail_start)) if tail_start > head_len => {
            // Code units start at even offsets.
            let tail = body.get(tail_start & !1..).unwrap_or_default();
            let mut text = narrow(head);
            text.push('\n');
            text.push_str(&narrow(tail));
            text
        }
        _ => narrow(body),
    };
    Some(Cow::Owned(text.into_bytes()))
}

/// Whether `ft` is a language the table scores and the head of the body
/// carries not one of its tokens. `false` for a language the table does not
/// score, which cannot be shown absent.
pub(super) fn lacks_language_evidence(ft: FileType, sniff: &Sniff<'_>) -> bool {
    Lang::from_file_type(ft).is_some_and(|lang| lang.score(sniff.head_scores()) == 0)
}

/// Whether the body carries any scored token of `ft`'s language. `false` for a
/// language the table does not score.
pub(super) fn has_language_evidence(ft: FileType, sniff: &Sniff<'_>) -> bool {
    Lang::from_file_type(ft).is_some_and(|lang| lang.score(sniff.head_scores()) > 0)
}

/// C statement structure: statements ended with `;` alongside braces, a C
/// comment, or a preprocessor line. Objective-C is a superset of C, so a `.m`
/// holding plain C (`int main(...) { GoFunc(); }`) is still what its name says;
/// a MATLAB script, a hosts file, or a batch file under the same letter is not.
pub(super) fn looks_like_c_family(data: &[u8]) -> bool {
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    let statement_end = head
        .split(|&b| b == b'\n')
        .any(|line| line.trim_ascii_end().ends_with(b";"));
    statement_end
        && (head.contains(&b'{')
            || contains(head, b"/*")
            || contains(head, b"//")
            || head
                .split(|&b| b == b'\n')
                .any(|l| l.trim_ascii_start().first() == Some(&b'#')))
}

/// Content that contradicts a source-language extension, and what it is
/// instead. The extension is the last word, not the first: a batch file named
/// `.t` is batch whatever Perl's `.t` says, and a page named `.ko` is a page.
/// Three ways to be contradicted:
///
/// * the line grammars read batch, VBScript, mIRC or ircII plainly and find
///   no line of the claimed language -- a `.vbs` that is obfuscated batch, a
///   `.bat` that is VBScript, a `.mrc` holding an ircII script;
/// * the body opens as markup, which no source language (bar the template
///   ones, which stay with their extension) begins with;
/// * the scorer names batch or VBScript outright and finds not one token of
///   the claimed language. Only those two: their conclusive tokens (`@echo`,
///   `WScript.`) occur nowhere else, while a weaker win -- JavaScript over an
///   nmap `.lua` library, Kotlin over a venv's `Activate.ps1` -- is the token
///   fight the extension exists to settle. A claimed language the table does
///   not score cannot be judged this way, so its extension stands.
pub(super) fn contradicts_extension(ext: FileType, sniff: &Sniff<'_>) -> Option<FileType> {
    // Template languages open with markup by design, and Scala has XML
    // literals; their extensions stand.
    if matches!(
        ext,
        FileType::Php
            | FileType::Asp
            | FileType::Jsp
            | FileType::Cfml
            | FileType::Html
            | FileType::Scala
    ) {
        return None;
    }
    let text = sniff.text();
    let body = text.trim_ascii_start();
    let scores = sniff.head_scores();
    // Ahead of the markup check: a batch file may open `<!-- :` to double as
    // the WSF or HTA it carries further down.
    let script = sniff.evidence();
    if let Some(found) = script.verdict() {
        let claimed = Lang::from_file_type(ext);
        if found == ext || script.supports(ext) || claimed.is_some_and(|l| l.score(scores) > 0) {
            return None;
        }
        // The name stands unless the body outweighs it. One command line does
        // not: `msiexec /i URL` is as much PowerShell as batch. A name whose
        // language nothing here reads (Elixir, Go) cannot be shown absent, so
        // only a run of lines overrides it -- `@echo off` alone is also an
        // Elixir module attribute.
        let tokens_agree = claimed.is_some()
            && Lang::from_file_type(found).is_some_and(|l| l.score(scores) >= THRESHOLD);
        return (script.conclusive(found) || tokens_agree).then_some(found);
    }
    if body.first() == Some(&b'<') && looks_like_html(text) {
        return Some(FileType::Html);
    }
    let claimed = Lang::from_file_type(ext)?;
    // Only batch or VBScript can contradict a name this way, and the scorer
    // names neither without its tokens in the head. Most source files stop
    // here instead of being scored in full.
    if Lang::Batch.score(scores) < THRESHOLD && Lang::Vbs.score(scores) < THRESHOLD {
        return None;
    }
    let found = sniff.scored_type()?;
    if found == ext || !matches!(found, FileType::Batch | FileType::Vbs) {
        return None;
    }
    (claimed.score(scores) == 0).then_some(found)
}

/// True when `head` reads like natural-language text rather than source.
///
/// Measured on the first 4 KiB: prose (novels, licenses) has 0.15-0.3% code
/// punctuation with ~4% of lines carrying any; minified JS 6.5% / 93%, Rust
/// 3.5% / 58%, a Makefile 4.1% / 91%, and even a Markdown README with embedded
/// snippets 2.8% / 30%. Both thresholds sit well inside that gap, and both must
/// hold — a file has to look like prose on the byte *and* the line axis.
fn looks_like_prose(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    let punct = head.iter().filter(|&&b| is_code_punct(b)).count();
    let mut lines = 0usize;
    let mut code_lines = 0usize;
    for line in head.split(|&b| b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        lines += 1;
        if line.iter().any(|&b| is_code_punct(b)) {
            code_lines += 1;
        }
    }
    if lines == 0 {
        return false;
    }
    punct * 100 < head.len() && code_lines * 100 < lines * 15
}

/// A conservative sectioned key/value document, such as an extensionless
/// desktop configuration. Every significant line must fit the format.
fn looks_like_ini_config(data: &[u8]) -> bool {
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    if head.starts_with(b"#!") || is_binary(head, Controls::Text) {
        return false;
    }
    let mut sections = 0usize;
    let mut fields = 0usize;
    let mut lines = head.split(|&b| b == b'\n').peekable();
    while let Some(line) = lines.next() {
        if lines.peek().is_none() && head.len() == SCAN_LIMIT {
            break;
        }
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            continue;
        }
        if let Some(name) = line.strip_prefix(b"[").and_then(|s| s.strip_suffix(b"]")) {
            if name.is_empty()
                || !name
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || b"_./: -".contains(c))
            {
                return false;
            }
            sections += 1;
            continue;
        }
        let Some((key, _)) = line
            .iter()
            .position(|&b| b == b'=')
            .map(|i| line.split_at(i))
        else {
            return false;
        };
        let key = key.trim_ascii();
        if sections == 0
            || key.is_empty()
            || !key
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
        {
            return false;
        }
        fields += 1;
    }
    sections >= 2 && fields >= 3
}

/// JSON containers, YAML mappings, and RFC822 stanzas are data even when
/// their values quote programming-language tokens.
fn looks_like_structured_data(data: &[u8]) -> bool {
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    // A shebang names an interpreter: that is a script, whatever follows.
    if head.starts_with(b"#!") {
        return false;
    }
    let body = head.trim_ascii_start();
    // JSON: opens a container and carries at least one quoted key.
    if (body.starts_with(b"{") || body.starts_with(b"["))
        && memchr::memmem::find(body, b"\":").is_some()
    {
        return true;
    }
    // YAML: block mappings and sequence entries dominate the significant lines.
    // A trailing partial line from the scan cut is dropped rather than judged.
    let mut lines = head.split(|&b| b == b'\n').peekable();
    let mut significant = 0usize;
    let mut structured = 0usize;
    while let Some(line) = lines.next() {
        if lines.peek().is_none() && head.len() == SCAN_LIMIT {
            break;
        }
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        significant += 1;
        if is_yaml_node_line(line) {
            structured += 1;
        }
    }
    if significant >= MIN_YAML_LINES && structured * 10 >= significant * 7 {
        return true;
    }

    looks_like_rfc822_stanzas(head)
}

/// `true` for an RFC822/deb822 stanza document: `Field-Name: value` lines whose
/// continuations are folded onto following lines that begin with a space.
///
/// Debian's `control`, APT's `Packages`/`Sources` and its `Translation-*`
/// description catalogues are all this shape, and the folded continuations are
/// free English prose -- which is why the YAML check above cannot see them: a
/// wrapped sentence is not a node line, so the ratio collapses even though
/// every field line is structured. APT's `Translation-en` is 32 MB of package
/// descriptions, and "This package contains…" occurring six times in the first
/// 4 KB was enough to type the whole catalogue as Kotlin and run credential
/// rules over English sentences.
fn looks_like_rfc822_stanzas(head: &[u8]) -> bool {
    let mut lines = head.split(|&b| b == b'\n').peekable();
    let mut fields = 0usize;
    let mut folded = 0usize;
    let mut other = 0usize;
    let mut first_significant_is_field = false;
    let mut seen_significant = false;

    while let Some(line) = lines.next() {
        // Drop the trailing partial line left by the scan cut rather than judge it.
        if lines.peek().is_none() && head.len() == SCAN_LIMIT {
            break;
        }
        if line.trim_ascii().is_empty() {
            continue;
        }
        // A folded continuation belongs to the field above it, so it is not
        // evidence either way -- but it only counts as one after a field.
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if fields > 0 {
                folded += 1;
                continue;
            }
            other += 1;
            continue;
        }
        let is_field = is_rfc822_field_line(line);
        if !seen_significant {
            seen_significant = true;
            first_significant_is_field = is_field;
        }
        if is_field {
            fields += 1;
        } else {
            other += 1;
        }
    }

    // Every unfolded line must be a field, the document must open with one, and
    // there must be enough of them to be a stanza rather than a stray `Note:`.
    first_significant_is_field && other == 0 && fields >= MIN_YAML_LINES && folded > 0
}

/// `true` for `Field-Name: value` with an RFC822 field name -- printable ASCII
/// without spaces or a colon. Rejects a Kotlin `package a.b` (no colon), a C
/// label (no value) and a prose line containing a mid-sentence colon.
fn is_rfc822_field_line(line: &[u8]) -> bool {
    let Some((name, value)) = line
        .iter()
        .position(|&b| b == b':')
        .and_then(|end| line.split_at_checked(end))
    else {
        return false;
    };
    if name.is_empty()
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return false;
    }
    // `value` opens with the colon itself.
    matches!(value.get(1), None | Some(b' ') | Some(b'\r'))
}

/// `true` for a line that opens a YAML sequence entry, a block mapping key, or
/// a document marker. Keys are matched by shape (`name:` followed by end of line
/// or a space), which is what separates `regex: \$_POST` from PHP's `$_POST`.
fn is_yaml_node_line(line: &[u8]) -> bool {
    if line == b"---" || line == b"..." || line.starts_with(b"--- ") {
        return true;
    }
    if line == b"-" || line.starts_with(b"- ") {
        return true;
    }
    // A sequence entry may carry its first mapping key: `- id: value`.
    let key = line.strip_prefix(b"- ").unwrap_or(line).trim_ascii_start();
    let end = key
        .iter()
        .position(|b| !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'/' | b'"' | b'\''))
        .unwrap_or(key.len());
    end > 0 && key.get(end) == Some(&b':') && matches!(key.get(end + 1), None | Some(b' '))
}

/// `true` when the first instruction of the document is `FROM` or `ARG`, the
/// only two a Dockerfile may open with. Comments, blank lines, and a leading
/// parser directive are skipped, matching what the builder accepts.
fn starts_with_dockerfile_instruction(data: &[u8]) -> bool {
    for line in data
        .get(..SCAN_LIMIT)
        .unwrap_or(data)
        .split(|&b| b == b'\n')
    {
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let word = line.split(u8::is_ascii_whitespace).next().unwrap_or(line);
        return word.eq_ignore_ascii_case(b"FROM") || word.eq_ignore_ascii_case(b"ARG");
    }
    false
}

/// `true` when the bytes carry a PHP tag delimiter — an opening `<?`, `<?php`,
/// or `<?=`, or the `?>` that closes a fragment whose opening tag was cut off.
/// `<?xml …?>` is an XML processing instruction and never counts on its own.
fn has_php_tag(data: &[u8]) -> bool {
    let mut saw_non_php_open = false;
    let mut rest = data;
    while let Some(pos) = memchr::memmem::find(rest, b"<?") {
        let Some(after) = rest.get(pos + 2..) else {
            break;
        };
        let bound = after.trim_ascii_start();
        // Java wildcard bounds in API signature catalogs are not PHP short
        // tags. Nor is Class<?>: its question mark is generic type syntax.
        // These cannot begin valid PHP statements. Continue searching so a
        // genuine tag later in a mixed file still establishes PHP content.
        let java_wildcard = after.starts_with(b">")
            || (after.first().is_some_and(u8::is_ascii_whitespace)
                && [b"extends".as_slice(), b"super".as_slice()]
                    .iter()
                    .any(|keyword| {
                        bound.starts_with(keyword)
                            && bound.get(keyword.len()).is_some_and(u8::is_ascii_whitespace)
                    }));
        if after
            .get(..3)
            .is_some_and(|pi| pi.eq_ignore_ascii_case(b"xml"))
            || java_wildcard
        {
            saw_non_php_open = true;
        } else {
            return true;
        }
        rest = after;
    }
    !saw_non_php_open && memchr::memmem::find(data, b"?>").is_some()
}

/// Tags that only markup carries. Static like [`SCANNER`]'s patterns, so a
/// build failure is a bug here: it panics rather than calling nothing HTML.
static HTML_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([
            "<!doctype html",
            "<html",
            "<head",
            "<body",
            "<script",
            "<div",
            "<span",
            "<p>",
            "<meta",
        ])
        .expect("HTML tags are a valid Aho-Corasick set")
});

/// Check if content looks like HTML (has actual markup tags).
/// Extension corroboration must inspect the entire body: HTML applications
/// can put arbitrarily long script or padding before their first markup tag.
/// The matcher stops at the first tag, so ordinary documents remain cheap.
pub(super) fn looks_like_html(data: &[u8]) -> bool {
    HTML_AC.is_match(data)
}

#[cfg(test)]
mod tests;
