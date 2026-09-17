//! Lightweight content heuristics for files where neither magic bytes nor
//! extension gave a result.
//!
//! Uses a single Aho-Corasick automaton (built once, cached in a `OnceLock`)
//! to scan the file prefix in one pass. Pattern hits are bucketed by language
//! and scored. This replaces ~80 independent `memmem::find` calls with a
//! single linear scan.
//!
//! Pattern selection: only high-signal patterns (weight >= 5) are included.
//! Each language has at least one conclusive (weight=10) pattern and 2-3
//! supporting patterns. This keeps the automaton small and cache-friendly.

use std::sync::OnceLock;

use super::FileType;

/// Minimum bytes of non-whitespace content required before we trust heuristics.
const MIN_CONTENT_BYTES: usize = 16;

/// Maximum bytes to scan for heuristics.
const SCAN_LIMIT: usize = 4096;

/// How many bytes from the end to check when the head is mostly whitespace.
const TAIL_SIZE: usize = 2048;

/// Minimum score to consider a language match.
const THRESHOLD: u16 = 10;

/// Significant lines a document needs before its shape is judged as YAML. Short
/// fragments carry too little structure to separate a mapping from prose.
const MIN_YAML_LINES: usize = 5;

#[derive(Clone, Copy)]
struct PatternEntry {
    lang: Lang,
    weight: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lang {
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
}

/// All languages in index order. Used to map score indices back to Lang values
/// without unsafe transmute.
const LANGS: [Lang; 14] = [
    Lang::Shell,
    Lang::Python,
    Lang::PowerShell,
    Lang::Perl,
    Lang::Php,
    Lang::Batch,
    Lang::Vbs,
    Lang::Lua,
    Lang::JavaScript,
    Lang::C,
    Lang::Kotlin,
    Lang::Dockerfile,
    Lang::Clojure,
    Lang::AppleScript,
];

const LANG_COUNT: usize = LANGS.len();

impl Lang {
    /// Index into the scores array.
    const fn idx(self) -> usize {
        match self {
            Self::Shell => 0,
            Self::Python => 1,
            Self::PowerShell => 2,
            Self::Perl => 3,
            Self::Php => 4,
            Self::Batch => 5,
            Self::Vbs => 6,
            Self::Lua => 7,
            Self::JavaScript => 8,
            Self::C => 9,
            Self::Kotlin => 10,
            Self::Dockerfile => 11,
            Self::Clojure => 12,
            Self::AppleScript => 13,
        }
    }

    fn to_file_type(self) -> FileType {
        match self {
            Self::Shell => FileType::Shell,
            Self::Python => FileType::Python,
            Self::PowerShell => FileType::PowerShell,
            Self::Perl => FileType::Perl,
            Self::Php => FileType::Php,
            Self::Batch => FileType::Batch,
            Self::Vbs => FileType::Vbs,
            Self::Lua => FileType::Lua,
            Self::JavaScript => FileType::JavaScript,
            Self::C => FileType::C,
            Self::Kotlin => FileType::Kotlin,
            Self::Dockerfile => FileType::Dockerfile,
            Self::Clojure => FileType::Clojure,
            Self::AppleScript => FileType::AppleScript,
        }
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
    (b"; do\n", Lang::Shell, 5),
    (b" && curl ", Lang::Shell, 10),
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
    // ── Perl ──
    (b"use strict;", Lang::Perl, 10),
    (b"use warnings;", Lang::Perl, 10),
    (b"use strict\n", Lang::Perl, 10),
    (b"use warnings\n", Lang::Perl, 10),
    (b"my $", Lang::Perl, 5),
    (b"chomp", Lang::Perl, 5),
    // ── PHP ──
    // Some malware corpora contain PHP fragments or PHP+HTML hybrids without a
    // leading `<?php` tag. Score PHP-specific globals and WordPress hook idioms
    // so `elseif ` in those files does not incorrectly win as Lua.
    (b"<?php", Lang::Php, 10),
    (b"$_SERVER", Lang::Php, 10),
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
    (b"#?(:clj", Lang::Clojure, 10),
    (b"#?(:cljs", Lang::Clojure, 10),
    (b"(let [", Lang::Clojure, 5),
    (b"(if-let [", Lang::Clojure, 5),
    (b"(when-let [", Lang::Clojure, 5),
    (b"(fn [", Lang::Clojure, 5),
    (b"#'", Lang::Clojure, 5),
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
];

struct AcScanner {
    ac: Option<aho_corasick::AhoCorasick>,
    entries: Vec<PatternEntry>,
}

fn build_scanner() -> AcScanner {
    let patterns: Vec<&[u8]> = PATTERNS.iter().map(|(p, _, _)| *p).collect();
    let ac = aho_corasick::AhoCorasick::builder().build(&patterns).ok();
    let entries: Vec<PatternEntry> = PATTERNS
        .iter()
        .map(|(_, lang, weight)| PatternEntry {
            lang: *lang,
            weight: *weight,
        })
        .collect();
    AcScanner { ac, entries }
}

fn scanner() -> &'static AcScanner {
    static SCANNER: OnceLock<AcScanner> = OnceLock::new();
    SCANNER.get_or_init(build_scanner)
}

/// Check if the first `limit` bytes are mostly whitespace.
fn is_mostly_whitespace(data: &[u8], limit: usize) -> bool {
    let head = &data[..data.len().min(limit)];
    let non_ws = head.iter().filter(|&&b| !b.is_ascii_whitespace()).count();
    non_ws < MIN_CONTENT_BYTES
}

/// Single-pass scan using Aho-Corasick. Returns per-language scores.
fn scan_scores(data: &[u8]) -> [u16; LANG_COUNT] {
    let s = scanner();
    let mut scores = [0u16; LANG_COUNT];

    if let Some(ac) = &s.ac {
        for mat in ac.find_overlapping_iter(data) {
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
            let entry = &s.entries[mat.pattern().as_usize()];
            let idx = entry.lang.idx();
            scores[idx] = scores[idx].saturating_add(u16::from(entry.weight));
        }
    }

    scores
}

/// Try to identify a file type from content patterns.
/// Only called when magic bytes and extension both failed.
pub(crate) fn detect_from_content(data: &[u8]) -> Option<FileType> {
    if data.len() < 4 {
        return None;
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

    let lang = best_lang?;

    // Must meet threshold
    if best_score < THRESHOLD {
        return None;
    }

    // Ambiguity: if the second-best is close (within 60%), bail
    if second_score > 0 && second_score * 100 / best_score > 60 {
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
        let tagged = has_php_tag(&data[..data.len().min(SCAN_LIMIT)])
            || (is_mostly_whitespace(data, SCAN_LIMIT)
                && data.len() > SCAN_LIMIT
                && has_php_tag(&data[data.len().saturating_sub(TAIL_SIZE)..]));
        if !tagged {
            return None;
        }
    }

    Some(lang.to_file_type())
}

/// First offset of `needle` in `haystack`.
/// Only inputs at least this large are screened by [`looks_like_prose`]: a
/// tiny script (`echo hi`) can legitimately have no code punctuation at all,
/// and a mis-typed tiny file costs nothing to parse.
const PROSE_GUARD_MIN_BYTES: usize = 1024;

/// Bytes that appear in essentially every programming language and essentially
/// never in running prose: brackets, statement/assignment/comparison operators,
/// and the shell/comment sigils.
const CODE_PUNCT: &[u8] = b"{}[]();=<>$#@\\|&*";

/// True when `head` reads like natural-language text rather than source.
///
/// Measured on the first 4 KiB: prose (novels, licenses) has 0.15-0.3% code
/// punctuation with ~4% of lines carrying any; minified JS 6.5% / 93%, Rust
/// 3.5% / 58%, a Makefile 4.1% / 91%, and even a Markdown README with embedded
/// snippets 2.8% / 30%. Both thresholds sit well inside that gap, and both must
/// hold — a file has to look like prose on the byte *and* the line axis.
/// `true` when the window carries enough control bytes that it cannot be one
/// of the scored languages.
///
/// Control bytes are the tell, not high bytes: bytes >= 0x80 are ordinary in
/// UTF-8 source and Latin-1 comments, while source essentially never contains
/// a byte below 0x20 that is not tab, newline or carriage return. Object code
/// is full of them -- the DOS sample that prompted this sits at 14% -- so a
/// small threshold separates the two decisively without judging encodings.
fn looks_like_binary(head: &[u8]) -> bool {
    const MIN_BYTES: usize = 64;
    const MAX_CONTROL_PERCENT: usize = 3;
    if head.len() < MIN_BYTES {
        return false;
    }
    let control = head
        .iter()
        .filter(|&&b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')) || b == 0x7F)
        .count();
    control * 100 > head.len() * MAX_CONTROL_PERCENT
}

fn looks_like_prose(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    let punct = head.iter().filter(|b| CODE_PUNCT.contains(b)).count();
    let mut lines = 0usize;
    let mut code_lines = 0usize;
    for line in head.split(|&b| b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        lines += 1;
        if line.iter().any(|b| CODE_PUNCT.contains(b)) {
            code_lines += 1;
        }
    }
    if lines == 0 {
        return false;
    }
    punct * 100 < head.len() && code_lines * 100 < lines * 15
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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
    if (body.starts_with(b"{") || body.starts_with(b"[")) && find(body, b"\":").is_some() {
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
    while let Some(pos) = find(&data[offset..], b"<?") {
        let after = offset + pos + 2;
        if data[after..].len() >= 3 && data[after..after + 3].eq_ignore_ascii_case(b"xml") {
            saw_xml_pi = true;
        } else {
            return true;
        }
        offset = after;
    }
    !saw_xml_pi && find(data, b"?>").is_some()
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

/// Check if content looks like HTML (has actual markup tags).
pub(crate) fn looks_like_html(data: &[u8]) -> bool {
    static HTML_AC: OnceLock<Option<aho_corasick::AhoCorasick>> = OnceLock::new();
    let ac = HTML_AC.get_or_init(|| {
        aho_corasick::AhoCorasick::builder()
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
            .ok()
    });

    let head = &data[..data.len().min(HTML_SCAN_WINDOW)];
    ac.as_ref().is_some_and(|ac| ac.is_match(head))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
