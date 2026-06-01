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
    Batch,
    Vbs,
    Lua,
    JavaScript,
    C,
    Kotlin,
    Dockerfile,
    Clojure,
}

/// All languages in index order. Used to map score indices back to Lang values
/// without unsafe transmute.
const LANGS: [Lang; 12] = [
    Lang::Shell,
    Lang::Python,
    Lang::PowerShell,
    Lang::Perl,
    Lang::Batch,
    Lang::Vbs,
    Lang::Lua,
    Lang::JavaScript,
    Lang::C,
    Lang::Kotlin,
    Lang::Dockerfile,
    Lang::Clojure,
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
            Self::Batch => 4,
            Self::Vbs => 5,
            Self::Lua => 6,
            Self::JavaScript => 7,
            Self::C => 8,
            Self::Kotlin => 9,
            Self::Dockerfile => 10,
            Self::Clojure => 11,
        }
    }

    fn to_file_type(self) -> FileType {
        match self {
            Self::Shell => FileType::Shell,
            Self::Python => FileType::Python,
            Self::PowerShell => FileType::PowerShell,
            Self::Perl => FileType::Perl,
            Self::Batch => FileType::Batch,
            Self::Vbs => FileType::Vbs,
            Self::Lua => FileType::Lua,
            Self::JavaScript => FileType::JavaScript,
            Self::C => FileType::C,
            Self::Kotlin => FileType::Kotlin,
            Self::Dockerfile => FileType::Dockerfile,
            Self::Clojure => FileType::Clojure,
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
    (b"xattr -c ", Lang::Shell, 5),
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
    // ── Batch ──
    (b"@echo", Lang::Batch, 10),
    (b"@ECHO", Lang::Batch, 10),
    (b"%~dp0", Lang::Batch, 10),
    (b"SETLOCAL", Lang::Batch, 5),
    (b"GOTO ", Lang::Batch, 5),
    (b"IF EXIST", Lang::Batch, 5),
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
    (b"console.", Lang::JavaScript, 5),
    (b"document.", Lang::JavaScript, 5),
    (b"window.", Lang::JavaScript, 5),
    (b"addEventListener", Lang::JavaScript, 5),
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

    let head = &data[..data.len().min(SCAN_LIMIT)];

    // If the head is mostly whitespace, also scan the tail
    let scores = if is_mostly_whitespace(data, SCAN_LIMIT) && data.len() > SCAN_LIMIT {
        let tail_start = data.len().saturating_sub(TAIL_SIZE);
        let tail = &data[tail_start..];
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

    Some(lang.to_file_type())
}

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

    let head = &data[..data.len().min(4096)];
    ac.as_ref().is_some_and(|ac| ac.is_match(head))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
