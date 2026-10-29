//! Line grammars for batch, VBScript, mIRC and ircII.
//!
//! All four are line-oriented: a statement announces its language in the first
//! word or two of its line. The weighted token table in `heuristics` counts a
//! token wherever it occurs, so it cannot tell a language from text that quotes
//! it -- a VBScript that writes `@echo off` into the batch file it drops scored
//! as batch, a makefile recipe's `@echo` as batch, and JScript's
//! `new ActiveXObject("WScript.Shell")` as VBScript. Reading each line the way
//! its interpreter would, verb first, separates the language from its strings.
//!
//! Every line is graded for each language: `Strong` when the line is written in
//! a form only that language uses, `Weak` when it is merely consistent with it.
//! A verdict needs strong lines, has to cover a fair share of the file, and has
//! to outscore the other three by a wide margin.

use super::{
    FileType,
    sniff::Sniff,
    text::{Controls, contains, contains_ci, find_ci, starts_ci},
};

/// How much text the grammars read. Droppers pad themselves with junk lines,
/// so this is wider than the token scorer's window.
pub(super) const WINDOW: usize = 32 * 1024;

/// Significant lines at the top of a file in which a batch prologue is read.
const LEAD_LINES: u32 = 12;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Grade {
    None,
    Weak,
    Strong,
}

#[derive(Clone, Copy, Default, Debug)]
struct Tally {
    strong: u32,
    weak: u32,
    /// Lines no program in this language could contain: braces, `;`
    /// terminators, `#` comments, another language's block closers.
    foreign: u32,
}

impl Tally {
    fn add(&mut self, grade: Grade) {
        match grade {
            Grade::Strong => self.strong += 1,
            Grade::Weak => self.weak += 1,
            Grade::None => {}
        }
    }

    fn score(self) -> u32 {
        self.strong * 3 + self.weak
    }

    fn covered(self) -> u32 {
        self.strong + self.weak
    }
}

/// What the four grammars found in a text.
#[derive(Default, Debug)]
pub(super) struct Evidence {
    batch: Tally,
    vbs: Tally,
    mirc: Tally,
    ircii: Tally,
    /// Non-blank lines read.
    lines: u32,
    /// The first line is one only a batch file opens with.
    batch_opener: bool,
    /// Strong batch lines among the first [`LEAD_LINES`].
    batch_lead: u32,
    /// A `<% ... %>` server block, which makes VBScript an ASP page.
    server_block: bool,
    /// Page markup opened before the first VBScript statement: the script is
    /// a block in a page, not a `.vbs`.
    page_first: bool,
    /// The window reads as object code: control bytes a text file never has.
    binary: bool,
    /// Byte offset of the first strong batch line.
    batch_first_strong: Option<usize>,
}

impl Evidence {
    /// Whether any line is written in a form only `ft` uses. `false` for a
    /// language these grammars do not read.
    pub(super) fn supports(&self, ft: FileType) -> bool {
        self.tally(ft).is_some_and(|t| t.strong > 0)
    }

    /// Whether the lines argue against `ft`: more of them are written in
    /// shapes it cannot have than in its own.
    pub(super) fn rules_out(&self, ft: FileType) -> bool {
        self.tally(ft)
            .is_some_and(|t| t.foreign > 0 && t.foreign * 2 > t.covered())
    }

    /// Whether the text had lines to judge. A file with no line breaks gives
    /// the grammars one line of everything, which says nothing either way.
    pub(super) fn has_lines(&self) -> bool {
        self.lines >= 2
    }

    /// Whether `ft` has enough strong lines to stand against a name that
    /// claims a language nothing here can read. A lone `@echo off` is also
    /// an Elixir module attribute.
    pub(super) fn conclusive(&self, ft: FileType) -> bool {
        self.tally(ft).is_some_and(|t| t.strong >= 3)
    }

    /// The most lines any one grammar has read as its own.
    fn max_covered(&self) -> u32 {
        [self.batch, self.vbs, self.mirc, self.ircii]
            .iter()
            .map(|t| t.covered())
            .max()
            .unwrap_or(0)
    }

    fn tally(&self, ft: FileType) -> Option<Tally> {
        match ft {
            FileType::Batch => Some(self.batch),
            FileType::Vbs | FileType::Asp | FileType::Html => Some(self.vbs),
            FileType::Mirc => Some(self.mirc),
            FileType::IrcII => Some(self.ircii),
            _ => None,
        }
    }

    /// The language the text is written in, when the lines say so plainly.
    pub(super) fn verdict(&self) -> Option<FileType> {
        // A DOS program carries the batch file it drops as data, somewhere in
        // the middle. A BAT/COM hybrid has to put its batch lines at the top,
        // where cmd.exe starts reading.
        if self.binary {
            let hybrid =
                self.batch.strong >= 2 && self.batch_first_strong.is_some_and(|at| at < 64);
            return hybrid.then_some(FileType::Batch);
        }
        // Polyglots put their batch half first because cmd.exe runs top-down:
        // `@if (@X)==(@Y) @end /*` JScript hybrids, `<!-- :` WSF/HTA hybrids,
        // `<# :` PowerShell hybrids. Whatever follows is data to cmd.exe, and
        // the file only works under a batch name.
        if self.batch_opener && self.batch_lead >= 2 {
            return Some(FileType::Batch);
        }
        let langs = [
            (FileType::Batch, self.batch),
            (FileType::Vbs, self.vbs),
            (FileType::Mirc, self.mirc),
            (FileType::IrcII, self.ircii),
        ];
        let (ft, best) = langs.iter().copied().max_by_key(|(_, t)| t.score())?;
        // Only a language with a line of its own is a contender; syntax the
        // languages share (mIRC's and ircII's `if ($1 == x)`, batch's and
        // VBScript's `rem`) weighs for all of them equally.
        let runner_up = langs
            .iter()
            .filter(|(other, t)| *other != ft && t.strong > 0)
            .map(|(_, t)| t.score())
            .max()
            .unwrap_or(0);
        // A one-liner (`MsgBox "hi"`, `on *:TEXT:*:#:{`) has room for one line.
        let strong_needed = if self.lines <= 3 { 1 } else { 2 };
        if best.strong < strong_needed || runner_up * 2 >= best.score() {
            return None;
        }
        // The language has to be the file, not a few lines quoted in it. A long
        // run of strong lines may sit beside an encoded payload blob.
        let covered = best.covered();
        let share = covered * 100 / self.lines;
        if share < 25 && !(best.strong >= 10 && share >= 10) {
            return None;
        }
        if best.foreign * 2 > covered {
            return None;
        }
        if ft == FileType::Vbs && self.server_block {
            return Some(FileType::Asp);
        }
        if ft == FileType::Vbs && self.page_first {
            return Some(FileType::Html);
        }
        Some(ft)
    }
}

/// Binary batch polyglots must keep their command prologue at source entry.
/// The same content evidence applies even when a registered extension would
/// otherwise bypass the script scorer and fall back to DOS object code.
pub(super) fn binary_batch_prologue(sniff: &Sniff<'_>) -> bool {
    let first = sniff
        .data
        .split(|b| *b == b'\r' || *b == b'\n')
        .find(|line| !line.trim_ascii().is_empty())
        .unwrap_or_default();
    batch_opener(first) && sniff.evidence().verdict() == Some(FileType::Batch)
}

/// A bare HTML opener followed by REM and a batch body is a DOS-script
/// prologue, not a page containing a script example. Keep actual markup
/// documents in the HTML parser. This does not assert browser activation.
pub(super) fn html_prefixed_batch(data: &[u8]) -> bool {
    let data = data.trim_ascii_start();
    let mut lines = data.splitn(2, |b| *b == b'\n');
    let first = lines.next().unwrap_or_default();
    let Some(rest) = lines.next() else {
        return false;
    };
    let Some((tag, after_html)) = first.split_at_checked(6) else {
        return false;
    };
    if !tag.eq_ignore_ascii_case(b"<html>") {
        return false;
    }
    let after_html = after_html.trim_ascii_start();
    if !after_html
        .get(..3)
        .is_some_and(|word| word.eq_ignore_ascii_case(b"rem"))
        || !after_html.get(3).is_some_and(u8::is_ascii_whitespace)
    {
        return false;
    }
    let body = rest.get(..WINDOW).unwrap_or(rest);
    if body.split(|b| *b == b'\n').any(|line| {
        let line = line.trim_ascii_start();
        line.starts_with(b"<") && line.contains(&b'>')
    }) {
        return false;
    }
    let ev = evidence(body);
    ev.conclusive(FileType::Batch) && ev.verdict() == Some(FileType::Batch)
}

/// Grade the lines of `text` for all four languages: [`WINDOW`] bytes from
/// the top, and as much from the end when the top settles nothing.
pub(super) fn evidence(text: &[u8]) -> Evidence {
    let text = skip_padding(text);
    let head = text.get(..WINDOW).unwrap_or(text);
    let mut ev = Evidence::default();
    ev.read(head, true);
    // Droppers bury their code under a payload or thousands of junk lines;
    // what they run is often at the end. The tail only speaks when the head
    // could not: a clear opening is not outvoted by a megabyte of payload.
    // A tail with no line break starts at an arbitrary byte of a line the head
    // already opened, not at a line start: it can begin inside a string and
    // invert the quote tracking, and one strong line decides a file of three
    // lines or fewer.
    if text.len() > 2 * WINDOW && ev.verdict().is_none() {
        let tail = text
            .get(text.len().saturating_sub(WINDOW)..)
            .unwrap_or_default();
        if let Some(after) = memchr::memchr2(b'\n', b'\r', tail).and_then(|at| tail.get(at + 1..)) {
            ev.read(after, false);
        }
    }
    ev
}

/// `text` past its leading blank lines and lines of bare `:` -- empty
/// statements to VBScript, empty labels to cmd.exe, and a favourite padding
/// of obfuscators, who emit them by the hundred thousand.
fn skip_padding(text: &[u8]) -> &[u8] {
    let mut rest = text;
    while !rest.is_empty() {
        let end = memchr::memchr(b'\n', rest).map_or(rest.len(), |n| n + 1);
        let (line, after) = rest.split_at_checked(end).unwrap_or((rest, &[]));
        if !line.iter().all(|&b| b == b':' || b.is_ascii_whitespace()) {
            break;
        }
        rest = after;
    }
    rest
}

impl Evidence {
    /// Grade one window's lines into the tallies. Only the head window says
    /// how the file opens.
    fn read(&mut self, window: &[u8], head: bool) {
        let spaced = ascii_spaces(window);
        let window = &spaced[..];
        if head {
            self.binary = super::text::is_binary(window, Controls::Script);
        }
        let first_line = self.lines + 1;
        let mut after_mirc_section = false;
        // A trailing `^` continues a batch command onto the next line;
        // obfuscators split words with it (`S^` / `ET x=1`).
        let mut carry: Vec<u8> = Vec::new();
        // Lines end in LF, CRLF, or -- in scripts saved on classic Mac OS or
        // mangled in transit -- a bare CR. The window's cut can leave a
        // partial last line; it is still read, as every grammar keys on how a
        // line starts.
        // Byte offset of `raw` in the window: the pieces are separated by one
        // line-break byte each.
        let mut next_line = 0;
        for raw in window.split(|&b| b == b'\n' || b == b'\r') {
            let line_start = next_line;
            next_line += raw.len() + 1;
            let trimmed = raw.trim_ascii();
            if let Some(start) = trimmed.strip_suffix(b"^").filter(|s| !s.ends_with(b"^")) {
                carry.extend_from_slice(start);
                continue;
            }
            let joined;
            let line = if carry.is_empty() {
                trimmed
            } else {
                carry.extend_from_slice(trimmed);
                joined = std::mem::take(&mut carry);
                &joined[..]
            };
            if line.iter().all(|&b| b == b':') {
                continue;
            }
            // A brace alone closes a block. It says nothing for the languages
            // that use braces and everything against the two that do not.
            if line
                .iter()
                .all(|b| matches!(b, b'{' | b'}' | b';' | b')' | b'('))
            {
                self.batch.foreign += u32::from(line != b")" && line != b"(");
                self.vbs.foreign += 1;
                continue;
            }
            self.lines += 1;
            // Every 64 lines, give up on a file none of the grammars has read
            // a twentieth of: it is not going to reach a quarter. Scripts in
            // these languages cover their own lines -- even their comments
            // are theirs.
            let read = self.lines + 1 - first_line;
            if read.is_multiple_of(64) && self.max_covered() * 20 < self.lines {
                break;
            }
            if line.starts_with(b"<%") || line.ends_with(b"%>") {
                self.server_block = true;
            }

            let vbs = vbs_line(line);
            let mut batch = if contains(line, b"^") {
                batch_line(&strip_carets(line))
            } else {
                batch_line(line)
            };
            // `@` suppresses a command's echo. At the left margin it is a
            // batch line whatever follows; a makefile's `@echo` is a
            // tab-indented recipe.
            let margin = raw
                .iter()
                .take_while(|b| matches!(b, b';' | b',' | b'='))
                .count();
            if batch == Grade::Weak
                && (raw.get(margin) == Some(&b'@')
                    || (self.batch_opener && line.starts_with(b"\x1b[")))
            {
                batch = Grade::Strong;
            }
            // `:::On Error Resume Next:::` -- VBScript's statement separator,
            // which cmd.exe would read as a comment.
            if line.starts_with(b"::") && vbs > Grade::None {
                batch = Grade::Weak;
            }
            if head && batch == Grade::Strong && self.batch_first_strong.is_none() {
                self.batch_first_strong = Some(line_start);
            }
            if head && self.lines == first_line {
                self.batch_opener = batch_opener(line);
            }
            if head && self.lines < first_line + LEAD_LINES && batch == Grade::Strong {
                self.batch_lead += 1;
            }
            self.batch.add(batch);
            if self.vbs.strong == 0
                && vbs != Grade::Strong
                && [
                    &b"<html"[..],
                    b"<script",
                    b"<body",
                    b"<head",
                    b"<!doctype html",
                    b"<hta:",
                ]
                .iter()
                .any(|tag| starts_ci(line, tag))
            {
                self.page_first = true;
            }
            self.vbs.add(vbs);
            if (batch == Grade::None || vbs == Grade::None) && foreign_shape(line) {
                if batch == Grade::None {
                    self.batch.foreign += 1;
                }
                // VBScript lives inside pages, HTAs and WSF jobs; their markup
                // is not evidence against it.
                if vbs == Grade::None && !line.starts_with(b"<") {
                    self.vbs.foreign += 1;
                }
            }

            // mIRC saves scripts as INI: `[script]`, then `n0=`, `n1=`...
            let mirc = if after_mirc_section && starts_ci(line, b"n0=") {
                Grade::Strong
            } else {
                mirc_line(line)
            };
            after_mirc_section = MIRC_SECTIONS.iter().any(|s| line.eq_ignore_ascii_case(s));
            self.mirc.add(mirc);
            let ircii = ircii_line(line);
            self.ircii.add(ircii);
            if foreign_to_irc(line) {
                if mirc == Grade::None {
                    self.mirc.foreign += 1;
                }
                if ircii == Grade::None {
                    self.ircii.foreign += 1;
                }
            }
        }
    }
}

/// A batch line as cmd.exe reads it: `^` escapes the next character, so
/// `p^o^w^e^r^s^h^e^l^l` is `powershell`. Quoted text keeps its carets.
fn strip_carets(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut quoted = false;
    let mut bytes = line.iter().copied();
    while let Some(b) = bytes.next() {
        match b {
            b'"' => {
                quoted = !quoted;
                out.push(b);
            }
            b'^' if !quoted => {
                if let Some(next) = bytes.next() {
                    out.push(next);
                }
            }
            _ => out.push(b),
        }
    }
    out
}

/// mIRC or ircII, when the lines say so plainly. `head` is the head of
/// [`Sniff::text`]; nearly every file is spared the grammars by its openings.
pub(super) fn irc_mark(sniff: &Sniff<'_>, head: &[u8]) -> Option<FileType> {
    if !opens_irc_line(head) {
        return None;
    }
    let ev = sniff.evidence();
    if ev.mirc.strong == 0 && ev.ircii.strong == 0 {
        return None;
    }
    ev.verdict()
        .filter(|ft| matches!(ft, FileType::Mirc | FileType::IrcII))
}

/// Whether any line opens the way a mIRC or ircII statement must: an event
/// handler, an alias, a block, an assignment, a silenced or typed command, or
/// the INI mIRC saves scripts in. Nearly every other file has no such line,
/// and is spared the grammars.
fn opens_irc_line(head: &[u8]) -> bool {
    const OPENERS: &[&[u8]] = &[
        b"on ",
        b"alias ",
        b"ctcp ",
        b"raw ",
        b"menu ",
        b"dialog ",
        b"bind ",
        b"assign ",
        b"xecho",
        b"[script]",
        b"[aliases]",
        b"[variables]",
        b"[users]",
        b"n0=",
    ];
    head.split(|&b| b == b'\n' || b == b'\r').any(|line| {
        let line = line.trim_ascii_start();
        match line.first() {
            Some(b'@') => line.get(1).is_some_and(u8::is_ascii_whitespace),
            Some(b'^') => true,
            Some(b'/') => line.get(1).is_some_and(u8::is_ascii_alphabetic),
            Some(b'.') => line.get(1).is_some_and(u8::is_ascii_alphabetic),
            Some(_) => OPENERS.iter().any(|o| starts_ci(line, o)),
            None => false,
        }
    })
}

/// Lines no batch file or VBScript contains: braces, `;` terminators, `#`
/// comments and headings, markup, and other languages' block keywords. Only
/// counted when neither grammar claimed the line.
fn foreign_shape(line: &[u8]) -> bool {
    if line.ends_with(b";") || line.ends_with(b"{") || line.ends_with(b"\\") {
        return true;
    }
    if [
        &b"{"[..],
        b"}",
        b"#",
        b"//",
        b"/*",
        b"*/",
        b"$",
        b"```",
        b"<",
    ]
    .iter()
    .any(|p| line.starts_with(p))
    {
        return true;
    }
    // `--` comments: Lua, SQL, AppleScript.
    if line.starts_with(b"--") {
        return true;
    }
    // Shell plumbing.
    if contains(line, b"/dev/null") || contains(line, b"$(") || contains(line, b"${") {
        return true;
    }
    let (verb, rest) = split_verb(line);
    let arg = rest.trim_ascii();
    let alone = arg.is_empty();
    let spaced = rest.first().is_some_and(u8::is_ascii_whitespace);
    let is = |w: &[u8]| verb == w;
    let is_ci = |w: &[u8]| verb.eq_ignore_ascii_case(w);
    if alone && (is(b"end") || is(b"fi") || is(b"done") || is(b"esac") || is(b"then")) {
        return true;
    }
    if spaced
        && (is(b"local")
            || is(b"return")
            || is(b"import")
            || is(b"def")
            || is(b"elif")
            || is(b"func")
            || is(b"fn"))
    {
        return true;
    }
    // Vim script, which shares `set`, `setlocal`, `call` and `echo` with batch.
    if [
        &b"let"[..],
        b"unlet",
        b"endif",
        b"endfunction",
        b"endfunc",
        b"endfor",
        b"endwhile",
        b"endtry",
        b"finish",
        b"augroup",
        b"autocmd",
        b"au",
        b"syntax",
        b"syn",
        b"highlight",
        b"hi",
        b"exe",
        b"nnoremap",
        b"noremap",
        b"inoremap",
        b"vnoremap",
        b"nmap",
        b"imap",
        b"command",
        b"function",
    ]
    .iter()
    .any(|w| verb == *w)
        && (alone || spaced || rest.starts_with(b"!"))
    {
        return true;
    }
    // AppleScript shares `if ... then` / `end if` with VBScript, and says
    // everything else its own way: `set x to y`, `end tell`, `end <handler>`,
    // `on handler(...)`, `repeat`, `tell application`, `global`.
    if is_ci(b"set") && spaced && find_word_ci(arg, b"to").is_some() && !contains(arg, b"=") {
        return true;
    }
    if is_ci(b"end") && spaced {
        let (block, _) = split_verb(arg);
        return ![
            &b"sub"[..],
            b"function",
            b"select",
            b"with",
            b"class",
            b"property",
            b"type",
        ]
        .iter()
        .chain(VB_NET_BLOCKS)
        .any(|w| block.eq_ignore_ascii_case(w));
    }
    if is_ci(b"on") && spaced && !starts_ci(arg, b"error") && arg.ends_with(b")") {
        return true;
    }
    spaced && (is_ci(b"repeat") || is_ci(b"tell") || is_ci(b"global") || is_ci(b"considering"))
        || (alone && is_ci(b"repeat"))
}

/// Lines no mIRC or ircII script contains: statement terminators and other
/// languages' declarations. Braces and `#` are both of theirs.
fn foreign_to_irc(line: &[u8]) -> bool {
    if line.ends_with(b";") {
        return true;
    }
    let (verb, rest) = split_verb(line);
    rest.first().is_some_and(u8::is_ascii_whitespace)
        && [
            &b"import"[..],
            b"package",
            b"public",
            b"private",
            b"protected",
            b"def",
            b"return",
            b"function",
            b"var",
            b"const",
            b"let",
        ]
        .iter()
        .any(|w| verb == *w)
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// `window` with Unicode spaces -- no-break, en, em, thin, ideographic --
/// turned into ASCII ones. Scripts copied out of web pages and word
/// processors carry them between every word, and the grammars split words on
/// ASCII whitespace.
fn ascii_spaces(window: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    fn unicode_space(s: &[u8]) -> Option<usize> {
        match s {
            [0xC2, 0xA0, ..] => Some(2),
            [0xE2, 0x80, 0x80..=0x8A | 0xAF, ..] | [0xE3, 0x80, 0x80, ..] => Some(3),
            _ => None,
        }
    }
    if memchr::memchr2(0xC2, 0xE2, window).is_none() && memchr::memchr(0xE3, window).is_none() {
        return std::borrow::Cow::Borrowed(window);
    }
    let mut out = Vec::with_capacity(window.len());
    let mut rest = window;
    while let Some((&b, after)) = rest.split_first() {
        if let Some(len) = unicode_space(rest) {
            out.push(b' ');
            rest = rest.get(len..).unwrap_or_default();
        } else {
            out.push(b);
            rest = after;
        }
    }
    std::borrow::Cow::Owned(out)
}

/// The leading word of a statement and what follows it.
fn split_verb(s: &[u8]) -> (&[u8], &[u8]) {
    let len = s
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        .count();
    s.split_at(len)
}

fn is_identifier_start(s: &[u8]) -> bool {
    s.first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
}

fn is_plain_identifier(s: &[u8]) -> bool {
    is_identifier_start(s) && s.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Offset of `word` in `s` on word boundaries, ignoring case.
fn find_word_ci(s: &[u8], word: &[u8]) -> Option<usize> {
    (0..=s.len().checked_sub(word.len())?).find(|&i| {
        s.get(i..i + word.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(word))
            && i.checked_sub(1)
                .and_then(|p| s.get(p))
                .is_none_or(|b| !b.is_ascii_alphanumeric())
            && s.get(i + word.len())
                .is_none_or(|b| !b.is_ascii_alphanumeric())
    })
}

mod batch;
mod irc;
mod vbs;

use batch::{batch_line, batch_opener, count_env_refs};
use irc::{MIRC_SECTIONS, ircii_line, mirc_line};
use vbs::{VB_NET_BLOCKS, vbs_line, vbs_object_expr};

#[cfg(test)]
mod tests;
