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

use super::FileType;

/// How much text the grammars read. Droppers pad themselves with junk lines,
/// so this is wider than the token scorer's window.
const WINDOW: usize = 32 * 1024;

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
pub(crate) struct Evidence {
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
    pub(crate) fn supports(&self, ft: FileType) -> bool {
        self.tally(ft).is_some_and(|t| t.strong > 0)
    }

    /// Whether the lines argue against `ft`: more of them are written in
    /// shapes it cannot have than in its own.
    pub(crate) fn rules_out(&self, ft: FileType) -> bool {
        self.tally(ft)
            .is_some_and(|t| t.foreign > 0 && t.foreign * 2 > t.covered())
    }

    /// Whether the text had lines to judge. A file with no line breaks gives
    /// the grammars one line of everything, which says nothing either way.
    pub(crate) fn has_lines(&self) -> bool {
        self.lines >= 2
    }

    /// Whether `ft` has enough strong lines to stand against a name that
    /// claims a language nothing here can read. A lone `@echo off` is also
    /// an Elixir module attribute.
    pub(crate) fn conclusive(&self, ft: FileType) -> bool {
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
    pub(crate) fn verdict(&self) -> Option<FileType> {
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

/// Grade the lines of `text` for all four languages.
pub(crate) fn evidence(text: &[u8]) -> Evidence {
    evidence_within(text, WINDOW)
}

/// [`evidence`] over at most `window` bytes at each end.
pub(crate) fn evidence_within(text: &[u8], window: usize) -> Evidence {
    let text = skip_padding(text);
    let head = text.get(..window).unwrap_or(text);
    let mut ev = Evidence::default();
    ev.read(head, true);
    // Droppers bury their code under a payload or thousands of junk lines;
    // what they run is often at the end. The tail only speaks when the head
    // could not: a clear opening is not outvoted by a megabyte of payload.
    // A tail with no line break starts at an arbitrary byte of a line the head
    // already opened, not at a line start: it can begin inside a string and
    // invert the quote tracking. A 355 KB one-line Lua payload cut that way
    // read its `if v<x then` as a VBScript `If`, and one strong line decides
    // a file of three lines or fewer.
    if text.len() > 2 * window && ev.verdict().is_none() {
        let tail = text
            .get(text.len().saturating_sub(window)..)
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
            self.binary = is_binary(window);
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
        for raw in window.split(|&b| b == b'\n' || b == b'\r') {
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
            if batch == Grade::Weak && raw.get(margin) == Some(&b'@') {
                batch = Grade::Strong;
            }
            // `:::On Error Resume Next:::` -- VBScript's statement separator,
            // which cmd.exe would read as a comment.
            if line.starts_with(b"::") && vbs > Grade::None {
                batch = Grade::Weak;
            }
            if head && batch == Grade::Strong && self.batch_first_strong.is_none() {
                self.batch_first_strong = Some(raw.as_ptr() as usize - window.as_ptr() as usize);
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

/// mIRC or ircII, when the lines say so plainly. Cheap enough to run on every
/// file that reaches the mark stage.
pub(crate) fn irc_mark(head: &[u8]) -> Option<FileType> {
    if !opens_irc_line(head) {
        return None;
    }
    let ev = evidence(head);
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

// ── Batch ────────────────────────────────────────────────────────────────

/// Windows programs and cmd.exe builtins that batch files call. They are only
/// weak evidence on their own -- PowerShell aliases half of them and prose
/// starts sentences with "start" and "type" -- until a `/switch`, a `%var%` or
/// a `>nul` shows the line was written for cmd.exe.
const BATCH_COMMANDS: &[&[u8]] = &[
    b"assoc",
    b"attrib",
    b"bcdedit",
    b"bitsadmin",
    b"break",
    b"cacls",
    b"cd",
    b"certutil",
    b"chdir",
    b"choice",
    b"cipher",
    b"cls",
    b"cmd",
    b"copy",
    b"cscript",
    b"curl",
    b"del",
    b"deltree",
    b"dir",
    b"doskey",
    b"erase",
    b"expand",
    b"find",
    b"findstr",
    b"forfiles",
    b"format",
    b"ftype",
    b"icacls",
    b"ipconfig",
    b"label",
    b"md",
    b"mkdir",
    b"more",
    b"move",
    b"msiexec",
    b"mshta",
    b"net",
    b"netsh",
    b"path",
    b"pause",
    b"ping",
    b"popd",
    b"powershell",
    b"prompt",
    b"pushd",
    b"pwsh",
    b"rd",
    b"reg",
    b"regedit",
    b"regsvr32",
    b"ren",
    b"rename",
    b"rmdir",
    b"robocopy",
    b"rundll32",
    b"sc",
    b"schtasks",
    b"shift",
    b"shutdown",
    b"sort",
    b"subst",
    b"systeminfo",
    b"takeown",
    b"taskkill",
    b"tasklist",
    b"timeout",
    b"title",
    b"type",
    b"ver",
    b"verify",
    b"vol",
    b"vssadmin",
    b"where",
    b"whoami",
    b"wmic",
    b"wscript",
    b"xcopy",
];

/// Commands Unix shells share, whose `/word` argument may be an absolute path
/// rather than a switch. Only a one- or two-letter switch counts for these.
const UNIX_SHARED: &[&[u8]] = &[
    b"cd", b"curl", b"dir", b"find", b"mkdir", b"more", b"ping", b"rmdir", b"sort", b"type",
    b"where",
];

/// A first line only a batch file opens with.
fn batch_opener(line: &[u8]) -> bool {
    let line = skip_delimiters(line);
    // Hybrid headers: cmd.exe reads each as a harmless redirect or label, the
    // other interpreter as the start of a comment.
    if starts_ci(line, b"<!-- :")
        || line.starts_with(b"0</* :")
        || line.starts_with(b"<# :")
        || starts_ci(line, b"@if (@")
    {
        return true;
    }
    if line.starts_with(b"::") {
        return true;
    }
    let Some(rest) = line.strip_prefix(b"@") else {
        return is_echo_off(line);
    };
    let (verb, _) = split_verb(rest);
    !verb.is_empty()
        && (is_echo_off(rest)
            || [
                &b"setlocal"[..],
                b"cls",
                b"chcp",
                b"ctty",
                b"goto",
                b"set",
                b"rem",
                b"title",
                b"color",
                b"mode",
                b"call",
                b"cd",
                b"pushd",
                b"break",
                b"prompt",
            ]
            .iter()
            .any(|v| verb.eq_ignore_ascii_case(v)))
}

/// `echo off` / `echo on`, optionally followed by another command.
fn is_echo_off(line: &[u8]) -> bool {
    let (verb, rest) = split_verb(line);
    if !verb.eq_ignore_ascii_case(b"echo") {
        return false;
    }
    let rest = rest.trim_ascii();
    let (word, tail) = split_verb(rest);
    (word.eq_ignore_ascii_case(b"off") || word.eq_ignore_ascii_case(b"on"))
        && matches!(tail.trim_ascii().first(), None | Some(b'&' | b'|'))
}

/// cmd.exe skips `;`, `,` and `=` in front of a command as it does spaces.
/// IExpress and INF hybrids put `;` before every batch line, so the other
/// format reads them as comments.
fn skip_delimiters(line: &[u8]) -> &[u8] {
    let n = line
        .iter()
        .take_while(|b| matches!(b, b';' | b',' | b'=' | b' ' | b'\t'))
        .count();
    line.get(n..).unwrap_or_default()
}

/// How a line grades given the grade of the command it continues into: an
/// opening `(` caps that command at `Weak`, a run of `%` references makes any
/// command behind it `Strong`. Indexed by that command's grade.
#[derive(Clone, Copy)]
struct Continuation([Grade; 3]);

impl Continuation {
    const SAME: Self = Self([Grade::None, Grade::Weak, Grade::Strong]);
    const AT_MOST_WEAK: Self = Self([Grade::None, Grade::Weak, Grade::Weak]);
    const ANY_IS_STRONG: Self = Self([Grade::None, Grade::Strong, Grade::Strong]);

    fn apply(self, grade: Grade) -> Grade {
        let [none, weak, strong] = self.0;
        match grade {
            Grade::None => none,
            Grade::Weak => weak,
            Grade::Strong => strong,
        }
    }

    /// `self` applied to what `inner` makes of the next command's grade.
    fn then(self, inner: Self) -> Self {
        Self(inner.0.map(|g| self.apply(g)))
    }
}

/// One step of [`batch_line`]: a grade, or the rest of the line to read
/// next and how its grade carries back.
enum BatchStep<'a> {
    Graded(Grade),
    Within(Continuation, &'a [u8]),
    Expanded(Continuation, Vec<u8>),
}

/// Grade a batch line. A line can continue into another command any number
/// of times (`((((`, `junk&junk&...`), so the continuations are followed in a
/// loop: a padded line must not grow the stack, which no `catch_unwind` saves.
fn batch_line(line: &[u8]) -> Grade {
    let mut carry = Continuation::SAME;
    let mut expanded: Vec<u8>;
    let mut line = line;
    loop {
        match batch_step(line) {
            BatchStep::Graded(grade) => return carry.apply(grade),
            BatchStep::Within(next, rest) => {
                carry = carry.then(next);
                line = rest;
            }
            BatchStep::Expanded(next, rest) => {
                carry = carry.then(next);
                expanded = rest;
                line = &expanded;
            }
        }
    }
}

fn batch_step(line: &[u8]) -> BatchStep<'_> {
    use BatchStep::{Expanded, Graded, Within};
    // A command separator leaves a command behind it: `&cls` after a junk
    // first line, `|| goto fail`.
    let line = skip_delimiters(line);
    let line = line
        .strip_prefix(b"&&")
        .or_else(|| line.strip_prefix(b"||"))
        .or_else(|| line.strip_prefix(b"&"))
        .unwrap_or(line)
        .trim_ascii_start();
    let Some((&first, after_first)) = line.split_first() else {
        return Graded(Grade::None);
    };
    // `::` is a label no other language writes; batch files use it as a comment.
    if line.starts_with(b"::") {
        return Graded(Grade::Strong);
    }
    // A label is what batch files are built around, but a colon and a name
    // is also an EDN keyword (`:handles`) and a Vim Ex command (`:endfor`).
    // The `goto` that jumps to it is the batch-only half.
    if first == b':' {
        return Graded(if is_batch_label(after_first) {
            Grade::Weak
        } else {
            Grade::None
        });
    }
    // Parenthesised blocks: `) else (`, `(echo x`.
    if first == b')' {
        let rest = after_first.trim_ascii_start();
        return Graded(if rest.is_empty() {
            Grade::Weak
        } else if rest.split_at_checked(4).is_some_and(|(word, tail)| {
            word.eq_ignore_ascii_case(b"else") && tail.trim_ascii() == b"("
        }) {
            Grade::Strong
        } else {
            Grade::None
        });
    }
    if first == b'(' {
        // Each `(` would cap the command behind it the same way, so a run of
        // them is one step.
        let opened = line.iter().take_while(|&&b| b == b'(').count();
        return Within(
            Continuation::AT_MOST_WEAK,
            line.get(opened..).unwrap_or_default(),
        );
    }
    let body = match line.strip_prefix(b"@") {
        Some(rest)
            if rest
                .first()
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'%') =>
        {
            rest
        }
        // `@"%SystemRoot%\System32\cscript.exe" //nologo "%~dpn0" %*`
        Some(rest) if rest.first() == Some(&b'"') => {
            return Graded(if has_batch_syntax(rest) {
                Grade::Strong
            } else {
                Grade::Weak
            });
        }
        _ => line,
    };
    // Obfuscated batch spells every command through undefined variables:
    // `@%LZG%e%QM%c%ZME%h%HH%o off` is `@echo off` to cmd.exe, which expands
    // each reference to nothing. Do the same and read what is left; a line
    // that is nothing but references assembles its command at run time.
    // `%_x:~23,1%` takes one character of a variable: batch's own
    // substring syntax, and how obfuscators assemble every command.
    if count_substring_refs(body) >= 2 {
        return Graded(Grade::Strong);
    }
    // `C:\Users\Public\x\run.exe -c ...`: a program by its Windows path.
    if matches!(body, [drive, b':', b'\\', _, ..] if drive.is_ascii_alphabetic()) {
        return Graded(if has_windows_program(body) {
            Grade::Strong
        } else {
            Grade::Weak
        });
    }
    if body.first() == Some(&b'%') {
        let (refs, rest) = strip_env_refs(body);
        if refs < 2 {
            return Graded(Grade::None);
        }
        let rest = rest.trim_ascii();
        return if rest.is_empty() {
            Graded(Grade::Strong)
        } else if rest.starts_with(b"%") {
            Graded(Grade::None)
        } else {
            Expanded(Continuation::ANY_IS_STRONG, rest.to_vec())
        };
    }
    let (verb, rest) = split_verb(body);
    let grade = if verb.is_empty() {
        Grade::None
    } else {
        batch_verb(verb, rest)
    };
    if grade == Grade::Weak && has_batch_syntax(rest) {
        return Graded(Grade::Strong);
    }
    // References spliced into the command itself (`C%x%:%y%\%z%W%q%indows`)
    // vanish when cmd.exe expands them; what is left has to be a command.
    // With no `%` left it cannot expand again, so this nests one level deep.
    if grade == Grade::None && memchr::memchr_iter(b'%', body).nth(3).is_some() {
        let (refs, expanded) = strip_env_refs(body);
        if refs >= 2
            && memchr::memchr(b'%', &expanded).is_none()
            && batch_line(&expanded) > Grade::None
        {
            return Graded(Grade::Strong);
        }
    }
    // `COMCOM\xFF\xFE&@cls&@set "_x=..."`: junk that fails as a command,
    // then the real ones chained behind `&`.
    if grade == Grade::None {
        if let Some(after) = unquoted_ampersand(body).and_then(|amp| body.get(amp + 1..)) {
            return Within(Continuation::SAME, after);
        }
    }
    Graded(grade)
}

/// The first `&` outside double quotes.
fn unquoted_ampersand(s: &[u8]) -> Option<usize> {
    let mut quoted = false;
    for (i, &b) in s.iter().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b'&' if !quoted => return Some(i),
            _ => {}
        }
    }
    None
}

fn batch_verb(verb: &[u8], rest: &[u8]) -> Grade {
    // cmd.exe ends a command name at whitespace or one of its delimiters:
    // `echo.`, `goto:eof`, `cd..`, `exit/b`, `set"x=1"`.
    if !rest.first().is_none_or(|b| {
        b.is_ascii_whitespace()
            || matches!(
                b,
                b'.' | b'('
                    | b':'
                    | b';'
                    | b','
                    | b'/'
                    | b'+'
                    | b'['
                    | b']'
                    | b'\\'
                    | b'"'
                    | b'='
                    | b'<'
                    | b'>'
                    | b'&'
                    | b'|'
            )
    }) {
        return Grade::None;
    }
    let is = |w: &[u8]| verb.eq_ignore_ascii_case(w);
    let arg = rest.trim_ascii();
    if is(b"echo") {
        // `echo.`, `echo(`, `echo:` and `echo/` print a blank line; nothing
        // else spells echo that way.
        if rest
            .first()
            .is_some_and(|b| matches!(b, b'.' | b'(' | b':' | b';' | b',' | b'/' | b'+' | b'['))
        {
            return Grade::Strong;
        }
        let (word, tail) = split_verb(arg);
        if (word.eq_ignore_ascii_case(b"off") || word.eq_ignore_ascii_case(b"on"))
            && matches!(tail.trim_ascii().first(), None | Some(b'&' | b'|'))
        {
            return Grade::Strong;
        }
        return Grade::Weak;
    }
    if is(b"rem") {
        return if rest.first().is_none_or(u8::is_ascii_whitespace) {
            Grade::Weak
        } else {
            Grade::None
        };
    }
    if is(b"set") {
        return batch_set(rest);
    }
    // Vim has a `setlocal` too, followed by its options (`setlocal ts=4`).
    if is(b"setlocal") {
        let (option, _) = split_verb(arg);
        return if arg.is_empty()
            || starts_ci(option, b"enable")
            || starts_ci(option, b"disable")
            || arg.starts_with(b"&")
        {
            Grade::Strong
        } else {
            Grade::None
        };
    }
    if is(b"endlocal") || is(b"ctty") {
        return Grade::Strong;
    }
    if is(b"goto") {
        return if arg.is_empty() || arg.ends_with(b";") {
            Grade::None
        } else {
            Grade::Strong
        };
    }
    if is(b"if") {
        return batch_if(arg);
    }
    if is(b"for") {
        let arg_lower = |p: &[u8]| starts_ci(arg, p);
        return if ["/f ", "/l ", "/d ", "/r "]
            .iter()
            .any(|p| arg_lower(p.as_bytes()))
            || arg.starts_with(b"%%")
            || (arg.first() == Some(&b'%') && arg.get(2).is_some_and(u8::is_ascii_whitespace))
        {
            Grade::Strong
        } else {
            Grade::None
        };
    }
    if is(b"call") {
        return if arg.starts_with(b":")
            || contains_ci(arg, b".bat")
            || contains_ci(arg, b".cmd")
            || arg.starts_with(b"%")
            || arg.starts_with(b"\"%")
        {
            Grade::Strong
        } else {
            Grade::Weak
        };
    }
    if is(b"exit") {
        return if starts_ci(arg, b"/b") {
            Grade::Strong
        } else if arg.iter().all(u8::is_ascii_digit) {
            Grade::Weak
        } else {
            Grade::None
        };
    }
    if is(b"start") {
        // `start "" /min x.exe`: the quoted first argument is a window title.
        return if arg.starts_with(b"\"") || has_switch(arg, false) || has_windows_program(arg) {
            Grade::Strong
        } else {
            Grade::Weak
        };
    }
    if is(b"color") {
        let hex = arg.len() <= 2 && !arg.is_empty() && arg.iter().all(u8::is_ascii_hexdigit);
        return if hex { Grade::Strong } else { Grade::None };
    }
    if is(b"chcp") {
        let digits = !arg.is_empty() && arg.iter().all(u8::is_ascii_digit);
        return if digits { Grade::Strong } else { Grade::None };
    }
    if is(b"mode") {
        return if starts_ci(arg, b"con") {
            Grade::Strong
        } else {
            Grade::None
        };
    }
    if let Some(cmd) = BATCH_COMMANDS.iter().find(|c| is(c)) {
        // Something has to follow the verb the way it follows a command: an
        // argument, a redirect, a separator. `Type:` and `Label,` are prose.
        if !rest
            .first()
            .is_none_or(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'<' | b'&' | b'|'))
        {
            return Grade::None;
        }
        let unix_shared = UNIX_SHARED.iter().any(|u| u == cmd);
        // `del *.*`, `copy %0 *.bat`, `taskkill /im x.exe`: DOS wildcards,
        // paths and programs.
        let dos_argument =
            has_windows_path(arg) || contains(arg, b"*.") || has_windows_program(arg);
        if has_switch(arg, unix_shared) || (!unix_shared && dos_argument) {
            return Grade::Strong;
        }
        return Grade::Weak;
    }
    Grade::None
}

/// `set /a`, `set "x=y"`, `set x=y`. VBScript's `Set x = CreateObject(...)`
/// shares the verb; an object on the right-hand side is its tell.
fn batch_set(rest: &[u8]) -> Grade {
    let arg = rest.trim_ascii();
    if arg.is_empty() {
        return Grade::Weak;
    }
    if starts_ci(arg, b"/a") || starts_ci(arg, b"/p") {
        return Grade::Strong;
    }
    let quoted = arg.first() == Some(&b'"');
    let field = arg.get(usize::from(quoted)..).unwrap_or_default();
    let name_len = field
        .iter()
        .take_while(|&&b| !matches!(b, b'=' | b' ' | b'\t' | b'"'))
        .count();
    let Some((name, after)) = field.split_at_checked(name_len) else {
        return Grade::None;
    };
    if name
        .first()
        .is_none_or(|&b| b.is_ascii_punctuation() && b != b'_')
    {
        return Grade::None;
    }
    if let Some(value) = after.strip_prefix(b"=") {
        if quoted || !vbs_object_expr(value.trim_ascii()) {
            return Grade::Strong;
        }
        return Grade::None;
    }
    // `set x = y` is legal batch, but it is how VBScript spells an assignment.
    let spaced = after.trim_ascii_start();
    if spaced.starts_with(b"=") && !spaced.starts_with(b"==") {
        return if has_batch_syntax(spaced) {
            Grade::Weak
        } else {
            Grade::None
        };
    }
    Grade::None
}

/// `if exist`, `if errorlevel`, `if defined`, `if "%1"==""`, the hybrid
/// header `@if (@X)==(@Y) @end`.
fn batch_if(arg: &[u8]) -> Grade {
    // `@if (@X)==(@Y) @end /*`, `@if (@CodeSection == @Batch) @then`: a
    // JScript conditional-compilation test that cmd.exe reads as a harmless
    // comparison, heading a batch/JScript hybrid.
    if arg.starts_with(b"(@") {
        return Grade::Strong;
    }
    let mut cond = arg;
    for prefix in [&b"/i "[..], b"not "] {
        if starts_ci(cond, prefix) {
            cond = cond
                .get(prefix.len()..)
                .unwrap_or_default()
                .trim_ascii_start();
        }
    }
    if [
        &b"exist "[..],
        b"errorlevel ",
        b"defined ",
        b"cmdextversion ",
    ]
    .iter()
    .any(|p| starts_ci(cond, p))
    {
        return Grade::Strong;
    }
    let compares = contains(cond, b"==")
        || [
            &b" equ "[..],
            b" neq ",
            b" lss ",
            b" leq ",
            b" gtr ",
            b" geq ",
        ]
        .iter()
        .any(|op| contains_ci(cond, op));
    // Batch has no braces; mIRC's `if ($1 == !quit) { ... }` does.
    if compares && !contains(cond, b"{") && (has_batch_syntax(cond) || has_delayed_ref(cond)) {
        return Grade::Strong;
    }
    Grade::None
}

/// `!name!`, a variable under delayed expansion.
fn has_delayed_ref(s: &[u8]) -> bool {
    s.iter().enumerate().any(|(i, &b)| {
        if b != b'!' {
            return false;
        }
        let name = s.get(i + 1..).unwrap_or_default();
        let len = name
            .iter()
            .take_while(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'[' | b']')
            })
            .count();
        len > 0 && name.first().is_some_and(u8::is_ascii_alphabetic) && name.get(len) == Some(&b'!')
    })
}

/// Syntax that belongs to cmd.exe wherever it appears on a command line:
/// `%~dp0`, `%%i`, `>nul`, `%errorlevel%`, `%var%`.
fn has_batch_syntax(s: &[u8]) -> bool {
    if contains_ci(s, b">nul") || contains_ci(s, b"> nul") || contains(s, b"%~") {
        return true;
    }
    // A line that expands `$VAR` is a shell's, and its `%` signs are a
    // strftime format: `date +"%Y-%m-%d %H:%M"`.
    if has_shell_variable(s) {
        return false;
    }
    s.windows(3)
        .any(|w| matches!(w, [b'%', b'%', c] if c.is_ascii_alphabetic() || *c == b'~'))
        || count_env_refs(s) > 0
        || s.windows(2).enumerate().any(|(i, w)| {
            matches!(w, [b'%', c] if c.is_ascii_digit() || *c == b'*')
                && i.checked_sub(1)
                    .and_then(|p| s.get(p))
                    .is_none_or(|b| matches!(b, b' ' | b'"' | b'\t' | b'='))
        })
}

/// `$name`, `${name}`, `$(cmd)`.
fn has_shell_variable(s: &[u8]) -> bool {
    s.windows(2).any(
        |w| matches!(w, [b'$', c] if c.is_ascii_alphabetic() || matches!(c, b'_' | b'{' | b'(')),
    )
}

/// `%name:~N,M%` references.
fn count_substring_refs(s: &[u8]) -> usize {
    if memchr::memchr(b'~', s).is_none() {
        return 0;
    }
    // `:~` cannot overlap itself, so the non-overlapping matches are all of them.
    memchr::memmem::find_iter(s, b":~")
        .filter(|&at| {
            let before = s.get(..at).unwrap_or_default();
            let after = s.get(at + 2..).unwrap_or_default();
            let digits = after
                .iter()
                .take_while(|b| b.is_ascii_digit() || matches!(b, b',' | b'-'))
                .count();
            let named = before
                .iter()
                .rev()
                .take(64)
                .position(|&b| b == b'%')
                .is_some_and(|n| n > 0);
            named && digits > 0 && after.get(digits) == Some(&b'%')
        })
        .count()
}

/// A Windows program or script among the arguments: `x.exe`, `run.bat`.
fn has_windows_program(s: &[u8]) -> bool {
    [
        &b".exe"[..],
        b".bat",
        b".cmd",
        b".vbs",
        b".vbe",
        b".ps1",
        b".msi",
        b".scr",
        b".hta",
    ]
    .iter()
    .any(|ext| {
        let mut from = 0;
        while let Some(at) = s.get(from..).and_then(|rest| find_ci(rest, ext)) {
            let end = from + at + ext.len();
            if s.get(end).is_none_or(|b| !b.is_ascii_alphanumeric()) {
                return true;
            }
            from = end;
        }
        false
    })
}

/// Offset of `needle` in `hay`, ignoring ASCII case. Every line of a file
/// passes through a few dozen of these, so candidates are found with `memchr`
/// on the needle's first byte rather than by comparing at every offset.
pub(crate) fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, _) = needle.split_first()?;
    let (lower, upper) = (first.to_ascii_lowercase(), first.to_ascii_uppercase());
    // Every offset a match could start at.
    let starts = hay.get(..=hay.len().checked_sub(needle.len())?)?;
    memchr::memchr2_iter(lower, upper, starts).find(|&at| {
        hay.get(at..at + needle.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle))
    })
}

/// `s` with its `%name%` references removed, and how many there were.
///
/// A variable name is anything up to the next `%` -- obfuscators name them in
/// Arabic, CJK or Latin-1, with spaces -- and a reference may slice its value
/// (`%_x:~23,1%`). A leading digit is an argument (`%1`), not a name.
fn strip_env_refs(s: &[u8]) -> (usize, Vec<u8>) {
    let mut out = Vec::with_capacity(s.len());
    let mut refs = 0;
    let mut rest = s;
    while let Some((&b, after)) = rest.split_first() {
        if b == b'%' {
            let len = after.iter().take(64).take_while(|&&b| b != b'%').count();
            let name = after.get(..len).unwrap_or_default();
            let named = len > 0
                && len < 64
                && after.get(len) == Some(&b'%')
                && !name.first().is_some_and(u8::is_ascii_digit)
                && !name.iter().any(|&b| b < 0x20);
            if named {
                refs += 1;
                // Past the name and its closing `%`.
                rest = after.get(len + 1..).unwrap_or_default();
                continue;
            }
        }
        out.push(b);
        rest = after;
    }
    (refs, out)
}

/// `%name%` references, `%name:~0,1%` included. Printf's `%s` has no closing
/// `%` and a percentage has no name, so neither counts.
fn count_env_refs(s: &[u8]) -> usize {
    let mut count = 0;
    let mut rest = s;
    while let Some((&b, name)) = rest.split_first() {
        if b != b'%' {
            rest = name;
            continue;
        }
        let len = name
            .iter()
            .take_while(|&&b| {
                b.is_ascii_alphanumeric()
                    || b >= 0x80
                    || matches!(b, b'_' | b'#' | b'$' | b'@' | b'.' | b'-')
            })
            .count();
        let starts_alpha = name
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_' || *b >= 0x80);
        // How far into `name` the reference reaches, closing `%` included.
        let skip = match name.get(len) {
            Some(b'%') if len > 0 && starts_alpha => {
                count += 1;
                len + 1
            }
            Some(b':') if len > 0 && starts_alpha => {
                // `%var:~0,1%` / `%var:a=b%`
                let tail = name.get(len..).unwrap_or_default();
                match tail.iter().take(40).position(|&b| b == b'%') {
                    Some(end) => {
                        count += 1;
                        len + end + 1
                    }
                    None => 0,
                }
            }
            _ => 0,
        };
        rest = name.get(skip..).unwrap_or_default();
    }
    count
}

/// A `/x` switch after whitespace. `short_only` admits just one or two
/// letters, for commands whose `/word` could be a Unix path.
fn has_switch(s: &[u8], short_only: bool) -> bool {
    let max = if short_only { 2 } else { 16 };
    s.iter().enumerate().any(|(i, &b)| {
        let after_word = || {
            i.checked_sub(1)
                .and_then(|p| s.get(p))
                .is_some_and(|b| !b.is_ascii_whitespace())
        };
        if b != b'/' || after_word() {
            return false;
        }
        let rest = s.get(i + 1..).unwrap_or_default();
        let len = rest
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'?' || **b == b'-')
            .count();
        len > 0
            && len <= max
            && rest
                .first()
                .is_some_and(|&c| c.is_ascii_alphabetic() || c == b'?')
            && rest
                .get(len)
                .is_none_or(|b| b.is_ascii_whitespace() || matches!(b, b':' | b'=' | b'"'))
    })
}

/// `C:\`, `\\server\share`, `%windir%\`.
fn has_windows_path(s: &[u8]) -> bool {
    contains(s, b"\\\\")
        || s.windows(3)
            .any(|w| matches!(w, [drive, b':', b'\\'] if drive.is_ascii_alphabetic()))
}

/// A label after its `:`: a name, then the end of the line or a comment.
fn is_batch_label(rest: &[u8]) -> bool {
    let len = rest
        .iter()
        .take_while(|&&b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'-' | b'.' | b'$' | b'#' | b'@' | b'~' | b'!')
        })
        .count();
    len > 0 && rest.get(len).is_none_or(u8::is_ascii_whitespace)
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

// ── VBScript ─────────────────────────────────────────────────────────────

fn vbs_line(line: &[u8]) -> Grade {
    match line.first() {
        Some(b'\'') => return Grade::Weak,
        // `:::On Error Resume Next:::` is statements behind empty ones, but
        // `:loop` is a batch label, not an empty statement before `Loop`.
        Some(b':') if line.starts_with(b"::") => {
            let colons = line.iter().take_while(|&&b| b == b':').count();
            let rest = line.get(colons..).unwrap_or_default();
            return if rest.is_empty() {
                Grade::None
            } else {
                vbs_line(rest)
            };
        }
        Some(b':') => return Grade::None,
        _ => {}
    }
    let mut best = Grade::None;
    for stmt in vbs_statements(line) {
        best = best.max(vbs_statement(stmt.trim_ascii()));
        if best == Grade::Strong {
            break;
        }
    }
    best
}

/// Split on the `:` statement separator, outside strings, up to a `'` comment.
fn vbs_statements(line: &[u8]) -> VbsStatements<'_> {
    VbsStatements { rest: Some(line) }
}

struct VbsStatements<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Iterator for VbsStatements<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let line = self.rest.take()?;
        let mut quoted = false;
        for (i, &b) in line.iter().enumerate() {
            match b {
                b'"' => quoted = !quoted,
                b'\'' if !quoted => return line.get(..i),
                b':' if !quoted => {
                    let (stmt, colon) = line.split_at_checked(i)?;
                    self.rest = colon.get(1..);
                    return Some(stmt);
                }
                _ => {}
            }
        }
        Some(line)
    }
}

fn vbs_statement(s: &[u8]) -> Grade {
    if s.is_empty() {
        return Grade::None;
    }
    if s.ends_with(b";") || s.ends_with(b"{") {
        return Grade::None;
    }
    let (verb, rest) = split_verb(s);
    let arg = rest.trim_ascii();
    let next = split_verb(arg).0;
    let next_is = |words: &[&[u8]]| words.iter().any(|w| next.eq_ignore_ascii_case(w));
    let is = |w: &[u8]| verb.eq_ignore_ascii_case(w);
    let spaced = rest.first().is_some_and(u8::is_ascii_whitespace);

    if (is(b"dim") || is(b"redim")) && spaced && is_dim_list(arg) {
        return Grade::Strong;
    }
    if is(b"on") && (starts_ci(arg, b"error resume next") || starts_ci(arg, b"error goto 0")) {
        return Grade::Strong;
    }
    if is(b"option") && starts_ci(arg, b"explicit") {
        return Grade::Strong;
    }
    if is(b"const") && spaced && contains(arg, b"=") {
        // JavaScript's `const` is always lower case.
        return if verb == b"const" {
            Grade::Weak
        } else {
            Grade::Strong
        };
    }
    if (is(b"private") || is(b"public")) && spaced {
        if next_is(&[
            b"sub",
            b"function",
            b"property",
            b"const",
            b"dim",
            b"default",
        ]) {
            return if contains(arg, b"{") {
                Grade::None
            } else {
                Grade::Strong
            };
        }
        let plain = !arg.is_empty()
            && arg.iter().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b',' | b' ' | b'(' | b')')
            });
        return if plain && !contains(arg, b"(") {
            Grade::Weak
        } else {
            Grade::None
        };
    }
    if is(b"sub") && spaced && is_procedure_header(arg) {
        return Grade::Strong;
    }
    if is(b"function") && spaced && is_procedure_header(arg) {
        // `function` in lower case is also Lua's.
        return if verb == b"function" {
            Grade::Weak
        } else {
            Grade::Strong
        };
    }
    if is(b"end")
        && next_is(&[
            b"sub",
            b"function",
            b"select",
            b"with",
            b"class",
            b"property",
            b"type",
        ])
    {
        return Grade::Strong;
    }
    // AppleScript closes its `if` and `try` the same way; the rest are the
    // blocks VB.NET adds.
    if is(b"end") && next_is(VB_NET_BLOCKS) {
        return Grade::Weak;
    }
    if (is(b"try") || is(b"finally")) && arg.is_empty()
        || is(b"catch") && (arg.is_empty() || contains_ci(arg, b" as "))
        || (is(b"namespace") || is(b"imports") || is(b"module"))
            && spaced
            && is_identifier_start(arg)
    {
        return Grade::Weak;
    }
    if is(b"if") || is(b"elseif") {
        return vbs_if(arg);
    }
    if is(b"else") && arg.is_empty() {
        return Grade::Weak;
    }
    if is(b"for") {
        if next.eq_ignore_ascii_case(b"each") && contains_ci(arg, b" in ") {
            return Grade::Strong;
        }
        return vbs_for_to(arg);
    }
    if is(b"next") && (arg.is_empty() || is_plain_identifier(arg)) {
        return Grade::Weak;
    }
    if is(b"do") {
        return if arg.is_empty() {
            Grade::Weak
        } else if next_is(&[b"while", b"until"]) && !contains(arg, b";") {
            Grade::Strong
        } else {
            Grade::None
        };
    }
    if is(b"loop") && (arg.is_empty() || next_is(&[b"while", b"until"])) {
        return Grade::Strong;
    }
    if is(b"wend") && arg.is_empty() {
        return Grade::Strong;
    }
    if is(b"while") && !arg.is_empty() && !arg.ends_with(b"do") && !contains(arg, b"==") {
        return Grade::Weak;
    }
    if is(b"select") && next.eq_ignore_ascii_case(b"case") {
        return Grade::Strong;
    }
    if is(b"case") {
        return if next.eq_ignore_ascii_case(b"else") {
            Grade::Strong
        } else if !arg.is_empty()
            && !arg.ends_with(b":")
            && !arg.ends_with(b")")
            && !arg.ends_with(b" in")
        {
            Grade::Weak
        } else {
            Grade::None
        };
    }
    if is(b"exit") && next_is(&[b"sub", b"function", b"do", b"for", b"property"]) {
        return Grade::Strong;
    }
    if is(b"with") && spaced && is_identifier_start(arg) && !contains(arg, b"(") {
        return Grade::Weak;
    }
    if is(b"call") && spaced && is_identifier_start(arg) {
        return Grade::Weak;
    }
    if is(b"set") {
        return vbs_set(rest);
    }
    if (is(b"msgbox") || is(b"inputbox"))
        && rest
            .first()
            .is_some_and(|b| b.is_ascii_whitespace() || matches!(b, b'(' | b'"'))
    {
        return Grade::Strong;
    }
    if is(b"wscript")
        && let Some(after_dot) = rest.strip_prefix(b".")
    {
        // JScript calls the same object, with parentheses and a semicolon.
        let member = split_verb(after_dot);
        return if member.1.first().is_none_or(u8::is_ascii_whitespace) {
            Grade::Strong
        } else {
            Grade::Weak
        };
    }
    if (is(b"execute") || is(b"executeglobal"))
        && rest
            .first()
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'(')
    {
        return Grade::Strong;
    }
    if is(b"randomize") && arg.is_empty() {
        return Grade::Strong;
    }
    if (is(b"createobject") || is(b"getobject")) && rest.first() == Some(&b'(') {
        return Grade::Strong;
    }
    if is(b"class") && spaced && is_plain_identifier(arg) {
        return Grade::Weak;
    }
    if is(b"rem") && rest.first().is_none_or(u8::is_ascii_whitespace) {
        return Grade::Weak;
    }
    vbs_expression(s)
}

/// `End` blocks shared with AppleScript (`if`, `try`) or added by VB.NET.
const VB_NET_BLOCKS: &[&[u8]] = &[
    b"if",
    b"try",
    b"namespace",
    b"module",
    b"structure",
    b"enum",
    b"get",
    b"set",
    b"using",
    b"while",
    b"interface",
    b"operator",
    b"event",
    b"synclock",
];

/// `Dim a, b(10), c As String`: names, each with optional bounds and type,
/// separated by commas. "Dim the lights" is two bare words.
fn is_dim_list(arg: &[u8]) -> bool {
    let arg = match arg.split_at_checked(b"preserve ".len()) {
        Some((word, tail)) if word.eq_ignore_ascii_case(b"preserve ") => tail.trim_ascii_start(),
        _ => arg,
    };
    arg.split(|&b| b == b',').all(|item| {
        let item = item.trim_ascii();
        let name = item
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count();
        if name == 0 || !is_identifier_start(item) {
            return false;
        }
        let mut rest = item.get(name..).unwrap_or_default().trim_ascii_start();
        if rest.first() == Some(&b'(') {
            let Some(close) = memchr::memchr(b')', rest) else {
                return false;
            };
            rest = rest.get(close + 1..).unwrap_or_default().trim_ascii_start();
        }
        rest.is_empty()
            || rest.split_at_checked(3).is_some_and(|(keyword, ty)| {
                keyword.eq_ignore_ascii_case(b"as ") && is_plain_identifier(ty.trim_ascii())
            })
    })
}

/// A procedure name, then its parameter list or the end of the line.
fn is_procedure_header(arg: &[u8]) -> bool {
    let name = arg
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    name > 0
        && is_identifier_start(arg)
        && matches!(
            arg.get(name..)
                .unwrap_or_default()
                .trim_ascii_start()
                .first(),
            None | Some(b'(')
        )
}

/// Built-in functions a VBScript assignment calls. `Space(86)` and `CStr(x)`
/// are VB's names; other languages spell these differently.
const VBS_BUILTINS: &[&[u8]] = &[
    b"array(",
    b"asc(",
    b"ascw(",
    b"cbool(",
    b"cbyte(",
    b"cdbl(",
    b"chr(",
    b"chrw(",
    b"cint(",
    b"clng(",
    b"cstr(",
    b"dateserial(",
    b"environ(",
    b"escape(",
    b"eval(",
    b"filter(",
    b"hex(",
    b"instr(",
    b"instrrev(",
    b"isarray(",
    b"isempty(",
    b"isnull(",
    b"isnumeric(",
    b"join(",
    b"lbound(",
    b"lcase(",
    b"left(",
    b"len(",
    b"ltrim(",
    b"mid(",
    b"replace(",
    b"right(",
    b"rtrim(",
    b"space(",
    b"split(",
    b"strreverse(",
    b"timeserial(",
    b"trim(",
    b"typename(",
    b"ubound(",
    b"ucase(",
    b"unescape(",
    b"vartype(",
];

/// `If cond Then`. Lua writes the same keywords with `==` and `~=`, shell with
/// `; then`, so those operators rule the line out.
fn vbs_if(arg: &[u8]) -> Grade {
    let Some(at) = find_word_ci(arg, b"then") else {
        return Grade::None;
    };
    let cond = arg.get(..at).unwrap_or_default();
    if [&b"=="[..], b"~=", b"!=", b"&&", b"||", b";", b"[", b":="]
        .iter()
        .any(|op| contains(cond, op))
    {
        return Grade::None;
    }
    if cond
        .iter()
        .any(|b| matches!(b, b'=' | b'<' | b'>' | b'(' | b'.'))
    {
        Grade::Strong
    } else {
        Grade::Weak
    }
}

/// `For i = 1 To n [Step s]`. Lua's `for i = 1, n do` and Pascal's `:=` are
/// ruled out.
fn vbs_for_to(arg: &[u8]) -> Grade {
    let name = arg
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    if name == 0 {
        return Grade::None;
    }
    let rest = arg.get(name..).unwrap_or_default().trim_ascii_start();
    if !rest.starts_with(b"=") || rest.starts_with(b"==") || arg.ends_with(b"do") {
        return Grade::None;
    }
    if find_word_ci(rest, b"to").is_some() {
        Grade::Strong
    } else {
        Grade::None
    }
}

/// `Set x = <object>`. An object on the right is VBScript; a plain string or a
/// `%var%` is batch's `set`.
fn vbs_set(rest: &[u8]) -> Grade {
    let arg = rest.trim_ascii();
    let name = arg
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'(' | b')'))
        .count();
    if name == 0 || !arg.first().is_some_and(u8::is_ascii_alphabetic) {
        return Grade::None;
    }
    let after = arg.get(name..).unwrap_or_default();
    let spaced = after.first().is_some_and(u8::is_ascii_whitespace);
    let Some(rhs) = after.trim_ascii_start().strip_prefix(b"=") else {
        return Grade::None;
    };
    let rhs = rhs.trim_ascii();
    if vbs_object_expr(rhs) {
        Grade::Strong
    } else if spaced && !rhs.starts_with(b"=") && !contains(rhs, b"%") {
        Grade::Weak
    } else {
        Grade::None
    }
}

/// An object expression: `CreateObject(...)`, `New X`, `Nothing`,
/// `obj.Member(...)`.
fn vbs_object_expr(rhs: &[u8]) -> bool {
    if [
        &b"createobject("[..],
        b"getobject(",
        b"new ",
        b"wscript.",
        b"server.",
        b"me.",
    ]
    .iter()
    .any(|p| starts_ci(rhs, p))
        || rhs.eq_ignore_ascii_case(b"nothing")
    {
        return true;
    }
    // `objFS.GetFolder(x)`, `fso.CreateTextFile(...)`
    let head = rhs
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    head > 0
        && rhs.first().is_some_and(u8::is_ascii_alphabetic)
        && rhs.get(head) == Some(&b'.')
        && rhs.get(head + 1).is_some_and(u8::is_ascii_alphabetic)
}

/// Statements without a keyword: assignments and calls, graded by what only
/// VBScript spells -- `CreateObject(`, `vbCrLf`, `&H` literals, `_`
/// continuations, and method calls without parentheses.
fn vbs_expression(s: &[u8]) -> Grade {
    let paren = memchr::memchr(b'(', s).is_some();
    if paren
        && (contains_ci(s, b"createobject(")
            || contains_ci(s, b"getobject(")
            || contains_ci(s, b"msgbox("))
    {
        let js = starts_ci(s, b"var ") || starts_ci(s, b"let ") || starts_ci(s, b"const ");
        return if js { Grade::None } else { Grade::Strong };
    }
    if let Some(at) = find_ci(s, b"vb") {
        let rest = s.get(at..).unwrap_or_default();
        if contains_ci(rest, b"vbcrlf")
            || contains_ci(rest, b"vbnewline")
            || contains_ci(rest, b"vbnullstring")
        {
            return Grade::Strong;
        }
    }
    if s.ends_with(b" _") || s.ends_with(b"(_") || s.ends_with(b",_") || s.ends_with(b"&_") {
        return Grade::Weak;
    }
    if let Some(rhs) = vbs_assignment(s) {
        // `x = x & "..."`: `&` joins strings. `x = Space(86)`, `x = Array(`:
        // VB's built-ins.
        if (contains(rhs, b" & ") && contains(rhs, b"\""))
            || VBS_BUILTINS.iter().any(|f| starts_ci(rhs, f))
            || rhs.eq_ignore_ascii_case(b"freefile")
        {
            return Grade::Weak;
        }
        // `list(3) = ...`: VB indexes with parentheses.
        // `rhs` is the end of `s`.
        let target = s
            .get(..s.len().saturating_sub(rhs.len()))
            .unwrap_or_default();
        if contains(target, b"(") {
            return Grade::Weak;
        }
    }
    if has_hex_literal(s) {
        return Grade::Weak;
    }
    // `fso.CopyFile a, b, True`, `pirch.WriteLine "..."`: a method call with its
    // arguments after a space.
    let head = s
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        .count();
    let target = s.get(..head).unwrap_or_default();
    if head > 2
        && s.first().is_some_and(u8::is_ascii_alphabetic)
        && memchr::memchr(b'.', target).is_some()
        && !target.ends_with(b".")
        && s.get(head) == Some(&b' ')
    {
        let arg = s.get(head..).unwrap_or_default().trim_ascii_start();
        if arg
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'"' | b'('))
            && !arg.starts_with(b"=")
        {
            return Grade::Weak;
        }
    }
    Grade::None
}

/// The right-hand side of `name = value` or `name(i) = value`.
fn vbs_assignment(s: &[u8]) -> Option<&[u8]> {
    let name = s
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        .count();
    if name == 0 || !s.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut rest = s.get(name..)?;
    if rest.first() == Some(&b'(') {
        let close = memchr::memchr(b')', rest)?;
        rest = rest.get(close + 1..)?;
    }
    let rest = rest.trim_ascii_start();
    let rhs = rest.strip_prefix(b"=")?;
    (!rhs.starts_with(b"=")).then(|| rhs.trim_ascii())
}

/// `&H1F`, VBScript's hex literal.
fn has_hex_literal(s: &[u8]) -> bool {
    if memchr::memchr(b'&', s).is_none() {
        return false;
    }
    s.windows(3).enumerate().any(|(i, w)| {
        matches!(w, [b'&', b'H' | b'h', digit] if digit.is_ascii_hexdigit())
            && i.checked_sub(1)
                .and_then(|p| s.get(p))
                .is_none_or(|b| !b.is_ascii_alphanumeric())
    })
}

// ── mIRC ─────────────────────────────────────────────────────────────────

/// Sections of the INI files mIRC saves scripts, aliases and variables in.
const MIRC_SECTIONS: &[&[u8]] = &[
    b"[script]",
    b"[aliases]",
    b"[variables]",
    b"[users]",
    b"[popups]",
];

/// mIRC events a remote script handles. The `on <level>:<EVENT>:` header is
/// mIRC's own syntax; the level varies (`1`, `10`, `*`, `@1`) and so does the
/// event.
const MIRC_EVENTS: &[&[u8]] = &[
    b"action",
    b"active",
    b"agent",
    b"appactive",
    b"ban",
    b"char",
    b"chat",
    b"close",
    b"connect",
    b"connectfail",
    b"ctcpreply",
    b"dccserver",
    b"dehelp",
    b"deop",
    b"devoice",
    b"dialog",
    b"disconnect",
    b"dns",
    b"error",
    b"exit",
    b"filercvd",
    b"filesent",
    b"getfail",
    b"help",
    b"hotlink",
    b"input",
    b"invite",
    b"join",
    b"keydown",
    b"keyup",
    b"kick",
    b"load",
    b"logon",
    b"mode",
    b"mp3end",
    b"nick",
    b"nosound",
    b"notice",
    b"notify",
    b"op",
    b"open",
    b"parseline",
    b"part",
    b"ping",
    b"pong",
    b"quit",
    b"rawmode",
    b"sendfail",
    b"serv",
    b"servermode",
    b"serverop",
    b"signal",
    b"snotice",
    b"sockclose",
    b"socklisten",
    b"sockopen",
    b"sockread",
    b"sockwrite",
    b"start",
    b"text",
    b"topic",
    b"udpread",
    b"udpwrite",
    b"unban",
    b"unload",
    b"unotify",
    b"usermode",
    b"voice",
    b"wallops",
];

/// Identifiers only mIRC's language has: `$+` concatenation, the event
/// identifiers and the file built-ins. ircII shares the `alias name {` form but
/// none of these.
const MIRC_IDENTIFIERS: &[&[u8]] = &[
    b" $+ ",
    b"$+(",
    b"$nick",
    b"$chan",
    b"$me ",
    b"$me)",
    b"$exists(",
    b"$lines(",
    b"$mircdir",
    b"$mircexe",
    b"$findfile(",
    b"$read(",
    b"$readini(",
    b"$decode(",
    b"$encode(",
    b"$gettok(",
    b"$shortfn(",
    b"$sockname",
    b"$sock(",
    b".timer",
    b"sockwrite ",
    b"haltdef",
];

/// Whether `line` uses one of [`MIRC_IDENTIFIERS`]. All but three start with
/// `$`, so a line without one skips the scan.
fn has_mirc_identifier(line: &[u8]) -> bool {
    let dollar = memchr::memchr(b'$', line).is_some();
    let dot = memchr::memchr(b'.', line).is_some();
    MIRC_IDENTIFIERS.iter().any(|id| {
        let needs = match id.first() {
            Some(b'$' | b' ') => dollar,
            Some(b'.') => dot,
            _ => true,
        };
        needs && contains_ci(line, id)
    })
}

/// Commands mIRC scripts run silently with a leading `.`.
const MIRC_QUIET: &[&[u8]] = &[
    b"auser",
    b"copy",
    b"dcc",
    b"disable",
    b"echo",
    b"enable",
    b"ignore",
    b"join",
    b"load",
    b"msg",
    b"nick",
    b"notice",
    b"part",
    b"play",
    b"quit",
    b"raw",
    b"reload",
    b"remote",
    b"remove",
    b"rename",
    b"rlevel",
    b"run",
    b"sockclose",
    b"socklisten",
    b"sockopen",
    b"sockwrite",
    b"timer",
    b"unload",
    b"write",
    b"writeini",
];

fn mirc_line(line: &[u8]) -> Grade {
    let stripped = strip_saved_prefix(line);
    // Every line of a saved script or variables file carries the prefix.
    let saved = stripped.len() < line.len();
    let line = stripped;
    if line.is_empty() {
        return Grade::None;
    }
    if is_mirc_handler(line) || is_mirc_block(line) {
        return Grade::Strong;
    }
    // `.msg $nick hi`, `.timer5 1 30 cmd`: a command run without echo. A
    // method chain (`.run((ctx) -> ...)`) has no space after its name.
    if let Some(rest) = line.strip_prefix(b".") {
        let (verb, tail) = split_verb(rest);
        let command = MIRC_QUIET.iter().any(|q| verb.eq_ignore_ascii_case(q))
            || verb.split_at_checked(5).is_some_and(|(word, suffix)| {
                word.eq_ignore_ascii_case(b"timer") && suffix.iter().all(u8::is_ascii_alphanumeric)
            });
        if command && tail.first().is_none_or(u8::is_ascii_whitespace) {
            return Grade::Strong;
        }
    }
    let identifiers = has_mirc_identifier(line);
    let (verb, rest) = split_verb(line.strip_prefix(b"/").unwrap_or(line));
    let arg = rest.trim_ascii();
    let is = |w: &[u8]| verb.eq_ignore_ascii_case(w);
    if is(b"alias") && is_alias_header(arg) {
        return if identifiers {
            Grade::Strong
        } else {
            Grade::Weak
        };
    }
    // mIRC variables carry a `%` sigil; batch's are wrapped in two.
    if (is(b"var") || is(b"set") || is(b"unset") || is(b"inc") || is(b"dec"))
        && arg.first() == Some(&b'%')
        && arg
            .get(1)
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && count_env_refs(arg) == 0
    {
        return Grade::Strong;
    }
    if is(b"sockopen") || is(b"sockwrite") || is(b"socklisten") || is(b"sockread") {
        return Grade::Strong;
    }
    if identifiers {
        return Grade::Weak;
    }
    // Control flow over identifiers and variables, and timers: the body of
    // an event handler.
    let variables = contains(line, b"$") || contains(line, b"%");
    if (is(b"if") || is(b"elseif") || is(b"while")) && arg.starts_with(b"(") && variables {
        return Grade::Weak;
    }
    if starts_ci(verb, b"timer") && rest.first().is_some_and(u8::is_ascii_whitespace) {
        return Grade::Weak;
    }
    if line.first() == Some(&b'/') && variables {
        return Grade::Weak;
    }
    if saved {
        return Grade::Weak;
    }
    // mIRC comments.
    if line.starts_with(b";") {
        return Grade::Weak;
    }
    Grade::None
}

/// `n12=` in front of every line of a saved script.
fn strip_saved_prefix(line: &[u8]) -> &[u8] {
    if let Some(numbered) = line.strip_prefix(b"n") {
        let digits = numbered.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0
            && let Some(body) = numbered.get(digits..).and_then(|r| r.strip_prefix(b"="))
        {
            return body.trim_ascii_start();
        }
    }
    line
}

/// `on 1:TEXT:`, `on *:JOIN:`, `on @10:PART:`, `ctcp 1:VERSION:`, `raw 311:*:`.
fn is_mirc_handler(line: &[u8]) -> bool {
    let (verb, rest) = split_verb(line);
    let on = verb.eq_ignore_ascii_case(b"on");
    if !(on || verb.eq_ignore_ascii_case(b"ctcp") || verb.eq_ignore_ascii_case(b"raw"))
        || !rest.first().is_some_and(u8::is_ascii_whitespace)
    {
        return false;
    }
    let rest = rest.trim_ascii_start();
    let level_len = rest
        .iter()
        .take_while(|&&b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'*' | b'@' | b'!' | b'+' | b'&' | b'^' | b'$' | b'=')
        })
        .count();
    if level_len == 0 || level_len > 12 || rest.get(level_len) != Some(&b':') {
        return false;
    }
    let event = rest.get(level_len + 1..).unwrap_or_default();
    let word_len = event
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'*')
        .count();
    if word_len == 0 || event.get(word_len) != Some(&b':') {
        return false;
    }
    let word = event.get(..word_len).unwrap_or_default();
    !on || MIRC_EVENTS.iter().any(|e| e.eq_ignore_ascii_case(word))
}

/// `menu nicklist {`, `dialog name {`, `#group on`.
fn is_mirc_block(line: &[u8]) -> bool {
    let (verb, rest) = split_verb(line);
    let arg = rest.trim_ascii();
    if verb.eq_ignore_ascii_case(b"menu") || verb.eq_ignore_ascii_case(b"dialog") {
        return arg.ends_with(b"{") && arg.len() > 1;
    }
    if let Some(group) = line.strip_prefix(b"#") {
        let (name, state) = split_verb(group);
        let state = state.trim_ascii();
        return !name.is_empty()
            && (state.eq_ignore_ascii_case(b"on")
                || state.eq_ignore_ascii_case(b"off")
                || state.eq_ignore_ascii_case(b"end"));
    }
    false
}

/// What follows `alias`: an optional `-l`, a name, then a block or a command.
fn is_alias_header(arg: &[u8]) -> bool {
    let arg = match arg.split_at_checked(b"-l ".len()) {
        Some((flag, tail)) if flag.eq_ignore_ascii_case(b"-l ") => tail.trim_ascii_start(),
        _ => arg,
    };
    let name = arg
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        .count();
    name > 0 && arg.get(name).is_none_or(u8::is_ascii_whitespace)
}

// ── ircII ────────────────────────────────────────────────────────────────

/// ircII / EPIC / BitchX hook events.
const IRCII_EVENTS: &[&[u8]] = &[
    b"action",
    b"channel_nick",
    b"channel_signoff",
    b"channel_sync",
    b"connect",
    b"ctcp",
    b"ctcp_reply",
    b"dcc_chat",
    b"dcc_connect",
    b"dcc_list",
    b"dcc_lost",
    b"dcc_offer",
    b"dcc_raw",
    b"dcc_request",
    b"disconnect",
    b"encrypted_notice",
    b"encrypted_privmsg",
    b"exec",
    b"exec_errors",
    b"exec_exit",
    b"exec_prompt",
    b"exit",
    b"flood",
    b"general_notice",
    b"general_privmsg",
    b"help",
    b"hook",
    b"idle",
    b"input",
    b"invite",
    b"join",
    b"kick",
    b"kill",
    b"leave",
    b"list",
    b"mail",
    b"mode",
    b"mode_stripped",
    b"msg",
    b"msg_group",
    b"names",
    b"nickname",
    b"note",
    b"notice",
    b"notify_signoff",
    b"notify_signon",
    b"oper_notice",
    b"part",
    b"pong",
    b"public",
    b"public_msg",
    b"public_notice",
    b"public_other",
    b"raw_irc",
    b"redirect",
    b"send_action",
    b"send_ctcp",
    b"send_dcc_chat",
    b"send_msg",
    b"send_notice",
    b"send_public",
    b"send_to_server",
    b"server_notice",
    b"set",
    b"signoff",
    b"silence",
    b"status_update",
    b"switch_channels",
    b"switch_windows",
    b"timer",
    b"topic",
    b"wallop",
    b"who",
    b"whois",
    b"whois_name",
    b"widelist",
    b"window",
    b"window_create",
    b"window_kill",
    b"yell",
];

fn ircii_line(line: &[u8]) -> Grade {
    // `^cmd` runs a command silently; `/cmd` is how a command is typed.
    let (prefixed, body) = match line.split_first() {
        Some((b'^' | b'/', body)) => (true, body),
        _ => (false, line),
    };
    if is_ircii_handler(body) {
        return Grade::Strong;
    }
    if is_ircii_assignment(line) {
        return Grade::Strong;
    }
    let (verb, rest) = split_verb(body);
    let arg = rest.trim_ascii();
    let is = |w: &[u8]| verb.eq_ignore_ascii_case(w);
    let spaced = rest.first().is_some_and(u8::is_ascii_whitespace);
    if !spaced && !rest.is_empty() {
        return Grade::None;
    }
    if is(b"xecho") || is(b"xeval") || is(b"xtype") || is(b"xquote") {
        return Grade::Strong;
    }
    if is(b"bind") && (arg.starts_with(b"^") || starts_ci(arg, b"meta")) {
        return Grade::Strong;
    }
    if is(b"assign") && is_identifier_start(arg.strip_prefix(b"-").unwrap_or(arg)) {
        return if prefixed { Grade::Strong } else { Grade::Weak };
    }
    if is(b"set") && prefixed && is_identifier_start(arg) {
        return Grade::Strong;
    }
    if is(b"alias") && is_alias_header(arg) {
        // `alias wa whois $.`, `alias d- ^set display off`: a body in ircII's
        // own variables or silenced commands.
        let body = split_verb(arg.strip_prefix(b"-l ").unwrap_or(arg)).1;
        let ircii_body = has_ircii_identifier(body)
            || contains(body, b" ^")
            || body.trim_ascii_start().starts_with(b"^");
        return if prefixed || ircii_body {
            Grade::Strong
        } else {
            Grade::Weak
        };
    }
    if is(b"load") && !arg.is_empty() && !contains(arg, b" ") {
        return Grade::Weak;
    }
    if line.starts_with(b"^")
        && (is(b"local") || is(b"stack") || is(b"timer") || is(b"eval") || is(b"on"))
    {
        return Grade::Strong;
    }
    if has_ircii_identifier(line) {
        return Grade::Weak;
    }
    // Syntax both IRC clients share: control flow over `$` variables,
    // commands typed with their slash, and ircII's `#` comments.
    let variables = contains(line, b"$");
    if (is(b"if") || is(b"while") || is(b"foreach") || is(b"fe"))
        && arg.starts_with(b"(")
        && variables
    {
        return Grade::Weak;
    }
    if (line.starts_with(b"/") && variables) || line.starts_with(b"# ") || line == b"#" {
        return Grade::Weak;
    }
    Grade::None
}

/// `on [modes]event [serial] "pattern" ...` -- `on ^msg "*" {`,
/// `on #-public 7763 '% *' {`, `on -join * ^tk.add $0`. mIRC's `on 1:TEXT:`
/// has a level and colons where this has modes and a pattern.
fn is_ircii_handler(body: &[u8]) -> bool {
    let (verb, rest) = split_verb(body);
    if !verb.eq_ignore_ascii_case(b"on") || !rest.first().is_some_and(u8::is_ascii_whitespace) {
        return false;
    }
    let rest = rest.trim_ascii_start();
    let modes = rest
        .iter()
        .take_while(|b| matches!(b, b'^' | b'-' | b'+' | b'#' | b'@' | b'&' | b'%' | b'!'))
        .count();
    let event_part = rest.get(modes..).unwrap_or_default();
    let event_len = event_part
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    if event_len == 0
        || !event_part
            .get(event_len)
            .is_some_and(u8::is_ascii_whitespace)
    {
        return false;
    }
    let Some((event, after_event)) = event_part.split_at_checked(event_len) else {
        return false;
    };
    let known = (event_len == 3 && event.iter().all(u8::is_ascii_digit))
        || IRCII_EVENTS.iter().any(|e| e.eq_ignore_ascii_case(event));
    if !known {
        return false;
    }
    let mut pattern = after_event.trim_ascii_start();
    // A serial number orders hooks on the same event: `on #-msg 55 * ...`.
    let serial = pattern
        .iter()
        .enumerate()
        .take_while(|(i, b)| b.is_ascii_digit() || (*i == 0 && **b == b'-'))
        .count();
    if serial > 0 && pattern.get(serial).is_some_and(u8::is_ascii_whitespace) {
        pattern = pattern.get(serial..).unwrap_or_default().trim_ascii_start();
    }
    match pattern.first() {
        Some(b'"' | b'\'' | b'*' | b'%') => true,
        Some(_) => modes > 0,
        None => false,
    }
}

/// `@ x = 1`, `@ :local = [$0]`, `@ count++` -- ircII's expression statement.
fn is_ircii_assignment(line: &[u8]) -> bool {
    let Some(rest) = line.strip_prefix(b"@") else {
        return false;
    };
    if !rest.first().is_some_and(u8::is_ascii_whitespace) {
        return false;
    }
    let rest = rest.trim_ascii_start();
    let rest = rest.strip_prefix(b":").unwrap_or(rest);
    let name = rest
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'[' | b']' | b'$'))
        .count();
    if name == 0 {
        return false;
    }
    let op = rest.get(name..).unwrap_or_default().trim_ascii_start();
    (op.starts_with(b"=") && !op.starts_with(b"=="))
        || op.starts_with(b"++")
        || op.starts_with(b"--")
        || op.starts_with(b"+=")
        || op.starts_with(b"-=")
        || op.starts_with(b"#=")
}

/// `$0-`, `[$1]`, `$[10]0`, `$*`, `$N`, `##` joins. `$1` and `$2-` are mIRC's
/// too; ircII counts its words from `$0`, and `$*`, `$,` and `$.` name the
/// whole argument list, the last sender and the last recipient.
fn has_ircii_identifier(line: &[u8]) -> bool {
    if memchr::memchr2(b'$', b'#', line).is_none() {
        return false;
    }
    contains(line, b"[$")
        || contains(line, b"$[")
        || contains(line, b" ## ")
        || line.ends_with(b"$*")
        || line.ends_with(b"$,")
        || line.ends_with(b"$.")
        || line.windows(3).any(|w| {
            matches!(
                w,
                [b'$', b'0', b'-' | b' ' | b']' | b')']
                    | [b'$', b'*' | b',' | b'.', b' ' | b')' | b']']
            ) || matches!(w, [b'$', b'N' | b'C' | b'T', c] if !c.is_ascii_alphanumeric())
        })
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

/// Whether the window carries the control bytes of object code. Tab, the line
/// breaks and form feed occur in any text; so do ESC (ANSI colour in `echo`
/// lines), SUB (the DOS end-of-file mark), and IRC's formatting codes -- bold,
/// colour, reset, reverse, italic, underline -- which mIRC scripts put in the
/// messages they send.
///
/// The same share-of-the-window test as `heuristics::looks_like_binary`, which
/// excuses none of these: the languages it scores do not print them, and a
/// line grammar has to read past them.
fn is_binary(window: &[u8]) -> bool {
    let text_control = |b: u8| {
        matches!(
            b,
            b'\t' | b'\n' | b'\r' | 0x0C | 0x1A | 0x1B | 0x02 | 0x03 | 0x0F | 0x16 | 0x1D | 0x1F
        )
    };
    let control = window
        .iter()
        .filter(|&&b| (b < 0x20 && !text_control(b)) || b == 0x7F)
        .count();
    control * 100 > window.len() * 3 && (window.len() >= 64 || control >= 3)
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

fn starts_ci(s: &[u8], prefix: &[u8]) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Whether `needle` occurs in `hay`. The needles here are a few bytes long
/// and the lines short, where a `memchr` on the first byte beats building a
/// substring searcher per call.
pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return false;
    };
    memchr::memchr_iter(first, hay)
        .any(|at| hay.get(at + 1..).is_some_and(|tail| tail.starts_with(rest)))
}

pub(crate) fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    find_ci(hay, needle).is_some()
}

#[cfg(test)]
mod tests;
