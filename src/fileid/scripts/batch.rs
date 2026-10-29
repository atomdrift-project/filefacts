//! The batch grammar: a line as cmd.exe reads it.

use super::{Grade, contains, contains_ci, find_ci, split_verb, starts_ci, vbs_object_expr};

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
pub(super) fn batch_opener(line: &[u8]) -> bool {
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
pub(super) fn batch_line(line: &[u8]) -> Grade {
    // Raw ANSI.SYS keyboard assignments are commonly emitted by DOS batch
    // scripts. The surrounding batch opener supplies the language evidence.
    if line.starts_with(b"\x1b[") && line.ends_with(b"p") && line.contains(&b';') {
        return Grade::Weak;
    }
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
pub(super) fn count_env_refs(s: &[u8]) -> usize {
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
