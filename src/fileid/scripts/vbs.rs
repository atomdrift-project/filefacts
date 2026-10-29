//! The VBScript grammar: a line as the Windows Script Host parses it.

use super::{
    Grade, contains, contains_ci, find_ci, find_word_ci, is_identifier_start, is_plain_identifier,
    split_verb, starts_ci,
};

pub(super) fn vbs_line(line: &[u8]) -> Grade {
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
pub(super) const VB_NET_BLOCKS: &[&[u8]] = &[
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
pub(super) fn vbs_object_expr(rhs: &[u8]) -> bool {
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
