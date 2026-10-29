//! The mIRC and ircII grammars.

use super::{
    Grade, contains, contains_ci, count_env_refs, is_identifier_start, split_verb, starts_ci,
};

/// Sections of the INI files mIRC saves scripts, aliases and variables in.
pub(super) const MIRC_SECTIONS: &[&[u8]] = &[
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

pub(super) fn mirc_line(line: &[u8]) -> Grade {
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

pub(super) fn ircii_line(line: &[u8]) -> Grade {
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
