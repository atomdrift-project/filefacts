//! Document shapes: text that is data or prose, not a language, however
//! many of a language's keywords it quotes.
//!
//! Two kinds live here. [`TEXT_SHAPES`] is the identification rule table: a
//! document in one of these shapes is [`FileType::Text`] ahead of the marks
//! and the language scorer. The scorer's guards -- a sectioned key/value
//! config, structured data, prose -- are judged by the scorer itself, because
//! they only decide that it has no language to name.
//!
//! Two other text verdicts are not here, because their precedence differs: a
//! Windows URL shortcut is a signature (its section names it whatever the
//! file is called), and a roff manual page is a mark (it yields to a language
//! name whose body carries that language).

use super::{
    FileType,
    heuristics::SCAN_LIMIT,
    sniff::Sniff,
    text::{self, Controls, contains_ci, is_binary, starts_ci, strip_utf8_bom},
};

/// Whether a document has a shape.
type Holds = fn(&Sniff<'_>) -> bool;

/// The document shapes identification settles as [`FileType::Text`], each
/// named for the decision log. Each checks the name it needs itself; binary
/// magic and executable shebangs have already won.
pub(super) const TEXT_SHAPES: &[(&str, Holds)] = &[
    ("gcc_specs", gcc_specs),
    ("git_config", |sniff| sniff.looks_like_git_config()),
    ("ftp_command_script", ftp_command_script),
    ("rexx_cms_exec", rexx_cms_exec),
    ("sap_abap_report", sap_abap_report),
    ("restructuredtext_document", restructuredtext_document),
];

/// The name of the first shape `sniff` has.
pub(super) fn shape_of(sniff: &Sniff<'_>) -> Option<&'static str> {
    TEXT_SHAPES
        .iter()
        .find(|(_, holds)| holds(sniff))
        .map(|&(name, _)| name)
}

/// GCC's extensionless specs files contain named `*spec:` sections. A name
/// alone is ambiguous, so both the filename and a section header are
/// required.
fn gcc_specs(sniff: &Sniff<'_>) -> bool {
    let data = sniff.data;
    sniff.path.file_name().is_some_and(|name| name == "specs")
        && text::head_is_text(data)
        && data.split(|b| *b == b'\n').any(|line| {
            line.trim_ascii()
                .strip_prefix(b"*")
                .and_then(|s| s.strip_suffix(b":"))
                .is_some_and(|name| {
                    !name.is_empty() && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                })
        })
}

/// CMS REXX EXECs may be extensionless and otherwise look like comment-led
/// prose. A bounded combination of REXX statements and CMS I/O, under no
/// name or a prose one.
fn rexx_cms_exec(sniff: &Sniff<'_>) -> bool {
    sniff.ext_type().is_none_or(|ft| ft == FileType::Text) && looks_like_cms_exec(sniff.text())
}

/// Extensionless ABAP report source with SAP repository I/O, under no name
/// or a prose one.
fn sap_abap_report(sniff: &Sniff<'_>) -> bool {
    sniff.ext_type().is_none_or(|ft| ft == FileType::Text) && looks_like_abap_report(sniff.text())
}

/// ReStructuredText documents often contain executable-looking examples. A
/// sectioned `.rst` document with directives or literal blocks is a document
/// by its content, even when those examples score as a language or carry
/// another format's mark.
///
/// A Python `.doctest` file is the same kind of document: sectioned
/// reStructuredText whose examples are `>>>` interpreter sessions rather than
/// `::` literal blocks (NLTK's `semantics.doctest`). Its prompts are the
/// examples; the headings are what make it a document.
fn restructuredtext_document(sniff: &Sniff<'_>) -> bool {
    match super::ext::lowercase_ext(sniff.path).as_deref() {
        Some("rst") => {
            sniff.ext_type() == Some(FileType::Text) && rst_document_structure(sniff.data, false)
        }
        Some("doctest") => rst_document_structure(sniff.data, true),
        _ => false,
    }
}

/// How much of a REXX or ABAP source is read.
const SOURCE_WINDOW: usize = 128 * 1024;

/// A CMS EXEC: a leading comment, then `SAY`, `PULL`, `DO WHILE`, `END` and
/// an `EXECIO` command, outside comments.
fn looks_like_cms_exec(data: &[u8]) -> bool {
    let data = data.get(..SOURCE_WINDOW).unwrap_or(data);
    if !data.trim_ascii_start().starts_with(b"/*") || is_binary(data, Controls::Script) {
        return false;
    }
    let mut in_comment = false;
    let mut say = false;
    let mut pull = false;
    let mut loop_stmt = false;
    let mut end = false;
    let mut execio = false;
    // One buffer for every line's code outside comments.
    let mut code = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        code.clear();
        let mut i = 0;
        while let Some(&byte) = line.get(i) {
            if in_comment {
                if line.get(i..i + 2) == Some(b"*/") {
                    in_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
            } else if line.get(i..i + 2) == Some(b"/*") {
                in_comment = true;
                i += 2;
            } else {
                code.push(byte);
                i += 1;
            }
        }
        let s = code.trim_ascii();
        say |= starts_ci(s, b"SAY ");
        pull |= starts_ci(s, b"PULL ");
        loop_stmt |= starts_ci(s, b"DO WHILE ");
        end |= s.eq_ignore_ascii_case(b"END") || starts_ci(s, b"END ");
        execio |= starts_ci(s, b"\"EXECIO ") || starts_ci(s, b"'EXECIO ");
    }
    say && pull && loop_stmt && end && execio
}

/// An ABAP report: `REPORT`, `READ REPORT ... INTO`, `LOOP AT` and
/// `ENDLOOP.`, outside comments.
fn looks_like_abap_report(data: &[u8]) -> bool {
    let data = data.get(..SOURCE_WINDOW).unwrap_or(data);
    if is_binary(data, Controls::Text) {
        return false;
    }
    let mut report = false;
    let mut read_report = false;
    let mut loop_at = false;
    let mut endloop = false;
    for line in data.split(|&b| b == b'\n') {
        // In ABAP, '*' starts a comment only in column one, and '"' runs one
        // to the end of the line; the statements sought have no string
        // operands to cut.
        if line.starts_with(b"*") {
            continue;
        }
        let code = line.split(|&b| b == b'"').next().unwrap_or_default();
        let s = code.trim_ascii();
        report |= starts_ci(s, b"REPORT ") && s.contains(&b'.');
        read_report |= starts_ci(s, b"READ REPORT ") && contains_ci(s, b" INTO ");
        loop_at |= starts_ci(s, b"LOOP AT ");
        endloop |= starts_ci(s, b"ENDLOOP.");
    }
    report && read_report && loop_at && endloop
}

/// A line-oriented FTP client command file is data for the FTP client, not
/// source code merely because its name ends in a language extension. Require
/// the full connect / binary / download / exit sequence in order, so a single
/// quoted or documented FTP command cannot override a source-file claim.
fn ftp_command_script(sniff: &Sniff<'_>) -> bool {
    ftp_commands(sniff.data).is_some()
}

/// `Some` when `data` is the command sequence [`ftp_command_script`] wants.
fn ftp_commands(data: &[u8]) -> Option<()> {
    if data.len() > 4096 || !data.is_ascii() {
        return None;
    }
    let mut lines = data
        .split(|b| *b == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|line| !line.is_empty());
    let mut first = lines
        .next()?
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty());
    if !first.next()?.eq_ignore_ascii_case(b"open") {
        return None;
    }
    let host = first.next()?;
    if host.is_empty()
        || !host
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    {
        return None;
    }
    if let Some(port) = first.next() {
        let valid_port = std::str::from_utf8(port)
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .is_some_and(|n| n > 0);
        if !valid_port || first.next().is_some() {
            return None;
        }
    }
    let mut binary = false;
    let mut get = false;
    let mut ended = false;
    for line in lines {
        if ended {
            return None;
        }
        if line
            .iter()
            .any(|b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
        {
            return None;
        }
        if line.eq_ignore_ascii_case(b"binary") || line.eq_ignore_ascii_case(b"bin") {
            binary = true;
        } else if get && (line.eq_ignore_ascii_case(b"bye") || line.eq_ignore_ascii_case(b"quit")) {
            ended = true;
        } else if binary {
            let mut words = line
                .split(u8::is_ascii_whitespace)
                .filter(|s| !s.is_empty());
            if words
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case(b"get"))
                && words.next().is_some()
            {
                get = true;
            }
        }
    }
    ended.then_some(())
}

/// How much of a reStructuredText document is read.
const RST_WINDOW: usize = 16 * 1024;

/// Two or more underlined headings, and a directive or a literal block.
/// `doctest_prompts` lets a `>>> ` interpreter prompt stand for the literal
/// block, as it does in a doctest file.
fn rst_document_structure(data: &[u8], doctest_prompts: bool) -> bool {
    let data = strip_utf8_bom(data);
    let head = data.get(..RST_WINDOW).unwrap_or(data);
    let lines: Vec<&[u8]> = head.split(|b| *b == b'\n').collect();
    let mut headings = 0;
    let mut directive = false;
    let mut literal_block = false;

    for (index, raw_line) in lines.iter().enumerate() {
        let line = raw_line
            .strip_suffix(b"\r")
            .unwrap_or(raw_line)
            .trim_ascii();
        if line.starts_with(b".. ") && line.windows(2).any(|w| w == b"::") {
            directive = true;
        }
        if doctest_prompts && line.starts_with(b">>> ") {
            literal_block = true;
        }
        if line.ends_with(b"::") {
            literal_block |= lines
                .get(index + 1..)
                .unwrap_or_default()
                .iter()
                .take(4)
                .map(|next| next.strip_suffix(b"\r").unwrap_or(next))
                .find(|next| !next.trim_ascii().is_empty())
                .is_some_and(|next| next.first().is_some_and(u8::is_ascii_whitespace));
        }
        if line.len() < 3 {
            continue;
        }
        let Some(previous) = index.checked_sub(1).and_then(|i| lines.get(i)) else {
            continue;
        };
        let previous = previous
            .strip_suffix(b"\r")
            .unwrap_or(previous)
            .trim_ascii();
        if previous.is_empty() || previous.len() > 120 || !previous.is_ascii() {
            continue;
        }
        if line.first().is_some_and(|&rule| {
            matches!(
                rule,
                b'=' | b'-' | b'~' | b'^' | b'"' | b'`' | b':' | b'#' | b'*' | b'+' | b'_'
            ) && line.iter().all(|b| *b == rule)
        }) {
            headings += 1;
        }
    }

    headings >= 2 && (directive || literal_block)
}

/// Recognize Git's config syntax from a bounded prefix. `.git/config` has no
/// extension and content is its only reliable identity; content must also win
/// over a misleading filename such as `Makefile` or `settings.py`.
pub(super) fn looks_like_git_config(data: &[u8]) -> bool {
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
    let head = data.get(..SCAN_LIMIT).unwrap_or(data);
    if head.is_empty() || is_binary(head, Controls::Text) {
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

        if let Some(name) = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")) {
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

        let Some(key) = line
            .iter()
            .position(|&byte| byte == b'=')
            .and_then(|equal| line.get(..equal))
        else {
            continue;
        };
        let key = key.trim_ascii();
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
    let Some((prefix, rest)) = header.split_at_checked(name.len()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case(name)
        && rest.starts_with(b" \"")
        && rest.len() > 3
        && rest.ends_with(b"\"")
}

/// Significant lines a document needs before its shape is judged as YAML. Short
/// fragments carry too little structure to separate a mapping from prose.
const MIN_YAML_LINES: usize = 5;

/// Only inputs at least this large are screened by [`looks_like_prose`]: a
/// tiny script (`echo hi`) can legitimately have no code punctuation at all,
/// and a mis-typed tiny file costs nothing to parse.
pub(super) const PROSE_GUARD_MIN_BYTES: usize = 1024;

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

/// True when `head` reads like natural-language text rather than source.
///
/// Measured on the first 4 KiB: prose (novels, licenses) has 0.15-0.3% code
/// punctuation with ~4% of lines carrying any; minified JS 6.5% / 93%, Rust
/// 3.5% / 58%, a Makefile 4.1% / 91%, and even a Markdown README with embedded
/// snippets 2.8% / 30%. Both thresholds sit well inside that gap, and both must
/// hold — a file has to look like prose on the byte *and* the line axis.
pub(super) fn looks_like_prose(head: &[u8]) -> bool {
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
pub(super) fn looks_like_ini_config(data: &[u8]) -> bool {
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
pub(super) fn looks_like_structured_data(data: &[u8]) -> bool {
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
    matches!(value.get(1), None | Some(b' ' | b'\r'))
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

#[cfg(test)]
mod tests;
