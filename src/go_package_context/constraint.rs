//! Go build constraints, as `go/build` applies them: the `//go:build` line
//! (or, without one, `// +build` lines) in a file's leading comment block,
//! and the `_GOOS`, `_GOARCH` and `_GOOS_GOARCH` file-name suffixes.

/// A port `go/build` can target, with whether cgo is on by default there
/// (`cgoEnabled` in `go/build`'s generated port table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Platform {
    pub(super) goos: &'static str,
    pub(super) goarch: &'static str,
    pub(super) cgo: bool,
}

const fn port(goos: &'static str, goarch: &'static str, cgo: bool) -> Platform {
    Platform { goos, goarch, cgo }
}

/// Every port `go tool dist list` reports.
pub(super) const PLATFORMS: &[Platform] = &[
    port("aix", "ppc64", true),
    port("android", "386", true),
    port("android", "amd64", true),
    port("android", "arm", true),
    port("android", "arm64", true),
    port("darwin", "amd64", true),
    port("darwin", "arm64", true),
    port("dragonfly", "amd64", true),
    port("freebsd", "386", true),
    port("freebsd", "amd64", true),
    port("freebsd", "arm", true),
    port("freebsd", "arm64", true),
    port("freebsd", "riscv64", true),
    port("illumos", "amd64", true),
    port("ios", "amd64", true),
    port("ios", "arm64", true),
    port("js", "wasm", false),
    port("linux", "386", true),
    port("linux", "amd64", true),
    port("linux", "arm", true),
    port("linux", "arm64", true),
    port("linux", "loong64", true),
    port("linux", "mips", true),
    port("linux", "mips64", true),
    port("linux", "mips64le", true),
    port("linux", "mipsle", true),
    port("linux", "ppc64", false),
    port("linux", "ppc64le", true),
    port("linux", "riscv64", true),
    port("linux", "s390x", true),
    port("netbsd", "386", true),
    port("netbsd", "amd64", true),
    port("netbsd", "arm", true),
    port("netbsd", "arm64", true),
    port("openbsd", "386", true),
    port("openbsd", "amd64", true),
    port("openbsd", "arm", true),
    port("openbsd", "arm64", true),
    port("openbsd", "ppc64", false),
    port("openbsd", "riscv64", true),
    port("plan9", "386", false),
    port("plan9", "amd64", false),
    port("plan9", "arm", false),
    port("solaris", "amd64", true),
    port("wasip1", "wasm", false),
    port("windows", "386", true),
    port("windows", "amd64", true),
    port("windows", "arm", false),
    port("windows", "arm64", true),
];

/// `knownOS` in `go/build/syslist.go`: every GOOS a file-name suffix can
/// name, past and future ports included.
const KNOWN_OS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "nacl",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];

/// `unixOS` in `go/build/syslist.go`: the GOOS values that satisfy `unix`.
const UNIX_OS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "linux",
    "netbsd",
    "openbsd",
    "solaris",
];

/// `knownArch` in `go/build/syslist.go`.
const KNOWN_ARCH: &[&str] = &[
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "armbe",
    "arm64",
    "arm64be",
    "loong64",
    "mips",
    "mipsle",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
];

impl Platform {
    /// Whether the default build context for this port satisfies `name`
    /// (`matchTag` in `go/build`): its GOOS and GOARCH, the GOOS a port
    /// implies (`android` builds `linux` files, `illumos` `solaris`, `ios`
    /// `darwin`), `unix`, `cgo` where enabled, the `gc` compiler, and every
    /// `go1.N` release tag (the toolchain is assumed new enough). Custom
    /// tags, `gccgo` and `goexperiment.*` are unset.
    pub(super) fn has_tag(&self, name: &str) -> bool {
        name == self.goos
            || name == self.goarch
            || name == "gc"
            || (name == "cgo" && self.cgo)
            || (name == "linux" && self.goos == "android")
            || (name == "solaris" && self.goos == "illumos")
            || (name == "darwin" && self.goos == "ios")
            || (name == "unix" && UNIX_OS.contains(&self.goos))
            || name
                .strip_prefix("go1.")
                .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()))
    }
}

/// Whether a file named `name` (no directory) builds where `tag` holds,
/// judged by its name alone (`goodOSArchFile` in `go/build`). Everything
/// from the first `.` is ignored, then everything before the first `_`;
/// a trailing `_test` is dropped; what remains may end in `_GOOS_GOARCH`,
/// `_GOOS` or `_GOARCH`, with only known names counting.
pub(super) fn file_name_matches(name: &str, tag: &impl Fn(&str) -> bool) -> bool {
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    let Some(underscore) = stem.find('_') else {
        return true;
    };
    let mut parts: Vec<&str> = stem[underscore..].split('_').collect();
    if parts.last() == Some(&"test") {
        parts.pop();
    }
    match parts.as_slice() {
        [.., os, arch] if KNOWN_OS.contains(os) && KNOWN_ARCH.contains(arch) => {
            tag(arch) && tag(os)
        }
        [.., last] if KNOWN_OS.contains(last) || KNOWN_ARCH.contains(last) => tag(last),
        _ => true,
    }
}

/// A build constraint expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Expr {
    Tag(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// The expression's value where `tag` says which tags hold.
    pub(super) fn eval(&self, tag: &impl Fn(&str) -> bool) -> bool {
        match self {
            Self::Tag(name) => tag(name),
            Self::Not(x) => !x.eval(tag),
            Self::And(x, y) => x.eval(tag) && y.eval(tag),
            Self::Or(x, y) => x.eval(tag) || y.eval(tag),
        }
    }

    fn and(x: Self, y: Self) -> Self {
        Self::And(Box::new(x), Box::new(y))
    }

    fn or(x: Self, y: Self) -> Self {
        Self::Or(Box::new(x), Box::new(y))
    }
}

/// Why a file's constraint could not be read; `go/build` refuses to build
/// such a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConstraintError {
    /// More than one `//go:build` line.
    MultipleGoBuild,
    /// The `//go:build` expression does not parse.
    Syntax(&'static str),
}

impl std::fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultipleGoBuild => f.write_str("multiple //go:build comments"),
            Self::Syntax(error) => write!(f, "parsing //go:build line: {error}"),
        }
    }
}

/// The build constraint of Go source `content` (`shouldBuild` in
/// `go/build`): its `//go:build` expression when the leading comment block
/// has one, else the conjunction of its `// +build` lines, else `None`.
/// Only the block before the first non-comment text counts, and a
/// `// +build` line only when a blank line follows it inside that block.
pub(super) fn file_constraint(content: &str) -> Result<Option<Expr>, ConstraintError> {
    let (header, go_build) = file_header(content)?;
    if let Some(line) = go_build {
        let expr = line
            .strip_prefix("//go:build")
            .ok_or(ConstraintError::Syntax("missing //go:build prefix"))?;
        return parse_expr(expr.trim())
            .map(Some)
            .map_err(ConstraintError::Syntax);
    }
    let mut constraint: Option<Expr> = None;
    for line in header.lines().map(str::trim) {
        let Some(expr) = line.strip_prefix("//").and_then(plus_build) else {
            continue;
        };
        // A malformed `+build` line is ignored, as `go/build` ignores it.
        if let Some(expr) = parse_plus_build(expr) {
            constraint = Some(match constraint {
                Some(previous) => Expr::and(previous, expr),
                None => expr,
            });
        }
    }
    Ok(constraint)
}

/// The leading comment block of `content` (`parseFileHeader` in
/// `go/build`): the text through the last blank line before the first
/// non-comment text, and the block's `//go:build` line, if any.
fn file_header(content: &str) -> Result<(&str, Option<&str>), ConstraintError> {
    let mut end = 0;
    let mut ended = false;
    let mut in_block_comment = false;
    let mut go_build = None;
    let mut rest = content;
    'lines: while !rest.is_empty() {
        let (line, next) = rest.split_once('\n').unwrap_or((rest, ""));
        rest = next;
        let mut line = line.trim();
        if line.is_empty() && !ended {
            end = content.len() - rest.len();
            continue;
        }
        if !line.starts_with("//") {
            ended = true;
        }
        if !in_block_comment && is_go_build(line) {
            if go_build.is_some() {
                return Err(ConstraintError::MultipleGoBuild);
            }
            go_build = Some(line);
        }
        while !line.is_empty() {
            if in_block_comment {
                let Some(close) = line.find("*/") else {
                    continue 'lines;
                };
                in_block_comment = false;
                line = line[close + 2..].trim();
                continue;
            }
            if line.starts_with("//") {
                continue 'lines;
            }
            if let Some(after) = line.strip_prefix("/*") {
                in_block_comment = true;
                line = after.trim();
                continue;
            }
            break 'lines;
        }
    }
    Ok((&content[..end], go_build))
}

/// Whether trimmed `line` is a `//go:build` line rather than, say,
/// `//go:buildx`.
fn is_go_build(line: &str) -> bool {
    line.strip_prefix("//go:build")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
}

/// The expression of a `+build` comment body (the text after `//`), or
/// `None` when it is not one.
fn plus_build(comment: &str) -> Option<&str> {
    let rest = comment.trim().strip_prefix("+build")?;
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then(|| rest.trim())
}

/// Most operators a `+build` line may combine, as in `go/build/constraint`.
const MAX_PLUS_BUILD_OPERATORS: usize = 100;

/// A `+build` expression: space-separated alternatives of comma-separated
/// conjunctions of optionally negated tags. An invalid tag reads as the
/// never-set `ignore`; too many operators make the line unreadable.
fn parse_plus_build(text: &str) -> Option<Expr> {
    let mut operators = 0;
    let mut alternatives: Option<Expr> = None;
    for clause in text.split_whitespace() {
        let mut conjunction: Option<Expr> = None;
        for literal in clause.split(',') {
            let term = if literal.starts_with("!!") || literal == "!" {
                Expr::Tag("ignore".into())
            } else {
                let (negated, name) = literal
                    .strip_prefix('!')
                    .map_or((false, literal), |name| (true, name));
                let tag = Expr::Tag(if is_valid_tag(name) { name } else { "ignore" }.into());
                if negated {
                    Expr::Not(Box::new(tag))
                } else {
                    tag
                }
            };
            conjunction = Some(match conjunction {
                Some(previous) => {
                    operators += 1;
                    if operators > MAX_PLUS_BUILD_OPERATORS {
                        return None;
                    }
                    Expr::and(previous, term)
                }
                None => term,
            });
        }
        let Some(conjunction) = conjunction else {
            continue;
        };
        alternatives = Some(match alternatives {
            Some(previous) => {
                operators += 1;
                if operators > MAX_PLUS_BUILD_OPERATORS {
                    return None;
                }
                Expr::or(previous, conjunction)
            }
            None => conjunction,
        });
    }
    Some(alternatives.unwrap_or_else(|| Expr::Tag("ignore".into())))
}

fn is_valid_tag(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

/// Most terms a `//go:build` expression may hold, as in
/// `go/build/constraint`; it also bounds the parser's recursion.
const MAX_EXPR_SIZE: usize = 1000;

/// Parse a `//go:build` expression: `||` over `&&` over `!` over tags and
/// parenthesized expressions. Double negation is refused, as Go refuses it.
fn parse_expr(text: &str) -> Result<Expr, &'static str> {
    let mut parser = ExprParser {
        text,
        pos: 0,
        token: Token::End,
        size: 0,
    };
    let expr = parser.or()?;
    if parser.token != Token::End {
        return Err("unexpected token");
    }
    Ok(expr)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    End,
    Open,
    Close,
    Not,
    And,
    Or,
    Tag(&'a str),
}

struct ExprParser<'a> {
    text: &'a str,
    pos: usize,
    token: Token<'a>,
    size: usize,
}

impl<'a> ExprParser<'a> {
    fn lex(&mut self) -> Result<(), &'static str> {
        let rest = &self.text[self.pos..];
        let trimmed = rest.trim_start_matches([' ', '\t']);
        self.pos += rest.len() - trimmed.len();
        let (token, len) = match trimmed.as_bytes() {
            [] => (Token::End, 0),
            [b'(', ..] => (Token::Open, 1),
            [b')', ..] => (Token::Close, 1),
            [b'!', ..] => (Token::Not, 1),
            [b'&', b'&', ..] => (Token::And, 2),
            [b'|', b'|', ..] => (Token::Or, 2),
            _ => {
                let len = trimmed
                    .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
                    .unwrap_or(trimmed.len());
                if len == 0 {
                    return Err("invalid syntax");
                }
                (Token::Tag(&trimmed[..len]), len)
            }
        };
        self.token = token;
        self.pos += len;
        Ok(())
    }

    fn or(&mut self) -> Result<Expr, &'static str> {
        let mut expr = self.and()?;
        while self.token == Token::Or {
            expr = Expr::or(expr, self.and()?);
        }
        Ok(expr)
    }

    fn and(&mut self) -> Result<Expr, &'static str> {
        let mut expr = self.not()?;
        while self.token == Token::And {
            expr = Expr::and(expr, self.not()?);
        }
        Ok(expr)
    }

    fn not(&mut self) -> Result<Expr, &'static str> {
        self.size += 1;
        if self.size > MAX_EXPR_SIZE {
            return Err("build expression too large");
        }
        self.lex()?;
        if self.token == Token::Not {
            self.lex()?;
            if self.token == Token::Not {
                return Err("double negation not allowed");
            }
            return Ok(Expr::Not(Box::new(self.atom()?)));
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Expr, &'static str> {
        match self.token {
            Token::Open => {
                let expr = self.or().map_err(|error| {
                    if error == "unexpected end of expression" {
                        "missing close paren"
                    } else {
                        error
                    }
                })?;
                if self.token != Token::Close {
                    return Err("missing close paren");
                }
                self.lex()?;
                Ok(expr)
            }
            Token::Tag(name) => {
                self.lex()?;
                Ok(Expr::Tag(name.into()))
            }
            Token::End => Err("unexpected end of expression"),
            _ => Err("unexpected token"),
        }
    }
}

#[cfg(test)]
mod tests;
