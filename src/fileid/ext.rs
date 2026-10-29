//! Extension and filename-based detection.

use std::path::Path;

use super::FileType;
use super::file_type::Strength;

/// What a path's name claims the file is, and how much that claim says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Claim {
    /// The type the name implies.
    pub(super) file_type: FileType,
    /// What the claim says about the bytes: the type's own strength, except
    /// where one spelling of a type says more or less than the others.
    pub(super) strength: Strength,
    /// The claim comes from a well-known filename rather than an extension.
    pub(super) by_name: bool,
}

impl Claim {
    /// The claim an extension naming `file_type` makes.
    const fn of(file_type: FileType) -> Self {
        Self {
            file_type,
            strength: file_type.strength(),
            by_name: false,
        }
    }

    /// An extension of a text language that has no analyzer of its own (a
    /// stylesheet, SQL, a config syntax): typed as text, but a language claim
    /// all the same. These syntaxes quote other languages' keywords (`let`,
    /// `-`, braces) densely enough to fool the language scorer, so keyword
    /// scoring does not replace the name; a binary or plainly foreign body
    /// does.
    const fn text_language() -> Self {
        Self {
            strength: Strength::Language,
            ..Self::of(FileType::Text)
        }
    }

    /// Whether the claim names a language: the extension's own strength, or
    /// its type's when a variant suffix weakened the claim.
    pub(super) const fn claims_language(self) -> bool {
        matches!(self.strength, Strength::Language)
            || matches!(self.file_type.strength(), Strength::Language)
    }

    /// Whether the language scorer replaces the claim.
    pub(super) const fn yields_to_scorer(self) -> bool {
        self.strength.yields_to_scorer()
    }

    /// Whether an unmistakable mark replaces the claim. A well-known
    /// filename yields to a mark as far as its type does: a `LICENSE`
    /// holding a manual page is text either way, while a `Makefile` or a
    /// `package.json` stays what it is named.
    pub(super) const fn yields_to_mark(self) -> bool {
        if self.by_name {
            self.file_type.strength().yields_to_mark()
        } else {
            self.strength.yields_to_mark()
        }
    }
}

/// What `path` claims: a well-known filename, then an extension.
pub(super) fn claim(path: &Path) -> Option<Claim> {
    if let Some(file_type) = detect_from_filename(path) {
        return Some(Claim {
            file_type,
            strength: filename_strength(path),
            by_name: true,
        });
    }
    let path_str = path.to_string_lossy();
    if is_github_workflow(&path_str) {
        return Some(Claim {
            file_type: FileType::GithubActions,
            strength: Strength::Named,
            by_name: true,
        });
    }
    let claim = extension_claim(path, &path_str)?;
    Some(if is_variant_suffix(path, claim) {
        Claim {
            strength: Strength::Weak,
            ..claim
        }
    } else {
        claim
    })
}

/// How far a well-known filename is believed against its content: the
/// language scorer may replace it unless its own extension is a claim the
/// scorer may not replace (`package.json`, `Cargo.toml`).
fn filename_strength(path: &Path) -> Strength {
    match detect_from_extension(path) {
        Some(ext) if !ext.yields_to_scorer() => Strength::Named,
        _ => Strength::Weak,
    }
}

/// An extension of one or two characters after a dotted family name
/// (`Trojan.BAT.DelAll.a`, `Backdoor.PHP.Agent.bb`) is a variant letter in a
/// naming scheme, not a type claim: the content decides, and the extension
/// only stands when the content names nothing. A dotted family name has at
/// least three components ahead of the suffix and opens with a capital, which
/// leaves the dotted names source trees use (`jquery.min.js`,
/// `app.component.ts`) alone.
fn is_variant_suffix(path: &Path, claim: Claim) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    claim.strength == Strength::Language
        && (1..=2).contains(&ext.len())
        && stem.bytes().filter(|&b| b == b'.').count() >= 2
        && stem.starts_with(|c: char| c.is_ascii_uppercase())
}

/// The claim a path's extension makes, multi-part suffixes included.
fn extension_claim(path: &Path, path_str: &str) -> Option<Claim> {
    // systemd service drop-ins: *.service.d/*.conf
    if (path_str.contains(".service.d/") || path_str.contains(".service.d\\"))
        && ends_with_ci(path_str.as_bytes(), b".conf")
    {
        return Some(Claim::of(FileType::SystemdService));
    }

    // Archive multi-part extensions (check before single extension)
    let p = path_str.as_bytes();
    if let Some(ft) = suffix_type(p, ARCHIVE_SUFFIXES) {
        return Some(Claim::of(ft));
    }

    // Versioned ELF shared libraries, e.g. libssl.so.3 or libc.so.6.
    if has_versioned_so_suffix(path_str) {
        return Some(Claim::of(FileType::Elf));
    }

    // JAR/WAR/EAR by extension
    if let Some(ft) = suffix_type(p, JAVA_ARCHIVE_SUFFIXES) {
        return Some(Claim::of(ft));
    }

    // mysqltest scripts (`t/*.test`, `include/*.inc`) and their recorded
    // output (`r/*.result`) in MySQL, MariaDB and Percona source trees. The
    // dialect is SQL plus `--source`/`--echo`/`--let` directives, with no
    // analyzer of its own; by content it scores as JavaScript, Python,
    // Clojure or Kotlin depending on the statements in each file, and that
    // language's rules then read test SQL as program code. Same reasoning as
    // `.sql` below. Bound to the directory, since `.test` and `.inc` are
    // generic extensions elsewhere (Tcl tests, PHP and Pascal includes).
    if is_mysqltest_file(path_str) {
        return Some(Claim::text_language());
    }

    // Single extension
    if let Some(claim) = detect_from_extension(path) {
        return Some(claim);
    }

    // Wrapper suffix: `configure-backdoor.c.fragment`, `payload.php.sample`,
    // `index.js.bak`. Incident corpora, quarantine folders and editor backups
    // all append a suffix that says something about the file's provenance and
    // nothing about its format. Without this the real extension is invisible
    // and the file types as unknown.
    //
    // Only a fixed set of wrappers is stripped, and only one layer, so a
    // genuine two-part name (`libc.so.6`, `archive.tar.gz`) still resolves
    // through the multi-part rules above.
    // Only magic-less inner types are accepted. A renamed binary or archive
    // (`note.so.old`) still resolves by content, where its magic decides; a
    // text file has no magic, so the extension under the wrapper is the only
    // evidence there is.
    strip_wrapper_suffix(path)
        .and_then(|inner| detect_from_extension(Path::new(inner)))
        .filter(|claim| is_wrapper_inner_type(claim.file_type))
}

/// Multi-part archive suffixes, tried in order: the first that ends the path
/// names its type, so a longer suffix precedes any shorter one it ends with.
const ARCHIVE_SUFFIXES: &[(&[u8], FileType)] = &[
    // Gentoo GLEP 78 binary package — must precede the `.tar` fallback.
    (b".gpkg.tar", FileType::GentooBinpkg),
    // Arch packages: the `.pkg.tar.*` family is Arch-specific. The zstd/gzip
    // bodies are confirmed by the `.PKGINFO` content scan; the xz body and the
    // uncompressed `.pkg.tar` can't be read, so the extension is authoritative.
    (b".pkg.tar.zst", FileType::PkgArch),
    (b".pkg.tar.xz", FileType::PkgArch),
    (b".pkg.tar.gz", FileType::PkgArch),
    (b".pkg.tar", FileType::PkgArch),
    (b".crate", FileType::Crate),
    (b".tar.gz", FileType::TarGz),
    (b".tgz", FileType::TarGz),
    (b".tar.bz2", FileType::TarBz2),
    (b".tbz2", FileType::TarBz2),
    (b".tbz", FileType::TarBz2),
    (b".tar.xz", FileType::TarXz),
    (b".txz", FileType::TarXz),
    (b".xbps", FileType::Xbps),
    (b".tar.zst", FileType::TarZst),
    (b".tzst", FileType::TarZst),
    (b".gem", FileType::Gem),
    (b".tar", FileType::Tar),
];

/// Java archives by suffix, tried after the versioned shared-library names.
const JAVA_ARCHIVE_SUFFIXES: &[(&[u8], FileType)] = &[
    (b".jar", FileType::Jar),
    (b".war", FileType::Jar),
    (b".ear", FileType::Jar),
];

/// The type of the first entry of `table` whose suffix ends `path`, compared
/// case-insensitively.
fn suffix_type(path: &[u8], table: &[(&[u8], FileType)]) -> Option<FileType> {
    table
        .iter()
        .find(|(suffix, _)| ends_with_ci(path, suffix))
        .map(|&(_, ft)| ft)
}

/// Inner types trusted under a wrapper suffix.
///
/// The reason to read the extension out from under a wrapper is that these
/// formats carry no signature of their own: once `.yaml` is hidden behind
/// `.bak`, nothing in the bytes says what the file is, and it would type as
/// unknown, which no rule reads.
///
/// Binaries and archives stay excluded: their magic is authoritative and is
/// consulted before any of this, so trusting a name like `note.so.old` would
/// only ever let a renamed payload claim a type its bytes do not support.
fn is_wrapper_inner_type(ft: FileType) -> bool {
    ft.is_source_code()
        || matches!(
            ft,
            FileType::Yaml | FileType::Json | FileType::Xml | FileType::Text | FileType::Markdown
        )
}

/// Suffixes that wrap a file without changing what it is. Kept deliberately
/// small: each one is a provenance or lifecycle marker, never a format.
const WRAPPER_SUFFIXES: &[&str] = &[
    "fragment",
    "sample",
    "bak",
    "orig",
    "old",
    "save",
    "copy",
    "disabled",
    "quarantine",
    "download",
    "part",
    "tmp",
    "orig_bak",
];

/// `foo.c.fragment` -> `foo.c`, when the trailing extension is a wrapper.
fn strip_wrapper_suffix(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let (stem, ext) = name.rsplit_once('.')?;
    if !WRAPPER_SUFFIXES.iter().any(|w| ext.eq_ignore_ascii_case(w)) {
        return None;
    }
    // The remaining name must still carry an extension of its own, otherwise
    // there is nothing to resolve and content heuristics should decide.
    if !stem.contains('.') {
        return None;
    }
    Some(stem)
}

/// `true` for a mysqltest script, include or result file under a
/// `mysql-test/` directory (either path separator).
fn is_mysqltest_file(path_str: &str) -> bool {
    let in_dir = path_str
        .split(['/', '\\'])
        .rev()
        .skip(1)
        .any(|dir| dir == "mysql-test");
    in_dir
        && [".test", ".result", ".inc"]
            .iter()
            .any(|ext| ends_with_ci(path_str.as_bytes(), ext.as_bytes()))
}

/// `true` for a GitHub Actions workflow file: a `.yml`/`.yaml` under a
/// `.github/workflows/` directory (either path separator).
fn is_github_workflow(path_str: &str) -> bool {
    (path_str.contains(".github/workflows/") || path_str.contains(".github\\workflows\\"))
        && (ends_with_ci(path_str.as_bytes(), b".yml")
            || ends_with_ci(path_str.as_bytes(), b".yaml"))
}

/// Detect from well-known filenames.
fn detect_from_filename(path: &Path) -> Option<FileType> {
    let name = path.file_name()?.to_str()?;

    // `<pkg>@<ver>.registry.json` — normalized registry metadata. Checked before
    // the generic `.json` extension so the suffix wins over `FileType::Json`.
    if ends_with_ci(name.as_bytes(), b".registry.json") {
        return Some(FileType::Registry);
    }
    if name.eq_ignore_ascii_case("package.json") {
        return Some(FileType::PackageJson);
    }
    if name.eq_ignore_ascii_case("package-lock.json") {
        return Some(FileType::PackageLockJson);
    }
    if name.eq_ignore_ascii_case("composer.json") {
        return Some(FileType::ComposerJson);
    }
    // Lockfiles and dependency pins under their tools' fixed names. A Yarn
    // lockfile kept for storage may carry a hash between name and suffix.
    for (fixed, file_type) in [
        ("go.mod", FileType::GoMod),
        ("go.sum", FileType::GoSum),
        ("requirements.txt", FileType::RequirementsTxt),
        ("poetry.lock", FileType::PoetryLock),
        ("pipfile.lock", FileType::PipfileLock),
        ("gemfile.lock", FileType::GemfileLock),
        ("composer.lock", FileType::ComposerLock),
        ("yarn.lock", FileType::YarnLock),
        ("pnpm-lock.yaml", FileType::PnpmLock),
    ] {
        if name.eq_ignore_ascii_case(fixed) {
            return Some(file_type);
        }
    }
    if name
        .get(..5)
        .is_some_and(|head| head.eq_ignore_ascii_case("yarn."))
        && ends_with_ci(name.as_bytes(), b".lock")
    {
        return Some(FileType::YarnLock);
    }
    if name.eq_ignore_ascii_case("binding.gyp") {
        return Some(FileType::Gyp);
    }
    // npm/yarn run-control files are INI-style `key=value` text with no
    // extension (`Path::extension` of `.npmrc` is None), so they fell through
    // to Unknown and matched no trait. They carry `node-options`, `script-shell`
    // and registry/token settings that change what every `npm` invocation in
    // the project runs, so they need to reach text rules.
    if name.eq_ignore_ascii_case(".npmrc") || name.eq_ignore_ascii_case(".yarnrc") {
        return Some(FileType::Text);
    }
    // Common extensionless project configuration files may be JSON, YAML,
    // INI-style text or ignore lists. Give them a text fallback so their
    // contents are scanned; stronger content and binary signatures still win.
    if [".babelrc", ".eslintrc", ".eslintignore", ".editorconfig"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        return Some(FileType::Text);
    }
    // Xcode project. The name is fixed by the format -- it is always
    // `<name>.xcodeproj/project.pbxproj` -- but the extension arm below still
    // covers the file copied out of its bundle for analysis.
    if name.eq_ignore_ascii_case("project.pbxproj") {
        return Some(FileType::Pbxproj);
    }
    // CMake's entry point is always this exact name; `.cmake` modules are
    // covered by the extension arm below.
    if name.eq_ignore_ascii_case("cmakelists.txt") {
        return Some(FileType::Cmake);
    }
    if name.eq_ignore_ascii_case("cargo.toml") {
        return Some(FileType::CargoToml);
    }
    if name.eq_ignore_ascii_case("cargo.lock") {
        return Some(FileType::CargoLock);
    }
    if name.eq_ignore_ascii_case("pyproject.toml") {
        return Some(FileType::PyProjectToml);
    }
    if name.eq_ignore_ascii_case(".pkginfo")
        || name.eq_ignore_ascii_case(".buildinfo")
        || name.eq_ignore_ascii_case(".mtree")
    {
        return Some(FileType::Text);
    }
    if name.eq_ignore_ascii_case("pkg-info") || name.eq_ignore_ascii_case("metadata") {
        return Some(FileType::PkgInfo);
    }
    if name.eq_ignore_ascii_case("meta.json") || name.eq_ignore_ascii_case("metadata.json") {
        return Some(FileType::PkgInfo);
    }
    if name.eq_ignore_ascii_case("extension.vsixmanifest")
        || name
            .get(name.len().saturating_sub(13)..)
            .is_some_and(|s| s.eq_ignore_ascii_case(".vsixmanifest"))
    {
        return Some(FileType::VsixManifest);
    }
    if name.eq_ignore_ascii_case("action.yml") || name.eq_ignore_ascii_case("action.yaml") {
        return Some(FileType::GithubActions);
    }
    if name == "Dockerfile" || name.starts_with("Dockerfile.") || name.starts_with("dockerfile.") {
        return Some(FileType::Dockerfile);
    }
    if name == "Containerfile" || name.starts_with("Containerfile.") {
        return Some(FileType::Dockerfile);
    }
    // CPAN's MakeMaker entry point generates a Makefile; it is itself Perl.
    // Settle the canonical name before the broad Makefile variant prefix.
    if name.eq_ignore_ascii_case("Makefile.PL") {
        return Some(FileType::Perl);
    }
    if name.starts_with("Makefile") || name.starts_with("GNUmakefile") {
        return Some(FileType::Makefile);
    }
    // Arch Linux PKGBUILD recipes are bash, but carry no shebang and — for short
    // recipes — too little shell syntax for content sniffing to catch, so they
    // fall through to Unknown and packaging traits never run. Recognize the
    // canonical name (it is always bash) so the pacman trait family applies.
    if name == "PKGBUILD" {
        return Some(FileType::Shell);
    }
    // Arch/AUR .SRCINFO: the machine-generated, normalized mirror of PKGBUILD
    // metadata (key = value lines). Parsed into a pkg.* value tree so it can be
    // compared field-by-field against the PKGBUILD that should have produced it.
    if name.eq_ignore_ascii_case(".SRCINFO") {
        return Some(FileType::SrcInfo);
    }
    // Meson build files. Their own DSL (not source code); classify as a build
    // file so source/AST traits (e.g. JavaScript obfuscation) do not run on them.
    if name.eq_ignore_ascii_case("meson.build")
        || name.eq_ignore_ascii_case("meson.options")
        || name.eq_ignore_ascii_case("meson_options.txt")
    {
        return Some(FileType::Makefile);
    }
    // License / copying files are plain text. Match the canonical names and
    // their license-name suffixes (LICENSE.GPLv3, LICENSE.LGPLv3, COPYING.LESSER,
    // LICENSE.txt, LICENSE-MIT) so content sniffing never scores license prose
    // as a programming language. Defer to the extension when it names a real
    // code type, so a source file like `license-checker.js` stays JavaScript.
    if let Some(stem) = name.split(['.', '-']).next()
        && (stem.eq_ignore_ascii_case("LICENSE")
            || stem.eq_ignore_ascii_case("LICENCE")
            || stem.eq_ignore_ascii_case("COPYING"))
        && detect_from_extension(path).is_none_or(|claim| claim.file_type == FileType::Text)
    {
        return Some(FileType::Text);
    }

    None
}

/// The claim a single file extension makes.
fn detect_from_extension(path: &Path) -> Option<Claim> {
    let ext = lowercase_ext(path)?;

    let file_type = match &*ext {
        "sh" | "bash" | "ksh" | "zsh" | "csh" | "tcsh" | "dash" | "fish" | "command" | "ebuild"
        | "eclass" => FileType::Shell,
        "py" | "pyw" | "pyi" | "pth" => FileType::Python,
        "js" | "mjs" | "cjs" | "jsx" | "jse" => FileType::JavaScript,
        "ts" | "tsx" | "mts" | "cts" => FileType::TypeScript,
        // CSS and preprocessor stylesheets. There is no dedicated stylesheet
        // analyzer, and their C-like braces/`;`/`//` syntax otherwise scores as
        // JavaScript under content heuristics — which fires JS AST rules
        // (arithmetic-density obfuscation, string-concat) on benign layout math
        // like `margin: $a - $b`. Treat them as plain text: still scanned for
        // strings/URLs/secrets, but never parsed as a JS AST.
        "css" | "scss" | "sass" | "less" | "styl" | "pcss" | "postcss" => {
            return Some(Claim::text_language());
        }
        // Vim script. No dedicated analyzer, and its ubiquitous `let ` bindings
        // otherwise score as JavaScript under content heuristics — which fires
        // JS rules on syntax databases like filetype.vim (a catalog of sensitive
        // path patterns: .aws/credentials, /etc/hosts, ...). Treat as plain text.
        "vim" => return Some(Claim::text_language()),
        // Lisp family. No dedicated analyzer; parenthesized arithmetic like
        // `(- a b)` otherwise scores as JavaScript and fires JS obfuscation
        // rules on e.g. the GCL ANSI test suite. Treat as plain text.
        "lsp" | "lisp" | "el" | "cl" | "scm" => return Some(Claim::text_language()),
        // PatEL (`.ptl`) — Iosevka's Lisp-like glyph / OpenType-layout DSL,
        // compiled by the `patel` npm package. No dedicated analyzer; its
        // `$$include`, `$`-prefixed macros, and bare command-like statement
        // heads otherwise content-score as Shell and fire shell
        // command-execution / obfuscated-command traits on font-outline source.
        // Treat as plain text: still scanned for strings/URLs, never as shell.
        "ptl" => return Some(Claim::text_language()),
        // OCaml family. No dedicated analyzer; `let`-heavy implementations
        // otherwise score as JavaScript and `.mli` `val` declarations score
        // as Kotlin under weak content heuristics. Treat as plain text.
        "ml" | "mli" | "mll" | "mly" | "mld" | "eliom" | "eliomi" => {
            return Some(Claim::text_language());
        }
        // SQL dumps/scripts. No dedicated analyzer; large dumps of long INSERT
        // statements otherwise content-score as Batch and fire batch
        // line/token-bloat obfuscation rules. Treat as plain text.
        "sql" | "ddl" | "dml" => return Some(Claim::text_language()),
        // Neo4j Cypher graph dumps (e.g. an agent's autogenerated knowledge
        // graph). No dedicated analyzer; `MERGE (n:Label {k: 'v'})` syntax —
        // braces, colons, quoted props — otherwise content-scores as JavaScript
        // and runs every Node.js stealer/exfil rule against what is really a
        // data export. Treat as text so content traits still match by string.
        "cypher" | "cql" => return Some(Claim::text_language()),
        // Smali (Android/Dalvik bytecode disassembly). No dedicated analyzer;
        // its dense arithmetic/array literals otherwise score as JavaScript and
        // fire JS arithmetic-obfuscation rules (e.g. jadx test .smali fixtures).
        "smali" => return Some(Claim::text_language()),
        // Unified-diff patches. No dedicated analyzer; their `-`/`+` line
        // prefixes otherwise content-score as JavaScript, and the removed-line
        // `-` markers parse as subtraction operators — tripping
        // js-arithmetic-array-init on benign kernel/source patch sets. Text.
        "patch" | "diff" => return Some(Claim::text_language()),
        // GNU M4 / Autoconf macro source. No dedicated parser; as text its
        // build-system behavior is still scanned.
        "m4" => return Some(Claim::text_language()),
        // TypeScript compiler test baselines (annotated code fixtures, not
        // executable JS): x.types / x.symbols / x.baseline.
        "types" | "symbols" | "baseline" => return Some(Claim::text_language()),
        // Protocol Buffer schemas. No dedicated analyzer; `.proto` syntax uses
        // `package` declarations and service/message identifiers that otherwise
        // content-score as Kotlin. Treat as text so C2/protocol traits can still
        // match without source-language misclassification.
        "proto" => return Some(Claim::text_language()),
        // YARA rule sources. No dedicated analyzer; `rule X { strings: ... }`
        // with `$`-prefixed identifiers content-scores as PHP, Kotlin, Python or
        // shell, so a shipped rule set would be read as those languages when
        // it is a list of detection patterns quoting malware strings. A
        // dedicated Yara type keeps source-language analysis off it.
        "yar" | "yara" => FileType::Yara,
        "go" => FileType::Go,
        "rs" => FileType::Rust,
        "java" => FileType::Java,
        "jsp" | "jspx" => FileType::Jsp,
        "asp" | "aspx" | "asa" | "asax" | "ascx" | "ashx" | "asmx" => FileType::Asp,
        "cfm" | "cfc" | "cfml" => FileType::Cfml,
        // `.cls` is also a Visual Basic class module, so it is not mapped here.
        "tex" | "sty" | "ltx" | "dtx" => FileType::Tex,
        "ps" | "eps" | "epsf" => FileType::PostScript,
        "com" => FileType::DosCom,
        "mrc" => FileType::Mirc,
        "ircii" => FileType::IrcII,
        "class" => FileType::JavaClass,
        "pyc" | "pyo" => FileType::PythonBytecode,
        "beam" => FileType::Beam,
        "wasm" => FileType::Wasm,
        "dex" => FileType::Dex,
        "rb" | "rbs" | "gemspec" => FileType::Ruby,
        "php" | "php3" | "php4" | "php5" | "php7" | "phtml" => FileType::Php,
        "pl" | "pm" | "t" => FileType::Perl,
        "ps1" | "psm1" | "psd1" => FileType::PowerShell,
        "kt" | "kts" => FileType::Kotlin,
        "bat" | "cmd" => FileType::Batch,
        "jcl" => FileType::Jcl,
        // A Windows registry export. Its header line is magic, so a `.reg`
        // without one is typed by its content and reported as a mismatch.
        "reg" => FileType::Reg,
        "vbs" | "vbe" | "wsf" | "wsc" | "wsh" => FileType::Vbs,
        "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" | "hxx" | "hh" | "pas" | "dpr" | "asm" | "s"
        | "nasm" => FileType::C,
        // Microsoft Interface Definition Language is C-like source; treating it as C
        // enables source facts even when content heuristics do not recognize MIDL syntax.
        "idl" => FileType::C,
        "lua" => FileType::Lua,
        "cs" => FileType::CSharp,
        "swift" => FileType::Swift,
        "m" | "mm" => FileType::ObjectiveC,
        "groovy" | "gradle" => FileType::Groovy,
        "scala" | "sc" => FileType::Scala,
        "zig" => FileType::Zig,
        "ex" | "exs" => FileType::Elixir,
        "clj" | "cljs" | "cljc" | "cljr" | "edn" | "bb" => FileType::Clojure,
        "scpt" | "applescript" => FileType::AppleScript,
        "service" => FileType::SystemdService,
        "desktop" => FileType::DesktopEntry,
        "svg" => FileType::Svg,
        // Interface Builder sources (.xib, .storyboard) are XML; their
        // compiled form is `Nib`.
        "xml" | "csproj" | "vbproj" | "fsproj" | "proj" | "props" | "targets" | "vcxproj"
        | "xaml" | "config" | "settings" | "nuspec" | "wsdl" | "xsd" | "xsl" | "xslt" | "xib"
        | "storyboard" => FileType::Xml,
        // VS Code multi-root workspace files are JSONC (comments, trailing
        // commas) and can carry a `tasks` block with `runOn: folderOpen`, the
        // same autorun surface as `.vscode/tasks.json`. Typed as text, they
        // were invisible to every JSON rule; the generic JSON extractor's
        // JSONC fallback parses them.
        "json" | "code-workspace" => FileType::Json,
        // Generic YAML. The specific manifests that happen to be YAML
        // (pnpm-lock.yaml, action.yml, .github/workflows/*) are matched by
        // filename earlier in `detect_from_path`, so only the rest reach here.
        "yaml" | "yml" => FileType::Yaml,
        "gyp" | "gypi" => FileType::Gyp,
        "plist" | "resx" => FileType::Plist,
        "nib" => FileType::Nib,
        "pbxproj" => FileType::Pbxproj,
        "cmake" => FileType::Cmake,
        "rtf" => FileType::Rtf,
        "doc" | "msg" | "dot" | "ppt" | "pps" | "pot" | "ppa" | "xls" | "xlt" | "xla" => {
            FileType::OleDoc
        }
        "msi" | "msp" | "mst" | "msm" => FileType::Msi,
        // Ubuntu Snap: a SquashFS image. The magic confirms the filesystem but
        // not the package, so the extension is what separates the two.
        "snap" => FileType::Snap,
        // Flatpak bundles carry no magic at a fixed offset — extension only.
        "flatpak" => FileType::Flatpak,
        "squashfs" | "sqsh" => FileType::SquashFs,
        // Detached OpenPGP signatures published beside release artifacts.
        "sig" | "asc" | "sign" => FileType::PgpSignature,
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "dotm" | "xltx" | "xltm"
        | "xlam" | "ppam" | "potx" | "potm" | "ppsx" | "ppsm" | "sldx" | "sldm" => FileType::Ooxml,
        ext if is_odf_extension(ext) => FileType::Odf,
        "exe" | "dll" | "sys" | "scr" | "cpl" | "ocx" | "drv" | "efi" | "pyd" => FileType::Pe,
        "so" | "elf" | "ko" => FileType::Elf,
        "dylib" | "bundle" | "macho" => FileType::MachO,
        "lnk" => FileType::Lnk,
        "pdf" => FileType::Pdf,
        "jpg" | "jpeg" | "jpe" | "jfif" => FileType::Jpeg,
        "png" => FileType::Png,
        "tif" | "tiff" => FileType::Tiff,
        "avif" | "avifs" => FileType::Avif,
        // Font containers. `.woff2`/`.woff`/`.eot` are web-delivery
        // wrappers, `.ttf`/`.otf` bare sfnt, `.ttc`/`.otc` collections.
        // Mapping them buys structural validation (see formats/font.rs)
        // for a family that is otherwise copied around unexamined.
        "ttf" | "otf" | "ttc" | "otc" | "woff" | "woff2" | "eot" => FileType::Font,
        // Media containers. Each has a structure walker (formats/containers.rs)
        // that reports which bytes the format accounts for, so a payload in
        // the remainder is visible.
        "wav" | "wave" => FileType::Wav,
        "aif" | "aiff" | "aifc" => FileType::Aiff,
        "mp3" => FileType::Mp3,
        "mp4" | "m4a" | "m4v" | "mov" => FileType::Mp4,
        "ico" | "cur" => FileType::Ico,
        "ani" => FileType::Ani,
        "gif" => FileType::Gif,
        "bmp" | "dib" => FileType::Bmp,
        "webp" => FileType::Webp,
        // Sphinx caches parsed document trees as protocol pickle streams with
        // the canonical `.doctree` suffix under its build directory.
        "pkl" | "pickle" | "joblib" | "debug_pkl" | "doctree" => FileType::Pickle,
        // Image4 payloads and trust caches: content names the trust-cache
        // table, and every other payload stays opaque data.
        "trustcache" | "im4p" => FileType::Data,
        // Zip-based package ecosystems with unambiguous extensions get their
        // own type (the magic branch agrees when `PK` is present; this keeps
        // the extension fallback consistent so it isn't flagged a mismatch).
        "ipa" => FileType::Ipa,
        "nupkg" => FileType::Nupkg,
        "vsix" => FileType::Vsix,
        "egg" => FileType::Egg,
        "conda" => FileType::Conda,
        "zip" | "apk" | "epub" | "aar" | "pyz" | "msix" | "appx" | "msixbundle" | "appxbundle"
        | "aab" | "apks" | "xapk" | "cbz" => FileType::Zip,
        "xpi" => FileType::Xpi,
        "whl" => FileType::Whl,
        "7z" | "cb7" => FileType::SevenZ,
        "rar" | "cbr" => FileType::Rar,
        "rpa" => FileType::Rpa,
        "rpyc" | "rpymc" => FileType::Rpyc,
        "deb" | "udeb" => FileType::Deb,
        // Static library: an `ar` archive of object files. Magic-based
        // detection also handles extensionless `.a`; this keeps the extension
        // fallback consistent (and off the `Deb` path).
        //
        // `.lib` is the Windows spelling -- both MSVC static libraries and
        // import libraries are `ar` archives, so a Windows static library is
        // consistent with its name.
        "a" | "lib" => FileType::StaticLib,
        "rpm" | "srpm" => FileType::Rpm,
        "crx" => FileType::Crx,
        "pkg" => FileType::PkgMacos,
        "dmg" => FileType::Dmg,
        "vhd" => FileType::Vhd,
        "iso" => FileType::Iso,
        "cab" | "msu" => FileType::Cab,
        "chm" => FileType::Chm,
        "asar" => FileType::Asar,
        "phar" => FileType::Phar,
        "cpio" => FileType::Cpio,
        "gz" => FileType::Gz,
        "bz2" => FileType::Bz2,
        "xz" => FileType::Xz,
        "lzma" => FileType::Lzma,
        "zst" => FileType::Zst,
        // `.hta` is an HTML Application: mshta.exe runs it as a local-trust
        // program, so it is markup on disk but a script in effect. Classified
        // as Html so markup and script analysis applies.
        "html" | "htm" | "hta" => FileType::Html,
        // R Markdown / Quarto / Sweave are markdown documents with embedded
        // code chunks — classify as Markdown so they aren't analysed as source
        // code (their YAML frontmatter and code chunks otherwise trip
        // polyglot/obfuscation matchers).
        "rmd" | "qmd" | "rnw" => FileType::Markdown,
        // Plain Markdown is a prose name: a document keeps it by its
        // structure, a script renamed `.md` does not.
        "md" | "markdown" => {
            return Some(Claim {
                strength: Strength::Document,
                ..Claim::of(FileType::Markdown)
            });
        }
        "mk" | "mak" => FileType::Makefile,
        "dockerfile" | "containerfile" => FileType::Dockerfile,
        // Checksum manifests shipped beside a release. Plain text listing
        // "<hex>  <filename>" pairs — no structure worth its own type, but
        // naming them keeps a release directory out of the unknown bucket.
        "sha256sum" | "sha512sum" | "sha1sum" | "md5sum" | "sha256" | "sha512" | "checksum"
        | "checksums" | "b64" | "base64" => return Some(Claim::text_language()),
        // Configuration syntaxes and the languages with no analyzer here
        // (Erlang, Elvish, Nushell). Their values and comments quote other
        // languages' tokens, which is not those languages.
        "toml" | "ini" | "cfg" | "conf" | "properties" | "erl" | "hrl" | "elv" | "nu" => {
            return Some(Claim::text_language());
        }
        // Prose names. A body that is plainly a language is that language;
        // the name is the fallback when the body says nothing.
        "txt" | "text" | "rst" | "adoc" | "csv" | "tsv" | "log" => FileType::Text,
        // Source maps are structured data sidecars. Keeping them as Data lets the
        // archive analyzer inspect both ordinary JSON maps and raw embedded
        // Base64 payloads instead of dropping them as unknown members.
        // The name settles it: the sources a map embeds are not its language.
        "map" => {
            return Some(Claim {
                strength: Strength::Named,
                ..Claim::of(FileType::Data)
            });
        }
        // Generic data suffixes that do not imply a more specific format.
        // Includes opaque payload blobs and common database filenames; content
        // signatures still take precedence over this path-based fallback.
        "dat" | "bin" | "db" | "payload" | "raw" => FileType::Data,
        _ => return None,
    };
    Some(Claim::of(file_type))
}

/// OpenDocument extensions: the document types, their templates, master
/// documents, databases, charts and images.
const ODF_EXTENSIONS: &[&str] = &[
    "odt", "ods", "odp", "odg", "odf", "ott", "ots", "otp", "odm", "oth", "otg", "odb", "odc",
    "odi",
];

/// Whether lowercase `ext` is an OpenDocument extension.
fn is_odf_extension(ext: &str) -> bool {
    ODF_EXTENSIONS.contains(&ext)
}

/// A path's extension, ASCII-lowercased into a stack buffer so that matching
/// it against the tables here does not allocate.
pub(super) struct LowercaseExt {
    buf: [u8; LowercaseExt::MAX_LEN],
    len: usize,
}

impl LowercaseExt {
    /// Longest extension kept. Every extension the tables name is shorter, so
    /// a longer one is treated as absent.
    const MAX_LEN: usize = 16;
}

impl std::ops::Deref for LowercaseExt {
    type Target = str;

    fn deref(&self) -> &str {
        // Lowercasing ASCII bytes keeps valid UTF-8 valid.
        self.buf
            .get(..self.len)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or_default()
    }
}

/// `path`'s extension in lowercase. `None` when there is none, it is not
/// UTF-8, or it is longer than [`LowercaseExt::MAX_LEN`].
pub(super) fn lowercase_ext(path: &Path) -> Option<LowercaseExt> {
    let ext = path.extension()?.to_str()?;
    let mut buf = [0; LowercaseExt::MAX_LEN];
    // An extension longer than the buffer has no slot, and so is absent.
    buf.get_mut(..ext.len())?.copy_from_slice(ext.as_bytes());
    buf.make_ascii_lowercase();
    Some(LowercaseExt {
        buf,
        len: ext.len(),
    })
}

fn has_versioned_so_suffix(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let bytes = name.as_bytes();
    let Some(suffix) = bytes
        .windows(4)
        .rposition(|window| window.eq_ignore_ascii_case(b".so."))
        .and_then(|pos| bytes.get(pos + 4..))
    else {
        return false;
    };
    !suffix.is_empty()
        && suffix.iter().any(u8::is_ascii_digit)
        && suffix.iter().all(|b| b.is_ascii_digit() || *b == b'.')
}

/// Case-insensitive suffix check on raw bytes (no allocation).
pub(super) fn ends_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .len()
        .checked_sub(needle.len())
        .and_then(|start| haystack.get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests;
