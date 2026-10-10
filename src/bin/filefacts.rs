//! `filefacts` command-line interface.
//!
//! Reads one file and emits its facts bundle, or one selected top-level
//! view from that bundle. When the positional argument is a directory it
//! is walked recursively, emitting one bundle per regular file.
//!
//! The terminal renderer mirrors the JSON detail in a colored, aligned
//! layout (heading pills, grouped metrics, columnar section / symbol
//! tables) inspired by sibling tools cleave and litmus.

// Use jemalloc on unix systems where it isn't the OS default (see Cargo.toml),
// unless built without the default `jemalloc` feature. Built-in
// `--features jemalloc-prof` activates jemalloc's heap-profiling support
// (`_RJEM_MALLOC_CONF=prof:true,...`) which cleave-tuna's memory-mode benches consume.
#[cfg(all(
    feature = "jemalloc",
    unix,
    not(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Default jemalloc options: return freed pages to the OS immediately
/// (`dirty_decay_ms:0`) instead of holding them for the default 10s decay
/// window. filefacts is a one-shot batch tool; each file's alloc/free burst
/// otherwise leaves dirty pages resident across the rest of the walk,
/// inflating peak RSS ~60% on a 200MB mixed corpus (345MB → 216MB) for ~1%
/// wall-clock. Overrides jemalloc's weak `_rjem_malloc_conf` definition;
/// the `_RJEM_MALLOC_CONF` environment variable still takes precedence, so
/// heap-profiling builds keep working unchanged.
///
/// SAFETY: jemalloc declares the symbol `const char *_rjem_malloc_conf` and
/// reads it as a NUL-terminated C string. `Option<&'static [u8; N]>` has the
/// layout of a nullable pointer (the null-pointer optimisation guarantees
/// it), and the reference's provenance covers every byte jemalloc reads, up
/// to and including the terminator. `export_name` is unsafe only because a
/// symbol of the wrong type would be undefined behaviour; these two are the
/// invariants that make it the right one. Scoped allow per the Cargo.toml
/// `unsafe_code = "deny"` rationale.
#[cfg(all(
    feature = "jemalloc",
    unix,
    not(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))
))]
#[allow(unsafe_code, non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static malloc_conf: Option<&'static [u8; 17]> = Some(b"dirty_decay_ms:0\0");

use std::borrow::Cow;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use filefacts::{Arg, OpenOptions, ParsedFile, Symbol, SymbolKind};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Terminal,
    Json,
}

#[derive(Debug, Default)]
struct Args {
    path: Option<PathBuf>,
    format: Format,
    /// The single view to emit; `None` emits the bundle.
    view: Option<View>,
}

/// One top-level view of a parsed file. Views are only ever constructed
/// through [`VIEWS`], so a variant missing from it is flagged as dead code.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum View {
    Fileid,
    Identity,
    Values,
    Text,
    Literals,
    Comments,
    Metrics,
    Sections,
    Symbols,
    /// One kind of symbol, filtered out of `Symbols`.
    Kind(SymbolKind),
    Flow,
    References,
    ArchiveMembers,
    Errors,
}

/// Every view as `(view, name, help)`, in output order. The name is the
/// positional word, the `--<name>` flag and the bundle's JSON key; parsing,
/// the usage text and the bundle are all derived from this table.
#[rustfmt::skip]
const VIEWS: &[(View, &str, &str)] = &[
    (View::Fileid,         "fileid",          "File identification."),
    (View::Identity,       "identity",        "Normalized identity claims."),
    (View::Values,         "values",          "Structural values tree."),
    (View::Text,           "text",            "Byte-scan text runs (ascii / utf16le)."),
    (View::Literals,       "literals",        "Parser-extracted string literals."),
    (View::Comments,       "comments",        "Source comment bodies."),
    (View::Metrics,        "metrics",         "Derived metrics."),
    (View::Sections,       "sections",        "Binary sections."),
    (View::Symbols,        "symbols",         "Every symbol, all kinds."),
    (View::Kind(SymbolKind::Import),     "imports",     "Import symbols."),
    (View::Kind(SymbolKind::Export),     "exports",     "Export symbols."),
    (View::Kind(SymbolKind::Function),   "functions",   "Function symbols."),
    (View::Kind(SymbolKind::Call),       "calls",       "Call symbols."),
    (View::Kind(SymbolKind::Member),     "members",     "Member symbols."),
    (View::Kind(SymbolKind::Bind),       "binds",       "Bind symbols."),
    (View::Kind(SymbolKind::Identifier), "identifiers", "Identifier symbols."),
    (View::Flow,           "flow",            "Value relationships, or null when unavailable."),
    (View::References,     "references",      "Packages, URLs and files the artifact references."),
    (View::ArchiveMembers, "archive_members", "Typed archive member index."),
    (View::Errors,         "errors",          "Recoverable parse errors."),
];

impl View {
    fn from_name(name: &str) -> Option<Self> {
        VIEWS
            .iter()
            .find(|(_, n, _)| *n == name)
            .map(|(v, _, _)| *v)
    }

    fn name(self) -> &'static str {
        VIEWS
            .iter()
            .find(|(v, _, _)| *v == self)
            .map(|(_, n, _)| *n)
            .expect("every view is listed in VIEWS")
    }

    /// Whether the bundle carries this view under its own key. A symbol
    /// kind's rows are already in `symbols`; flow is opt-in because building
    /// the graph is work no other view pays for (see the README).
    fn bundled(self) -> bool {
        !matches!(self, Self::Kind(_) | Self::Flow)
    }
}

/// The views the bundle carries, in output order.
fn bundled_views() -> impl Iterator<Item = (View, &'static str)> {
    VIEWS
        .iter()
        .filter(|(view, _, _)| view.bundled())
        .map(|(view, name, _)| (*view, *name))
}

fn main() -> ExitCode {
    install_debug_logging();
    install_signal_cleanup();
    let args = match parse_args(std::env::args_os().skip(1), |p| {
        std::fs::symlink_metadata(p).is_ok()
    }) {
        Ok(ParseOutcome::Run(a)) => a,
        Ok(ParseOutcome::Help) => {
            return exit_code(write!(io::stdout(), "{}", usage()).map(|()| true));
        }
        Ok(ParseOutcome::Version) => {
            let version = writeln!(io::stdout(), "filefacts {}", env!("CARGO_PKG_VERSION"));
            return exit_code(version.map(|()| true));
        }
        // The message can quote an argument, and `filefacts *` in a sample
        // directory makes a file name an argument.
        Err(msg) => {
            eprintln!("filefacts: {}", escape_controls(&msg));
            eprint!("{}", usage());
            return ExitCode::from(2);
        }
    };

    let Some(root) = args.path.as_deref() else {
        eprintln!("filefacts: no path supplied");
        eprint!("{}", usage());
        return ExitCode::from(2);
    };

    // The CLI rescans the same files, so it opts into the extraction cache
    // (`FILEFACTS_CACHE=0` still turns it off). Kick off cleanup on a
    // background thread: it drops superseded schema versions and bounds the
    // cache to its item cap (evicting least-recently-used entries).
    // Non-blocking and self-throttling — a short one-file run may exit
    // before it finishes and the next run resumes, while a long directory
    // scan lets it complete.
    let options = OpenOptions::new().cache(filefacts::cache::env_override().unwrap_or(true));
    filefacts::cache::cleanup();

    let mut out = io::BufWriter::new(io::stdout().lock());
    exit_code(run(&mut out, root, &args, &options))
}

/// Print the library's `tracing` diagnostics to stderr when `FILEFACTS_DEBUG`
/// is set (any value except empty, `0` or `false`). The generic `DEBUG` is
/// deliberately not honoured: other tools read it, and it must not make this
/// one chatty.
fn install_debug_logging() {
    if debug_requested(std::env::var_os("FILEFACTS_DEBUG").as_deref()) {
        let _ = tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .without_time()
            .try_init();
    }
}

/// Whether a `FILEFACTS_DEBUG` value turns debug output on.
fn debug_requested(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")))
}

/// On SIGINT, SIGTERM or SIGHUP, kill in-flight rizin process groups and
/// delete their temp inputs, then exit `128 + signal` like a shell would.
/// rizin runs in its own process group, so the terminal's SIGINT never
/// reaches it, and on macOS — which has no parent-death signal — it would
/// otherwise outlive this process. A dedicated thread does the work, since
/// the reaper locks and allocates (see `kill_all_rizin_groups`).
#[cfg(unix)]
fn install_signal_cleanup() {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP]) else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("filefacts-signals".into())
        .spawn(move || {
            if let Some(signal) = signals.forever().next() {
                filefacts::rizin::kill_all_rizin_groups();
                std::process::exit(128 + signal);
            }
        });
}

/// Windows: rizin's job object is closed, killing it, when this process
/// exits, so the default Ctrl-C handling already cleans up.
#[cfg(not(unix))]
fn install_signal_cleanup() {}

/// Exit status for a run: `Ok(false)` means some file failed and was
/// reported; `Err` means stdout itself failed.
fn exit_code(result: io::Result<bool>) -> ExitCode {
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        // The reader went away (`filefacts dir | head`): stop quietly and
        // succeed, as other Unix filters do.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("filefacts: cannot write output: {e}");
            ExitCode::from(1)
        }
    }
}

/// Analyze `root`, walking it recursively when it is a directory. Returns
/// `Ok(false)` when any file failed; an `Err` from `out` ends the walk.
fn run(
    out: &mut impl Write,
    root: &Path,
    args: &Args,
    options: &OpenOptions<'_>,
) -> io::Result<bool> {
    if !root.is_dir() {
        return analyze_one(out, root, args, options);
    }
    let mut ok = true;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("filefacts: cannot read dir {}: {e}", shown(&dir));
                ok = false;
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("filefacts: cannot read entry in {}: {e}", shown(&dir));
                    ok = false;
                    continue;
                }
            };
            let p = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(p),
                Ok(ft) if ft.is_file() => ok &= analyze_one(out, &p, args, options)?,
                _ => {}
            }
        }
    }
    Ok(ok)
}

// analyze_one parses one file and writes its rendered output. A file that
// cannot be read, parsed or serialised is reported on stderr and yields
// `Ok(false)` so a directory walk carries on; an `Err` means `out` failed.
fn analyze_one(
    out: &mut impl Write,
    path: &Path,
    args: &Args,
    options: &OpenOptions<'_>,
) -> io::Result<bool> {
    // A FIFO or device given as the path is refused rather than read
    // forever, and an input past the cap is refused rather than read into an
    // out-of-memory abort.
    let bytes = match filefacts::read_input(path, filefacts::MAX_INPUT_BYTES) {
        Ok(b) => b,
        Err(filefacts::Error::Io { source, .. }) => {
            eprintln!("filefacts: cannot read {}: {source}", shown(path));
            return Ok(false);
        }
        Err(e) => {
            eprintln!("filefacts: cannot read {}: {e}", shown(path));
            return Ok(false);
        }
    };

    let parsed = options.clone().path(path).open(&bytes);

    let written = match args.format {
        // Stream JSON straight to `out`. Building an intermediate
        // `serde_json::Value` tree (and then one giant pretty string)
        // doubles peak memory on string-heavy files; serialising the
        // borrowed views directly keeps only one copy live.
        Format::Json => write_json(out, &parsed, args.view),
        Format::Terminal => format_terminal(path, &parsed, args.view)
            .and_then(|text| writeln!(out, "{text}").map_err(serde_json::Error::io)),
    };
    if !report_serialisation(path, written)? {
        return Ok(false);
    }
    // Flush per file so a long walk shows progress.
    out.flush()?;
    Ok(true)
}

/// A path for a diagnostic on stderr, which is a terminal too: walked file
/// names come from the analysed tree, so control characters are escaped.
fn shown(path: &Path) -> String {
    escape_controls(&path.to_string_lossy()).into_owned()
}

/// Split a write's failure into the output failing (`Err`, which ends the
/// run) and the file's data failing to serialise (reported, `Ok(false)`).
fn report_serialisation(path: &Path, written: serde_json::Result<()>) -> io::Result<bool> {
    match written {
        Ok(()) => Ok(true),
        Err(e) if e.is_io() => Err(e.into()),
        Err(e) => {
            eprintln!("filefacts: serialisation failed for {}: {e}", shown(path));
            Ok(false)
        }
    }
}

// write_json pretty-prints the selected view (or the bundle) to `out`
// without materialising a `serde_json::Value` tree or an intermediate String.
fn write_json(
    out: &mut impl Write,
    parsed: &ParsedFile<'_>,
    view: Option<View>,
) -> serde_json::Result<()> {
    let mut escaped = EscapeC1(&mut *out);
    match view {
        None => serde_json::to_writer_pretty(&mut escaped, &Bundle(parsed))?,
        Some(view) => serde_json::to_writer_pretty(&mut escaped, &ViewData(parsed, view))?,
    }
    out.write_all(b"\n").map_err(serde_json::Error::io)
}

/// Rewrites DEL and the C1 controls (U+0080..=U+009F, including the 8-bit
/// CSI) as `\u00XX` escapes. JSON allows them raw and serde_json leaves them
/// so, but a terminal may act on them, and these strings come from the file
/// under analysis. Every such byte sequence in JSON output lies inside a
/// string, and serde_json writes whole UTF-8 fragments, so the rewrite is
/// safe per write.
struct EscapeC1<W>(W);

impl<W: Write> Write for EscapeC1<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        let mut i = 0;
        while let Some(&b) = buf.get(i) {
            let escape = match (b, buf.get(i + 1)) {
                (0x7f, _) => Some((0x7f, 1)),
                (0xc2, Some(&c1 @ 0x80..=0x9f)) => Some((c1, 2)),
                _ => None,
            };
            if let Some((code, len)) = escape {
                self.0.write_all(buf.get(start..i).unwrap_or_default())?;
                write!(self.0, "\\u{code:04x}")?;
                i += len;
                start = i;
            } else {
                i += 1;
            }
        }
        self.0.write_all(buf.get(start..).unwrap_or_default())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// The default output: the schema version, then every bundled view under
/// its name.
struct Bundle<'p, 'a>(&'p ParsedFile<'a>);

impl Serialize for Bundle<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schema_version", filefacts::SCHEMA_VERSION)?;
        for (view, name) in bundled_views() {
            map.serialize_entry(name, &ViewData(self.0, view))?;
        }
        map.end()
    }
}

/// One view of a parsed file, serialised straight from the borrowed data.
struct ViewData<'p, 'a>(&'p ParsedFile<'a>, View);

impl Serialize for ViewData<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let parsed = self.0;
        match self.1 {
            View::Fileid => parsed.fileid().serialize(serializer),
            View::Identity => parsed.identity().serialize(serializer),
            View::Values => parsed.values().serialize(serializer),
            View::Text => parsed.text().serialize(serializer),
            View::Literals => parsed.literals().serialize(serializer),
            View::Comments => parsed.comments().serialize(serializer),
            View::Metrics => parsed.metrics().serialize(serializer),
            View::Sections => parsed.sections().serialize(serializer),
            View::Symbols => parsed.symbols().serialize(serializer),
            View::Kind(kind) => serializer.collect_seq(parsed.symbols().iter_kind(kind)),
            View::Flow => parsed.flow().serialize(serializer),
            View::References => parsed.references().serialize(serializer),
            View::ArchiveMembers => parsed.archive_members().serialize(serializer),
            View::Errors => parsed.errors().serialize(serializer),
        }
    }
}

#[derive(Debug)]
enum ParseOutcome {
    Run(Args),
    Help,
    Version,
}

/// Parse the command line (without the program name). `exists` reports
/// whether a path names an existing file; a positional word that names both
/// a view and an existing file is read as the file, so a path is never
/// silently taken for a view.
fn parse_args(
    args: impl IntoIterator<Item = OsString>,
    exists: impl Fn(&Path) -> bool,
) -> Result<ParseOutcome, String> {
    let mut parsed = Args::default();
    // A view name read as a path because a file of that name exists; named
    // in the error if a second path then turns up.
    let mut shadowed_view: Option<&'static str> = None;
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        // Flags and view names are ASCII, so an argument that is not UTF-8
        // can only be a path; keep it as an OsString.
        let Some(s) = arg.to_str() else {
            set_path(&mut parsed.path, arg, shadowed_view)?;
            continue;
        };
        match s {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "-V" | "--version" => return Ok(ParseOutcome::Version),
            "-f" | "--format" => {
                let Some(value) = iter.next() else {
                    return Err("--format requires terminal or json".into());
                };
                parsed.format = parse_format(&value.to_string_lossy())?;
            }
            "-p" | "--pretty" => parsed.format = Format::Json,
            "--" => {
                let Some(rest) = iter.next() else {
                    return Err("-- must be followed by a path".into());
                };
                set_path(&mut parsed.path, rest, shadowed_view)?;
                if iter.peek().is_some() {
                    return Err("multiple paths supplied".into());
                }
            }
            s if s.starts_with("--format=") => {
                parsed.format = parse_format(&s["--format=".len()..])?;
            }
            s if s.starts_with('-') => {
                let view = s.strip_prefix("--").and_then(View::from_name);
                let Some(view) = view else {
                    return Err(format!("unknown flag: {s}"));
                };
                set_view(&mut parsed.view, view)?;
            }
            s => {
                if let Some(view) = View::from_name(s)
                    && parsed.view.is_none()
                {
                    if !exists(Path::new(s)) {
                        parsed.view = Some(view);
                        continue;
                    }
                    shadowed_view = Some(view.name());
                }
                set_path(&mut parsed.path, arg, shadowed_view)?;
            }
        }
    }
    Ok(ParseOutcome::Run(parsed))
}

fn parse_format(value: &str) -> Result<Format, String> {
    match value {
        "terminal" | "term" => Ok(Format::Terminal),
        "json" => Ok(Format::Json),
        other => Err(format!("unknown format: {other}")),
    }
}

fn set_view(slot: &mut Option<View>, view: View) -> Result<(), String> {
    if slot.is_some() {
        return Err("multiple view selectors supplied; pick one".into());
    }
    *slot = Some(view);
    Ok(())
}

fn set_path(
    slot: &mut Option<PathBuf>,
    value: OsString,
    shadowed_view: Option<&str>,
) -> Result<(), String> {
    if slot.is_some() {
        return Err(match shadowed_view {
            Some(name) => format!(
                "multiple paths supplied; `{name}` is an existing file, so it was read \
                 as a path (use --{name} to select the view)"
            ),
            None => "multiple paths supplied".into(),
        });
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

// ─── theme ──────────────────────────────────────────────────────────
//
// Truecolor RGB escapes, no external dep. Honour NO_COLOR by emitting
// raw text when the env var is set.
//
// Every string the renderers print passes through `fg`, `fg_bold` or
// `pill_bg`, which escape control characters: names, strings and paths
// come from the analysed file, and a raw ESC in one would let the file
// drive the user's terminal.

#[derive(Copy, Clone)]
struct Rgb(u8, u8, u8);

// Foreground palette — neutral, readable on dark terminal backgrounds.
const FG_TITLE: Rgb = Rgb(230, 230, 230); // bold path
const FG_LABEL: Rgb = Rgb(150, 150, 150); // metric key / column label
const FG_VALUE: Rgb = Rgb(210, 210, 210); // value text
const FG_DIM: Rgb = Rgb(110, 110, 110); // very-dim chrome
const FG_HEX: Rgb = Rgb(180, 150, 220); // hex offsets / addresses
const FG_NUM: Rgb = Rgb(180, 210, 140); // plain numbers
const FG_STR: Rgb = Rgb(220, 200, 140); // string content
const FG_FLAG_EXEC: Rgb = Rgb(255, 140, 80); // executable
const FG_FLAG_WRITE: Rgb = Rgb(255, 200, 80); // writable
const FG_FLAG_READ: Rgb = Rgb(120, 180, 140); // readable
const FG_RULE: Rgb = Rgb(60, 70, 85); // rule glyphs
const FG_ERROR: Rgb = Rgb(215, 95, 95); // error red
const FG_OK: Rgb = Rgb(95, 175, 95); // benign green
const FG_NULL: Rgb = Rgb(110, 110, 110); // null/none

// Heading bar colors — one per top-level view.
fn heading_color(view: &str) -> Rgb {
    match view {
        "fileid" => Rgb(180, 140, 100),
        "values" => Rgb(140, 175, 215),
        "strings" => Rgb(220, 195, 140),
        "metrics" => Rgb(140, 200, 175),
        "sections" => Rgb(190, 160, 220),
        "imports" => Rgb(200, 145, 175),
        "exports" => Rgb(170, 200, 145),
        "functions" => Rgb(220, 170, 130),
        "ast" => Rgb(155, 175, 230),
        "errors" => Rgb(215, 95, 95),
        _ => Rgb(160, 160, 160),
    }
}

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some()
}

fn fg(c: Rgb, text: &str) -> String {
    let text = escape_controls(text);
    if no_color() {
        return text.into_owned();
    }
    let Rgb(r, g, b) = c;
    format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
}

fn fg_bold(c: Rgb, text: &str) -> String {
    let text = escape_controls(text);
    if no_color() {
        return text.into_owned();
    }
    let Rgb(r, g, b) = c;
    format!("\x1b[1;38;2;{r};{g};{b}m{text}\x1b[0m")
}

fn dim(text: &str) -> String {
    fg(FG_DIM, text)
}

fn pill_bg(label: &str, bg: Rgb) -> String {
    let label = escape_controls(label);
    if no_color() {
        return format!(" {label} ");
    }
    let Rgb(r, g, b) = bg;
    format!("\x1b[1;38;2;255;255;255;48;2;{r};{g};{b}m {label} \x1b[0m")
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(60, 200)
}

fn rule(width: usize) -> String {
    fg(FG_RULE, &"─".repeat(width))
}

fn heading(view: &str, count: Option<usize>) -> String {
    let bar = fg_bold(heading_color(view), "▌");
    let label = fg_bold(heading_color(view), &view.to_uppercase());
    let mut out = format!("{bar} {label}");
    if let Some(n) = count {
        out.push(' ');
        out.push_str(&dim(&format!("({n})")));
    }
    out
}

// ─── top-level renderer ─────────────────────────────────────────────

fn format_terminal(
    path: &Path,
    parsed: &ParsedFile<'_>,
    view: Option<View>,
) -> serde_json::Result<String> {
    let width = terminal_width();
    let mut out = String::new();

    out.push_str(&render_file_header(path, parsed, width));
    out.push('\n');

    match view {
        None => {
            for (view, name) in bundled_views() {
                render_section(&mut out, name, &render_view(parsed, view)?);
            }
        }
        Some(view) => {
            let rendered = render_view(parsed, view)?;
            out.push_str(&heading(view.name(), rendered.count));
            out.push('\n');
            if rendered.body.is_empty() {
                out.push_str(&dim("  (empty)"));
                out.push('\n');
            } else {
                out.push_str(&rendered.body);
            }
        }
    }
    Ok(out.trim_end().to_string())
}

/// One view rendered for the terminal.
struct Rendered {
    /// Item count shown in the heading.
    count: Option<usize>,
    /// Whether the bundle shows the view as `(empty)` instead of `body`.
    empty: bool,
    body: String,
}

fn render_view(parsed: &ParsedFile<'_>, view: View) -> serde_json::Result<Rendered> {
    let render: fn(&Value) -> String = match view {
        // Rendered from the typed views: a located metric serialises as a
        // `{value, spans}` object, which the JSON path would print raw, and
        // a symbol's fields depend on its kind.
        View::Metrics => {
            let metrics = parsed.metrics();
            return Ok(Rendered {
                count: (metrics.len() > 6).then_some(metrics.len()),
                empty: metrics.is_empty(),
                body: render_metrics(metrics),
            });
        }
        View::ArchiveMembers => {
            let members = parsed.archive_members();
            return Ok(Rendered {
                count: Some(members.len()),
                empty: members.is_empty(),
                body: render_archive_members(members),
            });
        }
        View::Symbols | View::Kind(_) => {
            let symbols: Vec<&Symbol> = match view {
                View::Kind(kind) => parsed.symbols().iter_kind(kind).collect(),
                _ => parsed.symbols().iter().collect(),
            };
            let body = match view {
                View::Kind(SymbolKind::Import) => render_imports(&symbols),
                View::Kind(SymbolKind::Export) => render_exports(&symbols),
                View::Kind(SymbolKind::Function) => render_functions(&symbols),
                _ => render_symbols(&symbols),
            };
            return Ok(Rendered {
                count: Some(symbols.len()),
                empty: symbols.is_empty(),
                body,
            });
        }
        // Serialised only as far as the preview reaches: these hold a row
        // per string in the file, and making every row a `Value` costs
        // several times the rows' own memory to show the first few dozen.
        View::Text => {
            let text = parsed.text();
            let categories = [
                ("ascii", preview(text.ascii(), STRING_PREVIEW_LIMIT)?),
                ("utf16le", preview(text.utf16le(), STRING_PREVIEW_LIMIT)?),
            ];
            return Ok(Rendered {
                count: None,
                empty: categories.iter().all(|(_, (total, _))| *total == 0),
                body: render_strings(&categories),
            });
        }
        View::Literals | View::Comments => {
            let rows = match view {
                View::Literals => parsed.literals().as_slice(),
                _ => parsed.comments().as_slice(),
            };
            let (total, shown) = preview(rows.iter(), ARRAY_PREVIEW_LIMIT)?;
            let mut body = render_values_tree(&Value::Array(shown));
            if total > ARRAY_PREVIEW_LIMIT {
                let more = format!("... {} more", total - ARRAY_PREVIEW_LIMIT);
                body.push_str(&format!("  {}\n", dim(&more)));
            }
            return Ok(Rendered {
                count: Some(total),
                empty: total == 0,
                body,
            });
        }
        View::Fileid => render_fileid,
        View::Sections => |v| render_sections(v, None),
        View::Errors => render_errors,
        View::Identity | View::Values | View::Flow | View::References => render_values_tree,
    };
    let value = serde_json::to_value(ViewData(parsed, view))?;
    Ok(Rendered {
        count: top_level_count(&value),
        empty: is_empty_value(&value),
        body: render(&value),
    })
}

fn render_section(out: &mut String, name: &str, rendered: &Rendered) {
    out.push_str(&heading(name, rendered.count));
    out.push('\n');
    if rendered.empty {
        out.push_str(&dim("  (empty)"));
        out.push_str("\n\n");
        return;
    }
    let body = &rendered.body;
    out.push_str(body);
    if !body.ends_with("\n\n") {
        if body.ends_with('\n') {
            out.push('\n');
        } else {
            out.push_str("\n\n");
        }
    }
}

fn top_level_count(value: &Value) -> Option<usize> {
    match value {
        Value::Array(a) => Some(a.len()),
        Value::Object(o) => {
            // Heading count makes sense for top-level lists of items, not
            // for the fileid bag or the metrics map (whose count is the
            // number of distinct keys, displayed separately).
            if o.len() <= 6 { None } else { Some(o.len()) }
        }
        _ => None,
    }
}

fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        // An object whose every leaf is empty (e.g. AST with no calls,
        // member chains, etc.) reads as empty for header purposes.
        Value::Object(o) => o.is_empty() || o.values().all(is_empty_value),
        _ => false,
    }
}

// ─── file header ────────────────────────────────────────────────────

/// Metrics the header reads; a test pins both to the catalog.
const FILE_SIZE: &str = "file.size";
const FILE_ENTROPY: &str = "file.entropy";

fn render_file_header(
    path: &std::path::Path,
    parsed: &filefacts::ParsedFile<'_>,
    width: usize,
) -> String {
    let mut out = String::new();
    let path_str = path.display().to_string();
    let ft = format!("{:?}", parsed.fileid().file_type()).to_uppercase();
    let ft_color = file_type_color(parsed.fileid().file_type());
    out.push_str(&fg_bold(FG_TITLE, &path_str));
    out.push_str("  ");
    out.push_str(&pill_bg(&ft, ft_color));

    // Subtitle: size · entropy · mismatch
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "float-to-int `as` saturates (NaN is 0); file.size is a non-negative count"
    )]
    let size = parsed.metrics().get(FILE_SIZE).unwrap_or(0.0) as u64;
    let entropy = parsed.metrics().get(FILE_ENTROPY);
    let mut subtitle = Vec::<String>::new();
    subtitle.push(fg(FG_LABEL, &humanize_bytes(size)));
    if let Some(e) = entropy {
        subtitle.push(fg(FG_LABEL, &format!("entropy {e:.2}")));
    }
    if parsed.fileid().extension_mismatch() {
        subtitle.push(fg(FG_ERROR, "extension mismatch"));
    }
    if !subtitle.is_empty() {
        out.push('\n');
        out.push_str(&format!("  {}", subtitle.join(&dim(" · "))));
    }
    out.push('\n');
    out.push_str(&rule(width));
    out.push('\n');
    out
}

fn file_type_color(ft: filefacts::FileType) -> Rgb {
    use filefacts::FileType;
    match ft {
        FileType::Pe => Rgb(115, 60, 95),
        FileType::Elf => Rgb(60, 90, 115),
        FileType::MachO => Rgb(85, 65, 110),
        FileType::Pdf => Rgb(120, 60, 60),
        FileType::Zip
        | FileType::Crx
        | FileType::Odf
        | FileType::Jar
        | FileType::Tar
        | FileType::TarGz
        | FileType::TarBz2
        | FileType::TarXz
        | FileType::TarZst => Rgb(105, 80, 50),
        FileType::JavaClass => Rgb(90, 70, 50),
        _ => Rgb(70, 75, 90),
    }
}

// ─── fileid view ────────────────────────────────────────────────────

fn render_fileid(value: &Value) -> String {
    let Value::Object(map) = value else {
        return render_values_tree(value);
    };
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    let key_w = keys.iter().map(|k| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for k in keys {
        let v = &map[k];
        let formatted = match v {
            Value::Bool(true) => fg(FG_FLAG_WRITE, "true"),
            Value::Bool(false) => dim("false"),
            Value::String(s) => fg(FG_VALUE, s),
            other => fg(FG_VALUE, &scalar_string(other)),
        };
        out.push_str(&format!(
            "  {label}  {value}\n",
            label = fg(FG_LABEL, &pad(k, key_w)),
            value = formatted,
        ));
    }
    out
}

// ─── values view (generic nested tree) ──────────────────────────────

fn render_values_tree(value: &Value) -> String {
    let mut out = String::new();
    render_tree_node(&mut out, value, 2);
    out
}

const ARRAY_PREVIEW_LIMIT: usize = 50;

fn render_tree_node(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Object(map) => {
            // Two passes — scalars first (aligned), then nested children.
            let mut scalars: Vec<(&String, &Value)> = Vec::new();
            let mut nested: Vec<(&String, &Value)> = Vec::new();
            for (k, v) in map {
                if matches!(v, Value::Object(_) | Value::Array(_)) {
                    nested.push((k, v));
                } else {
                    scalars.push((k, v));
                }
            }
            let key_w = scalars.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (k, v) in scalars {
                out.push_str(&format!(
                    "{indent_pad}{label}  {value}\n",
                    indent_pad = " ".repeat(indent),
                    label = fg(FG_LABEL, &pad(k, key_w)),
                    value = format_scalar(v),
                ));
            }
            for (k, v) in nested {
                // Compact short scalar-only arrays inline.
                if let Value::Array(items) = v {
                    if items.iter().all(is_short_scalar) && items.len() <= 8 {
                        let inline = items
                            .iter()
                            .map(format_scalar)
                            .collect::<Vec<_>>()
                            .join(&dim(", "));
                        out.push_str(&format!(
                            "{pad}{label}  {dimb}{inline}{dimb2}\n",
                            pad = " ".repeat(indent),
                            label = fg(FG_LABEL, k),
                            dimb = dim("["),
                            dimb2 = dim("]"),
                        ));
                        continue;
                    }
                }
                out.push_str(&format!(
                    "{pad}{label}\n",
                    pad = " ".repeat(indent),
                    label = fg_bold(FG_VALUE, k),
                ));
                render_tree_node(out, v, indent + 2);
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str(&format!("{}{}\n", " ".repeat(indent), dim("[]")));
                return;
            }
            for (i, v) in items.iter().take(ARRAY_PREVIEW_LIMIT).enumerate() {
                match v {
                    Value::Object(_) | Value::Array(_) => {
                        out.push_str(&format!(
                            "{pad}{idx}\n",
                            pad = " ".repeat(indent),
                            idx = dim(&format!("[{i}]")),
                        ));
                        render_tree_node(out, v, indent + 2);
                    }
                    _ => out.push_str(&format!(
                        "{pad}{idx} {value}\n",
                        pad = " ".repeat(indent),
                        idx = dim(&format!("[{i}]")),
                        value = format_scalar(v),
                    )),
                }
            }
            if items.len() > ARRAY_PREVIEW_LIMIT {
                out.push_str(&format!(
                    "{pad}{tail}\n",
                    pad = " ".repeat(indent),
                    tail = dim(&format!("... {} more", items.len() - ARRAY_PREVIEW_LIMIT)),
                ));
            }
        }
        _ => out.push_str(&format!("{}{}\n", " ".repeat(indent), format_scalar(value))),
    }
}

fn is_short_scalar(v: &Value) -> bool {
    match v {
        Value::String(s) => s.len() <= 24,
        Value::Number(_) | Value::Bool(_) | Value::Null => true,
        _ => false,
    }
}

fn format_scalar(value: &Value) -> String {
    match value {
        Value::Null => fg(FG_NULL, "null"),
        Value::Bool(true) => fg(FG_FLAG_WRITE, "true"),
        Value::Bool(false) => dim("false"),
        Value::String(s) => fg(FG_VALUE, s),
        Value::Number(n) => fg(FG_NUM, &n.to_string()),
        _ => fg(FG_VALUE, &scalar_string(value)),
    }
}

fn scalar_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ─── metrics view ───────────────────────────────────────────────────

fn render_metrics(metrics: &filefacts::Metrics) -> String {
    // Group by leading prefix (`binary.foo` → group `binary`). Per-section
    // entropies (`sections[N].entropy`) collapse into a single `sections[*]`
    // bucket to keep the metric pane readable. `iter` yields keys sorted, so
    // each group's rows are too.
    let mut groups: std::collections::BTreeMap<&str, Vec<(&str, f64)>> =
        std::collections::BTreeMap::new();
    for (k, v) in metrics.iter() {
        groups.entry(metric_group(k)).or_default().push((k, v));
    }
    let mut out = String::new();
    for (group, entries) in groups {
        out.push_str(&format!("  {}\n", fg_bold(FG_VALUE, group)));
        // Drop the group prefix on each row.
        let strip_prefix = format!("{group}.");
        let rows: Vec<(String, String)> = entries
            .iter()
            .map(|&(k, v)| {
                let label = k.strip_prefix(&strip_prefix).unwrap_or(k).to_string();
                let value = format_metric_value(k, v);
                (label, value)
            })
            .collect();
        let key_w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (label, value) in rows {
            out.push_str(&format!(
                "    {label}  {value}\n",
                label = fg(FG_LABEL, &pad(&label, key_w)),
                value = value,
            ));
        }
    }
    out
}

fn metric_group(key: &str) -> &str {
    if let Some(idx) = key.find('.') {
        let head = &key[..idx];
        // Collapse `sections[0]`, `sections[1]`, ... under `sections` group.
        if let Some(stem) = head.split('[').next() {
            return stem;
        }
        return head;
    }
    key
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons,
    reason = "float-to-int `as` saturates (NaN is 0) and this only formats a metric for \
              display; the suffixes matched are metric-key segments, not file extensions"
)]
fn format_metric_value(key: &str, raw: f64) -> String {
    // Heuristics: booleans-as-numbers (0.0/1.0 for has_overlay etc.)
    // render compactly; sizes get byte-humanised; ratios/entropies
    // get fixed-precision; counts stay integer.
    if key.ends_with("_size") || key.ends_with("size_bytes") || key.ends_with("_size_bytes") {
        fg(FG_NUM, &humanize_bytes(raw as u64))
    } else if key.ends_with(".count") || key.ends_with("_count") || key.ends_with("error_count") {
        fg(FG_NUM, &(raw as u64).to_string())
    } else if key.ends_with("_ratio")
        || key.ends_with("_pct")
        || key.ends_with("entropy")
        || key.ends_with("_entropy")
        || key.ends_with("entropy_variance")
        || key.ends_with("name_entropy")
    {
        fg(FG_NUM, &format!("{raw:.3}"))
    } else if raw.fract() == 0.0 && raw.abs() < 1e15 {
        fg(FG_NUM, &(raw as i64).to_string())
    } else {
        fg(FG_NUM, &format!("{raw:.3}"))
    }
}

// ─── strings view ───────────────────────────────────────────────────

const STRING_PREVIEW_LIMIT: usize = 40;

/// The first `limit` of `rows` as JSON values, and how many rows there are.
fn preview<'r, T: Serialize + 'r>(
    rows: impl Iterator<Item = &'r T>,
    limit: usize,
) -> serde_json::Result<(usize, Vec<Value>)> {
    let mut shown = Vec::new();
    let mut total = 0;
    for row in rows {
        if total < limit {
            shown.push(serde_json::to_value(row)?);
        }
        total += 1;
    }
    Ok((total, shown))
}

/// The text view: per category, its row count and the first rows.
fn render_strings(categories: &[(&str, (usize, Vec<Value>))]) -> String {
    let mut out = String::new();
    // Summary line: ascii N · utf16le N
    let counts: Vec<String> = categories
        .iter()
        .map(|(k, (n, _))| format!("{} {}", fg(FG_LABEL, k), fg(FG_NUM, &n.to_string())))
        .collect();
    if !counts.is_empty() {
        out.push_str(&format!("  {}\n", counts.join(&dim("  ·  "))));
    }

    for (cat, (total, items)) in categories {
        if *total == 0 {
            continue;
        }
        out.push('\n');
        out.push_str(&format!(
            "  {} {}\n",
            fg_bold(FG_VALUE, cat),
            dim(&format!("({total})")),
        ));
        for s in items {
            let Value::Object(obj) = s else { continue };
            // Every row carries `value`; text rows are stng's (`data_offset`),
            // literal and comment rows filefacts' (`offset`).
            let offset = obj
                .get("offset")
                .or_else(|| obj.get("data_offset"))
                .and_then(Value::as_u64)
                .map_or_else(|| "        ".into(), |o| format!("0x{o:08x}"));
            let text = obj.get("value").and_then(Value::as_str).unwrap_or("");
            let mut tags = Vec::<String>::new();
            if let Some(section) = obj.get("section").and_then(Value::as_str) {
                tags.push(format!("{} {}", dim("§"), fg(FG_LABEL, section)));
            }
            if let Some(kind) = obj.get("kind").and_then(Value::as_str) {
                tags.push(dim(kind));
            }
            if let Some(encoding) = obj.get("encoding").and_then(Value::as_str) {
                tags.push(dim(encoding));
            }
            let tagged = if tags.is_empty() {
                String::new()
            } else {
                format!("  {}", tags.join(&dim(" ")))
            };
            out.push_str(&format!(
                "    {} {}{}\n",
                fg(FG_HEX, &offset),
                fg(FG_STR, &string_excerpt(text, 80)),
                tagged,
            ));
        }
        if *total > STRING_PREVIEW_LIMIT {
            out.push_str(&format!(
                "    {}\n",
                dim(&format!("... {} more", total - STRING_PREVIEW_LIMIT)),
            ));
        }
    }
    out
}

fn string_excerpt(text: &str, max: usize) -> String {
    let escaped = escape_controls(text);
    if escaped.chars().count() <= max {
        escaped.into_owned()
    } else {
        let keep = max.saturating_sub(1);
        let mut s: String = escaped.chars().take(keep).collect();
        s.push('…');
        s
    }
}

/// `text` with control characters written as escapes (`\n`, `\t`,
/// `\x1b`, `\x9b`, …), so file-derived text cannot drive the terminal.
/// Idempotent: the output holds no control characters.
fn escape_controls(text: &str) -> Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

// ─── sections view ──────────────────────────────────────────────────

const SECTIONS_PREVIEW_LIMIT: usize = 80;

/// Per-section block layout. Each section gets a name+flags+entropy
/// header line followed by an indented address-range line — readers
/// scan top-down by section, not column-by-column. Indented lines
/// share aligned `vaddr` / `file` columns within a single section so
/// the two extents stack cleanly.
fn render_sections(value: &Value, _metrics: Option<&Value>) -> String {
    let Value::Array(items) = value else {
        return render_values_tree(value);
    };
    let rows: Vec<SectionRow> = items.iter().filter_map(SectionRow::from_value).collect();
    if rows.is_empty() {
        return String::new();
    }
    // Unified column widths so `mem` and `disk` lines stack — the
    // hex extents and size columns sit in the same positions
    // regardless of which side is wider per section.
    let lo_w = rows
        .iter()
        .flat_map(|r| [r.vaddr_lo.len(), r.file_lo.len()])
        .max()
        .unwrap_or(0);
    let hi_w = rows
        .iter()
        .flat_map(|r| [r.vaddr_hi.len(), r.file_hi.len()])
        .max()
        .unwrap_or(0);
    let size_w = rows
        .iter()
        .flat_map(|r| [r.size_display.len(), r.file_size_display.len()])
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for (i, r) in rows.iter().take(SECTIONS_PREVIEW_LIMIT).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // Header: name (left), flags pill + entropy on the right.
        let mut tail = Vec::<String>::new();
        tail.push(r.flags_display.clone());
        if let Some(ent) = &r.entropy {
            tail.push(format!(
                "{} {}",
                fg(FG_LABEL, "entropy"),
                fg(FG_NUM, &format!("{ent:.2}")),
            ));
        }
        out.push_str(&format!(
            "  {name}  {tail}\n",
            name = fg_bold(FG_VALUE, &r.name),
            tail = tail.join(&dim("  ·  ")),
        ));

        // Two indented rows — `mem` (virtual extent) and `disk` (file
        // extent). Both share `lo_w` / `hi_w` / `size_w` so the
        // columns stack across sections too. BSS-style entries with no
        // on-disk bytes collapse to a single dim note.
        out.push_str(&format!(
            "    {label}   {lo} {arrow} {hi}   {size}\n",
            label = fg(FG_LABEL, "mem "),
            lo = fg(FG_HEX, &rpad(&r.vaddr_lo, lo_w)),
            arrow = dim(".."),
            hi = fg(FG_HEX, &rpad(&r.vaddr_hi, hi_w)),
            size = fg(FG_NUM, &rpad(&r.size_display, size_w)),
        ));
        if r.has_file_bytes {
            out.push_str(&format!(
                "    {label}   {lo} {arrow} {hi}   {size}\n",
                label = fg(FG_LABEL, "disk"),
                lo = fg(FG_HEX, &rpad(&r.file_lo, lo_w)),
                arrow = dim(".."),
                hi = fg(FG_HEX, &rpad(&r.file_hi, hi_w)),
                size = fg(FG_NUM, &rpad(&r.file_size_display, size_w)),
            ));
        } else {
            out.push_str(&format!(
                "    {label}   {note}\n",
                label = fg(FG_LABEL, "disk"),
                note = dim("(no on-disk bytes)"),
            ));
        }
    }
    if rows.len() > SECTIONS_PREVIEW_LIMIT {
        out.push_str(&format!(
            "  {}\n",
            dim(&format!("... {} more", rows.len() - SECTIONS_PREVIEW_LIMIT)),
        ));
    }
    out
}

struct SectionRow {
    name: String,
    flags_display: String,
    entropy: Option<f64>,
    vaddr_lo: String,
    vaddr_hi: String,
    size_display: String,
    has_file_bytes: bool,
    file_lo: String,
    file_hi: String,
    file_size_display: String,
}

impl SectionRow {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let vaddr = obj.get("vaddr").and_then(Value::as_u64).unwrap_or(0);
        let vsize = obj.get("vsize").and_then(Value::as_u64).unwrap_or(0);
        let file_offset = obj.get("file_offset").and_then(Value::as_u64).unwrap_or(0);
        let file_size = obj.get("file_size").and_then(Value::as_u64).unwrap_or(0);
        let entropy = obj.get("entropy").and_then(Value::as_f64);
        let flags_arr: Vec<&str> = obj
            .get("flags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        Some(Self {
            name,
            flags_display: format_section_flags(&flags_arr),
            entropy,
            vaddr_lo: format_hex(vaddr),
            vaddr_hi: format_hex(vaddr.saturating_add(vsize)),
            size_display: humanize_bytes(vsize),
            has_file_bytes: file_size > 0,
            file_lo: format_hex(file_offset),
            file_hi: format_hex(file_offset.saturating_add(file_size)),
            file_size_display: humanize_bytes(file_size),
        })
    }
}

fn format_hex(n: u64) -> String {
    if n == 0 {
        "0x0".into()
    } else {
        format!("0x{n:x}")
    }
}

fn format_section_flags(flags: &[&str]) -> String {
    let r = flags.contains(&"readable");
    let w = flags.contains(&"writable");
    let x = flags.contains(&"executable");
    let perms = format!(
        "{}{}{}",
        if r { fg(FG_FLAG_READ, "r") } else { dim("-") },
        if w { fg(FG_FLAG_WRITE, "w") } else { dim("-") },
        if x { fg(FG_FLAG_EXEC, "x") } else { dim("-") },
    );
    // Extras beyond r/w/x get appended dimly.
    let extras: Vec<&str> = flags
        .iter()
        .copied()
        .filter(|f| !matches!(*f, "readable" | "writable" | "executable"))
        .collect();
    if extras.is_empty() {
        perms
    } else {
        format!("{}  {}", perms, dim(&extras.join(",")))
    }
}

// ─── imports view ───────────────────────────────────────────────────

const IMPORTS_PREVIEW_PER_LIB: usize = 24;

/// An import row: name, file offset, ordinal.
type ImportRow<'a> = (&'a str, Option<u64>, Option<u32>);
/// An export row: name, file offset, ordinal, forwarder.
type ExportRow<'a> = (&'a str, Option<u64>, Option<u32>, Option<&'a str>);
/// A function row: name, file offset, complexity, callees.
type FunctionRow<'a> = (&'a str, Option<u64>, Option<u32>, &'a [String]);

fn render_imports(symbols: &[&Symbol]) -> String {
    // Group by library.
    let mut by_lib: std::collections::BTreeMap<&str, Vec<ImportRow<'_>>> =
        std::collections::BTreeMap::new();
    for symbol in symbols {
        let Symbol::Import {
            name,
            library,
            offset,
            ordinal,
            ..
        } = symbol
        else {
            continue;
        };
        let lib = library.as_deref().unwrap_or("(unknown)");
        by_lib
            .entry(lib)
            .or_default()
            .push((name, *offset, *ordinal));
    }
    let mut out = String::new();
    for (lib, entries) in by_lib {
        out.push_str(&format!(
            "  {} {}\n",
            fg_bold(FG_VALUE, lib),
            dim(&format!("({})", entries.len())),
        ));
        let show = entries.get(..IMPORTS_PREVIEW_PER_LIB).unwrap_or(&entries);
        let off_w = show
            .iter()
            .filter_map(|(_, offset, _)| *offset)
            .map(|n| format!("0x{n:x}").len())
            .max()
            .unwrap_or(0);
        for (name, offset, ordinal) in show {
            let offset = offset.map(|n| format!("0x{n:x}")).unwrap_or_default();
            let tail = match ordinal {
                Some(o) => format!("  {}", dim(&format!("#{o}"))),
                None => String::new(),
            };
            out.push_str(&format!(
                "    {off}  {name}{tail}\n",
                off = fg(FG_HEX, &rpad(&offset, off_w)),
                name = fg(FG_VALUE, name),
            ));
        }
        if entries.len() > show.len() {
            out.push_str(&format!(
                "    {}\n",
                dim(&format!("... {} more", entries.len() - show.len())),
            ));
        }
    }
    out
}

// ─── exports view ───────────────────────────────────────────────────

const EXPORTS_PREVIEW_LIMIT: usize = 80;

fn render_exports(symbols: &[&Symbol]) -> String {
    let exports: Vec<ExportRow<'_>> = symbols
        .iter()
        .filter_map(|symbol| match symbol {
            Symbol::Export {
                name,
                offset,
                ordinal,
                forward_to,
            } => Some((name.as_str(), *offset, *ordinal, forward_to.as_deref())),
            _ => None,
        })
        .collect();
    let off_w = exports
        .iter()
        .filter_map(|(_, offset, _, _)| *offset)
        .map(|n| format!("0x{n:x}").len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (name, offset, ordinal, forward_to) in exports.iter().take(EXPORTS_PREVIEW_LIMIT) {
        let offset = offset.map_or_else(|| "·".into(), |n| format!("0x{n:x}"));
        let mut tail = Vec::<String>::new();
        if let Some(o) = ordinal {
            tail.push(dim(&format!("#{o}")));
        }
        if let Some(f) = forward_to {
            tail.push(format!("{} {}", dim("→"), fg(FG_VALUE, f)));
        }
        out.push_str(&format!(
            "  {off}  {name}{tail}\n",
            off = fg(FG_HEX, &rpad(&offset, off_w)),
            name = fg(FG_VALUE, name),
            tail = if tail.is_empty() {
                String::new()
            } else {
                format!("  {}", tail.join(&dim(" ")))
            },
        ));
    }
    if exports.len() > EXPORTS_PREVIEW_LIMIT {
        out.push_str(&format!(
            "  {}\n",
            dim(&format!(
                "... {} more",
                exports.len() - EXPORTS_PREVIEW_LIMIT
            )),
        ));
    }
    out
}

// ─── functions view ─────────────────────────────────────────────────

const FUNCTIONS_PREVIEW_LIMIT: usize = 60;

fn render_functions(symbols: &[&Symbol]) -> String {
    let functions: Vec<FunctionRow<'_>> = symbols
        .iter()
        .filter_map(|symbol| match symbol {
            Symbol::Function {
                name,
                offset,
                complexity,
                callees,
            } => Some((name.as_str(), *offset, *complexity, callees.as_slice())),
            _ => None,
        })
        .collect();
    let off_w = functions
        .iter()
        .filter_map(|(_, offset, _, _)| *offset)
        .map(|n| format!("0x{n:x}").len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (name, offset, complexity, callees) in functions.iter().take(FUNCTIONS_PREVIEW_LIMIT) {
        let offset = offset.map_or_else(|| "·".into(), |n| format!("0x{n:x}"));
        let tail = match complexity {
            Some(c) => format!("  {}", fg(FG_LABEL, &format!("cx={c}"))),
            None => String::new(),
        };
        out.push_str(&format!(
            "  {off}  {name}{tail}\n",
            off = fg(FG_HEX, &rpad(&offset, off_w)),
            name = fg(FG_VALUE, name),
        ));
        if !callees.is_empty() {
            let inline = callees
                .iter()
                .take(8)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if callees.len() > 8 {
                format!(", … +{}", callees.len() - 8)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "    {arrow} {body}{suf}\n",
                arrow = dim("→"),
                body = dim(&inline),
                suf = dim(&suffix),
            ));
        }
    }
    if functions.len() > FUNCTIONS_PREVIEW_LIMIT {
        out.push_str(&format!(
            "  {}\n",
            dim(&format!(
                "... {} more",
                functions.len() - FUNCTIONS_PREVIEW_LIMIT
            )),
        ));
    }
    out
}

// ─── symbols view ───────────────────────────────────────────────────

const SYMBOL_PREVIEW_LIMIT: usize = 30;

/// Terminal rendering of the unified `Symbols` view (or any per-kind
/// filtered subset): kind, primary name/target/path, and a compact label
/// for the optional fields most rule authors care about.
fn render_symbols(symbols: &[&Symbol]) -> String {
    let mut out = String::new();
    for symbol in symbols.iter().take(SYMBOL_PREVIEW_LIMIT) {
        let (kind, extras) = match symbol {
            Symbol::Import { library, .. } => ("import", library.clone().unwrap_or_default()),
            Symbol::Export { .. } => ("export", String::new()),
            Symbol::Function { .. } => ("function", String::new()),
            Symbol::Call { args, .. } => (
                "call",
                args.iter().map(format_arg).collect::<Vec<_>>().join(", "),
            ),
            Symbol::Member { .. } => ("member", String::new()),
            Symbol::Bind { .. } => ("bind", String::new()),
            Symbol::Identifier { .. } => ("identifier", String::new()),
            // `Symbol` is non-exhaustive: a kind added later still renders.
            _ => ("symbol", String::new()),
        };
        out.push_str(&format!(
            "  {kind} {name}{spacer}{extras}\n",
            kind = dim(&rpad(kind, 10)),
            name = fg(FG_VALUE, symbol.name().unwrap_or("·")),
            spacer = if extras.is_empty() { "" } else { "  " },
            extras = dim(&extras),
        ));
    }
    if symbols.len() > SYMBOL_PREVIEW_LIMIT {
        out.push_str(&format!(
            "    {}\n",
            dim(&format!(
                "... {} more",
                symbols.len() - SYMBOL_PREVIEW_LIMIT
            )),
        ));
    }
    out
}

/// A call argument as it would read in source: literals with their
/// value, everything else by shape.
fn format_arg(arg: &Arg) -> String {
    match arg {
        Arg::String { value } => format!("\"{}\"", string_excerpt(value, 40)),
        Arg::Template { value } => format!("`{}`", string_excerpt(value, 40)),
        Arg::Number { text, .. } => text.clone(),
        Arg::Identifier { name } => name.clone(),
        Arg::Bool { value } => value.to_string(),
        Arg::Null => "null".into(),
        Arg::Object => "{…}".into(),
        Arg::Array => "[…]".into(),
        Arg::Function => "<function>".into(),
        Arg::Call => "<call>".into(),
        // `Expression`, and any shape added later.
        _ => "<expr>".into(),
    }
}

// ─── archive members view ───────────────────────────────────────────

const ARCHIVE_MEMBERS_PREVIEW_LIMIT: usize = 50;

/// One line per member: size, path, then whatever sets it apart from a
/// plain stored file. Paths come from the archive, so control characters
/// are escaped.
fn render_archive_members(members: &[filefacts::ArchiveMember]) -> String {
    let shown = members
        .get(..ARCHIVE_MEMBERS_PREVIEW_LIMIT)
        .unwrap_or(members);
    let sizes: Vec<String> = shown.iter().map(|m| humanize_bytes(m.size_bytes)).collect();
    let size_w = sizes.iter().map(String::len).max().unwrap_or(0);
    let mut out = String::new();
    for (m, size) in shown.iter().zip(&sizes) {
        let mut tail = Vec::<String>::new();
        if let Some(kind) = m.entry_type.as_deref().filter(|k| *k != "regular") {
            tail.push(dim(kind));
        }
        if let Some(method) = m.compression.as_ref().and_then(|c| c.method.as_deref()) {
            tail.push(dim(method));
        }
        if m.encrypted {
            tail.push(fg(FG_FLAG_WRITE, "encrypted"));
        }
        if let Some(link) = m.linkname.as_deref() {
            tail.push(format!(
                "{} {}",
                dim("→"),
                fg(FG_VALUE, &string_excerpt(link, 80))
            ));
        }
        out.push_str(&format!(
            "  {size}  {path}{tail}\n",
            size = fg(FG_NUM, &rpad(size, size_w)),
            path = fg(FG_VALUE, &string_excerpt(&m.path, 120)),
            tail = if tail.is_empty() {
                String::new()
            } else {
                format!("  {}", tail.join(&dim(" ")))
            },
        ));
    }
    if members.len() > shown.len() {
        out.push_str(&format!(
            "  {}\n",
            dim(&format!("... {} more", members.len() - shown.len()))
        ));
    }
    out
}

// ─── errors view ────────────────────────────────────────────────────

fn render_errors(value: &Value) -> String {
    let Value::Array(items) = value else {
        return render_values_tree(value);
    };
    if items.is_empty() {
        return format!("  {}\n", fg(FG_OK, "✓ none"));
    }
    let mut out = String::new();
    for v in items {
        let Some(obj) = v.as_object() else { continue };
        let kind = obj.get("kind").and_then(Value::as_str).unwrap_or("error");
        let stage = obj.get("stage").and_then(Value::as_str).unwrap_or("");
        let msg = obj.get("message").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!(
            "  {} {}  {}\n",
            fg_bold(FG_ERROR, kind),
            dim(stage),
            fg(FG_VALUE, msg),
        ));
    }
    out
}

// ─── helpers ────────────────────────────────────────────────────────

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Left-pad `s` to `width` ASCII columns, then color downstream. The
/// renderers color *after* padding so `{:<width$}` formatting never has
/// to count ANSI escape bytes — strings reaching `pad`/`rpad` are plain.
fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(width);
        out.push_str(s);
        for _ in 0..width - len {
            out.push(' ');
        }
        out
    }
}

fn rpad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(width);
        for _ in 0..width - len {
            out.push(' ');
        }
        out.push_str(s);
        out
    }
}

fn usage() -> String {
    let mut msg = String::from(
        "\
usage: filefacts [options] [view] <path>

Emits the facts bundle for <path>, or one view of it. A directory is walked
recursively, one result per regular file. The bundle holds every view but
flow, which is opt-in; the symbol kinds (imports .. identifiers) are the
matching rows of symbols.

views (select one by name, or with the --<view> flag; a name that is also
an existing file is read as that file):
",
    );
    for (_, name, help) in VIEWS {
        msg.push_str(&format!("  {name:<17}  {help}\n"));
    }
    msg.push_str(
        "
options:
  -f, --format <terminal|json>
                     Output format. Default: terminal.
  -p, --pretty       Compatibility shorthand for --format json.
  -h, --help         Show this help and exit.
  -V, --version      Print version and exit.
",
    );
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Hermetic open: tests here assert `parse_count() == 1`, which only
    /// holds when this process actually runs the extraction pipeline, so the
    /// disk cache is off explicitly — `FILEFACTS_CACHE` in the environment
    /// must not let a warm entry from a prior run leave the count at 0.
    fn open<'a>(path: &Path, bytes: &'a [u8]) -> ParsedFile<'a> {
        OpenOptions::new().cache(false).path(path).open(bytes)
    }

    /// Parse `words` as a command line on which only `existing` names files.
    fn parse(words: &[&str], existing: &[&str]) -> Result<Args, String> {
        let words = words.iter().map(OsString::from);
        match parse_args(words, |p| existing.iter().any(|e| Path::new(e) == p))? {
            ParseOutcome::Run(args) => Ok(args),
            other => panic!("expected a run, got {other:?}"),
        }
    }

    const SOURCE: &[u8] = b"import os  # fetch\nos.system('curl http://example.invalid/x')\n";

    /// The header's metric names must be ones the library can emit, or the
    /// header silently shows nothing after a rename.
    #[test]
    fn header_metrics_are_in_the_catalog() {
        let (catalog, _) = filefacts::known_metrics();
        for key in [FILE_SIZE, FILE_ENTROPY] {
            assert!(catalog.contains(&key), "{key} is not a cataloged metric");
        }
    }

    #[test]
    fn every_view_is_reachable_by_name_and_flag() {
        let help = usage();
        let mut names = BTreeSet::new();
        for &(view, name, _) in VIEWS {
            assert!(names.insert(name), "{name} is listed twice");
            assert_eq!(View::from_name(name), Some(view));
            assert_eq!(view.name(), name);
            assert!(
                help.contains(&format!("\n  {name} ")),
                "{name} not in usage"
            );
            let flag = format!("--{name}");
            for words in [[name, "x"], ["x", name], [flag.as_str(), "x"]] {
                let args = parse(&words, &[]).unwrap();
                assert_eq!(args.view, Some(view), "{words:?}");
                assert_eq!(args.path.as_deref(), Some(Path::new("x")), "{words:?}");
            }
        }
    }

    #[test]
    fn only_explicit_on_values_enable_debug_output() {
        use std::ffi::OsStr;
        assert!(debug_requested(Some(OsStr::new("1"))));
        assert!(debug_requested(Some(OsStr::new("yes"))));
        for off in ["", "0", "false", "FALSE"] {
            assert!(!debug_requested(Some(OsStr::new(off))), "{off:?}");
        }
        assert!(!debug_requested(None));
    }

    #[test]
    fn bundle_carries_every_view() {
        let parsed = open(Path::new("example.py"), SOURCE);
        let bundle = serde_json::to_value(Bundle(&parsed)).unwrap();
        let view_value = |view| serde_json::to_value(ViewData(&parsed, view)).unwrap();
        for &(view, name, _) in VIEWS {
            match view {
                _ if view.bundled() => assert_eq!(bundle[name], view_value(view), "{name}"),
                // A kind's rows are the matching rows of `symbols`.
                View::Kind(_) => {
                    let rows = view_value(view);
                    let symbols = bundle["symbols"].as_array().unwrap();
                    assert!(rows.as_array().unwrap().iter().all(|r| symbols.contains(r)));
                }
                // Opt-in: the README documents that the bundle skips it.
                View::Flow => {}
                _ => panic!("{name} is neither bundled nor covered"),
            }
        }
        assert!(
            !view_value(View::Kind(SymbolKind::Import))
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!bundle["comments"].as_array().unwrap().is_empty());

        let keys: BTreeSet<&str> = bundle
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<&str> = std::iter::once("schema_version")
            .chain(bundled_views().map(|(_, name)| name))
            .collect();
        assert_eq!(keys, expected);

        let text = format_terminal(Path::new("example.py"), &parsed, None).unwrap();
        for (_, name) in bundled_views() {
            let label = fg_bold(heading_color(name), &name.to_uppercase());
            assert!(
                text.contains(&label),
                "{name} missing from the terminal bundle"
            );
        }
        assert_eq!(parsed.parse_count(), 1);
    }

    #[test]
    fn existing_file_wins_over_a_positional_view_name() {
        let args = parse(&["metrics", "x"], &[]).unwrap();
        assert_eq!(args.view, Some(View::Metrics));
        assert_eq!(args.path.as_deref(), Some(Path::new("x")));

        let args = parse(&["metrics"], &["metrics"]).unwrap();
        assert_eq!(args.view, None);
        assert_eq!(args.path.as_deref(), Some(Path::new("metrics")));

        let args = parse(&["--metrics", "metrics"], &["metrics"]).unwrap();
        assert_eq!(args.view, Some(View::Metrics));
        assert_eq!(args.path.as_deref(), Some(Path::new("metrics")));

        let err = parse(&["metrics", "x"], &["metrics"]).unwrap_err();
        assert!(err.contains("--metrics"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argument_is_a_path() {
        use std::os::unix::ffi::OsStrExt;
        let raw = std::ffi::OsStr::from_bytes(b"sample-\xff.py").to_os_string();
        let words = ["--format".into(), "json".into(), raw.clone()];
        let Ok(ParseOutcome::Run(args)) = parse_args(words, |_| false) else {
            panic!("non-UTF-8 path rejected");
        };
        assert_eq!(args.path, Some(PathBuf::from(raw)));
        assert_eq!(args.format, Format::Json);
    }

    #[test]
    fn serialisation_failure_is_reported_and_output_failure_ends_the_run() {
        let path = Path::new("x");
        let data = serde_json::to_value(std::collections::HashMap::from([((1, 2), 3)]));
        assert!(!report_serialisation(path, data.map(drop)).unwrap());

        let closed = serde_json::Error::io(io::ErrorKind::BrokenPipe.into());
        let err = report_serialisation(path, Err(closed)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(exit_code(Err(err)), ExitCode::SUCCESS);
        let full = io::Error::from(io::ErrorKind::StorageFull);
        assert_eq!(exit_code(Err(full)), ExitCode::from(1));
    }

    /// Output that the reader has stopped consuming.
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn closed_output_ends_the_run_in_every_format() {
        let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/markdown"));
        for format in [Format::Terminal, Format::Json] {
            let args = Args {
                format,
                ..Args::default()
            };
            let options = OpenOptions::new().cache(false);
            let err = run(&mut ClosedPipe, dir, &args, &options).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{format:?}");
        }
    }

    #[test]
    fn flow_is_a_format_neutral_view() {
        assert_eq!(View::from_name("flow"), Some(View::Flow));
        assert_eq!(View::Flow.name(), "flow");
        let parsed = open(Path::new("example.py"), b"send(acquire())\n");
        let value = serde_json::to_value(ViewData(&parsed, View::Flow)).unwrap();
        assert_eq!(value["producer"], "tree-sitter");
        assert_eq!(value["language"], "python");
        assert!(value["values"].as_array().is_some());
        assert_eq!(parsed.parse_count(), 1);
    }

    #[test]
    fn unavailable_binary_flow_is_null_not_an_empty_graph() {
        let bytes = include_bytes!("../../tests/fixtures/test.elf");
        let parsed = open(Path::new("example.elf"), bytes);
        assert!(parsed.flow().is_none());
        let value = serde_json::to_value(ViewData(&parsed, View::Flow)).unwrap();
        assert!(value.is_null());
    }

    #[test]
    fn archive_members_render_one_escaped_line_each() {
        let mut bytes = Vec::new();
        let mut zip = zip::ZipWriter::new(io::Cursor::new(&mut bytes));
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for name in ["a.txt", "evil\x1b[2J.txt"] {
            zip.start_file(name, stored).unwrap();
            zip.write_all(b"hello\n").unwrap();
        }
        zip.finish().unwrap();

        let parsed = open(Path::new("x.zip"), &bytes);
        let view = Some(View::ArchiveMembers);
        let text = format_terminal(Path::new("x.zip"), &parsed, view).unwrap();
        let rows: Vec<&str> = text.lines().filter(|l| l.contains(".txt")).collect();
        assert_eq!(rows.len(), 2, "{text}");
        assert!(rows[1].contains("evil\\x1b[2J.txt"), "{text}");
        assert!(!text.contains("evil\x1b"), "{text}");
    }

    /// The string views serialise only the rows they show, yet count and
    /// report every row.
    #[test]
    fn string_views_count_every_row_beyond_the_preview() {
        let source: String = (0..120)
            .map(|i| format!("var v{i} = \"literal-{i}\"; // note {i}\n"))
            .collect();
        let parsed = open(Path::new("many.js"), source.as_bytes());
        for (view, total) in [
            (View::Literals, parsed.literals().len()),
            (View::Comments, parsed.comments().len()),
        ] {
            assert!(total > ARRAY_PREVIEW_LIMIT, "{view:?} {total}");
            let rendered = render_view(&parsed, view).unwrap();
            assert_eq!(rendered.count, Some(total), "{view:?}");
            let more = format!("... {} more", total - ARRAY_PREVIEW_LIMIT);
            assert!(rendered.body.contains(&more), "{view:?}: {}", rendered.body);
        }
        let ascii = parsed.text().ascii().count();
        assert!(ascii > STRING_PREVIEW_LIMIT, "{ascii}");
        let body = render_view(&parsed, View::Text).unwrap().body;
        assert!(body.contains(&format!("({ascii})")), "{body}");
        let more = format!("... {} more", ascii - STRING_PREVIEW_LIMIT);
        assert!(body.contains(&more), "{body}");
    }

    #[test]
    fn located_metric_renders_as_a_number() {
        let parsed = open(Path::new("example.py"), SOURCE);
        let located = parsed
            .metrics()
            .iter_facts()
            .find(|(_, f)| !f.spans.is_empty());
        assert!(located.is_some(), "fixture has no located metric");
        let text = format_terminal(Path::new("example.py"), &parsed, Some(View::Metrics)).unwrap();
        assert!(!text.contains("spans"), "{text}");
    }

    /// Escape sequences in `text` other than the renderer's own colours.
    fn foreign_escapes(text: &str) -> Vec<String> {
        const OWN: [&str; 3] = ["\x1b[38;2;", "\x1b[1;38;2;", "\x1b[0m"];
        text.match_indices('\x1b')
            .map(|(i, _)| &text[i..])
            .filter(|rest| !OWN.iter().any(|own| rest.starts_with(own)))
            .map(|rest| rest.chars().take(12).collect())
            .collect()
    }

    #[test]
    fn control_characters_from_the_file_are_escaped_in_every_view() {
        let files: [(&str, &[u8]); 2] = [
            (
                "evil\x1b[2J.py",
                b"# \x1b]0;pwned\x07\nimport os\nos.system(\"\x1b[2J\", \"\xc2\x9b31m\")\n",
            ),
            ("evil.json", br#"{"k\u001b[2J": ["\u001b]0;pwned\u0007"]}"#),
        ];
        for (name, bytes) in files {
            let parsed = open(Path::new(name), bytes);
            let views = VIEWS.iter().map(|(view, _, _)| Some(*view));
            for view in std::iter::once(None).chain(views) {
                let text = format_terminal(Path::new(name), &parsed, view).unwrap();
                assert_eq!(
                    foreign_escapes(&text),
                    Vec::<String>::new(),
                    "{name} {view:?}"
                );
                let stray = text
                    .chars()
                    .find(|c| c.is_control() && !"\n\x1b".contains(*c));
                assert_eq!(stray, None, "{name} {view:?}: {text}");
            }
            let bundle = format_terminal(Path::new(name), &parsed, None).unwrap();
            assert!(bundle.contains("\\x1b[2J"), "{bundle}");
        }
    }

    #[test]
    fn symbols_render_from_their_typed_fields() {
        let call = Symbol::Call {
            target: Some("os.system".into()),
            args: vec![
                Arg::String {
                    value: "curl \x1b[2J".into(),
                },
                Arg::Number {
                    text: "0x10".into(),
                    value: 16,
                    radix: 16,
                },
                Arg::Identifier { name: "url".into() },
                Arg::Bool { value: true },
                Arg::Call,
                Arg::Expression,
            ],
            offset: None,
        };
        let text = render_symbols(&[&call]);
        assert!(
            text.contains(r#""curl \x1b[2J", 0x10, url, true, <call>, <expr>"#),
            "{text}"
        );

        let function = Symbol::Function {
            name: "_get_cpuid".into(),
            offset: Some(0x4080),
            complexity: Some(7),
            callees: vec!["_resolve".into(), "_lzma_crc32".into()],
        };
        let text = render_functions(&[&function]);
        assert!(text.contains("0x4080") && text.contains("cx=7"), "{text}");
        assert!(text.contains("_resolve, _lzma_crc32"), "{text}");

        let import = Symbol::Import {
            name: "CreateFileW".into(),
            alias: None,
            library: Some("kernel32.dll".into()),
            offset: None,
            ordinal: Some(7),
        };
        let export = Symbol::Export {
            name: "Run".into(),
            offset: Some(0x1000),
            ordinal: None,
            forward_to: Some("NTDLL.RtlRun".into()),
        };
        let text = render_imports(&[&import, &export]);
        assert!(
            text.contains("kernel32.dll") && text.contains("#7"),
            "{text}"
        );
        assert!(!text.contains("Run"), "{text}");
        let text = render_exports(&[&import, &export]);
        assert!(text.contains("NTDLL.RtlRun"), "{text}");
        assert!(!text.contains("CreateFileW"), "{text}");
    }
}
