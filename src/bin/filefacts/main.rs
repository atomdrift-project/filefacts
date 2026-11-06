//! `filefacts` command-line interface.
//!
//! Reads each file named and emits its facts bundle, or one selected view
//! from it. A directory is walked recursively in sorted order, one result per
//! regular file. The terminal renderer ([`render`]) shows the JSON detail in
//! a colored, aligned layout.

mod render;

/// jemalloc as the global allocator, on unix systems where it is not already
/// the OS allocator (see Cargo.toml), unless built without the default
/// `jemalloc` feature. `--features jemalloc-prof` adds jemalloc's heap
/// profiling (`_RJEM_MALLOC_CONF=prof:true,...`).
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
mod alloc {
    #[global_allocator]
    static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

    /// Default jemalloc options: return freed pages to the OS immediately
    /// (`dirty_decay_ms:0`) instead of holding them for the default 10s decay
    /// window. filefacts is a one-shot batch tool; each file's alloc/free
    /// burst otherwise leaves dirty pages resident across the rest of the
    /// walk, inflating peak RSS ~60% on a 200MB mixed corpus (345MB → 216MB)
    /// for ~1% wall-clock. Overrides jemalloc's weak `_rjem_malloc_conf`
    /// definition; the `_RJEM_MALLOC_CONF` environment variable still takes
    /// precedence, so heap-profiling builds keep working unchanged.
    ///
    /// SAFETY: jemalloc declares the symbol `const char *_rjem_malloc_conf`
    /// and reads it as a NUL-terminated C string. `Option<&'static [u8; N]>`
    /// has the layout of a nullable pointer (the null-pointer optimisation
    /// guarantees it), and the reference's provenance covers every byte
    /// jemalloc reads, up to and including the terminator. `export_name` is
    /// unsafe only because a symbol of the wrong type would be undefined
    /// behaviour; these two are the invariants that make it the right one.
    /// Scoped allow per the Cargo.toml `unsafe_code = "deny"` rationale.
    #[allow(unsafe_code, non_upper_case_globals)]
    #[unsafe(export_name = "_rjem_malloc_conf")]
    static malloc_conf: Option<&'static [u8; 17]> = Some(b"dirty_decay_ms:0\0");
}

use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal as _, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use filefacts::{OpenOptions, ParsedFile, View};
use render::{Style, escape_controls};

/// Target of the CLI's own `tracing` events.
const LOG_TARGET: &str = "filefacts::cli";

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Terminal,
    Json,
}

#[derive(Debug, Default)]
struct Args {
    paths: Vec<PathBuf>,
    format: Format,
    /// The single view to emit; `None` emits the bundle.
    view: Option<View>,
    /// `--no-cache`: never read or write the extraction cache.
    no_cache: bool,
}

/// Exit status when a file could not be analysed or output failed.
const EXIT_FAILURE: u8 = 1;
/// Exit status for a command line that could not be parsed.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let debug = debug_requested(std::env::var_os("FILEFACTS_DEBUG").as_deref());
    if debug {
        let _ = tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .without_time()
            .try_init();
    }
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
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let cache = !args.no_cache && filefacts::cache::env_override().unwrap_or(true);
    // The CLI rescans the same files, so the extraction cache is on unless
    // `--no-cache` or `FILEFACTS_CACHE` turns it off.
    let options = OpenOptions::new().cache(cache);
    // Drops superseded schema versions and bounds the cache on a background
    // thread, without blocking: a short run may exit before it finishes and
    // the next run resumes. A run told to leave the cache alone must not
    // delete from it either.
    if cache {
        filefacts::cache::cleanup();
    }

    let style = Style {
        color: args.format == Format::Terminal
            && io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
        width: Style::width_from(std::env::var("COLUMNS").ok().as_deref()),
    };
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut result = Ok(true);
    for path in &args.paths {
        match run(&mut out, path, &args, style, &options) {
            Ok(ok) => result = result.map(|all| all && ok),
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    if debug {
        tracing::info!(stats = ?filefacts::recovery_stats(), "binform recovery stats");
    }
    exit_code(result)
}

/// Whether a `FILEFACTS_DEBUG` value turns debug output on: any value except
/// empty, `0` or `false`. The generic `DEBUG` is deliberately not honoured:
/// other tools read it, and it must not make this one chatty.
fn debug_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")))
}

/// Exit status for a run: `Ok(false)` means some file failed and was
/// reported; `Err` means stdout itself failed.
fn exit_code(result: io::Result<bool>) -> ExitCode {
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_FAILURE),
        // The reader went away (`filefacts dir | head`): stop quietly and
        // succeed, as other Unix filters do.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("filefacts: cannot write output: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Analyze `root`, walking it recursively when it is a directory. Returns
/// `Ok(false)` when any file failed; an `Err` from `out` ends the walk.
fn run(
    out: &mut impl Write,
    root: &Path,
    args: &Args,
    style: Style,
    options: &OpenOptions<'_>,
) -> io::Result<bool> {
    if !root.is_dir() {
        return analyze_one(out, root, args, style, options);
    }
    let mut ok = true;
    // One sorted listing per directory being walked, so files come out in
    // path order, whatever order the filesystem returns them in.
    let mut stack = vec![sorted_entries(root, &mut ok)];
    while let Some(entries) = stack.last_mut() {
        let Some((path, kind)) = entries.next() else {
            stack.pop();
            continue;
        };
        if kind.is_dir() {
            stack.push(sorted_entries(&path, &mut ok));
        } else if kind.is_file() {
            ok &= analyze_one(out, &path, args, style, options)?;
        } else if kind.is_symlink() {
            // Not followed: a link can point outside the tree or back into it.
            tracing::debug!(target: LOG_TARGET, path = %path.display(), "skipping symlink");
        } else {
            tracing::debug!(target: LOG_TARGET, path = %path.display(), "skipping non-regular file");
        }
    }
    Ok(ok)
}

/// The entries of `dir`, sorted by name, with their types. A directory or
/// entry that cannot be read is reported and clears `ok`.
fn sorted_entries(dir: &Path, ok: &mut bool) -> std::vec::IntoIter<(PathBuf, std::fs::FileType)> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("filefacts: cannot read dir {}: {e}", shown(dir));
            *ok = false;
            return Vec::new().into_iter();
        }
    };
    let mut listed = Vec::new();
    for entry in entries {
        match entry.and_then(|entry| Ok((entry.path(), entry.file_type()?))) {
            Ok(listed_entry) => listed.push(listed_entry),
            Err(e) => {
                eprintln!("filefacts: cannot read entry in {}: {e}", shown(dir));
                *ok = false;
            }
        }
    }
    listed.sort_by(|(a, _), (b, _)| a.cmp(b));
    listed.into_iter()
}

/// Parse one file and write its rendered output. A file that cannot be
/// read, parsed or serialised is reported on stderr and yields `Ok(false)`
/// so a directory walk carries on; an `Err` means `out` failed.
fn analyze_one(
    out: &mut impl Write,
    path: &Path,
    args: &Args,
    style: Style,
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
        Format::Json => write_json(out, &parsed, args.view),
        Format::Terminal => render::format_terminal(style, path, &parsed, args.view)
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

/// Pretty-print the selected view (or the bundle) straight to `out`.
/// Building an intermediate `serde_json::Value` tree (and then one giant
/// string) would double peak memory on string-heavy files; serialising the
/// borrowed views keeps only one copy live.
fn write_json(
    out: &mut impl Write,
    parsed: &ParsedFile<'_>,
    view: Option<View>,
) -> serde_json::Result<()> {
    let mut escaped = EscapeJsonTerminalControls(&mut *out);
    match view {
        None => serde_json::to_writer_pretty(&mut escaped, &parsed.bundle())?,
        Some(view) => serde_json::to_writer_pretty(&mut escaped, &parsed.view(view))?,
    }
    out.write_all(b"\n").map_err(serde_json::Error::io)
}

/// Rewrites the characters the terminal renderer escapes (see
/// [`render::is_unsafe_char`]) as JSON `\u` escapes, which decode to the same
/// text. JSON permits them raw and serde_json leaves them so, but a terminal
/// may act on them, and these strings come from the file under analysis.
/// serde_json has already escaped the C0 controls, so any left (the newlines
/// of pretty-printing) are JSON's own. Every other match lies inside a
/// string, and serde_json writes whole UTF-8 fragments, so the rewrite is
/// safe per write.
struct EscapeJsonTerminalControls<W>(W);

impl<W: Write> Write for EscapeJsonTerminalControls<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.utf8_chunks() {
            let text = chunk.valid();
            let mut start = 0;
            for (i, c) in text.char_indices() {
                if c < ' ' || !render::is_unsafe_char(c) {
                    continue;
                }
                self.0
                    .write_all(text.get(start..i).unwrap_or_default().as_bytes())?;
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(self.0, "\\u{unit:04x}")?;
                }
                start = i + c.len_utf8();
            }
            self.0
                .write_all(text.get(start..).unwrap_or_default().as_bytes())?;
            self.0.write_all(chunk.invalid())?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[derive(Debug)]
enum ParseOutcome {
    Run(Args),
    Help,
    Version,
}

/// Parse the command line (without the program name). `exists` reports
/// whether a path names an existing file.
///
/// A positional word naming a view selects it when no view is selected yet
/// and no file of that name exists; any other word is a path, and every word
/// after `--` is. A view name read as a path because the file exists is
/// ambiguous next to other paths, so that is an error naming the flag that
/// selects the view: a path is never silently taken for a view, nor a view
/// for one of several paths.
fn parse_args(
    args: impl IntoIterator<Item = OsString>,
    exists: impl Fn(&Path) -> bool,
) -> Result<ParseOutcome, String> {
    let mut parsed = Args::default();
    let mut shadowed_view: Option<&'static str> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        // Flags and view names are ASCII, so an argument that is not UTF-8
        // can only be a path; keep it as an OsString.
        let Some(s) = arg.to_str() else {
            parsed.paths.push(PathBuf::from(arg));
            continue;
        };
        match s {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "-V" | "--version" => return Ok(ParseOutcome::Version),
            "--no-cache" => parsed.no_cache = true,
            "-f" | "--format" => {
                let value = iter.next().ok_or("--format requires terminal or json")?;
                parsed.format = parse_format(&value.to_string_lossy())?;
            }
            "--" => parsed.paths.extend(iter.by_ref().map(PathBuf::from)),
            s if let Some(value) = s.strip_prefix("--format=") => {
                parsed.format = parse_format(value)?;
            }
            s if s.starts_with('-') => {
                let view = s.strip_prefix("--").and_then(View::from_name);
                let Some(view) = view else {
                    return Err(format!("unknown flag: {s}"));
                };
                if parsed.view.replace(view).is_some() {
                    return Err("multiple view selectors supplied; pick one".into());
                }
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
                parsed.paths.push(PathBuf::from(arg));
            }
        }
    }
    if parsed.paths.is_empty() {
        return Err("no path supplied".into());
    }
    if let Some(name) = shadowed_view
        && parsed.paths.len() > 1
    {
        return Err(format!(
            "`{name}` is an existing file, so it was read as a path; use --{name} to \
             select the view, or -- before the paths to read every one as a path"
        ));
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

fn usage() -> String {
    use std::fmt::Write as _;
    let mut msg = String::from(
        "\
usage: filefacts [options] [view] <path>...

Emits the facts bundle for each <path>, or one view of it. A directory is
walked recursively in sorted order, one result per regular file; symlinks
inside it are not followed. The bundle holds every view but flow, which is
opt-in; the symbol kinds (imports .. identifiers) are the matching rows of
symbols.

views (select one by name, or with the --<view> flag; a name that is also
an existing file is read as that file):
",
    );
    for &view in View::ALL {
        // Writing to a `String` cannot fail.
        let _ = writeln!(msg, "  {:<17}  {}", view.name(), view.description());
    }
    msg.push_str(
        "
options:
  -f, --format <terminal|json>
                     Output format. Default: terminal.
  --no-cache         Do not read or write the extraction cache.
  --                 Read every later argument as a path.
  -h, --help         Show this help and exit.
  -V, --version      Print version and exit.

environment:
  FILEFACTS_CACHE    0 or false turns the extraction cache off; it is on by
                     default.
  FILEFACTS_DEBUG    Any value but empty, 0 or false prints diagnostics and
                     function-recovery statistics to stderr.
  NO_COLOR           Any non-empty value turns terminal colour off. Colour is
                     only ever used when stdout is a terminal.
  COLUMNS            Width of the rule under each file header. Default: 100.

exit status:
  0    every file was analysed.
  1    some file could not be read or serialised, or output failed.
  2    the command line could not be parsed.
  128+N  killed by signal N.
",
    );
    msg
}

#[cfg(test)]
mod tests;
