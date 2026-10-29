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
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

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
    /// `--no-rizin`: never run rizin.
    no_rizin: bool,
    /// `--rizin-timeout`: the budget for one rizin run.
    rizin_timeout: Option<Duration>,
}

impl Args {
    /// The open options these arguments ask for. The CLI rescans the same
    /// files, so `main` turns the extraction cache on unless `--no-cache` or
    /// `FILEFACTS_CACHE` turns it off.
    fn options(&self, cache: bool) -> OpenOptions<'static> {
        let mut options = OpenOptions::new().cache(cache).rizin(!self.no_rizin);
        if let Some(timeout) = self.rizin_timeout {
            options = options.rizin_timeout(timeout);
        }
        options
    }
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
            return ExitCode::from(EXIT_USAGE);
        }
    };

    match rizin_concurrency(std::env::var_os("FILEFACTS_RIZIN_CONCURRENCY").as_deref()) {
        Ok(limit) => filefacts::rizin::set_max_concurrent_runs(limit),
        Err(value) => eprintln!(
            "filefacts: ignoring FILEFACTS_RIZIN_CONCURRENCY={}: not a positive integer",
            escape_controls(&value)
        ),
    }
    let cache = !args.no_cache && filefacts::cache::env_override().unwrap_or(true);
    let options = args.options(cache);
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
        filefacts::rizin::log_stats();
    }
    exit_code(result)
}

/// Whether a `FILEFACTS_DEBUG` value turns debug output on: any value except
/// empty, `0` or `false`. The generic `DEBUG` is deliberately not honoured:
/// other tools read it, and it must not make this one chatty.
fn debug_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")))
}

/// The rizin concurrency limit a `FILEFACTS_RIZIN_CONCURRENCY` value asks
/// for: unset or empty is no limit, a positive integer is that limit, and
/// anything else is returned as an error to report.
fn rizin_concurrency(value: Option<&OsStr>) -> Result<Option<NonZeroUsize>, String> {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    value
        .to_str()
        .and_then(|v| v.trim().parse::<NonZeroUsize>().ok())
        .map(Some)
        .ok_or_else(|| value.to_string_lossy().into_owned())
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
    let mut signals = match signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP]) {
        Ok(signals) => signals,
        Err(error) => {
            tracing::warn!(target: LOG_TARGET, %error, "cannot install signal cleanup");
            return;
        }
    };
    let spawned = std::thread::Builder::new()
        .name("filefacts-signals".into())
        .spawn(move || {
            if let Some(signal) = signals.forever().next() {
                filefacts::rizin::kill_all_rizin_groups();
                std::process::exit(128 + signal);
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(target: LOG_TARGET, %error, "cannot start the signal cleanup thread");
    }
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

// analyze_one parses one file and writes its rendered output. A file that
// cannot be read, parsed or serialised is reported on stderr and yields
// `Ok(false)` so a directory walk carries on; an `Err` means `out` failed.
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

/// Rewrites DEL, C1 controls and Unicode bidirectional formatting characters
/// as JSON escapes. JSON permits them raw and serde_json leaves them so, but a
/// terminal may act on them, and these strings come from the file under
/// analysis. Every matched byte sequence in JSON output lies inside a string,
/// and serde_json writes whole UTF-8 fragments, so the rewrite is safe per
/// write.
struct EscapeJsonTerminalControls<W>(W);

impl<W: Write> Write for EscapeJsonTerminalControls<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        let mut i = 0;
        while let Some(&b) = buf.get(i) {
            let escape = match (b, buf.get(i + 1), buf.get(i + 2)) {
                (0x7f, _, _) => Some((0x7f_u32, 1)),
                (0xc2, Some(&c1 @ 0x80..=0x9f), _) => Some((u32::from(c1), 2)),
                // U+061C ARABIC LETTER MARK.
                (0xd8, Some(0x9c), _) => Some((0x061c, 2)),
                // U+200E/U+200F and U+202A..U+202E.
                (0xe2, Some(0x80), Some(&tail @ (0x8e..=0x8f | 0xaa..=0xae))) => {
                    Some((0x2000 + u32::from(tail - 0x80), 3))
                }
                // U+2066..U+2069.
                (0xe2, Some(0x81), Some(&tail @ 0xa6..=0xa9)) => {
                    Some((0x2040 + u32::from(tail - 0x80), 3))
                }
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
            "--no-rizin" => parsed.no_rizin = true,
            "-f" | "--format" => {
                let value = iter.next().ok_or("--format requires terminal or json")?;
                parsed.format = parse_format(&value.to_string_lossy())?;
            }
            "--rizin-timeout" => {
                let value = iter
                    .next()
                    .ok_or("--rizin-timeout requires a number of seconds")?;
                parsed.rizin_timeout = Some(parse_timeout(&value.to_string_lossy())?);
            }
            "--" => parsed.paths.extend(iter.by_ref().map(PathBuf::from)),
            s if s.starts_with("--format=") => {
                parsed.format = parse_format(&s["--format=".len()..])?;
            }
            s if s.starts_with("--rizin-timeout=") => {
                parsed.rizin_timeout = Some(parse_timeout(&s["--rizin-timeout=".len()..])?);
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

fn parse_timeout(value: &str) -> Result<Duration, String> {
    match value.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(format!(
            "--rizin-timeout requires a positive number of seconds, not {value}"
        )),
    }
}

fn usage() -> String {
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
    for view in View::ALL {
        msg.push_str(&format!("  {:<17}  {}\n", view.name(), view.description()));
    }
    msg.push_str(&format!(
        "
options:
  -f, --format <terminal|json>
                     Output format. Default: terminal.
  --no-cache         Do not read or write the extraction cache.
  --no-rizin         Do not run rizin, even when it is installed.
  --rizin-timeout <seconds>
                     Wall-clock budget for one rizin run. Default: {timeout}.
  --                 Read every later argument as a path.
  -h, --help         Show this help and exit.
  -V, --version      Print version and exit.

environment:
  FILEFACTS_CACHE    0 or false turns the extraction cache off; it is on by
                     default.
  FILEFACTS_DEBUG    Any value but empty, 0 or false prints diagnostics and
                     rizin statistics to stderr.
  FILEFACTS_RIZIN_CONCURRENCY
                     Most rizin runs at once in this process. Default: no
                     limit.
  NO_COLOR           Any non-empty value turns terminal colour off. Colour is
                     only ever used when stdout is a terminal.
  COLUMNS            Width of the rule under each file header. Default: 100.

exit status:
  0    every file was analysed.
  1    some file could not be read or serialised, or output failed.
  2    the command line could not be parsed.
  128+N  killed by signal N; in-flight rizin runs are killed with it.
",
        timeout = filefacts::rizin::DEFAULT_RIZIN_TIMEOUT_SECS,
    ));
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Parse `words` as a command line on which only `existing` names files.
    fn parse(words: &[&str], existing: &[&str]) -> Result<Args, String> {
        let words = words.iter().map(OsString::from);
        match parse_args(words, |p| existing.iter().any(|e| Path::new(e) == p))? {
            ParseOutcome::Run(args) => Ok(args),
            other => panic!("expected a run, got {other:?}"),
        }
    }

    fn paths(args: &Args) -> Vec<&str> {
        args.paths.iter().map(|p| p.to_str().unwrap()).collect()
    }

    #[test]
    fn every_view_is_reachable_by_name_and_flag() {
        let help = usage();
        let mut names = BTreeSet::new();
        for view in View::ALL {
            let name = view.name();
            assert!(names.insert(name), "{name} is listed twice");
            assert!(
                help.contains(&format!("\n  {name} ")),
                "{name} not in usage"
            );
            let flag = format!("--{name}");
            for words in [[name, "x"], ["x", name], [flag.as_str(), "x"]] {
                let args = parse(&words, &[]).unwrap();
                assert_eq!(args.view, Some(view), "{words:?}");
                assert_eq!(paths(&args), ["x"], "{words:?}");
            }
        }
    }

    #[test]
    fn usage_documents_every_environment_variable_and_exit_status() {
        let help = usage();
        for name in [
            "FILEFACTS_CACHE",
            "FILEFACTS_DEBUG",
            "FILEFACTS_RIZIN_CONCURRENCY",
            "NO_COLOR",
            "COLUMNS",
            "--no-cache",
            "--no-rizin",
            "--rizin-timeout",
        ] {
            assert!(help.contains(name), "{name} not in usage");
        }
        for code in [EXIT_FAILURE, EXIT_USAGE] {
            assert!(
                help.contains(&format!("\n  {code} ")),
                "exit {code} not in usage"
            );
        }
        assert!(!help.contains("--pretty"));
    }

    #[test]
    fn only_explicit_on_values_enable_debug_output() {
        assert!(debug_requested(Some(OsStr::new("1"))));
        assert!(debug_requested(Some(OsStr::new("yes"))));
        for off in ["", "0", "false", "FALSE"] {
            assert!(!debug_requested(Some(OsStr::new(off))), "{off:?}");
        }
        assert!(!debug_requested(None));
    }

    #[test]
    fn rizin_concurrency_accepts_only_positive_integers() {
        assert_eq!(rizin_concurrency(None), Ok(None));
        assert_eq!(rizin_concurrency(Some(OsStr::new(""))), Ok(None));
        assert_eq!(
            rizin_concurrency(Some(OsStr::new("4"))),
            Ok(NonZeroUsize::new(4))
        );
        for bad in ["0", "-1", "many", "1.5"] {
            assert_eq!(
                rizin_concurrency(Some(OsStr::new(bad))),
                Err(bad.to_string()),
                "{bad}"
            );
        }
    }

    #[test]
    fn several_paths_are_analysed_in_order() {
        let args = parse(&["a", "metrics", "b", "c"], &[]).unwrap();
        assert_eq!(args.view, Some(View::Metrics));
        assert_eq!(paths(&args), ["a", "b", "c"]);
        // After `--` a view name is a path, so it shadows nothing.
        let args = parse(&["--", "metrics", "b"], &["metrics"]).unwrap();
        assert_eq!(args.view, None);
        assert_eq!(paths(&args), ["metrics", "b"]);
        assert!(parse(&[], &[]).unwrap_err().contains("no path"));
    }

    #[test]
    fn options_flags_parse_and_reach_the_open_options() {
        let args = parse(
            &["--no-cache", "--no-rizin", "--rizin-timeout", "30", "x"],
            &[],
        )
        .unwrap();
        assert!(args.no_cache && args.no_rizin);
        assert_eq!(args.rizin_timeout, Some(Duration::from_secs(30)));
        let args = parse(&["--rizin-timeout=5", "x"], &[]).unwrap();
        assert_eq!(args.rizin_timeout, Some(Duration::from_secs(5)));
        for bad in [
            &["--rizin-timeout", "0", "x"][..],
            &["--rizin-timeout=soon", "x"],
        ] {
            assert!(parse(bad, &[]).is_err(), "{bad:?}");
        }
        assert!(parse(&["--rizin-timeout"], &[]).is_err());
        assert!(parse(&["--pretty", "x"], &[]).is_err());
    }

    #[test]
    fn existing_file_wins_over_a_positional_view_name() {
        let args = parse(&["metrics", "x"], &[]).unwrap();
        assert_eq!(args.view, Some(View::Metrics));
        assert_eq!(paths(&args), ["x"]);

        let args = parse(&["metrics"], &["metrics"]).unwrap();
        assert_eq!(args.view, None);
        assert_eq!(paths(&args), ["metrics"]);

        let args = parse(&["--metrics", "metrics"], &["metrics"]).unwrap();
        assert_eq!(args.view, Some(View::Metrics));
        assert_eq!(paths(&args), ["metrics"]);

        let err = parse(&["metrics", "x"], &["metrics"]).unwrap_err();
        assert!(err.contains("--metrics"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argument_is_a_path() {
        use std::os::unix::ffi::OsStrExt;
        let raw = OsStr::from_bytes(b"sample-\xff.py").to_os_string();
        let words = ["--format".into(), "json".into(), raw.clone()];
        let Ok(ParseOutcome::Run(args)) = parse_args(words, |_| false) else {
            panic!("non-UTF-8 path rejected");
        };
        assert_eq!(args.paths, [PathBuf::from(raw)]);
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
        assert_eq!(exit_code(Err(full)), ExitCode::from(EXIT_FAILURE));
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

    fn hermetic() -> OpenOptions<'static> {
        OpenOptions::new().cache(false).rizin(false)
    }

    const PLAIN: Style = Style {
        color: false,
        width: 100,
    };

    #[test]
    fn closed_output_ends_the_run_in_every_format() {
        let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/markdown"));
        for format in [Format::Terminal, Format::Json] {
            let args = Args {
                format,
                ..Args::default()
            };
            let err = run(&mut ClosedPipe, dir, &args, PLAIN, &hermetic()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{format:?}");
        }
    }

    /// A walk visits files in path order, descending into each directory at
    /// its place in that order, and skips symlinks.
    #[test]
    fn directory_walk_is_sorted_and_skips_symlinks() {
        let dir = std::env::temp_dir().join(format!("filefacts-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["b", "a/z", "c"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for file in ["b/2.txt", "a/z/1.txt", "a/0.txt", "c/3.txt", "d.txt"] {
            std::fs::write(dir.join(file), b"x\n").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("d.txt"), dir.join("a/link.txt")).unwrap();
        let args = Args {
            view: Some(View::Fileid),
            ..Args::default()
        };
        let mut out = Vec::new();
        assert!(run(&mut out, &dir, &args, PLAIN, &hermetic()).unwrap());
        // Each file's terminal output opens with its path.
        let out = String::from_utf8(out).unwrap();
        let root = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);
        let visited: Vec<String> = out
            .lines()
            .filter_map(|line| line.strip_prefix(&root))
            .map(|rest| rest.split("  ").next().unwrap().replace('\\', "/"))
            .collect();
        assert_eq!(
            visited,
            ["a/0.txt", "a/z/1.txt", "b/2.txt", "c/3.txt", "d.txt"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
