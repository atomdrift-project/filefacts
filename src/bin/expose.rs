//! `expose` command-line interface.
//!
//! Single-shot file inspector. Reads one file, dumps the four views
//! (`fileid`, `values`, `strings`, `metrics`) as JSON, exits.
//!
//! Usage:
//!
//! ```text
//! expose <path>
//! expose -p|--pretty <path>
//! expose --values <path>     # only the values view
//! expose --strings <path>    # only the strings view
//! expose --metrics <path>    # only the metrics view
//! expose --fileid <path>     # only the fileid view (no extraction)
//! expose --help
//! expose --version
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;
use serde_json::json;

#[derive(Default)]
struct Args {
    path: Option<PathBuf>,
    pretty: bool,
    only: View,
}

#[derive(Default, Copy, Clone, PartialEq, Eq)]
enum View {
    #[default]
    All,
    Fileid,
    Values,
    Metrics,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("expose: {msg}");
            print_usage(true);
            return ExitCode::from(2);
        }
    };

    let Some(path) = args.path else {
        print_usage(true);
        return ExitCode::from(2);
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("expose: cannot read {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };

    let parsed = match expose::open_with_path(&path, &bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("expose: {e}");
            return ExitCode::from(1);
        }
    };

    let output = build_output(&parsed, args.only);

    let serialized = if args.pretty {
        serde_json::to_string_pretty(&output)
    } else {
        serde_json::to_string(&output)
    };
    match serialized {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("expose: serialisation failed: {e}");
            ExitCode::from(1)
        }
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct Output<'a> {
    schema_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fileid: Option<&'a expose::FileId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<&'a expose::Values>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<&'a expose::Metrics>,
}

fn build_output(parsed: &expose::ParsedFile<'_>, only: View) -> serde_json::Value {
    let mut out = Output {
        schema_version: expose::SCHEMA_VERSION,
        fileid: None,
        values: None,
        metrics: None,
    };
    match only {
        View::All => {
            out.fileid = Some(parsed.fileid());
            out.values = Some(parsed.values());
            out.metrics = Some(parsed.metrics());
        }
        View::Fileid => out.fileid = Some(parsed.fileid()),
        View::Values => out.values = Some(parsed.values()),
        View::Metrics => out.metrics = Some(parsed.metrics()),
    }
    serde_json::to_value(&out).unwrap_or_else(|_| json!({}))
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage(false);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("expose {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-p" | "--pretty" => args.pretty = true,
            "--fileid" => set_view(&mut args.only, View::Fileid)?,
            "--values" => set_view(&mut args.only, View::Values)?,
            "--metrics" => set_view(&mut args.only, View::Metrics)?,
            "--" => {
                if let Some(rest) = iter.next() {
                    if args.path.is_some() {
                        return Err("multiple paths supplied".into());
                    }
                    args.path = Some(PathBuf::from(rest));
                }
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown flag: {s}"));
            }
            _ => {
                if args.path.is_some() {
                    return Err("multiple paths supplied".into());
                }
                args.path = Some(PathBuf::from(arg));
            }
        }
    }
    Ok(args)
}

fn set_view(slot: &mut View, view: View) -> Result<(), String> {
    if *slot != View::All {
        return Err("multiple view selectors supplied; pick one".into());
    }
    *slot = view;
    Ok(())
}

fn print_usage(to_stderr: bool) {
    let msg = "\
usage: expose [options] <path>

options:
  -p, --pretty       Pretty-print the JSON output.
  --fileid           Only emit the fileid view (no extraction work).
  --values           Only emit the structural values tree (sections,
                     strings, ast, and format-specific keys live under
                     this tree).
  --metrics          Only emit the derived metrics view.
  -h, --help         Show this help and exit.
  -V, --version      Print version and exit.
";
    if to_stderr {
        eprint!("{msg}");
    } else {
        print!("{msg}");
    }
}
