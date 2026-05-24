//! `filefacts` command-line interface.
//!
//! Reads one file and emits its facts bundle, or one selected top-level
//! view from that bundle. When the positional argument is a directory it
//! is walked recursively, emitting one bundle per regular file.
//!
//! The terminal renderer mirrors the JSON detail in a colored, aligned
//! layout (heading pills, grouped metrics, columnar section / symbol
//! tables) inspired by sibling tools cleave and litmus.

// Use jemalloc on unix systems where it isn't the OS default (see Cargo.toml).
// Built-in `--features jemalloc-prof` activates jemalloc's heap-profiling support
// (`_RJEM_MALLOC_CONF=prof:true,...`) which cleave-tuna's memory-mode benches consume.
#[cfg(all(
    unix,
    not(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use serde_json::{json, Map, Value};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Terminal,
    Json,
}

#[derive(Default)]
struct Args {
    path: Option<PathBuf>,
    format: Format,
    view: View,
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
enum View {
    #[default]
    All,
    Fileid,
    Values,
    Strings,
    Metrics,
    Ast,
    Sections,
    Imports,
    Exports,
    Functions,
    Errors,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("filefacts: {msg}");
            print_usage(true);
            return ExitCode::from(2);
        }
    };

    let Some(root) = args.path.clone() else {
        print_usage(true);
        return ExitCode::from(2);
    };

    if root.is_dir() {
        let mut had_error = false;
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("filefacts: cannot read dir {}: {e}", dir.display());
                    had_error = true;
                    continue;
                }
            };
            for entry in entries.flatten() {
                let p = entry.path();
                match entry.file_type() {
                    Ok(ft) if ft.is_dir() => stack.push(p),
                    Ok(ft) if ft.is_file() => {
                        if !analyze_one(&p, &args) {
                            had_error = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        return if had_error {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }

    if analyze_one(&root, &args) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

// analyze_one parses one file and prints its rendered bundle. Returns
// false on read/parse/serialise failure so the caller can track whether
// any file in a directory walk failed.
fn analyze_one(path: &Path, args: &Args) -> bool {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("filefacts: cannot read {}: {e}", path.display());
            return false;
        }
    };

    let parsed = match filefacts::open_with_path(path, &bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("filefacts: {}: {e}", path.display());
            return false;
        }
    };

    let output = build_output(&parsed, args.view);
    let rendered = match args.format {
        Format::Json => match serde_json::to_string_pretty(&output) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "filefacts: serialisation failed for {}: {e}",
                    path.display()
                );
                return false;
            }
        },
        Format::Terminal => format_terminal(path, &parsed, args.view, &output),
    };

    println!("{rendered}");
    true
}

#[derive(Serialize)]
struct Facts<'a> {
    schema_version: &'static str,
    fileid: &'a filefacts::FileId,
    values: &'a filefacts::Values,
    strings: &'a filefacts::Strings,
    metrics: &'a filefacts::Metrics,
    ast: &'a filefacts::Ast,
    sections: &'a filefacts::Sections,
    imports: &'a filefacts::Imports,
    exports: &'a filefacts::Exports,
    functions: &'a filefacts::Functions,
    errors: &'a filefacts::Errors,
}

fn build_output(parsed: &filefacts::ParsedFile<'_>, view: View) -> Value {
    match view {
        View::All => serde_json::to_value(Facts {
            schema_version: filefacts::SCHEMA_VERSION,
            fileid: parsed.fileid(),
            values: parsed.values(),
            strings: parsed.strings(),
            metrics: parsed.metrics(),
            ast: parsed.ast(),
            sections: parsed.sections(),
            imports: parsed.imports(),
            exports: parsed.exports(),
            functions: parsed.functions(),
            errors: parsed.errors(),
        }),
        View::Fileid => serde_json::to_value(parsed.fileid()),
        View::Values => serde_json::to_value(parsed.values()),
        View::Strings => serde_json::to_value(parsed.strings()),
        View::Metrics => serde_json::to_value(parsed.metrics()),
        View::Ast => serde_json::to_value(parsed.ast()),
        View::Sections => serde_json::to_value(parsed.sections()),
        View::Imports => serde_json::to_value(parsed.imports()),
        View::Exports => serde_json::to_value(parsed.exports()),
        View::Functions => serde_json::to_value(parsed.functions()),
        View::Errors => serde_json::to_value(parsed.errors()),
    }
    .unwrap_or_else(|_| json!({}))
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage(false);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("filefacts {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-f" | "--format" => {
                let Some(value) = iter.next() else {
                    return Err("--format requires terminal or json".into());
                };
                args.format = parse_format(&value)?;
            }
            s if s.starts_with("--format=") => {
                args.format = parse_format(&s["--format=".len()..])?;
            }
            "-p" | "--pretty" => args.format = Format::Json,
            "--fileid" => set_view(&mut args.view, View::Fileid)?,
            "--values" => set_view(&mut args.view, View::Values)?,
            "--strings" => set_view(&mut args.view, View::Strings)?,
            "--metrics" => set_view(&mut args.view, View::Metrics)?,
            "--ast" => set_view(&mut args.view, View::Ast)?,
            "--sections" => set_view(&mut args.view, View::Sections)?,
            "--imports" => set_view(&mut args.view, View::Imports)?,
            "--exports" => set_view(&mut args.view, View::Exports)?,
            "--functions" => set_view(&mut args.view, View::Functions)?,
            "--errors" => set_view(&mut args.view, View::Errors)?,
            "--" => {
                let Some(rest) = iter.next() else {
                    return Err("-- must be followed by a path".into());
                };
                set_path(&mut args.path, rest)?;
                if iter.peek().is_some() {
                    return Err("multiple paths supplied".into());
                }
            }
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            s => {
                if args.view == View::All {
                    if let Some(view) = parse_view(s) {
                        args.view = view;
                        continue;
                    }
                }
                set_path(&mut args.path, arg)?;
            }
        }
    }
    Ok(args)
}

fn parse_format(value: &str) -> Result<Format, String> {
    match value {
        "terminal" | "term" => Ok(Format::Terminal),
        "json" => Ok(Format::Json),
        other => Err(format!("unknown format: {other}")),
    }
}

fn parse_view(value: &str) -> Option<View> {
    Some(match value {
        "fileid" => View::Fileid,
        "values" => View::Values,
        "strings" => View::Strings,
        "metrics" => View::Metrics,
        "ast" => View::Ast,
        "sections" => View::Sections,
        "imports" => View::Imports,
        "exports" => View::Exports,
        "functions" => View::Functions,
        "errors" => View::Errors,
        _ => return None,
    })
}

fn set_view(slot: &mut View, view: View) -> Result<(), String> {
    if *slot != View::All {
        return Err("multiple view selectors supplied; pick one".into());
    }
    *slot = view;
    Ok(())
}

fn set_path(slot: &mut Option<PathBuf>, value: String) -> Result<(), String> {
    if slot.is_some() {
        return Err("multiple paths supplied".into());
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

// ─── theme ──────────────────────────────────────────────────────────
//
// Truecolor RGB escapes, no external dep. Honour NO_COLOR by emitting
// raw text when the env var is set.

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
    if no_color() {
        return text.to_string();
    }
    let Rgb(r, g, b) = c;
    format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
}

fn fg_bold(c: Rgb, text: &str) -> String {
    if no_color() {
        return text.to_string();
    }
    let Rgb(r, g, b) = c;
    format!("\x1b[1;38;2;{r};{g};{b}m{text}\x1b[0m")
}

fn dim(text: &str) -> String {
    fg(FG_DIM, text)
}

fn pill_bg(label: &str, bg: Rgb) -> String {
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
    path: &std::path::Path,
    parsed: &filefacts::ParsedFile<'_>,
    view: View,
    output: &Value,
) -> String {
    let width = terminal_width();
    let mut out = String::new();

    out.push_str(&render_file_header(path, parsed, width));
    out.push('\n');

    match view {
        View::All => {
            render_section(&mut out, "fileid", output.get("fileid"), render_fileid);
            render_section(&mut out, "values", output.get("values"), render_values_tree);
            render_section(&mut out, "strings", output.get("strings"), render_strings);
            let metrics = output.get("metrics");
            render_section(&mut out, "metrics", metrics, render_metrics);
            render_section(&mut out, "sections", output.get("sections"), |v| {
                render_sections(v, None)
            });
            render_section(&mut out, "imports", output.get("imports"), render_imports);
            render_section(&mut out, "exports", output.get("exports"), render_exports);
            render_section(
                &mut out,
                "functions",
                output.get("functions"),
                render_functions,
            );
            render_section(&mut out, "ast", output.get("ast"), render_ast);
            render_section(&mut out, "errors", output.get("errors"), render_errors);
        }
        view => {
            let renderer: Box<dyn Fn(&Value) -> String> = match view {
                View::Fileid => Box::new(render_fileid),
                View::Values => Box::new(render_values_tree),
                View::Strings => Box::new(render_strings),
                View::Metrics => Box::new(render_metrics),
                View::Sections => Box::new(|v| render_sections(v, None)),
                View::Imports => Box::new(render_imports),
                View::Exports => Box::new(render_exports),
                View::Functions => Box::new(render_functions),
                View::Ast => Box::new(render_ast),
                View::Errors => Box::new(render_errors),
                View::All => unreachable!(),
            };
            let label = view.name();
            let count = top_level_count(output);
            out.push_str(&heading(label, count));
            out.push('\n');
            let body = renderer(output);
            if body.is_empty() {
                out.push_str(&dim("  (empty)"));
                out.push('\n');
            } else {
                out.push_str(&body);
            }
        }
    }
    out.trim_end().to_string()
}

fn render_section<F>(out: &mut String, name: &str, value: Option<&Value>, render: F)
where
    F: FnOnce(&Value) -> String,
{
    let Some(value) = value else {
        return;
    };
    let count = top_level_count(value);
    if is_empty_value(value) {
        out.push_str(&heading(name, count));
        out.push('\n');
        out.push_str(&dim("  (empty)"));
        out.push_str("\n\n");
        return;
    }
    out.push_str(&heading(name, count));
    out.push('\n');
    let body = render(value);
    out.push_str(&body);
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
            if o.len() <= 6 {
                None
            } else {
                Some(o.len())
            }
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
    let size = parsed.metrics().get("file.size_bytes").unwrap_or(0.0) as u64;
    let entropy = parsed.metrics().get("file.entropy");
    let mut subtitle = Vec::<String>::new();
    subtitle.push(fg(FG_LABEL, &humanize_bytes(size)));
    if let Some(e) = entropy {
        subtitle.push(fg(FG_LABEL, &format!("entropy {e:.2}")));
    }
    if parsed.fileid().extension_mismatch {
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
        _ => scalar_string(value),
    }
}

fn scalar_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ─── metrics view ───────────────────────────────────────────────────

fn render_metrics(value: &Value) -> String {
    let Value::Object(map) = value else {
        return render_values_tree(value);
    };
    // Group by leading prefix (`binary.foo` → group `binary`). Per-section
    // entropies (`sections[N].entropy`) collapse into a single `sections[*]`
    // bucket to keep the metric pane readable.
    let mut groups: std::collections::BTreeMap<String, Vec<(&str, &Value)>> =
        std::collections::BTreeMap::new();
    for (k, v) in map {
        let group = metric_group(k).to_string();
        groups.entry(group).or_default().push((k, v));
    }
    let mut out = String::new();
    for (group, mut entries) in groups {
        entries.sort_by_key(|(k, _)| *k);
        out.push_str(&format!("  {}\n", fg_bold(FG_VALUE, &group)));
        // Drop the group prefix on each row.
        let strip_prefix = format!("{group}.");
        let rows: Vec<(String, String)> = entries
            .iter()
            .map(|(k, v)| {
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

fn format_metric_value(key: &str, value: &Value) -> String {
    match value {
        Value::Number(n) => {
            let raw = n.as_f64().unwrap_or(0.0);
            // Heuristics: booleans-as-numbers (0.0/1.0 for has_overlay etc.)
            // render compactly; sizes get byte-humanised; ratios/entropies
            // get fixed-precision; counts stay integer.
            if key.ends_with("_size") || key.ends_with("size_bytes") || key.ends_with("_size_bytes")
            {
                fg(FG_NUM, &humanize_bytes(raw as u64))
            } else if key.ends_with(".count")
                || key.ends_with("_count")
                || key.ends_with("error_count")
            {
                fg(FG_NUM, &(raw as u64).to_string())
            } else if key.ends_with("_ratio")
                || key.ends_with("_pct")
                || key.ends_with("entropy")
                || key.ends_with("_entropy")
                || key.ends_with("entropy_mean")
                || key.ends_with("entropy_max")
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
        other => format_scalar(other),
    }
}

// ─── strings view ───────────────────────────────────────────────────

const STRING_PREVIEW_LIMIT: usize = 40;

fn render_strings(value: &Value) -> String {
    let Value::Object(map) = value else {
        return render_values_tree(value);
    };
    let mut categories: Vec<(&String, &Value)> = map.iter().collect();
    categories.sort_by_key(|(k, _)| k.as_str());

    let mut out = String::new();
    // Summary line: ascii N · literals N · utf16le N
    let counts: Vec<String> = categories
        .iter()
        .map(|(k, v)| {
            let n = v.as_array().map_or(0, Vec::len);
            format!("{} {}", fg(FG_LABEL, k), fg(FG_NUM, &n.to_string()))
        })
        .collect();
    if !counts.is_empty() {
        out.push_str(&format!("  {}\n", counts.join(&dim("  ·  "))));
    }

    for (cat, items) in categories {
        let Value::Array(items) = items else {
            continue;
        };
        if items.is_empty() {
            continue;
        }
        out.push('\n');
        out.push_str(&format!(
            "  {} {}\n",
            fg_bold(FG_VALUE, cat),
            dim(&format!("({})", items.len())),
        ));
        for s in items.iter().take(STRING_PREVIEW_LIMIT) {
            let Value::Object(obj) = s else { continue };
            let offset = obj
                .get("offset")
                .and_then(Value::as_u64)
                .map_or_else(|| "        ".into(), |o| format!("0x{o:08x}"));
            let text = obj.get("text").and_then(Value::as_str).unwrap_or("");
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
        if items.len() > STRING_PREVIEW_LIMIT {
            out.push_str(&format!(
                "    {}\n",
                dim(&format!("... {} more", items.len() - STRING_PREVIEW_LIMIT)),
            ));
        }
    }
    out
}

fn string_excerpt(text: &str, max: usize) -> String {
    let escaped: String = text
        .chars()
        .map(|c| match c {
            '\n' => "\\n".into(),
            '\r' => "\\r".into(),
            '\t' => "\\t".into(),
            c if c.is_control() => format!("\\x{:02x}", c as u32),
            c => c.to_string(),
        })
        .collect();
    if escaped.chars().count() <= max {
        escaped
    } else {
        let keep = max.saturating_sub(1);
        let mut s: String = escaped.chars().take(keep).collect();
        s.push('…');
        s
    }
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
    let r = flags.iter().any(|f| *f == "readable" || *f == "read");
    let w = flags.iter().any(|f| *f == "writable" || *f == "write");
    let x = flags
        .iter()
        .any(|f| *f == "executable" || *f == "execinstr");
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
        .filter(|f| {
            !matches!(
                *f,
                "readable" | "read" | "writable" | "write" | "executable" | "execinstr"
            )
        })
        .collect();
    if extras.is_empty() {
        perms
    } else {
        format!("{}  {}", perms, dim(&extras.join(",")))
    }
}

// ─── imports view ───────────────────────────────────────────────────

const IMPORTS_PREVIEW_PER_LIB: usize = 24;

fn render_imports(value: &Value) -> String {
    let Value::Array(items) = value else {
        return render_values_tree(value);
    };
    // Group by library.
    let mut by_lib: std::collections::BTreeMap<String, Vec<&Map<String, Value>>> =
        std::collections::BTreeMap::new();
    for v in items {
        let Some(obj) = v.as_object() else { continue };
        let lib = obj
            .get("library")
            .and_then(Value::as_str)
            .unwrap_or("(unknown)")
            .to_string();
        by_lib.entry(lib).or_default().push(obj);
    }
    let mut out = String::new();
    for (lib, entries) in by_lib {
        out.push_str(&format!(
            "  {} {}\n",
            fg_bold(FG_VALUE, &lib),
            dim(&format!("({})", entries.len())),
        ));
        let show: Vec<&&Map<String, Value>> =
            entries.iter().take(IMPORTS_PREVIEW_PER_LIB).collect();
        let off_w = show
            .iter()
            .filter_map(|e| e.get("offset").and_then(Value::as_u64))
            .map(|n| format!("0x{n:x}").len())
            .max()
            .unwrap_or(0);
        for e in &show {
            let name = e.get("name").and_then(Value::as_str).unwrap_or("");
            let offset = e
                .get("offset")
                .and_then(Value::as_u64)
                .map(|n| format!("0x{n:x}"))
                .unwrap_or_default();
            let ordinal = e.get("ordinal").and_then(Value::as_u64);
            let source = e.get("source").and_then(Value::as_str);
            let mut tail = Vec::<String>::new();
            if let Some(o) = ordinal {
                tail.push(dim(&format!("#{o}")));
            }
            if let Some(s) = source {
                tail.push(dim(s));
            }
            out.push_str(&format!(
                "    {off}  {name}{tail}\n",
                off = fg(FG_HEX, &rpad(&offset, off_w)),
                name = fg(FG_VALUE, name),
                tail = if tail.is_empty() {
                    String::new()
                } else {
                    format!("  {}", tail.join(&dim(" ")))
                },
            ));
        }
        if entries.len() > IMPORTS_PREVIEW_PER_LIB {
            out.push_str(&format!(
                "    {}\n",
                dim(&format!(
                    "... {} more",
                    entries.len() - IMPORTS_PREVIEW_PER_LIB
                )),
            ));
        }
    }
    out
}

// ─── exports view ───────────────────────────────────────────────────

const EXPORTS_PREVIEW_LIMIT: usize = 80;

fn render_exports(value: &Value) -> String {
    let Value::Array(items) = value else {
        return render_values_tree(value);
    };
    let mut out = String::new();
    let off_w = items
        .iter()
        .filter_map(|v| v.as_object())
        .filter_map(|o| o.get("offset").and_then(Value::as_u64))
        .map(|n| format!("0x{n:x}").len())
        .max()
        .unwrap_or(0);
    for v in items.iter().take(EXPORTS_PREVIEW_LIMIT) {
        let Some(obj) = v.as_object() else { continue };
        let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
        let offset = obj
            .get("offset")
            .and_then(Value::as_u64)
            .map_or_else(|| "·".into(), |n| format!("0x{n:x}"));
        let mut tail = Vec::<String>::new();
        if let Some(o) = obj.get("ordinal").and_then(Value::as_u64) {
            tail.push(dim(&format!("#{o}")));
        }
        if let Some(f) = obj.get("forward_to").and_then(Value::as_str) {
            tail.push(format!("{} {}", dim("→"), fg(FG_VALUE, f)));
        }
        if let Some(s) = obj.get("source").and_then(Value::as_str) {
            tail.push(dim(s));
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
    if items.len() > EXPORTS_PREVIEW_LIMIT {
        out.push_str(&format!(
            "  {}\n",
            dim(&format!("... {} more", items.len() - EXPORTS_PREVIEW_LIMIT)),
        ));
    }
    out
}

// ─── functions view ─────────────────────────────────────────────────

const FUNCTIONS_PREVIEW_LIMIT: usize = 60;

fn render_functions(value: &Value) -> String {
    let Value::Array(items) = value else {
        return render_values_tree(value);
    };
    let mut out = String::new();
    let off_w = items
        .iter()
        .filter_map(|v| v.as_object())
        .filter_map(|o| o.get("offset").and_then(Value::as_u64))
        .map(|n| format!("0x{n:x}").len())
        .max()
        .unwrap_or(0);
    for v in items.iter().take(FUNCTIONS_PREVIEW_LIMIT) {
        let Some(obj) = v.as_object() else { continue };
        let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
        let offset = obj
            .get("offset")
            .and_then(Value::as_u64)
            .map_or_else(|| "·".into(), |n| format!("0x{n:x}"));
        let mut tail = Vec::<String>::new();
        if let Some(k) = obj.get("kind").and_then(Value::as_str) {
            tail.push(dim(k));
        }
        if let Some(c) = obj.get("complexity").and_then(Value::as_u64) {
            tail.push(fg(FG_LABEL, &format!("cx={c}")));
        }
        if let Some(bb) = obj.get("basic_blocks").and_then(Value::as_u64) {
            tail.push(fg(FG_LABEL, &format!("bb={bb}")));
        }
        if let Some(ins) = obj.get("instructions").and_then(Value::as_u64) {
            tail.push(fg(FG_LABEL, &format!("ins={ins}")));
        }
        if let Some(true) = obj.get("recursive").and_then(Value::as_bool) {
            tail.push(fg(FG_FLAG_WRITE, "recursive"));
        }
        if let Some(true) = obj.get("noreturn").and_then(Value::as_bool) {
            tail.push(fg(FG_FLAG_EXEC, "noreturn"));
        }
        if let Some(true) = obj.get("is_linear").and_then(Value::as_bool) {
            tail.push(dim("linear"));
        }
        if let Some(s) = obj.get("source").and_then(Value::as_str) {
            tail.push(dim(s));
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
        let calls = obj
            .get("calls")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if !calls.is_empty() {
            let inline = calls.iter().take(8).copied().collect::<Vec<_>>().join(", ");
            let suffix = if calls.len() > 8 {
                format!(", … +{}", calls.len() - 8)
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
    if items.len() > FUNCTIONS_PREVIEW_LIMIT {
        out.push_str(&format!(
            "  {}\n",
            dim(&format!(
                "... {} more",
                items.len() - FUNCTIONS_PREVIEW_LIMIT
            )),
        ));
    }
    out
}

// ─── AST view ───────────────────────────────────────────────────────

const AST_PREVIEW_LIMIT: usize = 30;

fn render_ast(value: &Value) -> String {
    let Value::Object(map) = value else {
        return render_values_tree(value);
    };
    let mut out = String::new();
    if let Some(Value::Array(targets)) = map.get("targets") {
        if !targets.is_empty() {
            out.push_str(&format!(
                "  {} {}\n",
                fg_bold(FG_VALUE, "targets"),
                dim(&format!("({})", targets.len())),
            ));
            for v in targets.iter().take(AST_PREVIEW_LIMIT) {
                if let Some(s) = v.as_str() {
                    out.push_str(&format!("    {}\n", fg(FG_VALUE, s)));
                }
            }
            if targets.len() > AST_PREVIEW_LIMIT {
                out.push_str(&format!(
                    "    {}\n",
                    dim(&format!("... {} more", targets.len() - AST_PREVIEW_LIMIT)),
                ));
            }
        }
    }
    if let Some(Value::Array(chains)) = map.get("members") {
        if !chains.is_empty() {
            out.push('\n');
            out.push_str(&format!(
                "  {} {}\n",
                fg_bold(FG_VALUE, "members"),
                dim(&format!("({})", chains.len())),
            ));
            for v in chains.iter().take(AST_PREVIEW_LIMIT) {
                if let Some(s) = v.as_str() {
                    out.push_str(&format!("    {}\n", fg(FG_VALUE, s)));
                }
            }
            if chains.len() > AST_PREVIEW_LIMIT {
                out.push_str(&format!(
                    "    {}\n",
                    dim(&format!("... {} more", chains.len() - AST_PREVIEW_LIMIT)),
                ));
            }
        }
    }
    if let Some(Value::Array(calls)) = map.get("calls") {
        if !calls.is_empty() {
            out.push('\n');
            out.push_str(&format!(
                "  {} {}\n",
                fg_bold(FG_VALUE, "calls"),
                dim(&format!("({})", calls.len())),
            ));
            for v in calls.iter().take(AST_PREVIEW_LIMIT) {
                let Some(obj) = v.as_object() else { continue };
                let target = obj
                    .get("target")
                    .and_then(Value::as_str)
                    .map_or_else(|| "·".into(), str::to_string);
                let args = obj
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|v| v.as_str().unwrap_or("?").to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                out.push_str(&format!(
                    "    {target}{open}{args}{close}\n",
                    target = fg(FG_VALUE, &target),
                    open = dim("("),
                    args = dim(&args),
                    close = dim(")"),
                ));
            }
            if calls.len() > AST_PREVIEW_LIMIT {
                out.push_str(&format!(
                    "    {}\n",
                    dim(&format!("... {} more", calls.len() - AST_PREVIEW_LIMIT)),
                ));
            }
        }
    }
    if let Some(Value::Object(args_map)) = map.get("call_strings") {
        if !args_map.is_empty() {
            out.push('\n');
            out.push_str(&format!(
                "  {} {}\n",
                fg_bold(FG_VALUE, "call_strings"),
                dim(&format!("({})", args_map.len())),
            ));
            for (target, vals) in args_map.iter().take(AST_PREVIEW_LIMIT) {
                let Value::Array(arr) = vals else { continue };
                let inline = arr
                    .iter()
                    .filter_map(Value::as_str)
                    .take(4)
                    .map(|s| format!("{:?}", string_excerpt(s, 40)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let suffix = if arr.len() > 4 {
                    format!(", … +{}", arr.len() - 4)
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "    {t}  {body}{suf}\n",
                    t = fg(FG_VALUE, target),
                    body = fg(FG_STR, &inline),
                    suf = dim(&suffix),
                ));
            }
            if args_map.len() > AST_PREVIEW_LIMIT {
                out.push_str(&format!(
                    "    {}\n",
                    dim(&format!("... {} more", args_map.len() - AST_PREVIEW_LIMIT)),
                ));
            }
        }
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

impl View {
    fn name(self) -> &'static str {
        match self {
            Self::All => "facts",
            Self::Fileid => "fileid",
            Self::Values => "values",
            Self::Strings => "strings",
            Self::Metrics => "metrics",
            Self::Ast => "ast",
            Self::Sections => "sections",
            Self::Imports => "imports",
            Self::Exports => "exports",
            Self::Functions => "functions",
            Self::Errors => "errors",
        }
    }
}

fn print_usage(to_stderr: bool) {
    let msg = "\
usage: filefacts [options] [view] <path>

views:
  fileid values strings metrics ast sections imports exports functions errors

options:
  -f, --format <terminal|json>
                     Output format. Default: terminal.
  --fileid           Emit only the fileid view.
  --values           Emit only the structural values tree.
  --strings          Emit only extracted strings.
  --metrics          Emit only derived metrics.
  --ast              Emit only AST projections.
  --sections         Emit only binary sections.
  --imports          Emit only imported symbols.
  --exports          Emit only exported symbols.
  --functions        Emit only functions.
  --errors           Emit only recoverable parse errors.
  -p, --pretty       Compatibility shorthand for --format json.
  -h, --help         Show this help and exit.
  -V, --version      Print version and exit.
";
    if to_stderr {
        eprint!("{msg}");
    } else {
        print!("{msg}");
    }
}
