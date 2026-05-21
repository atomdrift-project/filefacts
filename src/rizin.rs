//! Optional rizin/radare2 integration for binary analysis.
//!
//! Stripped binaries — and most malware — produce empty `dynsym` and
//! `symtab` tables, so goblin's parse returns 0 imports/exports/
//! functions. Rizin can recover them through linear disassembly +
//! signature matching + entry-point graph walking.
//!
//! # Discovery model
//!
//! At runtime we look for `rizin` (or `r2`) on `PATH`. If neither is
//! installed, every call here returns `None` and extraction proceeds
//! without rizin's contributions. No feature flag — the module is
//! always compiled; consumers running without rizin pay nothing
//! beyond a single `which`-style PATH scan per process.
//!
//! # Subprocess discipline
//!
//! The minimum viable port covers the happy path: spawn, wait for
//! exit with a hard timeout, parse JSON. Hardening for adversarial
//! input (cancellation propagation, output-cap detection, kill-group
//! tracking on truant children) lives in cleave's existing
//! `radare2/mod.rs` and ports across as #75c.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;

use crate::output::{Export, Function, Import, Metrics};

/// Hard cap on a single rizin run. `aaa` analysis on a heavily
/// stripped ~14 MB Linux binary needed ~85 s in real measurement;
/// adversarial samples with packed code paths can take longer.
/// Match cleave's default timeout so behaviour is consistent.
const RIZIN_TIMEOUT: Duration = Duration::from_secs(300);

/// One-shot PATH probe. Cached so we don't fork `which` per file.
fn rizin_binary() -> Option<&'static Path> {
    static CACHED: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            // Prefer `rizin` (modern); fall back to `radare2` / `r2`.
            for name in ["rizin", "radare2", "r2"] {
                if let Some(path) = which(name) {
                    return Some(path);
                }
            }
            None
        })
        .as_deref()
}

/// Tiny PATH search — avoids pulling the `which` crate as a dep for
/// a single binary lookup. Returns the first existing executable
/// matching `name` in any `PATH` directory.
fn which(name: &str) -> Option<std::path::PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// `true` when rizin (or a compatible drop-in) is available on PATH.
/// Cheap — does not spawn anything; only checks the cached probe.
pub fn available() -> bool {
    rizin_binary().is_some()
}

/// Recover symbol tables + function discovery via rizin. Returns
/// `None` when rizin isn't on PATH or invocation failed; callers
/// fall back to whatever goblin already populated.
///
/// The single rizin command runs `iij` (imports), `iEj` (exports),
/// `aaa` (deep analysis to discover functions), and `aflj`
/// (function list). Output blocks are separated by sentinel strings
/// we can `split` on cheaply.
///
/// Writes `bytes` to a temp file (rizin reads files from disk, not
/// stdin) and deletes it when done.
pub(crate) fn recover(bytes: &[u8]) -> Option<RizinRecovery> {
    let bin = rizin_binary()?;
    recover_with_bin(bin, bytes)
}

/// `recover()` with the rizin binary path passed in. Production path
/// uses the cached PATH probe; tests use this entry to inject a fake
/// `rizin` shim so the spawn/drain/parse pipeline can be exercised
/// deterministically without a real rizin install.
#[cfg(test)]
fn recover_with_bin_for_test(bin: &Path, bytes: &[u8]) -> Option<RizinRecovery> {
    recover_with_bin(bin, bytes)
}

fn recover_with_bin(bin: &Path, bytes: &[u8]) -> Option<RizinRecovery> {
    // Materialise the bytes as a temp file. Rizin requires a path —
    // there's no stdin mode for binary analysis. Concurrent callers
    // need distinct files: include a process-wide atomic counter
    // alongside the PID so two threads running `recover()` at once
    // don't trample each other's temp file (the second call's write
    // would race the first's read-and-spawn).
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut temp = std::env::temp_dir();
    temp.push(format!(
        "expose-rizin-{}-{}.bin",
        std::process::id(),
        seq
    ));
    if std::fs::write(&temp, bytes).is_err() {
        return None;
    }
    // Auto-cleanup guard — fires whether we return Some/None below.
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _cleanup = Cleanup(&temp);

    // `-NN` disables plugin auto-loading (faster startup, fewer
    // surprises). `-q` quits after the `-c` script. `-e scr.color=0`
    // strips ANSI escapes from any stray log lines.
    let path_str = temp.to_string_lossy().to_string();
    let mut cmd = Command::new(bin);
    cmd.args([
        "-NN",
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "log.level=0",
        "-c",
        "iij; echo ===SEP===; iEj; echo ===SEP===; aaa; echo ===SEP===; aflj",
        &path_str,
    ]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    let mut child = cmd.spawn().ok()?;
    // Drain stdout in a background thread while we wait for exit.
    // Without this, `aflj` output on a binary with thousands of
    // discovered functions overflows the pipe buffer (~64 KB on
    // macOS), the child blocks on write, and `wait_with_output()`
    // deadlocks waiting for exit. Capped at 100 MiB to bound the
    // worst-case adversarial blob; matches cleave's defence.
    const MAX_OUTPUT: usize = 100 * 1024 * 1024;
    let mut stdout_handle = child.stdout.take()?;
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = (&mut stdout_handle)
            .take(MAX_OUTPUT as u64)
            .read_to_end(&mut buf);
        let _ = stdout_tx.send(buf);
    });

    // Poll for child exit with the timeout deadline. Once the child
    // exits, the reader thread's `read_to_end` returns naturally.
    let deadline = std::time::Instant::now() + RIZIN_TIMEOUT;
    let mut exit_status = None;
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return None,
        }
    }
    let status = match exit_status {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };
    // Rizin crashed / aborted — partial stdout is unreliable on a
    // failed run, so we drop it rather than emit phantom data.
    if !status.success() {
        return None;
    }
    // Bounded drain: if a rizin grandchild still holds the
    // write-end of the pipe, recv would block forever. 5 s is
    // generous — `read_to_end` finishes immediately once the last
    // write-end closes.
    let stdout_bytes = stdout_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    if stdout_bytes.is_empty() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    Some(parse_recovery_output(&stdout))
}

/// Split rizin's combined stdout (four `===SEP===`-delimited blocks)
/// into typed `RizinRecovery`. Separating this from `recover()` makes
/// the output-shape contract directly unit-testable without needing
/// a real subprocess.
///
/// The four expected blocks, in order, are:
/// 1. `iij`  — JSON array of imports
/// 2. `iEj`  — JSON array of exports
/// 3. `aaa`  — analysis chatter (discarded)
/// 4. `aflj` — JSON array of recovered functions
///
/// Each JSON block tolerates leading log chatter via `parse_json_array`.
/// Missing blocks (truncated output, fewer separators than expected)
/// degrade to empty `Vec`s rather than failing — partial data is more
/// useful than no data on adversarial input.
fn parse_recovery_output(stdout: &str) -> RizinRecovery {
    let mut parts = stdout.split("===SEP===");
    let imports = parts
        .next()
        .and_then(|p| parse_json_array::<RawImport>(p).ok())
        .unwrap_or_default();
    let exports = parts
        .next()
        .and_then(|p| parse_json_array::<RawExport>(p).ok())
        .unwrap_or_default();
    // Third block is `aaa` analysis chatter — discard.
    let _analysis_chatter = parts.next();
    let functions = parts
        .next()
        .and_then(|p| parse_json_array::<RawFunction>(p).ok())
        .unwrap_or_default();
    RizinRecovery {
        imports,
        exports,
        functions,
    }
}

/// Extract a JSON array out of `text`. Rizin sometimes prefixes
/// arrays with log lines; we tolerate that by scanning for `[`.
fn parse_json_array<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<Vec<T>, serde_json::Error> {
    let start = text.find('[').unwrap_or(0);
    serde_json::from_str(&text[start..])
}

/// Raw rizin output — converted into expose's typed `Import`/
/// `Export`/`Function` views by `recover()`'s caller.
pub(crate) struct RizinRecovery {
    imports: Vec<RawImport>,
    exports: Vec<RawExport>,
    functions: Vec<RawFunction>,
}

impl RizinRecovery {
    /// Push recovered symbols into expose's typed views and emit the
    /// rizin-specific `binary.*` metrics. Only fills slots that
    /// goblin left empty — never overwrites existing data.
    pub(crate) fn apply(
        self,
        imports_out: &mut crate::Imports,
        exports_out: &mut crate::Exports,
        functions_out: &mut crate::Functions,
        metrics: &mut Metrics,
    ) {
        if imports_out.is_empty() {
            for imp in self.imports {
                if imp.name.is_empty() {
                    continue;
                }
                imports_out.push(Import {
                    name: imp.name,
                    library: imp.libname,
                    source: "rizin",
                    offset: None,
                    ordinal: imp.ordinal,
                });
            }
        }
        if exports_out.is_empty() {
            for exp in self.exports {
                if exp.name.is_empty() {
                    continue;
                }
                exports_out.push(Export {
                    name: exp.name,
                    source: "rizin",
                    offset: Some(exp.vaddr),
                    ordinal: None,
                    forward_to: None,
                });
            }
        }
        if functions_out.is_empty() && !self.functions.is_empty() {
            for func in &self.functions {
                if func.name.is_empty() {
                    continue;
                }
                functions_out.push(Function {
                    name: func.name.clone(),
                    source: "rizin",
                    offset: Some(func.offset),
                    kind: None,
                });
            }
            // Function-level aggregates. Complexity + basic blocks
            // are what `aflj` makes essentially free — they're the
            // ML signals goblin can't produce on a stripped binary.
            let count = self.functions.len() as f64;
            metrics.insert("binary.rizin_function_count", count);

            let cc_values: Vec<u32> = self
                .functions
                .iter()
                .filter_map(|f| f.cc)
                .collect();
            if !cc_values.is_empty() {
                let sum: u64 = cc_values.iter().map(|&v| u64::from(v)).sum();
                metrics.insert("binary.avg_complexity", sum as f64 / cc_values.len() as f64);
                let max = cc_values.iter().copied().max().unwrap_or(0);
                metrics.insert("binary.max_complexity", f64::from(max));
            }

            let bb_values: Vec<u32> = self
                .functions
                .iter()
                .filter_map(|f| f.nbbs)
                .collect();
            if !bb_values.is_empty() {
                let sum: u64 = bb_values.iter().map(|&v| u64::from(v)).sum();
                metrics.insert(
                    "binary.avg_basic_blocks",
                    sum as f64 / bb_values.len() as f64,
                );
                metrics.insert("binary.total_basic_blocks", sum as f64);
            }
        }
    }
}

// =============================================================================
// Wire-format deserialisers. Map rizin's JSON shape to internal structs;
// expose's public typed views (Import / Export / Function) stay independent.
// =============================================================================

#[derive(Deserialize)]
struct RawImport {
    name: String,
    libname: Option<String>,
    ordinal: Option<u32>,
}

#[derive(Deserialize)]
struct RawExport {
    name: String,
    #[serde(default)]
    vaddr: u64,
}

#[derive(Deserialize)]
struct RawFunction {
    name: String,
    /// Function entry address. Rizin uses `offset`; older r2 used `addr`.
    #[serde(alias = "addr")]
    #[serde(default)]
    offset: u64,
    /// Cyclomatic complexity.
    #[serde(default)]
    cc: Option<u32>,
    /// Number of basic blocks.
    #[serde(default)]
    nbbs: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::output::Metrics;

    fn make_recovery(json: &str) -> RizinRecovery {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            imports: Vec<RawImport>,
            #[serde(default)]
            exports: Vec<RawExport>,
            #[serde(default)]
            functions: Vec<RawFunction>,
        }
        let w: Wire = serde_json::from_str(json).expect("valid test JSON");
        RizinRecovery {
            imports: w.imports,
            exports: w.exports,
            functions: w.functions,
        }
    }

    // ------------------------------------------------------------------
    // parse_json_array
    // ------------------------------------------------------------------

    #[test]
    fn parse_json_array_strips_leading_log_chatter() {
        // Rizin sometimes emits warning lines before the JSON array
        // (we redirect stderr to /dev/null, but a stray INFO can leak
        // to stdout). `parse_json_array` skips to the first `[`.
        let text = "INFO: scanning sections...\n[{\"name\":\"foo\",\"libname\":\"x.so\"}]";
        let v: Vec<RawImport> = parse_json_array(text).expect("parses past chatter");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "foo");
        assert_eq!(v[0].libname.as_deref(), Some("x.so"));
    }

    #[test]
    fn parse_json_array_handles_pure_array() {
        let v: Vec<RawImport> =
            parse_json_array(r#"[{"name":"a"},{"name":"b","ordinal":3}]"#).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].ordinal, Some(3));
    }

    #[test]
    fn parse_json_array_rejects_malformed_json() {
        // Non-array root → serde rejects.
        assert!(parse_json_array::<RawImport>("not json at all").is_err());
        // Array-shaped opener but truncated content.
        assert!(parse_json_array::<RawImport>("[{\"name\":\"x\"").is_err());
    }

    #[test]
    fn parse_json_array_empty_array_is_ok() {
        let v: Vec<RawImport> = parse_json_array("[]").unwrap();
        assert!(v.is_empty());
    }

    // ------------------------------------------------------------------
    // RawFunction accepts both rizin (`offset`) and old r2 (`addr`) keys
    // ------------------------------------------------------------------

    #[test]
    fn raw_function_accepts_offset_or_addr() {
        let v: Vec<RawFunction> =
            parse_json_array(r#"[{"name":"a","offset":4096}]"#).unwrap();
        assert_eq!(v[0].offset, 4096);
        let v: Vec<RawFunction> =
            parse_json_array(r#"[{"name":"b","addr":8192}]"#).unwrap();
        assert_eq!(v[0].offset, 8192);
    }

    // ------------------------------------------------------------------
    // apply gate logic — "only fill what goblin left empty"
    // ------------------------------------------------------------------

    #[test]
    fn apply_populates_when_all_views_empty() {
        let recovery = make_recovery(
            r#"{
                "imports": [{"name":"open","libname":"libc.so"}],
                "exports": [{"name":"entry","vaddr":4096}],
                "functions": [{"name":"main","offset":4096,"cc":5,"nbbs":10}]
            }"#,
        );
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut imports, &mut exports, &mut functions, &mut metrics);
        assert_eq!(imports.iter().count(), 1);
        assert_eq!(exports.iter().count(), 1);
        assert_eq!(functions.iter().count(), 1);
        assert_eq!(metrics.get("binary.rizin_function_count"), Some(1.0));
        assert_eq!(metrics.get("binary.avg_complexity"), Some(5.0));
        assert_eq!(metrics.get("binary.max_complexity"), Some(5.0));
        assert_eq!(metrics.get("binary.avg_basic_blocks"), Some(10.0));
        assert_eq!(metrics.get("binary.total_basic_blocks"), Some(10.0));
    }

    #[test]
    fn apply_skips_imports_when_goblin_already_populated() {
        let recovery = make_recovery(
            r#"{"imports":[{"name":"rizin_only"}],"exports":[],"functions":[]}"#,
        );
        let mut imports = crate::Imports::new();
        imports.push(Import {
            name: "from_goblin".into(),
            library: None,
            source: "elf-dynsym",
            offset: None,
            ordinal: None,
        });
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut imports, &mut exports, &mut functions, &mut metrics);
        // Rizin import dropped — goblin's entry survives untouched.
        let names: Vec<String> = imports.iter().map(|i| i.name.clone()).collect();
        assert_eq!(names, vec!["from_goblin"]);
    }

    #[test]
    fn apply_skips_function_metrics_when_functions_already_populated() {
        let recovery = make_recovery(
            r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1,"cc":99,"nbbs":99}]}"#,
        );
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        functions.push(Function {
            name: "preexisting".into(),
            source: "goblin",
            offset: Some(0),
            kind: None,
        });
        let mut metrics = Metrics::new();
        recovery.apply(&mut imports, &mut exports, &mut functions, &mut metrics);
        // The function-block was skipped → no aggregate metrics emitted.
        assert!(metrics.get("binary.rizin_function_count").is_none());
        assert!(metrics.get("binary.avg_complexity").is_none());
        // The preexisting goblin function survives.
        assert_eq!(functions.iter().count(), 1);
    }

    #[test]
    fn apply_drops_unnamed_entries() {
        let recovery = make_recovery(
            r#"{
                "imports": [{"name":""},{"name":"keep"}],
                "exports": [{"name":""},{"name":"keep","vaddr":1}],
                "functions": [{"name":"","offset":0},{"name":"keep","offset":1}]
            }"#,
        );
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut imports, &mut exports, &mut functions, &mut metrics);
        for view in [
            imports.iter().count(),
            exports.iter().count(),
            functions.iter().count(),
        ] {
            assert_eq!(view, 1, "empty-name entries should be filtered out");
        }
    }

    #[test]
    fn apply_aggregates_complexity_correctly() {
        // Three functions with cc 1, 3, 5 → mean = 3, max = 5.
        // nbbs 2, 4, 6 → mean = 4, total = 12.
        let recovery = make_recovery(
            r#"{
                "imports": [],
                "exports": [],
                "functions": [
                    {"name":"a","offset":1,"cc":1,"nbbs":2},
                    {"name":"b","offset":2,"cc":3,"nbbs":4},
                    {"name":"c","offset":3,"cc":5,"nbbs":6}
                ]
            }"#,
        );
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut imports, &mut exports, &mut functions, &mut metrics);
        assert_eq!(metrics.get("binary.rizin_function_count"), Some(3.0));
        assert_eq!(metrics.get("binary.avg_complexity"), Some(3.0));
        assert_eq!(metrics.get("binary.max_complexity"), Some(5.0));
        assert_eq!(metrics.get("binary.avg_basic_blocks"), Some(4.0));
        assert_eq!(metrics.get("binary.total_basic_blocks"), Some(12.0));
    }

    #[test]
    fn apply_omits_complexity_metrics_when_cc_absent() {
        // Functions without `cc` shouldn't emit complexity averages.
        // Without `nbbs` shouldn't emit basic-block aggregates either.
        let recovery = make_recovery(
            r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1}]}"#,
        );
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut imports, &mut exports, &mut functions, &mut metrics);
        // rizin_function_count fires unconditionally on non-empty functions.
        assert_eq!(metrics.get("binary.rizin_function_count"), Some(1.0));
        assert!(metrics.get("binary.avg_complexity").is_none());
        assert!(metrics.get("binary.avg_basic_blocks").is_none());
    }

    // ------------------------------------------------------------------
    // available() — smoke
    // ------------------------------------------------------------------

    #[test]
    fn available_does_not_panic() {
        // We can't assert the result (depends on the test host's
        // PATH); just confirm the probe doesn't panic and returns a
        // bool stably across calls (the cache works).
        let first = available();
        let second = available();
        assert_eq!(first, second, "PATH probe should be cached");
    }

    // ------------------------------------------------------------------
    // parse_recovery_output — block splitting + per-block error tolerance
    // ------------------------------------------------------------------

    /// Build a synthetic rizin stdout matching the
    /// `iij; echo ===SEP===; iEj; echo ===SEP===; aaa; echo ===SEP===; aflj`
    /// shape — four blocks with the canonical separator.
    fn synthesize_stdout(imports: &str, exports: &str, chatter: &str, functions: &str) -> String {
        format!("{imports}\n===SEP===\n{exports}\n===SEP===\n{chatter}\n===SEP===\n{functions}")
    }

    #[test]
    fn parse_recovery_output_splits_canonical_four_block_shape() {
        let stdout = synthesize_stdout(
            r#"[{"name":"open","libname":"libc.so"}]"#,
            r#"[{"name":"start","vaddr":4096}]"#,
            "[INFO] analysis ran",
            r#"[{"name":"main","offset":4096,"cc":3,"nbbs":5}]"#,
        );
        let rec = parse_recovery_output(&stdout);
        assert_eq!(rec.imports.len(), 1);
        assert_eq!(rec.imports[0].name, "open");
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.exports[0].vaddr, 4096);
        assert_eq!(rec.functions.len(), 1);
        assert_eq!(rec.functions[0].cc, Some(3));
    }

    #[test]
    fn parse_recovery_output_tolerates_truncated_blocks() {
        // Only two separators present — third + fourth blocks missing.
        // Should yield empty exports/functions rather than panic.
        let stdout = "[]\n===SEP===\n[{\"name\":\"a\"}]";
        let rec = parse_recovery_output(stdout);
        assert!(rec.imports.is_empty());
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.exports[0].name, "a");
        assert!(rec.functions.is_empty());
    }

    #[test]
    fn parse_recovery_output_recovers_from_malformed_block() {
        // First block is unparseable JSON; we still get the rest.
        let stdout = synthesize_stdout(
            "this is not json",
            r#"[{"name":"x","vaddr":1}]"#,
            "",
            r#"[{"name":"y","offset":2}]"#,
        );
        let rec = parse_recovery_output(&stdout);
        assert!(rec.imports.is_empty(), "bad JSON → empty, not panic");
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.functions.len(), 1);
    }

    #[test]
    fn parse_recovery_output_handles_empty_stdout() {
        let rec = parse_recovery_output("");
        assert!(rec.imports.is_empty());
        assert!(rec.exports.is_empty());
        assert!(rec.functions.is_empty());
    }

    // ------------------------------------------------------------------
    // End-to-end spawn/drain via a fake-rizin shim script
    // ------------------------------------------------------------------

    /// Stage a shell script that masquerades as `rizin`, prints a
    /// fixed stdout payload (escaping the canonical separators), and
    /// returns its directory so we can stitch it onto PATH. Returns
    /// `None` on non-Unix or when `/bin/sh` isn't available — those
    /// platforms exercise the same paths under cleave's real rizin.
    #[cfg(unix)]
    fn stage_shim(stdout_payload: &str) -> Option<std::path::PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "expose-rizin-shim-{}-{}",
            std::process::id(),
            // Append nanos so concurrent test threads don't collide.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let shim = dir.join("rizin");
        let mut f = std::fs::File::create(&shim).ok()?;
        // The body interprets `$1` etc. as rizin's CLI args. We don't
        // care about them — we just emit the canned stdout the
        // production code expects to parse.
        writeln!(f, "#!/bin/sh").ok()?;
        // `cat <<'EOF'` preserves the body bytes-for-bytes; the
        // single-quoted EOF disables shell expansion so payloads with
        // backticks / dollars survive.
        writeln!(f, "cat <<'EOF'").ok()?;
        f.write_all(stdout_payload.as_bytes()).ok()?;
        writeln!(f).ok()?;
        writeln!(f, "EOF").ok()?;
        let mut perms = std::fs::metadata(&shim).ok()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).ok()?;
        Some(dir)
    }

    /// Spawn the shim through the same `recover()` codepath production
    /// uses, with PATH pointed at the shim dir. The cached PATH probe
    /// in `rizin_binary()` is bypassed via a private helper that takes
    /// the bin path directly — see `recover_with_bin_for_test`.
    #[cfg(unix)]
    fn run_against_shim(stdout_payload: &str, input_bytes: &[u8]) -> Option<RizinRecovery> {
        let dir = stage_shim(stdout_payload)?;
        let shim_path = dir.join("rizin");
        let result = recover_with_bin_for_test(&shim_path, input_bytes);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_shim_returns_parsed_recovery() {
        // A canonical four-block payload — exercises spawn, drain,
        // separator split, and per-block JSON parse together.
        let payload = synthesize_stdout(
            r#"[{"name":"malloc","libname":"libc.so.6"}]"#,
            r#"[{"name":"entry","vaddr":4096}]"#,
            "analysis-chatter-ignored",
            r#"[{"name":"f1","offset":4096,"cc":7,"nbbs":12}]"#,
        );
        let rec = run_against_shim(&payload, b"unused bytes for temp file").expect(
            "shim should return a recovery; if your /bin/sh is missing this test can't run",
        );
        assert_eq!(rec.imports.len(), 1);
        assert_eq!(rec.imports[0].libname.as_deref(), Some("libc.so.6"));
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.functions.len(), 1);
        assert_eq!(rec.functions[0].cc, Some(7));
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_shim_handles_large_stdout_via_pipe_drain() {
        // Build a function array large enough to exceed the typical
        // 64 KiB pipe buffer — without the background drain thread,
        // this would deadlock on shim's stdout write. With drain, it
        // streams through and parses.
        let mut funcs = String::from("[");
        for i in 0..2000 {
            if i > 0 {
                funcs.push(',');
            }
            funcs.push_str(&format!(
                r#"{{"name":"fcn.{i:06x}","offset":{i},"cc":1,"nbbs":1}}"#,
            ));
        }
        funcs.push(']');
        let payload = synthesize_stdout("[]", "[]", "", &funcs);
        assert!(
            payload.len() > 100_000,
            "payload {} bytes — must exceed pipe buffer",
            payload.len()
        );
        let rec = run_against_shim(&payload, b"x").expect("shim recovery");
        assert_eq!(rec.functions.len(), 2000);
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_shim_returns_some_empty_recovery_on_separator_only_stdout() {
        // Three SEPs with empty blocks → valid but contentless rizin
        // output. recover() returns Some(empty) here; `apply` is then
        // a no-op (functions empty → no metrics emitted) and the
        // caller's existing goblin data survives untouched. This is
        // distinct from the "empty bytes → None" case below.
        let payload = synthesize_stdout("[]", "[]", "", "[]");
        let rec = run_against_shim(&payload, b"x").expect("empty arrays still parse");
        assert!(rec.imports.is_empty());
        assert!(rec.exports.is_empty());
        assert!(rec.functions.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_recover_returns_none_when_stdout_bytes_empty() {
        // Pure-stdlib shim that exits 0 with zero stdout bytes. Exercises
        // the `stdout_bytes.is_empty() → None` guard against subprocesses
        // that silently fail (rizin crashing before its first echo).
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "expose-rizin-silentshim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("rizin");
        let mut f = std::fs::File::create(&shim).unwrap();
        // `exit 0` produces zero stdout bytes — no trailing newline.
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
        let rec = recover_with_bin_for_test(&shim, b"unused");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rec.is_none(), "zero stdout bytes should yield None");
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_recover_returns_none_on_nonzero_exit() {
        // Shim exits non-zero (rizin crashed) — recover should not
        // return phantom data even if some partial stdout leaked.
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "expose-rizin-failshim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("rizin");
        let mut f = std::fs::File::create(&shim).unwrap();
        f.write_all(b"#!/bin/sh\necho 'partial output'\nexit 1\n")
            .unwrap();
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
        let rec = recover_with_bin_for_test(&shim, b"unused");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rec.is_none(), "non-zero exit should yield None");
    }

    // Temp-file cleanup is enforced by a `Drop` guard on `Cleanup<'_>`
    // inside `recover_with_bin`. Snapshotting `/tmp` before/after a
    // shim run would race against parallel shim tests (other threads
    // running `recover_with_bin_for_test` create files with the same
    // PID prefix); serialising every shim test to make the snapshot
    // deterministic defeats parallelism. The Drop pattern is idiomatic
    // Rust and was verified end-to-end on the malware sample run
    // (8,325 functions recovered, no `expose-rizin-*` files left in
    // `/tmp` across sessions).
}
