use super::*;
use crate::output::Metrics;

/// Tests that spawn rizin (or a shim) or reap process groups must hold
/// this mutex for the duration of their run: `RIZIN_PGIDS` is
/// process-wide, and without the lock the reaper test SIGKILLs shims
/// registered by other in-flight tests, producing intermittent "shim
/// recovery missing" failures. Settings are per call, so no test can
/// mute or re-time another.
fn rizin_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // `unwrap_or_else` so a poisoned mutex (from a panicking test
    // holding the guard) doesn't poison every subsequent test —
    // the registry state survives across test panics regardless.
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn make_recovery(json: &str) -> RizinRecovery {
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        imports: Vec<RawImport>,
        #[serde(default)]
        exports: Vec<RawExport>,
        #[serde(default)]
        functions: Vec<RawFunction>,
        #[serde(default)]
        sections: Vec<RawSection>,
    }
    let w: Wire = serde_json::from_str(json).expect("valid test JSON");
    RizinRecovery {
        imports: w.imports,
        exports: w.exports,
        functions: w.functions,
        sections: w.sections,
    }
}

#[test]
fn metrics_command_skips_unused_work_but_keeps_full_cfg_analysis() {
    assert!(RIZIN_METRICS_ARGS.contains(&"-T"));
    assert!(RIZIN_METRICS_ARGS.contains(&"-z"));
    assert!(
        RIZIN_METRICS_ARGS
            .windows(2)
            .any(|w| w == ["-e", "analysis.vars=false"]),
        "variable recovery is excluded"
    );
    assert!(
        RIZIN_METRICS_SCRIPT.contains("aaa"),
        "the default script keeps full analysis"
    );
    assert!(
        RIZIN_METRICS_SCRIPT_PE_X86.contains("aa; aac")
            && !RIZIN_METRICS_SCRIPT_PE_X86.contains("aaa"),
        "the PE x86 script replaces aaa with aa; aac"
    );
    for table in ["iij", "iEj", "aflj", "iSj"] {
        assert!(RIZIN_METRICS_SCRIPT.contains(table), "{table} imported");
        assert!(
            RIZIN_METRICS_SCRIPT_PE_X86.contains(table),
            "{table} imported"
        );
    }
}

#[test]
fn analysis_script_picks_the_fast_path_only_for_pe_x86() {
    fn pe(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x80];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x60u32.to_le_bytes());
        b[0x60..0x64].copy_from_slice(b"PE\0\0");
        b[0x64..0x66].copy_from_slice(&machine.to_le_bytes());
        b
    }
    assert_eq!(analysis_script(&pe(0x8664), 5, false).1, "pe-x86");
    assert_eq!(analysis_script(&pe(0x014c), 5, false).1, "pe-x86");
    assert_eq!(
        analysis_script(&pe(0x8664), 0, false).1,
        "pe-x86",
        "PE x86 is exact even without symbols"
    );
    assert_eq!(
        analysis_script(&pe(0xaa64), 5, false).1,
        "prelude",
        "arm64 PE takes the prelude script"
    );
    assert_eq!(
        analysis_script(b"\x7fELF\x02\x01\x01", 5, false).1,
        "prelude"
    );
    assert_eq!(
        analysis_script(b"\x7fELF\x02\x01\x01", 0, false).1,
        "full",
        "no symbol inventory keeps aaa"
    );
    assert_eq!(
        analysis_script(b"MZ", 5, false).1,
        "prelude",
        "truncated header is not PE x86"
    );
    let mut bad = pe(0x8664);
    bad[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    assert_eq!(
        analysis_script(&bad, 5, false).1,
        "prelude",
        "e_lfanew out of range is not PE x86"
    );
    assert_eq!(
        analysis_script(&pe(0x8664), 5, true).1,
        "go-pclntab",
        "Go metadata needs the pclntab pass, and takes it directly"
    );
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
    let v: Vec<RawImport> = parse_json_array(r#"[{"name":"a"},{"name":"b","ordinal":3}]"#).unwrap();
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
        parse_json_array(r#"[{"name":"a","offset":4096,"size":32}]"#).unwrap();
    assert_eq!(v[0].offset, 4096);
    assert_eq!(v[0].size, 32);
    let v: Vec<RawFunction> = parse_json_array(r#"[{"name":"b","addr":8192}]"#).unwrap();
    assert_eq!(v[0].offset, 8192);
    assert_eq!(v[0].size, 0);
}

#[test]
fn exposes_function_ranges_and_direct_call_edges() {
    let recovery = make_recovery(
        r#"{
                "functions": [
                    {
                        "name": "caller",
                        "offset": 4096,
                        "size": 64,
                        "callrefs": [
                            {"from": 4100, "to": 8192, "type": "CALL"},
                            {"from": 4105, "to": 4098, "type": "CODE"}
                        ]
                    },
                    {"name": "callee", "offset": 8192, "size": 24}
                ]
            }"#,
    );
    assert_eq!(recovery.function_ranges(), vec![(4096, 64), (8192, 24)]);
    assert_eq!(recovery.direct_call_edges(), vec![(4096, 4100, 8192)]);
}

// ------------------------------------------------------------------
// apply gate logic — "only fill what goblin left empty"
// ------------------------------------------------------------------

use crate::output::{Symbol, SymbolKind, Symbols};

fn first_function(symbols: &Symbols) -> Option<&Symbol> {
    symbols.iter_kind(SymbolKind::Function).next()
}

fn count_kind(symbols: &Symbols, kind: SymbolKind) -> usize {
    symbols.iter_kind(kind).count()
}

#[test]
fn apply_populates_cfg_fields_from_aflj() {
    // Full aflj payload — every CFG field exercised, including the
    // is-lineal kebab key, the callrefs list (some named, some
    // anonymous → only named ones land on `callees`), and the
    // signed stackframe normalisation.
    let recovery = make_recovery(
        r#"{
                "imports": [],
                "exports": [],
                "functions": [{
                    "name": "main",
                    "offset": 4096,
                    "cc": 7,
                    "nbbs": 12,
                    "edges": 18,
                    "ninstrs": 83,
                    "stackframe": 48,
                    "recursive": false,
                    "noreturn": false,
                    "is-lineal": false,
                    "callrefs": [
                        {"name": "puts", "from": 4100, "to": 8192, "type": "CALL"},
                        {"name": "exit", "from": 4105, "to": 12288, "type": "CALL"},
                        {"from": 4110, "to": 4098, "type": "CODE"}
                    ]
                }]
            }"#,
    );
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    let Some(Symbol::Function {
        complexity,
        callees,
        ..
    }) = first_function(&symbols)
    else {
        panic!("expected one rizin function");
    };
    assert_eq!(*complexity, Some(7));
    assert_eq!(*callees, vec!["puts".to_string(), "exit".to_string()]);
    assert_eq!(count_kind(&symbols, SymbolKind::Call), 2);
    let calls: Vec<_> = symbols.iter_kind(SymbolKind::Call).collect();
    assert!(matches!(
        calls[0],
        Symbol::Call {
            target: Some(target),
            offset: Some(4100),
            ..
        } if target == "puts"
    ));
    assert!(matches!(
        calls[1],
        Symbol::Call {
            target: Some(target),
            offset: Some(4105),
            ..
        } if target == "exit"
    ));
}

#[test]
fn apply_resolves_anonymous_binary_callrefs_by_target_address() {
    let recovery = make_recovery(
        r#"{
                "functions": [
                    {
                        "name": "entry0",
                        "offset": 4096,
                        "callrefs": [
                            {"from": 4100, "to": 8192, "type": "CALL"},
                            {"from": 4105, "to": 4098, "type": "CODE"}
                        ]
                    },
                    {
                        "name": "fcn.00002000",
                        "offset": 8192
                    }
                ]
            }"#,
    );
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);

    let calls: Vec<_> = symbols.iter_kind(SymbolKind::Call).collect();
    assert_eq!(calls.len(), 1);
    assert!(matches!(
        calls[0],
        Symbol::Call {
            target: Some(target),
            offset: Some(4100),
            ..
        } if target == "fcn.00002000"
    ));
    let entry = symbols
        .iter_kind(SymbolKind::Function)
        .find(|symbol| symbol.name() == Some("entry0"))
        .expect("entry function");
    assert!(matches!(
        entry,
        Symbol::Function { callees, .. } if callees == &["fcn.00002000".to_string()]
    ));
}

#[test]
fn apply_populates_when_all_views_empty() {
    let recovery = make_recovery(
        r#"{
                "imports": [{"name":"open","libname":"libc.so"}],
                "exports": [{"name":"entry","vaddr":4096}],
                "functions": [{"name":"main","offset":4096,"cc":5,"nbbs":10}]
            }"#,
    );
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    assert_eq!(count_kind(&symbols, SymbolKind::Import), 1);
    assert_eq!(count_kind(&symbols, SymbolKind::Export), 1);
    assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
    // Rizin-side aggregates stay under `binary.*_complexity` /
    // `binary.*_basic_blocks`.
    assert_eq!(metrics.get("binary.avg_complexity"), Some(5.0));
    assert_eq!(metrics.get("binary.max_complexity"), Some(5.0));
    assert_eq!(metrics.get("binary.avg_basic_blocks"), Some(10.0));
    assert_eq!(metrics.get("binary.basic_block_count"), Some(10.0));
}

#[test]
fn apply_skips_imports_when_goblin_already_populated() {
    let recovery =
        make_recovery(r#"{"imports":[{"name":"rizin_only"}],"exports":[],"functions":[]}"#);
    let mut symbols = Symbols::new();
    symbols.push(Symbol::Import {
        name: "from_goblin".into(),
        alias: None,
        library: None,
        offset: None,
        ordinal: None,
    });
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    // Rizin import dropped — goblin's entry survives untouched.
    let names: Vec<String> = symbols
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec!["from_goblin"]);
}

#[test]
fn recovered_import_anchors_at_plt_address() {
    // rizin's iij carries the PLT/stub address; recovery records it as the
    // import's offset (it only runs when goblin found zero imports). An
    // import without a plt stays unanchored rather than anchoring at 0.
    let recovery = make_recovery(
        r#"{"imports":[{"name":"dlopen","plt":4096},{"name":"getpid"}],"exports":[],"functions":[]}"#,
    );
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    let offsets: Vec<(String, Option<u64>)> = symbols
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, offset, .. } => Some((name.clone(), *offset)),
            _ => None,
        })
        .collect();
    assert_eq!(
        offsets,
        vec![
            ("dlopen".to_string(), Some(4096)),
            ("getpid".to_string(), None),
        ]
    );
}

#[test]
fn apply_skips_function_metrics_when_functions_already_populated() {
    let recovery = make_recovery(
        r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1,"cc":99,"nbbs":99}]}"#,
    );
    let mut symbols = Symbols::new();
    symbols.push(Symbol::Function {
        name: "preexisting".into(),
        offset: Some(0),
        complexity: None,
        callees: Vec::new(),
    });
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    // The function-block was skipped → no aggregate metrics emitted.
    assert!(metrics.get("binary.avg_complexity").is_none());
    // The preexisting goblin function survives.
    assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
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
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    assert_eq!(count_kind(&symbols, SymbolKind::Import), 1);
    assert_eq!(count_kind(&symbols, SymbolKind::Export), 1);
    assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
}

#[test]
fn without_exports_drops_only_the_export_view() {
    let recovery = make_recovery(
        r#"{
                "imports": [{"name":"open","libname":"libc.so"}],
                "exports": [{"name":"gopclntab","vaddr":4096}],
                "functions": [{"name":"main","offset":4096,"cc":5,"nbbs":10}]
            }"#,
    );
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    let counts = recovery.without_exports().apply(&mut symbols, &mut metrics);
    assert_eq!(counts.exports, 0);
    assert_eq!(count_kind(&symbols, SymbolKind::Export), 0);
    assert_eq!(count_kind(&symbols, SymbolKind::Import), 1);
    assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
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
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    assert_eq!(count_kind(&symbols, SymbolKind::Function), 3);
    assert_eq!(metrics.get("binary.avg_complexity"), Some(3.0));
    assert_eq!(metrics.get("binary.max_complexity"), Some(5.0));
    assert_eq!(metrics.get("binary.avg_basic_blocks"), Some(4.0));
    assert_eq!(metrics.get("binary.basic_block_count"), Some(12.0));
}

#[test]
fn apply_omits_complexity_metrics_when_cc_absent() {
    // Functions without `cc` shouldn't emit complexity averages.
    // Without `nbbs` shouldn't emit basic-block aggregates either.
    let recovery =
        make_recovery(r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1}]}"#);
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
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

#[test]
fn cache_fingerprint_is_stable_and_tracks_availability() {
    // Host-independent contract: the fingerprint is deterministic
    // within a process and reflects whether rizin is on PATH. When
    // absent it is the sentinel `rizin=none`; when present it names a
    // version (or `unknown`), so a no-rizin run and a rizin run never
    // collide on a cache key.
    let settings = Settings::default();
    let first = cache_fingerprint(&settings);
    let second = cache_fingerprint(&settings);
    assert_eq!(first, second, "fingerprint must be stable per process");
    assert!(first.starts_with("rizin="), "fingerprint names the tool");
    if available() {
        assert_ne!(first, "rizin=none");
    } else {
        assert_eq!(first, "rizin=none");
    }
}

/// Every setting that changes a persisted result changes the fingerprint;
/// the timeout, which only ever produces an unpersisted result, does not.
#[test]
fn cache_fingerprint_tracks_output_affecting_settings() {
    let base = Settings::default();
    let off = Settings {
        enabled: false,
        ..base
    };
    assert_eq!(cache_fingerprint(&off), "rizin=none");
    let slower = Settings {
        timeout: Duration::from_secs(1),
        ..base
    };
    assert_eq!(cache_fingerprint(&slower), cache_fingerprint(&base));
    if !available() {
        return;
    }
    assert_ne!(cache_fingerprint(&off), cache_fingerprint(&base));
    let native = Settings {
        native_arch_only: true,
        ..base
    };
    let capped = Settings {
        max_bytes: Some(1 << 20),
        ..base
    };
    let distinct: std::collections::HashSet<String> = [base, off, native, capped]
        .iter()
        .map(cache_fingerprint)
        .collect();
    assert_eq!(distinct.len(), 4, "{distinct:?}");
}

#[test]
fn settings_admit_only_enabled_inputs_within_the_cap() {
    let base = Settings::default();
    assert!(base.admits(&[0; 64]));
    let off = Settings {
        enabled: false,
        ..base
    };
    assert!(!off.admits(&[0; 64]));
    let capped = Settings {
        max_bytes: Some(64),
        ..base
    };
    assert!(capped.admits(&[0; 64]));
    assert!(!capped.admits(&[0; 65]));
}

// ------------------------------------------------------------------
// Go recovery: `aalg` must run before discovery
// ------------------------------------------------------------------

/// `aalg` names only the functions it creates; one `aa`/`aac` already made
/// stays `fcn.*`. The Go script ran `aa; aac; aalg` and left most of every
/// Go binary unnamed. Host-independent guard on the order.
#[test]
fn go_script_runs_aalg_before_discovery() {
    let (script, label) = analysis_script(b"", 1, true);
    assert_eq!(label, "go-pclntab");
    let aalg = script.find("aalg").expect("Go script runs aalg");
    let aa = script.find("aa;").expect("Go script runs aa");
    assert!(aalg < aa, "aalg must precede aa: {script}");
    assert!(!script.contains("aa; aac; aalg"), "{script}");
}

/// End to end on a stripped Go binary whose functions carry long
/// module-qualified and generic names (see
/// tests/fixtures/go-pclntab-names.md). In the old order none of its five
/// `sealedpayload` functions came back named and 1,514 of 2,082 were
/// `fcn.*`. Skips when rizin is not installed.
#[test]
fn go_recovery_names_pclntab_functions() {
    if !available() {
        return;
    }
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/go-pclntab-names.zst"
    ))
    .expect("fixture present");
    let bytes = zstd::decode_all(compressed.as_slice()).expect("fixture decompresses");
    // This spawns a real rizin, so it needs the same protection as the
    // shim tests: the reaper test SIGKILLs every registered process group,
    // which turns an in-flight recovery into `None`. `recover_with_bin`
    // rather than `recover_with_symbols` so the in-run memo cannot answer
    // in place of a real run.
    let _lock = rizin_test_lock();
    let bin = rizin_binary().expect("available() found rizin");
    let rec =
        recover_with_bin(bin, &bytes, 0, true, RIZIN_TIMEOUT).expect("rizin recovers the fixture");

    let total = rec.functions.len();
    let unnamed = rec
        .functions
        .iter()
        .filter(|f| f.name.starts_with("fcn."))
        .count();
    let ours: Vec<&str> = rec
        .functions
        .iter()
        .map(|f| f.name.as_str())
        .filter(|n| n.contains("sealedpayload"))
        .collect();

    assert!(total > 1000, "recovered only {total} functions");
    assert!(
        unnamed * 10 < total,
        "{unnamed} of {total} functions left as fcn.* -- is aalg running first?"
    );
    for want in ["OpenSealedPayload", "ReportLength", "mustValue"] {
        assert!(
            ours.iter().any(|n| n.contains(want)),
            "{want} not recovered by name; got {ours:?}"
        );
    }
}

/// Two files opened at the same time, one with rizin and one without,
/// each get exactly what they asked for: the setting travels with the
/// `ParsedFile`, so neither can mute or enable the other. Skips when rizin
/// is not installed.
#[test]
fn concurrent_opens_keep_their_own_rizin_settings() {
    if !available() {
        return;
    }
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/go-pe-no-exports.exe.zst"
    ))
    .expect("fixture present");
    let bytes = zstd::decode_all(compressed.as_slice()).expect("fixture decompresses");
    // The reaper test would turn the rizin-on recovery into `None`.
    let _lock = rizin_test_lock();
    let on = crate::OpenOptions::new().cache(false);
    let off = crate::OpenOptions::new().cache(false).rizin(false);
    let run = |options: &crate::OpenOptions<'_>| {
        let parsed = options.open(&bytes);
        (
            count_kind(parsed.symbols(), SymbolKind::Function),
            parsed.rizin_recovery_incomplete(),
        )
    };
    let ((on_functions, on_incomplete), (off_functions, off_incomplete)) =
        std::thread::scope(|scope| {
            let with = scope.spawn(|| run(&on));
            let without = scope.spawn(|| run(&off));
            (with.join().unwrap(), without.join().unwrap())
        });
    assert!(on_functions > 0, "rizin-on open recovered no functions");
    assert!(!on_incomplete);
    assert_eq!(off_functions, 0, "rizin-off open ran rizin");
    // Turned off on purpose is a stable result, not an incomplete one.
    assert!(!off_incomplete);
}

/// End to end on a Go PE with no export directory (see
/// tests/fixtures/go-pe-no-exports.md). Rizin recovers its functions but
/// also lists the `gopclntab` symbol under `iEj`; that must not reach the
/// export view. Skips when rizin is not installed.
#[test]
fn go_pe_without_export_directory_recovers_no_exports() {
    if !available() {
        return;
    }
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/go-pe-no-exports.exe.zst"
    ))
    .expect("fixture present");
    let bytes = zstd::decode_all(compressed.as_slice()).expect("fixture decompresses");
    // Held for the whole parse: the reaper test would turn this recovery
    // into `None`, and an empty recovery passes vacuously.
    let _lock = rizin_test_lock();
    let parsed = crate::open(&bytes);

    let symbols = parsed.symbols();
    assert!(
        count_kind(symbols, SymbolKind::Function) > 0,
        "rizin did not run, so the export check below proves nothing"
    );
    let exports: Vec<&Symbol> = symbols.iter_kind(SymbolKind::Export).collect();
    assert!(exports.is_empty(), "phantom exports: {exports:?}");
    assert!(parsed.metrics().get("pe.recovered_export_count").is_none());
}

// ------------------------------------------------------------------
// Hardening: reaper, stats counters
// ------------------------------------------------------------------

#[test]
#[cfg(unix)]
fn kill_all_rizin_groups_drains_pgid_registry_idempotently() {
    // Hold the rizin test lock — `kill_all_rizin_groups` SIGKILLs
    // every entry in the registry, which would otherwise reap
    // live shim subprocesses from sibling tests running in
    // parallel under the default cargo-test thread pool.
    let _lock = rizin_test_lock();
    // No PGIDs registered: should be a clean no-op. Verifies the
    // public reaper survives being called from a CLI signal
    // handler after a clean shutdown.
    let before = RIZIN_PGIDS.lock().map(|g| g.len()).unwrap_or(0);
    kill_all_rizin_groups();
    let after = RIZIN_PGIDS.lock().map(|g| g.len()).unwrap_or(0);
    assert_eq!(before, after);
}

#[test]
fn log_stats_is_no_op_when_total_zero() {
    // Just confirm the call doesn't panic when nothing has been
    // recorded yet. Real telemetry assertions would need a
    // tracing subscriber; that's out of scope here.
    // (We don't assert the counter — parallel tests may have
    // bumped it.)
    log_stats();
}

#[test]
fn stats_are_monotonic_named_counters() {
    let before = stats();
    let after = stats();
    // Parallel tests may bump counters between the two reads, never lower
    // them.
    assert!(after.total >= before.total);
    assert!(after.failures >= before.failures);
    assert!(after.abandoned_drains >= before.abandoned_drains);
}

// ------------------------------------------------------------------
// Temp input: unpredictable, private, never left behind
// ------------------------------------------------------------------

#[test]
fn temp_input_is_private_registered_and_removed_on_drop() {
    let input = TempInput::write(b"sample bytes").expect("temp dir is writable");
    let path = input.path().to_path_buf();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with(TEMP_INPUT_PREFIX), "{name}");
    assert!(
        !name.contains(&format!("-{}-", std::process::id())),
        "name must not be derivable from the pid: {name}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"sample bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "other users must not read the sample");
    }
    assert!(registry(&RIZIN_TEMP_INPUTS).contains(&path));
    drop(input);
    assert!(!path.exists(), "temp input deleted on drop");
    assert!(!registry(&RIZIN_TEMP_INPUTS).contains(&path));
}

#[test]
#[cfg(unix)]
fn temp_input_refuses_a_planted_path() {
    // The old name was `filefacts-rizin-{pid}-{seq}.bin`: plant a symlink at
    // every name it could have chosen next and check none is written through.
    let target = unique_shim_dir("filefacts-rizin-planted-target");
    let victim = target.with_extension("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    let mut planted = Vec::new();
    for seq in 0..64 {
        let p =
            std::env::temp_dir().join(format!("filefacts-rizin-{}-{seq}.bin", std::process::id()));
        if std::os::unix::fs::symlink(&victim, &p).is_ok() {
            planted.push(p);
        }
    }
    let input = TempInput::write(b"sample").unwrap();
    assert!(!planted.contains(&input.path().to_path_buf()));
    drop(input);
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    for p in planted {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_file(victim);
}

#[test]
fn kill_all_rizin_groups_removes_registered_temp_inputs() {
    let _lock = rizin_test_lock();
    let input = TempInput::write(b"in flight").unwrap();
    let path = input.path().to_path_buf();
    kill_all_rizin_groups();
    assert!(
        !path.exists(),
        "the reaper deletes inputs process::exit would leak"
    );
    // The run's own cleanup still tolerates the file being gone.
    drop(input);
    assert!(!registry(&RIZIN_TEMP_INPUTS).contains(&path));
}

// ------------------------------------------------------------------
// In-run memo: byte-bounded
// ------------------------------------------------------------------

#[test]
fn memo_is_bounded_by_bytes_as_well_as_entries() {
    let mut memo = Memo::new();
    let empty = || Some(make_recovery("{}"));
    memo.insert([1; 32], empty(), RIZIN_MEMO_MAX_BYTES / 8);
    assert!(memo.get(&[1; 32]).is_some());
    // Too large to share the budget: not remembered, and nothing evicted.
    memo.insert([2; 32], empty(), RIZIN_MEMO_MAX_BYTES / 2);
    assert!(memo.get(&[2; 32]).is_none());
    assert!(memo.get(&[1; 32]).is_some());
    // Filling past the byte budget resets the map instead of growing it.
    for k in 3..20u8 {
        memo.insert([k; 32], empty(), RIZIN_MEMO_MAX_BYTES / 5);
        assert!(memo.bytes <= RIZIN_MEMO_MAX_BYTES, "{} bytes", memo.bytes);
    }
    // A memoized failure is remembered as such.
    memo.insert([99; 32], None, 0);
    assert_eq!(memo.get(&[99; 32]).map(Option::is_none), Some(true));
}

#[test]
#[cfg(unix)]
fn outside_sigkill_is_transient_but_a_crash_is_decided() {
    let _lock = rizin_test_lock();
    let killed = stage_script("filefacts-rizin-killedshim", "kill -9 $$\n");
    let attempt = attempt_with_bin(&killed.join("rizin"), b"x", 0, false, RIZIN_TIMEOUT);
    assert!(attempt.recovery.is_none());
    assert!(
        !attempt.deterministic,
        "a SIGKILL we did not send must not be memoized"
    );
    let crashed = stage_script("filefacts-rizin-crashshim", "exit 3\n");
    let attempt = attempt_with_bin(&crashed.join("rizin"), b"x", 0, false, RIZIN_TIMEOUT);
    assert!(attempt.recovery.is_none());
    assert!(attempt.deterministic, "a crash on these bytes is theirs");
    let _ = std::fs::remove_dir_all(killed);
    let _ = std::fs::remove_dir_all(crashed);
}

// ------------------------------------------------------------------
// Hardened runner: output cap, version probe
// ------------------------------------------------------------------

/// Stage `body` as an executable `rizin` shell script in a fresh directory.
#[cfg(unix)]
fn stage_script(prefix: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_shim_dir(prefix);
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("rizin");
    std::fs::write(&shim, format!("#!/bin/sh\n{body}")).unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();
    dir
}

#[test]
#[cfg(unix)]
fn output_cap_kills_the_group_from_the_supervisor_and_keeps_the_prefix() {
    let _lock = rizin_test_lock();
    // Writes forever; only the cap can end it before the deadline.
    let dir = stage_script("filefacts-rizin-floodshim", "yes rizin-output\n");
    let started = std::time::Instant::now();
    let outcome = run_hardened(
        Command::new(dir.join("rizin")),
        Duration::from_secs(30),
        64 * 1024,
    );
    let RunOutcome::Exited {
        status,
        stdout,
        cap_hit,
    } = outcome
    else {
        panic!("a capped run still exits");
    };
    assert!(cap_hit);
    assert!(!status.success());
    assert_eq!(stdout.len(), 64 * 1024, "the prefix up to the cap is kept");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the cap, not the deadline, ended the run"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(unix)]
fn version_probe_is_bounded_by_its_deadline() {
    let _lock = rizin_test_lock();
    let dir = stage_script("filefacts-rizin-hangshim", "exec sleep 300\n");
    let started = std::time::Instant::now();
    assert_eq!(version_of(&dir.join("rizin"), Duration::from_secs(1)), None);
    assert!(started.elapsed() < Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);

    let dir = stage_script("filefacts-rizin-versionshim", "echo 'rizin 9.9.9 @ test'\n");
    assert_eq!(
        version_of(&dir.join("rizin"), Duration::from_secs(30)).as_deref(),
        Some("rizin 9.9.9 @ test")
    );
    let _ = std::fs::remove_dir_all(dir);
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

/// A name inside a JSON block is attacker-chosen. One spelling the separator
/// must not split its block, or every later block shifts and the binary's
/// imports, exports and functions all vanish from the recovery.
#[test]
fn parse_recovery_output_ignores_separator_inside_names() {
    let stdout = synthesize_stdout(
        r#"[{"name":"===SEP===","libname":"libc.so"},{"name":"open"}]"#,
        r#"[{"name":"start","vaddr":4096}]"#,
        "",
        r#"[{"name":"main","offset":4096}]"#,
    );
    let rec = parse_recovery_output(&stdout);
    assert_eq!(rec.imports.len(), 2);
    assert_eq!(rec.imports[0].name, "===SEP===");
    assert_eq!(rec.exports.len(), 1);
    assert_eq!(rec.functions.len(), 1);
    assert_eq!(rec.functions[0].name, "main");
}

/// Call sites resolved by address each copy the callee's binary-chosen name;
/// the copies stay within `MAX_RESOLVED_NAME_BYTES` however many sites call
/// one long name, and every call site is still recorded.
#[test]
fn resolved_call_names_are_bounded() {
    const SITES: usize = 80;
    let long = "f".repeat(1 << 20);
    let callrefs = vec![r#"{"to":1,"type":"CALL"}"#; SITES].join(",");
    let stdout = synthesize_stdout(
        "[]",
        "[]",
        "",
        &format!(
            r#"[{{"name":"{long}","offset":1}},{{"name":"g","offset":2,"callrefs":[{callrefs}]}}]"#
        ),
    );
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    parse_recovery_output(&stdout).apply(&mut symbols, &mut metrics);
    let mut copied = 0;
    let mut calls = 0;
    for symbol in symbols.iter() {
        match symbol {
            Symbol::Function { name, callees, .. } if name == "g" => {
                copied += callees.iter().map(String::len).sum::<usize>();
            }
            Symbol::Call { target, .. } => {
                calls += 1;
                copied += target.as_ref().map_or(0, String::len);
            }
            _ => {}
        }
    }
    assert!(copied <= MAX_RESOLVED_NAME_BYTES, "{copied} bytes copied");
    assert!(copied > 0);
    assert_eq!(calls, SITES);
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

/// Process-unique counter for shim scratch dirs. The previous
/// `pid + subsec_nanos` scheme raced when three tests staged dirs
/// inside the same nanosecond window under parallel execution.
#[cfg(any(unix, windows))]
fn unique_shim_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Execute a freshly staged shim once, untimed, so the timing assertions
/// below measure the recovery path and not the host's first-exec cost.
///
/// EndpointSecurity clients (macOS XProtect, and any third-party agent
/// installed alongside it) hold the *first* `exec` of a newly written file
/// while they scan it, then cache the verdict; the same shim runs in
/// milliseconds afterwards. Measured at 11-36 s on one developer Mac, which
/// is many times every bound asserted here. Every shim used by a timed test
/// exits immediately when its first argument is `warmup`.
#[cfg(unix)]
fn warm_shim_exec(shim: &Path) {
    let status = Command::new(shim)
        .arg("warmup")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("warm-up exec of the shim");
    assert!(status.success(), "shim warm-up exited with {status}");
}

/// Stage a shell script that masquerades as `rizin`, prints a
/// fixed stdout payload (escaping the canonical separators), and
/// returns its directory so we can stitch it onto PATH. Returns
/// `None` on non-Unix or when `/bin/sh` isn't available — those
/// platforms exercise the same paths under cleave's real rizin.
#[cfg(unix)]
fn stage_shim(stdout_payload: &str) -> Option<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_shim_dir("filefacts-rizin-shim");
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
    let _lock = rizin_test_lock();
    // A canonical four-block payload — exercises spawn, drain,
    // separator split, and per-block JSON parse together.
    let payload = synthesize_stdout(
        r#"[{"name":"malloc","libname":"libc.so.6"}]"#,
        r#"[{"name":"entry","vaddr":4096}]"#,
        "analysis-chatter-ignored",
        r#"[{"name":"f1","offset":4096,"cc":7,"nbbs":12}]"#,
    );
    let rec = run_against_shim(&payload, b"unused bytes for temp file")
        .expect("shim should return a recovery; if your /bin/sh is missing this test can't run");
    assert_eq!(rec.imports.len(), 1);
    assert_eq!(rec.imports[0].libname.as_deref(), Some("libc.so.6"));
    assert_eq!(rec.exports.len(), 1);
    assert_eq!(rec.functions.len(), 1);
    assert_eq!(rec.functions[0].cc, Some(7));
}

#[test]
#[cfg(unix)]
fn end_to_end_shim_handles_large_stdout_via_pipe_drain() {
    let _lock = rizin_test_lock();
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
    let _lock = rizin_test_lock();
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
    let _lock = rizin_test_lock();
    // Pure-stdlib shim that exits 0 with zero stdout bytes. Exercises
    // the `stdout_bytes.is_empty() → None` guard against subprocesses
    // that silently fail (rizin crashing before its first echo).
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_shim_dir("filefacts-rizin-silentshim");
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
    let _lock = rizin_test_lock();
    // Shim exits non-zero (rizin crashed) — recover should not
    // return phantom data even if some partial stdout leaked.
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_shim_dir("filefacts-rizin-failshim");
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

#[test]
#[cfg(unix)]
fn exited_rizin_cannot_leave_descendant_holding_worker() {
    let _lock = rizin_test_lock();

    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_shim_dir("filefacts-rizin-descendantshim");
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("rizin");
    let descendant_pid = dir.join("descendant.pid");
    let mut f = std::fs::File::create(&shim).unwrap();
    writeln!(f, "#!/bin/sh").unwrap();
    // See `warm_shim_exec`: the untimed warm-up run must not fork a helper.
    writeln!(f, "[ \"$1\" = warmup ] && exit 0").unwrap();
    // The descendant inherits stdout, then the shim exits immediately. If
    // the recovery path only reaps the group leader, `drain.join()` blocks
    // until this sleep ends and retains its Rayon caller in the meantime.
    writeln!(f, "sleep 5 &").unwrap();
    writeln!(f, "descendant=$!").unwrap();
    writeln!(
        f,
        "printf '%s\\n' \"$descendant\" > '{}'",
        descendant_pid.display()
    )
    .unwrap();
    writeln!(f, "exit 1").unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();
    drop(f);

    warm_shim_exec(&shim);

    let started = std::time::Instant::now();
    let rec = recover_with_bin_for_test(&shim, b"descendant cleanup fixture");
    let elapsed = started.elapsed();
    assert!(rec.is_none(), "failed Rizin must not emit partial facts");
    assert!(
        elapsed < Duration::from_secs(2),
        "lingering descendant retained the worker for {elapsed:?}"
    );

    let descendant: i32 = std::fs::read_to_string(&descendant_pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for _ in 0..100 {
        // SAFETY: signal 0 performs existence/permission probing only.
        #[allow(unsafe_code)]
        let exists = unsafe { libc::kill(descendant, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        if !exists {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: signal 0 performs existence/permission probing only.
    #[allow(unsafe_code)]
    let exists = unsafe { libc::kill(descendant, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    assert!(!exists, "Rizin descendant survived its leader's exit");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Windows counterpart of the `descendant_*` tests: a shim that
/// backgrounds a helper which inherits stdout and then exits must not
/// retain its Rayon caller.
///
/// This is the shape behind a whole-scan stall observed 2026-08-22 — every
/// archive queued on the scan memory gate while the permit holder sat at
/// 0% CPU. The leader is reaped, but `read_to_end` cannot return while a
/// descendant holds the pipe's write end, and the drain join was unbounded.
/// Unix contains this with a private process group; until the job object in
/// `win_job`, Windows had neither the containment nor this coverage.
#[test]
#[cfg(windows)]
fn windows_descendant_holding_stdout_does_not_retain_worker() {
    let _lock = rizin_test_lock();

    const HELPER_SECS: u64 = 20;
    let dir = unique_shim_dir("filefacts-rizin-winshim");
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("rizin.cmd");
    let marker = dir.join("shim-ran.txt");

    // `start /b` hands the helper an inherited copy of stdout and does not
    // wait for it, so the leader exits while the pipe stays open.
    let script = [
        "@echo off".to_string(),
        format!("echo ran > \"{}\"", marker.display()),
        format!(
            "start /b \"\" powershell -NoProfile -Command \"Start-Sleep -Seconds {HELPER_SECS}\""
        ),
        "exit 1".to_string(),
    ]
    .join("\r\n");
    std::fs::write(&shim, script).unwrap();

    let started = std::time::Instant::now();
    let rec = recover_with_bin_for_test(&shim, b"windows descendant fixture");
    let elapsed = started.elapsed();

    assert!(
        marker.exists(),
        "shim never executed — the assertions below would be vacuous"
    );
    assert!(rec.is_none(), "failed Rizin must not emit partial facts");
    assert!(
        elapsed < Duration::from_secs(HELPER_SECS / 2),
        "descendant holding stdout retained the worker for {elapsed:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(unix)]
fn timeout_kills_process_group_joins_reader_and_returns_worker() {
    let _lock = rizin_test_lock();

    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_shim_dir("filefacts-rizin-timeoutshim");
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("rizin");
    let leader_pid = dir.join("leader.pid");
    let descendant_pid = dir.join("descendant.pid");
    let mut f = std::fs::File::create(&shim).unwrap();
    writeln!(f, "#!/bin/sh").unwrap();
    // See `warm_shim_exec`: the untimed warm-up run must not block 300 s.
    writeln!(f, "[ \"$1\" = warmup ] && exit 0").unwrap();
    writeln!(f, "printf '%s\\n' \"$$\" > '{}'", leader_pid.display()).unwrap();
    writeln!(f, "sleep 300 &").unwrap();
    writeln!(f, "descendant=$!").unwrap();
    writeln!(
        f,
        "printf '%s\\n' \"$descendant\" > '{}'",
        descendant_pid.display()
    )
    .unwrap();
    writeln!(f, "wait \"$descendant\"").unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();
    drop(f);

    warm_shim_exec(&shim);

    let started = std::time::Instant::now();
    let rec = recover_with_bin(
        &shim,
        b"timeout cleanup fixture",
        0,
        false,
        Duration::from_secs(1),
    );
    let elapsed = started.elapsed();
    assert!(rec.is_none(), "timed-out Rizin must not emit partial facts");
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5),
        "one-second timeout returned after {elapsed:?}"
    );

    let leader: i32 = std::fs::read_to_string(&leader_pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let descendant: i32 = std::fs::read_to_string(&descendant_pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    fn process_exists(pid: i32) -> bool {
        // SAFETY: signal 0 performs existence/permission probing only.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::kill(pid, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    // The direct child is synchronously waited. Its background child is
    // killed by the same process-group signal and may remain a zombie for a
    // scheduler tick while init adopts it, so give reaping a short grace.
    for _ in 0..100 {
        if !process_exists(leader) && !process_exists(descendant) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!process_exists(leader), "Rizin group leader was not reaped");
    assert!(
        !process_exists(descendant),
        "Rizin descendant survived the process-group timeout"
    );
    assert!(
        !RIZIN_PGIDS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&leader),
        "timed-out Rizin remained in the live-process registry"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Temp-file cleanup is enforced by a `Drop` guard on `Cleanup<'_>`
// inside `recover_with_bin`. Snapshotting `/tmp` before/after a
// shim run would race against parallel shim tests (other threads
// running `recover_with_bin_for_test` create files with the same
// PID prefix); serialising every shim test to make the snapshot
// deterministic defeats parallelism. The Drop pattern is idiomatic
// Rust and was verified end-to-end on the malware sample run
// (8,325 functions recovered, no `filefacts-rizin-*` files left in
// `/tmp` across sessions).

#[test]
fn deadline_retry_targets_only_timeouts_and_runs_at_most_once() {
    let mut budgets = Vec::new();
    let first = Duration::from_millis(5);
    let second = Duration::from_millis(20);
    let result = attempt_with_retry(first, Some(second), |budget| {
        budgets.push(budget);
        Attempt::timed_out()
    });
    assert!(result.timed_out);
    assert_eq!(budgets, vec![first, second]);
    for attempt in [
        Attempt::transient(),
        Attempt::decided(None, 0),
        Attempt::decided(Some(make_recovery("{}")), 1),
    ] {
        let mut calls = 0;
        let result = attempt_with_retry(first, Some(second), |_| {
            calls += 1;
            attempt.clone()
        });
        assert_eq!(calls, 1);
        assert_eq!(result.timed_out, attempt.timed_out);
    }
}

#[test]
fn smaller_equal_or_disabled_retry_deadline_is_not_used() {
    for retry in [
        None,
        Some(Duration::from_millis(5)),
        Some(Duration::from_millis(1)),
    ] {
        let mut calls = 0;
        let result = attempt_with_retry(Duration::from_millis(5), retry, |_| {
            calls += 1;
            Attempt::timed_out()
        });
        assert!(result.timed_out);
        assert_eq!(calls, 1);
    }
}

#[test]
#[cfg(unix)]
fn timed_out_shim_retries_and_recovers_but_crash_does_not_retry() {
    let _lock = rizin_test_lock();
    // See `warm_shim_exec`: a held first exec would outlast the 100 ms budget.
    let dir = stage_script(
        "filefacts-native-retry",
        "[ \"$1\" = warmup ] && exit 0\nflag=\"${0}.first\"\nif [ ! -f \"$flag\" ]; then : > \"$flag\"; exec sleep 300; fi\nprintf '[]\\n===SEP===\\n[]\\n===SEP===\\n[]\\n===SEP===\\n[]\\n'\n",
    );
    warm_shim_exec(&dir.join("rizin"));
    let mut runs = 0;
    let result = attempt_with_retry(
        Duration::from_millis(100),
        Some(Duration::from_secs(2)),
        |timeout| {
            runs += 1;
            attempt_with_bin(&dir.join("rizin"), b"fixture", 0, false, timeout)
        },
    );
    assert_eq!(runs, 2);
    assert!(result.recovery.is_some());
    assert!(!result.timed_out);
    let crash = stage_script(
        "filefacts-native-retry-crash",
        "[ \"$1\" = warmup ] && exit 0\nexit 3\n",
    );
    warm_shim_exec(&crash.join("rizin"));
    let mut runs = 0;
    let result = attempt_with_retry(
        Duration::from_millis(100),
        Some(Duration::from_secs(2)),
        |timeout| {
            runs += 1;
            attempt_with_bin(&crash.join("rizin"), b"fixture", 0, false, timeout)
        },
    );
    assert_eq!(runs, 1);
    assert!(result.recovery.is_none());
    assert!(!result.timed_out);
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(crash);
}
