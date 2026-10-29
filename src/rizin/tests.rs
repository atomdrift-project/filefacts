use super::recovery::*;
use super::*;
use crate::output::{Metrics, SectionFlag, Symbol, SymbolKind, Symbols};

/// Serializes the tests that run rizin through the process-wide
/// [`SUPERVISOR`] (an open with rizin on), so their heavy real-rizin runs do
/// not compete for the machine. Every test that launches a shim or reaps
/// groups uses a private [`Supervisor`] instead and needs no lock: its
/// registry and shutdown latch are its own.
pub(crate) fn rizin_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    lock(&LOCK)
}

#[test]
fn gate_caps_live_runs_and_releases_on_unwind() {
    use std::sync::atomic::AtomicUsize;

    let gate = Gate::new();
    gate.set_limit(NonZeroUsize::new(2));
    let live = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..12 {
            let gate = &gate;
            let live = &live;
            let peak = &peak;
            scope.spawn(move || {
                let _permit = gate.acquire();
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(lock(&gate.state).active, 0);
    let _ = std::panic::catch_unwind(|| {
        let _permit = gate.acquire();
        panic!("release a permit on unwind");
    });
    assert_eq!(lock(&gate.state).active, 0);
}

/// Lifting the limit releases runs already waiting at the old one.
#[test]
fn gate_limit_change_wakes_waiting_runs() {
    let gate = Gate::new();
    gate.set_limit(NonZeroUsize::new(1));
    let held = gate.acquire();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| drop(gate.acquire()));
        // Whether or not the waiter has blocked yet, lifting the limit lets
        // it through while `held` is still out.
        gate.set_limit(None);
        waiter.join().unwrap();
    });
    drop(held);
    assert_eq!(lock(&gate.state).active, 0);
}

fn make_recovery(json: &str) -> RizinRecovery {
    #[derive(serde::Deserialize)]
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
            .any(|w| w == ["-e", "log.level=3"]),
        "keep warnings/errors without per-function debug/info logging"
    );
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

/// Every script's output splits into exactly the blocks the parser reads.
#[test]
fn every_script_emits_one_block_per_parsed_table() {
    for script in [
        RIZIN_METRICS_SCRIPT,
        RIZIN_METRICS_SCRIPT_PE_X86,
        RIZIN_METRICS_SCRIPT_PRELUDE,
        RIZIN_METRICS_SCRIPT_GO,
    ] {
        let blocks = script.matches("echo ===SEP===").count() + 1;
        assert_eq!(blocks, 5, "{script}");
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
    let label = |bytes: &[u8], symbols, go| analysis_script(bytes, symbols, go).label;
    assert_eq!(label(&pe(0x8664), 5, false), "pe-x86");
    assert_eq!(label(&pe(0x014c), 5, false), "pe-x86");
    assert_eq!(
        label(&pe(0x8664), 0, false),
        "pe-x86",
        "PE x86 is exact even without symbols"
    );
    assert_eq!(
        label(&pe(0xaa64), 5, false),
        "prelude",
        "arm64 PE takes the prelude script"
    );
    assert_eq!(label(b"\x7fELF\x02\x01\x01", 5, false), "prelude");
    assert_eq!(
        label(b"\x7fELF\x02\x01\x01", 0, false),
        "full",
        "no symbol inventory keeps aaa"
    );
    assert_eq!(
        label(b"MZ", 5, false),
        "prelude",
        "truncated header is not PE x86"
    );
    let mut bad = pe(0x8664);
    bad[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    assert_eq!(
        label(&bad, 5, false),
        "prelude",
        "e_lfanew out of range is not PE x86"
    );
    assert_eq!(
        label(&pe(0x8664), 5, true),
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

#[test]
fn raw_function_reads_offset_and_size() {
    let v: Vec<RawFunction> =
        parse_json_array(r#"[{"name":"a","offset":4096,"size":32}]"#).unwrap();
    assert_eq!(v[0].offset, 4096);
    assert_eq!(v[0].size, 32);
    let v: Vec<RawFunction> = parse_json_array(r#"[{"name":"b"}]"#).unwrap();
    assert_eq!((v[0].offset, v[0].size), (0, 0));
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
// apply gate logic — "only fill what the format parser left empty"
// ------------------------------------------------------------------

fn first_function(symbols: &Symbols) -> Option<&Symbol> {
    symbols.iter_kind(SymbolKind::Function).next()
}

fn count_kind(symbols: &Symbols, kind: SymbolKind) -> usize {
    symbols.iter_kind(kind).count()
}

#[test]
fn apply_populates_cfg_fields_from_aflj() {
    // A full aflj payload: named callrefs land on `callees` and as calls,
    // the CODE ref does not, and fields filefacts does not import are
    // ignored.
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
fn apply_skips_imports_when_the_parser_already_populated_them() {
    let recovery =
        make_recovery(r#"{"imports":[{"name":"rizin_only"}],"exports":[],"functions":[]}"#);
    let mut symbols = Symbols::new();
    symbols.push(Symbol::Import {
        name: "from_parser".into(),
        alias: None,
        library: None,
        offset: None,
        ordinal: None,
    });
    let mut metrics = Metrics::new();
    recovery.apply(&mut symbols, &mut metrics);
    // Rizin import dropped — the parser's entry survives untouched.
    let names: Vec<String> = symbols
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec!["from_parser"]);
}

#[test]
fn recovered_import_anchors_at_plt_address() {
    // rizin's iij carries the PLT/stub address; recovery records it as the
    // import's offset (it only runs when the parser found zero imports). An
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
    // The preexisting function survives.
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
fn apply_with_sections_fills_only_an_empty_table() {
    let recovery = || {
        make_recovery(
            r#"{"sections":[
                {"name":".text","size":16,"vaddr":4096,"paddr":512,"perm":"-r-x"},
                {"name":"","size":1}
            ]}"#,
        )
    };
    let mut symbols = Symbols::new();
    let mut metrics = Metrics::new();
    let mut sections = Vec::new();
    let counts = recovery().apply_with_sections(&mut symbols, &mut sections, &mut metrics);
    assert_eq!(counts.sections, 1);
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].name, ".text");
    assert_eq!(
        (
            sections[0].vaddr,
            sections[0].vsize,
            sections[0].file_offset
        ),
        (4096, 16, 512)
    );
    assert_eq!(
        sections[0].flags,
        [SectionFlag::Readable, SectionFlag::Executable]
    );
    let counts = recovery().apply_with_sections(&mut symbols, &mut sections, &mut metrics);
    assert_eq!(counts.sections, 0);
    assert_eq!(sections.len(), 1);
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
/// stays `fcn.*`, so the Go script must run `aalg` first. Host-independent
/// guard on the order.
#[test]
fn go_script_runs_aalg_before_discovery() {
    let script = analysis_script(b"", 1, true);
    assert_eq!(script.label, "go-pclntab");
    let aalg = script.commands.find("aalg").expect("Go script runs aalg");
    let aa = script.commands.find("aa;").expect("Go script runs aa");
    assert!(aalg < aa, "aalg must precede aa: {}", script.commands);
    assert!(
        !script.commands.contains("aa; aac; aalg"),
        "{}",
        script.commands
    );
}

/// End to end on a stripped Go binary whose functions carry long
/// module-qualified and generic names (see
/// tests/fixtures/go-pclntab-names.md). With discovery before `aalg`, none
/// of its five `sealedpayload` functions came back named and 1,514 of 2,082
/// were `fcn.*`. Skips when rizin is not installed.
#[test]
fn go_recovery_names_pclntab_functions() {
    let Some(bin) = rizin_binary() else {
        return;
    };
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/go-pclntab-names.zst"
    ))
    .expect("fixture present");
    let bytes = zstd::decode_all(compressed.as_slice()).expect("fixture decompresses");
    // A private supervisor, so neither the process-wide memo nor another
    // test's runs can answer in place of a real run.
    let supervisor = Supervisor::new();
    let script = analysis_script(&bytes, 0, true);
    let rec = supervisor
        .attempt(bin, &bytes, script, RIZIN_TIMEOUT)
        .recovery
        .expect("rizin recovers the fixture");

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
    let _lock = rizin_test_lock();
    let parsed = crate::OpenOptions::new().cache(false).open(&bytes);

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
fn kill_all_on_an_idle_supervisor_is_a_no_op() {
    // No groups registered: a clean no-op, as when a CLI signal handler runs
    // after a clean shutdown.
    let supervisor = Supervisor::new();
    supervisor.kill_all();
    supervisor.kill_all();
    assert!(lock(&supervisor.pgids).is_empty());
    assert!(*lock(&supervisor.shutdown));
}

#[test]
fn log_stats_is_no_op_when_total_zero() {
    // Just confirm the call doesn't panic, whatever other tests have
    // recorded in the process-wide counters.
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
    let supervisor = Supervisor::new();
    let input = TempInput::write(&supervisor, b"sample bytes").expect("temp dir is writable");
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
    assert!(lock(&supervisor.temp_inputs).contains(&path));
    drop(input);
    assert!(!path.exists(), "temp input deleted on drop");
    assert!(!lock(&supervisor.temp_inputs).contains(&path));
}

#[test]
#[cfg(unix)]
fn temp_input_refuses_a_planted_path() {
    // A name derived from the pid and a sequence number could be predicted:
    // plant a symlink at every such name and check none is written through.
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
    let supervisor = Supervisor::new();
    let input = TempInput::write(&supervisor, b"sample").unwrap();
    assert!(!planted.contains(&input.path().to_path_buf()));
    drop(input);
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    for p in planted {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_file(victim);
}

#[test]
fn kill_all_removes_registered_temp_inputs() {
    let supervisor = Supervisor::new();
    let input = TempInput::write(&supervisor, b"in flight").unwrap();
    let path = input.path().to_path_buf();
    supervisor.kill_all();
    assert!(
        !path.exists(),
        "the reaper deletes inputs process::exit would leak"
    );
    // The run's own cleanup still tolerates the file being gone.
    drop(input);
    assert!(!lock(&supervisor.temp_inputs).contains(&path));
    // And no new input is staged once shut down.
    assert!(TempInput::write(&supervisor, b"late").is_err());
}

// ------------------------------------------------------------------
// In-run memo: byte-bounded, keyed by script
// ------------------------------------------------------------------

#[test]
fn memo_is_bounded_by_bytes_as_well_as_entries() {
    let mut memo = Memo::new();
    let empty = || Some(make_recovery("{}"));
    memo.insert([1; 32], empty(), MEMO_MAX_BYTES / 8);
    assert!(memo.get(&[1; 32]).is_some());
    // Too large to share the budget: not remembered, and nothing evicted.
    memo.insert([2; 32], empty(), MEMO_MAX_BYTES / 2);
    assert!(memo.get(&[2; 32]).is_none());
    assert!(memo.get(&[1; 32]).is_some());
    // Filling past the byte budget resets the map instead of growing it.
    for k in 3..20u8 {
        memo.insert([k; 32], empty(), MEMO_MAX_BYTES / 5);
        assert!(memo.bytes <= MEMO_MAX_BYTES, "{} bytes", memo.bytes);
    }
    // A memoized failure is remembered as such.
    memo.insert([99; 32], None, 0);
    assert_eq!(memo.get(&[99; 32]).map(Option::is_none), Some(true));
}

#[test]
fn memo_key_covers_bytes_script_and_budget() {
    let settings = Settings::default();
    let full = analysis_script(b"x", 0, false);
    let prelude = analysis_script(b"x", 5, false);
    assert_ne!(full, prelude);
    let key = memo_key(b"x", full, &settings);
    assert_eq!(key, memo_key(b"x", full, &settings));
    assert_ne!(key, memo_key(b"y", full, &settings));
    assert_ne!(key, memo_key(b"x", prelude, &settings));
    let slower = Settings {
        timeout: Duration::from_secs(1),
        ..settings
    };
    assert_ne!(key, memo_key(b"x", full, &slower));
    let retried = Settings {
        retry_timeout: Some(RIZIN_TIMEOUT * 2),
        ..settings
    };
    assert_ne!(key, memo_key(b"x", full, &retried));
}

/// The memo answers a repeat of the same bytes under the same script, and
/// runs again for a different script over the same bytes.
#[test]
#[cfg(unix)]
fn memo_replays_a_repeat_but_not_another_script() {
    let dir = unique_shim_dir("filefacts-rizin-memoshim");
    let runs = dir.join("runs");
    let dir = stage_script(
        dir,
        &format!(
            "echo run >> '{}'\nprintf '[]\\n===SEP===\\n[]\\n===SEP===\\n\\n===SEP===\\n[]\\n===SEP===\\n[]\\n'\n",
            runs.display()
        ),
    );
    let bin = dir.join("rizin");
    let supervisor = Supervisor::new();
    let settings = Settings::default();
    let full = analysis_script(b"x", 0, false);
    let prelude = analysis_script(b"x", 5, false);
    let count = || std::fs::read_to_string(&runs).map_or(0, |s| s.lines().count());
    assert!(supervisor.recover(&bin, b"x", full, &settings).is_some());
    assert!(supervisor.recover(&bin, b"x", full, &settings).is_some());
    assert_eq!(count(), 1, "the repeat was not answered from the memo");
    assert!(supervisor.recover(&bin, b"x", prelude, &settings).is_some());
    assert_eq!(count(), 2, "another script must not share the memo entry");
    assert_eq!(supervisor.stats().total, 2);
    assert_eq!(supervisor.stats().successes, 2);
    let _ = std::fs::remove_dir_all(dir);
}

/// After too many abandoned readers rizin stays off: no run starts.
#[test]
#[cfg(unix)]
fn disabled_supervisor_runs_nothing() {
    let dir = stage_script(
        unique_shim_dir("filefacts-rizin-disabledshim"),
        "echo should-not-run\n",
    );
    let supervisor = Supervisor::new();
    supervisor.disabled.store(true, Ordering::Release);
    let script = analysis_script(b"x", 0, false);
    let recovered = supervisor.recover(&dir.join("rizin"), b"x", script, &Settings::default());
    assert!(recovered.is_none());
    assert_eq!(supervisor.stats().total, 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(unix)]
fn outside_sigkill_is_transient_but_a_crash_is_decided() {
    let supervisor = Supervisor::new();
    let killed = stage_script(
        unique_shim_dir("filefacts-rizin-killedshim"),
        "kill -9 $$\n",
    );
    let attempt = shim_attempt(&supervisor, &killed, RIZIN_TIMEOUT);
    assert!(attempt.recovery.is_none());
    assert!(
        !attempt.deterministic,
        "a SIGKILL we did not send must not be memoized"
    );
    let crashed = stage_script(unique_shim_dir("filefacts-rizin-crashshim"), "exit 3\n");
    let attempt = shim_attempt(&supervisor, &crashed, RIZIN_TIMEOUT);
    assert!(attempt.recovery.is_none());
    assert!(attempt.deterministic, "a crash on these bytes is theirs");
    assert_eq!(supervisor.stats().failures, 2);
    let _ = std::fs::remove_dir_all(killed);
    let _ = std::fs::remove_dir_all(crashed);
}

// ------------------------------------------------------------------
// Shims, and the version probe
// ------------------------------------------------------------------

/// A fresh, process-unique scratch path for a shim.
pub(super) fn unique_shim_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Stage `body` as an executable `rizin` shell script in `dir`, which it
/// creates, and return `dir`.
#[cfg(unix)]
pub(super) fn stage_script(dir: PathBuf, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("rizin");
    std::fs::write(&shim, format!("#!/bin/sh\n{body}")).unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();
    dir
}

/// One recovery run of the `rizin` shim in `dir` over a fixed input.
#[cfg(unix)]
pub(super) fn shim_attempt(supervisor: &Supervisor, dir: &Path, timeout: Duration) -> Attempt {
    let bytes = b"shim input";
    let script = analysis_script(bytes, 0, false);
    supervisor.attempt(&dir.join("rizin"), bytes, script, timeout)
}

/// [`shim_attempt`] under the default budget, keeping only the recovery.
#[cfg(unix)]
fn shim_recover(dir: &Path) -> Option<RizinRecovery> {
    shim_attempt(&Supervisor::new(), dir, RIZIN_TIMEOUT).recovery
}

#[test]
#[cfg(unix)]
fn version_probe_is_bounded_by_its_deadline() {
    // Unbounded, the shim would print its banner after 300 s; bounded by a
    // one-second deadline it is killed first and reads as unknown.
    let dir = stage_script(
        unique_shim_dir("filefacts-rizin-hangshim"),
        "sleep 300\necho 'rizin 0.0.0 late'\n",
    );
    let supervisor = Supervisor::new();
    assert_eq!(
        supervisor.version_of(&dir.join("rizin"), Duration::from_secs(1)),
        None
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = stage_script(
        unique_shim_dir("filefacts-rizin-versionshim"),
        "echo 'rizin 9.9.9 @ test'\n",
    );
    assert_eq!(
        supervisor
            .version_of(&dir.join("rizin"), Duration::from_secs(3600))
            .as_deref(),
        Some("rizin 9.9.9 @ test")
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ------------------------------------------------------------------
// parse_recovery_output — block splitting + per-block error tolerance
// ------------------------------------------------------------------

/// A synthetic rizin stdout in the five-block shape every script produces.
fn synthesize_stdout(imports: &str, exports: &str, chatter: &str, functions: &str) -> String {
    format!(
        "{imports}\n===SEP===\n{exports}\n===SEP===\n{chatter}\n===SEP===\n{functions}\n===SEP===\n[]"
    )
}

#[test]
fn parse_recovery_output_splits_canonical_block_shape() {
    let stdout = synthesize_stdout(
        r#"[{"name":"open","libname":"libc.so"}]"#,
        r#"[{"name":"start","vaddr":4096}]"#,
        "[INFO] analysis ran",
        r#"[{"name":"main","offset":4096,"cc":3,"nbbs":5}]"#,
    );
    let (rec, complete) = parse_recovery_output(&stdout);
    assert!(complete);
    assert_eq!(rec.imports.len(), 1);
    assert_eq!(rec.imports[0].name, "open");
    assert_eq!(rec.exports.len(), 1);
    assert_eq!(rec.exports[0].vaddr, 4096);
    assert_eq!(rec.functions.len(), 1);
    assert_eq!(rec.functions[0].cc, Some(3));
}

#[test]
fn parse_recovery_output_tolerates_truncated_blocks() {
    // Only one separator present — the later blocks are missing. Yields
    // empty tables rather than panicking, and says it is incomplete.
    let stdout = "[]\n===SEP===\n[{\"name\":\"a\"}]";
    let (rec, complete) = parse_recovery_output(stdout);
    assert!(!complete);
    assert!(rec.imports.is_empty());
    assert_eq!(rec.exports.len(), 1);
    assert_eq!(rec.exports[0].name, "a");
    assert!(rec.functions.is_empty());
}

#[test]
fn parse_recovery_output_recovers_from_malformed_block() {
    // First block is unparseable JSON; we still get the rest, flagged.
    let stdout = synthesize_stdout(
        "this is not json",
        r#"[{"name":"x","vaddr":1}]"#,
        "",
        r#"[{"name":"y","offset":2}]"#,
    );
    let (rec, complete) = parse_recovery_output(&stdout);
    assert!(!complete, "a malformed table is not a complete recovery");
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
    let (rec, complete) = parse_recovery_output(&stdout);
    assert!(complete);
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
    parse_recovery_output(&stdout)
        .0
        .apply(&mut symbols, &mut metrics);
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
    let (rec, complete) = parse_recovery_output("");
    assert!(!complete);
    assert!(rec.imports.is_empty());
    assert!(rec.exports.is_empty());
    assert!(rec.functions.is_empty());
}

// ------------------------------------------------------------------
// End-to-end spawn/drain via a fake-rizin shim script
// ------------------------------------------------------------------

/// Execute a freshly staged shim once, unsupervised, so a timed run below
/// measures the recovery path and not the host's first-exec cost.
///
/// EndpointSecurity clients (macOS XProtect, and any third-party agent
/// installed alongside it) hold the *first* `exec` of a newly written file
/// while they scan it, then cache the verdict; the same shim runs in
/// milliseconds afterwards. That hold can be tens of seconds, longer than a
/// short budget below. Every shim used by a budgeted test exits immediately
/// when its first argument is `warmup`.
#[cfg(unix)]
pub(super) fn warm_shim_exec(shim: &Path) {
    let status = std::process::Command::new(shim)
        .arg("warmup")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("warm-up exec of the shim");
    assert!(status.success(), "shim warm-up exited with {status}");
}

/// Stage a `rizin` shim that prints `stdout_payload` verbatim, whatever its
/// arguments.
#[cfg(unix)]
fn stage_shim(stdout_payload: &str) -> PathBuf {
    // A quoted here-document delimiter disables expansion, so payloads with
    // backticks and dollars survive byte for byte.
    stage_script(
        unique_shim_dir("filefacts-rizin-shim"),
        &format!("cat <<'EOF'\n{stdout_payload}\nEOF\n"),
    )
}

/// Run the shim printing `stdout_payload` through the production recovery
/// path: temp input, contained spawn, drain, parse.
#[cfg(unix)]
fn run_against_shim(stdout_payload: &str) -> Option<RizinRecovery> {
    let dir = stage_shim(stdout_payload);
    let result = shim_recover(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[test]
#[cfg(unix)]
fn end_to_end_shim_returns_parsed_recovery() {
    // A canonical payload — exercises spawn, drain, separator split, and
    // per-block JSON parse together.
    let payload = synthesize_stdout(
        r#"[{"name":"malloc","libname":"libc.so.6"}]"#,
        r#"[{"name":"entry","vaddr":4096}]"#,
        "analysis-chatter-ignored",
        r#"[{"name":"f1","offset":4096,"cc":7,"nbbs":12}]"#,
    );
    let rec = run_against_shim(&payload).expect("shim should return a recovery");
    assert_eq!(rec.imports.len(), 1);
    assert_eq!(rec.imports[0].libname.as_deref(), Some("libc.so.6"));
    assert_eq!(rec.exports.len(), 1);
    assert_eq!(rec.functions.len(), 1);
    assert_eq!(rec.functions[0].cc, Some(7));
}

/// Well-formed output counts as a success; output with a malformed table
/// keeps what parsed but counts as a failure.
#[test]
#[cfg(unix)]
fn malformed_output_is_kept_but_counted_as_a_failure() {
    let supervisor = Supervisor::new();
    let good = stage_shim(&synthesize_stdout("[]", "[]", "", "[]"));
    assert!(
        shim_attempt(&supervisor, &good, RIZIN_TIMEOUT)
            .recovery
            .is_some()
    );
    assert_eq!(
        (supervisor.stats().successes, supervisor.stats().failures),
        (1, 0)
    );
    let bad = stage_shim(&synthesize_stdout(
        "not json",
        r#"[{"name":"start","vaddr":4096}]"#,
        "",
        "[]",
    ));
    let rec = shim_attempt(&supervisor, &bad, RIZIN_TIMEOUT)
        .recovery
        .expect("partial recovery kept");
    assert_eq!(rec.exports.len(), 1);
    assert_eq!(
        (supervisor.stats().successes, supervisor.stats().failures),
        (1, 1)
    );
    let _ = std::fs::remove_dir_all(good);
    let _ = std::fs::remove_dir_all(bad);
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
    let rec = run_against_shim(&payload).expect("shim recovery");
    assert_eq!(rec.functions.len(), 2000);
}

#[test]
#[cfg(unix)]
fn end_to_end_shim_returns_some_empty_recovery_on_separator_only_stdout() {
    // Empty tables are valid but contentless rizin output. The recovery is
    // `Some(empty)`; `apply` is then a no-op (functions empty → no metrics
    // emitted) and the parser's existing data survives untouched. This is
    // distinct from the "empty bytes → None" case below.
    let payload = synthesize_stdout("[]", "[]", "", "[]");
    let rec = run_against_shim(&payload).expect("empty arrays still parse");
    assert!(rec.imports.is_empty());
    assert!(rec.exports.is_empty());
    assert!(rec.functions.is_empty());
}

#[test]
#[cfg(unix)]
fn end_to_end_recover_returns_none_when_stdout_bytes_empty() {
    // A shim that exits 0 with zero stdout bytes, like rizin crashing before
    // its first echo.
    let dir = stage_script(unique_shim_dir("filefacts-rizin-silentshim"), "exit 0\n");
    let rec = shim_recover(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(rec.is_none(), "zero stdout bytes should yield None");
}

#[test]
#[cfg(unix)]
fn end_to_end_recover_returns_none_on_nonzero_exit() {
    // Shim exits non-zero (rizin crashed) — recover should not
    // return phantom data even if some partial stdout leaked.
    let dir = stage_script(
        unique_shim_dir("filefacts-rizin-failshim"),
        "echo 'partial output'\nexit 1\n",
    );
    let rec = shim_recover(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(rec.is_none(), "non-zero exit should yield None");
}

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
    // The first run sleeps for an hour, so its 100 ms budget always expires;
    // the retry's budget is generous enough for any loaded machine.
    let dir = stage_script(
        unique_shim_dir("filefacts-native-retry"),
        "[ \"$1\" = warmup ] && exit 0\nflag=\"${0}.first\"\nif [ ! -f \"$flag\" ]; then : > \"$flag\"; exec sleep 3600; fi\nprintf '[]\\n===SEP===\\n[]\\n===SEP===\\n\\n===SEP===\\n[]\\n===SEP===\\n[]\\n'\n",
    );
    warm_shim_exec(&dir.join("rizin"));
    let supervisor = Supervisor::new();
    let mut runs = 0;
    let result = attempt_with_retry(
        Duration::from_millis(100),
        Some(Duration::from_secs(600)),
        |timeout| {
            runs += 1;
            shim_attempt(&supervisor, &dir, timeout)
        },
    );
    assert_eq!(runs, 2);
    assert!(result.recovery.is_some());
    assert!(!result.timed_out);
    // A crash under a budget it cannot exceed is never retried.
    let crash = stage_script(unique_shim_dir("filefacts-native-retry-crash"), "exit 3\n");
    let mut runs = 0;
    let result = attempt_with_retry(
        Duration::from_secs(600),
        Some(Duration::from_mins(20)),
        |timeout| {
            runs += 1;
            shim_attempt(&supervisor, &crash, timeout)
        },
    );
    assert_eq!(runs, 1);
    assert!(result.recovery.is_none());
    assert!(!result.timed_out);
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(crash);
}
