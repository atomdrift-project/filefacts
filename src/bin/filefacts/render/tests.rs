use super::*;
use filefacts::OpenOptions;
use std::io::Write as _;

/// Hermetic open: no disk cache and no rizin, so `parse_count() == 1` holds
/// and the result does not depend on the host.
fn open<'a>(path: &Path, bytes: &'a [u8]) -> ParsedFile<'a> {
    OpenOptions::new()
        .cache(false)
        .rizin(false)
        .path(path)
        .open(bytes)
}

const COLOR: Style = Style {
    color: true,
    width: 100,
};

const PLAIN: Style = Style {
    color: false,
    width: 100,
};

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
fn terminal_bundle_shows_every_bundled_view() {
    let parsed = open(Path::new("example.py"), SOURCE);
    let text = format_terminal(COLOR, Path::new("example.py"), &parsed, None).unwrap();
    for view in View::ALL.into_iter().filter(|v| v.bundled()) {
        let label = COLOR.bold(heading_color(view), &view.name().to_uppercase());
        assert!(
            text.contains(&label),
            "{} missing from the terminal bundle",
            view.name()
        );
    }
    assert_eq!(parsed.parse_count(), 1);
}

/// With colour off nothing but the text is written: no escape sequence at
/// all, in any view.
#[test]
fn plain_style_writes_no_escape_sequences() {
    let parsed = open(Path::new("example.py"), SOURCE);
    let views = View::ALL.into_iter().map(Some);
    for view in std::iter::once(None).chain(views) {
        let text = format_terminal(PLAIN, Path::new("example.py"), &parsed, view).unwrap();
        assert!(!text.contains('\x1b'), "{view:?}: {text}");
    }
}

#[test]
fn width_comes_from_columns_clamped() {
    assert_eq!(Style::width_from(None), 100);
    assert_eq!(Style::width_from(Some("wide")), 100);
    assert_eq!(Style::width_from(Some("120")), 120);
    assert_eq!(Style::width_from(Some("10")), 60);
    assert_eq!(Style::width_from(Some("1000")), 200);
    let parsed = open(Path::new("example.py"), SOURCE);
    let narrow = Style {
        color: false,
        width: 60,
    };
    let text = format_terminal(narrow, Path::new("example.py"), &parsed, None).unwrap();
    assert!(text.contains(&format!("\n{}\n", "─".repeat(60))), "{text}");
}

#[test]
fn archive_members_render_one_escaped_line_each() {
    let mut bytes = Vec::new();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for name in ["a.txt", "evil\x1b[2J.txt"] {
        zip.start_file(name, stored).unwrap();
        zip.write_all(b"hello\n").unwrap();
    }
    zip.finish().unwrap();

    let parsed = open(Path::new("x.zip"), &bytes);
    let view = Some(View::ArchiveMembers);
    let text = format_terminal(COLOR, Path::new("x.zip"), &parsed, view).unwrap();
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
        let rendered = render_view(PLAIN, &parsed, view).unwrap();
        assert_eq!(rendered.count, Some(total), "{view:?}");
        let more = format!("... {} more", total - ARRAY_PREVIEW_LIMIT);
        assert!(rendered.body.contains(&more), "{view:?}: {}", rendered.body);
    }
    let ascii = parsed.text().ascii().count();
    assert!(ascii > STRING_PREVIEW_LIMIT, "{ascii}");
    let body = render_view(PLAIN, &parsed, View::Text).unwrap().body;
    assert!(body.contains(&format!("({ascii})")), "{body}");
    let more = format!("... {} more", ascii - STRING_PREVIEW_LIMIT);
    assert!(body.contains(&more), "{body}");
    // Every run shows its offset and its value.
    let first = parsed.text().ascii().next().unwrap();
    let row = format!(
        "0x{:08x} {}",
        first.data_offset,
        string_excerpt(&first.value, 80)
    );
    assert!(body.contains(&row), "{row} not in {body}");
}

#[test]
fn located_metric_renders_as_a_number() {
    let parsed = open(Path::new("example.py"), SOURCE);
    let located = parsed
        .metrics()
        .iter_facts()
        .find(|(_, f)| !f.spans.is_empty());
    assert!(located.is_some(), "fixture has no located metric");
    let text =
        format_terminal(COLOR, Path::new("example.py"), &parsed, Some(View::Metrics)).unwrap();
    assert!(!text.contains("spans"), "{text}");
}

#[test]
fn metrics_group_by_first_segment_and_format_by_suffix() {
    assert_eq!(metric_group("binary.overlay_size"), "binary");
    assert_eq!(metric_group("sections[3].entropy"), "sections");
    assert_eq!(metric_group("standalone"), "standalone");
    assert_eq!(metric_group("odd[1]"), "odd[1]");
    for (key, raw, shown) in [
        ("binary.overlay_size", 2048.0, "2.0 KiB"),
        ("file.size_bytes", 10.0, "10 B"),
        ("functions.count", 7.0, "7"),
        ("pe.import_count", 3.0, "3"),
        ("file.entropy", 7.25, "7.250"),
        ("x.entropy_variance", 0.5, "0.500"),
        ("x.text_ratio", 0.25, "0.250"),
        ("x.whole", 42.0, "42"),
        ("x.fraction", 1.5, "1.500"),
    ] {
        assert_eq!(format_metric_value(PLAIN, key, raw), shown, "{key}");
    }
}

/// Sections render from their typed fields: name, permissions, entropy, and
/// both extents; a section with no file bytes says so.
#[test]
fn sections_render_from_their_typed_fields() {
    let parsed = open(
        Path::new("test.elf"),
        include_bytes!("../../../../tests/fixtures/test.elf"),
    );
    let sections = parsed.sections();
    let text = render_sections(PLAIN, sections);
    for section in sections.iter().take(SECTIONS_PREVIEW_LIMIT) {
        assert!(
            text.contains(&format!("  {}  ", section.name)),
            "{}",
            section.name
        );
    }
    let text_section = sections
        .iter()
        .find(|s| s.name == ".text")
        .expect("fixture has .text");
    let block = text
        .split("\n\n")
        .find(|block| block.starts_with("  .text  "))
        .unwrap();
    let perms: String = [
        (SectionFlag::Readable, 'r'),
        (SectionFlag::Writable, 'w'),
        (SectionFlag::Executable, 'x'),
    ]
    .iter()
    .map(|&(flag, c)| if text_section.has_flag(flag) { c } else { '-' })
    .collect();
    assert!(block.contains(&format!("  {perms}")), "{block}");
    assert!(text_section.is_executable(), "{block}");
    assert!(block.contains(&format_hex(text_section.vaddr)), "{block}");
    assert!(
        block.contains(&format_hex(text_section.file_offset)),
        "{block}"
    );
    if let Some(entropy) = text_section.entropy {
        assert!(block.contains(&format!("entropy {entropy:.2}")), "{block}");
    }
    let bss = sections.iter().find(|s| s.file_size == 0);
    if let Some(bss) = bss {
        let block = text
            .split("\n\n")
            .find(|block| block.starts_with(&format!("  {}  ", bss.name)))
            .unwrap();
        assert!(block.contains("(no on-disk bytes)"), "{block}");
    }
}

/// Diagnostics render from their typed fields: kind, stage and message.
#[test]
fn errors_render_from_their_typed_fields() {
    let parsed = open(Path::new("broken.zip"), b"PK\x03\x04 not really a zip");
    let errors = parsed.errors();
    assert!(!errors.is_empty(), "fixture produced no diagnostic");
    let text = render_errors(PLAIN, errors);
    for diagnostic in errors.iter() {
        let row = format!(
            "  {} {}  {}",
            diagnostic.kind.as_str(),
            diagnostic.stage.as_str(),
            diagnostic.message
        );
        assert!(text.contains(&row), "{row} not in {text}");
    }
    let clean = open(Path::new("example.py"), SOURCE);
    assert_eq!(render_errors(PLAIN, clean.errors()), "  ✓ none\n");
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
        let views = View::ALL.into_iter().map(Some);
        for view in std::iter::once(None).chain(views) {
            let text = format_terminal(COLOR, Path::new(name), &parsed, view).unwrap();
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
        let bundle = format_terminal(COLOR, Path::new(name), &parsed, None).unwrap();
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
    let text = render_symbols(COLOR, &[&call]);
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
    let text = render_functions(COLOR, &[&function]);
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
    let text = render_imports(COLOR, &[&import, &export]);
    assert!(
        text.contains("kernel32.dll") && text.contains("#7"),
        "{text}"
    );
    assert!(!text.contains("Run"), "{text}");
    let text = render_exports(COLOR, &[&import, &export]);
    assert!(text.contains("NTDLL.RtlRun"), "{text}");
    assert!(!text.contains("CreateFileW"), "{text}");
}

/// Offsets right-align in one column, sized to the widest.
#[test]
fn offsets_align_to_the_widest() {
    let export = |name: &str, offset| Symbol::Export {
        name: name.into(),
        offset: Some(offset),
        ordinal: None,
        forward_to: None,
    };
    let (short, long) = (export("a", 0x10), export("b", 0x123456));
    let text = render_exports(PLAIN, &[&short, &long]);
    assert!(
        text.contains("\n      0x10  a\n") || text.starts_with("      0x10  a\n"),
        "{text:?}"
    );
    assert!(text.contains("  0x123456  b\n"), "{text:?}");
}
