//! Hostile-input regressions.
//!
//! Each case builds a known-bad input in memory, opens it, and touches every
//! view. To pass, the case must finish on a 2 MiB worker thread (the stack a
//! rayon worker gets) within a time budget and a peak-RSS cap.
//!
//! A stack overflow or an allocation failure aborts the process, which no
//! `catch_unwind` can stop. So every case runs in a child copy of this test
//! binary (re-invoked with [`CHILD_ENV`] set), while the parent enforces the
//! deadline and the memory cap and reports how the child died. One abort
//! then fails one test instead of taking the whole harness down with it.
//!
//! Run with `cargo test --release --test hostile_inputs`. The heavier cases
//! are ignored in debug builds, where unoptimised parsing makes their time
//! budgets meaningless.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::float_cmp,
    reason = "fixtures build binary layouts from literals and compare exact expected values"
)]

use std::hint::black_box;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use filefacts::{FileId, OpenOptions, ParsedFile};

/// Set in the child process: run the case body instead of supervising it.
const CHILD_ENV: &str = "FILEFACTS_HOSTILE_CHILD";

/// The stack a rayon worker thread gets by default.
const WORKER_STACK: usize = 2 << 20;

/// Peak resident set allowed for one case, in KiB, unless the case sets its own.
const DEFAULT_RSS_CAP_KIB: u64 = 1 << 20;

/// Wall-clock budget for a case, given in release-build seconds. Debug builds
/// get ten times as long.
fn budget(release_secs: u64) -> Duration {
    let scale = if cfg!(debug_assertions) { 10 } else { 1 };
    Duration::from_secs(release_secs * scale)
}

/// Run `case` in a child copy of this test binary, on a [`WORKER_STACK`]
/// thread, failing if it does not exit cleanly within `limit` and `rss_cap_kib`.
fn isolated(name: &str, limit: Duration, rss_cap_kib: u64, case: fn()) {
    if std::env::var_os(CHILD_ENV).is_some() {
        let worker = std::thread::Builder::new()
            .name(name.to_owned())
            .stack_size(WORKER_STACK)
            .spawn(case)
            .expect("spawn worker thread");
        if let Err(payload) = worker.join() {
            std::panic::resume_unwind(payload);
        }
        return;
    }

    let exe = std::env::current_exe().expect("test binary path");
    let mut child = Command::new(exe)
        .args([
            name,
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env("FILEFACTS_CACHE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child test process");
    let mut stderr = child.stderr.take().expect("child stderr");
    let drain = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stderr.read_to_end(&mut out);
        out
    });

    let start = Instant::now();
    let mut peak_kib = 0;
    let verdict = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break Ok(status);
        }
        if let Some(kib) = peak_rss_kib(child.id()) {
            peak_kib = peak_kib.max(kib);
            if kib > rss_cap_kib {
                break Err(format!(
                    "peak RSS {kib} KiB exceeded the {rss_cap_kib} KiB cap"
                ));
            }
        }
        if start.elapsed() > limit {
            break Err(format!("still running after {limit:?}"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let elapsed = start.elapsed();
    if verdict.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stderr = drain.join().unwrap_or_default();
    let stderr = tail(&stderr);
    match verdict {
        Ok(status) if status.success() => {
            eprintln!("{name}: ok in {elapsed:.2?}, peak RSS {peak_kib} KiB");
        }
        Ok(status) => panic!(
            "{name}: child exited with {status} after {elapsed:.2?} (peak RSS {peak_kib} KiB)\n{stderr}"
        ),
        Err(why) => panic!("{name}: {why}\n{stderr}"),
    }
}

/// The child's peak resident set so far (`VmHWM`), where the OS exposes it.
#[cfg(target_os = "linux")]
fn peak_rss_kib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn peak_rss_kib(_pid: u32) -> Option<u64> {
    None
}

/// The last few lines of the child's stderr, for the failure message.
fn tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let skip = text.lines().count().saturating_sub(12);
    text.lines().skip(skip).collect::<Vec<_>>().join("\n")
}

/// Declares one hostile case as its own `#[test]`, run under [`isolated`].
macro_rules! hostile {
    (
        $(#[$attr:meta])*
        fn $name:ident(secs = $secs:expr $(, rss_kib = $rss:expr)?) $body:block
    ) => {
        $(#[$attr])*
        #[test]
        fn $name() {
            fn case() $body
            #[allow(unused_mut, unused_assignments)]
            let mut rss = DEFAULT_RSS_CAP_KIB;
            $(rss = $rss;)?
            isolated(stringify!($name), budget($secs), rss, case);
        }
    };
}

/// Options for a hermetic open: no disk cache and no rizin subprocess.
fn options() -> OpenOptions<'static> {
    OpenOptions::new().cache(false).rizin(false)
}

fn open_named<'a>(name: &str, bytes: &'a [u8]) -> ParsedFile<'a> {
    options().path(Path::new(name)).open(bytes)
}

/// Touch every view so each lazy extraction stage runs, the flow graph and
/// the source AST included.
fn touch_all(parsed: &ParsedFile<'_>) {
    black_box(parsed.fileid().file_type());
    black_box(parsed.values());
    black_box(parsed.text().len());
    black_box(parsed.literals());
    black_box(parsed.comments());
    black_box(parsed.metrics().len());
    black_box(parsed.archive_members().len());
    black_box(parsed.source_ast().is_some());
    black_box(parsed.sections());
    black_box(parsed.symbols());
    black_box(parsed.flow());
    black_box(parsed.identity());
    black_box(parsed.references().len());
    black_box(parsed.errors());
    black_box(parsed.embedded_sources().count());
    black_box(parsed.symbol_iter().count());
}

// ---------------------------------------------------------------------------
// Identification
// ---------------------------------------------------------------------------

hostile! {
    /// A long run of `(` once recursed once per byte in the batch-file
    /// line grader.
    fn paren_run_in_identification(secs = 5) {
        let mut bytes = vec![b'('; 16_000];
        bytes.extend_from_slice(b"x\n");
        black_box(FileId::from_bytes(&bytes));
        touch_all(&options().open(&bytes));
    }
}

// ---------------------------------------------------------------------------
// Structured data and source
// ---------------------------------------------------------------------------

hostile! {
    /// 20k nested `<array>` elements in an XML plist.
    fn deep_xml_plist(secs = 5) {
        let depth = 20_000;
        let mut doc = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">",
        );
        doc.push_str(&"<array>".repeat(depth));
        doc.push_str(&"</array>".repeat(depth));
        doc.push_str("</plist>\n");
        touch_all(&open_named("deep.plist", doc.as_bytes()));
    }
}

hostile! {
    /// A C parameter declarator nested 60k pointers deep, run through flow.
    fn deep_c_declarator_flow(secs = 5) {
        let src = format!("void f(int {}p){{}}\n", "*".repeat(60_000));
        touch_all(&open_named("deep_param.c", src.as_bytes()));
    }
}

hostile! {
    /// 15k functions over 20k module globals: flow once cloned every global
    /// into every function's scope.
    #[cfg_attr(debug_assertions, ignore = "release-only: run with --release")]
    fn python_many_globals_flow(secs = 3) {
        let mut src = String::new();
        for i in 0..20_000 {
            src.push_str(&format!("g{i} = {i}\n"));
        }
        for f in 0..15_000 {
            src.push_str(&format!("def f{f}(a):\n    return a + g{f}\n"));
        }
        touch_all(&open_named("globals.py", src.as_bytes()));
    }
}

// ---------------------------------------------------------------------------
// Archives and documents
// ---------------------------------------------------------------------------

hostile! {
    /// Rock Ridge continuation areas full of `CE` records that point back at
    /// their own area.
    fn iso_rock_ridge_ce_loop(secs = 5) {
        touch_all(&open_named("ce.iso", &iso_with_ce_loop(20)));
    }
}

hostile! {
    /// One JavaScript action naming the same 1 MiB deflated stream 400 times.
    /// Inflating it once per reference costs about 1 MiB of RSS per reference.
    fn pdf_repeated_js_refs(secs = 10, rss_kib = 256 << 10) {
        touch_all(&open_named("js.pdf", &pdf_with_js_refs(400)));
    }
}

hostile! {
    /// 100k distinct unknown chunk types, deduplicated with a linear scan.
    #[cfg_attr(debug_assertions, ignore = "release-only: run with --release")]
    fn png_distinct_unknown_chunks(secs = 3) {
        touch_all(&open_named("chunks.png", &png_with_chunks(100_000)));
    }
}

hostile! {
    /// A .docx with 2,000 ~840 KB XML parts and no overall scan budget.
    #[cfg_attr(debug_assertions, ignore = "release-only: run with --release")]
    fn docx_many_xml_parts(secs = 10) {
        touch_all(&open_named("parts.docx", &docx_with_parts(2_000)));
    }
}

hostile! {
    /// One corrupted local file header must not hide the central directory.
    fn zip_corrupt_local_header_keeps_members(secs = 5) {
        let bytes = zip_with_bad_local_header();
        let parsed = open_named("badlfh.zip", &bytes);
        touch_all(&parsed);
        let members = parsed.archive_members().len();
        assert_eq!(members, 3, "central directory lists 3 members, extracted {members}");
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// An ISO 9660 image whose single file carries a Rock Ridge `CE` pointing at
/// block 19, and block 19 holds `ce_per_area` `CE` records that each point
/// back at block 19.
fn iso_with_ce_loop(ce_per_area: usize) -> Vec<u8> {
    const SECTOR: usize = 2048;
    fn both32(v: u32) -> Vec<u8> {
        [v.to_le_bytes(), v.to_be_bytes()].concat()
    }
    fn both16(v: u16) -> Vec<u8> {
        [v.to_le_bytes(), v.to_be_bytes()].concat()
    }
    fn dirrec(name: &[u8], lba: u32, size: u32, flags: u8, su: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        body.extend(both32(lba));
        body.extend(both32(size));
        body.extend([0; 7]);
        body.extend([flags, 0, 0]);
        body.extend(both16(1));
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        if name.len().is_multiple_of(2) {
            body.push(0);
        }
        body.extend_from_slice(su);
        let mut rec = vec![(body.len() + 1) as u8];
        rec.extend(body);
        rec
    }
    fn ce(block: u32, off: u32, len: u32) -> Vec<u8> {
        let data = [both32(block), both32(off), both32(len)].concat();
        let mut rec = vec![b'C', b'E', (4 + data.len()) as u8, 1];
        rec.extend(data);
        rec
    }
    fn put(img: &mut [u8], at: usize, data: &[u8]) {
        img.get_mut(at..at + data.len())
            .expect("write inside the image")
            .copy_from_slice(data);
    }

    let mut img = vec![0u8; SECTOR * 24];
    let pvd = 16 * SECTOR;
    put(&mut img, pvd, &[1]);
    put(&mut img, pvd + 1, b"CD001");
    put(&mut img, pvd + 6, &[1]);
    put(&mut img, pvd + 80, &both32(24));
    put(&mut img, pvd + 120, &both16(1));
    put(&mut img, pvd + 124, &both16(1));
    put(&mut img, pvd + 128, &both16(SECTOR as u16));
    put(
        &mut img,
        pvd + 156,
        &dirrec(b"\0", 18, SECTOR as u32, 2, &[]),
    );
    let term = 17 * SECTOR;
    put(&mut img, term, &[255]);
    put(&mut img, term + 1, b"CD001");
    put(&mut img, term + 6, &[1]);

    let mut su = b"RR\x05\x01\x81".to_vec();
    su.extend(ce(19, 0, SECTOR as u32));
    let root = [
        dirrec(b"\0", 18, SECTOR as u32, 2, &[]),
        dirrec(b"\x01", 18, SECTOR as u32, 2, &[]),
        dirrec(b"A;1", 20, 1, 0, &su),
    ]
    .concat();
    put(&mut img, 18 * SECTOR, &root);

    let area: Vec<u8> = (0..ce_per_area)
        .flat_map(|_| ce(19, 0, SECTOR as u32))
        .collect();
    assert!(area.len() <= SECTOR, "CE records overflow one sector");
    put(&mut img, 19 * SECTOR, &area);
    img
}

/// A PDF whose OpenAction is one JavaScript dictionary repeating `/JS 2 0 R`
/// `refs` times, where object 2 is a 1 MiB FlateDecode stream.
fn pdf_with_js_refs(refs: usize) -> Vec<u8> {
    let mut script = b"app.alert(1);".to_vec();
    script.resize((1 << 20) - 20, b' ');
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&script).unwrap();
    let js = z.finish().unwrap();

    let mut stream =
        format!("<< /Length {} /Filter /FlateDecode >>\nstream\n", js.len()).into_bytes();
    stream.extend_from_slice(&js);
    stream.extend_from_slice(b"\nendstream");
    let objs: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 3 0 R /OpenAction 4 0 R >>".to_vec(),
        stream,
        b"<< /Type /Pages /Kids [] /Count 0 >>".to_vec(),
        format!("<< /S /JavaScript {}>>", "/JS 2 0 R ".repeat(refs)).into_bytes(),
    ];

    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, obj) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(obj);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A 1x1 greyscale PNG carrying `n` empty ancillary chunks, each with a
/// distinct lowercase type.
fn png_with_chunks(n: usize) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
        let mut crc = crc32fast::Hasher::new();
        crc.update(&kind);
        crc.update(data);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&kind);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc.finalize().to_be_bytes());
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    chunk(&mut out, *b"IHDR", &ihdr);
    for i in 0..n {
        let letter = |div: usize| b'a' + ((i / div) % 26) as u8;
        chunk(
            &mut out,
            [letter(1), letter(26), letter(676), letter(17_576)],
            &[],
        );
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&[0, 0]).unwrap();
    chunk(&mut out, *b"IDAT", &z.finish().unwrap());
    chunk(&mut out, *b"IEND", &[]);
    out
}

/// A minimal .docx plus `parts` copies of one ~840 KB XML part. The part is
/// deflated once and raw-copied, so building the input stays cheap.
fn docx_with_parts(parts: usize) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let deflated =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut body = String::from("<?xml version=\"1.0\"?><r>");
    body.push_str(&"<a b=\"c\">x</a>".repeat(60_000));
    body.push_str("</r>");
    let mut template = zip::ZipWriter::new(Cursor::new(Vec::new()));
    template.start_file("part.xml", deflated).unwrap();
    template.write_all(body.as_bytes()).unwrap();
    let template = template.finish().unwrap().into_inner();
    let mut template = zip::ZipArchive::new(Cursor::new(template)).unwrap();

    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let fixed = [
        (
            "[Content_Types].xml",
            "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
             <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
             <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>",
        ),
        (
            "_rels/.rels",
            "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
             <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>",
        ),
        (
            "word/document.xml",
            "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body/></w:document>",
        ),
    ];
    for (name, text) in fixed {
        zip.start_file(name, deflated).unwrap();
        zip.write_all(text.as_bytes()).unwrap();
    }
    for i in 0..parts {
        let part = template.by_index(0).unwrap();
        zip.raw_copy_file_rename(part, format!("word/p{i}.xml"))
            .unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// Three stored members; the second member's local header magic is broken.
/// The central directory is intact.
fn zip_with_bad_local_header() -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let stored = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in [
        ("AndroidManifest.xml", b"xxxxxxxxxx".to_vec()),
        (
            "classes.dex",
            [b"dex\n035\0".as_slice(), &[b'y'; 100]].concat(),
        ),
        ("b.txt", b"hello".to_vec()),
    ] {
        zip.start_file(name, stored).unwrap();
        zip.write_all(&data).unwrap();
    }
    let mut bytes = zip.finish().unwrap().into_inner();
    let second = bytes
        .windows(4)
        .enumerate()
        .skip(1)
        .find(|(_, w)| *w == b"PK\x03\x04")
        .map(|(at, _)| at)
        .expect("second local header");
    bytes
        .get_mut(second..second + 2)
        .expect("local header magic")
        .copy_from_slice(b"XX");
    bytes
}
