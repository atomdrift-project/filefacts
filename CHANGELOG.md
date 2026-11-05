# Changelog

All notable changes to filefacts. Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).
The output schema is versioned separately by `filefacts::SCHEMA_VERSION`; a bump is noted with its new value.

## 3.0.0-beta.1 (unreleased)

### Security

- Escape DEL, C1 and bidi characters in JSON output, blocking terminal-escape injection from analyzed files.
- Stop JSON, YAML, TOML and plist documents from overwriting `file.basename` and other filefacts-owned keys.
- Stop reporting CAB signatures as verified without binding them to the cabinet.
- Stop reporting header-only PE signatures as verified without checking the digest.
- Require the codeSigning EKU before granting platform or Developer ID trust.
- Ignore commented-out execution levels that could hide a manifest's real `requestedExecutionLevel`.

### Features

- Recover PE, ELF and Mach-O functions in-process with binform on every binary lacking a function inventory.
- Extract direct syscalls on 32-bit Arm and x86 too, resolving numbers and arguments built across blocks.
- Decode sockaddr arguments to connect and bind, reporting each destination in `elf.network_endpoints`.
- Bind each chained-fixup Mach-O import to its library, and name ELF import libraries from symbol versions.
- Name PE ordinal imports from msi, comctl32, mfc42 and other DLLs' own export tables.
- Probe PNG pixel data for hidden scripts and binaries packed into bit planes, XOR, Base64 or zlib.
- Identify trailing media content and PNG IEND residue separately from headers embedded in metadata.
- Recover supported PyArmor layouts statically, without executing Python or the native runtime.
- Recover RC4-encrypted DEX and ZIP containers, accepting only output that passes full integrity checks.
- Read Ren'Py RPA archives and rpyc scripts without constructing Python objects.
- Analyze JavaScript embedded in HTML and PHP embedded in other markup.
- Identify Commodore, ProDOS, DOS, VHD, DEX, MSBuild, Maven POM and Go module files.
- Identify source package archives by their root manifests.
- Decode PDF object streams with no filter, ASCIIHex, ASCII85 or chained filters.
- Read DWARF from big-endian ELF and compressed debug sections.
- Report signer count, key size, weak keys, weak algorithms and extended key usage for signatures.
- Detect shell FIFO network loops and measure batch variable cycles.
- Place every file type in one of 19 groups through `filefacts::Group`.
- Expose the CLI's versioned JSON document to library users through `ParsedFile::bundle`.
- Breaking: stop running rizin; its module, options, environment variable and CLI flags are gone.
- Breaking: bump `SCHEMA_VERSION` to 11, renaming people, hash, summary and archive-member keys.
- Breaking: report PE delay-load import offsets as RVAs, as every other PE import does.
- Breaking: make `OpenOptions::new` read no environment, so the cache stays off unless enabled.
- Breaking: drop `pe.signature_expired_days`, which went stale in cached facts; use not_after_unix instead.
- Breaking: remove public cache internals, metric and value key types, and the CLI's pretty flag.

### Fixes

- Compute PE imphash for ordinal imports as pefile and VirusTotal do.
- Type a file as go.mod only when every line is a go.mod directive, so Ruby modules get analyzed.
- Read ELF and Mach-O files goblin rejects, plus ELF and ordinal-only PE exports it dropped.
- Resolve long PE section names through the COFF string table.
- Align .NET managed resource offsets to eight bytes, so later resource streams are no longer hidden.
- Count PDF `/Type` dictionaries by PDF name rules, not byte tokens anywhere in the file.
- Report a lone PDF signature object as one, not zero.
- Read Go build info only where Go's own reader looks for it.
- Describe fat Mach-O binaries by their x86-64 or arm64 slice, so iOS binaries yield functions.
- Read plaintext APK entries whose ZIP encryption bit was set by a protector.
- Validate CAB and gzip carrier headers, cutting false stowaway findings in PNG metadata.
- Keep Rust ctor and Go generate facts on files over 2 MiB.
- Route two tree-sitter parses through the parse budget and abort guard.
- Bound Rust attribute and ISO namespace walks, OLE2 stream reads and the zstd window.

### Optimizations

- Read each binary, or each universal slice, once and share it across views, functions and stng.
- Check a signed phar's digest during extraction instead of hashing the whole file on identification.
- Stop decoding 4 MiB of UTF-16 on every identification.
- Drop the sevenz-rust and xz2 dependencies, parsing 7z headers in-house with one LZMA implementation.

## 2.0.1 (2026-10-10)

### Fixes

- Read Mach-O code-signature blobs only from xnu-honoured slots, ignoring decoy entitlements.
- Fail Authenticode signatures lacking an image digest, so grafted catalog signatures fail.
- Take Authenticode timestamps from the signed TSTInfo, not a forgeable byte search.
- Check nested PE signatures, and mark unrecomputable digests unverifiable, not intact.
- Correct PE `IMAGE_GUARD_*` masks for delay-load IAT and export-suppression flags.
- Use the last CRX3 header fields, as Chrome does, so decoys can't spoof extension IDs.
- Refuse cache roots that are relative, symlinked or writable by other users.
- Run rizin with an allowlisted environment, and parse its output separators strictly.
- Catch panics in metrics, identity and reference derivation instead of aborting.
- Escape control characters in CLI argument errors.
- Pickle: model the stack and memo, fix `LONG_BINGET` length, cap operand amplification.
- Budget ZIP open reads and PyTorch version reads, refusing EOCD floods and bombs.
- Cap ELF name copies, verneed/verdef walks, DWARF attributes and overlapping note walks.
- Clamp Mach-O `nsyms`, skip overlapping fat slices, and cap load-command record counts.
- Keep goblin away from PE import/export tables over 32 MiB, and cap TLS and delay-import counts.
- Limit Authenticode chain walks to 32 candidate issuers.
- Add overflow checks to CAB, CLR, APK, Authenticode, VBA and code-signature parsing.
- Cap member listings and path sizes in ISO, UDF, ASAR, RAR, 7z and CHM.
- Cap APK signature blocks, JAR `pom.properties` reads and AXML/Java string copies.
- Bound DMG reconstruction, font scanning, NIB archives and JPEG pixel decoding.
- Cap OOXML `.rels`, PDF action sites, YAML alias replay and VBA decompression.
- Read each repeated RPM header tag once, and cap Go buildinfo dependency records.
- Count reference-evidence misses against the budget, fixing slow huge `package-lock.json` scans.

### Features

- Verify CRX2 and CRX3 developer signatures, reported as `crx.signature_verified`.
- Report Authenticode `unsigned_trailing_bytes` for CVE-2013-3900-style padding.
- Add a `module_level` flag to value-flow values evaluated at load time.
- Identify Sphinx `.doctree` files as Pickle.
- Add public `tools::scrub_env` to restrict spawned tools' environments.
- Minimum Rust version raised from 1.94 to 1.97.

### Optimizations

- Resolve AST call chains once and layer flow scopes, removing quadratic slowdowns.
- Reuse PDF `endobj`/`endstream` search positions instead of rescanning to EOF per object.
- Index ELF section-in-segment checks, and parse each DWARF abbreviation table once.
- Pre-index PE API-hash call edges, so a million edges now finish.
- Replace linear dedup scans with hash sets in tar, ISO, OOXML, PKGBUILD and JS.
- Serialize only the displayed rows in CLI text views, cutting memory on large files.

## 2.0.0 (2026-10-09)

### Breaking Changes

- `open()` is now infallible; `OpenOptions` replaces `open_with_path`, `open_as` and `with_cancellation`.
- Global cache and rizin settings are replaced by per-file `OpenOptions` settings.
- Schema v9 renames 75 value and metric keys, such as `pe.imphash` → `pe.hashes.imphash`.
- `ParseError`/`ErrorKind` become `Diagnostic`/`DiagnosticKind`; `ExtractedString` becomes `Literal` with typed enums.
- Literal JSON uses `value` instead of `text` and drops `kind`, `section`, `vaddr` and `paddr`.
- Default features now include `cli` and `jemalloc`; library users should set `default-features = false`.

### Features

- New archive formats: RAR, 7z, CAB, cpio and PHP phar.
- New formats: AppleScript, nib/xib/bplist, ANI cursors, systemd units, Desktop Entry, deb822, Image4 and TorchScript.
- New language detection: YARA, JSP, ASP, CFML, TeX, PostScript, DOS COM, mIRC/ircII and Ammonite.
- Detects shellcode and decodes single-byte and repeating-key XOR PE payloads, including their symbols.
- Validates Authenticode and Mach-O signatures against embedded Microsoft and Apple root certificates.
- New `comments` and `references` CLI views; `archive_members` is now a typed member index.
- RTF objdata is now decoded, exposing OLE class names and new objdata metrics.
- Reads Mach-O imports from chained fixups and extracts text from compressed Flash (CWS) files.
- New metrics for Terraform registry lookalikes, PDF upload directories and encrypted 7z entries.

### Fixes

- `office.vba.modules[]` is now populated; it was empty for every document.
- Overlay metrics no longer count Mach-O `__LINKEDIT`, ELF section headers or fat-binary slices.
- APKs are identified by their manifest, and Office extensions no longer force OOXML parsing.
- Binaries are no longer misidentified as scripts because of chance token matches.
- Fixed Mach-O bind/export panics found by fuzzing and a tree-sitter ambiguous-parse bug.
- Improved detection of PHP, HTA, Markdown, PowerShell, Lua, shell droppers and appx/msix.
- ISO appended-payload detection now accounts for partition tables.

### Optimizations

- Upgraded to tree-sitter 0.28 with a tighter source-parse work budget.
- Go pclntab recovery uses rizin's fastest analysis mode (`aalg`).
- Identification relies on magic bytes over file extensions, and Mach-O imports/exports load lazily.
- The disk cache now writes atomically and runs a background sweep with age, count and size limits.

## 1.7.0 (2026-09-14)

### Features

- Shared `media.*` carrier facts: container, validity, stowaway classification, trailing/gap bytes, and entropy.
- Structure walkers and file types for RIFF (WAV/WebP/AVI), AIFF, ICO/CUR, GIF, BMP, MP3, MP4.
- Font extractor (`font.*`) for masquerades and table-gap stowaways.
- New Flow graph with Rust and Go producers, plus bounded payload provenance.
- `go_dependency_context`, `go_source_context` and `package_context::cargo_source_context` reconcile declarations, replacements, and checksums.
- ELF anomaly metrics from the Trusting-Trust binary-manipulation paper: entry redirection, uncovered notes and build-id, section overlap/past-EOF, full `elf.sections[]`.
- x86-64 direct-syscall site extraction with resolved numbers, constant arguments and file offsets.
- PNG recognizes C2PA caBX credentials as claimed metadata, still scanned for payloads.
- `has_named_reference_metadata` and hermetic `open_with_path`.

### Fixes

- Go PE binaries that fold `.gopclntab` into `.rdata` are detected via build-info, and rizin runs full `aaa` for Go so pclntab names survive.
- Rizin's recovery memo keys on the Go script, so Go and generic PE paths can't share an entry.
- Fonts, audio and video are distinct file-id groups.

### Optimizations

- Cache item ceiling raised to 16,384, matching stng and fletch.

## 1.6.0 (2026-09-10)

### Features

- New Xcode `.pbxproj` format parser, with pbxproj/CMake files recognized by extension and magic and usable as reference sources.
- Recognition of YAML documents, SquashFS images (hsqs/sqsh), Snap packages, Flatpak bundles, and OpenPGP signatures.

### Fixes

- npm lockfile alias keys (`alias@npm:real@^1`) now resolve to the aliased-to package instead of querying the registry for a name.
- Timing tests pre-execute staged shims so macOS EndpointSecurity's first-exec scan no longer breaks timing assertions.

## 1.5.0 (2026-09-08)

### Features

- New markdown extractor lifts README identity claims.
- New `pe_signature_trust` module splits an aged signature from a wrong one via `digest_matches` and `signed_within_validity`.
- npm manifests now emit cross-field judgements: `consistency.name_repo_mismatch`, `consistency.publisher_repo_owner_mismatch`.
- BIFF worksheet inventory (`office.sheet_count`, `office.xlm_sheet_count`, `office.hidden_sheet_count`) surfaces Excel 4.0 macro sheets.
- Source string literals and call arguments are now escape-decoded.
- `binding.gyp` parsing falls back to a tolerant Python-literal parse (`gyp.parse_lenient=1`).
- Malformed PE import directories are now detected and reported rather than silently walked.
- PE version-info consistency checks and `.lnk` location anchors.
- New `known_metrics()` API enumerates every metric key a build can emit.
- New `open_with_fileid()` lets a caller that already computed a `FileId` skip the second detection pass.

### Fixes

- Fixed a deadlock where a rizin subprocess wait could park an analysis-pool worker forever without reaping the child or firing its timeout.
- Fixed an off-by-one in ISO parsing.
- Fixed null-offset imports in PE, Java class, and WASM.
- Preserved `posix_spawn` for rizin subprocesses on FreeBSD.

### Optimizations

- PDF parsing no longer scans to end-of-file looking for a stream that isn't there.
- Rizin runs `aa; aac` instead of `aaa` on x86 PE images.
- Detection skips a redundant second byte-scan on single-stream containers.

## 1.4.0 (2026-08-25)

### Features

- Added full ISO 9660/UDF parsing and archive-member extraction.
- Added ELF syscall-site extraction for x86-64 and AArch64.
- Expanded PE native resolver, API-hash, and anomaly analysis.
- Added source/package identity extraction and richer npm/GitHub Actions references.

### Bugfixes

- Improved format heuristics for ambiguous and extensionless files.
- Hardened rizin subprocess cleanup and timeout handling.
- Corrected Mach-O symbol normalization and extraction-cache partitioning.

### Optimizations

- Added weighted code-entropy analysis and bounded source parsing.
- Improved cache reuse and tool-path resolution.

## 1.3.0 (2026-07-25)

### Detection & parsing

- PE .NET/CLR metadata (`pe.clr.*`): managed-binary detection independent of Authenticode — strong-name signing, module MVID, runtime/metadata versions, IL-only bits, and metadata stream inventory.
- Static libraries (`.a`) now identified as a distinct file type, disambiguated from `.deb` (both use the `!<arch>` magic).
- CRX signed-but-unverified detection fixed: the canonical extension ID is now read from the CRX3 signed header, correctly handling Web Store packages that carry a publisher proof before the developer proof (previously derived the wrong ID).
- Dependency extraction for `.gem` (runtime deps → `pkg:gem` PURLs) and VSIX (`<Dependency>` → `pkg:vscode` PURLs).

### Reliability

- Fixed panic parsing batch (`.bat`) comments when a line begins with a multibyte char (e.g. CJK) — a `rem` check byte-sliced mid-character. (Crashed the matrixone scan.)
- Auto-clearing cache: 30-day TTL + 2 GiB ceiling, non-blocking; also sweeps stng's on-disk string cache, which nothing else prunes in a filefacts/cleave process. Fixed an eviction-target overflow on very large `max_items`.

### Project

- Moved to GitHub (atomdrift-project/filefacts); stng dependency re-pinned. Dependency updates.

## 1.2.0 (2026-07-06)

### Features

- New formats: WebAssembly, OCI container images, Python sdist, Android DEX; better npm/gem/oci/xbps/gpkg detection.
- Recognizes SVG, Cypher/CQL, and Python template files.
- Windowed entropy metrics surface a concealed high-entropy region (peak + offset) even when overall entropy is low.
- Facts now carry byte-range spans pinpointing each measurement's evidence.
- Registry metadata gains a `security_hold` flag and `version_removed` metric.

### Performance

- Skips the XOR seed search on source/script files with no sign of XOR logic.
- Deduplicates stng strings; cache self-cleans (prunes to 90% of capacity instead of a 30-day TTL).

## 1.1.1 (2026-06-20)

- Hermetic open for cache-less testing.
- Add missing DMG support file.

## 1.1.0 (2026-06-20)

- Added external reference extraction: PURLs, URLs, evidence, offsets, hashes.
- Added package/lockfile parsing for npm, PyPI, Cargo, Go, Ruby, Composer, Arch.
- Added new file types: lockfiles, `go.mod`, `go.sum`, `.SRCINFO`, DMG.
- Added package metadata and reference output views.
- Added source call-target metrics, including obfuscated command targets.
- Improved JS/PHP/protobuf/package/DMG identification.
- Improved Go buildinfo, Mach-O slicing, and rizin symbol offsets.
- Added pre-commit hook support.

## 1.0.1 (2026-06-14)

- Program Identity extraction — pulls publisher/package metadata from CRX, npm, nupkg, Rust crate, wheel, and xpi archives.
- JCL (z/OS Job Control Language) detection; PKGBUILD classified as shell.
- Panic-safe binary parsing — goblin wrapped to fail soft on malformed PE/Mach-O/ELF instead of aborting.
- Binary fixes — corrected Mach-O FAT and PE offsets; richer PE version/debug info.
- Scanning rework — consolidated string scanning, improved wide-char handling.
- Dependency updates and cleanup.

## 1.0.0 (2026-06-12)

### New Signals

- Added richer package ecosystem identification: Android/Alpine APK, npm, Cargo crate, Ruby gem, Debian package, NuGet, VSIX, IPA, conda, egg, Arch/FreeBSD/macOS pkg.
- Added `.deb` identity features: package, version, architecture, maintainer, dependencies, installed size.
- Added `.gem` identity features: name, version, platform, homepage, authors, licenses, runtime/development dependency counts.
- Added more PE malware-relevant metrics, such as CLR managed resource count, max entropy, max size.

### Better Evidence Anchoring

- ELF dynamic imports now include offsets into `.dynstr`.
- Mach-O dylib references and code signatures now include offsets.
- Source member symbols now include byte offsets.

### Detection Quality

- Improved package disambiguation, especially Android vs Alpine `.apk`, npm `.tgz`, Arch/FreeBSD/macOS `.pkg`.
- Better AppleScript and pacman/AUR install-scriptlet detection.
- Reduced false positives by classifying unsupported OCaml, Vim, Lisp, SQL, Smali, patches/diffs, CSS-like files, and TS baselines as text instead of weakly guessing JS/Kotlin/Batch.

### Robustness For Large Corpora

- Hardened Tree-sitter extraction against panics, deep ASTs, huge query output, and scanner-risk cases.
- Added metrics such as `ast.depth_capped`, `source.query_limited.*`, and `source.ast_unavailable` so skipped/truncated AST extraction is explicit.
- Binary string extraction reuses existing PE/ELF/Mach-O parses, reducing duplicate parsing work.

### Breaking/Schema Notes

- `FileType::Pkg` became specific variants like `PkgMacos`, `PkgFreebsd`, and `PkgArch`.
- `Symbol::Member` now has optional `offset`.
- New source error stages: `SourceParse`, `SourceExtract`, `SourceAstWalk`.
- `pe.cert_table_size` moved from values to metrics.

## 0.9.5 (2026-06-09)

### Features

- Added Debian package metadata: package, version, architecture, maintainer, dependencies, and installed size.
- Added RubyGems metadata: name, version, platform, authors, licenses, homepage, and runtime deps.
- Split package ecosystems into distinct types, including Android/Alpine APK, npm, crate, conda, NuGet, IPA, VSIX, FreeBSD pkg, and Arch pkg.
- Added PE/.NET signals for managed resource entropy/size, suspicious VERSIONINFO identity text, `.reloc` overhang, and certificate table size.
- Improved AppleScript detection for plaintext macOS stealer scripts with random or unknown extensions.

### Performance

- Reuses parsed PE/ELF/Mach-O objects for string extraction instead of parsing binaries twice.
- Skips duplicate stng symbol/import extraction because filefacts already walks symbols itself.

### Bugfixes

- Hardened AST analysis against deeply nested source chains that could overflow the worker stack.
- Emits `ast.depth_capped` when hostile or generated source exceeds analysis depth.
- Reduced false positives by treating Vim, Lisp, SQL, Smali, diffs, and TS baseline files as text.
- Fixed archive disambiguation so legitimate `.apk` and `.pkg` ecosystem variants do not look like extension mismatches.

## 0.9.0 (2026-06-07)

### New language & format support

- Clojure and Windows Batch AST analysis (tree-sitter).
- AppleScript source detection.
- BEAM bytecode and FreeBSD zstd `.pkg` detection.
- `binding.gyp` parsed as JSON; Meson, Arch package metadata, and R Markdown/Quarto recognized.

### New facts & metrics

- Comments exposed as a matchable string tier; JS/TS/Go backtick strings no longer misread as comments; Lisp and Batch comment styles added.
- New obfuscation AST metrics: operator density, numeric arrays, XOR loops, const/string-return functions, identity functions, and more.
- Extension/content mismatch metrics name the transition (e.g. `binary_as_image`), with carve-outs for benign conventions.
- VBA identifier metrics: mean length, entropy, distinct trigger count.
- `binary.overall_entropy` emitted for every file type.
- Java constructors, C# qualified names, and import aliases (`import x as y`) surfaced.

### Detection accuracy

- Stylesheets treated as text, no longer misparsed as JavaScript.
- JS/Kotlin scoring fixed: `var`/`let`/`const` count for JS; `===` ignored in separator runs.
- Python relative imports keep their `.` prefix — no more false PyPI matches.
- PEs that goblin can't parse now get rizin section/import recovery.

### Performance & memory

- jemalloc tuned to release freed pages immediately: peak RSS −~60%.
- JSON output streams to stdout instead of building in memory.
- Tree-sitter queries compiled once and cached.

### API & maintenance

- Symbol objects slimmed: dropped `source`, `decl`, and rare rizin fields.
- Dependency updates.

## 0.8.0 (2026-05-28)

### Features

- Electron ASAR and Clojure support — new `.asar` archive parser and Clojure source identification.
- Generic JSON support — `.json` files are parsed into top-level keys (with a 75 KB cap; larger files stay analyzable as raw text).
- Broader file identification — more extensions in the fileid map, a dedicated PE extension map, and improved GitHub Actions workflow detection.

### Fixes

- Fixed a PDF `/Length` stream-end calculation bug that mis-bounded stream bodies when `endstream` had no preceding EOL.

### Hardening

- Capped AST recursion depth at 1000 to stop pathologically nested (generated/adversarial) source from overflowing the worker stack; `ast.max_depth` now saturates at the cap as a "deeply nested" signal.

### Internal

- Dependency updates and code cleanup.

## 0.7.0 (2026-05-26)

### New facts

- Markdown extractor — `markdown.first_heading` and deduped `markdown.github_repos[]`.
- `file.basename` / `file.stem` emitted whenever a path is supplied.
- Wheel outer-filename parsing: `whl.filename.{name_prefix,version,build,python_tag,abi_tag,platform_tag}` from the PEP 427 basename.
- PDB derived names — `pe.debug.pdb.basename` and `pe.debug.pdb.stem`.

### Hardening

- Tree-sitter scanner audit: per-grammar `ScannerAudit` table re-verified against locked crate sources; Python now models the actual combined delimiter + indent byte.
- Mach-O fat-binary panic fix — misclassified `CAFEBABE` Java `.class` no longer slices OOB on bogus `arch.offset`.
- Mach-O code-signature caps — Requirement-expression depth 32, plist depth 64, entitlement XML 1 MiB.
- CHM bounds arithmetic — directory / namelist / system walks converted to `checked_add` / `checked_mul`.
- `bytes_at::{u16,u32,u64}_{le,be}` helpers replace unchecked `try_into().unwrap()` reads.
- CLI — `--help` / `--version` no longer `process::exit`; readdir errors surface per-entry.

### Breaking API

- `unsafe_code = "deny"` (was warn).
- `FileId` fields private — use `file_type()`, `source()`, `extension_mismatch()`. `#[non_exhaustive]`.
- `ParseError.kind`/`.stage` are now `ErrorKind` / `Stage` enums (JSON wire form unchanged).
- `ArchiveMember` regrouped into `ArchiveCompression` / `ArchiveOwnership` / `ArchiveOffsets` sub-structs.
- VBA sentinel flattened to `filefacts::VBA_NON_LITERAL_SENTINEL`; rizin module no longer a re-export façade.
- `ParsedFile` is `#[must_use]`; `ParsedFile::strings()` renamed to `text()`.
- `Sections::from_iter_sections` removed in favour of standard `FromIterator`.

## 0.6.0 (2026-05-25)

### Breaking — schema v4 → v6

- Unified symbol model. The peer `Imports`, `Exports`, `Functions`, and `Ast` collections are collapsed into a single tagged `Symbols` enum with kinds `Import`, `Export`, `Function`, `Call`, `Member`, `Bind`, and `Identifier`. `Function.kind` is renamed to `decl`; `Function.calls` is renamed to `callees`. (v5)
- Strings split. `Strings` is replaced by two peers: `Text` (byte-scan ASCII + UTF-16LE — the strings(1) tier) and `Literals` (parser-extracted source string literals). The `StringCategory` enum and `ExtractedString.category` field are removed. (v6)

### New languages

- Perl, Groovy, Zig, Elixir, and Makefile join the tree-sitter language set.

### Source-analysis improvements

- Typed call arguments. Calls now emit an `Arg` enum carrying the actual literal value (`String { value }`, `Number { text, value, radix }`, `Identifier { name }`, `Bool { value }`, `Template { value }`, …), so rules can match on the literal directly instead of correlating against literals by offset.
- New `Identifier` symbol kind. Every bare-identifier leaf (variables, parameters, type names, call targets) is captured with first-seen offset, enabling naming-pattern rules.
- Subscript-as-member. `obj["constructor"]["constructor"](...)` now folds into a member chain instead of dropping out as a dynamic access, so JS sandbox-escape patterns land as `Member` symbols.
- Scanner-overflow guard. Files >2 MB, or Python sources whose estimated indent stack exceeds 450 levels, are skipped before parsing to avoid tree-sitter's external-scanner 1024-byte buffer abort in release builds.

### CLI

- New view flags: `--text`, `--literals`, `--symbols`, `--calls`, `--members`, `--binds`, `--identifiers`.
- Removed: `--strings`, `--ast` (replaced by the above).

## 0.5.0 (2026-05-24)

First release!

## Schema history

Output schema versions before 11:

- **Schema 9** — 75 value and metric keys renamed to one naming convention; section flags share one vocabulary; a `Reference` with no locatable position omits `offset`.
- **Schema 8** — located metrics serialize as `{"value", "spans"}`.
- **Schema 7** — the `Identity` view.
- **Schema 6** — `Strings` split into `Text` and `Literals`.
- **Schema 5** — `Imports`, `Exports`, `Functions` and `Ast` collapsed into the `Symbol` enum.
