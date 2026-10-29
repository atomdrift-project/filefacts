# Changelog

All notable changes to filefacts are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
output schema is versioned separately by `filefacts::SCHEMA_VERSION`; a bump
is listed under **Changed** with the new value.

## [Unreleased]

### Added

- `filefacts::{Bundle, View, ViewData}` with `ParsedFile::bundle()` and
  `ParsedFile::view()`: the CLI's versioned JSON document, now part of the
  library. The JSON is byte-identical to what the CLI wrote before.
- `OpenOptions::cache_dir`, `rizin::set_max_concurrent_runs`, `PartyRole`,
  `Ecosystem`, `Limitation`, `Resolution`, `UnresolvedReason`, `EntryType`,
  `Registry::new`, `Signer::new`.
- CLI: any number of paths; `--no-cache`, `--no-rizin`, `--rizin-timeout`;
  `usage()` documents environment variables and exit codes.
- File types `ani`, `nrbf`, `image4_trustcache`, `fat_boot_sector` and
  `certificate_signature` (each was `data`).
- Signatures report `signer_count`, `key_bits`, `weak_key`,
  `weak_algorithms[]` and `extended_key_usage[]`.
- PDF object streams with no filter, ASCIIHex, ASCII85 or chained filters are
  decoded; `pdf.limits` stage `object-stream-decode`.
- `deb` reads `control.tar.xz`; Arch packages publish `.PKGINFO` as `pkg.*`;
  `.tar.xz` source releases are probed for WordPress and autoconf identity.
- DWARF is read from big-endian ELF and from compressed `.debug_*` /
  `.zdebug` sections.
- `source.batch.cycle_analysis_limited`; `functions.*` metrics for every
  language with function definitions; Go imports carry their `alias`.
- `pe.manifest.parse_error`, `pe.debug.pdb.path_non_utf8`,
  `pe.debug.pdb.path_hex`; `crx.name`, `crx.format_version`,
  `xpi.author_email`.
- CI on Linux, macOS and Windows, an MSRV job, `cargo audit`, a fuzz build;
  `SECURITY.md` and `CONTRIBUTING.md`.

### Changed

- **`SCHEMA_VERSION` is now `10`.** Renamed or reshaped keys:
  - `cert_chain_depth` → `cert_bag_size` in every signature object;
    timestamp times are RFC 3339.
  - `elf.hashes.imphash` → `elf.hashes.import_hash`,
    `elf.hashes.symhash` → `elf.hashes.symtab_import_hash`,
    `macho.hashes.imphash` → `macho.hashes.import_hash`.
  - `python.summary`, `whl.summary`, `deb.summary`, `gem.summary`,
    `rpm.summary` → `*.description`; `gem.runtime_dependencies` →
    `gem.dependencies`; `gem.licenses[]` → `gem.license`.
  - `crx.version` is the extension's version; the CRX header version is
    `crx.format_version`.
  - People share one shape in every ecosystem: `<fmt>.authors`,
    `<fmt>.maintainers`, `<fmt>.owners` and `<fmt>.packagers`, each a list
    of `{name, email, url}`. Renamed: `npm.author`, `python.author`,
    `python.maintainer`, `whl.author`(`_email`), `whl.maintainer`(`_email`),
    `crx.author`(`_email`), `xpi.author`(`_email`), `deb.maintainer`,
    `apk.maintainer`, `apk.packager`, `rpm.packager`, `registry.author`;
    reshaped from strings:
    `crate.authors`, `gem.authors`, `nupkg.authors`, `nupkg.owners`.
    `deb.maintainers` includes `Uploaders`; comma-separated PEP 621 author
    lists are separate people.
  - `archive.members[]` is the typed `ArchiveMember` serialized flat;
    `entry_type` is an `EntryType` (cpio: `character` → `char-device`,
    `block` → `block-device`, `unknown` → `other`).
  - `Reference` gains `resolution`; `go.mod.unresolved-*` sources become
    `go.mod` with `resolution: {"unresolved": reason}`.
  - `GoPackage.variant`/`behaviors` → `platforms`; `CargoTarget.behaviors`
    removed.
  - `Party.role` and `Registry.ecosystem` are enums; known ecosystem labels
    are lowercase (`PyPI` → `pypi`).
  - CFML `Flow.limitations` `syntax-*` values are kebab-case.
  - `source.shell.fifo_network_loops` and the Python temporary-file facts
    (`source.python.temporary_files`) are reshaped as general relations.
- Semantic changes:
  - `pe.hashes.imphash` matches pefile and VirusTotal for ordinal imports.
  - PDF `/Type` counts (`pdf.*_count`, `pdf.shape.*`) count dictionaries in
    objects and object streams with PDF name rules (whitespace, comments,
    `#xx` escapes), not byte tokens anywhere in the file.
  - Go build info is read only from the region Go's `debug/buildinfo`
    reads, at 16-byte alignment.
  - ELF overlap counts include every intersecting range.
  - A fat Mach-O's primary slice is the first that parses.
  - Literals and `source.rust.modules` are in source order; identifier
    metrics count leaf identifiers.
  - Platform and Developer ID trust require the codeSigning EKU.
  - Configuration extensions (`.toml`, `.ini`, `.cfg`, …) are text by
    extension; an npm tarball named `.zip` is an extension mismatch.
- `OpenOptions::new()` reads no environment: the cache is off unless the host
  turns it on. The CLI reads `FILEFACTS_CACHE` and
  `FILEFACTS_RIZIN_CONCURRENCY` itself.
- CLI colour only when stdout is a terminal and `NO_COLOR` is unset or empty;
  directory walks are sorted.
- A structured document's keys merge beside filefacts' own values instead of
  replacing them.
- Dependencies: `zip` 9 (deflate only), `zstd` 0.14, `png` 0.18, `toml` 1,
  `cfb` 0.14; `lzma-rust2` is the one LZMA/xz implementation.

### Removed

- `sevenz-rust` and `xz2` dependencies; `sevenz.rs` parses the 7z header
  itself.
- Public `cache` internals (only `cleanup`, `env_override` and
  `DEFAULT_MAX_ITEMS` remain), `cache_sweep`, `tools`, the full `rpa` index
  (`rpa::members` returns what a host needs to carve members), `MetricKey`,
  `ValueKey`, the metric-key family functions, `ParsedFile::symbol_iter`,
  `FileType::is_supported`.
- `pe.signature_expired_days` (it depended on the clock, so cached facts went
  stale; use `not_after_unix`), the `pe.partial_parse` value,
  `office.compobj.app_version`.
- CLI `-p/--pretty`; the radare2 fallback (only `rizin` is run).
- Serde aliases for old `SectionFlag` and `Literal` spellings; the legacy
  stng cache sweep.

### Fixed

- A JSON, YAML, TOML or plist document could erase `file.basename` and forge
  filefacts-owned keys.
- A CAB signature reported `verified: true` without being bound to the
  cabinet; the PE header-only path reported `verified: true` without a digest
  check.
- `pdf.signature_object_count` was overwritten with a value that reported 0
  for a single `/Type/Sig`.
- A commented-out `requestedExecutionLevel` could hide a manifest's real one.
- The rizin child could get a looser memory limit than it inherited.
- Two tree-sitter parses bypassed the parse budget and abort guard; five
  pipeline stages printed caught panics to stderr.
- Quadratic walks in Rust attribute handling and ISO namespace merging;
  uncapped OLE2 stream reads; an unbounded zstd window; a 4 MiB UTF-16 decode
  per identification.
- Rust ctor and Go generate facts vanished on files over 2 MiB.
- Go build constraints followed the wrong rules.
- Python and Go environment reads never reached `environment-value-http-body`.
- Overlapping Aho-Corasick matches double-scored language tokens.
- Encrypted `.class` entries dropped out of `jar` class counts.
- Identifying a signed phar hashed the whole file; identification now reads
  the manifest and trailer shape only, and the extractor checks the digest.
- Mach-O `entry_section` was computed from a file offset, not the entry VA.
- On macOS a rizin run killed at its deadline was misreported as killed from
  outside; the rizin memo shared entries across scripts.

### Security

- Remaining `cargo audit` exceptions, both verification-only, are documented
  in `.cargo/audit.toml`: RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2026-0387
  (`crypto-bigint` via `p256`/`p384`).
- Real malware specimens in the test data are stored zstd-compressed; see
  `testdata/README.md`.

## History before this changelog

- **Schema 9** — 75 value and metric keys renamed to one naming convention;
  section flags share one vocabulary; a `Reference` with no locatable
  position omits `offset`.
- **Schema 8** — located metrics serialize as `{"value", "spans"}`.
- **Schema 7** — the `Identity` view.
- **Schema 6** — `Strings` split into `Text` and `Literals`.
- **Schema 5** — `Imports`, `Exports`, `Functions` and `Ast` collapsed into
  the `Symbol` enum.

[Unreleased]: https://github.com/atomdrift-project/filefacts/compare/v2.0.1...HEAD
