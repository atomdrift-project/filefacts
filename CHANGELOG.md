# Changelog

All notable changes to filefacts are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
output schema is versioned separately by `filefacts::SCHEMA_VERSION`; a bump
is listed under **Changed** with the new value.

## [Unreleased]

### Added

- `media.trailing_content_kind` identifies the actual trailing region separately
  from executable/archive signatures in metadata or interior gaps. This prevents
  assigning an unrelated embedded header to an ordinary image trailer.

- PNG trailer context: `png.trailing_iend_count`, bounded absolute byte offsets
  in `png.trailing_iend_offsets`, and `trailer_ends_with_iend` in features. These
  CRC-correct byte records can support investigating image overwrite residue;
  they never claim trailer coverage or establish that its contents are safe.

- `Registry::favorites` and the `registry.favorites` metric: stars, likes,
  or favers, a popularity count with no score behind it (unlike
  `rating_count`, the votes behind `rating`).
- `filefacts::values`: typed, borrowing reads of the value facts consumers act
  on, from any `&Values`, live or retained: `basename`, `npm_install_hooks`,
  `batch_command_sites` (as `BatchCommandSite`) and
  `batch_command_sites_truncated`. Their producers write through the same
  declarations, so the JSON output is unchanged.
- `impl From<serde_json::Value> for Values`, to read a tree retained as JSON.
- Bounded PNG pixel-payload probes for channel/bit-plane packing, traversal
  swaps, prime pixels and transparent RGB; Base64, hex, UTF-16, single-byte
  XOR, and checksum-validated zlib/gzip transforms. Script, configuration and
  binary-format recognition emit recovered layouts and bounded previews in
  `png.pixel_payloads`; probe budgets and limits are observable without
  treating random pixels alone as a recovered payload.
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
- `filefacts::Group`: every `FileType` belongs to exactly one of 19 groups
  (`Group::ALL`, `label`, `from_label`, `file_types`); `FileType::ALL` and
  `const FileType::group()` are public. `docs/file-groups.json` publishes
  the table for consumers that route or train per group.
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

- The section, import and export views of PE, ELF and Mach-O come from
  binform rather than goblin; goblin still reads the rest (headers,
  resources, Authenticode, load config, CLR, notes, the dynamic section).
  binform reads the ELF and Mach-O files goblin rejects, binds each
  chained-fixup Mach-O import to its library, lists each Mach-O import once
  rather than once per bind, adds ELF exports goblin's type filter dropped
  (`_end`, `_edata`, TLS) and ordinal-only PE exports (`Ordinal_n`), and
  resolves long PE section names (`/4`) through the COFF string table. PE
  imports by ordinal from msi, comctl32, cabinet, mfc42(u), and Windows CE's
  coredll (per CPU) and commctrl are named from those DLLs' own export
  tables; the imphash still names ordinals only as pefile does. binform
  reads each binary, or each slice of a universal one, once: the views,
  function recovery and stng's string passes share that read. Mach-O
  strings no longer come from a copy with forged bind streams emptied,
  since stng no longer runs goblin's bind interpreter. An ELF import
  names its library from its symbol version (`printf@GLIBC_2.2.5` is
  `libc`, from `libc.so.6`); unversioned imports name none. binform's
  "layout:" error is recorded only where goblin read the file, since
  goblin's own error otherwise reports the same defect, and a universal
  static library's `ar` slices are not read as images. A PE import or
  export table past goblin's walk budget is still reported as an error,
  but its view is binform's, read within binform's own budget of the same
  size, rather than left empty.
- PE, ELF and Mach-O function recovery runs in-process through binform
  instead of rizin, on every binary without a function inventory, and binform
  fills the section, import and export views of a PE goblin cannot read in
  full. filefacts no longer starts rizin, and its surface is gone: the
  `rizin` module, the `OpenOptions::rizin*` settings, `rizin::available`,
  `rizin_recovery_incomplete`, `FILEFACTS_RIZIN_CONCURRENCY`, and the CLI's
  `--no-rizin` and `--rizin-timeout` (now unknown flags). Binaries of an instruction set binform does not decode
  (eBPF, M*Core, Nios II, IA-64 and the like) keep their layout facts and get
  no functions.
- ELF `elf.syscalls_direct` is projected from `binform::calls`, which tracks
  register and stack values through each recovered function, rather than a
  fixed-window scan. This extends direct-syscall extraction from x86-64 and
  AArch64 to 32-bit Arm and x86, resolves numbers and arguments built across
  blocks (a `connect` whose number is `mov r7,0x100; add r7,0x1b`, which rizin
  and the old scan both miss), and no longer reports `0f05` bytes that fall
  inside other instructions. The syscall number-to-name tables move to
  binform (`binform::Binary::syscall`, generated from the `libc` crate). New:
  a `connect`/`bind` argument that points at a `sockaddr_in`/`sockaddr_in6`
  gets a `decoded` field with the IP and port, and a call through the libc
  `syscall()` wrapper carries `via: "syscall"`. A call to the libc `connect()`
  import is projected the same way, carrying `via: "connect"` with the socket
  syscall number for the architecture (from the new
  `binform::Binary::syscall_number`). In a statically linked binary, where
  `connect` reaches the kernel through an in-image wrapper (`mov eax, 42;
  syscall`), a direct call to that wrapper is projected from the caller with
  its arguments and carries `via: "wrapper"`. The decoded destinations are also
  surfaced as a first-class network IOC in `elf.network_endpoints` — one
  `{ip, port, kind, offset, syscall, via?}` per `sockaddr` a syscall points
  at — with the count in the `elf.network_endpoint_count` metric.

- **`SCHEMA_VERSION` is now `11`.** Renamed or reshaped keys:
  - A PE delay-load import's `offset` is its address-table slot's RVA, as
    every other PE import's is, rather than its lookup entry's file offset.
    The ELF section view no longer lists the null section at index 0; a
    relocatable object's sections are at the addresses its functions are
    recovered at. An executable's `.symtab`-only globals (`main`, `_start`)
    are functions, not exports: ELF exports are what other images can bind
    to. A Mach-O re-export has no `offset`. `pe.recovered_import_count`,
    `pe.recovered_export_count` and `pe.recovered_section_count` are gone:
    every binary's tables are binform's.
  - `pe.rizin_importless_analysis` → `pe.importless_analysis`,
    `pe.rizin_importless_function_count` → `pe.importless_function_count`;
    `binary.rizin_incomplete`, which nothing set, is gone.
  - PNG `image.*` statistics normalize palette and 16-bit samples rather than
    counting palette indices or alternating bytes as color samples.
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
  - `consistency.extension_content_mismatch.<content>_as_<ext>` names
    `Group` labels: `binary` → `native`, `bytecode` or `machine_code`;
    `script` → `scripts`; `archive` → `archives` or `compressed`;
    `document` → `documents`; `image` → `images`; `font` → `fonts`. New
    labels `build`, `signatures`, `serialized` and `unknown` take types
    that were `config` or `data`; HTML, TeX and Markdown move from `text`
    to `documents`, `lnk` from `binary` to `config`, and TypeScript from
    `source` to `scripts`.
- Semantic changes:
  - `pe.hashes.imphash` matches pefile and VirusTotal for ordinal imports.
  - PDF `/Type` counts (`pdf.*_count`, `pdf.shape.*`) count dictionaries in
    objects and object streams with PDF name rules (whitespace, comments,
    `#xx` escapes), not byte tokens anywhere in the file.
  - Go build info is read only from the region Go's `debug/buildinfo`
    reads, at 16-byte alignment.
  - ELF overlap counts include every intersecting range.
  - A fat Mach-O's primary slice, which the top-level views and the
    recovered functions describe, is the x86-64 slice, else arm64, else
    another binform decodes, else the first that parses: an armv7 + arm64
    iOS binary is described by its arm64 image, which yields functions.
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

- Content detection reads a file as `go.mod` only when every line after its
  `module` directive is a `go.mod` directive or block entry. A Ruby (or
  Fortran) file opening with `module Name` was typed `go.mod`, so no rule for
  its language ran: strong_password 0.0.7's `eval` of a pastebin fetch went
  unread.
- `font.layout_format` retains a structurally coherent WOFF whose signature
  bytes were reordered, while `font.format` stays `none` and `font.valid`
  stays false; corrupt decoder fixtures no longer become opaque payloads.
- Media-carrier CAB candidates require a bounded, versioned fixed header;
  ASCII `MSCF` in diagram/Base64 metadata is not an embedded cabinet.
- Media-carrier gzip findings validate reserved header flags and a bounded
  deflate stream, avoiding three-byte magic coincidences inside compressed
  PNG metadata while retaining real compressed stowaways.
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
