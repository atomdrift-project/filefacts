# expose

Exposes characteristics and metadata for a wide variety of file types.

A Rust library that parses binary, archive, document, and source-code
formats once and surfaces the structural facts as a typed
`ParsedFile<'a>` with four lazy views: `fileid`, `values`, `strings`,
`metrics`. Built as the parsing layer for the
[cleave](https://codeberg.org/atomdrift/cleave) forensic
static-analysis tool.

## Design rules

- **No external commands.** Every fact `expose` surfaces is recovered
  in-process from Rust code. We never shell out to `rizin`,
  `objdump`, `file`, `openssl`, `tar`, `7z`, or any other system
  binary. Tools that genuinely require process spawning (currently
  rizin/yara integration) live in cleave, not here.
- **No external dependencies that shell out either.** Crates we
  pull in (goblin, flate2/rust_backend, tree-sitter, zip, tar,
  plist, cms, x509-cert) are pure-Rust by policy. Adding a crate
  that internally calls a system binary is a regression of this
  rule.
- **Single-pass parsing.** Each format is parsed at most once per
  file; the typed views are computed lazily and cached. Trait
  evaluation in cleave reads from the same in-memory representation.
- **Pike-style schema.** Path names mirror the format spec's own
  terminology (`pe.dll_characteristics`, `macho.code_signature.cdhash`,
  `pdf.catalog.features`) with no filler words, no per-flag
  booleans where a flag array or presence check works, and no
  stutter. Trait authors can match what they already know.

## Naming

The project was originally `metaparse` while the schema settled;
it was renamed `expose` once the kv-tree-as-truth design was
finalized.
