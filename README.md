# filefacts

Extracts facts from a wide variety of file types.

A Rust library that parses binary, archive, document, and source-code
formats once and surfaces the structural facts as a typed
`ParsedFile<'a>` with lazy views: `fileid`, `values`, `strings`,
`metrics`, `ast`, `sections`, `imports`, `exports`, `functions`, and
`errors`. Built as the parsing layer for the
[cleave](https://codeberg.org/atomdrift/cleave) forensic
static-analysis tool.

## Design rules

- **No external commands.** Every fact `filefacts` surfaces is recovered
  in-process from Rust code. We never shell out to `rizin`,
  `objdump`, `file`, `openssl`, `tar`, `7z`, or any other system
  binary, and we never pull in crates that internally do. Tools that
  genuinely require process spawning (currently rizin/yara
  integration) live in cleave, not here.
- **Pure-Rust dependencies are welcome.** This rule is about
  *process spawning*, not about dependency count. If a Rust crate
  parses a format we need (e.g. `lzx`, `flate2`, `cms`, `goblin`),
  pulling it in is fine — it just runs as in-process Rust like the
  rest of `filefacts`. The bar for adding one is "is this format
  worth handling at all?", not "can we avoid the dependency?".
- **Test coverage target: 85%+ per format.** Every format extractor
  should cover at minimum: the happy path (canonical input, all
  values/metrics surfaced), every named metric the extractor emits, at
  least two malformed / truncated-input cases (no panic, sensible
  degradation), the rejection path (non-format input is silent),
  and any non-obvious decoding quirks (escape sequences, BOMs,
  endianness, length-prefix overflow). Lean test fixtures (built
  in-memory in `#[cfg(test)]`) are preferred over real-file
  corpora so the test suite stays self-contained and quick.
- **Single-pass parsing.** Each format is parsed at most once per
  file; the typed views are computed lazily and cached. Trait
  evaluation in cleave reads from the same in-memory representation.
- **Pike-style schema.** Path names mirror the format spec's own
  terminology (`pe.dll_characteristics`, `macho.code_signature.cdhash`,
  `pdf.catalog.features`) with no filler words, no per-flag
  booleans where a flag array or presence check works, and no
  stutter. Trait authors can match what they already know.

## Naming

`filefacts` emits a facts bundle. A bundle contains top-level views.
`values` is the structural tree view; downstream tools can query that
tree with value paths.
