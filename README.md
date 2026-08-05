# filefacts

[![Latest release](https://img.shields.io/github/v/release/atomdrift-project/filefacts)](https://github.com/atomdrift-project/filefacts/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/filefacts)](https://crates.io/crates/filefacts)
[![License](https://img.shields.io/github/license/atomdrift-project/filefacts)](LICENSE)

filefacts is an open-source Rust library and CLI that turns files into
structured, security-relevant facts. It identifies formats, parses their
structure, and exposes lazy views over text, symbols, sections, metrics,
metadata, ASTs, and archive members.

Use it when building a malware classifier, triage pipeline, dataset, or any
tool that needs more than a MIME type. It is the extraction layer used by
[cleave](https://github.com/atomdrift-project/cleave), packaged so you can use
the same parsers independently.

## Why filefacts?

- **Parse once, inspect what you need.** Views are computed lazily and cached.
- **Broad format coverage.** Handles source, executables, packages, archives,
  documents, images, manifests, lockfiles, and deployment configuration.
- **Evidence-oriented output.** Facts retain offsets, kinds, and provenance
  useful to models and human reviewers.
- **Recoverable failures.** Unsupported or damaged structures produce
  diagnostics instead of forcing the entire pipeline to fail.
- **Library and CLI.** Embed it in Rust or emit terminal/JSON output for another
  process.

## Install

### Rust library

```toml
[dependencies]
filefacts = "1.3"
```

```rust
let parsed = filefacts::open(&bytes)?;
let identity = parsed.fileid();
let metrics = parsed.metrics();
let symbols = parsed.symbols();
```

### Homebrew CLI on macOS or Linux

```bash
brew install atomdrift-project/tap/filefacts
```

### Build the CLI from source

Source builds require Git, Make, a C/C++ toolchain, and Rust 1.85 or newer.

```bash
git clone https://github.com/atomdrift-project/filefacts.git
cd filefacts
make install
```

## Quick start

```bash
# Inspect all available views in the terminal.
filefacts suspect.bin

# Emit the complete report as JSON.
filefacts --format json suspect.bin

# Request one focused view.
filefacts metrics suspect.bin
filefacts imports suspect.bin
filefacts errors suspect.bin

# Recursively inspect recognized files in a directory.
filefacts --format json ./samples
```

Run `filefacts --help` for the complete view and output list.

## Available views

| View | Contents |
| --- | --- |
| `fileid` | File type, container, compression, and format confidence |
| `identity` | Normalized package, signing, and producer identity claims |
| `values` | Format-specific structural fields |
| `text` / `literals` | Byte-scan text and parser-extracted string literals |
| `metrics` | Entropy, sizes, counts, and other numeric features |
| `sections` | Executable sections and segments |
| `symbols` | Imports, exports, functions, calls, members, and identifiers |
| `archive_members` | Recursively discovered container entries |
| `source_ast` | tree-sitter facts for recognized source languages |
| `errors` | Recoverable parser and extractor diagnostics |

The schema is versioned with `SCHEMA_VERSION`. Views are cached as
content-addressed, zstd-compressed records to make repeated corpus passes
inexpensive.

Most parsing is in-process. For PE, ELF, and Mach-O files, filefacts can invoke
an installed Rizin or radare2 subprocess to recover deeper control-flow and
symbol information. Its presence and version are part of the cache key, so pin
the analysis environment when producing reproducible training data.

## Coverage

Representative formats include PE, ELF, Mach-O, WebAssembly, Android DEX, Java
class files, Python bytecode, ZIP/TAR/7-Zip/RAR, deb/rpm/APK packages, OCI
images, npm/wheel/gem/crate/NuGet packages, PDF, Office/OLE2, OOXML, RTF, LNK,
plist, JPEG/PNG, JSON/YAML/TOML/XML, package manifests, lockfiles, and more than
20 source languages.

Issues and pull requests are welcome in the
[GitHub repository](https://github.com/atomdrift-project/filefacts).

## License

filefacts is available under the [Apache License 2.0](LICENSE).
