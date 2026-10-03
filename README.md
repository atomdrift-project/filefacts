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
filefacts = "2"
```

```rust
let parsed = filefacts::open(&bytes);
let identity = parsed.fileid();
let metrics = parsed.metrics();
let symbols = parsed.symbols();
```

`open` uses the library defaults. `OpenOptions` adds a path for identification,
a known type, a cancellation flag, and per-file cache and Rizin settings:

```rust
use std::{path::Path, time::Duration};

let parsed = filefacts::OpenOptions::new()
    .path(Path::new("sample.exe"))
    .cache(true)
    .rizin_timeout(Duration::from_secs(60))
    .open(&bytes);
```

Every setting belongs to the `ParsedFile` it opens; nothing is process-wide, so
one process can open files under different settings at once. Version 2.0
replaced `open_with_path`, `open_with_fileid`, `open_as`,
`ParsedFile::with_cancellation`, the `cache::set_caching_enabled` /
`enable_by_default` switches and the `rizin::disable` / `scoped_disable*` /
`set_*` globals with these options.

### Homebrew CLI on macOS or Linux

```bash
brew install atomdrift-project/tap/filefacts
```

### Build the CLI from source

Source builds require Git, Make, a C/C++ toolchain, and Rust 1.94 or newer.

```bash
git clone https://github.com/atomdrift-project/filefacts.git
cd filefacts
make install
```

## Quick start

```bash
# Inspect the default facts bundle in the terminal.
filefacts suspect.bin

# Emit the default facts bundle as JSON.
filefacts --format json suspect.bin

# Request one focused view.
filefacts metrics suspect.bin
filefacts imports suspect.bin
filefacts errors suspect.bin
filefacts --format json --flow suspect.bin

# Recursively inspect recognized files in a directory.
filefacts --format json ./samples
```

Run `filefacts --help` for the complete view and output list.

[Compiled AppleScript](docs/SCPT.md) exposes literals, calls, and known arguments
without running the script.

## Available views

| View | Contents |
| --- | --- |
| `fileid` | File type, container, compression, and format confidence |
| `identity` | Normalized package, signing, and producer identity claims |
| `values` | Format-specific structural fields |
| `text` / `literals` | Byte-scan text and parser-extracted string literals |
| `comments` | Comment bodies from recognized source languages |
| `metrics` | Entropy, sizes, counts, and other numeric features |
| `sections` | Executable sections and segments |
| `symbols` | Imports, exports, functions, calls, members, and identifiers |
| `flow` | Value relationships, producer, and limitations (opt-in) |
| `references` | Packages, URLs, and files the artifact points at (never fetched) |
| `archive_members` | Typed index of an archive's members: names, sizes, offsets |
| `errors` | Recoverable parser and extractor diagnostics |

Library callers can also borrow the shared tree-sitter parse with
`ParsedFile::source_ast()`; it is not a CLI view.

On the command line a view is selected by name or with `--<view>`. When a
positional name is also an existing file, the file wins; use the flag form to
force the view.

`ParsedFile::flow()` returns the shared `Flow` model. The view is lazy and
opt-in, so the default CLI bundle does not construct it. Currently the source
parser produces flow; binary flow recovery is not implemented. Unsupported
analysis returns `None` (`null` in CLI JSON), not an empty graph. Missing flow
or missing relationships are not evidence that a file is safe.

Value and metric keys follow one naming convention, described in
[docs/NAMING.md](docs/NAMING.md). Schema v9 renamed 75 keys to fit it;
[docs/schema-v9-renames.tsv](docs/schema-v9-renames.tsv) maps each old key to
its new name for consumers migrating from v8. Moving from filefacts 1.x to
2.0 (the API changes as well as the renames) is covered in
[docs/MIGRATING.md](docs/MIGRATING.md).

The schema is versioned with `SCHEMA_VERSION`. The CLI caches views on disk as
content-addressed, zstd-compressed records under the user cache directory
(for example `~/.cache/atomdrift/filefacts`) to make repeated corpus passes
inexpensive. Library callers get the same cache only by opting in with
`OpenOptions::cache(true)`; otherwise a `ParsedFile` never touches the disk.
Entries are keyed by content, the filefacts source and every setting that
changes the output, so upgrading filefacts or changing Rizin settings never
serves stale results.

Most parsing is in-process. For PE, ELF, and Mach-O files, filefacts can invoke
an installed Rizin or radare2 subprocess to recover deeper control-flow and
symbol information. Its presence and version are part of the cache key, so pin
the analysis environment when producing reproducible training data. Turn it off
per file with `OpenOptions::rizin(false)`, or bound it with `rizin_timeout`,
`rizin_max_bytes` and `rizin_native_arch_only`.

### Environment variables

| Variable | Effect |
| --- | --- |
| `FILEFACTS_CACHE` | `0` or `false` disables the disk cache; any other value enables it, including for library callers that did not choose. An explicit `OpenOptions::cache` overrides it. |
| `FILEFACTS_DEBUG` | Any value other than empty, `0`, or `false` prints extractor diagnostics to stderr. |

## Coverage

Representative formats include PE, ELF, Mach-O, WebAssembly, Android DEX, Java
class files, Python bytecode, ZIP/TAR/7-Zip/RAR, deb/rpm/APK packages, OCI
images, npm/wheel/gem/crate/NuGet packages, PHP phar archives, PDF, Office/OLE2,
OOXML, RTF, LNK, plist, nib, JPEG/PNG, JSON/YAML/TOML/XML, package manifests,
lockfiles, and more than 20 source languages.

Issues and pull requests are welcome in the
[GitHub repository](https://github.com/atomdrift-project/filefacts).

## License

filefacts is available under the [Apache License 2.0](LICENSE).
