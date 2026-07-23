# filefacts

A Rust library that reads a file and tells you what is in it — built for the
people who turn files into feature vectors. Malware classifiers, triage
systems, dataset builders: anything that needs a dense, honest description of a
file as model input. Extracted from
[cleave](https://github.com/atomdrift-project/cleave), it is the extraction layer that
sits underneath Atomdrift's own models — and it is designed to sit underneath
yours. (If you only want to understand a single file, it does that too.)

The pitch to an ML security researcher is one word: **reproducible.** Same bytes
in, same facts out, every time — no subprocesses, no `file`/`objdump`/`openssl`/
`tar` shelling out, no locale or tool-version drift leaking into your features.
A vector you extract during a training run is the same vector you extract when
you re-triage that sample in an incident six months later. That property is hard
to get from a pile of CLIs glued together, and it is the whole point here.

Give it bytes. filefacts identifies the format, parses it **once**, and returns
a `ParsedFile` of lazy, cached views — read what you want, the rest costs
nothing:

```rust
let facts = filefacts::open(&bytes)?;
let entropy = facts.metrics();   // computed on demand
let strings = facts.text();      // the other views never ran
```

`filefacts <path>` writes the same structure as JSON, one object per file, ready
to fold straight into a feature pipeline.

## The output

| View | What it carries |
|------|-----------------|
| `fileid` | Format identification — type, container, compression. Free; no view computed. |
| `values` | Residual structural fields, navigable as a JSON tree. |
| `text` | Byte-scan strings (ASCII + UTF-16LE) with offsets. |
| `literals` | Parser-extracted language string literals. |
| `comments` | Comments recovered from source and documents. |
| `metrics` | Derived numeric features — entropy, sizes, counts. |
| `sections` | Binary section / segment listings. |
| `symbols` | Unified named entities — imports, exports, functions, calls, members, identifiers — tagged by kind. |
| `archive_members` | Entries inside archives, recursively. |
| `source_ast` | tree-sitter AST facts for source files. |
| `errors` | Recoverable extractor diagnostics — never a panic. |

Every fact carries a **byte-range span** pointing at the evidence it was derived
from, so a downstream model (or a human) can trace any feature back to the exact
region of the file that produced it. The output schema is versioned
(`SCHEMA_VERSION`): field additions are non-breaking; renames or semantic changes
bump it, so a pipeline can pin a schema and trust it across releases.

## The signals that discriminate

filefacts surfaces the features that actually separate benign files from the
things they imitate — not a metadata dump:

- **Entropy, windowed.** Byte and per-section entropy, plus a windowed scan that
  surfaces a concealed high-entropy region (peak value + offset) even when the
  file's overall entropy looks unremarkable — the classic "small encrypted blob
  hidden in a large benign file" tell.
- **Structure over trust.** Section layout, import and symbol tables, signature
  validity (Authenticode verified in-process with pure-Rust crypto), and
  extension/content mismatches.
- **Supply-chain identity.** Registry and package metadata parsed into
  structured fields, including a `security_hold` flag and a `version_removed`
  metric for packages pulled from their registry.
- **Stego surface.** Per-channel entropy, edge density, and histogram flatness
  for images.

## What it parses

- **Executables** — PE, ELF (with DWARF), Mach-O, Java class, Python bytecode,
  WebAssembly, Android DEX.
- **Archives & packages** — zip, tar (+ gz/bz2/xz/zst), 7z, rar, deb, rpm, pkg,
  cab, CHM, DMG, CRX, XPI, WHL, JAR, VSIX, npm, gem, nupkg, Rust crate, Python
  sdist, OCI container images.
- **Documents** — PDF, RTF, OOXML, OLE2 (legacy Office, MSI, MSG), LNK, plist,
  AppleScript. Authenticode is verified in-process.
- **Images** — JPEG, PNG, with the stego metrics above.
- **Structured** — JSON, YAML, TOML, XML, SVG, pickle, Dockerfile, Makefile,
  systemd units, .desktop, GitHub Actions, lockfiles, and package manifests.
- **Source** — tree-sitter ASTs for 20+ languages: JavaScript, TypeScript,
  Python, Go, Rust, Java, C, C#, Bash, Batch, PowerShell, PHP, Ruby, Lua, Scala,
  Swift, Objective-C, Kotlin, Clojure, Elixir, Groovy, Zig, plus Cypher/CQL and
  Python template files.

## Install

```bash
make install                              # build + install via cargo

brew tap atomdrift/tap                     # one-time, macOS / Linux
brew install filefacts
```

`make install` builds the release binary and copies it to the first writeable
location on your `PATH`. As a library, add `filefacts = "1.2"` to `Cargo.toml`.

```bash
filefacts suspect.bin       # JSON facts for one file
filefacts /tmp/samples      # recurse a directory
```

## Performance

In-process and single-pass by design: one walk per file, no forking. Views are
cached on disk as zstd-compressed bincode keyed by SHA-256, so a second pass
over the same corpus is nearly free — handy when you re-extract features after
tweaking a downstream model. The cache self-cleans, pruning to 90% of capacity
under pressure rather than aging entries out on a timer. On source and script
files with no sign of XOR logic, the XOR seed search is skipped entirely.

---

Source and issues live on
[GitHub](https://github.com/atomdrift-project/filefacts). Apache 2.0.
