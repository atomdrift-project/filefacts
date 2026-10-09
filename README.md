# filefacts

[![Latest release](https://img.shields.io/github/v/release/atomdrift-project/filefacts)](https://github.com/atomdrift-project/filefacts/releases/latest)
[![License](https://img.shields.io/github/license/atomdrift-project/filefacts)](LICENSE)

filefacts is a Rust library and CLI that turns files into structured,
security-relevant facts: format identity, structural values, strings, symbols,
sections, metrics, references, and recoverable parse errors. It is the
extraction layer underneath [cleave](https://github.com/atomdrift-project/cleave),
for malware classifiers, triage pipelines, and datasets that need more than a MIME type.

It covers executables (PE, ELF, Mach-O, Wasm, DEX, class files, Python bytecode),
archives and packages (ZIP, TAR, 7z, RAR, deb, rpm, APK, OCI, npm, wheel, gem,
crate, NuGet, DMG), documents (PDF, OLE2, OOXML, RTF, LNK, plist), manifests,
lockfiles, and 20+ source languages. Damaged input yields diagnostics, not a panic.

## Install

```bash
brew install atomdrift-project/tap/filefacts   # macOS or Linux
make install                                    # from source: Rust 1.94+, C/C++ toolchain
```

## CLI

```bash
filefacts suspect.bin                  # default facts bundle in the terminal
filefacts --format json ./samples      # recurse a directory, emit JSON
filefacts imports suspect.bin          # a single view; see `filefacts --help`
```

Views include `fileid`, `identity`, `values`, `text`, `literals`, `metrics`,
`symbols`, `sections`, `references`, `archive_members`, and `errors`. The CLI
caches them under `~/.cache/atomdrift/filefacts`; set `FILEFACTS_CACHE=0` to
disable that, or `FILEFACTS_DEBUG=1` to print extractor diagnostics. For PE, ELF, and Mach-O,
filefacts uses an installed Rizin or radare2 for deeper symbol recovery.

## Library

```rust
let parsed = filefacts::open(&bytes);
println!("{:?}", parsed.fileid().file_type());
let metrics = parsed.metrics(); // views are computed lazily and cached
```

`OpenOptions` sets the path, a known type, cancellation, caching, and Rizin limits
per file; nothing is process-wide. filefacts is not on crates.io yet, so depend on
it via git and copy the `[patch.crates-io]` tree-sitter block from `Cargo.toml`.

Licensed under the [Apache License 2.0](LICENSE).
