# filefacts

[![CI](https://github.com/atomdrift-project/filefacts/actions/workflows/ci.yml/badge.svg)](https://github.com/atomdrift-project/filefacts/actions/workflows/ci.yml)
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
lockfiles, and 20+ source languages. Input is assumed hostile: filefacts never
executes it, bounds the work and memory each parser may spend, and turns
damaged input into diagnostics rather than a panic.

## Install

```bash
brew install atomdrift-project/tap/filefacts   # macOS or Linux
make install                                    # from source: Rust 1.97+, C/C++ toolchain
```

## CLI

```bash
filefacts suspect.bin                  # default facts bundle in the terminal
filefacts --format json ./samples      # recurse a directory, emit JSON
filefacts imports a.exe b.dll          # one view, for several files
filefacts --no-cache x.elf             # no disk cache
```

Views include `fileid`, `identity`, `values`, `text`, `literals`, `metrics`,
`symbols`, `sections`, `references`, `archive_members`, and `errors`; see
`filefacts --help` for the full list, every option, and the exit codes.

| Option | Effect |
|---|---|
| `-f`, `--format <terminal\|json>` | Output format (default `terminal`) |

## Library

```rust
let parsed = filefacts::open(&bytes);
println!("{:?}", parsed.fileid().file_type());
let metrics = parsed.metrics(); // views are computed lazily and cached
```

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, and the fixture policy.
- [SECURITY.md](SECURITY.md): reporting vulnerabilities privately.
- [CHANGELOG.md](CHANGELOG.md): release notes.

Licensed under the [Apache License 2.0](LICENSE).
