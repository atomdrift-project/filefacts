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
filefacts --no-rizin --no-cache x.elf  # no subprocess, no disk cache
```

Views include `fileid`, `identity`, `values`, `text`, `literals`, `metrics`,
`symbols`, `sections`, `references`, `archive_members`, and `errors`; see
`filefacts --help` for the full list, every option, and the exit codes.

| Option | Effect |
|---|---|
| `-f`, `--format <terminal\|json>` | Output format (default `terminal`) |
| `--no-rizin` | Never run rizin |
| `--rizin-timeout <secs>` | Wall-clock budget per rizin run (default 600) |
| `--no-cache` | Neither read nor write the disk cache |

| Environment | Effect |
|---|---|
| `FILEFACTS_CACHE=0` | Disable the disk cache (`~/.cache/atomdrift/filefacts` or the platform equivalent) |
| `FILEFACTS_DEBUG=1` | Print extractor diagnostics to stderr |
| `FILEFACTS_RIZIN_CONCURRENCY=<n>` | Run at most `n` rizin processes at once |

For PE, ELF, and Mach-O, filefacts uses an installed
[rizin](https://rizin.re) for deeper symbol recovery on stripped binaries. It
runs as a resource-limited subprocess with a scrubbed environment and a hard
timeout; without it, those views come from filefacts' own parsers.

## Library

```rust
let parsed = filefacts::open(&bytes);
println!("{:?}", parsed.fileid().file_type());
let metrics = parsed.metrics(); // views are computed lazily and cached
```

`OpenOptions` sets the path, a known type, cancellation, caching, and rizin
limits per file; the library reads no environment variables. filefacts is not
on crates.io yet, so depend on it via git with `default-features = false` (the
default features build the CLI) and copy the `[patch.crates-io]` block from
`Cargo.toml`: `[patch]` applies only in the root of a build, and without it
you get the unpatched tree-sitter releases.

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, and the fixture policy.
- [SECURITY.md](SECURITY.md): reporting vulnerabilities privately.
- [CHANGELOG.md](CHANGELOG.md): release notes.

Licensed under the [Apache License 2.0](LICENSE).
