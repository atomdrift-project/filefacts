# filefacts fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the
extraction pipeline. The crate is a member of the root workspace, so it
builds against the same `Cargo.lock` and `[patch.crates-io]` forks as the
library. It is not a default member: plain `cargo build` and `cargo test` at
the root skip it. `cargo check -p filefacts-fuzz` type-checks it on stable.

## Targets

| Target | What it exercises |
|---|---|
| `open_all_views` | Identification from content alone, then every view |
| `fileid` | Identification only, with and without a path |
| `pe`, `elf`, `macho`, `zip`, `pdf`, `iso`, `plist` | That extractor, forced with `OpenOptions::file_type` so inputs keep reaching it after mutation breaks the magic |
| `source_js`, `source_c`, `source_python` | tree-sitter source extraction, the AST walk and the flow graph |

Every target opens with the disk cache and rizin off, and touches every view:
strings, values, metrics, symbols, sections, archive members, flow, identity,
references and errors.

filefacts catches extractor panics and records them as `panic` diagnostics,
so on their own they never reach libFuzzer. The driver re-raises any it finds
as a crash. Set `FUZZ_ALLOW_CAUGHT_PANICS=1` to skip that and look only for
what the catch cannot stop.

Without rustup's `+nightly`, the stable compiler can build the targets when
it is allowed unstable flags and no sanitizer is requested:

```sh
RUSTC_BOOTSTRAP=1 cargo fuzz build -O -s none
RUSTC_BOOTSTRAP=1 cargo fuzz run -O -s none pdf -- -rss_limit_mb=2048 -timeout=10
```

## Running

You need a nightly toolchain and `cargo install cargo-fuzz`. Run from the
repository root:

```sh
make fuzz FUZZ_TARGET=pdf
# or directly:
cargo +nightly fuzz run pdf -- -rss_limit_mb=2048 -timeout=10 -max_len=1048576
```

The limits matter: the failures this harness exists to find are aborts,
runaway memory and runaway time, not panics.

- **`-rss_limit_mb=2048`** turns a runaway allocation into a reported crash
  instead of an OOM kill of the whole machine. Lower it (for example to 1024)
  to also catch large but bounded blowups.
- **`-timeout=10`** reports an input that takes over 10 s as a timeout. That
  catches exponential and quadratic paths, such as a parser that re-walks a
  structure once per reference.
- **`-max_len=1048576`** lets the fuzzer grow inputs big enough to reach size
  thresholds. The default of 4096 bytes is too small for most containers.

### Stack depth

libFuzzer calls each target on the main thread, whose 8 MiB stack hides
recursion that overflows a 2 MiB rayon worker in a real scan. The shared
driver (`src/lib.rs`) therefore runs every input on a 2 MiB thread. A stack
overflow aborts the process, and libFuzzer reports it as a deadly signal with
the reproducing input saved under `fuzz/artifacts/<target>/`.

### Seeds

Seed a corpus with the repository's fixtures, for example:

```sh
mkdir -p fuzz/corpus/pe && cp tests/fixtures/*.exe tests/fixtures/*.dll fuzz/corpus/pe/
```

Some fixtures are real malware specimens stored zstd-compressed (see
`testdata/README.md`); decompress them into the corpus only on a machine
where that is acceptable.

## Regression tests

Inputs that crashed belong in `tests/hostile_inputs.rs` at the repository root.
That file runs each known-bad shape in a child process on a 2 MiB thread with
a time budget and a peak-RSS cap:

```sh
cargo test --release --test hostile_inputs
```
