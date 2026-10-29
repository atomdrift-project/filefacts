# Contributing to filefacts

Thanks for helping. filefacts parses hostile input, so the bar is
correctness first: every change should leave the library unable to panic,
hang or allocate without bound on any file. Security problems go through
[SECURITY.md](SECURITY.md), not the issue tracker.

## Building

You need Rust 1.97 or newer (`rust-version` in `Cargo.toml`) and a C/C++
toolchain for the tree-sitter grammars. The Makefile wraps cargo and works
with GNU make and BSD make:

```sh
make            # debug build
make test       # cargo test
make lint       # rustfmt --check, then clippy --all-targets --all-features -D warnings
make fix        # apply clippy's fixes, then rustfmt
make release    # optimized binary in out/
```

rizin is optional. Tests that need it skip themselves when it is not
installed; install it to exercise them.

## Before you send a change

`make lint` and `make test` must pass; CI runs both on Linux, macOS and
Windows. `make install-hooks` installs a pre-commit hook that runs them for
you and also rejects a `Cargo.toml` with a `path` dependency outside the
repository.

Some tests are slow or need a release build and are not part of `make test`:

```sh
cargo test --release --test hostile_inputs   # time and memory budgets
cargo test --release -- --ignored            # CPU-saturating cases
```

To test a change against a project that depends on filefacts, point that
project at your checkout from the command line instead of editing its
manifest:

```sh
cargo build --config 'patch."https://github.com/atomdrift-project/filefacts".filefacts.path="../filefacts"'
```

## Code

- **Untrusted bytes.** Index with `get`, `first_chunk` or the helpers in
  `crate::bytes`, never `buf[i]`; clippy's `indexing_slicing` enforces this
  outside tests. Casts that can truncate a file-supplied value go through
  `try_from` or the saturating helpers. Every loop, recursion and allocation
  driven by the input has an explicit cap.
- **Degrade, don't fail.** A malformed or oversized input produces an
  `Errors` diagnostic or a recorded limit and whatever facts are still
  sound. Never a panic, and never a silent early return.
- **Logging.** Use `tracing` with structured fields (`format`, `stage`,
  `offset`, `len`, `error`) rather than formatted strings. The library only
  emits events; the host chooses a subscriber.
- **No environment reads in the library.** Configuration arrives through
  `OpenOptions`; the CLI maps environment variables onto it.
- **Comments describe the code as it is.** No change history ("used to",
  "previously", dates), no names of downstream projects or internal tickets,
  and no anecdotes about particular samples. History belongs in
  [CHANGELOG.md](CHANGELOG.md) and commit messages; a consumer's needs are
  stated as the contract they rely on.
- **`unsafe`** is denied crate-wide. The few process-control calls that need
  it carry a scoped `#[allow(unsafe_code)]` and a `// SAFETY:` comment.

## Tests

- A module `foo.rs` keeps its unit tests in `foo/tests.rs`, declared as
  `#[cfg(test)] mod tests;`. Integration tests live in `tests/`.
- Assert behaviour, not timing: prefer work counts or budget steps over
  wall-clock limits, which flake under a loaded parallel test run.
- Open files hermetically in tests, with
  `OpenOptions::new().cache(false).rizin(false)` unless the test is about the
  cache or rizin.
- An input that crashed or hung belongs in `tests/hostile_inputs.rs`.

## Fixtures

Fixtures live in `testdata/` and `tests/fixtures/`; the policy is in
[testdata/README.md](testdata/README.md). In short:

- Prefer synthetic fixtures built in the test or by a checked-in generator.
- Use a real specimen only when it is the point of the test, store it
  zstd-compressed (`<name>.zst`) and decompress it in memory in the test.
- Every real specimen has a README entry with the SHA-256 of the
  uncompressed file, its origin, its license, and what the test asserts.
- Never execute a fixture.

## Fuzzing

`fuzz/` holds cargo-fuzz targets; see [fuzz/README.md](fuzz/README.md).
`make fuzz FUZZ_TARGET=pdf` runs one with memory and time limits (nightly
toolchain and `cargo install cargo-fuzz` required).

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
