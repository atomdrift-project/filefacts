# Edit allowlist for implementing agents (filefacts)

The proposer hands ideas to a coding-agent (gemini by default) which
edits files inside the worktree. The agent has wide latitude in *how*
to realize an idea, but the following boundaries are enforced.

## May edit

- `src/**/*.rs`
- `Cargo.toml`
- `Cargo.lock` (let cargo regenerate after dep changes)
- Anywhere under a Rust source tree the proposer named explicitly via `hints`.

## Must not edit

- `tests/**` — never weaken test coverage to make a perf change pass.
- `.github/**` — CI changes are out of scope.
- `Makefile` — bench targets are the contract; changing them invalidates the measurement.
- `benches/**` if added later — same reasoning as tests.
- `vendor/**` if added later — vendored sources are locked.

## Trigger an auto-revert

`cleave-tuna` reverts the experiment without benchmarking if:

- `cargo check` fails.
- `cargo test --lib` fails.
- The agent produced no changes after its run.
- Diff touches any path in the "must not edit" list.

## filefacts-specific guardrails

- The `#[global_allocator]` declaration in `src/bin/filefacts.rs` is
  load-bearing for heap profiling. Tuna's memory-mode hotspot data
  depends on `tikv_jemallocator::Jemalloc` being the active allocator
  with the `jemalloc-prof` feature available. Don't replace it.
- The directory walk in `src/bin/filefacts.rs::main` is what
  cleave-tuna's bench invocation exercises. Refactoring it is fine;
  removing the `root.is_dir()` branch would break the bench.
- The public typed views in `src/lib.rs` (`ParsedFile<'a>`, `FileId`,
  `Values`, `Strings`, `Metrics`, `Ast`, `Sections`, `Imports`,
  `Exports`, `Functions`, `Errors`) are the contract external
  consumers (cleave, litmus) bind to. Internal restructuring is fine;
  changing the public surface will fail integration.
- The README's "no external commands" rule is load-bearing. Don't
  add subprocess calls; the existing rizin path is the one allowed
  exception.
