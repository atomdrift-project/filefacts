# Vendored: tree-sitter-clojure

This directory is the crates.io package
[`tree-sitter-clojure` 0.1.0](https://crates.io/crates/tree-sitter-clojure/0.1.0),
the Rust binding published from
<https://github.com/jerielverissimo/tree-sitter-clojure>, packaged from commit
`6248a3f3d3c76ec7d33c52e7553761facdcb4ab5`.

`grammar-src/` is the grammar itself, a git submodule of that repository
pointing at [sogaiu/tree-sitter-clojure](https://github.com/sogaiu/tree-sitter-clojure)
v0.0.13 (2024-05-15). It is unmodified.

## Licenses

- Rust binding (`src/lib.rs`, `build.rs`, manifest): MIT, as published.
- Grammar (`grammar-src/`): CC0 1.0, see `grammar-src/COPYING.txt`.

## Changes from upstream

The only functional change: the `tree-sitter` dependency is `0.28` instead of
`0.25.6`, because filefacts uses tree-sitter 0.28 and `links = "tree-sitter"`
permits only one copy in a build. The grammar binds through
`tree-sitter-language`'s `LanguageFn` ABI, and its `parser.c` (ABI 14) loads
unchanged under 0.28.

Packaging cleanups, with no effect on the built library:

- `Cargo.toml` is hand-written instead of cargo's normalized form, with
  `publish = false` and both licenses declared.
- `build.rs` is trimmed to the C compile, and the static library is named
  `tree-sitter-clojure` instead of `parser`.
- Packaging artifacts (`.cargo-ok`, `.cargo_vcs_info.json`,
  `Cargo.toml.orig`, `.gitmodules`, `Cargo.lock`) are removed.

## Updating

Replace `src/` and `grammar-src/` from a new upstream release, then re-apply
the tree-sitter version in `Cargo.toml` and record the new commit here. Drop
the vendored copy once a crates.io release supports the tree-sitter version
filefacts uses.
