# Bash 5.3 case-inversion script

`4a5376aa6c33.sh.zst` is a real obfuscated shell script, kept because it uses
Bash 5.3's `${parameter~~}` case-inversion expansion, which stock
tree-sitter-bash rejects as a syntax error. Stored zstd-compressed; never run
it. No license (see `../../README.md`).

- SHA-256 (uncompressed):
  `4a5376aa6c338480dd1c0e182db6c4388ed93f9e45fae0d7a482c23df082b218`
  (152,326 bytes)
- Origin: in-the-wild specimen, named by its SHA-256 prefix.
- Test: `bash_53_obfuscated_shell_regression_parses_without_losing_original_offsets`
  in `src/formats/source/parse/tests.rs`. The script parses with no error
  node, the AST's source text is the original byte for byte, and exactly two
  case-inversion expansions are found.
