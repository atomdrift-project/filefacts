# Bash 5.3 case-inversion parser regression

`4a5376aa6c33.sh` is retained only as static parser input. Its SHA-256 is
`4a5376aa6c338480dd1c0e182db6c4388ed93f9e45fae0d7a482c23df082b218`.
The test parses it and checks source-backed offsets; it never executes it.
The sample uses Bash 5.3 `${parameter~~}` expansions that tree-sitter-bash
0.25.1 reports as syntax errors.
