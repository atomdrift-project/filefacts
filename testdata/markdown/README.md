# Markdown identification regression specimens

Original, unchanged README members from naatin777.latex-graphics-helper 0.4.0. Exact archive member paths and SHA-256 digests are in provenance.json. The archive is retained in the triage input pool; the four documents are retained here to reproduce the engine bug without requiring the archive.

Before the repair these Markdown documents were identified as JavaScript because of fenced examples. This produced execution and endpoint findings from documented npx commands, example HTTP proxies, and a debug hex-formatting example.

Tests in src/fileid/markdown.rs cover original fixtures, ATX/Setext headings, BOM/CRLF, backtick/tilde fences, mismatched/short/indented/trailing-text closing fences, renamed real source, shebang/binary precedence, truncation and the 16 KiB window. The detector is a bounded shape check, not a full Markdown parser. It only runs for Markdown extension candidates after magic/shebang detection. Language evidence before the first fence retains source detection.
