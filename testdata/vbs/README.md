# Script wrapper

`balala-wrapper.sample.zst` is a real malicious script: JavaScript wrapped for
a Windows script host, with comments and indentation that a naive scorer
reads as a Makefile. Stored zstd-compressed; never run it. No license (see
`../README.md`).

- SHA-256 (uncompressed):
  `14a73c73e57496409d5219f62baeefa9dbd28e7da6c0a0b0e8bd6018f2c7451d`
  (6,449 bytes)
- Origin: in-the-wild specimen, identified by the SHA-256 above.
- Test: `javascript_comment_and_indented_code_do_not_look_like_makefile` in
  `src/fileid/tests.rs`. It identifies as `javascript`; a synthetic function
  with a `//post:` comment and tab-indented call is not `makefile`.
