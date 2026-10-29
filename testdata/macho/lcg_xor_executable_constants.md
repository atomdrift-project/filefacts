# lcg_xor_executable_constants.macho.zst

A real malicious universal (x86_64 + arm64) Mach-O, kept because it stores an
encrypted AppleScript in `__TEXT,__const`: data inside an executable segment,
which must not be counted as code. Never execute it or its decoded script.
No license (see `../README.md`).

- SHA-256: `a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1`
  (151,312 bytes uncompressed)
- Origin: in-the-wild specimen, identified by the SHA-256 above.
- Each slice holds five functions. Raw `__text` entropy is
  5.717601376712909 over 661 bytes (x86_64) and 5.982128755902718 over 748
  bytes (arm64).

## What the tests assert

`tests/macho_section_classification.rs` checks that:

- `binary.code_entropy` is computed over the real file spans of instruction
  sections only, not over constants that share the executable `__TEXT`
  segment;
- universal (FAT) slices are rebased once, leaving entropy unchanged;
- `S_ATTR_PURE_INSTRUCTIONS`, `S_ATTR_SOME_INSTRUCTIONS` and `S_SYMBOL_STUBS`
  mark instruction sections without relying on conventional section names,
  but never override a non-executable segment's permissions;
- in mutated copies, `S_ZEROFILL`, `S_GB_ZEROFILL` and
  `S_THREAD_LOCAL_ZEROFILL` sections report no file bytes, no entropy and no
  rebased offset;
- the PE and ELF execute flags are unaffected.
