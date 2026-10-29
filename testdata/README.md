# Test fixtures

Fixtures live here (`testdata/`), in `tests/fixtures/` and `tests/data/`, and,
for a few unit tests, next to the module under `src/**/testdata/`. Each
directory or fixture has a README recording its provenance.

## Policy

- **Synthetic first.** A fixture that only needs a shape (a header layout, a
  table, a malformed length) is built in the test or by a checked-in
  generator script, never copied from the wild.
- **Real specimens only when they are the point of the test.** Some behaviour
  can only be shown on real input: an obfuscator's actual output, a
  compiler's real layout, a parser bug a specific file triggers. Those files
  are kept, unmodified.
- **Real specimens are stored zstd-compressed**, as `<original name>.zst`,
  and the test decompresses them in memory. That keeps working malware out of
  the checked-out tree, where on-access scanners would quarantine it and
  packagers would reject the repository.
- **Never executed.** filefacts never runs its input, and no test, script or
  build step runs a fixture. Do not run them yourself; analyse them only in an
  environment suited to handling malware.
- **Provenance for every real specimen**: the SHA-256 of the *uncompressed*
  file, where it came from, its license, and what the test asserts.

## License of real specimens

Malware specimens are third-party works with no license. They are not
covered by this project's license and are redistributed unmodified, solely as
inert input for static-analysis tests. Benign third-party files carry their
own upstream license, noted beside them.

## Index

| Directory | Contents |
|---|---|
| `cfml/` | ColdFusion webshells (real) for the CFML tag, expression and flow parser |
| `chm/` | Compiled HTML Help files for overlay and directory-extent accounting |
| `dos-boot/` | A FAT boot-sector virus (real) for boot-sector identification |
| `dos-com/` | Two DOS COM viruses (real) for COM identification |
| `macho/` | A universal Mach-O (real) for section and entropy classification |
| `markdown/` | Third-party READMEs that once misidentified as source code |
| `shell/` | An obfuscated Bash 5.3 script (real) for parser coverage |
| `vbs/` | A JavaScript-in-VBS wrapper (real) for script identification |
| `../tests/fixtures/` | Executables, signatures and documents for format extractors |
