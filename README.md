# filefacts

A Rust library that reads a file and tells you what is in it. Extracted from
[cleave](https://codeberg.org/atomdrift/cleave) for people who build feature
extraction into ML security pipelines — malware classifiers, triage systems,
anything that needs a dense, honest description of a file as input. If you
simply want to understand a file, it serves you just as well.

Give it bytes. It identifies the format, parses it once, and returns a
`ParsedFile` with lazy, cached views: `fileid`, `values`, `text`, `literals`,
`comments`, `metrics`, `sections`, `symbols`, `archive_members`, `source_ast`,
and `errors`. Read what you want; the rest costs nothing. `filefacts <path>`
writes the same as JSON, ready to fold into a feature vector.

## Install

```bash
make install                              # build + install via cargo

brew tap atomdrift/tap                     # one-time, macOS / Linux
brew install filefacts
```

`make install` builds the release binary and copies it to the first writeable
location on your `PATH`. As a library, add `filefacts = "1.0"` to `Cargo.toml`.

```bash
filefacts suspect.bin       # JSON facts for one file
filefacts /tmp/samples      # recurse a directory
```

## What it parses

- Executables: PE, ELF (with DWARF), Mach-O, Java class, Python bytecode.
- Archives: zip, tar (+ gz/bz2/xz/zst), 7z, rar, deb, rpm, pkg, cab, CHM, CRX,
  XPI, WHL, JAR, VSIX.
- Documents: PDF, RTF, OOXML, OLE2 (legacy Office, MSI, MSG), LNK, plist,
  AppleScript. Authenticode is verified in-process with pure-Rust crypto.
- Images: JPEG, PNG — marker/chunk metadata plus per-channel entropy, edge
  density, and histogram flatness for stego detection.
- Structured: JSON, YAML, TOML, XML, pickle, Dockerfile, Makefile, systemd
  units, .desktop, GitHub Actions, package manifests.
- Source AST via tree-sitter (JavaScript, TypeScript, Python, Go, Rust, Java,
  C, C#, Bash, Ruby, Lua, Scala, Objective-C, Kotlin, Swift, PowerShell, PHP).

The features discriminate: entropy and string statistics, section layout,
import and symbol tables, signature validity, extension mismatches — the
signals that separate benign files from the things they imitate. In-process by
default: no shelling out to `file`, `objdump`, `openssl`, or `tar`. One pass
per file; views cached on disk as zstd-compressed bincode keyed by sha256.
