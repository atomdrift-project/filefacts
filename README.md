# filefacts

A Rust library that reads a file and tells you what is in it. Extracted from
[cleave](https://codeberg.org/atomdrift/cleave) for the data scientist who
wants rich features out of the file types malware likes to hide in.

Give it bytes. It identifies the format, parses it once, and returns a
`ParsedFile` with lazy, cached views: `fileid`, `values`, `strings`, `metrics`,
`sections`, `imports`, `exports`, `functions`, `ast`, `errors`. Read what you
want; the rest costs nothing. `filefacts <path>` writes the same as JSON.

What it parses:
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
  C, C#, Bash, Ruby, Lua, Scala, Objective-C, Kotlin, Swift, PowerShell, PHP):
  calls, members, imports, functions, classes.

Rules: in-process by default — no shelling out to `file`, `objdump`, `openssl`,
`tar`, and no crates that do. The lone exception is rizin, sandboxed with
RLIMIT, PR_SET_PDEATHSIG, and process-group kill, and disable-able at runtime.
One pass per file; views computed on demand and cached on disk as
zstd-compressed bincode keyed by sha256. Names match the spec — no filler.
