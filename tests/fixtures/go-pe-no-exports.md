# go-pe-no-exports.exe.zst

Inert, empty Go program (windows/amd64, stripped) for the PE export view. Its
optional header declares no export directory (`ExportTableRVA: 0x0`), yet
rizin's `iEj` lists the `gopclntab` COFF symbol as a global export. Never
execute fixtures.

SHA-256 (uncompressed): `c11b4ceec83415c966fc31bd3a891d3e1d1395761ab551e8eabd7f7b65db4886`.
Built for this project from the source below (Apache-2.0); the binary also
contains the Go runtime (BSD-3-Clause).

`go_pe_without_export_directory_recovers_no_exports` (`src/rizin/tests.rs`,
skipped without rizin) asserts that rizin's functions are recovered but no
export reaches the export view, since Go PEs always take the rizin path.
`concurrent_opens_keep_their_own_rizin_settings` uses it as a small binary
rizin can analyse quickly.

Built with Go 1.27 from:

```go
// go.mod: module example.com/filefacts-fixture/go-pe-no-exports

// main.go
package main

func main() {}
```

```
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o go-pe-no-exports.exe .
zstd -19 -o go-pe-no-exports.exe.zst go-pe-no-exports.exe
```
