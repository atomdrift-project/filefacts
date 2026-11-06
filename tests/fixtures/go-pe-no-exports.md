# go-pe-no-exports.exe.zst

Inert, empty Go program (windows/amd64, stripped) for the PE export view. Its
optional header declares no export directory (`ExportTableRVA: 0x0`), so no
export may be reported for it. Never execute fixtures.

SHA-256 (uncompressed): `c11b4ceec83415c966fc31bd3a891d3e1d1395761ab551e8eabd7f7b65db4886`.
Built for this project from the source below (Apache-2.0); the binary also
contains the Go runtime (BSD-3-Clause).

Go's PE linker folds the pclntab into `.rdata`, with no section of its own.
`a_stripped_go_pe_finds_its_pclntab_in_rdata`
(`src/formats/go_pclntab/tests.rs`) asserts that all 1,415 functions are found
there, that binform's function recovery never runs, and that the export view
stays empty.

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
