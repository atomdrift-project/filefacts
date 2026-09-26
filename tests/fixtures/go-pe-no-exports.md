# go-pe-no-exports.exe.zst

Inert, empty Go program (windows/amd64, stripped) for the PE export-view
regression. Its optional header declares no export directory
(`ExportTableRVA: 0x0`), yet rizin's `iEj` reports the `gopclntab` COFF symbol
as a global export. Go PEs always take the rizin path for function recovery, so
before 2026-09-26 that phantom export reached the export view and every Go
Windows binary read as "exports one symbol". Never execute fixtures.

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
