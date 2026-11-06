# go-macho-arm64.zst

Inert, empty Go program (darwin/arm64, stripped) for reading Go's function
table out of `__TEXT,__gopclntab`. Never execute fixtures.

SHA-256 (uncompressed): `1b1ee5be2fb85396128062e800127c3cb67473aed2c434271e755ae42c00a4c4`.
Built for this project from the source below (Apache-2.0); the binary also
contains the Go runtime (BSD-3-Clause).

`a_stripped_go_macho_reads_its_functions_from_the_pclntab`
(`src/formats/go_pclntab/tests.rs`) asserts that all 1,435 functions come
from the pclntab and that binform's function recovery never runs. Go 1.27 writes the pclntab
header's text-start word as zero, so the entries resolve only against the
image's own `__text` section.

Built with Go 1.27 from:

```go
// go.mod: module example.com/filefacts-fixture/go-macho

// main.go
package main

func main() {}
```

```
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o go-macho-arm64 .
zstd -19 -o go-macho-arm64.zst go-macho-arm64
```
