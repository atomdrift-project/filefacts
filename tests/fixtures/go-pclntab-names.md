# go-pclntab-names.zst

Inert synthetic Go program (linux/amd64, stripped) for Go function-name
recovery. Its functions live in a package with a deliberately long module
path, so their pclntab names run 105-267 bytes, and one generic helper is
instantiated over `cipher.Block` and `cipher.AEAD`, so its names carry
`{ } ;` type-shape characters. Never execute fixtures.

SHA-256 (uncompressed): `1a15a5bbb36a652b631ceef1c3fd9fd4087b66a6412a94e0d82c4256547137cf`.
Built for this project from the source below (Apache-2.0); the binary also
contains the Go runtime (BSD-3-Clause).

`go_recovery_names_pclntab_functions` (`src/rizin/tests.rs`, skipped without
rizin) asserts that rizin recovers more than 1,000 functions, that fewer than
10% stay unnamed `fcn.*`, and that `OpenSealedPayload`, `ReportLength` and
`mustValue` come back by name. That holds only when the Go analysis script
runs `aalg` (pclntab names) before `aa; aac`. The long and generic names
also exercise stng's funcnametab splitter, which must keep names over 80
bytes and names with generic shapes.

Built with Go 1.27 from:

```go
// go.mod: module example.com/atomdrift/filefacts-fixture/deliberately/long/module/path

// internal/sealedpayload/open.go
package sealedpayload

import ("crypto/aes"; "crypto/cipher"; "fmt")

//go:noinline
func mustValue[T any](v T, err error) T { if err != nil { panic(err) }; return v }

//go:noinline
func OpenSealedPayload(key, sealed []byte) []byte {
	block := mustValue(aes.NewCipher(key))
	aead := mustValue(cipher.NewGCM(block))
	n := aead.NonceSize()
	return mustValue(aead.Open(nil, sealed[:n], sealed[n:], nil))
}

//go:noinline
func ReportLength(b []byte) { fmt.Println(len(b)) }

// main.go
package main
import ("os"; "example.com/atomdrift/filefacts-fixture/deliberately/long/module/path/internal/sealedpayload")
func main() {
	if len(os.Args) > 3 {
		sealedpayload.ReportLength(sealedpayload.OpenSealedPayload([]byte(os.Args[1]), []byte(os.Args[2])))
	}
}
```

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o go-pclntab-names .
zstd -19 -o go-pclntab-names.zst go-pclntab-names
```
