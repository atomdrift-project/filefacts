# go-pclntab-names.zst

Inert synthetic Go program (linux/amd64, stripped) for Go function-name
recovery tests. Its functions live in a package with a deliberately long module
path, so their pclntab names run 105-267 bytes, and one generic helper is
instantiated over `cipher.Block` and `cipher.AEAD`, so its names carry
`{ } ;` type-shape characters. Never execute fixtures.

It covers two regressions:

- rizin's Go script must run `aalg` before `aa; aac`. In the old order `aalg`
  left every function `aa` had already created as `fcn.*` (1,514 of 2,082 here,
  and none of the five `sealedpayload` functions named); `aalg` first leaves
  ~40 unnamed and names all five.
- stng's funcnametab splitter must keep names over 80 bytes and with generic
  shapes (it dropped them, and their neighbours, before 2026-09-24).

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
