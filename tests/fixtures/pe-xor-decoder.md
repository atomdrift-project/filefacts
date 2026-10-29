# pe-xor-decoder.exe

Inert synthetic x86 PE for instruction-guided XOR string recovery. It holds
a tiny XOR decoder, a 21-byte key, and encrypted API-name and example-URL
strings, and imports nothing. Never execute fixtures.

SHA-256: `138a847d7722b7bb40cff3803071a8ef6efa269508a7ee6ac6f62c2eb6b02cc5`.
Written for the [stng](https://github.com/atomdrift-project/stng) project,
which generates it in its `pe_xor::tests::fixture`:

```
STNG_XOR_FIXTURE_OUT=pe-xor-decoder.exe cargo test --lib pe_xor::tests::benchmark_prefilter_and_recovery -- --ignored
```

`pe_instruction_xor_strings_keep_provenance_across_snapshot` (`src/tests.rs`)
asserts that `InternetReadFile` reaches the text view as an `XorDecode`
string with source spans `(0x800, 16)` (ciphertext) and `(0x600, 21)` (key),
that `ShellExecuteW` is recovered too, that no recovered name is promoted to a
PE import, and that all of this survives a cache snapshot round-trip.
