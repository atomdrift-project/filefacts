# DOS COM viruses

Real DOS COM viruses, kept because identifying a headerless COM program from
its code shape is the point of the tests. Stored zstd-compressed; never
execute them. No license (see `../README.md`).

| Fixture | SHA-256 (uncompressed) | Bytes |
|---|---|---|
| `anton-97.zst` | `d5cb77880c6cc5d9c05df276ee35d4b273ad85a6f5702126544316066998ebb1` | 5,120 |
| `nostardamus-1870.zst` | `5298db2f904e81c7ecb0a78c03ea8917f65405c03bd0a6451fe002a5fd24353e` | 3,970 |

Origin: public virus collections, where they are named
`Virus.DOS.Trivial.Anton.97` and `Nostardamus.1870`.

## What the tests assert

- **`anton-97`**: a 97-byte overwriter padded to 5,120 bytes. Under its
  collection name it identifies as `dos_com` by heuristic, with a consistent
  extension; a synthetic blob with the same `*.COM` string and a lone
  `int 21h`/`int 20h` does not.
- **`nostardamus-1870`**: its self-modifying XOR-decoder entry identifies as
  `dos_com` without a `.com` extension.
