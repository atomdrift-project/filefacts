# Obfuscated RTF object

`obfuscated-object.sample.zst` is a real malicious RTF document whose header
is deliberately malformed (no valid `{\rtf1`), so it reaches Word but not a
naive magic check, and which embeds two OLE objects through `\objdata`.
Stored zstd-compressed; never open it in a word processor. No license (see
`../../../testdata/README.md`).

- SHA-256 (uncompressed):
  `8dc06fc321e2e0f5b9a7795ae9dd79e95aefe51cb98beccb4bf1f467a8618156`
  (15,140 bytes)
- Origin: in-the-wild specimen, identified by the SHA-256 above.

## What the tests assert

- `recognizes_obfuscated_rtf_object_with_malformed_header`
  (`src/fileid/tests.rs`): it identifies as `rtf` by content heuristic under
  an unknown extension, while a lone `\object` marker in plain text does not.
- `parses_obfuscated_rtf_object_structure_after_malformed_header`
  (`src/formats/rtf.rs`): `rtf.features` includes `object` and `objdata`, and
  `rtf.objdata_count` is 2.
