# Compiled HTML Help files

Used by `chm_overlay_uses_archive_data_and_directory_extents` in
`src/tests.rs`. Never open them in a help viewer. No license (see
`../README.md`).

| Fixture | SHA-256 | Bytes | Test asserts |
|---|---|---|---|
| `overlay-persistence-sample.chm.zst` | `e0b131332683a6e8841853c2c898ae0bd8b3015a2e95297727591427ba483605` | 231,294 | `binary.has_overlay` = 1 and `binary.overlay_size` = 1546: bytes after the last CHM extent are an overlay |
| `directory-at-end.chm` | `7a5d74a471e4f354c0ec1e233a77454d28838985d182f6eb49e57c9ccd7070e8` | 96,022 | No overlay: the directory stored after the compressed stream is archive content, not a suffix |

Origin: in-the-wild files, identified by the SHA-256 above.
