# FAT boot-sector virus

`shimmer-boot-sector.d.zst` is a real 512-byte infected FAT boot sector, kept
because recognising a valid boot sector from its BPB and code is the point of
the test. Stored zstd-compressed; never write it to a disk or boot it. No
license (see `../README.md`).

- SHA-256 (uncompressed):
  `f07c78bef2de3da5e3113a6c1e8ed97a1bb6430c7d7dfd53185597496f503d99`
- Origin: public virus collections, where it is named
  `Virus.Boot-DOS.Shimmer`.
- Test: `shimmer_fat_boot_sector_is_recovered_as_analyzable_data` in
  `src/fileid/tests.rs`. The sector identifies as `data` by heuristic, so it
  is analysed rather than skipped; a synthetic 512-byte block that only ends
  in the `55 AA` signature does not.
