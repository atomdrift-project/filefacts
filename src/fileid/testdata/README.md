# File identification fixtures

Small inputs for unit tests under `src/fileid/`. See `testdata/README.md` for
the fixture policy. None is run; the identification tests only read them.

| File | SHA-256 (of the file as stored) | Origin | What the tests assert |
|---|---|---|---|
| `LICENSE` | `dccb58c694c31ac7fc026b3e3b1019c277696eff92e0e11badb4d795b54ed262` | Synthetic | A file named `LICENSE` whose text contains `===` stays text (`tests/names.rs`) |
| `go-module-stream.zip` | `fb362c1d7e4f1aa01369cae0645c3f0cb7e0dfa2cb0e2d0e42a77ee40d88251f` | Synthetic: two 14-byte members under `example.com/hello@v1.2.3/`, written by Go's `archive/zip` with data descriptors | A Go module zip is recognised from its central directory although the local headers carry zero sizes (`go_module/tests.rs`) |
| `php-backdoor.txt.zst` | `ded7bdb14f9cf7a9af99be04a6ca97273b4443af48e7d5af910268eb660d0ff5` | **Real specimen**, zstd-compressed: the public "Php Backdoor v 1.0" webshell saved as `.txt`. Source collection to be documented | A saved webshell that also embeds `document.write` is PHP, not text or JavaScript (`tests/languages.rs`) |
| `pkgbuild-first.tar` | `1793ad2a90f05f3ae0da1edf032db9c18e87790b41fb27be0bfe6f57a36f127f` | Synthetic: a tar of a 52-byte `PKGBUILD` and a 79-byte `.SRCINFO` | A tar whose first member is `PKGBUILD` is not called a zip from its file name (`tests/packages.rs`) |
| `tiny-avif.avif` | `fca97d4fcc8adaf8ea3acc10180f7600beaf092081274972afcb7e7f64490442` | A minimal AVIF image; generator to be documented | AVIF identification (`tests/documents.rs`) |
| `tiny-tiff.tif` | `9578b01a7393fd026d9408787ce58c9b830dfaff091fcf175f5c4bececcd5e2d` | A minimal little-endian TIFF with a deflated strip; generator to be documented | TIFF identification (`tests/documents.rs`) |
| `tiny-image4-trustcache.im4p` | `f37d029ab341f3807e20835f181fa7722500945234a983088d4a09588460c84e` | An IM4P container of type `trca` (an Apple trust cache); origin to be documented | The IM4P/trust-cache parse, its detection under any name, and that no truncation panics (`image4_trustcache/tests.rs`) |
| `tiny-perl-shell-shim.pl` | `719723331db6446c6c142c3c5f95701c32e6f87b9860024d2e5306599ff640b4` | Third-party, unmodified: a gprofng test script from GNU Binutils, Copyright (C) 2021-2023 Free Software Foundation, Inc., licensed GPL-3.0-or-later (see its header and `NOTICE`) | A `#!/bin/sh` file that re-executes itself under Perl is Perl, without a false shebang mismatch (`perl_shell_shim/tests.rs`) |
| `tiny-torchscript.pt` | `c553ae8da1c2f11fdf83dcfaefe60e9d037043fd31b47fb2f12deef8fb0ef0fd` | A TorchScript archive whose members are named `test_versioned_div_tensor_out_v3/…`, the name of a PyTorch operator-upgrader test model; exact source to be documented | A TorchScript zip keeps its zip type without a suffix mismatch (`torch/tests.rs`) |
| `tiny-torchscript.debug_pkl` | `10ffdc334bad127f2c4a931af5e8bc2b24b751c3016a3e70affe50ebf5044368` | The `code/__torch__.py.debug_pkl` member of `tiny-torchscript.pt` | A TorchScript debug pickle is recognised on its own (`torch/tests.rs`) |
