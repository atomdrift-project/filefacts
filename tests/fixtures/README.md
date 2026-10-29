# tests/fixtures

Inputs for the format extractors and integration tests. The fixture policy
and the license of real specimens are in [`../../testdata/README.md`](../../testdata/README.md).
Never execute a fixture.

## Documented individually

| Fixture | Kind | Provenance |
|---|---|---|
| `dropper.xib`, `dropper.nib`, `dropper-keyed.nib` | synthetic | [`dropper-nib.md`](dropper-nib.md) |
| `elf-syscall-wrapper-*.elf` | synthetic | [`elf-syscall-wrapper.md`](elf-syscall-wrapper.md) |
| `go-pclntab-names.zst` | synthetic | [`go-pclntab-names.md`](go-pclntab-names.md) |
| `go-pe-no-exports.exe.zst` | synthetic | [`go-pe-no-exports.md`](go-pe-no-exports.md) |
| `pe-xor-decoder.exe` | synthetic | [`pe-xor-decoder.md`](pe-xor-decoder.md) |
| `rtf/obfuscated-object.sample.zst` | real specimen | [`rtf/README.md`](rtf/README.md) |
| `apk/CERT.SF`, `apk/CERT.RSA` | generated | [`apk/generate.sh`](apk/generate.sh) (throwaway key) |
| `chains/*` | generated | [`chains/generate.sh`](chains/generate.sh) (throwaway keys) |

## Other fixtures

| Fixture | SHA-256 | What it is |
|---|---|---|
| `authenticode-digicert-tencent.p7b` | `bf53bb8b46292c5fbc6f83ef107095045686a37bf9b5a56bf057b32f1626ee4d` | Certificate bag of a real Authenticode signature: a Tencent leaf issued by DigiCert SHA2 Assured ID Code Signing CA. Public certificates only. |
| `authenticode-microsoft-root-authority-1997.p7b` | `b13815ee96dd3e286816f7fa8533ad502b84e577477d30820d5f562c58143a4f` | Certificate bag holding Microsoft Root Authority (1997), a root with no extensions. Public certificates only. |
| `base64.scpt` | `077c3045afe8cdad02c446b74f9bfd9cc736780b92a56114a6c3bd143d6a9ca4` | Compiled AppleScript with base64-encoded literals. |
| `stage4.scpt.zst` | `90afbc8e8c3f9ad84d663cb6ba17f60cc97cad23d39f2548bc3dfa752ed9a9c5` | Real obfuscated AppleScript stealer stage; tests check the recovered commands and targeted files. |
| `macho-darwin-variant-symbols.dylib.zst` | `87c5d0c93b80acf61d24e7aaf0faae231ab507ca45483ad3d441b5d1acebc43c` (uncompressed) | Real, already-public Mach-O malware whose `LC_SYMTAB` records libc calls under Darwin's `$`-variant names. |
| `managed-signed.dll`, `managed-unsigned.dll` | `07dee31dfb5dc246d558ab61c6bedd2a230b3aa5a86ce3e0a44f06ed8ba3da2b`, `12e477ab6a025ca701babb7ff902d485ad83f6b59aeff1fb838ece5eecd04202` | Tiny C# libraries built from one source, with and without `csc /keyfile`, for CLR strong-name extraction. |
| `test.exe`, `test.elf`, `test.macho` | `bc457d403feeab416d25aebaecf35b7d91aa9675a587eefe6ed237de290d5718`, `42308b675105f49b6ac8041d97a2fb3e34d94b12c4ab4da9d8cfcffb62c9033e`, `9752ef8af4114557677eb990ff6ba47d55ae58058591bc3993b88824b7e690bb` | Small benign executables (PE32+ x86-64, ELF x86-64 shared object, Mach-O x86-64) used as well-formed baselines and as the base for mutation tests. |
| `crx/test-rsa1024.pk8.der` | `01180fee1d7aa8e30a190706703bcb9b5b5e98ed09708611818a9c0f16529f19` | Throwaway RSA-1024 private key used only to sign CRX fixtures built in tests. |
| `../data/certificate-signature.sig` | `122f60c45a53704462050457d7639598e54741bbfa6c9b3f70407cd16e052eea` | A certificate-framed signature file of the kind shipped beside a signed library (`libwidevinecdm.dylib.sig`); must not be mistaken for OpenPGP. |
