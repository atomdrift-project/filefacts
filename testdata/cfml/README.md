# CFML webshells

Real ColdFusion webshells, kept because the CFML tokenizer, expression parser
and flow producer are tested against what attackers actually deploy. Stored
zstd-compressed; never execute them. No license (see `../README.md`).

| Fixture | SHA-256 (uncompressed) | Bytes |
|---|---|---|
| `datasource_shell.cfm.zst` | `987de3c74aaa5371c98365b281fdc3c4b680558aae5b4c9895ec6b8c9fc083d2` | 2,111 |
| `encrypted_shell_original.cfm.zst` | `c28894e4ab24d142a072fdbfddde4dfbfcaba9bfc741a00e935e596ac8c2b3d3` | 20,766 |
| `encrypted_shell_decoded.cfm.zst` | `110db2340e0aecb5c59d73b15617b28999d941f974ae04acf4d53ddcf945e9dc` | 20,626 |
| `implicit_command_shell.cmf.zst` | `29777403e2f3cd010ff179b71233137fe75379b0fc3b7f7b2932bb6af94a0dd9` | 803 |

Origin: in-the-wild specimens, identified by the SHA-256 above.
`encrypted_shell_decoded.cfm` is derived, not collected: it is the plaintext
of `encrypted_shell_original.cfm` (an Allaire-encrypted template), decoded
independently of filefacts.

## What the tests assert

- **`datasource_shell.cfm`**: command execution plus ColdFusion datasource
  password decryption. Tests check the `cfexecute` tag at byte 878, the
  `CreateObject` datasource-service call chain, that argument 0 of `Decrypt`
  reads `datasourceobb[*].password`, the `decryptPassword` assignment offset
  and its flow into `writeOutput`, that the `<cfscript>` body keeps its range
  with the closing `CFOUTPUT` after it, and the `cmd`/`opts`/`timeout`
  controls behind a conditional attribute suffix.
- **`encrypted_shell_original.cfm`**: the ciphertext is reported as
  unavailable encrypted syntax and is never tokenized as tags.
- **`encrypted_shell_decoded.cfm`**: a password-protected command and file
  manager. Tests check the `cfexecute` tag at byte 12558, the
  `IsDefined(session.in)` condition, the password binding and comparison, the
  Java request-parameter chain and `Replace`-based write path, all three
  `CFFILE` read-result bindings, the directory-create call carrying both
  `Form.dir` and `Form.cr_dir`, and the `FileContent`, `CFHEADER` and
  `CFCONTENT` response offsets.
- **`implicit_command_shell.cmf`**: a guarded `cmd.exe` shell. The test traces
  the unscoped command argument inside its `Form` existence guard and checks
  that the implicit scope resolution is marked runtime-dependent.

Synthetic tests beside these cover the general cases (comments and strings,
quoting, limits, malformed and truncated input); these files supply the
real-world shapes.
