//! Real CFML webshell specimens from `testdata/cfml`, stored zstd-compressed
//! so the plaintext never sits in the tree. Each is decoded once per test
//! process.

use std::sync::LazyLock;

macro_rules! specimen {
    ($(#[$doc:meta])* $name:ident, $file:literal) => {
        $(#[$doc])*
        pub(super) fn $name() -> &'static [u8] {
            static BYTES: LazyLock<Vec<u8>> = LazyLock::new(|| {
                zstd::decode_all(
                    &include_bytes!(concat!("../../../testdata/cfml/", $file, ".zst"))[..],
                )
                .expect("specimen is valid zstd")
            });
            &BYTES
        }
    };
}

specimen!(
    /// Command execution plus datasource credential decryption; SHA-256
    /// `987de3c7…83d2`.
    datasource_shell,
    "datasource_shell.cfm"
);
specimen!(
    /// The decoded plaintext of [`encrypted_shell_original`]; SHA-256
    /// `110db234…e9dc`.
    encrypted_shell_decoded,
    "encrypted_shell_decoded.cfm"
);
specimen!(
    /// An Allaire-encrypted template, ciphertext only.
    encrypted_shell_original,
    "encrypted_shell_original.cfm"
);
specimen!(
    /// A cmd.exe shell whose command argument is an unscoped name inside a
    /// Form existence guard.
    implicit_command_shell,
    "implicit_command_shell.cmf"
);
