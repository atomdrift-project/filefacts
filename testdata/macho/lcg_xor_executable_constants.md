# Mach-O instruction and executable-data distinction

SHA256: a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1

Malicious universal Mach-O; static analysis only. Both slices contain five
functions and an encrypted AppleScript in __TEXT,__const. The execute
permission on __TEXT covers data too; constants must not contribute to
binary.code_entropy. Preserve segment permissions and mark instruction
sections from S_ATTR_PURE_INSTRUCTIONS/S_ATTR_SOME_INSTRUCTIONS or S_SYMBOL_STUBS.

Raw __text entropy: x86_64 5.717601376712909 (661 bytes), ARM64
5.982128755902718 (748 bytes). Code entropy also includes instruction stubs.
Do not execute this fixture or its decoded script.

`tests/macho_section_classification.rs` checks independent entropy, instruction
attributes, FAT provenance, segment permissions, and PE/ELF conventions.
Mutations of this original fixture cover S_ZEROFILL, S_GB_ZEROFILL and
S_THREAD_LOCAL_ZEROFILL in thin and universal inputs: virtual size remains,
file size/offset are zero, and no header-byte entropy span is emitted.
