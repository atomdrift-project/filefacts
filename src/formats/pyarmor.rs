//! Static recovery of the reviewed PyArmor 8/9 container and code-object layouts.
//! No Python objects, native runtime or specimen code is executed. GCM's
//! counter stream is decoded and checked structurally; this is not tag authentication.
use crate::bytes::{u16_le, u32_le};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use md5::{Digest, Md5};

/// Recovered outer container. Its marshal stream can still contain protected
/// instruction bytes; recovery is not full Python deobfuscation or authentication.
#[derive(Debug)]
pub struct Recovery {
    /// Decrypted 32-byte container header followed by the marshal stream.
    pub container: Vec<u8>,
    /// CPython magic from the protected container, when recognizable.
    pub python_magic: Option<[u8; 4]>,
    key: [u8; 16],
}

/// A normalized marshal snapshot for static analysis, never execution.
#[derive(Debug)]
pub struct RecoveredPyc {
    /// PYC header and normalized marshal bytes, for static analysis only.
    pub data: Vec<u8>,
    /// Number of root and nested code objects parsed.
    pub code_objects: usize,
    /// Number of instruction regions decrypted.
    pub decrypted_regions: usize,
    /// Nonempty when protection remains beyond the recovered instructions.
    pub limitations: Vec<&'static str>,
}

#[path = "pyarmor/marshal.rs"]
mod marshal;

impl Recovery {
    /// Normalize PyArmor's extra marshal fields and recover nested instruction
    /// regions. Unsupported versions/layouts fail closed; known remaining
    /// protection is described in `limitations`. This is an analysis snapshot,
    /// not a runnable or authenticated reconstruction of the original program.
    ///
    /// # Errors
    /// Returns an error for unsupported versions, malformed marshal data,
    /// or exhausted parsing budgets.
    pub fn pyc(&self) -> Result<RecoveredPyc, &'static str> {
        let magic = self.python_magic.ok_or("missing CPython magic")?;
        let word = u16::from_le_bytes([magic[0], magic[1]]);
        let minor = match word {
            3400..=3413 => 8,
            3420..=3425 => 9,
            3430..=3439 => 10,
            3450..=3495 => 11,
            3500..=3531 => 12,
            3550..=3571 => 13,
            3627 => 14,
            _ => return Err("unsupported CPython marshal version"),
        };
        let body = self.container.get(32..).ok_or("truncated outer header")?;
        let mut recovered = marshal::normalize(body, minor, &self.key)?;
        let mut data = Vec::with_capacity(16 + recovered.data.len());
        data.extend_from_slice(&magic);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&recovered.data);
        recovered.data = data;
        Ok(recovered)
    }
}

/// Recognize a runtime serial without assuming the default all-zero license.
pub fn is_container(bytes: &[u8]) -> bool {
    bytes.get(..8).is_some_and(|b| {
        b.strip_prefix(b"PY")
            .is_some_and(|serial| serial.iter().all(u8::is_ascii_digit))
    })
}

fn span(b: &[u8], at: usize, n: usize) -> Option<&[u8]> {
    b.get(at..at.checked_add(n)?)
}
fn ctr(data: &[u8], key: &[u8], nonce: &[u8; 12]) -> Option<Vec<u8>> {
    let cipher = aes::Aes128::new_from_slice(key).ok()?;
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let counter = u32::try_from(i).ok()?.checked_add(2)?;
        let mut raw = [0; 16];
        raw[..12].copy_from_slice(nonce);
        raw[12..].copy_from_slice(&counter.to_be_bytes());
        let mut block = raw.into();
        cipher.encrypt_block(&mut block);
        out.extend(chunk.iter().zip(block.iter()).map(|(a, b)| a ^ b));
    }
    Some(out)
}
fn header_valid(plain: &[u8], n: usize, flags: u32) -> bool {
    u32_le(plain, 0) == Some(32)
        && u32_le(plain, 4) == Some(0)
        && u32_le(plain, 8) == u32::try_from(n.saturating_sub(32)).ok()
        && u32_le(plain, 12) == Some(flags)
        && u32_le(plain, 16) == Some(8)
}
/// Recover the reviewed container layout using a companion native runtime.
/// Keys are checked against independent decrypted header fields. Specimen
/// names, platform and default license serial do not gate recovery. Layouts
/// with a nonce-XOR procedure remain unsupported and return `None`.
pub fn recover(runtime: &[u8], pyc: &[u8]) -> Option<Recovery> {
    if runtime.len() > 8 * 1024 * 1024 || pyc.len() > 16 * 1024 * 1024 {
        return None;
    }
    let at = pyc.windows(8).position(is_container)?;
    let blob = pyc.get(at..)?;
    let offset = u32_le(blob, 0x1c)? as usize;
    let n = u32_le(blob, 0x20)? as usize;
    let flags = u32_le(blob, 0x24)?;
    if !(32..=16 * 1024 * 1024).contains(&n) || offset != 64 || flags & 0x700 == 0 {
        return None;
    }
    let cipher = span(blob, offset, n)?;
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&flags.to_le_bytes());
    nonce[4..].copy_from_slice(span(blob, 0x2c, 8)?);
    let id = runtime.windows(12).position(|v| v == b"pyarmor-vax-")?;
    let ident = span(runtime, id, 20)?;
    if !ident.get(12..18)?.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let start = id.checked_add(0x34)?;
    let public_at = start.checked_add(u32_le(runtime, id + 0x24)? as usize)?;
    let public_len = u32_le(runtime, id + 0x28)? as usize;
    let license = start.checked_add(u32_le(runtime, id + 0x2c)? as usize)?;
    let extra_len = u32_le(runtime, license + 4)? as usize;
    if public_len > 8192 || extra_len > 8192 {
        return None;
    }
    let mut prefix = Md5::new();
    prefix.update(ident);
    prefix.update(span(runtime, public_at, public_len)?);
    prefix.update(span(runtime, license.checked_add(32)?, extra_len)?);
    // The same runtime key layout occurs in PE, ELF and Mach-O runtimes.
    // Locate the DER RSA public key structurally rather than relying on a PE
    // writable-section offset. Admit masked and unmasked encodings, then
    // validate each candidate against the independent container header fields.
    const DER: &[u8] = &[0x30, 0x82, 1, 0x0a, 2, 0x82, 1, 1, 0];
    let mut candidates = 0;
    for (at, marker) in runtime.windows(DER.len()).enumerate() {
        for mask in [0u8, 0xf1] {
            if !marker.iter().zip(DER).all(|(a, b)| a ^ mask == *b) {
                continue;
            }
            candidates += 1;
            if candidates > 128 {
                return None;
            }
            let Some(salt) = span(runtime, at, 270) else {
                continue;
            };
            let mut hash = prefix.clone();
            hash.update(salt.iter().map(|b| b ^ mask).collect::<Vec<_>>());
            let key: [u8; 16] = hash.finalize().into();
            if header_valid(&ctr(cipher.get(..32)?, &key, &nonce)?, n, flags) {
                return Some(Recovery {
                    container: ctr(cipher, &key, &nonce)?,
                    python_magic: span(blob, 12, 4)
                        .filter(|m| m.get(2..) == Some(&[13, 10]))
                        .and_then(|m| m.try_into().ok()),
                    key,
                });
            }
        }
    }
    // Compatibility with reviewed PE runtimes whose salt is not a DER key.
    if runtime.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_le(runtime, 60)? as usize;
    if span(runtime, pe, 4)? != b"PE\0\0" {
        return None;
    }
    let count = usize::from(u16_le(runtime, pe + 6)?);
    if count > 96 {
        return None;
    }
    let sections = pe
        .checked_add(24)?
        .checked_add(usize::from(u16_le(runtime, pe + 20)?))?;
    let mut attempts = 0;
    for i in 0..count {
        let sh = sections.checked_add(i.checked_mul(40)?)?;
        if u32_le(runtime, sh + 36)? & 0x80000000 == 0 {
            continue;
        }
        let off = u32_le(runtime, sh + 20)? as usize;
        let size = u32_le(runtime, sh + 16)? as usize;
        let data = span(runtime, off, size)?;
        for salt in data.windows(270) {
            attempts += 1;
            if attempts > 65536 {
                return None;
            }
            let mut hash = prefix.clone();
            let salt: Vec<u8> = salt.iter().map(|v| v ^ 0xf1).collect();
            hash.update(&salt);
            let key = hash.finalize();
            let probe = ctr(cipher.get(..32)?, &key, &nonce)?;
            if header_valid(&probe, n, flags) {
                let container = ctr(cipher, &key, &nonce)?;
                let python_magic = span(blob, 12, 4)
                    .filter(|magic| magic.get(2..) == Some(&[0x0d, 0x0a]))
                    .and_then(|magic| magic.try_into().ok());
                return Some(Recovery {
                    container,
                    python_magic,
                    key: key.into(),
                });
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn independent_openssl_fixture_and_negative_controls() {
        let runtime = include_bytes!("../../testdata/pyarmor/runtime-data.bin");
        let container = include_bytes!("../../testdata/pyarmor/container.bin");
        let expected = include_bytes!("../../testdata/pyarmor/plain.bin");
        assert_eq!(
            recover(runtime, container)
                .as_ref()
                .map(|r| r.container.as_slice()),
            Some(expected.as_slice())
        );
        let mut wrong_salt = *runtime;
        wrong_salt[0x300] ^= 1;
        assert!(recover(&wrong_salt, container).is_none());
        let mut wrong_nonce = *container;
        wrong_nonce[0x2c] ^= 1;
        assert!(recover(runtime, &wrong_nonce).is_none());
        assert!(recover(runtime, &container[..100]).is_none());
    }
    #[test]
    fn ctr_roundtrip_and_structural_near_misses() {
        let mut header = vec![0u8; 80];
        for (at, v) in [(0, 32u32), (8, 48), (12, 0x40912), (16, 8)] {
            header[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        let decrypted = ctr(&header, &[0x7a; 16], &[0x19; 12])
            .and_then(|enc| ctr(&enc, &[0x7a; 16], &[0x19; 12]));
        assert_eq!(decrypted, Some(header.clone()));
        assert!(header_valid(&header, 80, 0x40912));
        assert!(!header_valid(&header, 81, 0x40912));
        header[16] = 9;
        assert!(!header_valid(&header, 80, 0x40912));
        assert!(recover(b"MZ", b"PY000000").is_none());
    }
}
/// Recover protected byte containers from the third argument of parsed Python
/// calls. Only byte literals are admitted; no expressions or Python code run.
/// Input, parser walk, count and decoded-byte budgets bound the work.
pub fn python_containers(source: &[u8]) -> Vec<Vec<u8>> {
    if source.len() > 16 * 1024 * 1024 {
        return Vec::new();
    }
    let parsed = crate::OpenOptions::new()
        .file_type(crate::FileType::Python)
        .rizin(false)
        .open(source);
    let Some(ast) = parsed.source_ast() else {
        return Vec::new();
    };
    let mut cursor = ast.tree.root_node().walk();
    let mut out = Vec::new();
    let mut total = 0usize;
    for _ in 0..100_000 {
        let node = cursor.node();
        if node.kind() == "call"
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut walk = args.walk();
            let arg = args
                .named_children(&mut walk)
                .filter(|n| n.kind() != "comment")
                .nth(2);
            if let Some(arg) = arg.filter(|n| n.kind() == "string")
                && let Some(literal) = ast.source.as_bytes().get(arg.byte_range())
                && let Some(blob) = python_bytes(literal)
                && is_container(&blob)
            {
                total = total.saturating_add(blob.len());
                if total > 16 * 1024 * 1024 || out.len() == 128 {
                    break;
                }
                out.push(blob);
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
    out
}

fn python_bytes(literal: &[u8]) -> Option<Vec<u8>> {
    let quote = literal.iter().position(|b| matches!(b, b'\'' | b'"'))?;
    let prefix = literal.get(..quote)?.to_ascii_lowercase();
    if !matches!(prefix.as_slice(), b"b" | b"br" | b"rb") {
        return None;
    }
    let rest = literal.get(quote..)?;
    let q = *rest.first()?;
    let width = if rest.starts_with(&[q; 3]) { 3 } else { 1 };
    if !rest.ends_with([q; 3].get(..width)?) {
        return None;
    }
    let body = rest.get(width..rest.len().checked_sub(width)?)?;
    if !body.is_ascii() {
        return None;
    }
    if prefix.contains(&b'r') {
        return Some(body.to_vec());
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let b = *body.get(i)?;
        i += 1;
        if b != b'\\' {
            out.push(b);
            continue;
        }
        let escaped = *body.get(i)?;
        i += 1;
        match escaped {
            b'x' => {
                let high = char::from(*body.get(i)?).to_digit(16)?;
                let low = char::from(*body.get(i + 1)?).to_digit(16)?;
                out.push(u8::try_from(high * 16 + low).ok()?);
                i += 2;
            }
            b'0'..=b'7' => {
                let mut value = u16::from(escaped - b'0');
                for _ in 0..2 {
                    let Some(next @ b'0'..=b'7') = body.get(i) else {
                        break;
                    };
                    value = value * 8 + u16::from(next - b'0');
                    i += 1;
                }
                out.push(u8::try_from(value & 255).ok()?);
            }
            b'\n' => {}
            b'\r' if body.get(i) == Some(&b'\n') => {
                i += 1;
            }
            b'\\' | b'\'' | b'"' => out.push(escaped),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(10),
            b'r' => out.push(13),
            b't' => out.push(9),
            b'v' => out.push(11),
            _ => {
                out.push(b'\\');
                out.push(escaped);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod wrapper_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn parsed_wrapper_to_standard_pyc_preserves_constants_and_names() {
        let source = include_bytes!("../../testdata/pyarmor/wrapper.py");
        let containers = python_containers(source);
        assert_eq!(containers.len(), 1);
        assert_eq!(
            containers[0],
            include_bytes!("../../testdata/pyarmor/marshal-container.bin")
        );
        let decoded = recover(
            include_bytes!("../../testdata/pyarmor/runtime-data.bin"),
            &containers[0],
        )
        .unwrap();
        assert_eq!(
            decoded.container,
            include_bytes!("../../testdata/pyarmor/marshal-plain.bin")
        );
        let pyc = decoded.pyc().unwrap().data;
        let parsed = crate::OpenOptions::new()
            .file_type(crate::FileType::PythonBytecode)
            .rizin(false)
            .open(&pyc);
        assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
        assert!(parsed.symbols().iter().any(|s| s.name() == Some("message")));
    }
    #[test]
    fn literal_reader_does_not_execute_expressions_or_decode_documentation() {
        for source in [
            b"data = b'PY000000'".as_slice(),
            b"# loader(a, b, b'PY000000')".as_slice(),
            b"doc = \"loader(a, b, b'PY000000')\"".as_slice(),
            b"loader(a, b, build_payload())".as_slice(),
            b"loader(a, b, 'PY000000')".as_slice(),
        ] {
            assert!(python_containers(source).is_empty());
        }
        assert_eq!(
            python_bytes(br#"b'PY000000\x00\377\n\\'"#).unwrap(),
            b"PY000000\x00\xff\n\\"
        );
        assert_eq!(
            python_bytes(br#"br'PY000000\x00'"#).unwrap(),
            br"PY000000\x00"
        );
        assert!(python_bytes(br#"b'PY000000\xQQ'"#).is_none());
        assert!(python_bytes(b"b'bad\\'").is_none());
    }
    #[test]
    fn malformed_inputs_and_non_code_containers_do_not_become_pyc() {
        let runtime = include_bytes!("../../testdata/pyarmor/runtime-data.bin");
        let container = include_bytes!("../../testdata/pyarmor/marshal-container.bin");
        for end in 0..container.len() {
            assert!(recover(runtime, &container[..end]).is_none());
        }
        assert!(
            recover(
                runtime,
                include_bytes!("../../testdata/pyarmor/container.bin")
            )
            .unwrap()
            .pyc()
            .is_err()
        );
        let mut corrupt = container.to_vec();
        corrupt[12..16].fill(0);
        assert!(recover(runtime, &corrupt).unwrap().pyc().is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod instruction_tests {
    use super::*;
    #[test]
    fn independent_nested_instruction_fixture() {
        let runtime = include_bytes!("../../testdata/pyarmor/runtime-data.bin");
        let container = include_bytes!("../../testdata/pyarmor/nested-container.bin");
        let recovered = recover(runtime, container).unwrap().pyc().unwrap();
        assert_eq!(
            recovered.data,
            include_bytes!("../../testdata/pyarmor/nested-normalized.pyc")
        );
        assert_eq!(recovered.code_objects, 2);
        assert_eq!(recovered.decrypted_regions, 2);
        assert!(recovered.limitations.is_empty());
        for end in 0..recovered.data.len().saturating_sub(16) {
            let body = &recovered.data[16..16 + end];
            assert!(marshal::normalize(body, 11, &[0; 16]).is_err());
        }
        let mut recovery = recover(runtime, container).unwrap();
        // Both short metadata and an invalid descriptor index must fail closed.
        *recovery.container.last_mut().unwrap() = 255;
        assert!(recovery.pyc().is_err());
    }
    #[test]
    fn recognizes_nondefault_serials() {
        assert!(is_container(b"PY123456"));
        assert!(!is_container(b"PYabc123"));
        let runtime = include_bytes!("../../testdata/pyarmor/runtime-data.bin");
        let mut blob = include_bytes!("../../testdata/pyarmor/nested-container.bin").to_vec();
        blob[2..8].copy_from_slice(b"123456");
        assert_eq!(
            recover(runtime, &blob).unwrap().pyc().unwrap().code_objects,
            2
        );
    }
    #[test]
    fn der_key_recovery_is_independent_of_native_file_format() {
        let runtime = include_bytes!("../../testdata/pyarmor/der-runtime.bin");
        let blob = include_bytes!("../../testdata/pyarmor/der-container.bin");
        for signature in [
            b"\x7fELF",
            b"MZ\0\0",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
        ] {
            let mut runtime = runtime.to_vec();
            runtime[..4].copy_from_slice(signature);
            assert!(recover(&runtime, blob).unwrap().pyc().is_ok());
        }
        let mut wrong = *runtime;
        wrong[768 + 20] ^= 1;
        assert!(recover(&wrong, blob).is_none());
    }
    #[test]
    fn unknown_instruction_nonce_protection_is_explicit() {
        let runtime = include_bytes!("../../testdata/pyarmor/runtime-data.bin");
        let container = include_bytes!("../../testdata/pyarmor/nested-container.bin");
        let mut recovery = recover(runtime, container).unwrap();
        let mut descriptor = vec![0; 12];
        descriptor.extend_from_slice(&6u32.to_le_bytes());
        descriptor.extend_from_slice(&1u32.to_le_bytes());
        let at = recovery
            .container
            .windows(20)
            .position(|v| v == descriptor)
            .unwrap();
        recovery.container[at + 8] = 4;
        let result = recovery.pyc().unwrap();
        assert_eq!(result.decrypted_regions, 1);
        assert!(
            result
                .limitations
                .contains(&"instruction nonce-XOR protection remains encrypted")
        );
    }
    #[test]
    fn relocated_prologues_and_short_nonce_descriptors() {
        let runtime = include_bytes!("../../testdata/pyarmor/runtime-data.bin");
        for (blob, expected) in [
            (
                include_bytes!("../../testdata/pyarmor/prologue-8-container.bin").as_slice(),
                include_bytes!("../../testdata/pyarmor/prologue-8-normalized.pyc").as_slice(),
            ),
            (
                include_bytes!("../../testdata/pyarmor/prologue-10-container.bin").as_slice(),
                include_bytes!("../../testdata/pyarmor/prologue-10-normalized.pyc").as_slice(),
            ),
        ] {
            let result = recover(runtime, blob).unwrap().pyc().unwrap();
            assert_eq!(result.data, expected);
            assert_eq!(result.decrypted_regions, 1);
            assert!(result.limitations.is_empty());
        }
    }
}
