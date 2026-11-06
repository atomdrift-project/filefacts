//! Static recovery of the reviewed PyArmor 8/9 container and code-object layouts.
//! No Python objects, native runtime or specimen code is executed. GCM's
//! counter stream is decoded and checked structurally; this is not tag authentication.
use crate::bytes::{sat_usize, u16_le, u32_le};
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

mod marshal;

/// Bytes of runtime data hashed into a key candidate.
const SALT_LEN: usize = 270;

/// Largest companion runtime searched for key material.
const MAX_RUNTIME_BYTES: usize = 8 << 20;
/// Largest protected input: a `.pyc`, a container, or the Python source a
/// container is recovered from; also the most container bytes one source
/// yields in all.
const MAX_PROTECTED_BYTES: usize = 16 << 20;
/// Most containers recovered from one Python source.
const MAX_CONTAINERS: usize = 128;
/// Syntax-tree nodes visited looking for containers in one Python source.
const MAX_WALK_NODES: usize = 100_000;

impl Recovery {
    /// Normalize PyArmor's extra marshal fields and recover nested instruction
    /// regions. Unsupported versions/layouts fail closed; known remaining
    /// protection is described in `limitations`. This is an analysis snapshot,
    /// not a runnable or authenticated reconstruction of the original program.
    ///
    /// # Errors
    /// [`crate::Error::Malformed`] for unsupported versions, malformed
    /// marshal data, or exhausted parsing budgets.
    pub fn pyc(&self) -> Result<RecoveredPyc, crate::Error> {
        self.normalize()
            .map_err(|detail| crate::Error::malformed("pyarmor", detail))
    }

    fn normalize(&self) -> Result<RecoveredPyc, &'static str> {
        let magic = self.python_magic.ok_or("missing CPython magic")?;
        let word = u16::from_le_bytes([magic[0], magic[1]]);
        let minor = super::pyc::python3_minor_for_magic(word)
            .filter(|&minor| minor >= 8)
            .ok_or("unsupported CPython marshal version")?;
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
    if runtime.len() > MAX_RUNTIME_BYTES || pyc.len() > MAX_PROTECTED_BYTES {
        return None;
    }
    let at = pyc.windows(8).position(is_container)?;
    let blob = pyc.get(at..)?;
    let offset = sat_usize(u32_le(blob, 0x1c)?);
    let n = sat_usize(u32_le(blob, 0x20)?);
    let flags = u32_le(blob, 0x24)?;
    if !(32..=MAX_PROTECTED_BYTES).contains(&n) || offset != 64 || flags & 0x700 == 0 {
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
    let public_at = start.checked_add(sat_usize(u32_le(runtime, id + 0x24)?))?;
    let public_len = sat_usize(u32_le(runtime, id + 0x28)?);
    let license = start.checked_add(sat_usize(u32_le(runtime, id + 0x2c)?))?;
    let extra_len = sat_usize(u32_le(runtime, license.checked_add(4)?)?);
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
            let Some(salt) = span(runtime, at, SALT_LEN) else {
                continue;
            };
            let mut masked = [0u8; SALT_LEN];
            for (out, b) in masked.iter_mut().zip(salt) {
                *out = b ^ mask;
            }
            let mut hash = prefix.clone();
            hash.update(masked);
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
    let pe = sat_usize(u32_le(runtime, 60)?);
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
        let off = sat_usize(u32_le(runtime, sh + 20)?);
        let size = sat_usize(u32_le(runtime, sh + 16)?);
        let data = span(runtime, off, size)?;
        for salt in data.windows(SALT_LEN) {
            attempts += 1;
            if attempts > 65536 {
                return None;
            }
            let mut masked = [0u8; SALT_LEN];
            for (out, v) in masked.iter_mut().zip(salt) {
                *out = v ^ 0xf1;
            }
            let mut hash = prefix.clone();
            hash.update(masked);
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

/// Recover protected byte containers from the third argument of parsed Python
/// calls. Only byte literals are admitted; no expressions or Python code run.
/// Input, parser walk, count and decoded-byte budgets bound the work.
pub fn python_containers(source: &[u8]) -> Vec<Vec<u8>> {
    if source.len() > MAX_PROTECTED_BYTES {
        return Vec::new();
    }
    // A host calls this outside the extraction pipeline, so the parse gets
    // the pipeline's panic guard here.
    let parsed = crate::panic_guard::catch_infallible(|| {
        super::source::TreeCache::parse(source, crate::FileType::Python, None)
    });
    let Some(ast) = parsed
        .as_ref()
        .ok()
        .and_then(super::source::TreeParse::cache)
    else {
        return Vec::new();
    };
    let text = ast.source();
    let mut cursor = ast.tree().root_node().walk();
    let mut out = Vec::new();
    let mut total = 0usize;
    for _ in 0..MAX_WALK_NODES {
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
                && let Some(literal) = text.as_bytes().get(arg.byte_range())
                && let Some(blob) = python_bytes(literal)
                && is_container(&blob)
            {
                total = total.saturating_add(blob.len());
                if total > MAX_PROTECTED_BYTES || out.len() == MAX_CONTAINERS {
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
mod tests;
