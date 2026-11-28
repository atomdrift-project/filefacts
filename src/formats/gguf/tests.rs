#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use super::*;

/// Builds GGUF files for the tests: metadata, a tensor index, padding to the
/// alignment, tensor bytes and any trailing bytes.
struct Builder {
    version: u32,
    kv: Vec<u8>,
    kv_count: u64,
    tensors: Vec<u8>,
    tensor_count: u64,
    data_len: u64,
    alignment: u64,
}

impl Builder {
    fn new() -> Self {
        Self {
            version: 3,
            kv: Vec::new(),
            kv_count: 0,
            tensors: Vec::new(),
            tensor_count: 0,
            data_len: 0,
            alignment: 32,
        }
    }

    fn len_field(&self, out: &mut Vec<u8>, n: u64) {
        if self.version == 1 {
            out.extend_from_slice(&(n as u32).to_le_bytes());
        } else {
            out.extend_from_slice(&n.to_le_bytes());
        }
    }

    fn string_field(&self, out: &mut Vec<u8>, s: &[u8]) {
        self.len_field(out, s.len() as u64);
        out.extend_from_slice(s);
    }

    fn key(&mut self, key: &str, kind: u32) {
        let mut kv = std::mem::take(&mut self.kv);
        self.string_field(&mut kv, key.as_bytes());
        kv.extend_from_slice(&kind.to_le_bytes());
        self.kv = kv;
        self.kv_count += 1;
    }

    fn string(mut self, key: &str, value: &str) -> Self {
        self.key(key, T_STRING);
        let mut kv = std::mem::take(&mut self.kv);
        self.string_field(&mut kv, value.as_bytes());
        self.kv = kv;
        self
    }

    fn u32(mut self, key: &str, value: u32) -> Self {
        self.key(key, T_U32);
        self.kv.extend_from_slice(&value.to_le_bytes());
        if key == "general.alignment" && value.is_power_of_two() {
            self.alignment = u64::from(value);
        }
        self
    }

    /// An array of `count` strings, like a tokenizer vocabulary.
    fn strings(mut self, key: &str, values: &[&str]) -> Self {
        self.key(key, T_ARRAY);
        let mut kv = std::mem::take(&mut self.kv);
        kv.extend_from_slice(&T_STRING.to_le_bytes());
        self.len_field(&mut kv, values.len() as u64);
        for v in values {
            self.string_field(&mut kv, v.as_bytes());
        }
        self.kv = kv;
        self
    }

    /// One F32 tensor of `elements` floats at the next data offset.
    fn tensor(mut self, name: &str, elements: u64) -> Self {
        let mut t = std::mem::take(&mut self.tensors);
        self.string_field(&mut t, name.as_bytes());
        t.extend_from_slice(&1u32.to_le_bytes());
        t.extend_from_slice(&elements.to_le_bytes());
        t.extend_from_slice(&0u32.to_le_bytes()); // F32
        t.extend_from_slice(&self.data_len.to_le_bytes());
        self.tensors = t;
        self.tensor_count += 1;
        self.data_len += elements * 4;
        self
    }

    /// The header and tensor index, padded with `pad` to the alignment.
    fn header(&self, pad: u8) -> Vec<u8> {
        let mut out = b"GGUF".to_vec();
        out.extend_from_slice(&self.version.to_le_bytes());
        self.len_field(&mut out, self.tensor_count);
        self.len_field(&mut out, self.kv_count);
        out.extend_from_slice(&self.kv);
        out.extend_from_slice(&self.tensors);
        while !(out.len() as u64).is_multiple_of(self.alignment) {
            out.push(pad);
        }
        out
    }

    /// A whole file: header, tensor data, then `trailing`.
    fn build(&self, trailing: &[u8]) -> Vec<u8> {
        let mut out = self.header(0);
        out.extend(std::iter::repeat_n(0x11, self.data_len as usize));
        out.extend_from_slice(trailing);
        out
    }
}

fn run(bytes: &[u8]) -> (Values, Metrics) {
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    extract(bytes, &mut values, &mut metrics);
    (values, metrics)
}

fn metric(m: &Metrics, key: &crate::MetricKey) -> Option<f64> {
    m.lookup(key)
}

const TEMPLATE: &str = "{% for message in messages %}{{ message.content }}{% endfor %}";

fn model() -> Builder {
    Builder::new()
        .string("general.architecture", "qwen3")
        .strings("tokenizer.ggml.tokens", &["<s>", "a", "b"])
        .string("tokenizer.chat_template", TEMPLATE)
        .tensor("token_embd.weight", 64)
        .tensor("output.weight", 32)
}

#[test]
fn reads_header_facts_of_a_clean_model() {
    let b = model();
    let file = b.build(&[]);
    let (v, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.version")), Some(3.0));
    assert_eq!(metric(&m, &metric!("gguf.tensor_count")), Some(2.0));
    assert_eq!(metric(&m, &metric!("gguf.metadata_count")), Some(3.0));
    assert_eq!(metric(&m, &metric!("gguf.alignment")), Some(32.0));
    assert_eq!(
        v.lookup(value_key!("gguf.architecture")),
        Some(&json!("qwen3"))
    );
    let data_offset = b.header(0).len() as u64;
    assert_eq!(
        v.lookup(value_key!("gguf.data_offset")),
        Some(&json!(data_offset))
    );
    assert_eq!(
        v.lookup(value_key!("gguf.data_end")),
        Some(&json!(file.len() as u64))
    );
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), None);
    assert_eq!(metric(&m, &metric!("gguf.padding_nonzero_bytes")), None);
    assert!(v.lookup(value_key!("gguf.truncated")).is_none());
}

#[test]
fn chat_template_offset_and_length_address_the_template_bytes() {
    let file = model().build(&[]);
    let (v, _) = run(&file);
    let templates = v.lookup(value_key!("gguf.chat_templates")).unwrap();
    let t = &templates[0];
    assert_eq!(t["key"], "tokenizer.chat_template");
    let offset = t["offset"].as_u64().unwrap() as usize;
    let length = t["length"].as_u64().unwrap() as usize;
    assert_eq!(&file[offset..offset + length], TEMPLATE.as_bytes());
}

#[test]
fn named_templates_are_reported_and_lookalike_keys_are_not() {
    let file = Builder::new()
        .string("tokenizer.chat_template.tool_use", "{{ tools }}")
        .string("tokenizer.chat_templates", "not a template key")
        .string("tokenizer.chat_template_extra", "nor this")
        .build(&[]);
    let (v, _) = run(&file);
    let templates = v.lookup(value_key!("gguf.chat_templates")).unwrap();
    assert_eq!(templates.as_array().unwrap().len(), 1);
    assert_eq!(templates[0]["key"], "tokenizer.chat_template.tool_use");
}

#[test]
fn bytes_past_the_last_tensor_are_trailing_data() {
    let mut payload = b"MZ".to_vec();
    payload.extend_from_slice(&[0x90; 4094]);
    let file = model().build(&payload);
    let (_, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), Some(4096.0));
    assert_eq!(
        metric(&m, &metric!("gguf.trailing_nonzero_bytes")),
        Some(4096.0)
    );
}

#[test]
fn zero_trailing_padding_has_no_nonzero_count() {
    let file = model().build(&[0; 64]);
    let (_, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), Some(64.0));
    assert_eq!(metric(&m, &metric!("gguf.trailing_nonzero_bytes")), None);
}

#[test]
fn header_only_carve_is_truncated_and_keeps_its_template() {
    let b = model();
    let header = b.header(0);
    let (v, m) = run(&header);
    assert_eq!(v.lookup(value_key!("gguf.truncated")), Some(&json!(true)));
    assert!(v.lookup(value_key!("gguf.chat_templates")).is_some());
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), None);
}

#[test]
fn unknown_tensor_type_leaves_the_data_end_unknown() {
    let b = model();
    let mut file = b.build(&[1, 2, 3]);
    // Retype the first tensor (F32 = 0) to an unassigned ggml type.
    let name = b"token_embd.weight";
    let at = file.windows(name.len()).position(|w| w == name).unwrap() + name.len() + 4 + 8;
    file[at..at + 4].copy_from_slice(&200u32.to_le_bytes());
    let (v, m) = run(&file);
    assert!(v.lookup(value_key!("gguf.data_end")).is_none());
    assert_eq!(
        v.lookup(value_key!("gguf.unknown_tensor_types")),
        Some(&json!([200]))
    );
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), None);
}

#[test]
fn custom_alignment_moves_the_data_offset() {
    let b = model().u32("general.alignment", 4096);
    let file = b.build(b"X");
    let (v, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.alignment")), Some(4096.0));
    let data_offset = v
        .lookup(value_key!("gguf.data_offset"))
        .unwrap()
        .as_u64()
        .unwrap();
    assert_eq!(data_offset % 4096, 0);
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), Some(1.0));
}

#[test]
fn alignment_that_is_not_a_power_of_two_is_ignored() {
    let file = model().u32("general.alignment", 48).build(&[]);
    let (_, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.alignment")), Some(32.0));
}

#[test]
fn nonzero_alignment_padding_is_counted() {
    let b = model();
    let mut file = b.header(0xAB);
    let pad = file.iter().rev().take_while(|&&x| x == 0xAB).count();
    assert!(pad > 0, "builder must leave padding to fill");
    file.extend(std::iter::repeat_n(0x11, b.data_len as usize));
    let (_, m) = run(&file);
    assert_eq!(
        metric(&m, &metric!("gguf.padding_nonzero_bytes")),
        Some(pad as f64)
    );
}

#[test]
fn duplicate_keys_are_reported() {
    let file = Builder::new()
        .string("tokenizer.chat_template", "first")
        .string("tokenizer.chat_template", "second")
        .build(&[]);
    let (v, _) = run(&file);
    assert_eq!(
        v.lookup(value_key!("gguf.duplicate_keys")),
        Some(&json!(["tokenizer.chat_template"]))
    );
    assert_eq!(
        v.lookup(value_key!("gguf.chat_templates"))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn version_one_uses_narrow_lengths() {
    let mut b = Builder::new();
    b.version = 1;
    let file = b
        .string("general.architecture", "llama")
        .string("tokenizer.chat_template", TEMPLATE)
        .tensor("w", 8)
        .build(b"tail");
    let (v, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.version")), Some(1.0));
    assert_eq!(
        v.lookup(value_key!("gguf.architecture")),
        Some(&json!("llama"))
    );
    assert_eq!(metric(&m, &metric!("gguf.trailing_bytes")), Some(4.0));
}

#[test]
fn only_little_endian_versions_one_to_three_are_gguf() {
    assert!(is_gguf(b"GGUF\x03\x00\x00\x00"));
    assert!(is_gguf(b"GGUF\x01\x00\x00\x00"));
    assert!(!is_gguf(b"GGUF\x00\x00\x00\x03")); // byte-swapped
    assert!(!is_gguf(b"GGUF\x04\x00\x00\x00"));
    assert!(!is_gguf(b"GGUF\x03\x00\x00"));
    assert!(!is_gguf(b"GGML\x03\x00\x00\x00"));
    let (v, m) = run(b"GGUF\x09\x00\x00\x00rest");
    assert!(v.is_empty() && metric(&m, &metric!("gguf.version")).is_none());
}

// ── hostile input ──

#[test]
fn every_prefix_of_a_model_parses_without_panic() {
    let file = model().u32("general.alignment", 64).build(b"MZtrailing");
    for end in 0..=file.len() {
        let _ = run(&file[..end]);
    }
}

#[test]
fn oversized_counts_stop_the_walk_without_allocating() {
    let mut file = b"GGUF\x03\x00\x00\x00".to_vec();
    file.extend_from_slice(&u64::MAX.to_le_bytes()); // tensors
    file.extend_from_slice(&u64::MAX.to_le_bytes()); // metadata
    let (v, m) = run(&file);
    assert_eq!(metric(&m, &metric!("gguf.version")), Some(3.0));
    assert!(v.lookup(value_key!("gguf.data_end")).is_none());
}

#[test]
fn huge_array_counts_and_string_lengths_end_the_walk() {
    for (elem, count) in [
        (T_STRING, u64::MAX),
        (T_U64, u64::MAX / 4),
        (T_ARRAY, MAX_ITEMS + 1),
    ] {
        let mut b = Builder::new();
        b.key("tokenizer.ggml.tokens", T_ARRAY);
        b.kv.extend_from_slice(&elem.to_le_bytes());
        b.kv.extend_from_slice(&count.to_le_bytes());
        let file = b.string("tokenizer.chat_template", TEMPLATE).build(&[]);
        let (v, _) = run(&file);
        assert!(v.lookup(value_key!("gguf.chat_templates")).is_none());
    }
    let mut b = Builder::new();
    b.key("general.name", T_STRING);
    b.kv.extend_from_slice(&u64::MAX.to_le_bytes());
    let _ = run(&b.build(&[]));
}

#[test]
fn deeply_nested_arrays_are_refused() {
    let mut b = Builder::new();
    b.key("nested", T_ARRAY);
    for _ in 0..64 {
        b.kv.extend_from_slice(&T_ARRAY.to_le_bytes());
        b.kv.extend_from_slice(&1u64.to_le_bytes());
    }
    let file = b.string("tokenizer.chat_template", TEMPLATE).build(&[]);
    let (v, _) = run(&file);
    assert!(v.lookup(value_key!("gguf.chat_templates")).is_none());
}

#[test]
fn overflowing_tensor_extents_leave_the_data_end_unknown() {
    let mut b = Builder::new();
    let mut t = Vec::new();
    b.string_field(&mut t, b"w");
    t.extend_from_slice(&2u32.to_le_bytes());
    t.extend_from_slice(&u64::MAX.to_le_bytes());
    t.extend_from_slice(&u64::MAX.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&u64::MAX.to_le_bytes());
    b.tensors = t;
    b.tensor_count = 1;
    let (v, _) = run(&b.build(&[]));
    assert!(v.lookup(value_key!("gguf.data_offset")).is_some());
    assert!(v.lookup(value_key!("gguf.data_end")).is_none());
}

#[test]
fn too_many_dimensions_end_the_walk() {
    let mut b = Builder::new();
    let mut t = Vec::new();
    b.string_field(&mut t, b"w");
    t.extend_from_slice(&(MAX_DIMS + 1).to_le_bytes());
    b.tensors = t;
    b.tensor_count = 1;
    let (v, _) = run(&b.build(&[]));
    assert!(v.lookup(value_key!("gguf.data_offset")).is_none());
}

/// The whole-file passes skip a model's weights: no entropy scan and no
/// byte-scan strings, only the size and the header facts.
#[test]
fn parse_skips_whole_file_passes_for_a_model() {
    let file = model().build(&[]);
    let parsed = crate::open(&file);
    assert_eq!(parsed.fileid().file_type, crate::FileType::Gguf);
    assert_eq!(parsed.metrics().get("file.size"), Some(file.len() as f64));
    assert_eq!(parsed.metrics().get("file.entropy"), None);
    assert!(parsed.text().is_empty());
    assert!(parsed.values().get("gguf.chat_templates").is_some());
}
