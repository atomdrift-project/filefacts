use super::{class_frames, class_len};

fn class() -> Vec<u8> {
    let mut b = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 5];
    for (tag, bytes) in [
        (1u8, b"\0\x07Example".as_slice()),
        (7, b"\0\x01"),
        (1, b"\0\x10java/lang/Object"),
        (7, b"\0\x03"),
    ] {
        b.push(tag);
        b.extend_from_slice(bytes);
    }
    b.extend_from_slice(&[0, 0x21, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
    b
}
#[test]
fn skips_magic_in_attributes_and_reports_resource_limits() {
    let c = class();
    let mut outer = c.clone();
    let n = outer.len();
    outer[n - 1] = 1; // one class-level attribute
    outer.extend_from_slice(&[0, 1]);
    outer.extend_from_slice(&(c.len() as u32).to_be_bytes());
    outer.extend_from_slice(&c);
    let mut carrier = vec![0x1c, 0x9a, 0x4a, 0x92];
    carrier.extend_from_slice(&outer);
    assert_eq!(class_frames(&carrier), (vec![(4, outer.len())], false));
    let mut many = vec![0x1c, 0x9a, 0x4a, 0x92];
    for _ in 0..257 {
        many.extend_from_slice(&c);
    }
    let (frames, incomplete) = class_frames(&many);
    assert_eq!(frames.len(), 256);
    assert!(incomplete);
}
#[test]
fn frames_multiple_classes_and_ignores_truncated_candidates() {
    let c = class();
    let mut carrier = vec![0x1c, 0x9a, 0x4a, 0x92, 0, 0, 0];
    let first = carrier.len();
    carrier.extend_from_slice(&c);
    carrier.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0]);
    let second = carrier.len();
    carrier.extend_from_slice(&c);
    assert_eq!(
        class_frames(&carrier),
        (vec![(first, c.len()), (second, c.len())], true)
    );
    assert!(class_frames(&c).0.is_empty());
    carrier.truncate(first + c.len() - 1);
    assert!(class_frames(&carrier).0.is_empty());
}

/// A thousand candidate headers, each carried as the attribute of a field
/// in the one before it, whose field tables all run on into one shared tail
/// of empty attributes: every candidate re-read the whole tail.
#[test]
fn candidates_sharing_one_tail_read_it_once() {
    let header: &[u8] = &[
        0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, // magic, version
        0, 2, 7, 0, 1, // one constant
        0, 0x21, 0, 1, 0, 0, 0, 0, // flags, this, super, no interfaces
        0xff, 0xff, // fields
    ];
    let mut module = vec![0x1c, 0x9a, 0x4a, 0x92];
    for _ in 0..1000 {
        // A field with one attribute whose body is the next header.
        module.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
        module.extend_from_slice(&(header.len() as u32).to_be_bytes());
        module.extend_from_slice(header);
    }
    // The tail: one field of 65,535 empty attributes, then the end.
    module.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    for _ in 0..0xffff {
        module.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    let first = 4 + 14;
    let mut steps = usize::MAX;
    assert_eq!(class_len(&module[first..], &mut steps), None);
    let one_candidate = usize::MAX - steps;
    assert!(one_candidate > 0xffff);
    // Each candidate alone reads the tail, so framing every one of them
    // whole would take a thousand times that; the budget is the module.
    assert!(1000 * one_candidate > 100 * module.len());
    assert_eq!(class_frames(&module), (Vec::new(), true));
}
