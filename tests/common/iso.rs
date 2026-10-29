//! ISO 9660 building blocks for synthetic disc images.

/// The ISO 9660 logical sector size.
pub(crate) const SECTOR: usize = 2048;

/// `v` in ISO 9660's both-byte-order form: little-endian, then big-endian.
pub(crate) fn both32(v: u32) -> Vec<u8> {
    [v.to_le_bytes(), v.to_be_bytes()].concat()
}

/// [`both32`] for a 16-bit field.
pub(crate) fn both16(v: u16) -> Vec<u8> {
    [v.to_le_bytes(), v.to_be_bytes()].concat()
}

/// One directory record. `name` is already in the namespace's encoding,
/// `recorded` is the 7-byte recording date, and `system_use` is appended
/// after the (padded) name — where Rock Ridge entries live.
pub(crate) fn dir_record(
    name: &[u8],
    lba: u32,
    size: u32,
    flags: u8,
    recorded: [u8; 7],
    system_use: &[u8],
) -> Vec<u8> {
    let mut b = vec![0_u8, 0]; // length placeholder, ext-attr length
    b.extend(both32(lba));
    b.extend(both32(size));
    b.extend(recorded);
    b.push(flags);
    b.extend([0, 0]); // file unit size, interleave gap
    b.extend(both16(1)); // volume sequence number
    b.push(u8::try_from(name.len()).expect("a name fits a directory record"));
    b.extend_from_slice(name);
    if name.len().is_multiple_of(2) {
        b.push(0); // pad the name field to an even length
    }
    b.extend_from_slice(system_use);
    let len = u8::try_from(b.len()).expect("a directory record fits 255 bytes");
    *b.first_mut().expect("a directory record has a length byte") = len;
    b
}

/// Copy `data` into `img` at byte offset `at`.
pub(crate) fn put(img: &mut [u8], at: usize, data: &[u8]) {
    img.get_mut(at..at + data.len())
        .expect("write inside the image")
        .copy_from_slice(data);
}
