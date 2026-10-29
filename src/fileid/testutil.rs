//! Builders for the archives identification tests feed it.

use std::io::{Cursor, Write};

/// An uncompressed ustar archive of `(path, body)` members.
pub(super) fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, body) in members {
        let mut header = tar::Header::new_ustar();
        header
            .set_path(path)
            .expect("member path fits a ustar header");
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *body).expect("member appends");
    }
    builder.into_inner().expect("tar finishes")
}

/// `data` gzip-compressed.
pub(super) fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).expect("gzip writes");
    encoder.finish().expect("gzip finishes")
}

/// `data` zstd-compressed.
pub(super) fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).expect("zstd encodes")
}

/// A zip of `(name, body)` members written with `method`.
pub(super) fn zip_with(members: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let options = zip::write::SimpleFileOptions::default().compression_method(method);
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, body) in members {
        writer.start_file(*name, options).expect("member starts");
        writer.write_all(body).expect("member writes");
    }
    writer.finish().expect("zip finishes").into_inner()
}

/// A zip of `(name, body)` members with the writer's default method.
pub(super) fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with(members, zip::CompressionMethod::Deflated)
}

/// A fixture stored zstd-compressed, so endpoint protection leaves a
/// checkout holding real specimens intact.
pub(super) fn unzstd(compressed: &[u8]) -> Vec<u8> {
    zstd::decode_all(compressed).expect("fixture decompresses")
}
