//! Archive layouts read during identification: what a tar's members and a
//! zip's entries make the file.

use std::io::Read;

use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

use super::{FileType, Sniff, path_ends_with_ci};
use crate::bytes;
use crate::fileid::{
    ArchiveFormat, Compression, container_of, go_module,
    package_layout::{self, TarProbe},
};

/// How far detection will inflate a gzip tar while reading its member names.
/// npm packages, sdists and crates name themselves anywhere under their one
/// root, and sdists often put `PKG-INFO` last, after generated clients, tests
/// and documentation, so this is generous; it still bounds a decompression
/// bomb.
pub(super) const TAR_PEEK_LIMIT: u64 = 64 << 20;

/// How far detection will inflate a zstd tar. Its packages (FreeBSD, Arch,
/// Void) name themselves in their leading members.
pub(super) const TAR_HEAD_LIMIT: u64 = 1 << 20;

/// What a container's decoded bytes turned out to be.
#[derive(Clone, Copy)]
pub(super) enum Inside {
    /// The codec could not produce a first block: a truncated or corrupt
    /// stream, or no decoder linked. The content has not spoken.
    Unreadable,
    /// The stream decoded and is not a tar.
    NotTar,
    /// A tar, typed by its layout: a package, or plain [`FileType::Tar`].
    Tar(FileType),
}

/// What a tar's members make it: a package layout [`TarProbe`] recognises,
/// or plain [`FileType::Tar`]. `deep` reads on for container-image markers,
/// which only a plain tar can carry.
pub(super) fn tar_layout(mut reader: impl Read, deep: bool) -> Inside {
    // Read the first header block by hand, so a stream the codec cannot
    // decode is told apart from one that decodes to something else.
    let mut block = [0u8; 512];
    let mut filled = 0;
    while let Some(unfilled @ [_, ..]) = block.get_mut(filled..) {
        match reader.read(unfilled) {
            Ok(0) => return Inside::NotTar,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Inside::Unreadable,
        }
    }
    let mut archive = tar::Archive::new(std::io::Cursor::new(block).chain(reader));
    let Ok(mut entries) = archive.entries() else {
        return Inside::NotTar;
    };
    let mut probe = TarProbe::new();
    loop {
        let entry = match entries.next() {
            Some(Ok(entry)) => entry,
            // A stream whose first header does not parse is not a tar.
            Some(Err(_)) if probe.members() == 0 => return Inside::NotTar,
            Some(Err(error)) => {
                tracing::debug!(
                    target: "filefacts::fileid",
                    members = probe.members(),
                    %error,
                    "tar layout: member header unreadable, settling on what was read"
                );
                break;
            }
            None => break,
        };
        let header_type = entry.header().entry_type();
        if matches!(
            header_type,
            tar::EntryType::XGlobalHeader
                | tar::EntryType::XHeader
                | tar::EntryType::GNULongName
                | tar::EntryType::GNULongLink
        ) {
            continue;
        }
        let Ok(path) = entry.path() else { continue };
        let path = path.to_string_lossy().into_owned();
        let name = path.trim_start_matches("./").trim_end_matches('/');
        let size = entry.size();
        if let Some(layout) = probe.observe(name, header_type.is_file(), entry, size) {
            return Inside::Tar(layout);
        }
        if probe.members() >= probe.cap(deep) {
            break;
        }
    }
    if probe.members() > 0 {
        Inside::Tar(probe.finish())
    } else {
        Inside::NotTar
    }
}

/// Settle a file compressed with `compression`: the package its layout
/// names, else the package its name names on the same container, else the
/// generic tar. `None` when it is no tar at all. When the content could not be
/// read, only a name can say a tar is inside.
pub(super) fn classify_tar(
    sniff: &Sniff<'_>,
    compression: Compression,
    inside: Inside,
) -> Option<FileType> {
    let (path, data) = (sniff.path, sniff.data);
    let layout = match inside {
        Inside::NotTar => return None,
        Inside::Unreadable => None,
        Inside::Tar(ft) => Some(ft),
    };
    let fits = |ft: FileType| {
        container_of(ft, data)
            .is_some_and(|c| c.archive == ArchiveFormat::Tar && c.compression == compression)
    };
    if let Some(ft) = layout.filter(|&ft| ft != FileType::Tar && fits(ft)) {
        return Some(ft);
    }
    // `.apk` names Android's zip or Alpine's gzip tar; the container decides.
    let claim = if path_ends_with_ci(path, b".apk") {
        Some(FileType::ApkAlpine)
    } else {
        sniff.ext_type()
    };
    if let Some(ft) = claim.filter(|&ft| fits(ft)) {
        return Some(ft);
    }
    layout.map(|_| match compression {
        Compression::Gzip => FileType::TarGz,
        Compression::Bzip2 => FileType::TarBz2,
        Compression::Xz => FileType::TarXz,
        Compression::Zstd => FileType::TarZst,
        _ => FileType::Tar,
    })
}

/// The entry names along a zip's local-header chain, in order.
///
/// A plain substring search for a member name answers a different question:
/// whether the bytes appear anywhere. They do whenever a zip stores an Office
/// document uncompressed, because the inner package's own header is then
/// present verbatim in the outer file, and the outer zip is not that document.
///
/// So step from header to header by each entry's declared compressed size.
/// When the iterator ends, `complete` says whether it reached a real end of
/// chain (or the entry cap). A walk that lost the thread -- a streaming entry
/// with no size to step by, a header whose sizes are nonsense -- proves
/// nothing absent, and callers fall back to a looser test rather than
/// reporting a confident "no".
pub(super) struct ZipNames<'a> {
    data: &'a [u8],
    /// The next local header, or `None` once the walk has stopped.
    off: Option<usize>,
    left: usize,
    pub(super) complete: bool,
}

impl<'a> ZipNames<'a> {
    /// Entries to walk. A package names its content types first, but a
    /// marker such as an APK's `AndroidManifest.xml` sits wherever the
    /// packager put it, often hundreds of entries in. Each step is a bounds
    /// check and a few integer reads, so the ceiling is set by what a real
    /// archive holds rather than by what the walk costs.
    pub(super) const MAX_ENTRIES: usize = 8192;

    pub(super) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            off: Some(0),
            left: Self::MAX_ENTRIES,
            complete: false,
        }
    }
}

impl<'a> Iterator for ZipNames<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let data = self.data;
        let off = self.off.take()?;
        if self.left == 0 {
            self.complete = true;
            return None;
        }
        self.left -= 1;
        let u16_at = |at| bytes::u16_le(data, at).map(usize::from);
        let u32_at = |at| bytes::u32_le(data, at).map(|v| v as usize);
        let sig = data.get(off..off + 4)?;
        if sig != b"PK\x03\x04" {
            // Only a real end-of-chain marker completes the walk. Anything else
            // means it lost the thread: a malformed package is still an
            // Office document, and saying otherwise routes it to a reader
            // that rejects it outright.
            self.complete = matches!(
                sig,
                b"PK\x01\x02" | b"PK\x05\x06" | b"PK\x06\x06" | b"PK\x06\x07"
            );
            return None;
        }
        let flags = u16_at(off + 6)?;
        let compressed = u32_at(off + 18)?;
        let name_len = u16_at(off + 26)?;
        let extra_len = u16_at(off + 28)?;
        let name = data.get(off + 30..off + 30 + name_len)?;
        // Bit 3: the sizes are repeated in a trailing data descriptor. When
        // the local header carries them too they can still be stepped by;
        // when it does not, there is nothing to step by and the walk stops.
        self.off = (flags & 0x08 == 0 || compressed != 0)
            .then(|| off.checked_add(30 + name_len + extra_len + compressed))
            .flatten()
            .filter(|&next| next <= data.len())
            .and_then(|next| {
                if flags & 0x08 == 0 || data.get(next..next + 4) != Some(b"PK\x07\x08") {
                    return Some(next);
                }
                // Signature + crc + two sizes, four bytes each, or eight each
                // in zip64. Which one is in use is not declared here, so take
                // the length that lands on something a chain continues with.
                [16usize, 24]
                    .into_iter()
                    .map(|skip| next + skip)
                    .find(|&at| {
                        matches!(
                            data.get(at..at + 4),
                            Some(b"PK\x03\x04" | b"PK\x01\x02" | b"PK\x05\x06")
                        )
                    })
            });
        Some(name)
    }
}

/// The members that name a zip-based package, gathered in one walk.
#[derive(Default)]
struct ZipMarks {
    android: bool,
    content_types: bool,
    mimetype: bool,
    vsix: bool,
    appx: bool,
    nuspec: bool,
    jar: bool,
    wheel: bool,
    egg: bool,
    ipa: bool,
    conda_metadata: bool,
    conda_info: bool,
    xpi: bool,
    complete: bool,
}

impl ZipMarks {
    fn scan(data: &[u8]) -> Self {
        let mut m = Self::default();
        let mut names = ZipNames::new(data);
        for name in names.by_ref() {
            let top_level = !name.contains(&b'/');
            match name {
                b"AndroidManifest.xml" => m.android = true,
                b"[Content_Types].xml" => m.content_types = true,
                b"mimetype" => m.mimetype = true,
                b"extension.vsixmanifest" => m.vsix = true,
                b"AppxManifest.xml" | b"AppxMetadata/AppxBundleManifest.xml" => m.appx = true,
                b"META-INF/MANIFEST.MF" => m.jar = true,
                b"EGG-INFO/PKG-INFO" => m.egg = true,
                b"metadata.json" => m.conda_metadata = true,
                b"install.rdf" | b"META-INF/mozilla.rsa" => m.xpi = true,
                _ if top_level && name.ends_with(b".nuspec") => m.nuspec = true,
                _ if top_level && name.starts_with(b"info-") && name.ends_with(b".tar.zst") => {
                    m.conda_info = true;
                }
                _ if name
                    .strip_suffix(b".dist-info/WHEEL")
                    .is_some_and(|dir| !dir.is_empty() && !dir.contains(&b'/')) =>
                {
                    m.wheel = true;
                }
                _ if name.starts_with(b"Payload/")
                    && memchr::memmem::find(name, b".app/").is_some() =>
                {
                    m.ipa = true;
                }
                _ => {}
            }
        }
        m.complete = names.complete;
        m
    }
}

/// Markers whose bytes anywhere in a zip are evidence when the entry walk
/// lost the thread, or which gate a costlier check. Found in one pass.
#[derive(Clone, Copy)]
enum Marker {
    ContentTypes,
    VsixManifest,
    AppxManifest,
    AppxBundleManifest,
    OpenDocumentMime,
    ComposerJson,
}

impl Marker {
    const ALL: [Self; 6] = [
        Self::ContentTypes,
        Self::VsixManifest,
        Self::AppxManifest,
        Self::AppxBundleManifest,
        Self::OpenDocumentMime,
        Self::ComposerJson,
    ];

    const fn needle(self) -> &'static str {
        match self {
            Self::ContentTypes => "[Content_Types].xml",
            Self::VsixManifest => "extension.vsixmanifest",
            Self::AppxManifest => "AppxManifest.xml",
            Self::AppxBundleManifest => "AppxMetadata/AppxBundleManifest.xml",
            Self::OpenDocumentMime => "application/vnd.oasis.opendocument.",
            Self::ComposerJson => "composer.json",
        }
    }
}

/// The automaton over every [`Marker`]. The needles are fixed, so a build
/// failure is a bug here, not something an input can cause.
static MARKERS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(Marker::ALL.map(Marker::needle))
        .expect("zip markers are a valid Aho-Corasick set")
});

/// Which [`Marker`]s occur anywhere in `data`, as a bit per marker.
fn markers_in(data: &[u8]) -> u8 {
    let mut found = 0u8;
    for m in MARKERS.find_overlapping_iter(data) {
        found |= 1 << m.pattern().as_usize();
        if found.count_ones() as usize == Marker::ALL.len() {
            break;
        }
    }
    found
}

/// The zip-based package a name claims, trusted when no member contradicts
/// it. Office names are absent on purpose: an office extension is a claim,
/// not the format, and without the OPC marker the file is a zip. `.apk` is
/// shared with Alpine's gzip tar, so the name says Zip; a zip so named is an
/// Android package.
fn zip_name_claim(sniff: &Sniff<'_>) -> Option<FileType> {
    if path_ends_with_ci(sniff.path, b".apk") {
        return Some(FileType::ApkAndroid);
    }
    sniff.ext_type().filter(|ft| {
        ft.archive_format() == Some(ArchiveFormat::Zip)
            && !matches!(ft, FileType::Zip | FileType::Crx)
    })
}

/// Classify a zip by the members only one kind of package carries; the name
/// settles only what the members leave open.
///
/// That order decides whether anything looks inside. A file typed Ooxml goes
/// to the office analyzer, which reads OPC parts; a file typed Zip goes to the
/// archive analyzer, which walks the members. A zip holding one payload under
/// an Office name must reach the archive analyzer, and an APK, JAR or NuGet
/// package delivered without its extension must still reach its own.
pub(super) fn classify_pk(sniff: &Sniff<'_>) -> FileType {
    let data = sniff.data;
    let m = ZipMarks::scan(data);
    let found = std::cell::OnceCell::new();
    let present =
        |marker: Marker| *found.get_or_init(|| markers_in(data)) & (1 << marker as u8) != 0;
    // Where the walk lost the thread, a marker's bytes anywhere are the best
    // evidence left.
    let loose = |marker: Marker| !m.complete && present(marker);
    let opc = m.content_types || loose(Marker::ContentTypes);
    // A name that claims an archive, not a document: a zip so named holding
    // an OPC `[Content_Types].xml` stays the archive it says it is.
    let archive_name = sniff.ext_type().is_some_and(|ft| ft.is_archive());
    // An OpenDocument file stores `mimetype` first; an Android package can
    // carry the namespace URI in any of its resources and is not one.
    let odf = m.mimetype && present(Marker::OpenDocumentMime);

    if go_module::recognized(sniff) {
        FileType::GoModule
    } else if m.android {
        FileType::ApkAndroid
    } else if m.vsix || loose(Marker::VsixManifest) {
        // VSIX and NuGet are OPC zips too; their manifests win.
        FileType::Vsix
    } else if m.appx || loose(Marker::AppxManifest) || loose(Marker::AppxBundleManifest) {
        // So are MSIX/APPX packages, which carry whole application trees
        // (a bundled Python runtime, helper executables) that only the archive
        // analyzer walks. The manifest is usually written last, past the
        // entry cap on a large package, hence the loose fallback.
        FileType::Zip
    } else if opc && m.nuspec {
        FileType::Nupkg
    } else if opc && !archive_name {
        FileType::Ooxml
    } else if odf {
        FileType::Odf
    } else if let Some(claimed) = zip_name_claim(sniff) {
        claimed
    } else if m.ipa {
        FileType::Ipa
    } else if m.wheel {
        FileType::Whl
    } else if m.egg {
        FileType::Egg
    } else if m.conda_metadata && m.conda_info {
        FileType::Conda
    } else if m.xpi {
        FileType::Xpi
    } else if m.jar {
        FileType::Jar
    } else if present(Marker::ComposerJson) && package_layout::composer_zip(sniff) {
        FileType::Composer
    } else {
        FileType::Zip
    }
}
