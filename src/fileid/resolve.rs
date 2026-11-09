//! A file's type, layered the way a consumer analyzing it needs: what
//! [`detect`](super::detect) says, then the conventions it leaves out.
//!
//! - A name like `.env`, `.PKGINFO` or `*.rsc` says "inert text", and the
//!   caller chooses the name; letting it outrank the bytes would let a
//!   script saved as `.env` (or an ELF, or a zip) be read as text. For
//!   those names the bytes are asked alone, and code, binaries and archives
//!   are typed by what they are; content nothing recognizes keeps the
//!   name's type.
//! - Content nothing else recognizes gets a last-resort VBScript sniff.
//! - `Cargo.toml`, `go.mod` and `pyproject.toml` are typed by basename, and
//!   `.dat`/`.bin`/`.payload`/`.raw`/`.map` as opaque data.

use std::path::Path;

use super::FileType;

/// The type `path` declares by its name alone: for comparing a name with
/// what the bytes say, or retrying a member whose detected format failed to
/// parse. Use [`file_type`] to know what a file *is*.
#[must_use]
pub fn declared_file_type(path: &Path) -> FileType {
    if is_dotenv_name(path) || is_arch_package_metadata_name(path) || is_routeros_script_name(path)
    {
        return FileType::Text;
    }
    super::detect_path(path)
        .map(|d| d.file_type)
        .filter(|ft| *ft != FileType::Unknown)
        .or_else(|| known_manifest_type_from_basename(path))
        .or_else(|| known_data_type_from_extension(path))
        .unwrap_or(FileType::Unknown)
}

/// What the file at `path` holding `data` is: content first, then the name.
#[must_use]
pub fn file_type(path: &Path, data: &[u8]) -> FileType {
    file_type_with(path, data, super::detect(path, data).map(|d| d.file_type))
}

/// [`file_type`] with [`detect`](super::detect)'s answer already in hand,
/// for a caller that also needs the full detection (on a compressed tar it
/// inflates up to 64 MiB to decide npm/sdist).
#[must_use]
pub fn file_type_with(path: &Path, data: &[u8], detected: Option<FileType>) -> FileType {
    let inert_name = is_dotenv_name(path)
        || is_arch_package_metadata_name(path)
        || is_routeros_script_name(path);
    let detected = inert_name
        .then(|| super::detect(Path::new("content"), data))
        .flatten()
        .map(|d| d.file_type)
        .filter(|ft| ft.is_source_code() || ft.is_executable_code() || ft.is_archive())
        .or(detected);
    detected
        .filter(|ft| *ft != FileType::Unknown)
        .or_else(|| sniff_script(data))
        .or_else(|| inert_name.then_some(FileType::Text))
        .or_else(|| known_manifest_type_from_basename(path))
        .or_else(|| known_data_type_from_extension(path))
        .unwrap_or(FileType::Unknown)
}

/// VBScript idioms, lowercase ASCII spelling. A file is called VBScript when
/// [`VBS_MARKER_THRESHOLD`] *distinct* markers appear anywhere in it.
const VBS_MARKERS: [&str; 8] = [
    "on error resume next",
    "createobject(",
    "createobject (",
    "wscript.shell",
    "wscript.scriptfullname",
    "function ",
    "end function",
    ".run ",
];

const VBS_MARKER_THRESHOLD: u32 = 3;

/// Markers in both ASCII and UTF-16LE spelling: pattern `i` is
/// `VBS_MARKERS[i]`, pattern `i + VBS_MARKERS.len()` is its wide form, so
/// `index % VBS_MARKERS.len()` recovers the marker either way. Matching is
/// ASCII-case-insensitive, which leaves the wide form's interleaved NULs
/// untouched.
fn vbs_marker_automaton() -> Option<&'static aho_corasick::AhoCorasick> {
    static AUTOMATON: std::sync::OnceLock<Option<aho_corasick::AhoCorasick>> =
        std::sync::OnceLock::new();
    AUTOMATON
        .get_or_init(|| {
            let ascii = VBS_MARKERS.iter().map(|m| m.as_bytes().to_vec());
            let wide = VBS_MARKERS
                .iter()
                .map(|m| m.bytes().flat_map(|b| [b, 0]).collect::<Vec<u8>>());
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(ascii.chain(wide).collect::<Vec<_>>())
                .ok()
        })
        .as_ref()
}

/// Largest input the script sniff will look at. See
/// [`sniff_script`] for why it is capped.
const SCRIPT_SNIFF_MAX_BYTES: usize = 4 << 20;

/// Last-resort VBScript sniff, for content that magic bytes, extension, and
/// filefacts' prefix heuristics all left unidentified.
///
/// Scans the raw bytes once for VBScript idioms in both ASCII and UTF-16LE
/// spelling, case-insensitively — the needle is transcoded, never the
/// haystack, the same way stng matches wide strings. Overlapping iteration is
/// required: markers nest (`end function` contains `function `), and
/// non-overlapping matching would let the outer one consume the inner one's
/// occurrence, which is not what "does this marker appear?" means.
///
/// **Capped by size**, because this sniff's precision collapses as inputs grow.
/// Several markers are generic (`function `, `.run `), so the chance that a
/// large file contains three of them *somewhere* approaches 1 regardless of
/// what it holds. A 1.5 GB APFS partition image inside a `.dmg` hit exactly
/// `function `, `end function`, and `.run ` — at offsets 157 MB, 268 MB and
/// 397 MB, none within 100 MB of another — and was analyzed as VBScript, which
/// pushed the whole disk image through the source-code path. Delivered
/// VBScript is kilobytes; a file over the cap is not a script this fallback
/// was built to catch, and both the magic and extension paths still see it.
fn sniff_script(data: &[u8]) -> Option<FileType> {
    if data.len() > SCRIPT_SNIFF_MAX_BYTES {
        return None;
    }

    // Compiled YARA-X databases contain fragments from many unrelated scripts.
    // Their binary header is not script source, even when those fragments
    // satisfy the fallback VBScript marker threshold.
    if data.starts_with(b"YARA-X\0\0") {
        return None;
    }

    let mut seen: u32 = 0;
    for m in vbs_marker_automaton()?.find_overlapping_iter(data) {
        seen |= 1 << (m.pattern().as_usize() % VBS_MARKERS.len());
        if seen.count_ones() >= VBS_MARKER_THRESHOLD {
            return Some(FileType::Vbs);
        }
    }

    None
}

fn is_dotenv_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    name == ".env" || name == ".env.backup" || name.starts_with(".env.backup.")
}

fn known_manifest_type_from_basename(file_path: &Path) -> Option<FileType> {
    let name = file_path.file_name()?.to_str()?.to_ascii_lowercase();
    match name.as_str() {
        "cargo.toml" => Some(FileType::CargoToml),
        "go.mod" => Some(FileType::GoMod),
        "pyproject.toml" => Some(FileType::PyProjectToml),
        _ => None,
    }
}

fn known_data_type_from_extension(file_path: &Path) -> Option<FileType> {
    let extension = file_path.extension()?.to_str()?.to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "dat" | "bin" | "payload" | "raw" | "map"
    )
    .then_some(FileType::Data)
}

fn is_arch_package_metadata_name(file_path: &Path) -> bool {
    let Some(name) = file_path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".pkginfo" | ".buildinfo" | ".mtree"
    )
}

fn is_routeros_script_name(file_path: &Path) -> bool {
    file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rsc"))
}

#[cfg(test)]
mod tests;
