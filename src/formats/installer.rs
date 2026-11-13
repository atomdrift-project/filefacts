//! Self-extracting installers a PE carries in its own body: NSIS, Inno
//! Setup, PyInstaller, Nuitka one-file, IExpress cabinets and InstallShield
//! `ISSetupStream` launchers.
//!
//! Each format writes a marker its runtime looks for -- the NSIS
//! `0xDEADBEEF` first header beside its strings, Inno's setup-data banner,
//! PyInstaller's cookie, Nuitka's one-file runtime and compressed payload,
//! IExpress's UTF-16 `CABINET`/`RUNPROGRAM` resource names around a cabinet.
//! A marker inside an embedded image (`binary.embedded[]`) belongs to that
//! child, not to the host, so it is not counted here.
//!
//! `binary.installer = {kind, marker_offset}` names the installer and where
//! its data starts; a consumer that unpacks installers reads it. A
//! PyInstaller bundle adds `python_version` (`"3.11"`), the interpreter its
//! cookie names. An InstallShield launcher adds `entry_count` and `entries`
//! (`name`, absolute `offset`, `stored_size`) from its stream table, which
//! [`installshield`] decodes. An NSIS installer whose header decodes adds
//! `script`: its install commands, rendered and by kind (see
//! [`nsis::script`]).

pub(crate) mod installshield;
pub(crate) mod nsis;

use memchr::memmem;
use serde_json::{Map, Value as JsonValue};

use super::embedded::EmbeddedBinary;
use crate::bytes::{u16_le, u32_be, u32_le};
use crate::output::Values;
use crate::value_key;

const NSIS_DEADBEEF: &[u8] = &[0xEF, 0xBE, 0xAD, 0xDE];
const NSIS_STRINGS: [&[u8]; 4] = [
    b"Nullsoft Install System",
    b"NSIS Error",
    b"nsis.sf.net/NSIS_Error",
    b"/NCRC",
];
const INNO_MARKER: &[u8] = b"Inno Setup Setup Data";
const PYINSTALLER_COOKIE: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const NUITKA_RUNTIME: &[u8] = b"NUITKA_ONEFILE_";
const NUITKA_PAYLOAD: &[u8] = b"KAY\x28\xb5\x2f\xfd";
const CABINET: &[u8] = b"MSCF";

/// Emit `binary.installer` for the PE `data`, given its embedded images.
pub(crate) fn emit(data: &[u8], embedded: &[EmbeddedBinary], values: &mut Values) {
    let Some((kind, marker_offset)) = detect(data, embedded) else {
        return;
    };
    let mut obj = Map::new();
    obj.insert("kind".into(), kind.into());
    if let Some(offset) = marker_offset {
        obj.insert("marker_offset".into(), offset.into());
        if kind == "pyinstaller"
            && let Some(version) = pyinstaller_python_version(data, offset)
        {
            obj.insert("python_version".into(), version.into());
        }
        if kind == "installshield" {
            installshield_values(data, offset, &mut obj);
        }
    }
    if kind == "nsis" {
        match nsis::script(data) {
            Ok(script) => {
                obj.insert("script".into(), nsis::values(&script));
            }
            Err(error) => {
                tracing::debug!(target: "filefacts::nsis", %error, "NSIS install script not decoded");
            }
        }
    }
    values.insert_key(value_key!("binary.installer"), JsonValue::Object(obj));
}

/// Most `ISSetupStream` entries listed in the values.
const MAX_LISTED_ENTRIES: usize = 512;

/// The `ISSetupStream` table at `offset`: its entry count and entries.
fn installshield_values(data: &[u8], offset: usize, obj: &mut Map<String, JsonValue>) {
    let Some(listing) = data
        .get(offset..)
        .and_then(|stream| installshield::entries(stream).ok())
    else {
        return;
    };
    obj.insert("entry_count".into(), listing.declared.into());
    obj.insert("complete".into(), listing.complete.into());
    let entries = listing
        .entries
        .iter()
        .take(MAX_LISTED_ENTRIES)
        .map(|entry| {
            let mut item = Map::new();
            item.insert("name".into(), entry.name.clone().into());
            item.insert("offset".into(), offset.saturating_add(entry.offset).into());
            item.insert("stored_size".into(), entry.stored_size.into());
            JsonValue::Object(item)
        })
        .collect();
    obj.insert("entries".into(), JsonValue::Array(entries));
}

/// The Python version a PyInstaller cookie at `cookie` names: a big-endian
/// `u32` 20 bytes in, `major * 100 + minor` (`311`), or `major * 10 + minor`
/// before Python 3.10 (`27`, `39`).
fn pyinstaller_python_version(data: &[u8], cookie: usize) -> Option<String> {
    let encoded = u32_be(data, cookie.checked_add(20)?)?;
    let (major, minor) = if encoded >= 100 {
        (encoded / 100, encoded % 100)
    } else {
        (encoded / 10, encoded % 10)
    };
    (2..=3).contains(&major).then(|| format!("{major}.{minor}"))
}

/// The installer kind and the offset of the marker its data starts at.
pub(crate) fn detect(
    data: &[u8],
    embedded: &[EmbeddedBinary],
) -> Option<(&'static str, Option<usize>)> {
    let outside = |marker: &[u8]| marker_outside(data, marker, embedded);
    if let Some(at) = installshield::find(data).filter(|&at| !inside_image(at, embedded)) {
        return Some(("installshield", Some(at)));
    }
    if let Some(at) = outside(INNO_MARKER) {
        return Some(("inno", Some(at)));
    }
    if let Some(at) = outside(NSIS_DEADBEEF)
        && NSIS_STRINGS.iter().any(|s| outside(s).is_some())
    {
        return Some(("nsis", Some(at)));
    }
    if let Some(at) = outside(PYINSTALLER_COOKIE) {
        return Some(("pyinstaller", Some(at)));
    }
    if outside(NUITKA_RUNTIME).is_some()
        && let Some(at) = outside(NUITKA_PAYLOAD)
    {
        return Some(("nuitka", Some(at)));
    }
    if let Some(at) = iexpress_cabinet(data, embedded) {
        return Some(("iexpress", Some(at)));
    }
    None
}

/// The first `marker` that does not lie inside a raw embedded image.
fn marker_outside(data: &[u8], marker: &[u8], embedded: &[EmbeddedBinary]) -> Option<usize> {
    memmem::find_iter(data, marker).find(|&offset| !inside_image(offset, embedded))
}

fn inside_image(offset: usize, embedded: &[EmbeddedBinary]) -> bool {
    embedded.iter().any(|image| {
        image.encoding.is_none()
            && offset >= image.offset
            && offset < image.offset.saturating_add(image.size)
    })
}

/// IExpress stores its format-mandated `CABINET` and `RUNPROGRAM` resource
/// names as UTF-16. Both are required, and a bounded, structurally plausible
/// cabinet, rather than inferring a bundle from a vendor string or bare
/// `MSCF` bytes.
fn iexpress_cabinet(data: &[u8], embedded: &[EmbeddedBinary]) -> Option<usize> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    for name in ["CABINET", "RUNPROGRAM"] {
        let marker: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        marker_outside(data, &marker, embedded)?;
    }
    memmem::find_iter(data, CABINET).find(|&offset| {
        if inside_image(offset, embedded) {
            return false;
        }
        let Some(header) = data.get(offset..offset.saturating_add(36)) else {
            return false;
        };
        let (Some(len), Some(files)) = (u32_le(header, 8), u32_le(header, 16)) else {
            return false;
        };
        let (Ok(len), Ok(files)) = (usize::try_from(len), usize::try_from(files)) else {
            return false;
        };
        header.get(4..8) == Some(&[0; 4])
            && header.get(24..26) == Some(&[3, 1])
            && len >= 36
            && files >= 36
            && files < len
            && u16_le(header, 26).is_some_and(|folders| folders > 0)
            && u16_le(header, 28).is_some_and(|count| count > 0)
            && data.get(offset..offset.saturating_add(len)).is_some()
    })
}

#[cfg(test)]
mod tests;
