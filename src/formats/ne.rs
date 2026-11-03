//! Bounded extraction of import references from 16-bit NE relocation tables.
//!
//! The ordinal names below cover common Windows 3.x APIs. Other platforms and
//! unrecognized ordinals retain their numeric identity instead of guessing.
//! NE layout and the Win16 ordinal conventions can be checked against Wine's
//! `tools/winedump/ne.c` and its `dlls/*.exe16/*.spec` files.

use std::collections::BTreeSet;

use crate::error::Error;
use crate::metric;
use crate::output::{Metrics, Symbol, Symbols};

const MAX_SEGMENTS: usize = 4096;
const MAX_RELOCATIONS: usize = 65_536;

fn word(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn dword(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn pascal(data: &[u8], offset: usize) -> Option<String> {
    let n = usize::from(*data.get(offset)?);
    if n == 0 {
        return None;
    }
    let start = offset.checked_add(1)?;
    let bytes = data.get(start..start.checked_add(n)?)?;
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

fn ordinal_name(library: &str, ordinal: u16) -> Option<&'static str> {
    Some(match (library, ordinal) {
        ("kernel", 1) => "FatalExit",
        ("kernel", 3) => "GetVersion",
        ("kernel", 5) => "LocalAlloc",
        ("kernel", 6) => "LocalReAlloc",
        ("kernel", 7) => "LocalFree",
        ("kernel", 10) => "LocalSize",
        ("kernel", 15) => "GlobalAlloc",
        ("kernel", 16) => "GlobalReAlloc",
        ("kernel", 18) => "GlobalLock",
        ("kernel", 19) => "GlobalUnlock",
        ("kernel", 20) => "GlobalSize",
        ("kernel", 23) => "LockSegment",
        ("kernel", 24) => "UnlockSegment",
        ("kernel", 30) => "WaitEvent",
        ("kernel", 49) => "GetModuleFileName",
        ("kernel", 50) => "GetProcAddress",
        ("kernel", 51) => "MakeProcInstance",
        ("kernel", 59) => "WriteProfileString",
        ("kernel", 60) => "FindResource",
        ("kernel", 61) => "LoadResource",
        ("kernel", 62) => "LockResource",
        ("kernel", 63) => "FreeResource",
        ("kernel", 74) => "OpenFile",
        ("kernel", 81) => "_lclose",
        ("kernel", 82) => "_lread",
        ("kernel", 83) => "_lcreat",
        ("kernel", 85) => "_lopen",
        ("kernel", 86) => "_lwrite",
        ("kernel", 91) => "InitTask",
        ("kernel", 95) => "LoadLibrary",
        ("kernel", 102) => "DOS3Call",
        ("kernel", 129) => "WritePrivateProfileString",
        ("kernel", 131) => "GetDOSEnvironment",
        ("kernel", 132) => "GetWinFlags",
        ("kernel", 137) => "FatalAppExit",
        ("kernel", 146) => "DeleteFile",
        ("kernel", 166) => "WinExec",
        ("kernel", 169) => "GetFreeSpace",
        ("kernel", 171) => "AllocDStoCSAlias",
        ("kernel", 176) => "FreeSelector",
        ("kernel", 178) => "__WINFLAGS",
        ("kernel", 197) => "GlobalFix",
        ("kernel", 198) => "GlobalUnfix",
        ("user", 1) => "MessageBox",
        ("user", 5) => "InitApp",
        ("user", 6) => "PostQuitMessage",
        ("user", 7) => "ExitWindows",
        ("user", 10) => "SetTimer",
        ("user", 12) => "KillTimer",
        ("user", 13) => "GetTickCount",
        ("user", 41) => "CreateWindow",
        ("user", 45) => "BringWindowToTop",
        ("user", 50) => "FindWindow",
        ("user", 53) => "DestroyWindow",
        ("user", 57) => "RegisterClass",
        ("user", 66) => "GetDC",
        ("user", 68) => "ReleaseDC",
        ("user", 104) => "MessageBeep",
        ("user", 106) => "GetKeyState",
        ("user", 107) => "DefWindowProc",
        ("user", 108) => "GetMessage",
        ("user", 111) => "SendMessage",
        ("user", 113) => "TranslateMessage",
        ("user", 114) => "DispatchMessage",
        ("user", 121) => "SetWindowsHook",
        ("user", 125) => "InvalidateRect",
        ("user", 137) => "OpenClipboard",
        ("user", 138) => "CloseClipboard",
        ("user", 139) => "EmptyClipboard",
        ("user", 141) => "SetClipboardData",
        ("user", 156) => "GetSystemMenu",
        ("user", 173) => "LoadCursor",
        ("user", 174) => "LoadIcon",
        ("user", 175) => "LoadBitmap",
        ("user", 179) => "GetSystemMetrics",
        ("user", 249) => "GetAsyncKeyState",
        ("user", 286) => "GetDesktopWindow",
        ("user", 291) => "SetWindowsHookEx",
        ("user", 411) => "AppendMenu",
        ("user", 452) => "CreateWindowEx",
        ("gdi", 1) => "SetBkColor",
        ("gdi", 3) => "SetMapMode",
        ("gdi", 34) => "BitBlt",
        ("gdi", 45) => "SelectObject",
        ("gdi", 48) => "CreateBitmap",
        ("gdi", 51) => "CreateCompatibleBitmap",
        ("gdi", 52) => "CreateCompatibleDC",
        ("gdi", 53) => "CreateDC",
        ("gdi", 67) => "DPtoLP",
        ("gdi", 68) => "DeleteDC",
        ("gdi", 69) => "DeleteObject",
        ("gdi", 81) => "GetMapMode",
        ("gdi", 82) => "GetObject",
        ("gdi", 87) => "GetStockObject",
        ("mmsystem", 2) => "sndPlaySound",
        ("shell", 2) => "RegCreateKey",
        ("shell", 3) => "RegCloseKey",
        ("shell", 5) => "RegSetValue",
        _ => return None,
    })
}

pub(super) fn extract(
    data: &[u8],
    symbols: &mut Symbols,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    fn parse(data: &[u8]) -> Option<(Vec<Symbol>, usize)> {
        if data.get(..2)? != b"MZ" {
            return None;
        }
        let base = usize::try_from(dword(data, 0x3c)?).ok()?;
        if data.get(base..base.checked_add(2)?)? != b"NE" {
            return None;
        }
        let segments = usize::from(word(data, base.checked_add(0x1c)?)?);
        let modules = usize::from(word(data, base.checked_add(0x1e)?)?);
        if segments > MAX_SEGMENTS || modules > MAX_SEGMENTS {
            return None;
        }
        let segment_table = base.checked_add(usize::from(word(data, base.checked_add(0x22)?)?))?;
        let module_table = base.checked_add(usize::from(word(data, base.checked_add(0x28)?)?))?;
        let import_table = base.checked_add(usize::from(word(data, base.checked_add(0x2a)?)?))?;
        let shift = u32::from(word(data, base.checked_add(0x32)?)?);
        if shift > 16 {
            return None;
        }
        let windows = *data.get(base.checked_add(0x36)?)? == 2;
        data.get(segment_table..segment_table.checked_add(segments.checked_mul(8)?)?)?;
        data.get(module_table..module_table.checked_add(modules.checked_mul(2)?)?)?;
        let mut names = Vec::with_capacity(modules);
        for index in 0..modules {
            let offset = usize::from(word(
                data,
                module_table.checked_add(index.checked_mul(2)?)?,
            )?);
            names.push(pascal(data, import_table.checked_add(offset)?)?.to_ascii_lowercase());
        }
        let mut output = Vec::new();
        let mut seen = BTreeSet::new();
        let mut total = 0usize;
        for index in 0..segments {
            let entry = segment_table.checked_add(index.checked_mul(8)?)?;
            let sector = usize::from(word(data, entry)?);
            let size = usize::from(word(data, entry.checked_add(2)?)?);
            let flags = word(data, entry.checked_add(4)?)?;
            if sector == 0 || flags & 0x0100 == 0 {
                continue;
            }
            let start = sector.checked_shl(shift)?;
            let table = start.checked_add(if size == 0 { 65_536 } else { size })?;
            let count = usize::from(word(data, table)?);
            total = total.checked_add(count)?;
            if total > MAX_RELOCATIONS {
                return None;
            }
            let records = table.checked_add(2)?;
            data.get(records..records.checked_add(count.checked_mul(8)?)?)?;
            for r in 0..count {
                let at = records.checked_add(r.checked_mul(8)?)?;
                let kind = *data.get(at.checked_add(1)?)? & 3;
                if kind != 1 && kind != 2 {
                    continue;
                }
                let module = usize::from(word(data, at.checked_add(4)?)?);
                let lib = names.get(module.checked_sub(1)?)?;
                let target = word(data, at.checked_add(6)?)?;
                let (name, ordinal) = if kind == 1 {
                    let name = windows
                        .then(|| ordinal_name(lib, target))
                        .flatten()
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("ordinal_{target}"));
                    (name, Some(u32::from(target)))
                } else {
                    (
                        pascal(data, import_table.checked_add(usize::from(target))?)?,
                        None,
                    )
                };
                if seen.insert((lib.clone(), name.clone(), ordinal)) {
                    output.push(Symbol::Import {
                        name,
                        alias: None,
                        library: Some(lib.clone()),
                        offset: Some(at as u64),
                        ordinal,
                    });
                }
            }
        }
        Some((output, names.len()))
    }
    let (imports, dependencies) = parse(data)
        .ok_or_else(|| Error::malformed("ne", "invalid or truncated NE import tables"))?;
    for import in imports {
        symbols.push(import);
    }
    metrics.insert(metric!("dependencies.count"), dependencies as f64);
    Ok(())
}

#[cfg(test)]
mod tests;
