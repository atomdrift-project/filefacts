#!/usr/bin/env python3
"""Generate src/formats/pe/ordinal_names.rs: the export names behind the
ordinals of DLLs that programs import by ordinal, for naming imports.

Sources, each the DLL's own record of its exports:

- msi.dll, comctl32.dll (5.82 and 6.0), cabinet.dll: the export tables of
  the 32-bit DLLs a Windows installation ships (SysWOW64, and WinSxS for
  comctl32 6.0). Paths are given on the command line.
- mfc42.dll, mfc42u.dll: Ghidra's export lists (Apache-2.0),
  Ghidra/Features/Base/data/symbols/win32/<dll>.exports. MFC exports by
  ordinal only, so the DLL itself carries no names.
- coredll.dll, commctrl.dll (Windows CE): the export files (`.exp`, COFF
  objects holding the `.edata` the linker writes into the DLL) of
  Microsoft's Windows CE 5.0 Standard SDK (STANDARD_SDK.msi, from
  download.microsoft.com). `7z x` extracts them from the MSI as
  `_<n>coredll_exp` and `_<n>commctrl_exp`, one or more per CPU: Thumb
  (ARMV4I), x86, SH4, MIPS and MIPSFPU, as each file's COFF machine says.

Usage:
  gen_ordinal_names.py OUT.rs DLL[@CPU]=PATH...
  e.g. msi=msi.dll mfc42=mfc42.exports coredll@arm=_6coredll_exp

A DLL given several sources for one CPU (or none) keeps only the ordinals
they all name alike; one version renumbering an export drops it. A DLL
given per-CPU sources, as coredll is (its ordinals differ between CPUs),
becomes a table of the ordinals every CPU names alike, `DLL`, and one per
CPU, `DLL_CPU`, of the rest of that CPU's.
"""

import re
import struct
import sys


def pe_exports(path):
    """(ordinal, name) of each named export in the PE at `path`."""
    data = open(path, 'rb').read()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise SystemExit(f'{path}: no PE signature')
    nsections, = struct.unpack_from('<H', data, pe + 6)
    optional_size, = struct.unpack_from('<H', data, pe + 20)
    optional = pe + 24
    magic, = struct.unpack_from('<H', data, optional)
    directories = optional + (96 if magic == 0x10b else 112)
    export_rva, _ = struct.unpack_from('<II', data, directories)
    sections = []
    for i in range(nsections):
        at = optional + optional_size + 40 * i
        vsize, va, raw_size, raw = struct.unpack_from('<IIII', data, at + 8)
        sections.append((va, max(vsize, raw_size), raw))

    def offset(rva):
        for va, size, raw in sections:
            if va <= rva < va + size:
                return rva - va + raw
        raise SystemExit(f'{path}: RVA {rva:#x} in no section')

    def cstr(rva):
        at = offset(rva)
        return data[at:data.index(b'\0', at)].decode('ascii')

    d = offset(export_rva)
    base, nfunctions, nnames, functions, names, ordinals = struct.unpack_from('<IIIIII', data, d + 16)
    out = []
    for i in range(nnames):
        name_rva, = struct.unpack_from('<I', data, offset(names) + 4 * i)
        index, = struct.unpack_from('<H', data, offset(ordinals) + 2 * i)
        out.append((base + index, cstr(name_rva)))
    return out


def exp_exports(path):
    """(ordinal, name) of each named export in a COFF export file (`.exp`):
    the export directory a linker writes into the DLL, as `.edata`, whose
    table pointers are offsets into that section (relocated at link)."""
    data = open(path, 'rb').read()
    nsections, = struct.unpack_from('<H', data, 2)
    symbols, nsymbols = struct.unpack_from('<II', data, 8)
    optional_size, = struct.unpack_from('<H', data, 16)
    for i in range(nsections):
        at = 20 + optional_size + 40 * i
        if data[at:at + 8].rstrip(b'\0') == b'.edata':
            size, raw, relocs = struct.unpack_from('<III', data, at + 16)
            nrelocs, = struct.unpack_from('<H', data, at + 32)
            edata = bytearray(data[raw:raw + size])
            number = i + 1
            break
    else:
        raise SystemExit(f'{path}: no .edata')
    # Apply each relocation against a symbol of `.edata` itself (the section,
    # or a label in it): the stored addend plus the symbol's offset.
    for r in range(nrelocs):
        where, index = struct.unpack_from('<II', data, relocs + 10 * r)
        value, section = struct.unpack_from('<Ih', data, symbols + 18 * index + 8)
        if section == number:
            addend, = struct.unpack_from('<I', edata, where)
            struct.pack_into('<I', edata, where, addend + value)
    edata = bytes(edata)
    base, _, nnames, _, names, ordinals = struct.unpack_from('<IIIIII', edata, 16)

    def cstr(at):
        return edata[at:edata.index(b'\0', at)].decode('ascii')

    return [(base + struct.unpack_from('<H', edata, ordinals + 2 * i)[0],
             cstr(struct.unpack_from('<I', edata, names + 4 * i)[0]))
            for i in range(nnames)]


def ghidra_exports(path):
    """(ordinal, name) of each export in a Ghidra `.exports` file."""
    text = open(path, encoding='utf-8').read()
    return [(int(o), n) for o, n in re.findall(r'<EXPORT ORDINAL="(\d+)" NAME="([^"]*)"', text)
            if n and not n.startswith('Ordinal_')]


def rust_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def main():
    out_path, *specs = sys.argv[1:]
    tables = {}  # (dll, cpu or None) -> {ordinal: name}
    sources = {}
    for spec in specs:
        key, path = spec.split('=', 1)
        dll, _, cpu = key.partition('@')
        key = (dll, cpu or None)
        if path.endswith('.exports'):
            entries = ghidra_exports(path)
        elif path.lower().endswith(('.exp', '_exp')):
            entries = exp_exports(path)
        else:
            entries = pe_exports(path)
        found = dict(entries)
        if key in tables:
            agreed = {o: n for o, n in tables[key].items() if found.get(o) == n}
            if len(agreed) < len(tables[key]):
                print(f'{key_name(key)}: {len(tables[key]) - len(agreed)} ordinals dropped, '
                      'sources disagree', file=sys.stderr)
            found = agreed
        tables[key] = found
        sources.setdefault(dll, []).append(path.replace('\\', '/').split('/')[-1])
    per_cpu = {}
    # Split each per-CPU DLL into what every CPU agrees on and the rest.
    for dll in sorted({d for d, c in tables if c}):
        if (dll, None) in tables:
            raise SystemExit(f'{dll}: sources with and without a CPU')
        cpus = [tables[k] for k in tables if k[0] == dll]
        common = {o: n for o, n in cpus[0].items() if all(t.get(o) == n for t in cpus)}
        for k in [k for k in tables if k[0] == dll]:
            tables[k] = {o: n for o, n in tables[k].items() if o not in common}
        tables[(dll, None)] = common
        per_cpu[dll] = sorted(c for d, c in tables if d == dll and c)
        for k in [k for k in tables if k[0] == dll and k[1] and not tables[k]]:
            del tables[k]
    lines = [
        '//! Export names behind the ordinals of DLLs programs import by ordinal,',
        '//! for naming those imports. Generated by `scripts/gen_ordinal_names.py`',
        '//! from each DLL\'s own export table (MFC\'s, which carries no names, from',
        '//! Ghidra\'s export lists; Windows CE\'s from its SDK\'s export files); do',
        '//! not edit. The imphash does not use these: it names ordinals only as',
        '//! pefile does (see `ordinals.rs`). Sorted by ordinal.',
        '',
    ]
    for key in sorted(tables, key=lambda k: (k[0], k[1] or '')):
        dll, cpu = key
        if cpu:
            lines.append(f'/// `{dll}.dll` on {cpu}: the ordinals it does not share with')
            lines.append(f'/// every CPU\'s `{dll}.dll`.')
        elif dll in per_cpu:
            lines.append(f'/// `{dll}.dll` on every CPU, from its export files for '
                         f'{", ".join(per_cpu[dll])}.')
        else:
            lines.append(f'/// `{dll}.dll`, from {", ".join(sorted(set(sources[dll])))}.')
        lines.append(f'pub(super) const {key_name(key)}: &[(u16, &str)] = &[')
        for ordinal in sorted(tables[key]):
            lines.append(f'    ({ordinal}, {rust_str(tables[key][ordinal])}),')
        lines.append('];')
        lines.append('')
    open(out_path, 'w', encoding='utf-8', newline='\n').write('\n'.join(lines))
    for key in sorted(tables, key=lambda k: (k[0], k[1] or '')):
        print(key_name(key), len(tables[key]))


def key_name(key):
    dll, cpu = key
    return dll.upper() + ('_' + cpu.upper() if cpu else '')


main()
