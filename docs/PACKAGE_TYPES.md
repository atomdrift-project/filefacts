# Package-type identity (distinct from container format)

## Goal

Treat each **package ecosystem** (npm, PyPI/wheel, RubyGems, Cargo, conda,
Debian, RPM, Alpine, Android, …) as its own `FileType`, *separate from the
underlying container format* (zip, tar, gzip-tar, ar). Downstream this gives
every major package type its own litmus model "for free" (litmus discovers
`filetypes/<type>/` model bundles by directory and routes on the cleave
`file_type` string — no litmus code change), and its own collimator vocabulary
token (the feature vocab is built dynamically from observed `file_type`s).

Package types stay in the **`archive` file-group** (`fileid::file_group`), so
nothing that consumes the coarse grouping changes. Only the fine-grained
`file_type` label gains resolution.

This is already the established pattern: `Whl` and `Jar` are distinct
`FileType`s with their own `formats/{whl,jar}.rs` extractors, both mapped to
`"archive"` by `file_group`. `Rpm` already extracts package metadata
(name/version/maintainer/deps) from the header without touching the payload.
This document generalizes that pattern to the rest.

## Two separable jobs

1. **Detection** (`fileid/`): assign the distinct `FileType`. Must be cheap —
   it runs on every file *and every nested archive member*, recursively, across
   hundreds of millions of archives.
2. **Metadata extraction** (`formats/`): emit `<type>.*` facts, including
   metadata that lives *outside* the installed file tree (a gem's
   `metadata.gz`, a deb's `control.tar`, an rpm header). Runs once per
   top-level package, not per member.

## Detection: tiered cost model

The governing rule: **make each discriminator's cost proportional to how
cheaply it can be obtained, and gate every expensive step behind the cheap
one.** Three tiers, each reached only if the prior tier matched:

### Tier 1 — magic byte @ offset 0 (free; already read)

`magic::detect_from_content` already dispatches on `data[0]`. The container
magic alone separates most package families before any member work:

| magic | container | examples |
|---|---|---|
| `PK\x03\x04` | zip | whl, jar, xpi, **apk (Android)**, conda, nupkg, egg, vsix |
| `\x1f\x8b` | gzip(+tar) | npm `.tgz`, `.crate`, **apk (Alpine)** |
| `!<arch>` | ar | deb |
| `0xED AB EE DB` | rpm | rpm |
| `xar!` | xar | **pkg (macOS)** |
| `0x28 B5 2F FD` | zstd(+tar) | **pkg (FreeBSD)**, **pkg (Arch)** |
| `ustar` @257 | plain tar | **gem** |
| `7z\xBC\xAF` / `Rar!` | 7z / rar | — |

Two same-extension collisions are resolved entirely by Tier-1 magic — no member
peek needed:

- **apk-android vs apk-alpine**: Android apks are always zip (`PK`), Alpine apks
  are always gzip-concatenated tar (`\x1f\x8b`). They never overlap.
- **pkg-macos vs pkg-freebsd**: macOS pkgs are XAR (`xar!`), FreeBSD pkgs are
  compressed tars (zstd/xz). Different magic.

### Tier 2 — extension as the prior that gates the peek

Only when `(magic, ext)` matches a *profiled candidate* do we list members at
all. A random `.gz` log or an unprofiled `.tgz` never triggers a peek — it
stays `Gz`/`TarGz`. Each input checks **only its own** candidate marker, never
the whole table. This is what keeps the marginal cost near zero at scale.

### Tier 3 — bounded structured peek (only the residual ambiguities)

Reserved for cases magic+ext cannot resolve:

- **npm `.tgz` vs Rust `.crate`** (both gzip+tar) — root member is
  `package/package.json` vs `<name>-<ver>/Cargo.toml`.
- **pkg-freebsd vs pkg-arch** (both zstd tar) — FreeBSD's first member is
  `+COMPACT_MANIFEST` / `+MANIFEST`; Arch's is `.PKGINFO`. This check already
  exists as `is_freebsd_pkg_zstd` (`magic.rs`), which zstd-decodes the first
  32 bytes and matches the `+MANIFEST` markers. (It currently only covers the
  zstd branch; older FreeBSD `.txz` pkgs need the same marker check added to
  the xz arm.)

Mechanics:

- **zip-family:** `zip::ZipArchive::file_names()` reads only the central
  directory — O(members), no decompression. (What `whl.rs` does.)
- **tar-family:** decompress only until the **first tar header (512 B)** and
  match the root entry; cap at ~8 headers then bail. The root marker is almost
  always entry #1, so this is typically <1 KB of gunzip. **Never decompress
  member bodies during detection.** Use the structured member *name*, not a raw
  `memmem` over compressed bytes (the marker would be compressed, so a raw scan
  both misses and false-positives).

### Efficiency traps to avoid at scale

- **Don't double-open the container.** Detection must not parse the zip central
  directory and then have `formats/` parse it again. Thread the open handle /
  member list through, or push the marker check into the single open the
  dispatcher already does (`formats/mod.rs` opens the zip once for generic +
  jar/whl/xpi facts).
- **Keep metadata extraction off the per-member hot path.** Tier 1–3 detection
  is the only thing that runs on every nested member. The heavier
  `gem.rs`/`deb.rs` metadata parse runs once, for the top-level package.

## Per-type plan

`status`: ✅ done · ◻ new · serialized `file_type` is snake_case of the variant.

### Language ecosystems

| ecosystem | `file_type` | container | detection | metadata source | status |
|---|---|---|---|---|---|
| PyPI wheel | `whl` | zip | ext | `*.dist-info/` METADATA/RECORD | ✅ |
| Java | `jar` | zip | ext | `META-INF/MANIFEST.MF`, pom.properties | ✅ |
| RubyGems | `gem` | plain tar | ext (`ustar`) | **`metadata.gz` (gzipped YAML) — `gem.*`** | ✅ |
| npm | `npm` | gzip tar | ext `.tgz` + `package/package.json` marker peek | `package/package.json` (member-analyzed) | ✅ |
| Cargo | `crate` | gzip tar | ext `.crate` | root `Cargo.toml` (member-analyzed) | ✅ |
| conda | `conda` | zip (`.conda`) | ext | `info/index.json` (member-analyzed) | ✅ |
| Python egg | `egg` | zip | ext `.egg` | `EGG-INFO/PKG-INFO` (member-analyzed) | ✅ |
| NuGet | `nupkg` | zip | ext `.nupkg` | `*.nuspec` (member-analyzed) | ✅ |
| iOS app | `ipa` | zip | ext `.ipa` | `Payload/*.app/Info.plist` (member-analyzed) | ✅ |
| VS Code ext | `vsix` | zip | ext `.vsix` | `extension.vsixmanifest` (member-analyzed) | ✅ |

### OS ecosystems

| ecosystem | `file_type` | container | detection | metadata source | status |
|---|---|---|---|---|---|
| RPM | `rpm` | rpm header + cpio | magic | header tags — `rpm.*` | ✅ |
| Debian | `deb` | ar | magic `!<arch>` | **`control.tar.*` → `./control` — `deb.*`** | ✅ |
| Android | `apk_android` | zip | **magic `PK` + ext `.apk`** | members (`AndroidManifest.xml`, `classes.dex`) | ✅ |
| Alpine | `apk_alpine` | gzip tar | **magic `\x1f\x8b` + ext `.apk`** | members (`.PKGINFO`) | ✅ |
| macOS | `pkg_macos` | xar | magic `xar!` | (type only) | ✅ |
| FreeBSD | `pkg_freebsd` | zstd tar | magic `0x28B52FFD` + `+MANIFEST` marker peek | (type only) | ✅ |
| Arch | `pkg_arch` | zstd tar | ext `.pkg.tar.zst` + `.PKGINFO` marker peek | members (`.PKGINFO`) | ✅ |

All landed. `gem`, `deb`, and `rpm` carry external metadata extractors
(`formats/{gem,deb,rpm}.rs`); the zip/tar-family packages get their identity
manifests analyzed as members by cleave's recursive extraction. Two Tier-3
marker peeks exist — npm (`package/` prefix, tolerant of macOS AppleDouble
`._*` sidecars and pax/GNU headers) and Arch (`.PKGINFO`) — both bounded to the
first few tar headers. The apk and macOS/FreeBSD splits fall out of Tier-1
magic for free.

### Not yet covered (follow-ups)

- Legacy conda `.tar.bz2` (bzip2 — filefacts has no bzip2 decompressor).
- FreeBSD `.txz` pkgs (xz — no xz decompressor in filefacts); only the zstd
  `.pkg` form is split out today.
- deb `control.tar.xz` metadata (xz) — `.gz` and `.zst` control tars are read;
  `.xz` degrades to no `deb.*` (members still analyzed).

## Downstream: nothing structural

- **litmus**: `Model::load_specialists` discovers `filetypes/<type>/` by
  directory; `score_all_routes` looks up the cleave `file_type` in a HashMap.
  A new variant needs only a trained `filetypes/gem/` bundle + thresholds in
  `config.json`. No code change.
- **collimator**: `filetype_vocab` is built from observed `file_type`s; a
  retrain picks up new tokens.
- **cleave**: `FileType` is `#[non_exhaustive]`; the binary crate's matches
  fall through to their defaults, so new variants flow through serde as new
  `file_type` strings without breaking compilation.
