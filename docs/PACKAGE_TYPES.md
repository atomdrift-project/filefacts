# Package types

filefacts gives each package ecosystem (npm, PyPI, RubyGems, Cargo, Debian,
RPM, Alpine, Android, …) its own `FileType`, separate from the container it
ships in (zip, tar, gzip-tar, ar, xar). A wheel is `whl`, not `zip`; an npm
tarball is `npm`, not `tar_gz`. The fine-grained `file_type` label is what a
consumer routes on, while the coarse `file_group` of every package type stays
`archive`, so code that only cares about "is this a container?" is unaffected.

The authoritative list is the `file_types!` table in `src/fileid/mod.rs`.
Each package type documents its container and its discriminator there.

## Two separate jobs

1. **Detection** (`src/fileid/`) assigns the `FileType`. It runs on every
   file and, in a recursive host, on every nested archive member, so it must
   be cheap and must never decompress member bodies.
2. **Metadata extraction** (`src/formats/`) emits `<type>.*` facts, including
   metadata that lives outside the installed file tree: a gem's
   `metadata.gz`, a deb's `control.tar.*`, an RPM header. It runs once per
   opened package.

## Detection cost model

Each discriminator costs only what it must, and every expensive step is gated
behind a cheap one.

### 1. Container magic

The first bytes separate most families before any member is read (examples,
not the full list):

| Magic | Container | Package types |
|---|---|---|
| `PK\x03\x04` | zip | whl, jar, xpi, apk_android, conda, egg, nupkg, ipa, vsix, composer |
| `\x1f\x8b` | gzip(+tar) | npm, crate, apk_alpine, python_sdist, pub, cran, cpan, hackage |
| `!<arch>` | ar | deb |
| `ED AB EE DB` | rpm lead | rpm |
| `xar!` | xar | pkg_macos |
| `28 B5 2F FD` | zstd(+tar) | pkg_freebsd, pkg_arch |
| `ustar` at 257 | plain tar | gem, hex, oci_image |

Two extension collisions are settled by magic alone:

- **`.apk`**: Android packages are zip, Alpine packages are gzip-concatenated
  tar.
- **`.pkg`**: macOS packages are XAR, FreeBSD and Arch packages are
  compressed tar.

### 2. Extension as the gate

Member names are listed only when the magic and the extension together name a
candidate package type, and each input checks only its own candidate's
marker. A random `.gz` log never triggers a peek.

### 3. Bounded member-name peek

For what magic and extension cannot settle (npm vs crate vs sdist, FreeBSD vs
Arch), detection reads member *names*:

- **zip**: the central directory only, O(members), no decompression.
- **tar**: decompress just far enough to read the first few 512-byte headers.
  Markers such as `package/package.json` (npm), `<root>/Cargo.toml.orig`
  (crate), `<root>/PKG-INFO` (sdist), `+MANIFEST` (FreeBSD) and `.PKGINFO`
  (Arch) sit in the first entries. Never scan compressed bytes for a marker:
  it is compressed too, so a raw search both misses and false-positives.

## Rules for a new package type

- Add a row to the `file_types!` table in the `archive` group, with its
  container and discriminator in the doc comment.
- Detect it with the cheapest tier that separates it, and add a negative test
  showing the generic container still wins when the marker is absent.
- Open the container once. Detection must not parse a zip central directory
  that extraction then parses again; pass what detection learned through.
- Keep metadata extraction off the per-member path: detection is what runs on
  nested members.

## Known gaps

- Legacy conda `.tar.bz2` packages are not typed: filefacts has no bzip2
  decoder.
- FreeBSD `.txz` packages stay `tar_xz`; only the zstd `.pkg` form is typed.
