//! Fast file format identification by magic bytes, shebangs, and extensions.
//!
//! `fileid` identifies file formats with a content-first pipeline:
//!
//! 1. **Signatures** — magic bytes, shebangs and structural markers. Most sit
//!    in the first few bytes; some are read further in (a tar header at 257, an
//!    ISO volume descriptor at 32 KiB, a DMG trailer at the end), and archives
//!    are walked far enough to see which package layout they carry
//! 2. **Fast content heuristics** — lightweight patterns over a bounded window
//!    (a few KiB, plus the tail of a padded file; no tree-sitter)
//! 3. **Filename and extension fallback** — used only when content checks do not
//!    identify a stronger type
//!
//! Strong content markers can override filename-only types, unknown extensions,
//! weak extensions, and recognized polyglot/container disguises. Ordinary source
//! extensions remain authoritative against ambiguous language-keyword matches.
//! If no content rule or filename fallback yields a result, `detect` returns `None`.
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
pub(crate) use magic::looks_like_obfuscated_rtf;
mod markdown;
mod restructuredtext;
mod scripts;
pub(crate) mod shellcode;
mod sniff;

pub use container::{ArchiveFormat, Compression, Container, container_of};

use sniff::Sniff;
use std::path::Path;
use stng::{RepeatingXorKey, recover_repeating_xor_pe};

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
///
/// Serialized as `file_type`, `source`, `extension_mismatch` and
/// `mismatch_ext_type`; the last two are derived from how the extension
/// relates to the content.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FileId {
    pub(crate) file_type: FileType,
    pub(crate) source: DetectionSource,
    /// How the extension relates to the content, benign conventions already
    /// excused. [`Self::extension_mismatch`] and the extension's type are
    /// read from it, so the two cannot disagree.
    pub(crate) ext_match: ExtensionMatch,
    /// The key of a PE under a repeating XOR key; see [`identify`].
    pub(crate) xor_pe_key: Option<RepeatingXorKey>,
}

impl Serialize for FileId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileId", 4)?;
        state.serialize_field("file_type", &self.file_type)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("extension_mismatch", &self.extension_mismatch())?;
        state.serialize_field("mismatch_ext_type", &self.mismatch_ext_type())?;
        state.end()
    }
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
        // Detection runs many hand-written heuristics over untrusted bytes; a
        // panic in one must not take the caller down with it.
        let identified =
            crate::formats::goblin_safe::catch_infallible(|| identify(path, bytes)).ok();
        let Some((detection, xor_pe_key)) = identified else {
            return Self {
                source: DetectionSource::Failed,
                ..Self::forced(FileType::Unknown)
            };
        };
        match detection {
            // `identify` has already excused the benign format conventions,
            // so this is the same answer `detect` gives.
            Some(d) => Self {
                file_type: d.file_type,
                source: d.source,
                ext_match: d.ext_match,
                xor_pe_key,
            },
            None => Self {
                file_type: FileType::Unknown,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Consistent,
                xor_pe_key: None,
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
            ext_match: ExtensionMatch::Consistent,
            xor_pe_key: None,
        }
    }

    /// The identified file type.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// For opaque data that is a PE under a repeating XOR key, the key that
    /// decodes it. Recovered once, during identification.
    #[must_use]
    pub fn xor_pe_key(&self) -> Option<RepeatingXorKey> {
        self.xor_pe_key
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
        self.ext_match.is_mismatch(self.source)
    }

    /// When [`Self::extension_mismatch`] holds, the type the *extension*
    /// implied (`None` when the extension is unrecognized). Lets callers
    /// describe the mismatch as a content-group→extension-group transition
    /// without deciding, here, whether that transition is dangerous.
    fn mismatch_ext_type(&self) -> Option<FileType> {
        if self.extension_mismatch() {
            self.ext_match.extension_type(self.file_type)
        } else {
            None
        }
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
        if !self.extension_mismatch() {
            return None;
        }
        let content = file_group(self.file_type);
        let ext = self.mismatch_ext_type().map_or("unknown", file_group);
        Some((content, ext))
    }
}

/// Coarse content category for a [`FileType`], used to describe an
/// extension/content mismatch as a `content_group → extension_group`
/// transition. Every row of the [`FileType`] table names one, so a new
/// variant forces a category choice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Binary,
    /// Interpreted scripting languages (cleave's `scripts` for-group).
    Script,
    /// Compiled / typed source languages (cleave's `source` for-group).
    Source,
    Config,
    Archive,
    Document,
    Image,
    /// Audio and video are their own classes: a payload renamed from
    /// `.wav` to `.png` is a real transition, not a benign refinement.
    Audio,
    Video,
    /// Fonts are their own class, not images: a font renamed to `.png`
    /// is a format transition worth reporting, not a benign refinement.
    Font,
    Text,
    Data,
}

impl Group {
    const fn label(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Script => "script",
            Self::Source => "source",
            Self::Config => "config",
            Self::Archive => "archive",
            Self::Document => "document",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Font => "font",
            Self::Text => "text",
            Self::Data => "data",
        }
    }
}

/// The name of `ft`'s [`Group`] in a mismatch transition.
fn file_group(ft: FileType) -> &'static str {
    ft.group().label()
}

/// The predicate flags a row of the [`FileType`] table can set; a row names
/// the ones that hold for it.
#[derive(Clone, Copy)]
struct Flags(u8);

impl Flags {
    /// A compiled native binary or bytecode: [`FileType::is_binary`].
    const BINARY: Self = Self(1);
    /// Source code with AST support: [`FileType::is_source_code`].
    const SOURCE_CODE: Self = Self(1 << 1);
    /// A manifest parsed whole into the `values` tree:
    /// [`FileType::is_structured_data`].
    const STRUCTURED_DATA: Self = Self(1 << 2);
    /// Not analyzed, so [`FileType::is_program`] is false.
    const UNSUPPORTED: Self = Self(1 << 3);

    const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }
}

/// Declares [`FileType`] from one table, so the enum, its labels, groups and
/// predicate flags cannot drift apart. A row is a variant's documentation,
/// then `Variant => "label", Group, FLAGS...;`.
///
/// The table generates the enum, [`FileType::label`], [`FileType::from_label`]
/// (a repeated label is an unreachable-pattern warning), the `group` and
/// `flags` lookups the predicates read, and, for tests, `FileType::ALL` in
/// declaration order.
macro_rules! file_types {
    (
        $(#[$meta:meta])*
        pub enum FileType {
            $(
                $(#[doc = $doc:literal])*
                $variant:ident => $label:literal, $group:ident $(, $flag:ident)*;
            )+
        }
    ) => {
        $(#[$meta])*
        pub enum FileType {
            $(
                $(#[doc = $doc])*
                $variant,
            )+
        }

        impl FileType {
            /// Every variant, in declaration order.
            #[cfg(test)]
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

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
                    $(Self::$variant => $label,)+
                }
            }

            /// Parse a [`FileType`] from its canonical [`label`](FileType::label).
            /// Returns `None` for any string that is not a label — the exact inverse
            /// of `label`, verified exhaustively by the `label_round_trips` test.
            #[must_use]
            pub fn from_label(label: &str) -> Option<Self> {
                Some(match label {
                    $($label => Self::$variant,)+
                    _ => return None,
                })
            }

            const fn group(self) -> Group {
                match self {
                    $(Self::$variant => Group::$group,)+
                }
            }

            const fn flags(self) -> Flags {
                match self {
                    $(Self::$variant => Flags(0 $(| Flags::$flag.0)*),)+
                }
            }
        }
    };
}

file_types! {
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
        MachO => "macho", Binary, BINARY;
        /// ELF binary (Linux/Unix executable or shared library)
        Elf => "elf", Binary, BINARY;
        /// PE binary (Windows executable, DLL)
        Pe => "pe", Binary, BINARY;
        /// Windows New Executable (16-bit NE) binary
        Ne => "ne", Binary, BINARY;
        /// Unix shell script (bash, sh, zsh, etc.)
        Shell => "shell", Script, SOURCE_CODE;
        /// Windows batch file (.bat, .cmd)
        Batch => "batch", Script;
        /// IBM z/OS Job Control Language batch script (.jcl)
        Jcl => "jcl", Script;
        /// VBScript source file (.vbs, .vbe, .wsf, .wsc)
        Vbs => "vbs", Script;
        /// Python source file (.py)
        Python => "python", Script, SOURCE_CODE;
        /// JavaScript source file (.js, .mjs, .cjs)
        JavaScript => "javascript", Script, SOURCE_CODE;
        /// TypeScript source file (.ts, .tsx)
        TypeScript => "typescript", Source, SOURCE_CODE;
        /// Go source file (.go)
        Go => "go", Source, SOURCE_CODE;
        /// Rust source file (.rs)
        Rust => "rust", Source, SOURCE_CODE;
        /// Java source file (.java)
        Java => "java", Source, SOURCE_CODE;
        /// Compiled Java bytecode (.class)
        JavaClass => "java_class", Binary, BINARY;
        /// Python compiled bytecode (.pyc)
        PythonBytecode => "python_bytecode", Binary, BINARY;
        /// Erlang/Elixir compiled BEAM bytecode (.beam; `FOR1`…`BEAM` IFF container)
        Beam => "beam", Binary, BINARY;
        /// WebAssembly binary module (.wasm; `\0asm` magic + version). A portable
        /// bytecode payload — frequently a Go/TinyGo/Rust/Emscripten compile target
        /// loaded by a JS host. Routed through the generic analyzer so string
        /// extraction, entropy, and symbol-name traits fire on the embedded
        /// `syscall/js` imports, struct tags, and rodata.
        Wasm => "wasm", Binary, BINARY;
        /// Dalvik/ART executable bytecode (`dex\n035\0` and later versions).
        /// APKs carry this as `classes.dex`; a standalone `.dex` is the same
        /// format, not an APK. There is no competing popular "DEX" file type —
        /// the name is the format, not a platform qualifier.
        Dex => "dex", Binary, BINARY;
        /// Java archive (.jar, .war, .ear)
        Jar => "jar", Archive;
        /// Ruby source file (.rb)
        Ruby => "ruby", Script, SOURCE_CODE;
        /// PHP source file (.php)
        Php => "php", Script, SOURCE_CODE;
        /// Perl source file (.pl, .pm)
        Perl => "perl", Script, SOURCE_CODE;
        /// Lua source file (.lua)
        Lua => "lua", Script, SOURCE_CODE;
        /// C# source file (.cs)
        CSharp => "csharp", Source, SOURCE_CODE;
        /// PowerShell script (.ps1, .psm1)
        PowerShell => "powershell", Script, SOURCE_CODE;
        /// Swift source file (.swift)
        Swift => "swift", Source, SOURCE_CODE;
        /// Objective-C source file (.m, .mm)
        ObjectiveC => "objective_c", Source, SOURCE_CODE;
        /// Groovy source file (.groovy)
        Groovy => "groovy", Source, SOURCE_CODE;
        /// Scala source file (.scala)
        Scala => "scala", Source, SOURCE_CODE;
        /// Kotlin source file (.kt, .kts)
        Kotlin => "kotlin", Source, SOURCE_CODE;
        /// Zig source file (.zig)
        Zig => "zig", Source, SOURCE_CODE;
        /// Elixir source file (.ex, .exs)
        Elixir => "elixir", Source, SOURCE_CODE;
        /// Clojure / ClojureScript / EDN source (.clj, .cljs, .cljc, .cljr, .edn, .bb)
        Clojure => "clojure", Source;
        /// C source file (.c, .h)
        C => "c", Source, SOURCE_CODE;
        /// npm package.json manifest
        PackageJson => "package.json", Config, STRUCTURED_DATA;
        /// npm package-lock.json lockfile
        PackageLockJson => "package-lock.json", Config, STRUCTURED_DATA;
        /// VSCode extension manifest (.vsixmanifest)
        VsixManifest => "vsix_manifest", Config;
        /// Chrome extension manifest.json
        ChromeManifest => "chrome_manifest", Config, STRUCTURED_DATA;
        /// Rust Cargo.toml manifest
        CargoToml => "cargo.toml", Config, STRUCTURED_DATA;
        /// Rust Cargo.lock lockfile — pins every crate to an exact version + sha256.
        CargoLock => "cargo.lock", Config, STRUCTURED_DATA;
        /// Python pip requirements file (requirements.txt) — `name==version` pins.
        RequirementsTxt => "requirements.txt", Config;
        /// Python Poetry lockfile (poetry.lock) — resolved package set.
        PoetryLock => "poetry.lock", Config, STRUCTURED_DATA;
        /// Python Pipenv lockfile (Pipfile.lock) — resolved package set with hashes.
        PipfileLock => "pipfile.lock", Config, STRUCTURED_DATA;
        /// Ruby Bundler lockfile (Gemfile.lock) — resolved gem set with versions.
        GemfileLock => "gemfile.lock", Config;
        /// PHP Composer lockfile (composer.lock) — resolved package set with dists.
        ComposerLock => "composer.lock", Config, STRUCTURED_DATA;
        /// Yarn lockfile (yarn.lock) — resolved npm package set with integrity.
        YarnLock => "yarn.lock", Config;
        /// pnpm lockfile (pnpm-lock.yaml) — resolved npm package set with integrity.
        PnpmLock => "pnpm-lock.yaml", Config, STRUCTURED_DATA;
        /// Python pyproject.toml manifest
        PyProjectToml => "pyproject.toml", Config, STRUCTURED_DATA;
        /// PHP composer.json manifest
        ComposerJson => "composer.json", Config, STRUCTURED_DATA;
        /// Generic JSON document (.json)
        Json => "json", Config;
        /// node-gyp build manifest (binding.gyp, .gyp, .gypi). JSON-shaped build
        /// config; its `<!(...)`/`<!@(...)` command-expansion runs arbitrary shell
        /// during `node-gyp configure` (npm runs this automatically on install of a
        /// package containing binding.gyp), a known supply-chain execution vector.
        Gyp => "gyp", Config;
        /// GitHub Actions workflow YAML
        GithubActions => "github_actions", Config, STRUCTURED_DATA;
        /// systemd service unit file (.service, .service.d/*.conf)
        SystemdService => "systemd_service", Config;
        /// freedesktop.org Desktop Entry (.desktop) - XDG application launcher / autostart
        DesktopEntry => "desktop_entry", Config;
        /// Generic XML document (.xml, MSBuild .csproj, SVG, XML config files, etc.)
        Xml => "xml", Config;
        /// Generic YAML document (.yaml, .yml) that is not one of the specific
        /// manifests above (a GitHub Actions workflow, a pnpm lockfile). YAML is the
        /// default configuration language for CI, Kubernetes and model cards, so an
        /// unrecognized one is worth naming rather than leaving as `unknown`.
        Yaml => "yaml", Config;
        /// Python package metadata (PKG-INFO, METADATA)
        PkgInfo => "pkg_info", Config, STRUCTURED_DATA;
        /// Arch/AUR generated package metadata (.SRCINFO) — normalized mirror of PKGBUILD
        SrcInfo => "src_info", Config, STRUCTURED_DATA;
        /// Normalized package-registry metadata (`*.registry.json`) — an upstream
        /// provider's account of a release (publish date, author, downloads,
        /// rating, deprecation), the serialized form of [`crate::Registry`].
        Registry => "registry", Config, STRUCTURED_DATA;
        /// Windows registry export (`.reg`), the script `regedit` imports and
        /// exports. Its first line names the format: `REGEDIT4`, or `Windows
        /// Registry Editor Version 5.00` in UTF-8 or (as `regedit` writes it)
        /// UTF-16LE behind a byte-order mark. Unrelated to [`Self::Registry`].
        Reg => "reg", Config;
        /// Go module manifest (go.mod) — `require` directives are declared dependencies.
        GoMod => "go.mod", Config;
        /// Go module checksum database (go.sum) — pins every module to an `h1:` hash.
        GoSum => "go.sum", Config;
        /// ZIP archive (zip, apk, ipa, nupkg, etc.)
        Zip => "zip", Archive;
        /// TAR archive (plain, no compression)
        Tar => "tar", Archive;
        /// ASCII CPIO archive (odc, newc, or newc checksum layout).
        Cpio => "cpio", Archive;
        /// Gzip-compressed TAR (.tar.gz, .tgz, .crate)
        TarGz => "tar.gz", Archive;
        /// Bzip2-compressed TAR (.tar.bz2, .tbz2)
        TarBz2 => "tar.bz2", Archive;
        /// XZ-compressed TAR (.tar.xz, .txz)
        TarXz => "tar.xz", Archive;
        /// Zstandard-compressed TAR (.tar.zst, .xbps)
        TarZst => "tar.zst", Archive;
        /// Gzip-compressed single file (.gz, not a tar)
        Gz => "gz", Archive;
        /// Bzip2-compressed single file (.bz2, not a tar)
        Bz2 => "bz2", Archive;
        /// XZ-compressed single file (.xz, not a tar)
        Xz => "xz", Archive;
        /// LZMA-alone compressed single file (.lzma)
        Lzma => "lzma", Archive;
        /// Zstandard-compressed single file (.zst, not a tar)
        Zst => "zst", Archive;
        /// 7-Zip archive (.7z)
        SevenZ => "7z", Archive;
        /// RAR archive (.rar)
        Rar => "rar", Archive;
        /// Debian package (.deb)
        Deb => "deb", Archive;
        /// Unix static library (.a) — an `ar` archive of relocatable object files.
        /// Shares the `!<arch>` magic with `.deb`; distinguished by the first `ar`
        /// member (`.deb` leads with `debian-binary`, a static library does not).
        StaticLib => "static-lib", Binary;
        /// RPM package (.rpm)
        Rpm => "rpm", Archive;
        /// macOS installer package (.pkg, XAR format). Named `PkgMacos` (not bare
        /// `Pkg`) because the `.pkg` extension is ambiguous: FreeBSD and Arch also
        /// use it for compressed-tar packages, disambiguated by container magic.
        PkgMacos => "pkg_macos", Archive;
        /// Apple Disk Image (.dmg, UDIF container).
        Dmg => "dmg", Archive;
        /// Optical-disc image (.iso): ISO 9660 and/or UDF filesystem — full OS
        /// install media. Identified by the volume-descriptor magic at sector 16;
        /// unpacked downstream by 7-Zip (ISO 9660, Joliet, Rock Ridge, and UDF).
        Iso => "iso", Archive;
        /// SquashFS read-only filesystem image — `hsqs` (little-endian) or `sqsh`
        /// (big-endian) superblock magic. Ships inside firmware images and appliance
        /// builds, and is the wire format of a Snap package (see [`FileType::Snap`]).
        SquashFs => "squashfs", Archive;
        /// Cabinet archive (.cab)
        Cab => "cab", Archive;
        /// Compiled HTML Help (.chm) — Microsoft ITSF/ITOL container with
        /// LZX-compressed HTML topics. Common malware delivery vector.
        Chm => "chm", Archive;
        /// Chrome extension (.crx)
        Crx => "crx", Archive;
        /// Mozilla Firefox extension (.xpi) — ZIP container with WebExtension or
        /// legacy XUL layout. Disambiguated from generic ZIP so the XPI-specific
        /// signing-scheme shape (`META-INF/mozilla.*`, `META-INF/cose.*`) can be
        /// surfaced.
        Xpi => "xpi", Archive;
        /// Python wheel (.whl) — ZIP container with PEP 427 layout. Distinct
        /// from generic ZIP so the wheel-specific surface (dist-info, RECORD,
        /// native-extension count, top-level packages) can be extracted.
        Whl => "whl", Archive;
        /// RubyGems package (.gem) — uncompressed `ustar` tar holding
        /// `metadata.gz` (gzipped `Gem::Specification` YAML), `data.tar.gz`, and
        /// `checksums.yaml.gz`. Distinct from generic tar so the gem's external
        /// identity metadata can be surfaced as `gem.*`.
        Gem => "gem", Archive;
        /// Android application package (.apk) — ZIP container (`AndroidManifest.xml`,
        /// `classes.dex`). Disambiguated from the Alpine `.apk` by container magic
        /// (`PK` zip vs gzip tar) so each ecosystem gets its own model.
        ApkAndroid => "apk_android", Archive;
        /// Alpine Linux package (.apk) — gzip-concatenated tar (signature ‖ control
        /// ‖ data) carrying `.PKGINFO`. Disambiguated from the Android `.apk` by
        /// container magic (gzip vs `PK` zip).
        ApkAlpine => "apk_alpine", Archive;
        /// npm package (.tgz) — gzip tar with everything under a `package/` prefix
        /// (`package/package.json`). Disambiguated from a generic gzip tar by that
        /// marker, so npm supply-chain signal (install scripts, bin shims) routes
        /// to its own model.
        Npm => "npm", Archive;
        /// Rust crate (.crate) — gzip tar laid out as `<name>-<version>/` with a
        /// `Cargo.toml` at its root. The `.crate` extension is cargo-specific.
        Crate => "crate", Archive;
        /// conda package (.conda) — ZIP holding `metadata.json` plus zstd-compressed
        /// `info-*`/`pkg-*` tars. Distinct from generic ZIP so conda identity
        /// (`info/index.json`) routes to its own model.
        Conda => "conda", Archive;
        /// Python egg (.egg) — ZIP with an `EGG-INFO/` directory (`PKG-INFO`).
        Egg => "egg", Archive;
        /// NuGet package (.nupkg) — ZIP carrying a `*.nuspec` manifest.
        Nupkg => "nupkg", Archive;
        /// iOS application archive (.ipa) — ZIP with `Payload/*.app/Info.plist`.
        Ipa => "ipa", Archive;
        /// VS Code / Open VSX extension (.vsix) — ZIP carrying
        /// `extension.vsixmanifest`. Distinct from the manifest file type
        /// [`FileType::VsixManifest`], which is that inner XML alone.
        Vsix => "vsix", Archive;
        /// FreeBSD package (.pkg) — zstd-compressed tar whose first member is the
        /// `+COMPACT_MANIFEST` / `+MANIFEST` metadata. Disambiguated from the macOS
        /// `.pkg` by container magic (zstd-tar vs `xar!`) and from Arch by the
        /// `+MANIFEST` marker.
        PkgFreebsd => "pkg_freebsd", Archive;
        /// Arch Linux package (.pkg.tar.{zst,xz,gz}) — compressed tar whose first
        /// member is `.PKGINFO`. Disambiguated from FreeBSD by that marker; the
        /// `.pkg.tar.*` extension is Arch-specific where the body can't be read.
        PkgArch => "pkg_arch", Archive;
        /// Python source distribution (sdist) — gzip tar laid out as
        /// `<name>-<version>/` with a `PKG-INFO` metadata file at its root.
        /// Disambiguated from a generic gzip tar by that marker, so the PyPI
        /// publisher identity (`python.*`) routes to its own model.
        PythonSdist => "python_sdist", Archive;
        /// OCI / Docker container image archive — an (uncompressed) tar carrying
        /// either an OCI `oci-layout` + `index.json` or a `docker save`
        /// `manifest.json`. Distinct from a generic tar so image refs and content
        /// digests can be surfaced as `oci.*`.
        OciImage => "oci_image", Archive;
        /// Void Linux package (.xbps) — zstd-compressed tar carrying `props.plist`
        /// metadata. Distinguished from a generic `.tar.zst` by its extension.
        Xbps => "xbps", Archive;
        /// Ubuntu Snap package (.snap) — a SquashFS image carrying `meta/snap.yaml`.
        /// Distinguished from a bare [`FileType::SquashFs`] image by its extension,
        /// which is the only signal available without reading the filesystem.
        Snap => "snap", Archive;
        /// Flatpak single-file bundle (.flatpak) — an OSTree static delta in GVariant
        /// framing. Unlike every other package format here it carries no magic at a
        /// fixed offset and none is registered with `file(1)`, so the extension is
        /// the identification.
        Flatpak => "flatpak", Archive;
        /// Gentoo binary package (GLEP 78 `.gpkg.tar`) — an uncompressed tar
        /// bundling `metadata.tar.*`, `image.tar.*`, and a `Manifest`. Distinct
        /// from a generic tar by its `.gpkg.tar` extension.
        GentooBinpkg => "gentoo_binpkg", Archive;
        /// Electron ASAR application archive (.asar)
        Asar => "asar", Archive;
        /// PHP archive in the native phar format: a PHP stub, a manifest, and
        /// the packaged files. Tar- and zip-based phars are `tar` and `zip`.
        Phar => "phar", Archive;
        /// AppleScript source file (.applescript, .scpt)
        AppleScript => "applescript", Script;
        /// Apple Property List (.plist)
        Plist => "plist", Config, STRUCTURED_DATA;
        /// Compiled Interface Builder archive (.nib): the object graph AppKit or
        /// UIKit instantiates for a window or view, in either the `NIBArchive`
        /// layout or an `NSKeyedArchiver` binary plist. Distinct from `Plist`
        /// because the graph names the app's own classes, action selectors,
        /// and Swift modules, which is attribution a plain plist never carries.
        Nib => "nib", Config, STRUCTURED_DATA;
        /// Xcode project file (`project.pbxproj`) — an OpenStep-style property
        /// list describing targets, build phases, and build settings. Kept
        /// distinct from `Plist` because it is the only plist dialect that carries
        /// executable build scripts, which is what makes it a supply-chain target.
        Pbxproj => "pbxproj", Config, STRUCTURED_DATA;
        /// CMake build script (`CMakeLists.txt`, `*.cmake`). Its own type rather
        /// than generic text because it is executable build logic — `execute_process`
        /// and `add_custom_command` run at configure and build time — so rules that
        /// target build systems must be able to name it.
        Cmake => "cmake", Config;
        /// Rich Text Format document (.rtf)
        Rtf => "rtf", Document;
        /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
        OleDoc => "ole_doc", Document;
        /// Windows Installer package / patch (OLE2/CFBF: .msi, .msp). Same compound
        /// container as [`OleDoc`](Self::OleDoc), but a distinct product surface (installer tables,
        /// custom-action binaries, SummaryInformation) — not a document.
        // Installer packages share the OLE2/CFBF wire format with OleDoc but
        // are not documents — treat them as archive-class for mismatch
        // transitions (e.g. an MSI renamed `.doc` is archive→document).
        Msi => "msi", Archive;
        /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
        Ooxml => "ooxml", Document;
        /// Windows Shell Link file (.lnk)
        Lnk => "lnk", Binary;
        /// JPEG image
        Jpeg => "jpeg", Image;
        /// PNG image
        Png => "png", Image;
        /// RIFF audio (`.wav`). Chunked container; see formats/containers.rs.
        Wav => "wav", Audio;
        /// IFF audio (`.aiff`, `.aifc`).
        Aiff => "aiff", Audio;
        /// MPEG audio with optional ID3 tags (`.mp3`).
        Mp3 => "mp3", Audio;
        /// ISO base media (`.mp4`, `.m4a`, `.mov`) — a flat box sequence.
        Mp4 => "mp4", Video;
        /// Windows icon or cursor (`.ico`, `.cur`). The favicon every web package
        /// ships and nobody opens, which is what makes it a carrier.
        Ico => "ico", Image;
        /// GIF image (`.gif`).
        Gif => "gif", Image;
        /// Windows bitmap (`.bmp`).
        Bmp => "bmp", Image;
        /// RIFF image (`.webp`).
        Webp => "webp", Image;
        /// Font container: sfnt (`.ttf`/`.otf`/`.ttc`), WOFF, WOFF2, or EOT.
        /// One variant for the family because the abuse patterns are shared —
        /// a payload wearing a font name, or a stowaway in the table gaps —
        /// and the concrete container is reported as `font.format`.
        Font => "font", Font;
        /// SVG image (.svg) — XML-based vector graphic. Unlike raster images it
        /// is text and can embed `<script>` / event handlers, making it a common
        /// phishing/HTML-smuggling carrier; classified as media but scanned as XML.
        Svg => "svg", Image;
        /// Python pickle serialized data (.pkl, .pickle, .joblib)
        Pickle => "pickle", Data;
        /// PDF document
        Pdf => "pdf", Document;
        /// HTML document (.html, .htm)
        Html => "html", Text, UNSUPPORTED;
        /// JavaServer Pages (`.jsp`, `.jspx`). The page directive is unique to JSP.
        Jsp => "jsp", Script;
        /// Classic ASP and ASP.NET (`.asp`, `.aspx`, and the related suffixes).
        Asp => "asp", Script;
        /// ColdFusion Markup Language (`.cfm`, `.cfc`, `.cfml`).
        Cfml => "cfml", Script;
        /// TeX or LaTeX source (`.tex`, `.sty`, `.ltx`, `.dtx`). `.cls` is shared
        /// with Visual Basic, so a class file is TeX only when its body says so.
        Tex => "tex", Text;
        /// YARA rule source (`.yar`, `.yara`).
        // A detection ruleset, not prose. A `.yar` renamed `.txt` is
        // config→text; it is not the same kind of file as a note.
        Yara => "yara", Config;
        /// PostScript or EPS (`.ps`, `.eps`).
        PostScript => "postscript", Document;
        /// DOS COM executable. No header of its own; `INT 21h` (`CD 21`) is the syscall.
        DosCom => "dos_com", Binary, BINARY;
        /// Headerless x86 / x86-64 position-independent code, recognised by the
        /// GetPC idiom it opens with (see `fileid::shellcode`).
        Shellcode => "shellcode", Binary, BINARY;
        /// mIRC script (`.mrc`).
        Mirc => "mirc", Script;
        /// ircII or EPIC script. The `^on` / `^alias` hook syntax is the mark.
        IrcII => "ircii", Script;
        /// Markdown document (.md, .markdown)
        Markdown => "markdown", Text, UNSUPPORTED;
        /// Makefile / GNU Make build file
        Makefile => "makefile", Config;
        /// Dockerfile — container image build definition
        Dockerfile => "dockerfile", Config;
        /// OpenDocument Format (.odt, .ods, .odp, .odg) — ZIP-based office documents
        Odf => "odf", Document, UNSUPPORTED;
        /// OpenPGP signature (.sig, .asc) — the detached signature published beside
        /// a release artifact. Both the ASCII-armored and binary packet forms.
        /// Provenance evidence rather than payload, and named so a release directory
        /// does not read as a pile of unknowns.
        PgpSignature => "pgp_signature", Data;
        /// Plain text data (.txt, .text, or printable text with no stronger type)
        Text => "text", Text;
        /// Opaque or sidecar data (.dat, .bin, .payload, .raw, and .map) — commonly carries
        /// encrypted/XOR-d payloads or source-map embedded code. Routed through the generic analyzer
        /// so string extraction, entropy, and encoded-payload detection still fire.
        Data => "data", Data;
        /// File type could not be determined
        Unknown => "unknown", Data, UNSUPPORTED;
    }
}

impl FileType {
    /// Returns true for every type except `Unknown`, `Html`, `Markdown` and
    /// `Odf`.
    ///
    /// Despite the name this is not limited to executable code: binaries,
    /// scripts, manifests and archives count, and so do images, media, fonts,
    /// plain text and opaque data.
    #[must_use]
    pub fn is_program(&self) -> bool {
        !self.flags().contains(Flags::UNSUPPORTED)
    }

    /// Returns true if this file type is an archive or compressed container
    /// whose members archive walkers can enumerate.
    ///
    /// This is narrower than the `"archive"` group: Flatpak bundles group as
    /// archives for extension-mismatch purposes but stay opaque, because no
    /// walker reads their OSTree delta framing yet. Windows Installer packages
    /// group there too, and are read as OLE2 storage rather than walked.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        self.group() == Group::Archive && !matches!(self, Self::Flatpak | Self::Msi)
    }

    /// Returns true if this file type is a compiled native binary.
    #[must_use]
    pub fn is_binary(&self) -> bool {
        self.flags().contains(Flags::BINARY)
    }

    /// Returns true if cleave supports analysis of this file type. Currently
    /// the same as [`Self::is_program`], so `Unknown`, `Html`, `Markdown` and
    /// `Odf` are not supported.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.is_program()
    }

    /// Returns true if this file type represents source code with AST support.
    #[must_use]
    pub fn is_source_code(&self) -> bool {
        self.flags().contains(Flags::SOURCE_CODE)
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
        self.flags().contains(Flags::STRUCTURED_DATA)
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
    /// [`crate::OpenOptions::file_type`], bypassing detection. Used when the language is
    /// already known from context the bytes alone don't carry — e.g. the
    /// inner source of a `python3 -c "<code>"` payload, whose extracted
    /// body has no shebang, extension, or magic to detect.
    Forced,
    /// Detection panicked on these bytes, so the type is
    /// [`FileType::Unknown`]. [`crate::ParsedFile::errors`] records it under
    /// [`crate::Stage::Identify`].
    Failed,
}

/// What the file extension implies about the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionMatch {
    /// Extension maps to the same type as content detection, or no extension present.
    Consistent,
    /// Extension maps to a different known type.
    Different(FileType),
    /// Extension is present but not recognized by fileid.
    Unknown,
    /// The extension was believed over a shebang naming another scripting
    /// language (see [`is_shebang_juke`]), so the detected type is the
    /// extension's. Holds the type the shebang claimed.
    ShebangClaimed(FileType),
    /// The extension disagrees with the content by a known format convention
    /// (see [`is_benign_extension_mismatch`]), so it is not reported as a
    /// mismatch. Holds the type the extension implies, when it is known.
    Conventional(Option<FileType>),
}

impl ExtensionMatch {
    /// How `ext`, the type the path's extension implies, relates to
    /// `detected`, the type the content was identified as. An extension fileid
    /// does not know is `Unknown` only when it names something; see
    /// [`has_named_extension`].
    fn of(path: &Path, ext: Option<FileType>, detected: FileType) -> Self {
        match ext {
            Some(FileType::Yaml) if is_yaml_dialect(detected) => Self::Consistent,
            // A phar is also written as a plain tar or zip archive.
            Some(FileType::Phar) if matches!(detected, FileType::Tar | FileType::Zip) => {
                Self::Consistent
            }
            Some(e) if e != detected => Self::Different(e),
            None if has_named_extension(path) => Self::Unknown,
            Some(_) | None => Self::Consistent,
        }
    }

    /// Whether this disagreement is reported as a mismatch for a type that
    /// was found by `source`. A type taken from the name has nothing to
    /// disagree with.
    fn is_mismatch(self, source: DetectionSource) -> bool {
        matches!(
            source,
            DetectionSource::Magic
                | DetectionSource::Shebang
                | DetectionSource::Heuristic
                | DetectionSource::ExtensionOverridesShebang
        ) && matches!(
            self,
            Self::Different(_) | Self::Unknown | Self::ShebangClaimed(_)
        )
    }

    /// The type the extension implies, where it differs from the content
    /// or was believed over a shebang; `detected` is the type identified.
    fn extension_type(self, detected: FileType) -> Option<FileType> {
        match self {
            Self::Different(ft) | Self::Conventional(Some(ft)) => Some(ft),
            Self::ShebangClaimed(_) => Some(detected),
            Self::Consistent | Self::Unknown | Self::Conventional(None) => None,
        }
    }
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
    /// - The disagreement is a known format convention (AppleDouble sidecars,
    ///   Android/Alpine APK, package-specific archives, XHTML), as for
    ///   [`FileId::extension_mismatch`]
    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        self.ext_match.is_mismatch(self.source)
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
    /// `None` when the extension is absent, unrecognized, or matches the
    /// detected type. After a shebang juke ([`Self::is_shebang_juke`]) the
    /// extension was believed, so its type is the detected type.
    #[must_use]
    pub fn extension_type(&self) -> Option<FileType> {
        self.ext_match.extension_type(self.file_type)
    }

    /// The scripting language a shebang claimed when the extension was
    /// believed over it ([`Self::is_shebang_juke`]).
    #[must_use]
    pub fn shebang_type(&self) -> Option<FileType> {
        match self.ext_match {
            ExtensionMatch::ShebangClaimed(ft) => Some(ft),
            _ => None,
        }
    }

    /// `self`, with a mismatch that is a known format convention no longer
    /// reported as one.
    fn excuse_convention(mut self, path: &Path, data: &[u8]) -> Self {
        if self.extension_mismatch() && is_benign_extension_mismatch(path, data, self) {
            self.ext_match = ExtensionMatch::Conventional(self.extension_type());
        }
        self
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
            // A signatureless image extension cannot establish that the
            // bytes are an image. Let strong source-language heuristics win;
            // real JPEG/PNG magic has already returned in stage 1.
            | FileType::Jpeg
            | FileType::Png
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
            // An image suffix names a container, but without its signature it
            // should not overrule unmistakable text/source content.
            | FileType::Jpeg
            | FileType::Png
            | FileType::JavaScript
            | FileType::Python
            | FileType::Vbs
    )
}

/// The UTF-8 byte-order mark. Windows editors write it ahead of scripts and
/// markup alike, so content checks read past it.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// `data` without a leading [`UTF8_BOM`].
fn strip_utf8_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(UTF8_BOM).unwrap_or(data)
}

/// A leading tag. Used when the extension is a variant letter (`.sc`, `.ex`)
/// rather than a claim that the body is that language.
fn leading_markup(data: &[u8]) -> bool {
    let rest = data.get(..32).unwrap_or(data).trim_ascii_start();
    let starts = |prefix: &[u8]| {
        rest.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
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
fn ex_variant_override(sniff: &Sniff<'_>) -> Option<FileType> {
    let ext = sniff.path.extension().and_then(|e| e.to_str())?;
    if !ext.eq_ignore_ascii_case("ex") {
        return None;
    }
    if let Some(marked) = sniff.unmistakable() {
        return Some(marked);
    }
    let data = sniff.data;
    if leading_markup(data) || utf16le_markup(data) {
        return Some(FileType::Html);
    }
    if leading_batch(data) {
        return Some(FileType::Batch);
    }
    None
}

fn leading_batch(data: &[u8]) -> bool {
    let rest = data.get(..80).unwrap_or(data).trim_ascii_start();
    if !rest
        .get(..5)
        .is_some_and(|head| head.eq_ignore_ascii_case(b"@echo"))
    {
        return false;
    }
    let line = rest
        .split(|b| *b == b'\n' || *b == b'\r')
        .next()
        .unwrap_or(rest);
    line.windows(3).any(|w| w.eq_ignore_ascii_case(b"off"))
}

fn utf16le_markup(data: &[u8]) -> bool {
    let Some(rest) = data.strip_prefix(b"\xff\xfe") else {
        return false;
    };
    let (units, _) = rest.as_chunks::<2>();
    let mut text = [0u8; 16];
    let mut n = 0;
    for (slot, &[lo, hi]) in text.iter_mut().zip(units) {
        if hi != 0 {
            return false;
        }
        *slot = lo;
        n += 1;
    }
    leading_markup(text.get(..n).unwrap_or_default())
}

/// `.txt` / `.text` claim prose. They are listed as data formats so a note
/// that mentions a keyword stays text, but a file whose body is clearly a
/// language (`Php_Backdoor.txt`) should be that language. Other extensions
/// that map to `Text` (OCaml `.ml`, CSS, SQL) stay on the extension.
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

/// True when a path's trailing dot-segment is a named extension rather than
/// a version number or the final component of a dotted executable name.
///
/// `Path::extension` splits on the last dot, so `keyvault-keys@4.8.0` reports
/// an extension of `"0"`, `react-redux@7.1.25` reports `"25"`, and `python3.11`
/// reports `"11"`. Registry artifacts are routinely named this way — npm, crates
/// and gem tarballs are stored as `<name>@<semver>` with no suffix at all.
///
/// An unregistered UpperCamelCase tail after a dotted stem is often a module
/// or executable name, such as `org.example.MyModule` or `us.zoom.ZoomDaemon`,
/// rather than a claim that the file has an unknown suffix. Known extensions
/// are resolved separately and still take precedence.
///
/// Treating version digits as unrecognized extensions made packages appear to
/// mismatch their content. A run of digits claims nothing about a file's format,
/// so it is not something content can disagree with. The `.so.1.1` case has its
/// own handling in `ext::has_versioned_so_suffix`, which assigns the type.
fn has_named_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if ext.is_empty() || ext.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let dotted_camel_case_tail =
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| {
                stem.contains('.')
                    && ext.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && ext.chars().any(|c| c.is_ascii_lowercase())
            });
    !dotted_camel_case_tail
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
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| ext::ends_with_ci(n.as_bytes(), suffix.as_bytes()))
    };
    // `.exe` is shared by the older 16-bit Windows NE format and PE. The
    // extension database resolves it to PE, but NE content is a valid `.exe`.
    if name_ends_ci(".exe") && ext_type == FileType::Pe && content == FileType::Ne {
        return true;
    }
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
    // A Windows Script Host job or component declares its own language, and
    // JScript is as much at home in a `.wsf` / `.wsc` as VBScript.
    if ext_type == FileType::Vbs
        && content == FileType::JavaScript
        && (name_ends_ci(".wsf") || name_ends_ci(".wsc"))
    {
        return true;
    }
    // XHTML served with a `.html` extension but parsed as XML.
    if ext_type == FileType::Html && content == FileType::Xml {
        let head = data.get(..4096).unwrap_or(data);
        let prefix = String::from_utf8_lossy(head).to_ascii_lowercase();
        return prefix.contains("<!doctype html") || prefix.contains("<html");
    }
    false
}

/// Detect file type from content + path. Content is trusted first, extension as fallback.
///
/// Returns `None` if the file format cannot be identified. This is the same
/// detection [`FileId::from_path_and_bytes`] makes, benign extension
/// conventions included; only the XOR key of [`FileId::xor_pe_key`] is not
/// carried.
#[must_use]
pub fn detect(path: &Path, data: &[u8]) -> Option<Detection> {
    identify(path, data).0
}

/// [`detect`], plus the key when the file is a PE under a repeating XOR key,
/// as droppers ship their payload inside a jar or package (`hvnc.enc`,
/// `payload.bin`). Magic cannot see such a file, and as Unknown it was skipped
/// outright; as Data it reaches the generic analyzer, and the key lets the
/// consumer decode the image. It is recovered from known plaintext and checked
/// against the PE header, so this cannot claim random bytes. Only opaque
/// outcomes (Data, or nothing recognised) are tried: anything else was
/// identified by its own bytes.
pub(crate) fn identify(path: &Path, data: &[u8]) -> (Option<Detection>, Option<RepeatingXorKey>) {
    let (detection, key) = match detect_known(&Sniff::new(path, data)) {
        Some(d) if d.file_type == FileType::Data => (Some(d), recover_repeating_xor_pe(data)),
        Some(d) => (Some(d), None),
        None => match recover_repeating_xor_pe(data) {
            // An unrecognised extension (`.enc`) says nothing that opaque
            // data contradicts.
            Some(key) => (
                Some(Detection {
                    file_type: FileType::Data,
                    source: DetectionSource::Heuristic,
                    ext_match: ExtensionMatch::Consistent,
                }),
                Some(key),
            ),
            None => (unnamed_program(path, data), None),
        },
    };
    (detection.map(|d| d.excuse_convention(path, data)), key)
}

/// Everything [`identify`] recognises without key recovery.
///
/// The stages consult `sniff` for anything more than one of them derives, so
/// each derivation runs once however many stages ask for it.
fn detect_known(sniff: &Sniff<'_>) -> Option<Detection> {
    let (path, data) = (sniff.path, sniff.data);
    let ext_ft = sniff.ext_type();

    // Stage 1: Content-based detection (magic bytes, shebangs)
    if let Some((file_type, source)) = magic::detect_from_sniff(sniff) {
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
            if let Some(marked) = sniff.unmistakable() {
                if matches!(marked, FileType::Jsp | FileType::Asp | FileType::Cfml) {
                    return Some(Detection {
                        file_type: marked,
                        source: DetectionSource::Heuristic,
                        ext_match: ExtensionMatch::of(path, ext_ft, marked),
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
                        ext_match: ExtensionMatch::ShebangClaimed(file_type),
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

        return Some(Detection {
            file_type,
            source,
            ext_match: ExtensionMatch::of(path, ext_ft, file_type),
        });
    }

    // A standalone FAT volume boot sector has no container magic. Identify its
    // validated BPB before an opaque/unknown extension can leave it unscanned.
    if heuristics::looks_like_fat_boot_sector(data) {
        return Some(Detection {
            file_type: FileType::Data,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::of(path, ext_ft, FileType::Data),
        });
    }

    // `.git/config` is normally extensionless. Its section/key structure is
    // a strong content signature, and may correct even a misleading filename
    // before source-language or exact-name fallbacks get a chance to win.
    if sniff.looks_like_git_config() {
        return Some(Detection {
            file_type: FileType::Text,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::of(path, ext_ft, FileType::Text),
        });
    }
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
    if let Some(kind) = ex_variant_override(sniff) {
        return Some(Detection {
            file_type: kind,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(FileType::Elixir),
        });
    }

    // One unmistakable mark beats the language scorer. It only replaces a
    // weak or absent extension (`.txt`, `.m`, `.lua`, a page typed HTML
    // because of a prologue). A `.java` or `.py` name stays what it says.
    if let Some(marked) = sniff.unmistakable() {
        if ext_ft.is_none_or(|ext| ext == marked || mark_replaces(ext)) {
            return Some(Detection {
                file_type: marked,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::of(path, ext_ft, marked),
            });
        }
    }

    // `.ps` is shared by PostScript and PowerShell. A strong PowerShell content
    // score disambiguates script payloads, while the `%!PS` magic above keeps
    // real PostScript authoritative.
    if ext_ft == Some(FileType::PostScript)
        && !data.trim_ascii_start().starts_with(b"%!PS")
        && (sniff.scored_type() == Some(FileType::PowerShell)
            || heuristics::has_powershell_char_code_array(data))
    {
        return Some(Detection {
            file_type: FileType::PowerShell,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Different(FileType::PostScript),
        });
    }

    // ReStructuredText documents often contain executable-looking examples.
    // A sectioned document with directives or literal blocks is a document by
    // its content, even when those examples happen to score as a source language.
    if ext_ft == Some(FileType::Text)
        && path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rst"))
        && restructuredtext::document_structure(data)
    {
        return Some(Detection {
            file_type: FileType::Text,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Consistent,
        });
    }

    // A document's fenced examples are not its execution language. Keep
    // content-first detection for scripts renamed .md; actual Markdown needs
    // both a leading heading and a complete fenced block before this applies.
    if ext_ft == Some(FileType::Markdown) && markdown::document_structure(data) {
        return Some(Detection {
            file_type: FileType::Markdown,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Consistent,
        });
    }

    // Stage 3: Content heuristics can override a filename-only type and weak
    // extensions, and inspect extension-claimed containers/polyglots. Ordinary
    // source extensions stay authoritative here: language keyword scoring is
    // too weak to override `.go`, `.js`, `.swift`, etc. A non-magic `.zip` body
    // may still be a script payload wearing an archive name.
    if ((heuristic_may_override_ext || sniff.is_filename_match()) && !ext::is_data_format(path))
        || prose_extension_may_be_source(path)
    {
        if let Some(file_type) = sniff.scored_type() {
            return Some(Detection {
                file_type,
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::of(path, ext_ft, file_type),
            });
        }
    }

    // Content signatures and language patterns have had the first chance to
    // identify the body. An exact filename is only a fallback when its bytes
    // carry no stronger evidence.
    if sniff.is_filename_match() {
        if let Some(file_type) = ext_ft {
            return Some(Detection {
                file_type,
                source: DetectionSource::Filename,
                ext_match: ExtensionMatch::Consistent,
            });
        }
    }

    // The fast text probe handles named but unregistered suffixes such as `.conf`.
    // Leave extensionless files unclassified unless a stronger content rule
    // recognizes them; many corpus files use opaque extensionless names.
    if ext_ft.is_none()
        && has_named_extension(path)
        && !data.is_empty()
        && magic::content_is_text(data)
    {
        return Some(Detection {
            file_type: FileType::Text,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Unknown,
        });
    }

    // Object code with a source extension is not that language. DOS COM samples
    // named `Burger.m` or `Trivial.45.t` used to inherit Objective-C or Perl
    // from the suffix. UTF-16 source is excluded inside `binary_not_source`.
    if let Some(ext) = ext_ft.filter(|ft| claims_source(*ft)) {
        if sniff.binary_not_source() {
            return Some(Detection {
                file_type: binary_body_type(data),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(ext),
            });
        }
        // Text the extension misnames: a page, or another language the scorer
        // is sure of while finding nothing of the claimed one.
        if let Some(found) = heuristics::contradicts_extension(ext, sniff) {
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
        if sniff.binary_not_source() {
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
                file_type: unclaimed_body_type(sniff),
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
                file_type: unclaimed_body_type(sniff),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(file_type),
            });
        }
        // A bitmap's header is decided in stage 1. A `.dib` may leave out the
        // 14-byte file header and start at the info header; anything else
        // named `.bmp` is whatever its bytes are, not an image because of its
        // name.
        if file_type == FileType::Bmp && !data.is_empty() && !magic::looks_like_dib_header(data) {
            return Some(Detection {
                file_type: unclaimed_body_type(sniff),
                source: DetectionSource::Heuristic,
                ext_match: ExtensionMatch::Different(FileType::Bmp),
            });
        }
        // SVG magic is decided in stage 1. Reaching this fallback means the
        // body has no `<svg>` root, so the name is not a reason to call it an
        // image. `logo.svg` containing a script is the script.
        if file_type == FileType::Svg {
            return Some(Detection {
                file_type: unclaimed_body_type(sniff),
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
        // and carved shellcode routinely carry them. A program-shaped body
        // under a generic data name is the program, not opaque data.
        if file_type == FileType::Data {
            if let Some(program) = headerless_program(data) {
                return Some(Detection {
                    file_type: program,
                    source: DetectionSource::Heuristic,
                    ext_match: ExtensionMatch::Different(FileType::Data),
                });
            }
        }
        return Some(Detection {
            file_type,
            source: DetectionSource::Extension,
            ext_match: ExtensionMatch::Consistent,
        });
    }

    None
}

/// Nothing recognised the file. Corpora name samples by hash, so a DOS COM
/// there has no `.com` to go on, and carved shellcode has no name at all;
/// without this they were Unknown, which no trait walks.
fn unnamed_program(path: &Path, data: &[u8]) -> Option<Detection> {
    headerless_program(data).map(|file_type| Detection {
        file_type,
        source: DetectionSource::Heuristic,
        ext_match: if has_named_extension(path) {
            ExtensionMatch::Unknown
        } else {
            ExtensionMatch::Consistent
        },
    })
}

/// A program with no header of its own: a DOS COM, else x86 code that opens
/// with a GetPC idiom. DOS COM is checked first; its test is the older one.
fn headerless_program(data: &[u8]) -> Option<FileType> {
    if heuristics::looks_like_unnamed_dos_com(data) {
        Some(FileType::DosCom)
    } else if shellcode::detect(data).is_some() {
        Some(FileType::Shellcode)
    } else {
        None
    }
}

/// Types whose extension names a language or script, so a body that is not
/// text, or is plainly another language, contradicts it.
fn claims_source(ft: FileType) -> bool {
    ft.is_source_code()
        || matches!(
            ft,
            FileType::Clojure
                | FileType::Batch
                | FileType::Vbs
                | FileType::AppleScript
                | FileType::Mirc
                | FileType::IrcII
        )
}

/// Formats that start with magic stage 1 always recognises. Reaching the
/// extension fallback means the magic is absent, so the name is wrong.
fn is_magic_defined(ft: FileType) -> bool {
    matches!(
        ft,
        // A registry export always opens with its header line.
        FileType::Reg
            | FileType::StaticLib
            | FileType::Elf
            | FileType::Pe
            | FileType::MachO
            | FileType::JavaClass
            | FileType::Dex
            | FileType::Wasm
    )
}

/// Object code with no header: a DOS COM program when it calls DOS, x86
/// shellcode when it opens with a GetPC idiom, otherwise opaque data.
fn binary_body_type(data: &[u8]) -> FileType {
    if heuristics::looks_like_dos_com(data) {
        FileType::DosCom
    } else if shellcode::detect(data).is_some() {
        FileType::Shellcode
    } else {
        FileType::Data
    }
}

/// What a body is once its extension has been ruled out: binary, a page, a
/// language the scorer recognises, or plain text. A COM program shorter than
/// the binary judgement's window still cannot pass as text: `CD 21` is never
/// valid UTF-8.
fn unclaimed_body_type(sniff: &Sniff<'_>) -> FileType {
    let data = sniff.data;
    if sniff.binary_not_source()
        || (heuristics::looks_like_dos_com(data) && std::str::from_utf8(data).is_err())
    {
        binary_body_type(data)
    } else if let Some(marked) = sniff.unmistakable() {
        marked
    } else if heuristics::looks_like_html(data) {
        FileType::Html
    } else {
        sniff.scored_type().unwrap_or(FileType::Text)
    }
}

/// Detect file type from content alone: the signature stage (magic bytes,
/// shebangs and structural markers such as a `go.mod` directive).
///
/// Does not consider file extensions or the language heuristics.
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
mod tests;

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

/// Batch, VBScript, mIRC, ircII and bitmaps identified by their bytes: with no
/// name, under a name that lies, and under a name that is right.
#[cfg(test)]
mod script_and_bitmap_content_tests;
