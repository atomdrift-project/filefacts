//! The [`FileType`] table: every variant with its label, group, extension
//! strength, predicate flags and archive container, declared in one place.

use super::container::{ArchiveFormat, Compression, Container};

/// The group a [`FileType`] belongs to. Every type is in exactly one, so the
/// groups partition the types: rule authors target them, models train on
/// them, and an extension/content mismatch is reported as a
/// `content → extension` group transition. A new variant forces a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Group {
    /// Compiled native executables and libraries (PE, ELF, Mach-O).
    Native,
    /// Virtual-machine bytecode (JVM, Dalvik, CPython, BEAM, Wasm).
    Bytecode,
    /// Raw machine code with no container: a DOS `.com`, shellcode, a boot
    /// sector.
    MachineCode,
    /// Interpreted scripting languages.
    Scripts,
    /// Compiled or typed source languages.
    Source,
    /// Build definitions: Makefiles, CMake, Dockerfiles, Xcode projects.
    Build,
    /// Manifests, lockfiles and structured configuration.
    Config,
    /// Archives, packages and disk images: containers of members.
    Archives,
    /// Single-stream compression (gzip, bzip2, xz, lzma, zstd): one
    /// compressed payload, not a container of members.
    Compressed,
    /// Authored documents: office formats, PDF, RTF, PostScript, HTML, TeX
    /// and Markdown.
    Documents,
    /// Plain text with no recognized markup.
    Text,
    /// Raster and vector images.
    Images,
    /// Audio and video are their own groups: a payload renamed from `.wav`
    /// to `.png` is a real transition, not a benign refinement.
    Audio,
    /// Video containers.
    Video,
    /// Fonts are their own group, not images: a font renamed to `.png` is a
    /// format transition worth reporting.
    Fonts,
    /// Detached signatures and trust records: what vouches for other files.
    Signatures,
    /// Object-serialization streams (Python pickle, .NET NRBF): data that
    /// a deserializer turns back into live objects.
    Serialized,
    /// Opaque data with no recognized structure.
    Data,
    /// Content not identified at all.
    Unknown,
}

impl Group {
    /// Every group, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Native,
        Self::Bytecode,
        Self::MachineCode,
        Self::Scripts,
        Self::Source,
        Self::Build,
        Self::Config,
        Self::Archives,
        Self::Compressed,
        Self::Documents,
        Self::Text,
        Self::Images,
        Self::Audio,
        Self::Video,
        Self::Fonts,
        Self::Signatures,
        Self::Serialized,
        Self::Data,
        Self::Unknown,
    ];

    /// The group's stable name, as rules and model routes spell it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Bytecode => "bytecode",
            Self::MachineCode => "machine_code",
            Self::Scripts => "scripts",
            Self::Source => "source",
            Self::Build => "build",
            Self::Config => "config",
            Self::Archives => "archives",
            Self::Compressed => "compressed",
            Self::Documents => "documents",
            Self::Text => "text",
            Self::Images => "images",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Fonts => "fonts",
            Self::Signatures => "signatures",
            Self::Serialized => "serialized",
            Self::Data => "data",
            Self::Unknown => "unknown",
        }
    }

    /// The group named `label`, the inverse of [`Group::label`].
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|g| g.label() == label)
    }

    /// The types in this group, in declaration order.
    pub fn file_types(self) -> impl Iterator<Item = FileType> {
        FileType::ALL
            .iter()
            .copied()
            .filter(move |t| t.group() == self)
    }
}

impl std::fmt::Display for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// What an extension naming a type says about the bytes behind it. Every
/// rule of identification that weighs a name against content reads this
/// column and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Strength {
    /// A filename habit, not a format: `.dat`, `.txt`. The language scorer
    /// and unmistakable marks replace it.
    Weak,
    /// A container whose signature is checked before any name is: `.zip`,
    /// `.png`, `.woff2`. Once the signature has not matched, the name is the
    /// only thing claiming the container, so content replaces it as it
    /// replaces a weak name.
    Container,
    /// A prose document: `.md`. A body plainly written in a language is that
    /// language, but a mark quoted in the prose does not make the document.
    Document,
    /// A web page: `.html`. A server page or template saved under the name
    /// is what its mark says, keyword scoring does not replace it, and a body
    /// without markup is no page.
    Page,
    /// A source language. Keyword scoring is too weak to overrule it, but a
    /// binary body, or a body plainly written in another language, does.
    Language,
    /// A format defined by its magic: `.exe`, `.so`, `.a`. The signature
    /// stage always recognises the real thing, so once it has not, the name
    /// is wrong and the body is typed by what it is.
    MagicDefined,
    /// A format the name settles on its own: manifests, documents, and
    /// formats whose body carries no signature.
    Named,
}

impl Strength {
    /// Whether the language scorer replaces the name.
    pub(super) const fn yields_to_scorer(self) -> bool {
        matches!(self, Self::Weak | Self::Container | Self::Document)
    }

    /// Whether an unmistakable mark replaces the name.
    pub(super) const fn yields_to_mark(self) -> bool {
        matches!(self, Self::Weak | Self::Container | Self::Page)
    }
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

/// Declares [`FileType`] from one table, so the enum, its labels, groups,
/// extension strengths, predicate flags and containers cannot drift apart. A
/// row is a variant's documentation, then
/// `Variant => "label", Group, Strength, FLAGS... => Archive(Compression);`
/// where the flags and the container are optional, and the compression is
/// optional within the container.
///
/// The table generates the enum, [`FileType::label`], [`FileType::from_label`]
/// (a repeated label is an unreachable-pattern warning),
/// [`FileType::archive_format`], the `group`, `strength`, `flags` and
/// `declared_compression` lookups, and, for tests, `FileType::ALL` in
/// declaration order.
macro_rules! file_types {
    (@archive) => { None };
    (@archive $archive:ident $($compression:ident)?) => { Some(ArchiveFormat::$archive) };
    (@compression) => { Compression::None };
    (@compression $compression:ident) => { Compression::$compression };
    (
        $(#[$meta:meta])*
        pub enum FileType {
            $(
                $(#[doc = $doc:literal])*
                $variant:ident => $label:literal, $group:ident, $strength:ident
                    $(, $flag:ident)* $(=> $archive:ident $(($compression:ident))?)?;
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
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The canonical, stable label for this type, which is also its
            /// serialized form (see the `serde` impls).
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

            /// The archive container format underlying this type, or `None` when
            /// the type is not an archive-backed package.
            ///
            /// `None` covers source, binaries, and manifests, and also the pure
            /// single-file compression wrappers (`.gz`, `.bz2`, `.xz`, `.zst`):
            /// those carry no multi-file container of their own, so there is
            /// nothing to name here — a consumer decompresses them and
            /// re-identifies the inner bytes.
            ///
            /// The returned format is the stable key for model selection: prefer a
            /// specialist trained for the exact [`FileType`], and fall back to the
            /// container format (ignoring compression) when none exists.
            #[must_use]
            pub const fn archive_format(self) -> Option<ArchiveFormat> {
                match self {
                    $(Self::$variant => file_types!(@archive $($archive $($compression)?)?),)+
                }
            }

            /// The compression a type declares on its own, before any byte
            /// inspection. For [`FileType::PkgArch`] this is the modern Arch
            /// default; [`container_of`](super::container_of) refines it from
            /// the bytes.
            const fn declared_compression(self) -> Compression {
                match self {
                    $(Self::$variant => file_types!(@compression $($($compression)?)?),)+
                }
            }

            /// The one [`Group`] this type belongs to.
            #[must_use]
            pub const fn group(self) -> Group {
                match self {
                    $(Self::$variant => Group::$group,)+
                }
            }

            /// What an extension naming this type says about the bytes.
            pub(super) const fn strength(self) -> Strength {
                match self {
                    $(Self::$variant => Strength::$strength,)+
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
    // [`FileType::from_label`] pair (see the `impl serde::*` below), not a
    // derived `rename_all`, so the serialized form and the label are one
    // string rather than two near-identical vocabularies.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum FileType {
        /// Mach-O binary (macOS/iOS executable or library)
        MachO => "macho", Native, MagicDefined, BINARY;
        /// ELF binary (Linux/Unix executable or shared library)
        Elf => "elf", Native, MagicDefined, BINARY;
        /// PE binary (Windows executable, DLL)
        Pe => "pe", Native, MagicDefined, BINARY;
        /// Windows New Executable (16-bit NE) binary
        Ne => "ne", Native, MagicDefined, BINARY;
        /// Unix shell script (bash, sh, zsh, etc.)
        Shell => "shell", Scripts, Language, SOURCE_CODE;
        /// Windows batch file (.bat, .cmd)
        Batch => "batch", Scripts, Language;
        /// IBM z/OS Job Control Language batch script (.jcl)
        Jcl => "jcl", Scripts, Named;
        /// VBScript source file (.vbs, .vbe, .wsf, .wsc)
        Vbs => "vbs", Scripts, Language;
        /// Python source file (.py)
        Python => "python", Scripts, Language, SOURCE_CODE;
        /// JavaScript source file (.js, .mjs, .cjs)
        JavaScript => "javascript", Scripts, Language, SOURCE_CODE;
        /// TypeScript source file (.ts, .tsx)
        TypeScript => "typescript", Scripts, Language, SOURCE_CODE;
        /// Go source file (.go)
        Go => "go", Source, Language, SOURCE_CODE;
        /// Rust source file (.rs)
        Rust => "rust", Source, Language, SOURCE_CODE;
        /// Java source file (.java)
        Java => "java", Source, Language, SOURCE_CODE;
        /// Compiled Java bytecode (.class)
        JavaClass => "java_class", Bytecode, MagicDefined, BINARY;
        /// Python compiled bytecode (.pyc)
        PythonBytecode => "python_bytecode", Bytecode, Named, BINARY;
        /// Ren'Py compiled script (RPC2 slots holding pickled AST data)
        Rpyc => "rpyc", Bytecode, Named, BINARY;
        /// Erlang/Elixir compiled BEAM bytecode (.beam; `FOR1`…`BEAM` IFF container)
        Beam => "beam", Bytecode, Named, BINARY;
        /// WebAssembly binary module (.wasm; `\0asm` magic + version). A portable
        /// bytecode payload — frequently a Go/TinyGo/Rust/Emscripten compile target
        /// loaded by a JS host. Routed through the generic analyzer so string
        /// extraction, entropy, and symbol-name traits fire on the embedded
        /// `syscall/js` imports, struct tags, and rodata.
        Wasm => "wasm", Bytecode, MagicDefined, BINARY;
        /// Dalvik/ART executable bytecode (`dex\n035\0` and later versions).
        /// APKs carry this as `classes.dex`; a standalone `.dex` is the same
        /// format, not an APK. There is no competing popular "DEX" file type —
        /// the name is the format, not a platform qualifier.
        Dex => "dex", Bytecode, MagicDefined, BINARY;
        /// Java archive (.jar, .war, .ear)
        Jar => "jar", Archives, Container => Zip;
        /// Ruby source file (.rb)
        Ruby => "ruby", Scripts, Language, SOURCE_CODE;
        /// PHP source file (.php)
        Php => "php", Scripts, Language, SOURCE_CODE;
        /// Perl source file (.pl, .pm)
        Perl => "perl", Scripts, Language, SOURCE_CODE;
        /// Lua source file (.lua)
        Lua => "lua", Scripts, Language, SOURCE_CODE;
        /// C# source file (.cs)
        CSharp => "csharp", Source, Language, SOURCE_CODE;
        /// PowerShell script (.ps1, .psm1)
        PowerShell => "powershell", Scripts, Language, SOURCE_CODE;
        /// Swift source file (.swift)
        Swift => "swift", Source, Language, SOURCE_CODE;
        /// Objective-C source file (.m, .mm)
        ObjectiveC => "objective_c", Source, Language, SOURCE_CODE;
        /// Groovy source file (.groovy)
        Groovy => "groovy", Source, Language, SOURCE_CODE;
        /// Scala source file (.scala)
        Scala => "scala", Source, Language, SOURCE_CODE;
        /// Kotlin source file (.kt, .kts)
        Kotlin => "kotlin", Source, Language, SOURCE_CODE;
        /// Zig source file (.zig)
        Zig => "zig", Source, Language, SOURCE_CODE;
        /// Elixir source file (.ex, .exs)
        Elixir => "elixir", Source, Language, SOURCE_CODE;
        /// Clojure / ClojureScript / EDN source (.clj, .cljs, .cljc, .cljr, .edn, .bb)
        Clojure => "clojure", Source, Language;
        /// C source file (.c, .h)
        C => "c", Source, Language, SOURCE_CODE;
        /// npm package.json manifest
        PackageJson => "package.json", Config, Named, STRUCTURED_DATA;
        /// npm package-lock.json lockfile
        PackageLockJson => "package-lock.json", Config, Named, STRUCTURED_DATA;
        /// VSCode extension manifest (.vsixmanifest)
        VsixManifest => "vsix_manifest", Config, Named;
        /// Chrome extension manifest.json
        ChromeManifest => "chrome_manifest", Config, Named, STRUCTURED_DATA;
        /// Rust Cargo.toml manifest
        CargoToml => "cargo.toml", Config, Named, STRUCTURED_DATA;
        /// Rust Cargo.lock lockfile — pins every crate to an exact version + sha256.
        CargoLock => "cargo.lock", Config, Named, STRUCTURED_DATA;
        /// Python pip requirements file (requirements.txt) — `name==version` pins.
        RequirementsTxt => "requirements.txt", Config, Named;
        /// Python Poetry lockfile (poetry.lock) — resolved package set.
        PoetryLock => "poetry.lock", Config, Named, STRUCTURED_DATA;
        /// Python Pipenv lockfile (Pipfile.lock) — resolved package set with hashes.
        PipfileLock => "pipfile.lock", Config, Named, STRUCTURED_DATA;
        /// Ruby Bundler lockfile (Gemfile.lock) — resolved gem set with versions.
        GemfileLock => "gemfile.lock", Config, Named;
        /// PHP Composer lockfile (composer.lock) — resolved package set with dists.
        ComposerLock => "composer.lock", Config, Named, STRUCTURED_DATA;
        /// Yarn lockfile (yarn.lock) — resolved npm package set with integrity.
        YarnLock => "yarn.lock", Config, Named;
        /// pnpm lockfile (pnpm-lock.yaml) — resolved npm package set with integrity.
        PnpmLock => "pnpm-lock.yaml", Config, Named, STRUCTURED_DATA;
        /// Python pyproject.toml manifest
        PyProjectToml => "pyproject.toml", Config, Named, STRUCTURED_DATA;
        /// PHP composer.json manifest
        ComposerJson => "composer.json", Config, Named, STRUCTURED_DATA;
        /// Generic JSON document (.json)
        Json => "json", Config, Named;
        /// node-gyp build manifest (binding.gyp, .gyp, .gypi). JSON-shaped build
        /// config; its `<!(...)`/`<!@(...)` command-expansion runs arbitrary shell
        /// during `node-gyp configure` (npm runs this automatically on install of a
        /// package containing binding.gyp), a known supply-chain execution vector.
        Gyp => "gyp", Config, Named;
        /// GitHub Actions workflow YAML
        GithubActions => "github_actions", Config, Named, STRUCTURED_DATA;
        /// systemd service unit file (.service, .service.d/*.conf)
        SystemdService => "systemd_service", Config, Named;
        /// freedesktop.org Desktop Entry (.desktop) - XDG application launcher / autostart
        DesktopEntry => "desktop_entry", Config, Named;
        /// Generic XML document (.xml, MSBuild .csproj, SVG, XML config files, etc.)
        Xml => "xml", Config, Named;
        /// Generic YAML document (.yaml, .yml) that is not one of the specific
        /// manifests above (a GitHub Actions workflow, a pnpm lockfile). YAML is the
        /// default configuration language for CI, Kubernetes and model cards, so an
        /// unrecognized one is worth naming rather than leaving as `unknown`.
        Yaml => "yaml", Config, Named;
        /// Python package metadata (PKG-INFO, METADATA)
        PkgInfo => "pkg_info", Config, Named, STRUCTURED_DATA;
        /// Arch/AUR generated package metadata (.SRCINFO) — normalized mirror of PKGBUILD
        SrcInfo => "src_info", Config, Named, STRUCTURED_DATA;
        /// Normalized package-registry metadata (`*.registry.json`) — an upstream
        /// provider's account of a release (publish date, author, downloads,
        /// rating, deprecation), the serialized form of [`crate::Registry`].
        Registry => "registry", Config, Named, STRUCTURED_DATA;
        /// Windows registry export (`.reg`), the script `regedit` imports and
        /// exports. Its first line names the format: `REGEDIT4`, or `Windows
        /// Registry Editor Version 5.00` in UTF-8 or (as `regedit` writes it)
        /// UTF-16LE behind a byte-order mark. Unrelated to [`Self::Registry`].
        Reg => "reg", Config, MagicDefined;
        /// Go module manifest (go.mod) — `require` directives are declared dependencies.
        GoMod => "go.mod", Config, Named;
        /// Go module checksum database (go.sum) — pins every module to an `h1:` hash.
        GoSum => "go.sum", Config, Named;
        /// ZIP archive (zip, apk, ipa, nupkg, etc.)
        Zip => "zip", Archives, Container => Zip;
        /// Go module distribution ZIP — all members share a `module@version/` prefix.
        /// Distinct from Go source and the standalone `go.mod` manifest.
        GoModule => "go_module", Archives, Container => Zip;
        /// TAR archive (plain, no compression)
        Tar => "tar", Archives, Named => Tar;
        /// ASCII CPIO archive (odc, newc, or newc checksum layout).
        Cpio => "cpio", Archives, Named => Cpio;
        /// Gzip-compressed TAR (.tar.gz, .tgz, .crate)
        TarGz => "tar.gz", Archives, Named => Tar(Gzip);
        /// Bzip2-compressed TAR (.tar.bz2, .tbz2)
        TarBz2 => "tar.bz2", Archives, Named => Tar(Bzip2);
        /// XZ-compressed TAR (.tar.xz, .txz)
        TarXz => "tar.xz", Archives, Named => Tar(Xz);
        /// Zstandard-compressed TAR (.tar.zst, .xbps)
        TarZst => "tar.zst", Archives, Named => Tar(Zstd);
        /// Gzip-compressed single file (.gz, not a tar)
        Gz => "gz", Compressed, Named;
        /// Bzip2-compressed single file (.bz2, not a tar)
        Bz2 => "bz2", Compressed, Named;
        /// XZ-compressed single file (.xz, not a tar)
        Xz => "xz", Compressed, Named;
        /// LZMA-alone compressed single file (.lzma)
        Lzma => "lzma", Compressed, Named;
        /// Zstandard-compressed single file (.zst, not a tar)
        Zst => "zst", Compressed, Named;
        /// 7-Zip archive (.7z)
        SevenZ => "7z", Archives, Container => SevenZip;
        /// RAR archive (.rar)
        Rar => "rar", Archives, Container => Rar;
        /// Ren'Py archive (.rpa), with an RPA-2.0 or RPA-3.0 index header.
        Rpa => "rpa", Archives, Named => Rpa;
        /// Debian package (.deb)
        Deb => "deb", Archives, Named => Ar;
        /// Unix static library (.a) — an `ar` archive of relocatable object files.
        /// Shares the `!<arch>` magic with `.deb`; distinguished by the first `ar`
        /// member (`.deb` leads with `debian-binary`, a static library does not).
        StaticLib => "static-lib", Native, MagicDefined;
        /// RPM package (.rpm)
        Rpm => "rpm", Archives, Named;
        /// macOS installer package (.pkg, XAR format). Named `PkgMacos` (not bare
        /// `Pkg`) because the `.pkg` extension is ambiguous: FreeBSD and Arch also
        /// use it for compressed-tar packages, disambiguated by container magic.
        PkgMacos => "pkg_macos", Archives, Named => Xar;
        /// Apple Disk Image (.dmg, UDIF container).
        Dmg => "dmg", Archives, Named;
        /// Virtual Hard Disk, fixed or sparse, with a validated footer.
        Vhd => "vhd", Archives, Named;
        /// Optical-disc image (.iso): ISO 9660 and/or UDF filesystem — full OS
        /// install media. Identified by the volume-descriptor magic at sector 16;
        /// unpacked downstream by 7-Zip (ISO 9660, Joliet, Rock Ridge, and UDF).
        Iso => "iso", Archives, Named => Iso9660;
        /// SquashFS read-only filesystem image — `hsqs` (little-endian) or `sqsh`
        /// (big-endian) superblock magic. Ships inside firmware images and appliance
        /// builds, and is the wire format of a Snap package (see [`FileType::Snap`]).
        SquashFs => "squashfs", Archives, MagicDefined;
        /// Cabinet archive (.cab)
        Cab => "cab", Archives, Container => Cab;
        /// Compiled HTML Help (.chm) — Microsoft ITSF/ITOL container with
        /// LZX-compressed HTML topics. Common malware delivery vector.
        Chm => "chm", Archives, Container;
        /// Chrome extension (.crx)
        Crx => "crx", Archives, Named => Zip;
        /// Mozilla Firefox extension (.xpi) — ZIP container with WebExtension or
        /// legacy XUL layout. Disambiguated from generic ZIP so the XPI-specific
        /// signing-scheme shape (`META-INF/mozilla.*`, `META-INF/cose.*`) can be
        /// surfaced.
        Xpi => "xpi", Archives, Container => Zip;
        /// Python wheel (.whl) — ZIP container with PEP 427 layout. Distinct
        /// from generic ZIP so the wheel-specific surface (dist-info, RECORD,
        /// native-extension count, top-level packages) can be extracted.
        Whl => "whl", Archives, Container => Zip;
        /// RubyGems package (.gem) — uncompressed `ustar` tar holding
        /// `metadata.gz` (gzipped `Gem::Specification` YAML), `data.tar.gz`, and
        /// `checksums.yaml.gz`. Distinct from generic tar so the gem's external
        /// identity metadata can be surfaced as `gem.*`.
        Gem => "gem", Archives, Named => Tar;
        /// Android application package (.apk) — ZIP container (`AndroidManifest.xml`,
        /// `classes.dex`). Disambiguated from the Alpine `.apk` by container magic
        /// (`PK` zip vs gzip tar) so each ecosystem gets its own model.
        ApkAndroid => "apk_android", Archives, Container => Zip;
        /// Alpine Linux package (.apk) — gzip-concatenated tar (signature ‖ control
        /// ‖ data) carrying `.PKGINFO`. Disambiguated from the Android `.apk` by
        /// container magic (gzip vs `PK` zip).
        ApkAlpine => "apk_alpine", Archives, Named => Tar(Gzip);
        /// npm package (.tgz) — gzip tar with everything under a `package/` prefix
        /// (`package/package.json`). Disambiguated from a generic gzip tar by that
        /// marker, so npm supply-chain signal (install scripts, bin shims) routes
        /// to its own model.
        Npm => "npm", Archives, Named => Tar(Gzip);
        /// Rust crate (.crate) — gzip tar laid out as `<name>-<version>/` with a
        /// `Cargo.toml` at its root. The `.crate` extension is cargo-specific.
        Crate => "crate", Archives, Named => Tar(Gzip);
        /// PHP Composer source distribution ZIP with a root composer.json.
        Composer => "composer", Archives, Named => Zip;
        /// Hex release tar wrapping metadata.config and contents.tar.gz.
        Hex => "hex", Archives, Named => Tar;
        /// Dart/pub.dev gzip source distribution with a root pubspec.yaml.
        Pub => "pub", Archives, Named => Tar(Gzip);
        /// CRAN R source package with a root DESCRIPTION identity.
        Cran => "cran", Archives, Named => Tar(Gzip);
        /// CPAN Perl gzip source distribution with META.json or META.yml.
        Cpan => "cpan", Archives, Named => Tar(Gzip);
        /// Hackage gzip source distribution with a matching .cabal manifest.
        Hackage => "hackage", Archives, Named => Tar(Gzip);
        /// conda package (.conda) — ZIP holding `metadata.json` plus zstd-compressed
        /// `info-*`/`pkg-*` tars. Distinct from generic ZIP so conda identity
        /// (`info/index.json`) routes to its own model.
        Conda => "conda", Archives, Named => Zip;
        /// Python egg (.egg) — ZIP with an `EGG-INFO/` directory (`PKG-INFO`).
        Egg => "egg", Archives, Named => Zip;
        /// NuGet package (.nupkg) — ZIP carrying a `*.nuspec` manifest.
        Nupkg => "nupkg", Archives, Named => Zip;
        /// iOS application archive (.ipa) — ZIP with `Payload/*.app/Info.plist`.
        Ipa => "ipa", Archives, Named => Zip;
        /// VS Code / Open VSX extension (.vsix) — ZIP carrying
        /// `extension.vsixmanifest`. Distinct from the manifest file type
        /// [`FileType::VsixManifest`], which is that inner XML alone.
        Vsix => "vsix", Archives, Named => Zip;
        /// FreeBSD package (.pkg) — zstd-compressed tar whose first member is the
        /// `+COMPACT_MANIFEST` / `+MANIFEST` metadata. Disambiguated from the macOS
        /// `.pkg` by container magic (zstd-tar vs `xar!`) and from Arch by the
        /// `+MANIFEST` marker.
        PkgFreebsd => "pkg_freebsd", Archives, Named => Tar(Zstd);
        /// Arch Linux package (.pkg.tar.{zst,xz,gz}) — compressed tar whose first
        /// member is `.PKGINFO`. Disambiguated from FreeBSD by that marker; the
        /// `.pkg.tar.*` extension is Arch-specific where the body can't be read.
        /// Its compression is not pinned by the type; zstd is the declared default
        /// and [`container_of`](super::container_of) reads the real one.
        PkgArch => "pkg_arch", Archives, Named => Tar(Zstd);
        /// Python source distribution (sdist) — gzip tar laid out as
        /// `<name>-<version>/` with a `PKG-INFO` metadata file at its root.
        /// Disambiguated from a generic gzip tar by that marker, so the PyPI
        /// publisher identity (`python.*`) routes to its own model.
        PythonSdist => "python_sdist", Archives, Named => Tar(Gzip);
        /// OCI / Docker container image archive — an (uncompressed) tar carrying
        /// either an OCI `oci-layout` + `index.json` or a `docker save`
        /// `manifest.json`. Distinct from a generic tar so image refs and content
        /// digests can be surfaced as `oci.*`.
        OciImage => "oci_image", Archives, Named => Tar;
        /// Void Linux package (.xbps) — zstd-compressed tar carrying `props.plist`
        /// metadata. Distinguished from a generic `.tar.zst` by its extension.
        Xbps => "xbps", Archives, Named => Tar(Zstd);
        /// Ubuntu Snap package (.snap) — a SquashFS image carrying `meta/snap.yaml`.
        /// Distinguished from a bare [`FileType::SquashFs`] image by its extension,
        /// which is the only signal available without reading the filesystem.
        Snap => "snap", Archives, MagicDefined;
        /// Flatpak single-file bundle (.flatpak) — an OSTree static delta in GVariant
        /// framing. Unlike every other package format here it carries no magic at a
        /// fixed offset and none is registered with `file(1)`, so the extension is
        /// the identification.
        Flatpak => "flatpak", Archives, Named;
        /// Gentoo binary package (GLEP 78 `.gpkg.tar`) — an uncompressed tar
        /// bundling `metadata.tar.*`, `image.tar.*`, and a `Manifest`. Distinct
        /// from a generic tar by its `.gpkg.tar` extension.
        GentooBinpkg => "gentoo_binpkg", Archives, Named => Tar;
        /// Electron ASAR application archive (.asar)
        Asar => "asar", Archives, Named => Asar;
        /// PHP archive in the native phar format: a PHP stub, a manifest, and
        /// the packaged files. Tar- and zip-based phars are `tar` and `zip`.
        Phar => "phar", Archives, Named;
        /// AppleScript source file (.applescript, .scpt)
        AppleScript => "applescript", Scripts, Language;
        /// Apple Property List (.plist)
        Plist => "plist", Config, Named, STRUCTURED_DATA;
        /// Compiled Interface Builder archive (.nib): the object graph AppKit or
        /// UIKit instantiates for a window or view, in either the `NIBArchive`
        /// layout or an `NSKeyedArchiver` binary plist. Distinct from `Plist`
        /// because the graph names the app's own classes, action selectors,
        /// and Swift modules, which is attribution a plain plist never carries.
        Nib => "nib", Config, Named, STRUCTURED_DATA;
        /// Xcode project file (`project.pbxproj`) — an OpenStep-style property
        /// list describing targets, build phases, and build settings. Kept
        /// distinct from `Plist` because it is the only plist dialect that carries
        /// executable build scripts, which is what makes it a supply-chain target.
        Pbxproj => "pbxproj", Build, Named, STRUCTURED_DATA;
        /// CMake build script (`CMakeLists.txt`, `*.cmake`). Its own type rather
        /// than generic text because it is executable build logic — `execute_process`
        /// and `add_custom_command` run at configure and build time — so rules that
        /// target build systems must be able to name it.
        Cmake => "cmake", Build, Named;
        /// Rich Text Format document (.rtf)
        Rtf => "rtf", Documents, Named;
        /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
        OleDoc => "ole_doc", Documents, Named;
        /// Windows Installer package / patch (OLE2/CFBF: .msi, .msp). Same compound
        /// container as [`OleDoc`](Self::OleDoc), but a distinct product surface (installer tables,
        /// custom-action binaries, SummaryInformation) — not a document.
        // Installer packages share the OLE2/CFBF wire format with OleDoc but
        // are not documents — treat them as archive-class for mismatch
        // transitions (e.g. an MSI renamed `.doc` is archive→document).
        Msi => "msi", Archives, Named;
        /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
        Ooxml => "ooxml", Documents, Container;
        /// Windows Shell Link file (.lnk)
        Lnk => "lnk", Config, Named;
        /// JPEG image
        Jpeg => "jpeg", Images, Container;
        /// PNG image
        Png => "png", Images, Container;
        /// Tagged Image File Format (classic TIFF or BigTIFF).
        Tiff => "tiff", Images, Container;
        /// AV1 Image File Format, identified by its ISO-BMFF brands.
        Avif => "avif", Images, Container;
        /// RIFF audio (`.wav`). Chunked container; see formats/containers.rs.
        Wav => "wav", Audio, Container;
        /// IFF audio (`.aiff`, `.aifc`).
        Aiff => "aiff", Audio, Container;
        /// MPEG audio with optional ID3 tags (`.mp3`).
        Mp3 => "mp3", Audio, Container;
        /// ISO base media (`.mp4`, `.m4a`, `.mov`) — a flat box sequence.
        Mp4 => "mp4", Video, Container;
        /// Windows icon or cursor (`.ico`, `.cur`). The favicon every web package
        /// ships and nobody opens, which is what makes it a carrier.
        Ico => "ico", Images, Container;
        /// Windows animated cursor (`.ani`): a RIFF `ACON` form whose frames are
        /// icons.
        Ani => "ani", Images, Container;
        /// GIF image (`.gif`).
        Gif => "gif", Images, Container;
        /// Windows bitmap (`.bmp`).
        Bmp => "bmp", Images, Container;
        /// RIFF image (`.webp`).
        Webp => "webp", Images, Container;
        /// Font container: sfnt (`.ttf`/`.otf`/`.ttc`), WOFF, WOFF2, or EOT.
        /// One variant for the family because the abuse patterns are shared —
        /// a payload wearing a font name, or a stowaway in the table gaps —
        /// and the concrete container is reported as `font.format`.
        Font => "font", Fonts, Container;
        /// SVG image (.svg) — XML-based vector graphic. Unlike raster images it
        /// is text and can embed `<script>` / event handlers, making it a common
        /// phishing/HTML-smuggling carrier; classified as media but scanned as XML.
        Svg => "svg", Images, Named;
        /// Python pickle serialized data (.pkl, .pickle, .joblib)
        Pickle => "pickle", Serialized, Named;
        /// .NET Remoting Binary Format stream (MS-NRBF): `BinaryFormatter`
        /// output, opened by a `SerializedStreamHeader` record.
        Nrbf => "nrbf", Serialized, Named;
        /// Apple Image4 payload (`IM4P`) of type `trca` holding a version-2
        /// trust-cache table of code-directory hashes.
        Image4TrustCache => "image4_trustcache", Signatures, Named;
        /// PDF document
        Pdf => "pdf", Documents, Named;
        /// HTML document (.html, .htm)
        Html => "html", Documents, Page;
        /// JavaServer Pages (`.jsp`, `.jspx`). The page directive is unique to JSP.
        Jsp => "jsp", Scripts, Named;
        /// Classic ASP and ASP.NET (`.asp`, `.aspx`, and the related suffixes).
        Asp => "asp", Scripts, Named;
        /// ColdFusion Markup Language (`.cfm`, `.cfc`, `.cfml`).
        Cfml => "cfml", Scripts, Named;
        /// TeX or LaTeX source (`.tex`, `.sty`, `.ltx`, `.dtx`). `.cls` is shared
        /// with Visual Basic, so a class file is TeX only when its body says so.
        Tex => "tex", Documents, Named;
        /// YARA rule source (`.yar`, `.yara`).
        // A detection ruleset, not prose. A `.yar` renamed `.txt` is
        // config→text; it is not the same kind of file as a note.
        Yara => "yara", Config, Named;
        /// PostScript or EPS (`.ps`, `.eps`).
        PostScript => "postscript", Documents, Named;
        /// DOS COM executable. No header of its own; `INT 21h` (`CD 21`) is the syscall.
        DosCom => "dos_com", MachineCode, Named, BINARY;
        /// Headerless x86 / x86-64 position-independent code, recognised by the
        /// GetPC idiom it opens with (see `fileid::shellcode`).
        Shellcode => "shellcode", MachineCode, Named, BINARY;
        /// A FAT12/16/32 volume boot sector: a BIOS jump, a BIOS parameter block
        /// whose fields agree with each other, and the `55 AA` signature. The
        /// boot code behind the BPB is what runs.
        FatBootSector => "fat_boot_sector", MachineCode, Named, BINARY;
        /// mIRC script (`.mrc`).
        Mirc => "mirc", Scripts, Language;
        /// ircII or EPIC script. The `^on` / `^alias` hook syntax is the mark.
        IrcII => "ircii", Scripts, Language;
        /// Markdown document (.md, .markdown)
        Markdown => "markdown", Documents, Named, UNSUPPORTED;
        /// Makefile / GNU Make build file
        Makefile => "makefile", Build, Named;
        /// Dockerfile — container image build definition
        Dockerfile => "dockerfile", Build, Named;
        /// OpenDocument Format (.odt, .ods, .odp, .odg) — ZIP-based office documents
        Odf => "odf", Documents, Container, UNSUPPORTED => Zip;
        /// OpenPGP signature (.sig, .asc) — the detached signature published beside
        /// a release artifact. Both the ASCII-armored and binary packet forms.
        /// Provenance evidence rather than payload, and named so a release directory
        /// does not read as a pile of unknowns.
        PgpSignature => "pgp_signature", Signatures, Named;
        /// Detached signature sidecar holding one X.509 certificate, the
        /// signature bytes, and a flags field, each length-framed. Several
        /// content-decryption clients ship these beside their libraries.
        CertificateSignature => "certificate_signature", Signatures, Named;
        /// Plain text data (.txt, .text, or printable text with no stronger type)
        Text => "text", Text, Weak;
        /// Opaque or sidecar data (.dat, .bin, .payload, .raw, and .map) — commonly carries
        /// encrypted/XOR-d payloads or source-map embedded code. Routed through the generic analyzer
        /// so string extraction, entropy, and encoded-payload detection still fire.
        Data => "data", Data, Weak;
        /// File type could not be determined
        Unknown => "unknown", Unknown, Named, UNSUPPORTED;
    }
}

impl FileType {
    /// Returns true for every type except `Unknown`, `Markdown` and `Odf`.
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
    /// That is the `archives` and `compressed` groups, less two archives no
    /// walker reads: Flatpak bundles stay opaque, because no walker reads
    /// their OSTree delta framing yet, and Windows Installer packages are read
    /// as OLE2 storage rather than walked.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        matches!(self.group(), Group::Archives | Group::Compressed)
            && !matches!(self, Self::Flatpak | Self::Msi)
    }

    /// Returns true if this file type is a compiled native binary.
    #[must_use]
    pub fn is_binary(&self) -> bool {
        self.flags().contains(Flags::BINARY)
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

    /// The full archive-plus-compression decomposition of this type, derived
    /// from the type alone, or `None` for non-archive types (see
    /// [`FileType::archive_format`]).
    ///
    /// Compression is exact for every type except Arch Linux packages
    /// ([`FileType::PkgArch`]), whose `.pkg.tar.{zst,xz,gz}` codec the type
    /// does not pin; this reports its modern default ([`Compression::Zstd`]).
    /// Call [`container_of`](super::container_of) with the file bytes to
    /// resolve that case exactly.
    #[must_use]
    pub const fn container(self) -> Option<Container> {
        let Some(archive) = self.archive_format() else {
            return None;
        };
        Some(Container {
            archive,
            compression: self.declared_compression(),
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
