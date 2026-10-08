//! Per-format extractors.
//!
//! Each module here owns the extraction logic for one format family. The
//! contract is the same across all of them: take the source bytes and fill
//! the public output views with format-conventional facts. Extractors must
//! never read from the filesystem and must never panic on malformed input —
//! return [`crate::Error::Malformed`] instead.
//!
//! Dispatch to the right extractor happens in [`extract`], keyed off the
//! [`FileType`] produced by [`crate::fileid`].
//!
//! [`Values`]: crate::Values
//! [`Strings`]: crate::output::Strings
//! [`Metrics`]: crate::Metrics
//! [`FileType`]: crate::FileType

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Errors, Metrics, Section, Strings, Symbols, Values};
use crate::value_key;

mod ani;
mod desktop_entry;
mod systemd;

/// Mutable output collectors that every format extractor writes into.
/// Bundled to keep the [`extract`] dispatch signature manageable and
/// to give future extractors a single place to grow new views.
pub(crate) struct ExtractCtx<'a> {
    pub(crate) values: &'a mut Values,
    pub(crate) strings: &'a mut Strings,
    pub(crate) metrics: &'a mut Metrics,
    pub(crate) archive_members: &'a mut Vec<ArchiveMember>,
    pub(crate) sections: &'a mut Vec<Section>,
    pub(crate) symbols: &'a mut Symbols,
    pub(crate) errors: &'a mut Errors,
    /// End of the executable image in file offsets, for formats whose
    /// image extends past its last section (Mach-O `__LINKEDIT`, the ELF
    /// section-header table). The `binary.*overlay*` metrics count only
    /// bytes past both this and the last section. `None` = sections only.
    pub(crate) image_end: &'a mut Option<u64>,
    /// File basename, when known — lets format-agnostic types (e.g. Shell)
    /// dispatch on a recognized filename such as `PKGBUILD`.
    pub(crate) basename: Option<&'a str>,
    /// The repeating XOR key identification recovered (see
    /// [`crate::FileId::xor_pe_key`]), recorded as the `xor.*` facts.
    pub(crate) xor_pe_key: Option<stng::RepeatingXorKey>,
    /// This open's rizin settings, for the native-binary extractors' symbol
    /// recovery (see [`common::rizin_fallback`]).
    pub(crate) rizin: crate::rizin::Settings,
}

impl ExtractCtx<'_> {
    /// A shorter-lived copy of this context, for handing to one extractor
    /// while the dispatcher keeps its own for the cross-format passes that
    /// run afterwards.
    pub(crate) fn reborrow(&mut self) -> ExtractCtx<'_> {
        ExtractCtx {
            values: self.values,
            strings: self.strings,
            metrics: self.metrics,
            archive_members: self.archive_members,
            sections: self.sections,
            symbols: self.symbols,
            errors: self.errors,
            image_end: self.image_end,
            basename: self.basename,
            xor_pe_key: self.xor_pe_key,
            rizin: self.rizin,
        }
    }
}

/// Owned collectors behind an [`ExtractCtx`], for tests that drive one
/// extractor directly and then inspect what it wrote.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Sinks {
    pub(crate) values: Values,
    pub(crate) strings: Strings,
    pub(crate) metrics: Metrics,
    pub(crate) archive_members: Vec<ArchiveMember>,
    pub(crate) sections: Vec<Section>,
    pub(crate) symbols: Symbols,
    pub(crate) errors: Errors,
    pub(crate) image_end: Option<u64>,
}

#[cfg(test)]
impl Sinks {
    /// A context over these collectors with default settings and no
    /// basename or XOR key.
    pub(crate) fn ctx(&mut self) -> ExtractCtx<'_> {
        ExtractCtx {
            values: &mut self.values,
            strings: &mut self.strings,
            metrics: &mut self.metrics,
            archive_members: &mut self.archive_members,
            sections: &mut self.sections,
            symbols: &mut self.symbols,
            errors: &mut self.errors,
            image_end: &mut self.image_end,
            basename: None,
            xor_pe_key: None,
            rizin: crate::rizin::Settings::default(),
        }
    }
}
mod apk_alpine;
mod apk_android;
mod archive_stats;
mod asar;
mod axml;
mod binary_attribution;
mod bounded;
mod build_toolchain;
mod cab;
mod carrier;
pub(crate) mod cfml;
mod chm;
mod class;
pub(crate) mod common;
mod containers;
mod cpio;
mod crx;
mod deb;
mod dmg;
mod elf;
mod elf_dwarf;
mod elf_dynamic;
mod elf_hashes;
mod elf_syscalls;
mod font;
mod gem;
mod generic;
mod go_buildinfo;
pub(crate) mod goblin_safe;
pub(crate) mod identity;
mod image_stats;
pub(crate) mod iso;
mod jar;
mod jpeg;
mod lnk;
mod macho;
mod macho_code_signature;
mod macho_hashes;
mod markdown;
mod nib;
mod npm;
mod nupkg;
mod oci;
mod ole2;
mod ooxml;
mod pbxproj;
mod pdf;
mod pe;
mod pe_authenticode;
mod pe_debug;
mod pe_image_hash;
mod pe_manifest;
mod pe_rich;
mod pe_signature_trust;
mod pe_version_info;
pub(crate) mod phar;
mod pickle;
mod pkgmeta;
mod plist_guard;
mod png;
mod pyc;
mod python_sdist;
mod rar;
pub(crate) mod references;
mod registry;
mod rpm;
mod rtf;
mod rust_crate;
mod scpt;
mod sevenz;
mod shellcode;
// Pending: lift once the in-flight source-walk refactor lands and fixes its hits.
pub(crate) mod source;
mod source_meta;
mod structured;
mod symbol_hashes;
mod tar;
mod udf;
mod upx;
mod vba;
pub(crate) mod vba_symbols;
mod vsix;
mod wasm;
mod whl;
mod xpi;
mod zip;

/// Run one container walker and emit the shared `media.*` facts.
///
/// Strings are extracted first: the masquerade case is exactly the one where
/// the strings are the evidence, and cleave's recursive decode pipeline reads
/// them to surface `metadata/encoded-payload/*` for base64 blobs and URLs
/// hidden in the container.
fn media_container(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    walk: fn(&[u8]) -> carrier::Coverage,
) {
    common::extract_binary_strings(bytes, strings, common::XorScan::No);
    let coverage = walk(bytes);
    carrier::emit(bytes, &coverage, values, metrics);
}

/// A ZIP-family package: open the container once, emit the generic archive
/// facts, then hand the same archive to the package's own layer. A
/// container the `zip` crate will not open even after repair still gets its
/// member listing from the raw central directory; the package layer, which
/// reads member contents, is then skipped.
fn zip_package<'a>(
    bytes: &'a [u8],
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
    errors: &mut Errors,
    package: impl FnOnce(&mut zip::Archive<'a>, &mut Values, &mut Metrics, &mut Errors),
) -> Result<(), Error> {
    if let Some(mut archive) = zip::open_and_walk(bytes, values, metrics, archive_members, errors)?
    {
        package(&mut archive, values, metrics, errors);
    }
    Ok(())
}

/// Drive the right extractor for `file_type` and merge its output into
/// the public views. Unsupported types fall through to [`generic::extract`]
/// (which still records `file.size` and Shannon entropy).
pub(crate) fn extract(
    file_type: FileType,
    bytes: &[u8],
    tree_cache: Option<&source::TreeCache<'_>>,
    mut ctx: ExtractCtx<'_>,
) -> Result<(), Error> {
    // Every file gets the generic byte-level metrics. Format-specific
    // extractors layer on top of (and may shadow with more accurate
    // values) what generic emits.
    generic::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
    if file_type == FileType::Xml && axml::looks_like_axml(bytes) {
        axml::extract_values(bytes, ctx.values);
    }
    if let Some(key) = ctx.xor_pe_key {
        generic::extract_xor_pe(key, ctx.values, ctx.metrics);
    }
    if ctx
        .basename
        .is_some_and(|name| crate::has_named_reference_metadata(std::path::Path::new(name)))
    {
        ctx.values.insert_key(
            value_key!("go_manifest.kind"),
            serde_json::json!(ctx.basename),
        );
    }

    // Archive-backed types carry their container decomposition (archive +
    // compression) as facts, so a consumer can route on the underlying
    // container — e.g. a `.gem`/`.whl`/`.crate` reports `tar`/`zip`/`tar`
    // here. Emitted centrally so every archive arm gets it; the codec for an
    // Arch `.pkg.tar.*` is resolved from the bytes. Non-archive types emit
    // nothing.
    if let Some(container) = crate::fileid::container_of(file_type, bytes) {
        ctx.values.insert_key(
            value_key!("archive.container.archive"),
            serde_json::Value::String(container.archive.label().into()),
        );
        ctx.values.insert_key(
            value_key!("archive.container.compression"),
            serde_json::Value::String(container.compression.label().into()),
        );
    }

    let result = match file_type {
        FileType::AppleScript => {
            scpt::extract(bytes, ctx.values, ctx.strings, ctx.metrics, ctx.symbols)
        }
        FileType::Pe => pe::extract(bytes, ctx.reborrow()),
        FileType::Elf => {
            elf::extract(bytes, ctx.reborrow());
            Ok(())
        }
        FileType::Wasm => {
            wasm::extract(bytes, ctx.reborrow());
            Ok(())
        }
        FileType::MachO => {
            macho::extract(bytes, ctx.reborrow());
            Ok(())
        }
        // An APK is a zip: walk it for members, then read AndroidManifest.xml
        // and the v1 signature block for the android.* identity facts.
        FileType::ApkAndroid => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            apk_android::extract_from_archive,
        ),
        FileType::Zip | FileType::Odf | FileType::Conda | FileType::Egg | FileType::Ipa => {
            // Zip-based packages (Android apk, conda, egg, ipa): the generic
            // archive walk surfaces their member listing and the identity
            // manifests inside (PKG-INFO, Info.plist, …).
            zip::extract(
                bytes,
                ctx.values,
                ctx.metrics,
                ctx.archive_members,
                ctx.errors,
            )
        }
        FileType::Cab => cab::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        // RAR's headers hold the member table even when payloads are encrypted.
        // Metadata-only, matching CAB/7z: never decompress, never shell out.
        FileType::Rar => rar::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        // The inner `.nuspec` carries the nupkg.* NuGet publisher identity.
        FileType::Nupkg => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            nupkg::extract_from_archive,
        ),
        // The inner extension.vsixmanifest carries the vsix.identity.*
        // publisher/id/version triple.
        FileType::Vsix => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            |archive, values, metrics, errors| {
                vsix::extract_from_archive(archive, values, ctx.strings, metrics, errors);
            },
        ),
        // CRX is a ZIP with a signed header prepended: walk the ZIP, then
        // decode the header for the public key and derived extension id.
        FileType::Crx => crx::extract(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
        ),
        FileType::Asar => asar::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        FileType::Phar => phar::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        FileType::Cpio => cpio::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        // The OOXML-specific `office.*` layer, then macros decompressed from
        // any `vbaProject.bin` member so `office.vba.modules[]` is populated
        // for OOXML, mirroring the OleDoc arm. A macro-free doc leaves it
        // unset; a project that is present but broken is recorded in
        // `errors`.
        FileType::Ooxml => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            |archive, values, metrics, errors| {
                ooxml::extract_from_archive(archive, values, metrics, errors);
                vba::extract_from_zip(archive, values, metrics, ctx.symbols, errors);
            },
        ),
        FileType::OleDoc | FileType::Msi => {
            ole2::extract(bytes, ctx.values, ctx.metrics, ctx.errors)?;
            // VBA module source-text extraction. A doc without macros just
            // leaves `office.vba.*` unpopulated; a broken project is
            // recorded in `errors`. MSI rarely carries VBA; the call is
            // still cheap and keeps the OLE2 extract path uniform.
            vba::extract(bytes, ctx.values, ctx.metrics, ctx.symbols, ctx.errors);
            Ok(())
        }
        FileType::Jar => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            jar::extract_from_archive,
        ),
        // The XPI-specific signing-shape layer.
        FileType::Xpi => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            xpi::extract_from_archive,
        ),
        // The wheel-specific dist-info / RECORD layer.
        FileType::Whl => zip_package(
            bytes,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
            whl::extract_from_archive,
        ),
        // Plain and Gentoo binpkg tars are uncompressed — walked in full.
        // Gentoo's nested `metadata.tar.*`/`image.tar.*` identity isn't cheap
        // to reach, so it stops at the member listing for now.
        FileType::Tar
        | FileType::TarGz
        | FileType::TarBz2
        | FileType::TarXz
        | FileType::TarZst
        | FileType::GentooBinpkg => tar::extract(
            bytes,
            file_type,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
        ),
        // 7z's header holds the member table even when its payload streams
        // are encrypted. Keep this metadata-only, matching the ZIP/TAR
        // extractors: cleave owns any recursive extraction.
        FileType::SevenZ => sevenz::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        // Compressed-tar packages (Alpine apk, FreeBSD/Arch pkg, Void xbps):
        // same handling as the other compressed-tar variants — format label
        // only; cleave decompresses and re-submits the members. Void's
        // `props.plist` identity needs a plist parse, deferred for now.
        // An Alpine package is concatenated gzip streams, not a plain
        // `.tar.gz`, so the generic tar walk declines it. Read the control
        // segment for the apk.* publisher identity the way npm/crate/gem read
        // theirs; cleave still decompresses and re-submits the members.
        FileType::ApkAlpine => {
            apk_alpine::extract(bytes, ctx.values, ctx.metrics);
            Ok(())
        }
        FileType::PkgFreebsd | FileType::PkgArch | FileType::Xbps => tar::extract(
            bytes,
            file_type,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
        ),
        // A Python sdist is a gzip tar: read `<root>/PKG-INFO` for the
        // python.* publisher identity, then list members (format label only).
        FileType::PythonSdist => python_sdist::extract(
            bytes,
            file_type,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
        ),
        // An OCI/Docker image is an uncompressed tar: walk it for the member
        // listing, then read the image manifest for the oci.* identity facts.
        FileType::OciImage => {
            tar::extract(
                bytes,
                file_type,
                ctx.values,
                ctx.metrics,
                ctx.archive_members,
            )?;
            oci::extract(bytes, ctx.values, ctx.metrics, ctx.errors);
            Ok(())
        }
        // A Rust `.crate` is a gzipped tar: walk it, then read the embedded
        // `Cargo.toml` for the crate.* publisher identity.
        FileType::Crate => rust_crate::extract(
            bytes,
            file_type,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
        ),
        // An npm package is a gzipped tar: walk it for the member listing,
        // then read `package/package.json` for the npm.* publisher identity.
        FileType::Npm => npm::extract(
            bytes,
            file_type,
            ctx.values,
            ctx.metrics,
            ctx.archive_members,
            ctx.errors,
        ),
        // A gem is an uncompressed `ustar` tar. Walk it for the generic
        // archive.* surface, then read the gzipped metadata member for the
        // gem.* identity facts (name/version/deps live only in `metadata.gz`).
        FileType::Gem => {
            tar::extract(
                bytes,
                file_type,
                ctx.values,
                ctx.metrics,
                ctx.archive_members,
            )?;
            gem::extract(bytes, ctx.values, ctx.metrics, ctx.errors);
            Ok(())
        }
        // Structured manifests parse their entire content into `values`
        // with the format-native key shape (the parsed JSON/YAML/TOML
        // tree, verbatim).
        FileType::PackageLockJson
        | FileType::ChromeManifest
        | FileType::PipfileLock
        | FileType::ComposerLock => structured::extract_json(bytes, ctx.values),
        FileType::ComposerJson => structured::extract_composer_json(bytes, ctx.values),
        // A bare package.json: the verbatim JSON tree, plus the same
        // npm.* identity layer the tarball path emits.
        FileType::PackageJson => {
            structured::extract_json(bytes, ctx.values)?;
            if let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(bytes) {
                npm::emit(&manifest, ctx.values, ctx.metrics);
            }
            Ok(())
        }
        FileType::Json => structured::extract_generic_json(bytes, ctx.values, ctx.metrics),
        // gyp is Python-literal syntax: JSON in the common case, but real (and
        // hostile) manifests use trailing commas, `#` comments, single quotes,
        // and byte escapes that strict JSON rejects. extract_gyp parses JSON
        // first, then falls back to a tolerant Python-literal parse so value
        // paths like targets[*].sources[*] and a byte-escaped target `type`
        // still resolve instead of vanishing into a text/raw scan.
        FileType::Gyp => structured::extract_gyp(bytes, ctx.values, ctx.metrics),
        FileType::VsixManifest => {
            vsix::extract(bytes, ctx.values, ctx.strings, ctx.metrics, ctx.errors);
            Ok(())
        }
        FileType::CargoToml => {
            structured::extract_toml(bytes, ctx.values)?;
            let mode = match ctx.values.get("package.build") {
                Some(serde_json::Value::Bool(false)) => "disabled",
                Some(serde_json::Value::String(_)) => "custom",
                _ => "implicit",
            };
            ctx.values
                .insert_key(value_key!("cargo.build_mode"), serde_json::json!(mode));
            Ok(())
        }
        FileType::CargoLock | FileType::PoetryLock | FileType::PyProjectToml => {
            structured::extract_toml(bytes, ctx.values)
        }
        FileType::GithubActions | FileType::PnpmLock | FileType::Yaml => {
            structured::extract_yaml(bytes, ctx.values)
        }
        FileType::Plist => {
            structured::extract_plist(bytes, ctx.values)?;
            structured::plist_entitlement_metrics(ctx.values, ctx.metrics);
            Ok(())
        }
        FileType::Nib => nib::extract(bytes, ctx.values, ctx.strings, ctx.metrics),
        FileType::Pbxproj => pbxproj::extract(bytes, ctx.values, ctx.strings, ctx.metrics),
        FileType::PkgInfo => structured::extract_pkginfo(bytes, ctx.values),
        FileType::SrcInfo => pkgmeta::extract_srcinfo(bytes, ctx.values),
        FileType::Registry => registry::extract(bytes, ctx.values, ctx.metrics),
        // A Windows registry export is a text script, not package metadata:
        // `text.*` metrics for the UTF-8 spellings, and the shared string scan
        // below for every encoding (`regedit` writes UTF-16LE).
        FileType::Reg => {
            source::extract_text_only(bytes, ctx.metrics);
            Ok(())
        }
        FileType::Chm => {
            chm::extract(bytes, ctx.values, ctx.strings, ctx.metrics, ctx.image_end);
            Ok(())
        }
        FileType::JavaClass => {
            class::extract(bytes, ctx.values, ctx.strings, ctx.metrics, ctx.symbols);
            Ok(())
        }
        FileType::Jpeg => {
            jpeg::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        FileType::Lnk => {
            lnk::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        FileType::Shellcode => {
            shellcode::extract(bytes, ctx.values, ctx.metrics);
            Ok(())
        }
        FileType::Pdf => {
            pdf::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        FileType::Pickle => {
            pickle::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        FileType::Font => {
            font::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        // Media containers: walk the structure, then let carrier::emit turn
        // the coverage into the shared `media.*` facts. Strings are extracted
        // for all of them, which is also what enrols them in cleave's
        // encoded-payload decode pipeline.
        FileType::Wav | FileType::Webp => {
            media_container(
                bytes,
                ctx.values,
                ctx.strings,
                ctx.metrics,
                containers::riff,
            );
            Ok(())
        }
        FileType::Aiff => {
            media_container(bytes, ctx.values, ctx.strings, ctx.metrics, containers::iff);
            Ok(())
        }
        FileType::Mp3 => {
            media_container(bytes, ctx.values, ctx.strings, ctx.metrics, containers::mp3);
            Ok(())
        }
        FileType::Mp4 | FileType::Avif => {
            media_container(
                bytes,
                ctx.values,
                ctx.strings,
                ctx.metrics,
                containers::iso_bmff,
            );
            Ok(())
        }
        FileType::Ico => {
            media_container(bytes, ctx.values, ctx.strings, ctx.metrics, containers::ico);
            Ok(())
        }
        FileType::Gif => {
            media_container(bytes, ctx.values, ctx.strings, ctx.metrics, containers::gif);
            Ok(())
        }
        FileType::Bmp => {
            media_container(bytes, ctx.values, ctx.strings, ctx.metrics, containers::bmp);
            Ok(())
        }
        // SVG is XML text, so its strings come from the shared text fallback
        // below rather than a binary scan; only the container coverage is
        // added here.
        FileType::Svg => {
            carrier::emit(bytes, &containers::svg(bytes), ctx.values, ctx.metrics);
            Ok(())
        }
        FileType::Png => {
            png::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        FileType::PythonBytecode => {
            pyc::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }
        FileType::Rpm => rpm::extract(bytes, ctx.values, ctx.strings, ctx.metrics, ctx.errors),
        FileType::Deb => deb::extract(bytes, ctx.values, ctx.metrics, ctx.errors),
        FileType::Dmg => dmg::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members),
        FileType::Iso => {
            iso::extract(bytes, ctx.values, ctx.metrics, ctx.archive_members);
            Ok(())
        }
        FileType::Rtf => {
            rtf::extract(bytes, ctx.values, ctx.strings, ctx.metrics);
            Ok(())
        }

        // Source-code extraction is delegated to the source dispatcher,
        // which routes to the appropriate tree-sitter grammar. Languages
        // filefacts doesn't yet support fall through to `extract_text_only`
        // below so they still get language-agnostic `text.*` metrics.
        FileType::JavaScript
        | FileType::TypeScript
        | FileType::Python
        | FileType::Go
        | FileType::Rust
        | FileType::Java
        | FileType::Php
        | FileType::Ruby
        | FileType::Lua
        | FileType::CSharp
        | FileType::C
        | FileType::Scala
        | FileType::ObjectiveC
        | FileType::Kotlin
        | FileType::Swift
        | FileType::PowerShell
        | FileType::Perl
        | FileType::Groovy
        | FileType::Zig
        | FileType::Elixir
        | FileType::Clojure
        | FileType::Batch
        | FileType::Makefile => source::extract(
            bytes,
            file_type,
            tree_cache,
            ctx.values,
            ctx.strings,
            ctx.metrics,
            ctx.symbols,
        ),

        // Shell gets the normal source/AST extraction; a PKGBUILD additionally
        // gets its package-metadata fields lifted into a pkg.* value tree so it
        // can be compared field-for-field against a sibling .SRCINFO.
        FileType::Shell => {
            let r = source::extract(
                bytes,
                file_type,
                tree_cache,
                ctx.values,
                ctx.strings,
                ctx.metrics,
                ctx.symbols,
            );
            if ctx.basename == Some("PKGBUILD") {
                pkgmeta::extract_pkgbuild(bytes, ctx.values, ctx.errors);
            }
            r
        }

        // Text-like languages without a tree-sitter binding in filefacts.
        // They still earn `text.*` metrics — pure byte/line analysis,
        // no AST required.
        FileType::Vbs | FileType::Jcl => {
            source::extract_text_only(bytes, ctx.metrics);
            Ok(())
        }

        // Markdown: extract identity-signal facts (first heading, GitHub
        // refs) for supply-chain impersonation detection. Plain text
        // metrics get layered on top.
        FileType::Markdown => {
            source::extract_text_only(bytes, ctx.metrics);
            markdown::extract(bytes, ctx.values, ctx.metrics);
            Ok(())
        }

        FileType::Data => {
            ani::extract(bytes, ctx.values, ctx.metrics);
            if let Some(table) = crate::fileid::image4_trustcache::parse(bytes) {
                let entries: Vec<_> = table
                    .entries
                    .as_chunks::<24>()
                    .0
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "cdhash": common::hex_encode(&entry[..20]),
                            "hash_type": entry[20], "flags": entry[21],
                            "constraint_category": entry[22], "reserved": entry[23]
                        })
                    })
                    .collect();
                ctx.values.insert_key(
                    value_key!("image4.trustcache"),
                    serde_json::json!({
                        "payload_type": "trca", "description": table.description,
                        "version": 2, "uuid": common::hex_encode(table.uuid),
                        "entry_count": entries.len(), "entries": entries
                    }),
                );
            }
            Ok(())
        }
        FileType::DesktopEntry => {
            desktop_entry::extract(bytes, ctx.values);
            Ok(())
        }
        FileType::SystemdService => {
            systemd::extract(bytes, ctx.values);
            Ok(())
        }
        _ => Ok(()),
    };

    // filefacts is the single string-extraction authority. Binary formats
    // (PE/ELF/Mach-O and friends) already ran the stng scan; source and
    // unsupported text-like files still need a `strings(1)`-tier view, so run
    // the rich stng extraction here when the format handler produced none
    // (source files keep their tree-sitter `literals`/`comments` alongside).
    //
    // Structured manifests are excluded: their whole content is already in the
    // `values` tree, so byte-scanning the same bytes would only duplicate it as
    // noise. (Generic `Json`/`Gyp` are *not* structured-data here — when their
    // size-limited parse is skipped they legitimately fall through to a scan.)
    // Containers whose whole payload is one compressed stream (a plain
    // `.gz`/`.xz`/…, a gzip/xz/zstd tar and the packages built on one) are
    // skipped too: a byte scan of codec output is high-entropy noise at
    // 20-40 ms/MiB on the analyzer's calling thread, and every member is
    // scanned on its own once extracted. Zip-style containers are NOT
    // skipped: stored (uncompressed) entries and the central directory are
    // readable in place, and container-level string findings from them feed
    // the report-wide strip/rescue passes.
    let compressed_stream = matches!(
        file_type,
        FileType::Gz | FileType::Bz2 | FileType::Xz | FileType::Lzma | FileType::Zst
    ) || crate::fileid::container_of(file_type, bytes)
        .is_some_and(|c| c.compression != crate::fileid::Compression::None);
    if !file_type.is_structured_data() && !compressed_stream && ctx.strings.text.is_empty() {
        // This is the fallback path — everything without its own format
        // handler. stng's XOR auto-detect scan is expensive and FP-prone, so it
        // runs only for source/script that shows XOR intent (`^` operator or
        // the `xor` keyword). stng skips it on text of its own accord, so in
        // practice it reaches only a script carrying binary content — a
        // dropper with its payload appended. Such a script must carry its
        // decoder in the same file, so `has_xor_intent` keeps that detection
        // while sparing the chance anchor matches an appended blob invites.
        //
        // Nothing else here gets it. Archive containers are compressed and
        // high-entropy — any real XOR payload lives in a *member*, scanned on
        // its own — and the remaining unknown/text-like bytes have no decoder to
        // pair a payload with. The formats where XOR *is* a live technique
        // (ELF/PE/Mach-O) have their own handlers, which pass
        // [`common::XorScan::Yes`] explicitly.
        let xor = if file_type.is_source_code() && common::has_xor_intent(bytes) {
            common::XorScan::Yes
        } else {
            common::XorScan::No
        };
        common::extract_text_strings(bytes, ctx.strings, xor);
        // A compressed Flash movie (CWS) stores its strings past a zlib
        // stream. The raw bytes are codec noise; the movie is the text.
        if let Some(movie) = inflate_cws(bytes) {
            common::extract_text_strings(&movie, ctx.strings, common::XorScan::No);
        }
    }

    /// Inflate a CWS body. The u32 at offset 4 is the uncompressed movie size,
    /// header included. Refuse anything past a megabyte so a hostile length
    /// cannot expand without bound.
    fn inflate_cws(bytes: &[u8]) -> Option<Vec<u8>> {
        use std::io::Read;
        if !bytes.starts_with(b"CWS") {
            return None;
        }
        let declared = crate::bytes::u32_le(bytes, 4)? as usize;
        if !(8..=1 << 20).contains(&declared) {
            return None;
        }
        let mut out = Vec::new();
        let mut dec = flate2::read::ZlibDecoder::new(bytes.get(8..)?).take(declared as u64);
        dec.read_to_end(&mut out).ok()?;
        if out.is_empty() { None } else { Some(out) }
    }

    // Cross-format binary attribution derived from the merged symbol
    // view (sanitizer instrumentation, FORTIFY_SOURCE wrappers).
    // Skipped silently when no symbols were collected.
    if !ctx.symbols.is_empty() {
        binary_attribution::emit(ctx.symbols, ctx.values);
    }

    // Interior source identity: a source archive (.tar.gz/.zip release) or a
    // bare plugin PHP that carries no ecosystem manifest, probed for a
    // WordPress plugin header or an autoconf AC_INIT. Self-gates by type,
    // reads only a bounded set of members; the normalizer folds `source.*`
    // in below.
    source_meta::extract(bytes, file_type, ctx.values);

    result
}

#[cfg(test)]
mod generic_yaml_routing_tests {
    #[test]
    fn yaml_type_populates_mapping_and_sequence_values() {
        let mapping = crate::OpenOptions::new()
            .file_type(crate::FileType::Yaml)
            .open(b"tasks:\n  lint:\n    cmds: [go test]\n");
        assert_eq!(
            mapping.values().get("tasks.lint.cmds[0]"),
            Some(&serde_json::json!("go test"))
        );
        let sequence = crate::OpenOptions::new()
            .file_type(crate::FileType::Yaml)
            .open(b"- title: Guide\n  url: guide\n");
        assert_eq!(
            sequence.values().get("root[0].title"),
            Some(&serde_json::json!("Guide"))
        );
    }
}

#[cfg(test)]
mod cws_string_tests {
    use std::io::Write;

    #[test]
    fn inflated_cws_exposes_the_remote_movie_url() {
        let movie = b"http://cdn.example/x\x00ff.swf\x00";
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(movie).unwrap();
        let compressed = enc.finish().unwrap();
        let mut file = b"CWS\x08".to_vec();
        file.extend_from_slice(&((8 + movie.len()) as u32).to_le_bytes());
        file.extend_from_slice(&compressed);
        let opened = crate::open(&file);
        let extracted = opened.extracted();
        let text: Vec<&str> = extracted
            .strings
            .text
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert!(
            text.iter().any(|s| s.contains("http://cdn.example/x")),
            "{text:?}"
        );
        assert!(text.iter().any(|s| s.contains("ff.swf")), "{text:?}");
    }
}
