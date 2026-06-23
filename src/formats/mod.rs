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
//! [`Strings`]: crate::Strings
//! [`Metrics`]: crate::Metrics
//! [`FileType`]: crate::FileType

use crate::error::Error;
use crate::fileid::FileType;
use crate::output::{ArchiveMember, Errors, Metrics, Section, Strings, Symbols, Values};

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
    /// File basename, when known — lets format-agnostic types (e.g. Shell)
    /// dispatch on a recognized filename such as `PKGBUILD`.
    pub(crate) basename: Option<&'a str>,
}

mod asar;
mod binary_attribution;
mod build_toolchain;
mod chm;
mod class;
pub(crate) mod common;
mod crx;
mod deb;
mod dmg;
mod elf;
mod elf_dwarf;
mod elf_dynamic;
mod elf_hashes;
mod gem;
mod generic;
mod go_buildinfo;
mod goblin_safe;
pub(crate) mod identity;
mod image_stats;
mod jar;
mod jpeg;
mod lnk;
mod macho;
mod macho_code_signature;
mod macho_hashes;
mod markdown;
mod npm;
mod nupkg;
mod ole2;
mod ooxml;
mod pdf;
mod pe;
mod pe_authenticode;
mod pe_debug;
mod pe_image_hash;
mod pe_manifest;
mod pe_rich;
mod pe_version_info;
mod pickle;
mod pkgmeta;
mod png;
mod pyc;
pub(crate) mod references;
mod registry;
mod rpm;
mod rtf;
mod rust_crate;
pub(crate) mod source;
mod structured;
mod tar;
mod upx;
mod vba;
pub(crate) mod vba_symbols;
mod vsix;
mod whl;
mod xpi;
mod zip;

/// Drive the right extractor for `file_type` and merge its output into
/// the public views. Unsupported types fall through to [`generic::extract`]
/// (which still records `file.size_bytes` and Shannon entropy).
pub(crate) fn extract(
    file_type: FileType,
    bytes: &[u8],
    tree_cache: Option<&source::TreeCache<'_>>,
    ctx: ExtractCtx<'_>,
) -> Result<(), Error> {
    let ExtractCtx {
        values,
        strings,
        metrics,
        archive_members,
        sections,
        symbols,
        errors,
        basename,
    } = ctx;
    // Every file gets the generic byte-level metrics. Format-specific
    // extractors layer on top of (and may shadow with more accurate
    // values) what generic emits.
    generic::extract(bytes, values, strings, metrics);

    let result = match file_type {
        FileType::Pe => pe::extract(bytes, values, strings, metrics, sections, symbols, errors),
        FileType::Elf => elf::extract(bytes, values, strings, metrics, sections, symbols, errors),
        FileType::MachO => {
            macho::extract(bytes, values, strings, metrics, sections, symbols, errors)
        }
        FileType::Zip
        | FileType::Odf
        | FileType::ApkAndroid
        | FileType::Conda
        | FileType::Egg
        | FileType::Ipa => {
            // Zip-based packages (Android apk, conda, egg, ipa): the generic
            // archive walk surfaces their member listing and the identity
            // manifests inside (PKG-INFO, Info.plist, …).
            zip::extract(bytes, values, metrics, archive_members)
        }
        FileType::Nupkg => {
            // Open the ZIP once: generic archive facts, then the inner
            // `.nuspec` for the nupkg.* NuGet publisher identity.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            nupkg::extract_from_archive(&mut archive, values, metrics)
        }
        FileType::Vsix => {
            // Open the ZIP container once: generic archive facts first,
            // then parse the inner extension.vsixmanifest for the
            // vsix.identity.* publisher/id/version triple.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            vsix::extract_from_archive(&mut archive, values, strings, metrics)
        }
        // CRX is a ZIP with a signed header prepended: walk the ZIP, then
        // decode the header for the public key and derived extension id.
        FileType::Crx => crx::extract(bytes, values, metrics, archive_members),
        FileType::Asar => asar::extract(bytes, values, metrics, archive_members),
        FileType::Ooxml => {
            // Open the ZIP container once: generic archive facts first,
            // then the OOXML-specific `office.*` layer from the same handle.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            ooxml::extract_from_archive(&mut archive, values, metrics)?;
            // Decompress macros from any `vbaProject.bin` member so
            // `office.vba.modules[]` is populated for OOXML, mirroring the
            // OleDoc arm. Best-effort: a macro-free doc leaves it unset.
            vba::extract_from_zip(&mut archive, values, metrics, symbols);
            Ok(())
        }
        FileType::OleDoc => {
            ole2::extract(bytes, values, metrics)?;
            // VBA module source-text extraction (best-effort).
            // `vba::extract` is silent on failure — a doc without
            // macros just leaves `office.vba.*` unpopulated.
            vba::extract(bytes, values, metrics, symbols);
            Ok(())
        }
        FileType::Jar => {
            // Open the ZIP container once: generic archive facts first,
            // then the JAR-specific surface from the same handle.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            jar::extract_from_archive(&mut archive, values, metrics)
        }
        FileType::Xpi => {
            // Open the ZIP container once: generic archive facts first,
            // then the XPI-specific signing-shape layer.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            xpi::extract_from_archive(&mut archive, values, metrics)
        }
        FileType::Whl => {
            // Open the ZIP container once: generic archive facts first,
            // then the wheel-specific dist-info / RECORD layer.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            whl::extract_from_archive(&mut archive, values, metrics)
        }
        FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst => {
            tar::extract(bytes, file_type, values, metrics, archive_members)
        }
        // Compressed-tar packages (Alpine apk, FreeBSD/Arch pkg): same
        // handling as the other compressed-tar variants — format label only;
        // cleave decompresses and re-submits the members.
        FileType::ApkAlpine | FileType::PkgFreebsd | FileType::PkgArch => {
            tar::extract(bytes, file_type, values, metrics, archive_members)
        }
        // A Rust `.crate` is a gzipped tar: walk it, then read the embedded
        // `Cargo.toml` for the crate.* publisher identity.
        FileType::Crate => rust_crate::extract(bytes, file_type, values, metrics, archive_members),
        // An npm package is a gzipped tar: walk it for the member listing,
        // then read `package/package.json` for the npm.* publisher identity.
        FileType::Npm => npm::extract(bytes, file_type, values, metrics, archive_members),
        // A gem is an uncompressed `ustar` tar. Walk it for the generic
        // archive.* surface, then read the gzipped metadata member for the
        // gem.* identity facts (name/version/deps live only in `metadata.gz`).
        FileType::Gem => {
            tar::extract(bytes, file_type, values, metrics, archive_members)?;
            gem::extract(bytes, values, metrics)
        }
        // Structured manifests parse their entire content into `values`
        // with the format-native key shape (the parsed JSON/YAML/TOML
        // tree, verbatim).
        FileType::PackageLockJson
        | FileType::ComposerJson
        | FileType::ChromeManifest
        | FileType::PipfileLock
        | FileType::ComposerLock => structured::extract_json(bytes, values),
        // A bare package.json: the verbatim JSON tree, plus the same
        // npm.* identity layer the tarball path emits.
        FileType::PackageJson => {
            structured::extract_json(bytes, values)?;
            if let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(bytes) {
                npm::emit(&manifest, values);
            }
            Ok(())
        }
        FileType::Json => structured::extract_generic_json(bytes, values, metrics),
        // gyp is JSON-shaped (binding.gyp is plain JSON in the common case); parse
        // it as generic JSON so value paths like targets[*].sources[*] resolve.
        // text/raw matchers still fall back when a .gyp uses comments/quotes.
        FileType::Gyp => structured::extract_generic_json(bytes, values, metrics),
        FileType::VsixManifest => vsix::extract(bytes, values, strings, metrics),
        FileType::CargoToml
        | FileType::CargoLock
        | FileType::PoetryLock
        | FileType::PyProjectToml => structured::extract_toml(bytes, values),
        FileType::GithubActions | FileType::PnpmLock => structured::extract_yaml(bytes, values),
        FileType::Plist => structured::extract_plist(bytes, values),
        FileType::PkgInfo => structured::extract_pkginfo(bytes, values),
        FileType::SrcInfo => pkgmeta::extract_srcinfo(bytes, values),
        FileType::Registry => registry::extract(bytes, values, metrics),
        FileType::Chm => chm::extract(bytes, values, strings, metrics),
        FileType::JavaClass => class::extract(bytes, values, strings, metrics, symbols),
        FileType::Jpeg => jpeg::extract(bytes, values, strings, metrics),
        FileType::Lnk => lnk::extract(bytes, values, strings, metrics),
        FileType::Pdf => pdf::extract(bytes, values, strings, metrics),
        FileType::Pickle => pickle::extract(bytes, values, strings, metrics),
        FileType::Png => png::extract(bytes, values, strings, metrics),
        FileType::PythonBytecode => pyc::extract(bytes, values, strings, metrics),
        FileType::Rpm => rpm::extract(bytes, values, strings, metrics),
        FileType::Deb => deb::extract(bytes, values, metrics),
        FileType::Dmg => dmg::extract(bytes, values, metrics, archive_members),
        FileType::Rtf => rtf::extract(bytes, values, strings, metrics),

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
            bytes, file_type, tree_cache, values, strings, metrics, symbols,
        ),

        // Shell gets the normal source/AST extraction; a PKGBUILD additionally
        // gets its package-metadata fields lifted into a pkg.* value tree so it
        // can be compared field-for-field against a sibling .SRCINFO.
        FileType::Shell => {
            let r = source::extract(
                bytes, file_type, tree_cache, values, strings, metrics, symbols,
            );
            if basename == Some("PKGBUILD") {
                let _ = pkgmeta::extract_pkgbuild(bytes, values);
            }
            r
        }

        // Text-like languages without a tree-sitter binding in filefacts.
        // They still earn `text.*` metrics — pure byte/line analysis,
        // no AST required.
        FileType::Vbs | FileType::Jcl => {
            source::extract_text_only(bytes, metrics);
            Ok(())
        }

        // Markdown: extract identity-signal facts (first heading, GitHub
        // refs) for supply-chain impersonation detection. Plain text
        // metrics get layered on top.
        FileType::Markdown => {
            source::extract_text_only(bytes, metrics);
            markdown::extract(bytes, values, metrics)
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
    if !file_type.is_structured_data() && strings.text.is_empty() {
        // Decide whether to run stng's (expensive, FP-prone) XOR auto-detect
        // scan alongside the always-on printable-run extraction:
        //   * Archive containers — never. Their bytes are compressed/high-entropy;
        //     any real XOR payload lives in a *member*, which is scanned on its
        //     own. Scanning the container only burns cycles and manufactures
        //     speculative-decode false positives.
        //   * Source/script — only when the bytes show XOR intent (`^` operator
        //     or the `xor` keyword). A self-contained script wielding an
        //     XOR-encoded payload must carry its decoder in the same file, so
        //     `has_xor_intent` preserves real detection while skipping the scan
        //     (and its speculative FPs) on the overwhelming majority of benign
        //     source.
        //   * Everything else (binaries, unknown text-like) — full scan; their
        //     decode logic is machine code, not greppable.
        let run_xor = !file_type.is_archive()
            && (!file_type.is_source_code() || common::has_xor_intent(bytes));
        common::extract_text_strings(bytes, strings, run_xor);
    }

    // Cross-format binary attribution derived from the merged symbol
    // view (sanitizer instrumentation, FORTIFY_SOURCE wrappers).
    // Skipped silently when no symbols were collected.
    if !symbols.is_empty() {
        binary_attribution::emit(symbols, values);
    }

    result
}
