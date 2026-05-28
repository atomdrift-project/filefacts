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
}

mod asar;
mod binary_attribution;
mod build_toolchain;
mod chm;
mod class;
pub(crate) mod common;
mod elf;
mod elf_dwarf;
mod elf_dynamic;
mod elf_hashes;
mod generic;
mod go_buildinfo;
mod goblin_safe;
mod image_stats;
mod jar;
mod jpeg;
mod lnk;
mod macho;
mod macho_code_signature;
mod macho_hashes;
mod markdown;
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
mod png;
mod pyc;
mod rpm;
mod rtf;
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
        FileType::Zip | FileType::Crx | FileType::Odf => {
            zip::extract(bytes, values, metrics, archive_members)
        }
        FileType::Asar => asar::extract(bytes, values, metrics, archive_members),
        FileType::Ooxml => {
            // Open the ZIP container once: generic archive facts first,
            // then the OOXML-specific `office.*` layer from the same handle.
            let mut archive = zip::open_archive(bytes)?;
            zip::extract_from_archive(&mut archive, bytes, values, metrics, archive_members)?;
            ooxml::extract_from_archive(&mut archive, values, metrics)
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
        // Structured manifests parse their entire content into `values`
        // with the format-native key shape (the parsed JSON/YAML/TOML
        // tree, verbatim).
        FileType::PackageJson
        | FileType::PackageLockJson
        | FileType::ComposerJson
        | FileType::ChromeManifest => structured::extract_json(bytes, values),
        FileType::Json => structured::extract_generic_json(bytes, values, metrics),
        FileType::VsixManifest => vsix::extract(bytes, values, strings, metrics),
        FileType::CargoToml | FileType::PyProjectToml => structured::extract_toml(bytes, values),
        FileType::GithubActions => structured::extract_yaml(bytes, values),
        FileType::Plist => structured::extract_plist(bytes, values),
        FileType::PkgInfo => structured::extract_pkginfo(bytes, values),
        FileType::Chm => chm::extract(bytes, values, strings, metrics),
        FileType::JavaClass => class::extract(bytes, values, strings, metrics, symbols),
        FileType::Jpeg => jpeg::extract(bytes, values, strings, metrics),
        FileType::Lnk => lnk::extract(bytes, values, strings, metrics),
        FileType::Pdf => pdf::extract(bytes, values, strings, metrics),
        FileType::Pickle => pickle::extract(bytes, values, strings, metrics),
        FileType::Png => png::extract(bytes, values, strings, metrics),
        FileType::PythonBytecode => pyc::extract(bytes, values, strings, metrics),
        FileType::Rpm => rpm::extract(bytes, values, strings, metrics),
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
        | FileType::Shell
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
        | FileType::Makefile => source::extract(
            bytes, file_type, tree_cache, values, strings, metrics, symbols,
        ),

        // Text-like languages without a tree-sitter binding in filefacts.
        // They still earn `text.*` metrics — pure byte/line analysis,
        // no AST required.
        FileType::Vbs | FileType::Batch | FileType::Clojure => {
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

    // Cross-format binary attribution derived from the merged symbol
    // view (sanitizer instrumentation, FORTIFY_SOURCE wrappers).
    // Skipped silently when no symbols were collected.
    if !symbols.is_empty() {
        binary_attribution::emit(symbols, values);
    }

    result
}
