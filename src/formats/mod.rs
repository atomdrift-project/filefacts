//! Per-format extractors.
//!
//! Each module here owns the extraction logic for one format family. The
//! contract is the same across all of them: take the source bytes, fill
//! [`Values`], [`Strings`], and [`Metrics`] views with format-conventional
//! keys and values. Extractors must never read from the filesystem and
//! must never panic on malformed input — return [`crate::Error::Malformed`]
//! instead.
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
use crate::output::{Errors, Metrics, Section, Strings, Values};

mod build_toolchain;
mod chm;
mod class;
mod common;
mod elf;
mod generic;
mod goblin_safe;
mod jar;
mod jpeg;
mod lnk;
mod macho;
mod macho_code_signature;
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
mod vba;
pub(crate) mod vba_symbols;
mod vsix;
mod zip;

/// Drive the right extractor for `file_type` and merge its output into
/// the three views. Unsupported types fall through to [`generic::extract`]
/// (which still records `file.size_bytes` and Shannon entropy).
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract(
    file_type: FileType,
    bytes: &[u8],
    tree_cache: Option<&source::TreeCache<'_>>,
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    sections: &mut Vec<Section>,
    imports: &mut crate::Imports,
    exports: &mut crate::Exports,
    functions: &mut crate::Functions,
    errors: &mut Errors,
) -> Result<(), Error> {
    // Only PE / ELF / Mach-O record structured `Errors` today.
    // Other extractors will start populating it as their goblin/zip
    // / CFB calls grow panic-safe wrappers. Suppress the
    // unused-mut warning on the binding until then.
    let _ = &mut *errors;
    // Every file gets the generic byte-level metrics. Format-specific
    // extractors layer on top of (and may shadow with more accurate
    // values) what generic emits.
    generic::extract(bytes, values, strings, metrics);

    match file_type {
        FileType::Pe => pe::extract(
            bytes, values, strings, metrics, sections, imports, exports, functions, errors,
        ),
        FileType::Elf => elf::extract(
            bytes, values, strings, metrics, sections, imports, exports, functions, errors,
        ),
        FileType::MachO => macho::extract(
            bytes, values, strings, metrics, sections, imports, exports, functions, errors,
        ),
        FileType::Zip | FileType::Crx | FileType::Odf => zip::extract(bytes, values, metrics),
        FileType::Ooxml => {
            // The generic archive walk emits `archive.members[]` /
            // `archive.compression.*` first; the OOXML extractor then
            // layers the format-specific `office.*` schema on top
            // (kind, core metadata, application, macro presence, …).
            zip::extract(bytes, values, metrics)?;
            ooxml::extract(bytes, values, metrics)
        }
        FileType::OleDoc => {
            ole2::extract(bytes, values, metrics)?;
            // VBA module source-text extraction (best-effort).
            // `vba::extract` is silent on failure — a doc without
            // macros just leaves `office.vba.*` unpopulated.
            vba::extract(bytes, values, metrics, imports, functions);
            Ok(())
        }
        FileType::Jar => {
            // JAR is a zip — run the generic archive walk for
            // `archive.*` paths, then layer the JAR-specific
            // `jar.manifest.*` / `jar.pom.*` / `jar.features[]`
            // surface on top.
            zip::extract(bytes, values, metrics)?;
            jar::extract(bytes, values, metrics)
        }
        FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst => {
            tar::extract(bytes, file_type, values, metrics)
        }
        // Structured manifests parse their entire content into `values`
        // with the format-native key shape (the parsed JSON/YAML/TOML
        // tree, verbatim).
        FileType::PackageJson
        | FileType::PackageLockJson
        | FileType::ComposerJson
        | FileType::ChromeManifest => structured::extract_json(bytes, values),
        FileType::VsixManifest => vsix::extract(bytes, values, strings, metrics),
        FileType::CargoToml | FileType::PyProjectToml => structured::extract_toml(bytes, values),
        FileType::GithubActions => structured::extract_yaml(bytes, values),
        FileType::Plist => structured::extract_plist(bytes, values),
        FileType::PkgInfo => structured::extract_pkginfo(bytes, values),
        FileType::Chm => chm::extract(bytes, values, strings, metrics),
        FileType::JavaClass => class::extract(bytes, values, strings, metrics, imports, functions),
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
        // expose doesn't yet support fall through to the generic
        // byte-level pass.
        FileType::JavaScript
        | FileType::TypeScript
        | FileType::Python
        | FileType::Go
        | FileType::Rust
        | FileType::Java
        | FileType::Shell
        | FileType::Php => source::extract(
            bytes, file_type, tree_cache, values, strings, metrics, imports, functions,
        ),

        _ => Ok(()),
    }
}
