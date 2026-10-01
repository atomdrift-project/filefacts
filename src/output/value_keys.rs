//! The value-key catalog: every [`Values`](super::Values) path filefacts
//! writes, checked at compile time.
//!
//! Format extractors write `values`, and several passes read them back by
//! path: identity folds the scattered per-format fields into one view,
//! references turns manifest fields into fetchable coordinates, and some
//! extractors consult what an earlier stage emitted. With a plain string on
//! both sides, renaming a key on either side still compiles and silently
//! empties the consumer.
//!
//! [`value_key!`](crate::value_key) closes that gap the way
//! [`metric!`](crate::metric) does for metrics. It resolves a literal against
//! [`VALUE_CATALOG`] at compile time. Writers
//! ([`Values::insert_key`](super::Values::insert_key)) and readers
//! ([`Values::get_key`](super::Values::get_key)) both take the resulting
//! [`ValueKey`], so both sides are checked against the same list. A key that
//! is not declared below is a build failure at the call site.
//!
//! Every write takes a [`ValueKey`]: `insert_key`, `insert_key_at`, and the
//! format helpers (`put_str` and friends) all require one. A unit test rejects
//! production calls to the unchecked [`Values::insert`](super::Values::insert),
//! so the catalog is the whole set of paths filefacts can name, and downstream
//! validators read it through [`crate::known_values`].
//!
//! When a key's tail is data, such as an array index or a manifest field name,
//! the fixed base is cataloged, and the call site supplies the rest through
//! [`Values::get_key_at`](super::Values::get_key_at) or
//! [`Values::insert_key_at`](super::Values::insert_key_at).
//!
//! Two kinds of path are not listed, because the input names them rather than
//! filefacts:
//!
//! - anything below a cataloged key: the fields of an object or the elements
//!   of an array stored there, and data tails written with `insert_key_at`;
//! - the parsed document of a structured format (JSON, YAML, TOML, plist,
//!   `PKG-INFO`, and the Xcode project file), which is promoted to the values
//!   root verbatim. The keys filefacts adds alongside it, such as
//!   `pbxproj.scripts` or `cargo.build_mode`, are listed.

use serde_json::Value as JsonValue;

use super::metric_keys::str_eq;

/// A [`Values`](super::Values) path that is known to be declared in
/// [`VALUE_CATALOG`].
///
/// The inner string is private, and outside this module the only constructor
/// is [`value_key!`](crate::value_key), so holding a `ValueKey` means the path
/// was checked at compile time. It wraps a `&'static str`, so it is `Copy` and
/// APIs take it by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueKey(&'static str);

impl ValueKey {
    /// The path as it appears in the values tree and in trait rules.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Look this key up in a JSON tree shaped like [`Values`](super::Values),
    /// using the same dot-path rules as [`Values::get`](super::Values::get).
    ///
    /// This is for a values object that has already been serialized into
    /// another fact, where there is no `Values` to call
    /// [`get_key`](super::Values::get_key) on.
    #[must_use]
    pub fn get_in(self, root: &JsonValue) -> Option<&JsonValue> {
        super::values::navigate(root, self.0)
    }
}

impl AsRef<str> for ValueKey {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl std::fmt::Display for ValueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Resolve a literal against [`VALUE_CATALOG`], or fail the build.
///
/// This is an implementation detail of [`value_key!`](crate::value_key). It is
/// public only because an exported macro can only call public items, and it
/// is not part of the supported API. `value_key!` evaluates it in a `const`
/// context, which turns an undeclared key into a compile error. Calling it
/// directly from runtime code would move that panic to runtime and lose the
/// check.
///
/// # Panics
///
/// If `name` is not in [`VALUE_CATALOG`]. Through `value_key!` this is a
/// `const` evaluation failure, reported as a build error at the offending call
/// site. That is the only way this panic is expected to happen.
#[doc(hidden)]
#[must_use]
pub const fn declared_value_key(name: &'static str) -> ValueKey {
    let mut rest = VALUE_CATALOG;
    while let [key, tail @ ..] = rest {
        if str_eq(key, name) {
            return ValueKey(name);
        }
        rest = tail;
    }
    panic!("undeclared value key: add it to VALUE_CATALOG in src/output/value_keys.rs");
}

/// Build a checked [`ValueKey`] from a literal.
///
/// ```ignore
/// values.insert_key(value_key!("pe.signatures"), signatures);
/// let first = values.get_key_at(value_key!("pe.signatures"), "[0]");
/// ```
///
/// The literal must appear in [`VALUE_CATALOG`]. If it does not, the call
/// site fails to compile.
#[macro_export]
macro_rules! value_key {
    ($name:literal) => {{
        const KEY: $crate::ValueKey = $crate::declared_value_key($name);
        KEY
    }};
}

/// Every fixed value key filefacts writes, sorted.
///
/// Keep it sorted, with one key per line: this list is read as a diff far more
/// often than it is read as a list. Each key must be written through
/// [`value_key!`](crate::value_key) somewhere outside a test; a unit test
/// enforces that, so a key whose last writer goes away cannot stay here and
/// keep its readers compiling against nothing.
pub const VALUE_CATALOG: &[&str] = &[
    "android.allow_backup",
    "android.app_class",
    "android.app_label",
    "android.cleartext_traffic",
    "android.compile_sdk",
    "android.components",
    "android.debuggable",
    "android.install_location",
    "android.min_sdk",
    "android.network_security_config",
    "android.package",
    "android.permissions",
    "android.shared_user_id",
    "android.signatures",
    "android.target_sdk",
    "android.version_code",
    "android.version_name",
    "android_xml.values",
    "apk.arch",
    "apk.builddate",
    "apk.builder",
    "apk.commit",
    "apk.datahash",
    "apk.dependencies",
    "apk.description",
    "apk.homepage",
    "apk.license",
    "apk.maintainer",
    "apk.name",
    "apk.origin",
    "apk.packager",
    "apk.provides",
    "apk.signing_keys",
    "apk.version",
    "archive.builder.gnames",
    "archive.builder.unames",
    "archive.comment",
    "archive.compression.methods",
    "archive.container.archive",
    "archive.container.compression",
    "archive.duplicate_member_names",
    "archive.extra_field_tags",
    "archive.format.entry_types",
    "archive.format.kind",
    "archive.members",
    "archive.signing.chrome_webstore_shape",
    "archive.signing.jar_signed_shape",
    "archive.signing.mozilla_extension_shape",
    "archive.timing.mtime_max",
    "archive.timing.mtime_min",
    "archive.timing.mtime_outlier_members",
    "binary.fortify",
    "binary.packer",
    "binary.packer_version",
    "binary.sanitizers",
    "build.toolchain.compiler",
    "build.toolchain.version",
    "cab.compression",
    "cab.header_reserve",
    "cab.limits",
    "cab.next_cabinet",
    "cab.next_disk",
    "cab.prev_cabinet",
    "cab.prev_disk",
    "cab.set_id",
    "cab.set_index",
    "cab.signatures",
    "cab.version",
    "cargo.build_mode",
    "chm.content_sections",
    "chm.entries",
    "chm.features",
    "chm.itsf",
    "chm.lzx",
    "chm.system",
    "class.access_flags",
    "class.class_refs",
    "class.constant_pool_count",
    "class.inner_classes",
    "class.interfaces",
    "class.java_version",
    "class.major_version",
    "class.minor_version",
    "class.signature",
    "class.source_file",
    "class.strings",
    "class.super_class",
    "class.this_class",
    "cpio.complete",
    "cpio.variant",
    "crate.authors",
    "crate.description",
    "crate.homepage",
    "crate.limits",
    "crate.name",
    "crate.repository",
    "crate.version",
    "crx.author",
    "crx.author_email",
    "crx.description",
    "crx.extension_id",
    "crx.homepage",
    "crx.limits",
    "crx.public_key_sha256",
    "crx.version",
    "deb.arch",
    "deb.dependencies",
    "deb.limits",
    "deb.maintainer",
    "deb.name",
    "deb.priority",
    "deb.section",
    "deb.summary",
    "deb.version",
    "dmg.compression.codecs",
    "dmg.filesystem",
    "dmg.format",
    "dmg.image_variant",
    "dmg.partitions",
    "dmg.udif_format",
    "dmg.udif_version",
    "dmg.volume.created_unix",
    "dmg.volume.filesystem",
    "dmg.volume.formatted_by",
    "dmg.volume.last_mounted_version",
    "dmg.volume.modified_unix",
    "dmg.volume.name",
    "elf.abi",
    "elf.abi_version",
    "elf.build_id",
    "elf.class",
    "elf.comment",
    "elf.distro",
    "elf.dt_flags",
    "elf.dt_flags_1",
    "elf.dwarf.comp_dirs",
    "elf.dwarf.languages",
    "elf.dwarf.producers",
    "elf.dwarf.source_files",
    "elf.dynsym_functions",
    "elf.e_flags",
    "elf.e_flags_raw",
    "elf.ehsize",
    "elf.endian",
    "elf.entry",
    "elf.entry_section",
    "elf.fini_array",
    "elf.gcc_command_line",
    "elf.gnu_property",
    "elf.go",
    "elf.hashes.dyn_hash",
    "elf.hashes.export_hash",
    "elf.hashes.imphash",
    "elf.hashes.symhash",
    "elf.ident_pad",
    "elf.ident_version",
    "elf.ifuncs",
    "elf.init_array",
    "elf.interpreter",
    "elf.linker_family",
    "elf.machine",
    "elf.needed",
    "elf.needed_versions",
    "elf.osabi",
    "elf.overlapping_segments",
    "elf.package",
    "elf.pauth_scheme",
    "elf.phentsize",
    "elf.phoff",
    "elf.relocation_kinds",
    "elf.relro",
    "elf.rpath",
    "elf.runpath",
    "elf.sections",
    "elf.segments",
    "elf.shentsize",
    "elf.shoff",
    "elf.shstrndx",
    "elf.soname",
    "elf.stripped_metadata_sections",
    "elf.symbol_kinds.bindings",
    "elf.symbol_kinds.types",
    "elf.symbol_kinds.visibility",
    "elf.syscalls_arch",
    "elf.syscalls_direct",
    "elf.toolchain",
    "elf.toolchain_family",
    "elf.type",
    "elf.verdef",
    "elf.version",
    "elf.x86_isa_level",
    "file.basename",
    "file.stem",
    "font.content_kind",
    "font.features",
    "font.format",
    "font.problems",
    "font.sfnt_version",
    "font.stowaway",
    "font.tables",
    "font.unknown_tables",
    "font.valid",
    "gem.authors",
    "gem.homepage",
    "gem.licenses",
    "gem.name",
    "gem.platform",
    "gem.runtime_dependencies",
    "gem.summary",
    "gem.version",
    "go_manifest.kind",
    "iso.abstract_file",
    "iso.anomalies",
    "iso.application_id",
    "iso.bibliographic_file",
    "iso.boot.bootable",
    "iso.boot.efi",
    "iso.boot.entries",
    "iso.boot.manufacturer",
    "iso.boot.platforms",
    "iso.boot.system_id",
    "iso.builder",
    "iso.builder_source",
    "iso.copyright_file",
    "iso.extensions",
    "iso.file_extensions",
    "iso.files",
    "iso.format",
    "iso.joliet",
    "iso.preparer_id",
    "iso.publisher_id",
    "iso.system_area.kind",
    "iso.system_area.partitions",
    "iso.system_id",
    "iso.udf.domain",
    "iso.udf.file_set_id",
    "iso.udf.implementation_id",
    "iso.udf.logical_volume_id",
    "iso.udf.partition_contents",
    "iso.udf.revision",
    "iso.udf.tree_truncated",
    "iso.udf.volume_set_id",
    "iso.unclaimed",
    "iso.volume_descriptors",
    "iso.volume_id",
    "iso.volume_set_id",
    "jar.class_count",
    "jar.embedded_jar_count",
    "jar.entry_count",
    "jar.features",
    "jar.index_count",
    "jar.manifest",
    "jar.native_lib_count",
    "jar.pom",
    "jar.service_count",
    "jar.signature_block_count",
    "jar.signature_count",
    "jar.versioned_class_count",
    "jpeg.adobe.color_transform",
    "jpeg.comment",
    "jpeg.exif",
    "jpeg.features",
    "json.parse.limit_bytes",
    "json.parse.reason",
    "json.parse.size",
    "json.parse.skipped",
    "lnk.arguments",
    "lnk.arguments_offset",
    "lnk.blocks",
    "lnk.darwin_data",
    "lnk.darwin_data_offset",
    "lnk.description",
    "lnk.description_offset",
    "lnk.environment_target",
    "lnk.environment_target_offset",
    "lnk.header",
    "lnk.icon_environment_target",
    "lnk.icon_environment_target_offset",
    "lnk.icon_location",
    "lnk.icon_location_offset",
    "lnk.known_folder_id",
    "lnk.network",
    "lnk.relative_path",
    "lnk.relative_path_offset",
    "lnk.shim_layer_name",
    "lnk.shim_layer_name_offset",
    "lnk.special_folder_id",
    "lnk.target_path",
    "lnk.target_path_offset",
    "lnk.tracker",
    "lnk.volume",
    "lnk.working_directory",
    "lnk.working_directory_offset",
    "macho.build_version",
    "macho.class_bits",
    "macho.code_signature.cdhash",
    "macho.code_signature.cms",
    "macho.code_signature.cms_size",
    "macho.code_signature.code_limit",
    "macho.code_signature.code_slots",
    "macho.code_signature.der_entitlements_size",
    "macho.code_signature.entitlements",
    "macho.code_signature.entitlements_xml",
    "macho.code_signature.exec_segment_base",
    "macho.code_signature.exec_segment_flags",
    "macho.code_signature.exec_segment_limit",
    "macho.code_signature.flags",
    "macho.code_signature.hash",
    "macho.code_signature.hash_size",
    "macho.code_signature.identifier",
    "macho.code_signature.identifier_offset",
    "macho.code_signature.page_size",
    "macho.code_signature.platform",
    "macho.code_signature.requirements",
    "macho.code_signature.requirements_size",
    "macho.code_signature.special_slots",
    "macho.code_signature.team_id",
    "macho.code_signature.version",
    "macho.code_signature_offset",
    "macho.code_signature_size",
    "macho.cpu_subtype",
    "macho.cpu_type",
    "macho.cpu_type_raw",
    "macho.data_in_code_kinds",
    "macho.dyld_path",
    "macho.endian",
    "macho.entry",
    "macho.entry_section",
    "macho.file_type",
    "macho.file_type_raw",
    "macho.flags",
    "macho.flags_raw",
    "macho.function_starts_count",
    "macho.go",
    "macho.hashes.dylib_hash",
    "macho.hashes.entitlement_hash",
    "macho.hashes.export_hash",
    "macho.hashes.imphash",
    "macho.hashes.symhash",
    "macho.info_plist",
    "macho.install_name",
    "macho.install_name_kind",
    "macho.launchd_plist",
    "macho.libraries",
    "macho.linker_options",
    "macho.load_commands",
    "macho.load_commands_size",
    "macho.load_dylibs",
    "macho.objc",
    "macho.rpaths",
    "macho.segments",
    "macho.slices",
    "macho.source_version",
    "macho.swift_sections",
    "macho.uuid",
    "macho.uuid_offset",
    "macho.wx_segments",
    "markdown.first_heading",
    "markdown.github_repos",
    "markdown.install_extensions",
    "markdown.install_packages",
    "markdown.npm_packages",
    "media.container",
    "media.content_kind",
    "media.problems",
    "media.stowaway",
    "media.valid",
    "nib.actions",
    "nib.archiver",
    "nib.bindings",
    "nib.class_names",
    "nib.classes",
    "nib.format",
    "nib.format_version",
    "nib.modules",
    "nib.outlets",
    "nib.resources",
    "npm.author",
    "npm.description",
    "npm.homepage",
    "npm.limits",
    "npm.maintainers",
    "npm.name",
    "npm.repository.url",
    "npm.scripts.install",
    "npm.scripts.postinstall",
    "npm.scripts.preinstall",
    "npm.version",
    "nupkg.authors",
    "nupkg.description",
    "nupkg.homepage",
    "nupkg.limits",
    "nupkg.name",
    "nupkg.owners",
    "nupkg.repository",
    "nupkg.title",
    "nupkg.version",
    "oci.config.digest",
    "oci.kind",
    "oci.limits",
    "oci.manifest.digest",
    "oci.ref",
    "office.application",
    "office.category",
    "office.company",
    "office.compobj",
    "office.content_status",
    "office.controls",
    "office.created",
    "office.creator",
    "office.custom_ui_onload",
    "office.dangerous_clsids",
    "office.dde_links",
    "office.description",
    "office.document_security",
    "office.embedded",
    "office.external_relationships",
    "office.features",
    "office.hyperlink_base",
    "office.keywords",
    "office.kind",
    "office.last_modified_by",
    "office.last_printed",
    "office.limits",
    "office.macros",
    "office.manager",
    "office.modified",
    "office.msg.attachments",
    "office.names",
    "office.presentation_format",
    "office.revision",
    "office.security_flag",
    "office.sheet_names",
    "office.slide_count",
    "office.streams",
    "office.subject",
    "office.template",
    "office.title",
    "office.vba.modules",
    "pbxproj.archive_version",
    "pbxproj.build_settings",
    "pbxproj.isa",
    "pbxproj.object_version",
    "pbxproj.scripts",
    "pdf.actions",
    "pdf.catalog",
    "pdf.embedded_files",
    "pdf.filter_chains",
    "pdf.form_fields",
    "pdf.header",
    "pdf.info",
    "pdf.javascript",
    "pdf.limits",
    "pdf.shape",
    "pdf.streams",
    "pe.api_hash_profiles",
    "pe.api_hash_resolver_requests",
    "pe.base_relocations",
    "pe.bound_imports",
    "pe.characteristics",
    "pe.characteristics_raw",
    "pe.checked_export_walk_sites",
    "pe.clr.entry_point_token",
    "pe.clr.flags",
    "pe.clr.metadata_version",
    "pe.clr.mvid",
    "pe.clr.runtime_version",
    "pe.clr.streams",
    "pe.coff.dos_header_pe_pointer",
    "pe.coff.symbol_count",
    "pe.coff.symbol_table_offset",
    "pe.data_directories",
    "pe.data_directory_anomalies",
    "pe.data_directory_count",
    "pe.debug.entries",
    "pe.debug.pdb.age",
    "pe.debug.pdb.basename",
    "pe.debug.pdb.guid",
    "pe.debug.pdb.path",
    "pe.debug.pdb.path_offset",
    "pe.debug.pdb.stem",
    "pe.debug.pdb.timestamp",
    "pe.declared_data_directories",
    "pe.delay_imports",
    "pe.dll_characteristics",
    "pe.dll_characteristics_raw",
    "pe.entry_point",
    "pe.entry_section",
    "pe.export_timestamp",
    "pe.file_alignment",
    "pe.go",
    "pe.hashes.imphash",
    "pe.headers_size",
    "pe.image_base",
    "pe.image_hash",
    "pe.image_size",
    "pe.inflated_sections",
    "pe.linker_major_version",
    "pe.linker_minor_version",
    "pe.load_config",
    "pe.machine",
    "pe.machine_id",
    "pe.manifest.assembly_identity.name",
    "pe.manifest.assembly_identity.name_offset",
    "pe.manifest.assembly_identity.version",
    "pe.manifest.assembly_identity.version_offset",
    "pe.manifest.auto_elevate",
    "pe.manifest.auto_elevate_offset",
    "pe.manifest.dependencies",
    "pe.manifest.description",
    "pe.manifest.description_offset",
    "pe.manifest.dpi_aware",
    "pe.manifest.dpi_aware_offset",
    "pe.manifest.dpi_awareness",
    "pe.manifest.dpi_awareness_offset",
    "pe.manifest.long_path_aware",
    "pe.manifest.long_path_aware_offset",
    "pe.manifest.requested_execution_level",
    "pe.manifest.requested_execution_level_offset",
    "pe.manifest.supported_os",
    "pe.manifest.ui_access",
    "pe.manifest.ui_access_offset",
    "pe.misaligned_sections",
    "pe.os_version",
    "pe.overflowing_sections",
    "pe.overlapping_sections",
    "pe.partial_parse",
    "pe.peb_access_sites",
    "pe.resource_timestamp",
    "pe.resource_types",
    "pe.rich.entries",
    "pe.rich.hash",
    "pe.rich.key",
    "pe.section_alignment",
    "pe.signature_integrity",
    "pe.signatures",
    "pe.subsystem",
    "pe.subsystem_raw",
    "pe.subsystem_version",
    "pe.timestamp",
    "pe.tls_callbacks",
    "pe.version.comments",
    "pe.version.comments_offset",
    "pe.version.company",
    "pe.version.company_offset",
    "pe.version.copyright",
    "pe.version.copyright_offset",
    "pe.version.description",
    "pe.version.description_offset",
    "pe.version.file_version",
    "pe.version.file_version_offset",
    "pe.version.flags",
    "pe.version.internal_name",
    "pe.version.internal_name_offset",
    "pe.version.original_filename",
    "pe.version.original_filename_offset",
    "pe.version.os",
    "pe.version.private_build",
    "pe.version.private_build_offset",
    "pe.version.product_name",
    "pe.version.product_name_offset",
    "pe.version.product_version",
    "pe.version.product_version_offset",
    "pe.version.special_build",
    "pe.version.special_build_offset",
    "pe.version.subtype",
    "pe.version.trademarks",
    "pe.version.trademarks_offset",
    "pe.version.type",
    "pickle.dangerous_opcodes",
    "pickle.globals",
    "pickle.modules",
    "pickle.opcodes",
    "pickle.protocol",
    "pkg",
    "pkg.checksums",
    "pkg.source_github_owners",
    "pkg.url_github_owner",
    "png.chunks",
    "png.dimensions",
    "png.features",
    "png.icc_profile_name",
    "png.last_modified",
    "png.text",
    "png.unknown_chunks",
    "pyc.hash",
    "pyc.magic",
    "pyc.python_version",
    "pyc.source_files",
    "pyc.source_size",
    "pyc.timestamp",
    "python.author",
    "python.homepage",
    "python.license",
    "python.maintainer",
    "python.name",
    "python.requires_python",
    "python.summary",
    "python.version",
    "rar.authenticity_info",
    "rar.comment",
    "rar.comment_packed",
    "rar.created_unix",
    "rar.encryption.kdf_count",
    "rar.encryption.rar4_version",
    "rar.encryption.version",
    "rar.end_present",
    "rar.extra_record_types",
    "rar.first_volume",
    "rar.headers_encrypted",
    "rar.limits",
    "rar.locator",
    "rar.locked",
    "rar.members",
    "rar.new_numbering",
    "rar.not_last_volume",
    "rar.ntfs_streams",
    "rar.original_name",
    "rar.quick_open",
    "rar.recovery",
    "rar.services",
    "rar.solid",
    "rar.unpack_version.max",
    "rar.unpack_version.min",
    "rar.version",
    "rar.volume",
    "rar.volume_number",
    "registry.author",
    "registry.deprecated",
    "registry.description",
    "registry.ecosystem",
    "registry.homepage",
    "registry.latest_version",
    "registry.license",
    "registry.name",
    "registry.publisher",
    "registry.publisher_email_domain",
    "registry.repository",
    "registry.repository_commit",
    "registry.title",
    "registry.version",
    "root",
    "rpm.arch",
    "rpm.buildhost",
    "rpm.buildtime",
    "rpm.cookie",
    "rpm.distribution",
    "rpm.epoch",
    "rpm.group",
    "rpm.homepage",
    "rpm.license",
    "rpm.limits",
    "rpm.name",
    "rpm.os",
    "rpm.packager",
    "rpm.payload_compressor",
    "rpm.payload_flags",
    "rpm.payload_format",
    "rpm.platform",
    "rpm.release",
    "rpm.rpmversion",
    "rpm.scriptlets",
    "rpm.signature",
    "rpm.sourcerpm",
    "rpm.summary",
    "rpm.vendor",
    "rpm.version",
    "rtf.charset",
    "rtf.codepage",
    "rtf.deflang",
    "rtf.features",
    "rtf.fields",
    "rtf.info",
    "rtf.objects",
    "rtf.shape",
    "rtf.version",
    "scpt.limits",
    "scpt.version",
    "shellcode.arch",
    "shellcode.getpc",
    "source.autoconf.name",
    "source.autoconf.version",
    "source.execution.module_http",
    "source.go.generate",
    "source.go.generate_incomplete",
    "source.go.global_initializer_count",
    "source.go.init_count",
    "source.go.initialization_events",
    "source.go.initialization_http",
    "source.go.package",
    "source.go.test_entry_candidates",
    "source.language",
    "source.payload_flow.events",
    "source.payload_flow.truncated",
    "source.rust.initializers",
    "source.rust.modules",
    "source.rust.proc_macro",
    "source.wordpress.plugin_name",
    "source.wordpress.slug",
    "source.wordpress.text_domain",
    "source.wordpress.theme_name",
    "source.wordpress.version",
    "vsix.assets",
    "vsix.categories",
    "vsix.dependencies",
    "vsix.description",
    "vsix.display_name",
    "vsix.identity",
    "vsix.limits",
    "vsix.properties",
    "vsix.tags",
    "vsix.target_platform",
    "wasm.exports",
    "wasm.has_start",
    "wasm.import_modules",
    "wasm.imports",
    "wasm.memory.initial",
    "wasm.memory.max",
    "wasm.producers",
    "whl.author",
    "whl.author_email",
    "whl.data_dir",
    "whl.dist_info_dir",
    "whl.distribution",
    "whl.filename.abi_tag",
    "whl.filename.build",
    "whl.filename.name_prefix",
    "whl.filename.platform_tag",
    "whl.filename.python_tag",
    "whl.filename.version",
    "whl.has_data_dir",
    "whl.has_metadata",
    "whl.has_record",
    "whl.has_wheel",
    "whl.homepage",
    "whl.maintainer",
    "whl.maintainer_email",
    "whl.purelib_shape",
    "whl.signing.has_record_jws",
    "whl.signing.has_record_p7s",
    "whl.summary",
    "whl.top_level_packages",
    "whl.version",
    "xor.pe_key",
    "xpi.author",
    "xpi.description",
    "xpi.has_chrome_manifest",
    "xpi.has_install_rdf",
    "xpi.has_web_extension_manifest",
    "xpi.homepage",
    "xpi.legacy_xul_shape",
    "xpi.limits",
    "xpi.name",
    "xpi.signing.schemes",
    "xpi.unsigned_shape",
    "xpi.version",
    "zip.limits",
];

/// Value keys with a data-derived segment that is not a tail, as templates in
/// which each `<name>` stands for a non-empty run of characters other than
/// `.` and `[`.
///
/// This is the values counterpart of [`FAMILIES`](crate::FAMILIES), and it is
/// empty: no extractor writes such a key. Every key is either fixed and listed
/// in [`VALUE_CATALOG`], or a cataloged base followed by a data tail. Where a
/// segment is drawn from a closed set of names, as with the
/// `pe.version.<leaf>_offset` companions or the npm lifecycle hooks, each
/// member is cataloged on its own, so a validator can still reject a
/// misspelled one.
///
/// A family belongs here only when the file supplies a segment that is
/// followed by more path, so no cataloged base covers it. Add its template
/// together with a constructor in this module that builds the key, as
/// `metric_keys` does for metric families.
pub const VALUE_FAMILIES: &[&str] = &[];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::*;

    /// An unsorted or duplicated entry means a merge went wrong.
    #[test]
    fn catalog_is_sorted_and_unique() {
        for pair in VALUE_CATALOG.windows(2) {
            assert!(
                pair[0] < pair[1],
                "VALUE_CATALOG must be sorted and free of duplicates: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// Every entry is a plain dot path with no index or wildcard. A key with a
    /// data-derived tail is cataloged at its base, and the tail is supplied at
    /// the call site.
    #[test]
    fn catalog_entries_are_plain_paths() {
        for key in VALUE_CATALOG {
            assert!(
                key.split('.').all(|seg| !seg.is_empty()
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')),
                "not a plain value path: {key}"
            );
        }
    }

    #[test]
    fn declared_resolves_to_the_literal() {
        assert_eq!(value_key!("pe.signatures").as_str(), "pe.signatures");
        assert_eq!(value_key!("pkg").to_string(), "pkg");
    }

    #[test]
    fn get_in_navigates_like_values() {
        let root = serde_json::json!({"pe": {"signatures": [{"subject": "CN=x"}]}});
        let sigs = value_key!("pe.signatures").get_in(&root);
        assert_eq!(sigs, root.pointer("/pe/signatures"));
        assert!(value_key!("pe.go").get_in(&root).is_none());
    }

    /// Modules that only consume `values`. Every `value_key!` in them is a
    /// read, whatever it is passed to.
    const READER_MODULES: &[&str] = &[
        "src/embedded_sources.rs",
        "src/formats/identity.rs",
        "src/formats/references.rs",
        "src/formats/references/",
        "src/go_package_context.rs",
        "src/package_context.rs",
    ];

    /// Functions and methods that read the key passed directly to them.
    const READ_CALLS: &[&str] = &["get_key", "get_key_at"];

    /// `ValueKey` methods that read when called on a `value_key!(…)`.
    const READ_METHODS: &[&str] = &["get_in"];

    /// Format helpers whose second argument is the key they write. They take a
    /// [`ValueKey`], so the compiler already rejects a string there; the scan
    /// also checks them so that loosening a signature back to `&str` cannot
    /// quietly reopen the gap.
    const KEY_HELPERS: &[&str] = &["put_i64", "put_str", "put_u64"];

    /// Each catalog key must have at least one `value_key!` use that is not a
    /// read. Otherwise a reader can name a key that nothing produces, and the
    /// compile-time check passes against a catalog entry with no writer
    /// behind it.
    ///
    /// The scan works on tokens, not lines. Comments, doc examples, string
    /// contents and `#[cfg(test)]` / `#[test]` items are skipped, and an
    /// invocation split across lines is still found. A use counts as a read
    /// when it is in a reader module, when it is the direct argument of a read
    /// call (`values.get_key(value_key!(…))`), or when a read method is called
    /// on it. Any other use counts as a write: an argument to `insert_key` or
    /// a format helper, or an entry in a writer's key table.
    #[test]
    fn every_catalog_key_is_written_through_value_key() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for module in READER_MODULES {
            assert!(
                root.join(module).exists(),
                "READER_MODULES lists {module}, which no longer exists"
            );
        }
        let mut written = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for (rel, source) in sources() {
            let scan = scan::scan(&source);
            let reader_module = READER_MODULES.iter().any(|m| rel.starts_with(m));
            for found in scan.uses {
                seen.insert(found.key.clone());
                if !reader_module && !found.read {
                    written.insert(found.key);
                }
            }
        }
        let unused: Vec<_> = VALUE_CATALOG
            .iter()
            .filter(|k| !seen.contains(**k))
            .collect();
        assert!(
            unused.is_empty(),
            "catalog keys never used through value_key!: {unused:?}"
        );
        let unwritten: Vec<_> = VALUE_CATALOG
            .iter()
            .filter(|k| !written.contains(**k))
            .collect();
        assert!(
            unwritten.is_empty(),
            "catalog keys that are read but never written through value_key!: {unwritten:?}"
        );
    }

    /// Production code writes `values` only at checked keys, which is what
    /// makes [`VALUE_CATALOG`] the complete list of paths filefacts can emit.
    ///
    /// The scan, which skips comments, strings and test items as above,
    /// rejects two shapes:
    ///
    /// - any call to the unchecked `Values::insert`, as `values.insert(path,
    ///   value)` or `Values::insert(…)`. A receiver is taken for a `Values`
    ///   when it is named `values`, as every one in the crate is today, or
    ///   when the file binds the name to one earlier (`v: &mut Values`,
    ///   `let mut v = Values::new()`). The two arguments tell it from a set's
    ///   `insert`. A variable path counts too, since it is as unchecked as a
    ///   literal;
    /// - a [`KEY_HELPERS`] call whose key is a string literal or a `format!`.
    #[test]
    fn values_are_written_only_through_checked_keys() {
        let mut unchecked = Vec::new();
        for (rel, source) in sources() {
            for write in scan::scan(&source).unchecked_writes {
                unchecked.push(format!("{rel}:{}: {}", write.line, write.call));
            }
        }
        assert!(
            unchecked.is_empty(),
            "values written at an unchecked path; declare the key in VALUE_CATALOG and \
             write it with insert_key / insert_key_at and value_key!:\n{}",
            unchecked.join("\n")
        );
    }

    /// Every `.rs` file under `src/`, as (crate-relative path, contents).
    /// Fails on a `#[cfg(test)] mod name;`, whose out-of-line body the scan
    /// would otherwise read as production code.
    fn sources() -> Vec<(String, String)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&root.join("src"), &mut files);
        files
            .into_iter()
            .map(|file| {
                let rel = file
                    .strip_prefix(root)
                    .expect("under the crate root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = std::fs::read_to_string(&file).expect("readable source");
                let test_modules = scan::scan(&source).out_of_line_test_modules;
                assert!(
                    test_modules.is_empty(),
                    "{rel} declares out-of-line #[cfg(test)] modules {test_modules:?}; \
                     teach this scan to skip them"
                );
                (rel, source)
            })
            .collect()
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("readable source directory")
            .map(|e| e.expect("readable entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn scan_skips_comments_strings_and_test_items() {
        let source = r##"
            // value_key!("comment.line")
            /* value_key!("comment.block") /* nested */ value_key!("comment.nested") */
            /// value_key!("doc.example")
            const S: &str = "value_key!(\"in.string\")";
            const R: &str = r#"value_key!("in.raw") "quoted" "#;
            const Q: char = '"';
            const B: u8 = b'"';
            fn f<'a>(x: &'a str) -> &'a str { x }
            const ATTR: &str = "#[cfg(test)]";
            fn write(values: &mut Values) {
                values.insert_key(
                    value_key!(
                        "split.across.lines"
                    ),
                    json!(1),
                );
                put_str(values, value_key!("helper.write"), "x");
                for (k, v) in [(value_key!("table.write"), 1)] {}
                let _ = values.get_key(value_key!("direct.read"));
                let _ = values.get_key_at(value_key!("suffix.read"), "[0]");
                let _ = value_key!("method.read").get_in(&root);
                let _ = value_key!("label.only").as_str();
                let _ = r#type;
            }
            #[cfg(test)]
            mod tests {
                fn t() { values.insert_key(value_key!("test.write"), json!(1)); }
            }
            #[test]
            fn bare_test() { values.insert_key(value_key!("bare.test"), json!(1)); }
            #[cfg(test)]
            const TEST_ONLY: [ValueKey; 1] = [value_key!("test.const")];
            fn after() { put_str(values, crate::value_key!("after.test"), "y"); }
        "##;
        let scan = scan::scan(source);
        let got: Vec<(&str, bool)> = scan.uses.iter().map(|u| (u.key.as_str(), u.read)).collect();
        assert_eq!(
            got,
            [
                ("split.across.lines", false),
                ("helper.write", false),
                ("table.write", false),
                ("direct.read", true),
                ("suffix.read", true),
                ("method.read", true),
                ("label.only", false),
                ("after.test", false),
            ]
        );
        assert!(scan.out_of_line_test_modules.is_empty());
        let scan = scan::scan("#[cfg(test)]\nmod fixtures;\n");
        assert_eq!(scan.out_of_line_test_modules, ["fixtures"]);
    }

    #[test]
    fn scan_finds_unchecked_writes() {
        let source = r##"
fn write(values: &mut Values, out: &mut Out, map: &mut Map) {
    // values.insert("comment", json!(1));
    let s = "values.insert(\"in.string\", v)";
    values.insert_key(value_key!("checked"), json!(1));
    values.insert_key_at(value_key!("base"), &field, json!(1));
    put_str(values, value_key!("helper"), "x");
    values.insert(FlowOrigin { value: id, bindings });
    map.insert("not.values", 1);
    values.insert("literal", json!(1));
    values
        .insert(&format!("fmt.{x}"), json!(1));
    out.values.insert(key, json!(1));
    Values::insert(&mut values, "ufcs", json!(1));
    put_str(values, "helper.literal", "x");
    put_u64(values, &format!("helper.{x}"), 1);
    put_i64(values, key, 1);
}
fn renamed(v: &mut crate::Values, set: &mut BTreeSet<String>) {
    v.insert("renamed.param", json!(1));
    let mut acc = Values::new();
    acc.insert(&key, json!(1));
    set.insert("not.values".to_string());
}
fn put_str(values: &mut Values, key: ValueKey, s: String) {}
#[cfg(test)]
mod tests {
    fn t(values: &mut Values, m: &mut Values) {
        values.insert("test.literal", json!(1));
        put_str(values, "test.helper", "x");
    }
}
fn later(m: &mut HashMap<&str, u8>) {
    m.insert("not.values", 1);
}
"##;
        let scan = scan::scan(source);
        let got: Vec<(&str, usize)> = scan
            .unchecked_writes
            .iter()
            .map(|w| (w.call.as_str(), w.line))
            .collect();
        assert_eq!(
            got,
            [
                ("values.insert", 10),
                ("values.insert", 12),
                ("values.insert", 13),
                ("Values::insert", 14),
                ("put_str", 15),
                ("put_u64", 16),
                ("v.insert", 20),
                ("acc.insert", 22),
            ]
        );
    }

    /// Family templates are sorted, unique and well formed, and none sits
    /// below a cataloged key, where the catalog already covers it.
    #[test]
    fn families_are_templates_the_catalog_does_not_cover() {
        for pair in VALUE_FAMILIES.windows(2) {
            assert!(
                pair[0] < pair[1],
                "VALUE_FAMILIES must be sorted and free of duplicates: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
        for family in VALUE_FAMILIES {
            let mut placeholders = 0;
            for seg in family.split('.') {
                let mut rest = seg;
                while !rest.is_empty() {
                    if let Some(open) = rest.strip_prefix('<') {
                        let (name, tail) = open.split_once('>').unwrap_or_default();
                        assert!(
                            !name.is_empty()
                                && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                            "malformed placeholder in {family}"
                        );
                        placeholders += 1;
                        rest = tail;
                    } else {
                        let plain = rest.find('<').unwrap_or(rest.len());
                        let (lit, tail) = rest.split_at(plain);
                        assert!(
                            lit.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                            "not a value path template: {family}"
                        );
                        rest = tail;
                    }
                }
                assert!(!seg.is_empty(), "empty segment in {family}");
            }
            assert!(
                placeholders > 0,
                "{family} is fixed; list it in VALUE_CATALOG"
            );
            let covering = VALUE_CATALOG
                .iter()
                .find(|key| family.starts_with(&format!("{key}.")));
            assert!(
                covering.is_none(),
                "{family} sits below the cataloged key {covering:?}"
            );
        }
    }

    /// A small Rust tokenizer, just enough to find `value_key!` invocations
    /// and unchecked `values` writes in real code, and to tell reads from
    /// writes.
    mod scan {
        use std::collections::BTreeSet;

        use super::{KEY_HELPERS, READ_CALLS, READ_METHODS};

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum Tok {
            Ident(String),
            Str(String),
            Punct(char),
        }

        /// One `value_key!("…")` invocation.
        #[derive(Debug)]
        pub(super) struct Use {
            pub(super) key: String,
            pub(super) read: bool,
        }

        /// A write that names its key without the catalog: a
        /// `Values::insert` call, or a key helper given a string.
        #[derive(Debug)]
        pub(super) struct UncheckedWrite {
            /// `values.insert`, `Values::insert`, or the helper's name.
            pub(super) call: String,
            /// 1-based line of the call.
            pub(super) line: usize,
        }

        #[derive(Debug, Default)]
        pub(super) struct Scan {
            pub(super) uses: Vec<Use>,
            pub(super) unchecked_writes: Vec<UncheckedWrite>,
            /// `#[cfg(test)] mod name;` declarations, whose bodies live in
            /// another file this scan would otherwise treat as production.
            pub(super) out_of_line_test_modules: Vec<String>,
        }

        pub(super) fn scan(source: &str) -> Scan {
            let (toks, lines) = tokens(source);
            let mut out = Scan::default();
            // Names a `Values` goes by, from the production code read so far.
            let mut receivers = BTreeSet::from(["values".to_string()]);
            // Open delimiters, each with the identifier that names the call
            // it opens (`get_key` in `values.get_key(`), if any.
            let mut stack: Vec<(char, Option<&str>)> = Vec::new();
            let mut i = 0;
            while let Some(tok) = toks.get(i) {
                if let Some(attr_len) = test_attribute(&toks, i) {
                    let start = i + attr_len;
                    let end = skip_item(&toks, start);
                    if let [Tok::Ident(kw), Tok::Ident(name), Tok::Punct(';')] =
                        toks.get(start..end).unwrap_or_default()
                        && kw == "mod"
                    {
                        out.out_of_line_test_modules.push(name.clone());
                    }
                    i = end;
                    continue;
                }
                match tok {
                    Tok::Ident(name) if name == "value_key" => {
                        if let Some((key, len)) = invocation(&toks, i) {
                            let direct_read = matches!(
                                stack.last(),
                                Some(('(', Some(callee))) if READ_CALLS.contains(callee)
                            );
                            let method_read = toks.get(i + len) == Some(&Tok::Punct('.'))
                                && matches!(
                                    toks.get(i + len + 1),
                                    Some(Tok::Ident(m)) if READ_METHODS.contains(&m.as_str())
                                );
                            out.uses.push(Use {
                                key,
                                read: direct_read || method_read,
                            });
                            i += len;
                            continue;
                        }
                    }
                    Tok::Ident(_) => {
                        if let Some(name) = values_binding(&toks, i) {
                            receivers.insert(name);
                        }
                        if let Some(call) = unchecked_write(&toks, i, &receivers) {
                            out.unchecked_writes.push(UncheckedWrite {
                                call,
                                line: lines.get(i).copied().unwrap_or_default(),
                            });
                        }
                    }
                    Tok::Punct(open @ ('(' | '[' | '{')) => {
                        let callee = match i.checked_sub(1).and_then(|p| toks.get(p)) {
                            Some(Tok::Ident(name)) if *open == '(' => Some(name.as_str()),
                            _ => None,
                        };
                        stack.push((*open, callee));
                    }
                    Tok::Punct(')' | ']' | '}') => {
                        stack.pop();
                    }
                    _ => {}
                }
                i += 1;
            }
            out
        }

        /// `value_key ! <open> "<key>" <close>` at `i`: the key and the
        /// number of tokens the invocation spans.
        fn invocation(toks: &[Tok], i: usize) -> Option<(String, usize)> {
            let [
                Tok::Ident(_),
                Tok::Punct('!'),
                Tok::Punct(open),
                Tok::Str(key),
                Tok::Punct(close),
            ] = toks.get(i..i + 5)?
            else {
                return None;
            };
            matches!((open, close), ('(', ')') | ('[', ']') | ('{', '}')).then(|| (key.clone(), 5))
        }

        /// The name that the `Values` type or constructor at `i` binds:
        /// `name: &mut Values`, `name: Values`, or `name = Values::new()`,
        /// with or without a path before `Values`.
        fn values_binding(toks: &[Tok], i: usize) -> Option<String> {
            if !matches!(toks.get(i), Some(Tok::Ident(t)) if t == "Values") {
                return None;
            }
            let at = |j: usize, back: usize| j.checked_sub(back).and_then(|p| toks.get(p));
            let punct = |tok: Option<&Tok>, c: char| tok == Some(&Tok::Punct(c));
            let mut j = i;
            while punct(at(j, 1), ':')
                && punct(at(j, 2), ':')
                && matches!(at(j, 3), Some(Tok::Ident(_)))
            {
                j -= 3;
            }
            let constructor = punct(toks.get(i + 1), ':')
                && punct(toks.get(i + 2), ':')
                && matches!(toks.get(i + 3), Some(Tok::Ident(f)) if f == "new" || f == "default");
            if constructor {
                return match (at(j, 1), at(j, 2)) {
                    (Some(Tok::Punct('=')), Some(Tok::Ident(name))) => Some(name.clone()),
                    _ => None,
                };
            }
            if matches!(at(j, 1), Some(Tok::Ident(m)) if m == "mut") {
                j -= 1;
            }
            if punct(at(j, 1), '&') {
                j -= 1;
            }
            match (at(j, 1), at(j, 2), at(j, 3)) {
                (Some(Tok::Punct(':')), Some(Tok::Ident(name)), before) if !punct(before, ':') => {
                    Some(name.clone())
                }
                _ => None,
            }
        }

        /// The unchecked write that the identifier at `i` calls, if any:
        /// `insert(path, value)` on one of the `receivers` or as
        /// `Values::insert(…)`, whatever the path, or a [`KEY_HELPERS`] call
        /// whose key is a string.
        fn unchecked_write(toks: &[Tok], i: usize, receivers: &BTreeSet<String>) -> Option<String> {
            let Tok::Ident(name) = toks.get(i)? else {
                return None;
            };
            if toks.get(i + 1) != Some(&Tok::Punct('(')) {
                return None;
            }
            let before = |n: usize| i.checked_sub(n).and_then(|p| toks.get(p));
            let ident =
                |tok: Option<&Tok>, want: &str| matches!(tok, Some(Tok::Ident(n)) if n == want);
            let args = call_args(toks, i + 1);
            if name == "insert" {
                let receiver = match (before(1), before(2)) {
                    (Some(Tok::Punct('.')), Some(Tok::Ident(r))) if receivers.contains(r) => {
                        Some(r)
                    }
                    _ => None,
                };
                // `insert(path, value)`; a set's `insert` takes one argument.
                // A turbofish in the path can only split it further.
                if let Some(receiver) = receiver
                    && args.len() >= 2
                {
                    return Some(format!("{receiver}.insert"));
                }
                let path = before(1) == Some(&Tok::Punct(':'))
                    && before(2) == Some(&Tok::Punct(':'))
                    && ident(before(3), "Values");
                return path.then(|| "Values::insert".to_string());
            }
            let call = KEY_HELPERS.contains(&name.as_str())
                && before(1) != Some(&Tok::Punct('.'))
                && !ident(before(1), "fn");
            (call && args.get(1).is_some_and(|key| is_string_path(key))).then(|| name.clone())
        }

        /// The arguments of the call whose `(` is at `open`, split at its
        /// top-level commas. A trailing comma adds no argument.
        fn call_args(toks: &[Tok], open: usize) -> Vec<&[Tok]> {
            let mut args = Vec::new();
            let mut depth = 0usize;
            let mut start = open + 1;
            for (i, tok) in toks.iter().enumerate().skip(start) {
                match tok {
                    Tok::Punct('(' | '[' | '{') => depth += 1,
                    Tok::Punct(')' | ']' | '}') if depth == 0 => {
                        if i > start {
                            args.push(toks.get(start..i).unwrap_or_default());
                        }
                        break;
                    }
                    Tok::Punct(')' | ']' | '}') => depth -= 1,
                    Tok::Punct(',') if depth == 0 => {
                        args.push(toks.get(start..i).unwrap_or_default());
                        start = i + 1;
                    }
                    _ => {}
                }
            }
            args
        }

        /// A path written as a string: a literal or a `format!`/`concat!`,
        /// possibly borrowed.
        fn is_string_path(arg: &[Tok]) -> bool {
            let mut arg = arg;
            while let [Tok::Punct('&'), rest @ ..] = arg {
                arg = rest;
            }
            match arg {
                [Tok::Str(_), ..] => true,
                [Tok::Ident(mac), Tok::Punct('!'), ..] => mac == "format" || mac == "concat",
                _ => false,
            }
        }

        /// Length of a `#[cfg(test)]` or `#[test]` attribute at `i`.
        fn test_attribute(toks: &[Tok], i: usize) -> Option<usize> {
            let p = |c| Tok::Punct(c);
            let id = |s: &str| Tok::Ident(s.to_string());
            let cfg_test = [
                p('#'),
                p('['),
                id("cfg"),
                p('('),
                id("test"),
                p(')'),
                p(']'),
            ];
            let test = [p('#'), p('['), id("test"), p(']')];
            let rest = toks.get(i..)?;
            if rest.starts_with(&cfg_test) {
                Some(cfg_test.len())
            } else if rest.starts_with(&test) {
                Some(test.len())
            } else {
                None
            }
        }

        /// The index just past the item that starts at `i`: through its first
        /// top-level `;` or its first top-level `{ … }` block. A closing
        /// delimiter at the top level ends the item without being consumed,
        /// since it belongs to the enclosing group (an attributed field or
        /// variant).
        fn skip_item(toks: &[Tok], mut i: usize) -> usize {
            let mut depth = 0usize;
            while let Some(tok) = toks.get(i) {
                match tok {
                    Tok::Punct('{') if depth == 0 => return matching_brace(toks, i),
                    Tok::Punct('(' | '[' | '{') => depth += 1,
                    Tok::Punct(')' | ']' | '}') if depth == 0 => return i,
                    Tok::Punct(')' | ']' | '}') => depth -= 1,
                    Tok::Punct(';') if depth == 0 => return i + 1,
                    _ => {}
                }
                i += 1;
            }
            i
        }

        /// The index just past the `}` matching the `{` at `i`.
        fn matching_brace(toks: &[Tok], mut i: usize) -> usize {
            let mut depth = 0usize;
            while let Some(tok) = toks.get(i) {
                match tok {
                    Tok::Punct('{') => depth += 1,
                    Tok::Punct('}') => {
                        depth -= 1;
                        if depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            i
        }

        /// The tokens of `source`, and the 1-based line each one starts on.
        fn tokens(source: &str) -> (Vec<Tok>, Vec<usize>) {
            let chars: Vec<char> = source.chars().collect();
            let at = |i: usize| chars.get(i).copied();
            let mut out = Vec::new();
            let mut lines = Vec::new();
            let (mut line, mut counted) = (1, 0);
            let mut i = 0;
            while let Some(c) = at(i) {
                let start = i;
                let before = out.len();
                match c {
                    c if c.is_whitespace() => i += 1,
                    '/' if at(i + 1) == Some('/') => {
                        while at(i).is_some_and(|c| c != '\n') {
                            i += 1;
                        }
                    }
                    '/' if at(i + 1) == Some('*') => i = block_comment_end(&chars, i),
                    '"' => {
                        let (text, end) = cooked_string(&chars, i + 1);
                        out.push(Tok::Str(text));
                        i = end;
                    }
                    '\'' => i = quote_end(&chars, i),
                    c if c == '_' || c.is_alphanumeric() => {
                        let start = i;
                        while at(i).is_some_and(|c| c == '_' || c.is_alphanumeric()) {
                            i += 1;
                        }
                        let word: String = chars.get(start..i).unwrap_or_default().iter().collect();
                        match (word.as_str(), at(i)) {
                            ("b" | "c", Some('"')) => {
                                let (text, end) = cooked_string(&chars, i + 1);
                                out.push(Tok::Str(text));
                                i = end;
                            }
                            ("b", Some('\'')) => i = quote_end(&chars, i),
                            ("r" | "br" | "cr", Some('"' | '#')) => {
                                let hashes = chars
                                    .get(i..)
                                    .unwrap_or_default()
                                    .iter()
                                    .take_while(|&&c| c == '#')
                                    .count();
                                if at(i + hashes) == Some('"') {
                                    let (text, end) = raw_string(&chars, i + hashes + 1, hashes);
                                    out.push(Tok::Str(text));
                                    i = end;
                                } else {
                                    // A raw identifier (`r#type`): the name
                                    // lexes on the next pass.
                                    i += hashes;
                                }
                            }
                            _ => out.push(Tok::Ident(word)),
                        }
                    }
                    c => {
                        out.push(Tok::Punct(c));
                        i += 1;
                    }
                }
                if out.len() > before {
                    let skipped = chars.get(counted..start).unwrap_or_default();
                    line += skipped.iter().filter(|&&c| c == '\n').count();
                    counted = start;
                    lines.push(line);
                }
            }
            (out, lines)
        }

        /// The index just past a (possibly nested) block comment at `i`.
        fn block_comment_end(chars: &[char], mut i: usize) -> usize {
            let mut depth = 0usize;
            while let Some(&c) = chars.get(i) {
                let next = chars.get(i + 1).copied();
                if c == '/' && next == Some('*') {
                    depth += 1;
                    i += 2;
                } else if c == '*' && next == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            i
        }

        /// A `"…"` body starting at `i` (just past the opening quote): its
        /// text and the index just past the closing quote.
        fn cooked_string(chars: &[char], mut i: usize) -> (String, usize) {
            let mut text = String::new();
            while let Some(&c) = chars.get(i) {
                match c {
                    '"' => return (text, i + 1),
                    '\\' => {
                        if let Some(&escaped) = chars.get(i + 1) {
                            text.push(escaped);
                        }
                        i += 2;
                    }
                    c => {
                        text.push(c);
                        i += 1;
                    }
                }
            }
            (text, i)
        }

        /// A raw string body starting at `i`, closed by `"` and `hashes` `#`.
        fn raw_string(chars: &[char], mut i: usize, hashes: usize) -> (String, usize) {
            let mut text = String::new();
            while let Some(&c) = chars.get(i) {
                let closes = c == '"' && (1..=hashes).all(|n| chars.get(i + n) == Some(&'#'));
                if closes {
                    return (text, i + 1 + hashes);
                }
                text.push(c);
                i += 1;
            }
            (text, i)
        }

        /// The index just past a char literal at `i`, or just past the quote
        /// when it opens a lifetime or label (whose name lexes next).
        fn quote_end(chars: &[char], i: usize) -> usize {
            match chars.get(i + 1) {
                Some('\\') => {
                    // Escaped char: skip the escaped character, then run to
                    // the closing quote (`'\u{1F600}'` is longer than one).
                    let mut j = i + 3;
                    while chars.get(j).is_some_and(|&c| c != '\'') {
                        j += 1;
                    }
                    j + 1
                }
                Some(_) if chars.get(i + 2) == Some(&'\'') => i + 3,
                _ => i + 1,
            }
        }
    }
}
