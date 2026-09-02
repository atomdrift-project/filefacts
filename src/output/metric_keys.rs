//! The metric catalog: every metric key filefacts is allowed to emit.
//!
//! [`Metrics::insert`](super::Metrics::insert) takes a [`MetricKey`], and
//! there are exactly two ways to build one:
//!
//! - [`metric!`](crate::metric) for a fixed key. It resolves the literal
//!   against [`CATALOG`] *at compile time*, so a key that is not declared
//!   below is a build failure, not a silently-dead metric.
//! - The family constructors at the bottom of this file, for the handful of
//!   keys with a templated segment (a compression method, an AST operator).
//!   Their templates are listed in [`FAMILIES`].
//!
//! Adding a metric therefore means adding a line here, and renaming one means
//! editing a line here — which is the point. The keys are a public contract:
//! cleave's trait rules reference them by name, and a rename that does not
//! show up in this file's diff is a rename that silently stops matching.
//!
//! Downstream consumers enumerate the surface through
//! [`crate::known_metrics`] rather than re-deriving it by scanning source.

use std::borrow::Cow;

/// A metric name that is known to be declared.
///
/// The inner string is private: outside this module the only constructors are
/// [`metric!`](crate::metric) and the family functions below, which is what
/// makes "emitted but undeclared" unrepresentable rather than merely unlikely.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetricKey(Cow<'static, str>);

impl MetricKey {
    /// The key as it appears in the metrics map and in trait rules.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// An unchecked key, for tests that exercise the map itself rather than
    /// any particular metric — ordering, serialisation. Test-only on
    /// purpose: production code being unable to do this is the entire point
    /// of the type.
    #[cfg(test)]
    pub(crate) fn unchecked(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }
}

impl From<MetricKey> for String {
    fn from(k: MetricKey) -> Self {
        k.0.into_owned()
    }
}

impl std::fmt::Display for MetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `str` equality usable from a `const` context.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Resolve a literal against [`CATALOG`], or fail the build.
///
/// Call it through [`metric!`](crate::metric), which forces the `const`
/// context that turns an undeclared key into a compile error. Calling it
/// directly from runtime code would defer the panic to runtime and defeat
/// the whole arrangement.
///
/// # Panics
///
/// If `name` is not in [`CATALOG`]. Through `metric!` this is a `const`
/// evaluation failure — a build error pointing at the offending call site —
/// which is the intended and only expected way to hit it.
#[must_use]
pub const fn declared(name: &'static str) -> MetricKey {
    let mut i = 0;
    while i < CATALOG.len() {
        if str_eq(CATALOG[i], name) {
            return MetricKey(Cow::Borrowed(name));
        }
        i += 1;
    }
    panic!("undeclared metric key: add it to CATALOG in src/output/metric_keys.rs");
}

/// Build a checked [`MetricKey`] from a literal.
///
/// ```ignore
/// metrics.insert(metric!("file.entropy"), scan.overall);
/// ```
///
/// The literal must appear in [`CATALOG`]; if it does not, this fails to
/// compile at the call site.
#[macro_export]
macro_rules! metric {
    ($name:literal) => {{
        const KEY: $crate::MetricKey = $crate::declared($name);
        KEY
    }};
}

/// Every fixed metric key filefacts emits, sorted.
///
/// Keep it sorted and keep one key per line: this list is read as a diff far
/// more often than it is read as a list.
pub const CATALOG: &[&str] = &[
    "archive.comment_size",
    "archive.compressed_size",
    "archive.compression.ratio",
    "archive.crc_collision_count",
    "archive.directory_count",
    "archive.double_extension_count",
    "archive.duplicate_member_count",
    "archive.entry_comment_count",
    "archive.entry_comment_size",
    "archive.executable_count",
    "archive.extra_field_size",
    "archive.file_count",
    "archive.format.regular_count",
    "archive.has_comment",
    "archive.header_size",
    "archive.hidden_file_count",
    "archive.homoglyph_filename_count",
    "archive.max_filename_length",
    "archive.member_count",
    "archive.misplaced_executable_count",
    "archive.nested_archive_count",
    "archive.noise_file_count",
    "archive.path_traversal_count",
    "archive.prefix_bytes",
    "archive.rtlo_filename_count",
    "archive.script_count",
    "archive.security.encrypted_count",
    "archive.security.setgid_count",
    "archive.security.setuid_count",
    "archive.security.sticky_count",
    "archive.security.symlink_count",
    "archive.security.world_writable_count",
    "archive.symlink_escape_count",
    "archive.timing.future_mtime_count",
    "archive.timing.mtime_dominant_count",
    "archive.timing.mtime_dominant_fraction",
    "archive.timing.mtime_outlier_count",
    "archive.timing.mtime_spread_seconds",
    "archive.timing.mtime_unique_count",
    "archive.timing.mtime_unique_ratio",
    "archive.timing.sentinel_mtime_count",
    "archive.trailing_bytes",
    "archive.uncompressed_size",
    "archive.unicode_filename_count",
    "archive.uses_zip64",
    "archive.zip_bomb_ratio",
    "ast.call_count",
    "ast.const_return_function_count",
    "ast.const_return_function_ratio",
    "ast.depth_capped",
    "ast.identity_function_count",
    "ast.infinite_loop_count",
    "ast.max_array_len",
    "ast.max_concat_chain",
    "ast.max_depth",
    "ast.max_numeric_array",
    "ast.max_numeric_seq",
    "ast.member_count",
    "ast.member_depth_max",
    "ast.node_count",
    "ast.self_compare_count",
    "ast.sequence_count",
    "ast.string_return_function_count",
    "ast.string_return_function_ratio",
    "ast.xor_mod_loop_count",
    "binary.avg_basic_blocks",
    "binary.avg_complexity",
    "binary.avg_string_length",
    "binary.basic_blocks",
    "binary.code_entropy",
    "binary.code_to_data_ratio",
    "binary.data_entropy",
    "binary.entropy_variance",
    "binary.has_overlay",
    "binary.high_entropy_string_count",
    "binary.huge_func_count",
    "binary.is_pie",
    "binary.is_stripped",
    "binary.largest_section_ratio",
    "binary.leaf_func_count",
    "binary.max_complexity",
    "binary.max_string_length",
    "binary.overlay_entropy",
    "binary.overlay_ratio",
    "binary.overlay_size",
    "binary.peak_region_bytes",
    "binary.peak_region_entropy",
    "binary.rizin_incomplete",
    "binary.sentence_string_count",
    "binary.sentence_string_ratio",
    "binary.string_count",
    "binary.string_length_stddev",
    "binary.tiny_func_count",
    "binds.count",
    "calls.dynamic_target_count",
    "calls.obfuscated_target_count",
    "chm.control_entry_count",
    "chm.default_topic_missing",
    "chm.html_entry_count",
    "chm.image_entry_count",
    "chm.infotype_count",
    "chm.lzx_compression_ratio",
    "chm.lzx_reset_count",
    "chm.max_user_entry_size",
    "chm.no_compiler_version",
    "chm.script_entry_count",
    "chm.title_topic_mismatch",
    "chm.total_user_entry_size",
    "chm.user_byte_ratio",
    "chm.user_entry_count",
    "class.constant_pool_size",
    "class.external_class_count",
    "class.interface_count",
    "class.major_version",
    "class.method_ref_count",
    "comments.base64",
    "comments.chars",
    "comments.code",
    "comments.count",
    "comments.empty",
    "comments.fixme_count",
    "comments.hack_count",
    "comments.high_entropy",
    "comments.lines",
    "comments.to_code_ratio",
    "comments.todo_count",
    "comments.url_in_comments",
    "comments.xxx_count",
    "consistency.extension_content_mismatch",
    "deb.depends_count",
    "deb.installed_size",
    "dependencies.count",
    "dmg.compression.ratio",
    "dmg.data_fork_bytes",
    "dmg.partition_count",
    "dmg.sector_count",
    "dmg.total_uncompressed_bytes",
    "dmg.volume.block_size",
    "dmg.volume.file_count",
    "dmg.volume.folder_count",
    "dmg.volume.symlink_count",
    "dmg.volume.timezone_skew_seconds",
    "elf.bits",
    "elf.build_id_length",
    "elf.comment_distinct_count",
    "elf.comment_entry_count",
    "elf.compressed_sections_count",
    "elf.debug_section_count",
    "elf.direct_syscall_count",
    "elf.dt_flags_1_raw",
    "elf.dt_needed_abs_path_count",
    "elf.dt_needed_traversal_count",
    "elf.dt_runpath_uses_origin",
    "elf.dt_versym_count",
    "elf.duplicate_section_name_count",
    "elf.dwarf.cu_count",
    "elf.dynrel_count",
    "elf.dynrela_count",
    "elf.dynsym_count",
    "elf.entry",
    "elf.entry_in_last_segment",
    "elf.entry_in_writable_segment",
    "elf.entry_outside_segments",
    "elf.executable_stack",
    "elf.fini_array_count",
    "elf.first_segment_gap",
    "elf.fortify_source_count",
    "elf.has_aarch64_bti",
    "elf.has_aarch64_pac",
    "elf.has_both_hash_tables",
    "elf.has_build_id",
    "elf.has_cet_ibt",
    "elf.has_cet_shstk",
    "elf.has_debuglink",
    "elf.has_direct_loader_dep",
    "elf.has_dt_audit",
    "elf.has_dt_debug",
    "elf.has_dt_depaudit",
    "elf.has_dt_relr",
    "elf.has_dt_textrel",
    "elf.has_eh_frame",
    "elf.has_gnu_hash",
    "elf.has_got",
    "elf.has_indirect_syscall",
    "elf.has_note",
    "elf.has_plt",
    "elf.has_rpath",
    "elf.has_runpath",
    "elf.has_rustc_section",
    "elf.has_symtab",
    "elf.hidden_symbol_count",
    "elf.init_array_count",
    "elf.little_endian",
    "elf.load_segment_max_file_size",
    "elf.load_segment_max_memory_size",
    "elf.multiple_pt_interp",
    "elf.no_gnu_stack",
    "elf.note_count",
    "elf.nx_enabled",
    "elf.parse_failed",
    "elf.parse_panicked",
    "elf.pltreloc_count",
    "elf.preinit_array_count",
    "elf.program_header_count",
    "elf.relacount",
    "elf.rodata_writable",
    "elf.section_header_count_mismatch",
    "elf.section_relocation_group_count",
    "elf.segment_overlap_count",
    "elf.stack_canary",
    "elf.stripped_metadata_section_count",
    "elf.stripped_with_symtab",
    "elf.symtab_count",
    "elf.text_section_writable",
    "elf.wx_segment_count",
    "exports.count",
    "file.entropy",
    "file.size",
    "functions.anonymous",
    "functions.avg_length_lines",
    "functions.avg_name_length",
    "functions.avg_nesting_depth",
    "functions.avg_param_name_length",
    "functions.avg_params",
    "functions.code_ratio",
    "functions.count",
    "functions.density",
    "functions.high_entropy_names",
    "functions.length_stddev",
    "functions.many_params_count",
    "functions.max_length_lines",
    "functions.max_nesting_depth",
    "functions.max_params",
    "functions.min_length_lines",
    "functions.nested",
    "functions.no_params_count",
    "functions.numeric_suffix_names",
    "functions.one_liners",
    "functions.over_100_lines",
    "functions.over_500_lines",
    "functions.single_char_names",
    "functions.single_char_params",
    "gem.dependency_count",
    "gem.development_dependency_count",
    "gem.runtime_dependency_count",
    "gyp.parse_lenient",
    "identifiers.all_lowercase_ratio",
    "identifiers.all_uppercase_ratio",
    "identifiers.avg_entropy",
    "identifiers.avg_length",
    "identifiers.base64_like_names",
    "identifiers.count",
    "identifiers.double_underscore_count",
    "identifiers.has_digit_ratio",
    "identifiers.hex_like_names",
    "identifiers.high_entropy_count",
    "identifiers.high_entropy_ratio",
    "identifiers.keyboard_pattern_names",
    "identifiers.length_stddev",
    "identifiers.max_length",
    "identifiers.min_length",
    "identifiers.numeric_suffix_count",
    "identifiers.repeated_char_names",
    "identifiers.reuse_ratio",
    "identifiers.sequential_names",
    "identifiers.single_char_count",
    "identifiers.single_char_ratio",
    "identifiers.underscore_prefix_count",
    "identifiers.unique",
    "image.b_entropy",
    "image.channels",
    "image.edge_density",
    "image.g_entropy",
    "image.height",
    "image.histogram_flatness",
    "image.pixel_entropy",
    "image.r_entropy",
    "image.width",
    "imports.aliased",
    "imports.count",
    "imports.dynamic",
    "imports.relative",
    "imports.relative_ratio",
    "imports.stdlib_count",
    "imports.stdlib_ratio",
    "imports.third_party_count",
    "imports.third_party_ratio",
    "imports.wildcard",
    "iso.anomaly_count",
    "iso.application_use_nonzero_bytes",
    "iso.associated_file_count",
    "iso.blank_identifier_fields",
    "iso.boot.bootable_entry_count",
    "iso.boot.catalog_lba",
    "iso.boot.entry_count",
    "iso.created_gmt_offset_minutes",
    "iso.created_unix",
    "iso.declared_bytes",
    "iso.dir_count",
    "iso.divergent_name_count",
    "iso.effective_gmt_offset_minutes",
    "iso.effective_unix",
    "iso.executable_file_count",
    "iso.expires_gmt_offset_minutes",
    "iso.expires_unix",
    "iso.file_count",
    "iso.file_structure_version",
    "iso.hidden_file_count",
    "iso.joliet_level",
    "iso.largest_file_bytes",
    "iso.largest_file_ratio",
    "iso.lnk_file_count",
    "iso.logical_block_size",
    "iso.max_depth",
    "iso.missing_bytes",
    "iso.modified_gmt_offset_minutes",
    "iso.modified_unix",
    "iso.path_table_bytes",
    "iso.setuid_file_count",
    "iso.surfaced_file_count",
    "iso.symlink_count",
    "iso.system_area.nonzero_bytes",
    "iso.total_file_bytes",
    "iso.trailing_bytes",
    "iso.udf.dir_count",
    "iso.udf.file_count",
    "iso.udf.logical_block_size",
    "iso.udf.partition_sectors",
    "iso.udf.partition_start_lba",
    "iso.unallocated_bytes",
    "iso.unallocated_ratio",
    "iso.unclaimed_region_count",
    "iso.volume_descriptor_count",
    "iso.volume_sequence_number",
    "iso.volume_set_size",
    "iso.volume_space_sectors",
    "jar.class_count",
    "jar.embedded_jar_count",
    "jar.entry_count",
    "jar.signature_count",
    "jpeg.app_segment_count",
    "jpeg.appended_bytes",
    "jpeg.com_count",
    "jpeg.comment_bytes",
    "jpeg.dht_count",
    "jpeg.dqt_count",
    "jpeg.exif_size",
    "jpeg.maker_note_bytes",
    "jpeg.segment_count",
    "jpeg.soi_count",
    "json.parse_limit_bytes",
    "json.parsed_bytes",
    "lnk.args_leading_spaces",
    "lnk.args_leading_tabs",
    "lnk.args_max_whitespace_run",
    "lnk.args_whitespace_total",
    "lnk.file_size",
    "macho.code_signature_size",
    "macho.data_in_code_count",
    "macho.entry_in_writable_segment",
    "macho.entry_outside_segments",
    "macho.function_starts_count",
    "macho.has_chained_fixups",
    "macho.has_data_const_segment",
    "macho.has_dyld_info_legacy",
    "macho.has_encrypted_section",
    "macho.has_main_command",
    "macho.has_unixthread_command",
    "macho.load_command_count",
    "macho.old_style_entry",
    "macho.pagezero_size",
    "macho.parse_failed",
    "macho.parse_panicked",
    "macho.slice_count",
    "macho.text_segment_writable",
    "macho.uses_legacy_version_min",
    "macho.wx_segment_count",
    "oci.image_count",
    "oci.layer_count",
    "oci.manifest_count",
    "office.control_count",
    "office.custom_ui_onload_count",
    "office.dangerous_clsid_count",
    "office.dde_link_count",
    "office.embedded_count",
    "office.embedded_executable_count",
    "office.external_relationship_count",
    "office.hidden_sheet_count",
    "office.macro_count",
    "office.name_count",
    "office.sheet_count",
    "office.stream_count",
    "office.vba.createobject_count",
    "office.vba.createobject_non_literal_count",
    "office.vba.declare_count",
    "office.vba.declare_non_literal_count",
    "office.vba.distinct_trigger_count",
    "office.vba.getobject_count",
    "office.vba.getobject_non_literal_count",
    "office.vba.identifier_entropy",
    "office.vba.mean_identifier_length",
    "office.vba.module_count",
    "office.vba.trigger_handler_count",
    "office.vba_project_size",
    "office.xlm_sheet_count",
    "parse.error_count",
    "pdf.action_count",
    "pdf.annotation_count",
    "pdf.annotations_per_page",
    "pdf.byte_range_count",
    "pdf.decoded_form_value_max_len",
    "pdf.dict_region_truncated",
    "pdf.duplicate_form_name_count",
    "pdf.duplicate_form_name_rect_count",
    "pdf.duplicate_form_rect_count",
    "pdf.embedded_file_count",
    "pdf.eof_count",
    "pdf.flate_filter_count",
    "pdf.font_count",
    "pdf.form_field_count",
    "pdf.header_count",
    "pdf.hidden_zero_rect_field_count",
    "pdf.javascript_action_count",
    "pdf.javascript_count",
    "pdf.javascript_total_bytes",
    "pdf.jbig2_filter_count",
    "pdf.leading_bytes_before_header",
    "pdf.metadata_count",
    "pdf.object_count",
    "pdf.object_stream_inner_object_count",
    "pdf.objstm_count",
    "pdf.overlap_check_truncated",
    "pdf.overlapping_form_field_pair_count",
    "pdf.page_count",
    "pdf.risky_feature_score",
    "pdf.signature_object_count",
    "pdf.signed_incremental_update_count",
    "pdf.startxref_count",
    "pdf.stream_bad_delimiter_count",
    "pdf.stream_count",
    "pdf.stream_invalid_length_count",
    "pdf.stream_length_mismatch_count",
    "pdf.stream_missing_endstream_count",
    "pdf.stream_missing_length_count",
    "pdf.streams_with_unusual_filter_count",
    "pdf.three_d_object_count",
    "pdf.trailer_count",
    "pdf.trailing_bytes_after_eof",
    "pdf.unreferenced_object_count",
    "pdf.uri_action_count",
    "pdf.uri_actions_per_page",
    "pdf.visible_object_count",
    "pdf.xobject_count",
    "pdf.xref_stream_count",
    "pe.aliased_export_count",
    "pe.api_hash_constant_folded_request_count",
    "pe.api_hash_name_match_count",
    "pe.api_hash_resolver_request_count",
    "pe.base_relocation_block_count",
    "pe.base_relocation_entry_count",
    "pe.bound_import_count",
    "pe.bound_imports_fingerprint",
    "pe.bss_like_section_count",
    "pe.cert_table_size",
    "pe.checked_export_walk_x86_count",
    "pe.checksum",
    "pe.checksum_stripped",
    "pe.checksum_valid",
    "pe.clr.is_32bit_preferred",
    "pe.clr.is_32bit_required",
    "pe.clr.is_il_only",
    "pe.clr.is_native_entrypoint",
    "pe.clr.managed_resource_count",
    "pe.clr.managed_resource_max_entropy",
    "pe.clr.managed_resource_max_size",
    "pe.clr.strong_name_sig_size",
    "pe.clr.strong_name_signed",
    "pe.computed_checksum",
    "pe.custom_byte_hash_loop_x86_count",
    "pe.data_directory_anomaly_count",
    "pe.data_directory_nonzero_rva_zero_size_count",
    "pe.data_directory_zero_rva_nonzero_size_count",
    "pe.declared_data_directory_count",
    "pe.delay_import_count",
    "pe.dos_stub_modified",
    "pe.dos_stub_zeroed",
    "pe.entry_in_header",
    "pe.entry_in_writable_section",
    "pe.entry_outside_sections",
    "pe.export_timestamp",
    "pe.file_alignment",
    "pe.forwarded_export_count",
    "pe.has_cfg",
    "pe.has_manifest",
    "pe.has_overlay",
    "pe.has_safe_seh",
    "pe.has_version_info",
    "pe.icon_count",
    "pe.image_size",
    "pe.misaligned_section_count",
    "pe.overlay_end",
    "pe.overlay_offset",
    "pe.overlay_padding",
    "pe.overlay_size",
    "pe.parse_failed",
    "pe.parse_panicked",
    "pe.partial_parse",
    "pe.peb_access_x64_count",
    "pe.peb_access_x86_count",
    "pe.recovered_exports",
    "pe.recovered_functions",
    "pe.recovered_imports",
    "pe.recovered_sections",
    "pe.reloc_overhang_bytes",
    "pe.reloc_overhang_ratio",
    "pe.resource_count",
    "pe.resource_walk_panicked",
    "pe.rizin_importless_analysis",
    "pe.rizin_importless_function_count",
    "pe.section_count_mismatch",
    "pe.section_overflow_count",
    "pe.section_overlap_count",
    "pe.security_directory_out_of_bounds",
    "pe.signature_expired_days",
    "pe.timestamp",
    "pe.tls_callback_count",
    "pe.version.identity_entropy",
    "pe.version.identity_symbol_ratio",
    "pickle.protocol",
    "png.a_entropy",
    "png.chunk_count",
    "png.chunks_after_iend",
    "png.compression_ratio",
    "png.idat_chunk_count",
    "png.text_chunk_bytes",
    "png.trailing_bytes",
    "png.unknown_chunk_count",
    "pyc.source_file_count",
    "pyc.source_size",
    "pyc.timestamp",
    "references.declared_count",
    "references.unresolved_count",
    "registry.age_days",
    "registry.days_since_previous_release",
    "registry.downloads_recent",
    "registry.downloads_total",
    "registry.file_count",
    "registry.first_published_at",
    "registry.has_install_script",
    "registry.is_deprecated",
    "registry.maintainers",
    "registry.package_age_days",
    "registry.previous_published_at",
    "registry.published_at",
    "registry.publisher_in_maintainers",
    "registry.publisher_verified",
    "registry.rating",
    "registry.rating_count",
    "registry.release_count",
    "registry.releases_24h",
    "registry.releases_48h",
    "registry.security_hold",
    "registry.unpacked_size",
    "registry.version_removed",
    "registry.vulnerability_count",
    "rpm.buildtime",
    "rpm.epoch",
    "rtf.control_word_count",
    "rtf.control_word_density",
    "rtf.group_depth_max",
    "sections.code_size",
    "sections.count",
    "sections.entropy_max",
    "sections.entropy_mean",
    "sections.executable_count",
    "sections.executable_writable_count",
    "sections.name_entropy",
    "sections.nonstandard_count",
    "sections.writable_count",
    "source.ast_unavailable",
    "source.ast_unavailable.parse_cancelled",
    "source.ast_unavailable.parse_failed",
    "source.ast_unavailable.parse_timeout",
    "source.ast_unavailable.tree_sitter_guard",
    "source.ast_walk_panic",
    "source.class_count",
    "source.extract_panic",
    "source.function_count",
    "source.query_limited",
    "strings.avg_entropy",
    "strings.avg_length",
    "strings.base64_candidates",
    "strings.bytes",
    "strings.count",
    "strings.domain_count",
    "strings.email_count",
    "strings.embedded_code_candidates",
    "strings.empty_count",
    "strings.entropy_stddev",
    "strings.hex",
    "strings.high_entropy_count",
    "strings.ip_count",
    "strings.max_length",
    "strings.path_count",
    "strings.shell",
    "strings.sql",
    "strings.unicode_heavy",
    "strings.url_count",
    "strings.url_encoded",
    "strings.very_high_entropy_count",
    "strings.very_long",
    "text.anonymous_function_ratio",
    "text.ascii_art_lines",
    "text.avg_line_length",
    "text.char_entropy",
    "text.digit_ratio",
    "text.dynamic_import_ratio",
    "text.dynamic_string_ratio",
    "text.empty_line_ratio",
    "text.encoded_string_ratio",
    "text.escape_density",
    "text.hex_escape_count",
    "text.identifier_density",
    "text.identifiers_to_functions_ratio",
    "text.import_density",
    "text.imports_to_functions_ratio",
    "text.invisible_chars",
    "text.last_line_length",
    "text.line_length_stddev",
    "text.lines",
    "text.lines_over_1000",
    "text.lines_over_200",
    "text.lines_over_500",
    "text.long_token_count",
    "text.max_line_length",
    "text.max_ws_run",
    "text.mixed_indent",
    "text.non_ascii_ratio",
    "text.non_printable_ratio",
    "text.normalized_function_count",
    "text.normalized_import_count",
    "text.normalized_string_count",
    "text.normalized_unique_identifiers",
    "text.null_byte_count",
    "text.octal_escape_count",
    "text.repeated_char_sequences",
    "text.space_count",
    "text.string_density",
    "text.strings_to_functions_ratio",
    "text.suspicious_comment_ratio",
    "text.suspicious_identifier_ratio",
    "text.suspicious_string_ratio",
    "text.tab_count",
    "text.top_char",
    "text.top_char_null",
    "text.top_char_ratio",
    "text.trailing_whitespace_lines",
    "text.unicode_escape_count",
    "text.unique_chars",
    "text.unusual_whitespace",
    "text.whitespace_ratio",
    "vsix.asset_count",
    "vsix.property_count",
    "wasm.export_count",
    "wasm.import_count",
    "wasm.section_count",
    "whl.native_extension_count",
];

/// Metric keys whose last segment is data rather than a fixed name.
///
/// Each entry is a template; the constructors below are the only way to
/// build one, so the unconstrained part of the surface is exactly this list
/// and no larger. Prefer a fixed key in [`CATALOG`] whenever the set of
/// values is closed — a family is a hole in the check, kept only where the
/// segment genuinely comes from the file being parsed.
pub const FAMILIES: &[&str] = &[
    "archive.compression.method_counts.<method>",
    "archive.format.<entry_type>_count",
    "ast.op.<operator>",
    "ast.op_density.<operator>",
    // Emitted by the follow phase, not by an extractor: what became of the
    // references a file declared, attributed back to the declaring file. The
    // per-ecosystem count is a family because the ecosystem comes from the
    // reference's own PURL type (`pkg:vscode/...` -> `vscode`).
    "references.unresolved_<ecosystem>_count",
    "consistency.extension_content_mismatch.<content>_as_<extension>",
    "dmg.compression.codec_counts.<codec>",
    "source.query_limited.<query>",
    "source.query_limited.<query>.match_limit",
    "source.query_limited.<query>.output_limit",
    "source.query_limited.<query>.timeout",
];

/// `archive.compression.method_counts.<method>` — members per compression method.
#[must_use]
pub fn archive_method_count(method: &str) -> MetricKey {
    MetricKey(Cow::Owned(format!(
        "archive.compression.method_counts.{method}"
    )))
}

/// `archive.format.<entry_type>_count` — members per archive entry type.
#[must_use]
pub fn archive_entry_type_count(entry_type: &str) -> MetricKey {
    MetricKey(Cow::Owned(format!("archive.format.{entry_type}_count")))
}

/// `ast.op.<operator>` — occurrences of one AST operator.
#[must_use]
pub fn ast_op(operator: &str) -> MetricKey {
    MetricKey(Cow::Owned(format!("ast.op.{operator}")))
}

/// `ast.op_density.<operator>` — occurrences per KB of one AST operator.
#[must_use]
pub fn ast_op_density(operator: &str) -> MetricKey {
    MetricKey(Cow::Owned(format!("ast.op_density.{operator}")))
}

/// `consistency.extension_content_mismatch.<content>_as_<extension>` —
/// a file whose detected content class disagrees with its extension class.
#[must_use]
pub fn extension_content_mismatch(content: &str, extension: &str) -> MetricKey {
    MetricKey(Cow::Owned(format!(
        "consistency.extension_content_mismatch.{content}_as_{extension}"
    )))
}

/// `dmg.compression.codec_counts.<codec>` — DMG blocks per compression codec.
#[must_use]
pub fn dmg_codec_count(codec: &str) -> MetricKey {
    MetricKey(Cow::Owned(format!("dmg.compression.codec_counts.{codec}")))
}

/// Which tree-sitter query budget a `source.query_limited.<query>` hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryLimit {
    /// The query ran, but was cut off by one of the budgets below.
    Any,
    /// Hit the match-count ceiling.
    Match,
    /// Hit the output-size ceiling.
    Output,
    /// Hit the wall-clock ceiling.
    Timeout,
}

/// `source.query_limited.<query>[.<budget>]` — a tree-sitter query that hit
/// a budget, so downstream consumers know the facts it feeds are partial.
#[must_use]
pub fn source_query_limited(query: &str, which: QueryLimit) -> MetricKey {
    MetricKey(Cow::Owned(match which {
        QueryLimit::Any => format!("source.query_limited.{query}"),
        QueryLimit::Match => format!("source.query_limited.{query}.match_limit"),
        QueryLimit::Output => format!("source.query_limited.{query}.output_limit"),
        QueryLimit::Timeout => format!("source.query_limited.{query}.timeout"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog is the contract downstream reads; an unsorted or
    /// duplicated entry means a merge went wrong.
    #[test]
    fn catalog_is_sorted_and_unique() {
        for pair in CATALOG.windows(2) {
            assert!(
                pair[0] < pair[1],
                "CATALOG must be sorted and free of duplicates: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// Every declared key is a dotted lowercase path. Catches a stray
    /// description or a copy-paste of a `Values` path.
    #[test]
    fn catalog_entries_are_dotted_paths() {
        for key in CATALOG {
            assert!(
                key.contains('.')
                    && key.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'.'
                        || b == b'_'),
                "not a metric path: {key}"
            );
        }
    }

    #[test]
    fn declared_resolves_to_the_literal() {
        assert_eq!(metric!("file.entropy").as_str(), "file.entropy");
    }

    #[test]
    fn families_build_the_documented_shape() {
        assert_eq!(
            archive_method_count("deflate").as_str(),
            "archive.compression.method_counts.deflate"
        );
        assert_eq!(
            source_query_limited("identifiers", QueryLimit::Output).as_str(),
            "source.query_limited.identifiers.output_limit"
        );
    }
}
