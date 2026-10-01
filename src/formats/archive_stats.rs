//! The shared `archive.*` aggregates and the `archive.members[]` value.
//!
//! Every archive extractor reports the same family of facts about its member
//! table: how many members of each kind, how big, how they are named, and
//! when they were written. The counting lives here once. An extractor builds
//! each [`ArchiveMember`] once, hands it to [`ArchiveStats::observe`] with its
//! own [`Reading`] of what the typed member leaves open, derives the
//! `archive.members[]` value with [`member_value`], and finally calls
//! [`ArchiveStats::emit`].
//!
//! Formats differ in which aggregates they can honestly report (a CAB has no
//! POSIX modes, an ASAR no timestamps) and in a few definitions, such as
//! whether a symlink counts as a file. Each format states those choices as
//! its list of [`Agg`]s and its [`Reading`]s rather than re-implementing the
//! counts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::metric;
use crate::output::{ArchiveMember, Metrics, Values};

/// Year-2100 ceiling for a believable member timestamp, as Unix seconds. A
/// fixed ceiling needs no wall clock, so it works offline and survives
/// system-clock skew.
const FUTURE_UNIX: i64 = 4_102_444_800;

/// Cap on member paths listed in `archive.timing.mtime_outlier_members`.
const MAX_OUTLIER_PATHS: usize = 16;

/// Which members an aggregate covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Scope {
    /// Every observed member.
    All,
    /// Only the members the format reads as files ([`Reading::file`]).
    Files,
}

/// How `archive.timing.mtime_dominant_*` groups members by timestamp.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Dominance {
    /// Members without a timestamp form a group of their own, so a run of
    /// unstamped members plus one stamped straggler reads as an outlier.
    UntimedGroup,
    /// Only stamped members are grouped; unstamped ones still count toward
    /// the member total the fraction is taken over.
    TimedOnly,
}

/// One shared aggregate a format reports. The metric and value keys each one
/// writes are listed on the variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Agg {
    /// `archive.member_count`.
    MemberCount,
    /// `archive.file_count`: members read as files.
    FileCount,
    /// `archive.directory_count`: members whose entry type is `directory`.
    DirectoryCount,
    /// `archive.uncompressed_size`, saturating.
    UncompressedSize(Scope),
    /// `archive.compressed_size`, saturating.
    CompressedSize,
    /// `archive.compression.ratio`: compressed over uncompressed bytes, when
    /// any member has a size.
    CompressionRatio,
    /// `archive.compression.methods` (values) and
    /// `archive.compression.method_counts.*`. With `always`, the list is
    /// written even when no member names a method.
    Methods {
        /// Write the list even when it is empty.
        always: bool,
    },
    /// `archive.format.entry_types` (values) and `archive.format.<type>_count`.
    EntryTypes,
    /// `archive.security.{setuid,setgid,sticky,world_writable}_count`.
    ModeBits,
    /// `archive.security.symlink_count`.
    SymlinkCount,
    /// `archive.symlink_escape_count`: symlinks whose target is absolute or
    /// climbs with `..`.
    SymlinkEscapes,
    /// `archive.security.encrypted_count`.
    EncryptedCount,
    /// `archive.max_filename_length`, in bytes.
    MaxFilenameLength,
    /// `archive.hidden_file_count`: members read as hidden.
    HiddenFiles,
    /// `archive.path_traversal_count`.
    PathTraversal(Scope),
    /// `archive.{unicode,homoglyph,rtlo}_filename_count` and
    /// `archive.double_extension_count`.
    NameTricks,
    /// `archive.executable_count`: files with an executable extension or
    /// executable mode bits.
    Executables,
    /// `archive.script_count`.
    Scripts,
    /// `archive.nested_archive_count`.
    NestedArchives,
    /// `archive.misplaced_executable_count`.
    MisplacedExecutables,
    /// `archive.noise_file_count`.
    NoiseFiles,
    /// `archive.duplicate_member_count`: members whose path an earlier member
    /// already used.
    DuplicateMembers,
    /// `archive.zip_bomb_ratio`: the largest per-member expansion, when any.
    ZipBombRatio(Scope),
    /// `archive.builder.unames` / `archive.builder.gnames` (values).
    BuilderNames,
    /// `archive.timing.sentinel_mtime_count`: members with no timestamp.
    SentinelMtimes,
    /// `archive.timing.mtime_{min,max}` (values) and
    /// `archive.timing.mtime_{spread_seconds,unique_count}`.
    MtimeRange,
    /// `archive.timing.mtime_unique_ratio`, `future_mtime_count`, and the
    /// `mtime_dominant_*` / `mtime_outlier_*` supply-chain shape.
    MtimeAnomalies(Dominance),
}

/// A format's reading of one member: the parts of the aggregates a typed
/// [`ArchiveMember`] does not settle on its own.
pub(super) struct Reading {
    /// Counts toward `archive.file_count`, and is the only kind of member
    /// the content counts (executable, script, nested archive) look at.
    pub(super) file: bool,
    /// Counts toward `archive.hidden_file_count`.
    pub(super) hidden: bool,
    /// The member's mode bits make it executable whatever its name.
    pub(super) exec_mode: bool,
    /// What the member's name says.
    pub(super) class: FilenameClass,
}

impl Reading {
    /// The default reading: every non-directory is a file, and hidden-ness
    /// and content kind come from the name.
    pub(super) fn of(member: &ArchiveMember) -> Self {
        let class = classify_filename(&member.path);
        Self {
            file: member.entry_type.as_deref() != Some("directory"),
            hidden: class.is_hidden,
            exec_mode: false,
            class,
        }
    }

    /// A member with a synthetic name (a carved region, a boot image). It is
    /// counted as a member, but neither its name nor its kind says anything.
    pub(super) fn opaque() -> Self {
        Self {
            file: false,
            hidden: false,
            exec_mode: false,
            class: FilenameClass::default(),
        }
    }
}

/// Running `archive.*` aggregates over one archive's members.
#[derive(Default)]
pub(super) struct ArchiveStats {
    aggs: &'static [Agg],
    /// Per-member state only some aggregates need.
    keep_seen_paths: bool,
    keep_owner_names: bool,
    keep_timed_paths: bool,
    members: u64,
    files: u64,
    directories: u64,
    size_all: u64,
    size_files: u64,
    compressed: u64,
    methods: BTreeMap<String, u64>,
    entry_types: BTreeMap<String, u64>,
    setuid: u64,
    setgid: u64,
    sticky: u64,
    world_writable: u64,
    symlinks: u64,
    symlink_escapes: u64,
    encrypted: u64,
    max_name: u64,
    hidden: u64,
    traversal_all: u64,
    traversal_files: u64,
    unicode: u64,
    homoglyph: u64,
    double_extension: u64,
    rtlo: u64,
    executables: u64,
    scripts: u64,
    nested: u64,
    misplaced: u64,
    noise: u64,
    seen: BTreeSet<String>,
    duplicates: u64,
    bomb_all: f64,
    bomb_files: f64,
    unames: BTreeSet<String>,
    gnames: BTreeSet<String>,
    /// Each member's timestamp, in observation order.
    times: Vec<Option<i64>>,
    /// Each member's path, aligned with `times`; kept only when an outlier
    /// list can be asked for.
    paths: Vec<String>,
}

impl ArchiveStats {
    /// Aggregates that will report `aggs`. Only what those need is retained
    /// per member.
    pub(super) fn new(aggs: &'static [Agg]) -> Self {
        Self {
            aggs,
            keep_seen_paths: aggs.contains(&Agg::DuplicateMembers),
            keep_owner_names: aggs.contains(&Agg::BuilderNames),
            keep_timed_paths: aggs.iter().any(|a| matches!(a, Agg::MtimeAnomalies(_))),
            ..Self::default()
        }
    }

    /// Fold one member in.
    pub(super) fn observe(&mut self, member: &ArchiveMember, reading: &Reading) {
        let path = member.path.as_str();
        let class = &reading.class;
        let entry_type = member.entry_type.as_deref();
        self.members += 1;
        if entry_type == Some("directory") {
            self.directories += 1;
        }
        if reading.file {
            self.files += 1;
            self.size_files = self.size_files.saturating_add(member.size_bytes);
        }
        self.size_all = self.size_all.saturating_add(member.size_bytes);

        let compressed = member.compression.as_ref().and_then(|c| c.compressed_size);
        self.compressed = self.compressed.saturating_add(compressed.unwrap_or(0));
        if let Some(c) = compressed
            && c > 0
            && member.size_bytes > 0
        {
            let ratio = member.size_bytes as f64 / c as f64;
            if ratio > self.bomb_all {
                self.bomb_all = ratio;
            }
            if reading.file && ratio > self.bomb_files {
                self.bomb_files = ratio;
            }
        }
        if let Some(method) = member
            .compression
            .as_ref()
            .and_then(|c| c.method.as_deref())
        {
            count_key(&mut self.methods, method);
        }
        if let Some(t) = entry_type {
            count_key(&mut self.entry_types, t);
        }

        if let Some(ownership) = &member.ownership {
            if let Some(mode) = ownership.mode_octal {
                self.setuid += u64::from(mode & 0o4000 != 0);
                self.setgid += u64::from(mode & 0o2000 != 0);
                self.sticky += u64::from(mode & 0o1000 != 0);
                self.world_writable += u64::from(mode & 0o002 != 0);
            }
            if self.keep_owner_names {
                if let Some(name) = &ownership.uname {
                    self.unames.insert(name.clone());
                }
                if let Some(name) = &ownership.gname {
                    self.gnames.insert(name.clone());
                }
            }
        }
        if entry_type == Some("symlink") {
            self.symlinks += 1;
            self.symlink_escapes += u64::from(member.linkname.as_deref().is_some_and(|target| {
                target.starts_with('/') || target.split('/').any(|c| c == "..")
            }));
        }
        self.encrypted += u64::from(member.encrypted);

        self.max_name = self.max_name.max(path.len() as u64);
        self.hidden += u64::from(reading.hidden);
        self.traversal_all += u64::from(class.has_path_traversal);
        self.unicode += u64::from(class.is_unicode);
        self.homoglyph += u64::from(class.has_homoglyph);
        self.double_extension += u64::from(class.has_double_extension);
        self.rtlo += u64::from(class.has_rtlo);
        if reading.file {
            self.traversal_files += u64::from(class.has_path_traversal);
            self.executables += u64::from(class.is_executable || reading.exec_mode);
            self.scripts += u64::from(class.is_script);
            self.nested += u64::from(class.is_nested_archive);
            // Only an executable name is ever misplaced.
            self.misplaced += u64::from(class.is_misplaced_executable);
        }
        self.noise += u64::from(is_noise_filename(path));
        if self.keep_seen_paths {
            if self.seen.contains(path) {
                self.duplicates += 1;
            } else {
                self.seen.insert(path.to_owned());
            }
        }

        self.times.push(member.mtime_unix);
        if self.keep_timed_paths {
            self.paths.push(path.to_owned());
        }
    }

    /// Members observed so far.
    pub(super) fn member_count(&self) -> u64 {
        self.members
    }

    /// Summed size of every observed member.
    pub(super) fn uncompressed_size(&self) -> u64 {
        self.size_all
    }

    /// Members observed with no timestamp.
    pub(super) fn untimed(&self) -> u64 {
        self.times.iter().filter(|t| t.is_none()).count() as u64
    }

    /// Write every aggregate the format asked for.
    pub(super) fn emit(&self, values: &mut Values, metrics: &mut Metrics) {
        for agg in self.aggs {
            self.emit_one(*agg, values, metrics);
        }
    }

    fn emit_one(&self, agg: Agg, values: &mut Values, metrics: &mut Metrics) {
        let pick = |scope: Scope, all: u64, files: u64| match scope {
            Scope::All => all,
            Scope::Files => files,
        };
        match agg {
            Agg::MemberCount => {
                metrics.insert(metric!("archive.member_count"), self.members as f64)
            }
            Agg::FileCount => metrics.insert(metric!("archive.file_count"), self.files as f64),
            Agg::DirectoryCount => {
                metrics.insert(metric!("archive.directory_count"), self.directories as f64);
            }
            Agg::UncompressedSize(scope) => metrics.insert(
                metric!("archive.uncompressed_size"),
                pick(scope, self.size_all, self.size_files) as f64,
            ),
            Agg::CompressedSize => {
                metrics.insert(metric!("archive.compressed_size"), self.compressed as f64);
            }
            Agg::CompressionRatio => {
                if self.size_all > 0 {
                    metrics.insert(
                        metric!("archive.compression.ratio"),
                        self.compressed as f64 / self.size_all as f64,
                    );
                }
            }
            Agg::Methods { always } => {
                if always || !self.methods.is_empty() {
                    values.insert("archive.compression.methods", key_list(&self.methods));
                    for (method, count) in &self.methods {
                        metrics.insert(crate::archive_method_count(method), *count as f64);
                    }
                }
            }
            Agg::EntryTypes => {
                values.insert("archive.format.entry_types", key_list(&self.entry_types));
                for (entry_type, count) in &self.entry_types {
                    metrics.insert(
                        crate::archive_entry_type_count(&entry_type.replace('-', "_")),
                        *count as f64,
                    );
                }
            }
            Agg::ModeBits => {
                metrics.insert(metric!("archive.security.setuid_count"), self.setuid as f64);
                metrics.insert(metric!("archive.security.setgid_count"), self.setgid as f64);
                metrics.insert(metric!("archive.security.sticky_count"), self.sticky as f64);
                metrics.insert(
                    metric!("archive.security.world_writable_count"),
                    self.world_writable as f64,
                );
            }
            Agg::SymlinkCount => {
                metrics.insert(
                    metric!("archive.security.symlink_count"),
                    self.symlinks as f64,
                );
            }
            Agg::SymlinkEscapes => metrics.insert(
                metric!("archive.symlink_escape_count"),
                self.symlink_escapes as f64,
            ),
            Agg::EncryptedCount => metrics.insert(
                metric!("archive.security.encrypted_count"),
                self.encrypted as f64,
            ),
            Agg::MaxFilenameLength => {
                metrics.insert(metric!("archive.max_filename_length"), self.max_name as f64);
            }
            Agg::HiddenFiles => {
                metrics.insert(metric!("archive.hidden_file_count"), self.hidden as f64);
            }
            Agg::PathTraversal(scope) => metrics.insert(
                metric!("archive.path_traversal_count"),
                pick(scope, self.traversal_all, self.traversal_files) as f64,
            ),
            Agg::NameTricks => {
                metrics.insert(
                    metric!("archive.unicode_filename_count"),
                    self.unicode as f64,
                );
                metrics.insert(
                    metric!("archive.homoglyph_filename_count"),
                    self.homoglyph as f64,
                );
                metrics.insert(
                    metric!("archive.double_extension_count"),
                    self.double_extension as f64,
                );
                metrics.insert(metric!("archive.rtlo_filename_count"), self.rtlo as f64);
            }
            Agg::Executables => {
                metrics.insert(metric!("archive.executable_count"), self.executables as f64);
            }
            Agg::Scripts => metrics.insert(metric!("archive.script_count"), self.scripts as f64),
            Agg::NestedArchives => {
                metrics.insert(metric!("archive.nested_archive_count"), self.nested as f64);
            }
            Agg::MisplacedExecutables => metrics.insert(
                metric!("archive.misplaced_executable_count"),
                self.misplaced as f64,
            ),
            Agg::NoiseFiles => {
                metrics.insert(metric!("archive.noise_file_count"), self.noise as f64)
            }
            Agg::DuplicateMembers => metrics.insert(
                metric!("archive.duplicate_member_count"),
                self.duplicates as f64,
            ),
            Agg::ZipBombRatio(scope) => {
                let ratio = match scope {
                    Scope::All => self.bomb_all,
                    Scope::Files => self.bomb_files,
                };
                if ratio > 0.0 {
                    metrics.insert(metric!("archive.zip_bomb_ratio"), ratio);
                }
            }
            Agg::BuilderNames => {
                if !self.unames.is_empty() {
                    values.insert("archive.builder.unames", string_list(&self.unames));
                }
                if !self.gnames.is_empty() {
                    values.insert("archive.builder.gnames", string_list(&self.gnames));
                }
            }
            Agg::SentinelMtimes => metrics.insert(
                metric!("archive.timing.sentinel_mtime_count"),
                self.untimed() as f64,
            ),
            Agg::MtimeRange => self.emit_mtime_range(values, metrics),
            Agg::MtimeAnomalies(dominance) => self.emit_mtime_anomalies(dominance, values, metrics),
        }
    }

    fn emit_mtime_range(&self, values: &mut Values, metrics: &mut Metrics) {
        let timed = || self.times.iter().flatten().copied();
        let (Some(min), Some(max)) = (timed().min(), timed().max()) else {
            return;
        };
        values.insert("archive.timing.mtime_min", JsonValue::Number(min.into()));
        values.insert("archive.timing.mtime_max", JsonValue::Number(max.into()));
        // `abs_diff`: a tar's base-256 mtime can span the whole i64 range.
        metrics.insert(
            metric!("archive.timing.mtime_spread_seconds"),
            max.abs_diff(min) as f64,
        );
        let unique: BTreeSet<i64> = timed().collect();
        metrics.insert(
            metric!("archive.timing.mtime_unique_count"),
            unique.len() as f64,
        );
    }

    fn emit_mtime_anomalies(
        &self,
        dominance: Dominance,
        values: &mut Values,
        metrics: &mut Metrics,
    ) {
        let timed: Vec<i64> = self.times.iter().flatten().copied().collect();
        if !timed.is_empty() {
            let unique: BTreeSet<i64> = timed.iter().copied().collect();
            metrics.insert(
                metric!("archive.timing.mtime_unique_ratio"),
                unique.len() as f64 / timed.len() as f64,
            );
        }
        let future = timed.iter().filter(|t| **t > FUTURE_UNIX).count();
        if future > 0 {
            metrics.insert(metric!("archive.timing.future_mtime_count"), future as f64);
        }

        // The timestamp most members share, and every member that strays
        // from it once it covers a strict majority: the "thirteen files at
        // the build sentinel plus one dropped in later" supply-chain shape.
        let total = self.members;
        let dominant = match dominance {
            Dominance::UntimedGroup => dominant(self.times.iter().copied()),
            Dominance::TimedOnly => dominant(timed.iter().copied().map(Some)),
        };
        let Some((stamp, count)) = dominant else {
            return;
        };
        if total == 0 {
            return;
        }
        let fraction = match dominance {
            Dominance::UntimedGroup => count as f64 / total as f64,
            Dominance::TimedOnly => count as f64 / total.max(1) as f64,
        };
        metrics.insert(metric!("archive.timing.mtime_dominant_count"), count as f64);
        metrics.insert(metric!("archive.timing.mtime_dominant_fraction"), fraction);
        if count.saturating_mul(2) <= total || count >= total {
            return;
        }
        metrics.insert(
            metric!("archive.timing.mtime_outlier_count"),
            total.saturating_sub(count) as f64,
        );
        let stamped = self.times.iter().zip(&self.paths);
        let outliers: Vec<JsonValue> = match dominance {
            // Grouped by timestamp, unstamped first, then oldest first.
            Dominance::UntimedGroup => {
                let mut groups: BTreeMap<Option<i64>, Vec<&String>> = BTreeMap::new();
                for (t, path) in stamped {
                    groups.entry(*t).or_default().push(path);
                }
                groups
                    .into_iter()
                    .filter(|(t, _)| *t != stamp)
                    .flat_map(|(_, paths)| paths)
                    .take(MAX_OUTLIER_PATHS)
                    .map(|p| JsonValue::String(p.clone()))
                    .collect()
            }
            // In member order, stamped members only.
            Dominance::TimedOnly => stamped
                .filter(|(t, _)| t.is_some() && **t != stamp)
                .take(MAX_OUTLIER_PATHS)
                .map(|(_, p)| JsonValue::String(p.clone()))
                .collect(),
        };
        if !outliers.is_empty() {
            values.insert(
                "archive.timing.mtime_outlier_members",
                JsonValue::Array(outliers),
            );
        }
    }
}

/// The most common timestamp among `times` and how many members carry it. A
/// tie goes to the later timestamp; unstamped sorts first.
fn dominant(times: impl Iterator<Item = Option<i64>>) -> Option<(Option<i64>, u64)> {
    let mut counts: BTreeMap<Option<i64>, u64> = BTreeMap::new();
    for t in times {
        *counts.entry(t).or_default() += 1;
    }
    counts.into_iter().max_by_key(|(_, count)| *count)
}

/// Bump `key`'s count without allocating when it is already present.
fn count_key(counts: &mut BTreeMap<String, u64>, key: &str) {
    if let Some(n) = counts.get_mut(key) {
        *n += 1;
    } else {
        counts.insert(key.to_owned(), 1);
    }
}

fn key_list(counts: &BTreeMap<String, u64>) -> JsonValue {
    JsonValue::Array(
        counts
            .keys()
            .map(|k| JsonValue::String(k.clone()))
            .collect(),
    )
}

fn string_list(set: &BTreeSet<String>) -> JsonValue {
    JsonValue::Array(set.iter().map(|s| JsonValue::String(s.clone())).collect())
}

/// Which optional groups of a typed member its `archive.members[]` value
/// carries. A format whose published value never had a group keeps it out,
/// so the public shape does not change under it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Shape {
    /// `header_offset`, `data_offset`, `central_header_offset`.
    pub(super) offsets: bool,
    /// `compressed_size`, `compression_method`.
    pub(super) compression: bool,
}

impl Shape {
    /// Every group the typed member has.
    pub(super) const FULL: Self = Self {
        offsets: true,
        compression: true,
    };
}

/// The `archive.members[]` value for one typed member: every populated
/// field under its published key. `encrypted` appears only when set. Formats
/// append their own extra keys to the returned object.
pub(super) fn member_value(m: &ArchiveMember, shape: Shape) -> JsonMap<String, JsonValue> {
    fn put(obj: &mut JsonMap<String, JsonValue>, key: &str, value: Option<impl Into<JsonValue>>) {
        if let Some(v) = value {
            obj.insert(key.into(), v.into());
        }
    }
    let mut obj = JsonMap::new();
    obj.insert("path".into(), JsonValue::String(m.path.clone()));
    obj.insert("size_bytes".into(), m.size_bytes.into());
    put(&mut obj, "entry_type", m.entry_type.clone());
    put(&mut obj, "mtime_unix", m.mtime_unix);
    put(&mut obj, "linkname", m.linkname.clone());
    put(&mut obj, "host_os", m.host_os.clone());
    put(&mut obj, "crc32", m.crc32);
    if m.encrypted {
        obj.insert("encrypted".into(), JsonValue::Bool(true));
    }
    if shape.compression
        && let Some(c) = &m.compression
    {
        put(&mut obj, "compressed_size", c.compressed_size);
        put(&mut obj, "compression_method", c.method.clone());
    }
    if let Some(o) = &m.ownership {
        put(&mut obj, "mode_octal", o.mode_octal);
        put(&mut obj, "uid", o.uid);
        put(&mut obj, "gid", o.gid);
        put(&mut obj, "uname", o.uname.clone());
        put(&mut obj, "gname", o.gname.clone());
    }
    if shape.offsets {
        put(&mut obj, "header_offset", m.offsets.header);
        put(&mut obj, "data_offset", m.offsets.data);
        put(&mut obj, "central_header_offset", m.offsets.central_header);
    }
    obj
}

/// Classification flags for one member path, from the name alone.
#[derive(Default)]
pub(super) struct FilenameClass {
    pub(super) is_hidden: bool,
    pub(super) has_path_traversal: bool,
    pub(super) is_unicode: bool,
    pub(super) has_homoglyph: bool,
    pub(super) has_double_extension: bool,
    pub(super) has_rtlo: bool,
    pub(super) is_executable: bool,
    pub(super) is_script: bool,
    pub(super) is_nested_archive: bool,
    pub(super) is_misplaced_executable: bool,
}

/// Classify a member path. The same rules apply to every archive format.
pub(super) fn classify_filename(path: &str) -> FilenameClass {
    let mut c = FilenameClass {
        // Hidden: any path component starts with `.` (excluding `.`/`..`).
        is_hidden: path
            .split('/')
            .any(|p| p.starts_with('.') && p != "." && p != ".."),
        // Path traversal: any `..` component, or an absolute path (leading
        // `/` or a Windows drive letter).
        has_path_traversal: path.split('/').any(|p| p == "..")
            || path.starts_with('/')
            || path
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
                && path.get(1..).is_some_and(|rest| rest.starts_with(":\\")),
        // Non-ASCII content anywhere in the path.
        is_unicode: !path.is_ascii(),
        // Homoglyphs: Cyrillic / Greek look-alikes for ASCII Latin letters.
        // Small curated set; generic Unicode security is out of scope.
        has_homoglyph: path.chars().any(is_homoglyph_char),
        // Right-to-left override and related bidi-format control chars.
        has_rtlo: path
            .chars()
            .any(|ch| matches!(ch as u32, 0x202A..=0x202E | 0x2066..=0x2069)),
        ..FilenameClass::default()
    };

    let basename = path.rsplit('/').next().unwrap_or(path);
    let lower = basename.to_ascii_lowercase();

    // Double extension: `something.<inner>.<outer>` where outer is
    // executable and inner is a benign-looking document/text suffix.
    if let Some((stem, outer)) = lower.rsplit_once('.')
        && is_executable_extension(outer)
        && let Some((_, inner)) = stem.rsplit_once('.')
    {
        const SAFE_LOOKING: &[&str] = &[
            "txt", "pdf", "doc", "docx", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "csv", "xls",
            "xlsx", "rtf",
        ];
        c.has_double_extension = SAFE_LOOKING.contains(&inner);
    }

    let extension = lower.rsplit_once('.').map_or("", |(_, e)| e);
    c.is_executable = is_executable_extension(extension);
    c.is_script = is_script_extension(extension);
    c.is_nested_archive = is_archive_extension(extension);

    if c.is_executable {
        // PE executables belong under a `bin/`-like prefix and `.so`/`.dylib`
        // under `lib*/`; anything else is "misplaced", the canonical lure.
        let is_unix_lib = matches!(extension, "so" | "dylib");
        let is_pe = matches!(extension, "exe" | "dll" | "sys" | "scr");
        let in_bin = ["bin/", "usr/bin/", "sbin/", "usr/sbin/", "usr/local/bin/"]
            .iter()
            .any(|p| path.starts_with(p));
        let in_lib = ["lib/", "lib64/", "usr/lib/", "usr/lib64/", "usr/local/lib/"]
            .iter()
            .any(|p| path.starts_with(p));
        c.is_misplaced_executable = if is_unix_lib {
            !in_lib
        } else if is_pe {
            !path.to_ascii_lowercase().contains("bin/")
        } else {
            matches!(extension, "bin" | "elf") && !in_bin
        };
    }
    c
}

/// Developer/OS detritus: macOS resource forks and `.DS_Store`, Windows
/// `Thumbs.db` / `desktop.ini`. Sloppy packaging, not malice on its own.
pub(super) fn is_noise_filename(path: &str) -> bool {
    if path.starts_with("__MACOSX/") {
        return true;
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    matches!(base, ".DS_Store" | "Thumbs.db" | "desktop.ini")
}

fn is_executable_extension(ext: &str) -> bool {
    matches!(
        ext,
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "cpl"
            | "msi"
            | "so"
            | "dylib"
            | "bin"
            | "elf"
            | "out"
            | "app"
    )
}

fn is_script_extension(ext: &str) -> bool {
    matches!(
        ext,
        "sh" | "bash"
            | "zsh"
            | "ksh"
            | "csh"
            | "fish"
            | "py"
            | "pyc"
            | "pyo"
            | "pl"
            | "pm"
            | "rb"
            | "js"
            | "mjs"
            | "cjs"
            | "ps1"
            | "psm1"
            | "psd1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "wsf"
            | "wsh"
            | "lua"
            | "php"
    )
}

fn is_archive_extension(ext: &str) -> bool {
    matches!(
        ext,
        "zip"
            | "jar"
            | "war"
            | "ear"
            | "apk"
            | "ipa"
            | "xpi"
            | "crx"
            | "nupkg"
            | "tar"
            | "gz"
            | "tgz"
            | "bz2"
            | "tbz2"
            | "xz"
            | "txz"
            | "zst"
            | "tzst"
            | "7z"
            | "rar"
            | "cab"
            | "iso"
            | "deb"
            | "rpm"
            | "msi"
            | "pkg"
    )
}

/// Characters commonly used in homoglyph attacks: Cyrillic and Greek glyphs
/// that visually mimic ASCII Latin letters.
fn is_homoglyph_char(ch: char) -> bool {
    matches!(
        ch,
        // Cyrillic look-alikes for a/c/e/o/p/x/у (and uppercase).
        'а' | 'с' | 'е' | 'о' | 'р' | 'х' | 'у' | 'А' | 'В' | 'С' | 'Е' | 'Н'
            | 'К' | 'М' | 'О' | 'Р' | 'Т' | 'Х'
        // Greek look-alikes.
            | 'Α' | 'Β' | 'Ε' | 'Ζ' | 'Η' | 'Ι' | 'Κ' | 'Μ' | 'Ν' | 'Ο'
            | 'Ρ' | 'Τ' | 'Υ' | 'Χ'
            | 'ο' | 'ν'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{ArchiveCompression, ArchiveOffsets, ArchiveOwnership};

    fn member(path: &str, entry_type: &str, size: u64) -> ArchiveMember {
        ArchiveMember {
            path: path.into(),
            size_bytes: size,
            entry_type: Some(entry_type.into()),
            mtime_unix: None,
            linkname: None,
            host_os: None,
            crc32: None,
            encrypted: false,
            compression: None,
            ownership: None,
            offsets: ArchiveOffsets::default(),
        }
    }

    fn stamped(path: &str, mtime: Option<i64>) -> ArchiveMember {
        ArchiveMember {
            mtime_unix: mtime,
            ..member(path, "regular", 1)
        }
    }

    fn run(aggs: &'static [Agg], members: &[ArchiveMember]) -> (Values, Metrics) {
        let mut stats = ArchiveStats::new(aggs);
        for m in members {
            stats.observe(m, &Reading::of(m));
        }
        let (mut values, mut metrics) = (Values::new(), Metrics::new());
        stats.emit(&mut values, &mut metrics);
        (values, metrics)
    }

    #[test]
    fn only_the_requested_aggregates_are_written() {
        let members = [member("a.exe", "regular", 3), member("d", "directory", 0)];
        let (values, metrics) = run(&[Agg::MemberCount, Agg::Executables], &members);
        assert_eq!(metrics.get("archive.member_count"), Some(2.0));
        assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
        assert_eq!(metrics.len(), 2);
        assert_eq!(values.as_json(), &serde_json::json!({}));
    }

    #[test]
    fn scope_separates_files_from_every_member() {
        // A directory carrying a size and a traversal name counts under
        // Scope::All only.
        let members = [member("../up/", "directory", 7), member("f", "regular", 5)];
        let (_, all) = run(
            &[
                Agg::UncompressedSize(Scope::All),
                Agg::PathTraversal(Scope::All),
            ],
            &members,
        );
        let (_, files) = run(
            &[
                Agg::UncompressedSize(Scope::Files),
                Agg::PathTraversal(Scope::Files),
            ],
            &members,
        );
        assert_eq!(all.get("archive.uncompressed_size"), Some(12.0));
        assert_eq!(all.get("archive.path_traversal_count"), Some(1.0));
        assert_eq!(files.get("archive.uncompressed_size"), Some(5.0));
        assert_eq!(files.get("archive.path_traversal_count"), Some(0.0));
    }

    #[test]
    fn sizes_saturate_instead_of_overflowing() {
        let huge = member("a", "regular", u64::MAX);
        let (_, metrics) = run(&[Agg::UncompressedSize(Scope::All)], &[huge.clone(), huge]);
        assert_eq!(
            metrics.get("archive.uncompressed_size"),
            Some(u64::MAX as f64)
        );
    }

    #[test]
    fn reading_overrides_name_based_defaults() {
        let m = member("payload", "regular", 1);
        let mut stats = ArchiveStats::new(&[Agg::HiddenFiles, Agg::Executables, Agg::FileCount]);
        let mut reading = Reading::of(&m);
        reading.hidden = true;
        reading.exec_mode = true;
        stats.observe(&m, &reading);
        // An opaque member is a member, but its name and kind say nothing.
        stats.observe(&member(".x/run.exe", "slack", 1), &Reading::opaque());
        let mut metrics = Metrics::new();
        stats.emit(&mut Values::new(), &mut metrics);
        assert_eq!(metrics.get("archive.hidden_file_count"), Some(1.0));
        assert_eq!(metrics.get("archive.executable_count"), Some(1.0));
        assert_eq!(metrics.get("archive.file_count"), Some(1.0));
    }

    #[test]
    fn mode_bits_symlinks_and_escapes_come_from_the_typed_member() {
        let with_mode = |path: &str, kind: &str, mode: u32, link: Option<&str>| ArchiveMember {
            linkname: link.map(str::to_string),
            ownership: Some(ArchiveOwnership {
                mode_octal: Some(mode),
                ..Default::default()
            }),
            ..member(path, kind, 0)
        };
        let members = [
            with_mode("s", "regular", 0o4755, None),
            with_mode("w", "regular", 0o666, None),
            with_mode("l1", "symlink", 0o777, Some("../../etc/passwd")),
            with_mode("l2", "symlink", 0o777, Some("sibling")),
        ];
        let (_, metrics) = run(
            &[Agg::ModeBits, Agg::SymlinkCount, Agg::SymlinkEscapes],
            &members,
        );
        assert_eq!(metrics.get("archive.security.setuid_count"), Some(1.0));
        // The 0o666 file and both 0o777 symlinks.
        assert_eq!(
            metrics.get("archive.security.world_writable_count"),
            Some(3.0)
        );
        assert_eq!(metrics.get("archive.security.symlink_count"), Some(2.0));
        assert_eq!(metrics.get("archive.symlink_escape_count"), Some(1.0));
    }

    #[test]
    fn methods_list_is_written_when_empty_only_if_asked() {
        let (always, _) = run(&[Agg::Methods { always: true }], &[]);
        let (if_any, _) = run(&[Agg::Methods { always: false }], &[]);
        assert_eq!(
            always.get("archive.compression.methods"),
            Some(&serde_json::json!([]))
        );
        assert!(if_any.get("archive.compression.methods").is_none());

        let packed = ArchiveMember {
            compression: Some(ArchiveCompression {
                compressed_size: Some(1),
                method: Some("lzma".into()),
            }),
            ..member("a", "regular", 10)
        };
        let (values, metrics) = run(
            &[
                Agg::Methods { always: false },
                Agg::ZipBombRatio(Scope::All),
            ],
            &[packed],
        );
        assert_eq!(
            values.get("archive.compression.methods"),
            Some(&serde_json::json!(["lzma"]))
        );
        assert_eq!(
            metrics.get("archive.compression.method_counts.lzma"),
            Some(1.0)
        );
        assert_eq!(metrics.get("archive.zip_bomb_ratio"), Some(10.0));
    }

    #[test]
    fn duplicate_paths_are_counted_after_the_first() {
        let members = [
            member("same", "regular", 1),
            member("same", "regular", 1),
            member("same", "regular", 1),
            member("other", "regular", 1),
        ];
        let (_, metrics) = run(&[Agg::DuplicateMembers], &members);
        assert_eq!(metrics.get("archive.duplicate_member_count"), Some(2.0));
    }

    #[test]
    fn untimed_group_can_dominate_and_lists_stamped_outliers() {
        let members = [
            stamped("a", None),
            stamped("b", None),
            stamped("c", None),
            stamped("dropped", Some(1_750_000_000)),
        ];
        let (values, metrics) = run(
            &[
                Agg::SentinelMtimes,
                Agg::MtimeAnomalies(Dominance::UntimedGroup),
            ],
            &members,
        );
        assert_eq!(
            metrics.get("archive.timing.sentinel_mtime_count"),
            Some(3.0)
        );
        assert_eq!(
            metrics.get("archive.timing.mtime_dominant_count"),
            Some(3.0)
        );
        assert_eq!(
            metrics.get("archive.timing.mtime_dominant_fraction"),
            Some(0.75)
        );
        assert_eq!(metrics.get("archive.timing.mtime_outlier_count"), Some(1.0));
        assert_eq!(
            values.get("archive.timing.mtime_outlier_members"),
            Some(&serde_json::json!(["dropped"]))
        );
    }

    #[test]
    fn timed_only_dominance_ignores_unstamped_members() {
        let members = [
            stamped("a", Some(100)),
            stamped("b", Some(100)),
            stamped("c", Some(100)),
            stamped("late", Some(4_200_000_000)),
            stamped("none", None),
        ];
        let (values, metrics) = run(
            &[Agg::MtimeRange, Agg::MtimeAnomalies(Dominance::TimedOnly)],
            &members,
        );
        assert_eq!(
            metrics.get("archive.timing.mtime_dominant_count"),
            Some(3.0)
        );
        assert_eq!(
            metrics.get("archive.timing.mtime_dominant_fraction"),
            Some(0.6)
        );
        // The unstamped member counts toward the total but is never listed.
        assert_eq!(metrics.get("archive.timing.mtime_outlier_count"), Some(2.0));
        assert_eq!(
            values.get("archive.timing.mtime_outlier_members"),
            Some(&serde_json::json!(["late"]))
        );
        assert_eq!(metrics.get("archive.timing.future_mtime_count"), Some(1.0));
        assert_eq!(metrics.get("archive.timing.mtime_unique_count"), Some(2.0));
        assert_eq!(metrics.get("archive.timing.mtime_unique_ratio"), Some(0.5));
    }

    #[test]
    fn mtime_spread_survives_the_full_i64_range() {
        let members = [stamped("a", Some(i64::MIN)), stamped("b", Some(i64::MAX))];
        let (values, metrics) = run(&[Agg::MtimeRange], &members);
        assert_eq!(
            metrics.get("archive.timing.mtime_spread_seconds"),
            Some(u64::MAX as f64)
        );
        assert_eq!(
            values.get("archive.timing.mtime_min"),
            Some(&serde_json::json!(i64::MIN))
        );
    }

    #[test]
    fn member_value_maps_typed_fields_and_honours_the_shape() {
        let m = ArchiveMember {
            mtime_unix: Some(5),
            crc32: Some(7),
            compression: Some(ArchiveCompression {
                compressed_size: Some(2),
                method: Some("deflate".into()),
            }),
            ownership: Some(ArchiveOwnership {
                mode_octal: Some(0o644),
                uid: Some(1),
                ..Default::default()
            }),
            offsets: ArchiveOffsets {
                header: Some(0),
                data: Some(30),
                central_header: None,
            },
            ..member("a.txt", "regular", 4)
        };
        assert_eq!(
            JsonValue::Object(member_value(&m, Shape::FULL)),
            serde_json::json!({
                "path": "a.txt",
                "size_bytes": 4,
                "entry_type": "regular",
                "mtime_unix": 5,
                "crc32": 7,
                "compressed_size": 2,
                "compression_method": "deflate",
                "mode_octal": 0o644,
                "uid": 1,
                "header_offset": 0,
                "data_offset": 30,
            })
        );
        let bare = member_value(
            &ArchiveMember {
                encrypted: true,
                ..m
            },
            Shape {
                offsets: false,
                compression: false,
            },
        );
        assert_eq!(bare.get("encrypted"), Some(&JsonValue::Bool(true)));
        for absent in [
            "compressed_size",
            "compression_method",
            "header_offset",
            "data_offset",
        ] {
            assert!(!bare.contains_key(absent), "{absent}");
        }
    }

    #[test]
    fn classify_filename_flags() {
        let c = classify_filename("photos/invoice.pdf.exe");
        assert!(c.is_executable && c.has_double_extension && c.is_misplaced_executable);
        assert!(!classify_filename("bin/tool.exe").is_misplaced_executable);
        assert!(classify_filename("C:\\evil.dll").has_path_traversal);
        assert!(!classify_filename("é:\\x").has_path_traversal);
        assert!(classify_filename("a/.git/config").is_hidden);
        assert!(!classify_filename("./a/../b").is_hidden);
        assert!(classify_filename("r\u{0435}sume.doc").has_homoglyph);
        assert!(classify_filename("x\u{202e}gpj.exe").has_rtlo);
        assert!(classify_filename("pkg.tar.gz").is_nested_archive);
        assert!(classify_filename("run.PS1").is_script);
    }

    #[test]
    fn is_noise_filename_helper() {
        assert!(is_noise_filename("__MACOSX/anything"));
        assert!(is_noise_filename(".DS_Store"));
        assert!(is_noise_filename("nested/path/.DS_Store"));
        assert!(is_noise_filename("Thumbs.db"));
        assert!(is_noise_filename("desktop.ini"));
        assert!(!is_noise_filename("ok.txt"));
        assert!(!is_noise_filename("a/b/c.txt"));
        // Case-sensitive — exact Windows / macOS conventions only.
        assert!(!is_noise_filename("THUMBS.DB"));
    }
}
