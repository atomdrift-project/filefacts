//! Cross-format identity normalization.
//!
//! Every format extractor writes identity facts into its own corner of
//! the [`Values`] tree — `macho.code_signature.identifier`,
//! `pe.version.company`, `office.creator`, `npm.authors`, … This
//! pass runs once after extraction and folds those scattered fields
//! into the single normalized [`Identity`] view, so a consumer reads
//! "who and what does this claim to be" the same way for every format.
//!
//! The guiding question is *here is the claimed identity, here are the
//! behaviors — do they agree?* To serve it, every scalar lands as a
//! [`Claim`] tagged with its source key and a `verified` flag that is
//! true only when a cryptographic signature backs it. Manifest fields
//! and document properties are claims anyone can write; a CMS signer
//! certificate is proof.
//!
//! Only what is embedded in the artifact is read. Detached trust material
//! (a Sigstore bundle, a cosign `.sig`, a distro `.asc`) lives outside the
//! bytes and would have to be fetched, which filefacts never does.

use std::collections::BTreeSet;

use serde_json::Value as JsonValue;

use crate::fileid::FileType;
use crate::formats::cms::Signature;
use crate::output::{Claim, Identity, Party, PartyRole, Trust, Url, UrlKind, ValueKey, Values};
use crate::value_key;

mod byte_scan;
mod filename;
mod trust;

use byte_scan::{home_path_scan, reveals_home, scan_token};
use filename::filename_fallback;
use trust::{CertInfo, cert_trust, signature, signer_struct};

/// Fold the per-format structural values into the normalized identity
/// view. Never fails: missing inputs simply yield empty fields.
pub(crate) fn derive(file_type: FileType, bytes: &[u8], values: &Values) -> Identity {
    let mut id = Identity::default();

    match file_type {
        FileType::MachO => macho(values, bytes, &mut id),
        FileType::Pe => pe(values, &mut id),
        FileType::Vsix | FileType::VsixManifest => vsix(values, &mut id),
        FileType::Xpi => xpi(values, &mut id),
        FileType::Nupkg => nupkg(values, &mut id),
        FileType::Whl => wheel(values, &mut id),
        FileType::Jar => jar(values, &mut id),
        FileType::Gem => gem(values, &mut id),
        FileType::Npm | FileType::PackageJson => npm(values, &mut id),
        FileType::Crate => rust_crate(values, &mut id),
        FileType::PythonSdist => python_sdist(values, &mut id),
        FileType::OciImage => oci(values, &mut id),
        FileType::Crx => crx(values, &mut id),
        FileType::Ooxml | FileType::OleDoc | FileType::Msi => office(values, &mut id),
        FileType::Pdf => pdf(values, &mut id),
        FileType::Rtf => rtf(values, &mut id),
        FileType::Png => png(values, &mut id),
        FileType::Lnk => lnk(values, &mut id),
        FileType::Cab => cab(values, &mut id),
        FileType::Rar => rar(values, &mut id),
        FileType::ApkAlpine => apk_alpine(values, &mut id),
        FileType::ApkAndroid => apk_android(values, &mut id),
        FileType::Iso => iso(values, &mut id),
        FileType::Dmg => dmg(values, &mut id),
        FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst => {
            tar(values, &mut id);
        }
        FileType::Rpm => rpm(values, &mut id),
        FileType::Deb => deb(values, &mut id),
        _ => {}
    }

    // What the artifact says it is for, and whose it is, in its own words.
    description(values, &mut id);

    // Build-time source path — an origin artifact carried by native
    // executables regardless of format.
    if matches!(file_type, FileType::Pe | FileType::Elf | FileType::MachO) {
        build_path(bytes, values, &mut id);
    }

    // A Go binary's main module, when nothing stronger named the project.
    match file_type {
        FileType::Pe => go_module(value_key!("pe.go"), values, &mut id),
        FileType::Elf => go_module(value_key!("elf.go"), values, &mut id),
        FileType::MachO => go_module(value_key!("macho.go"), values, &mut id),
        _ => {}
    }

    // The compiler that emitted the object, straight from DWARF. Carried by
    // ELF regardless of what else the file claims, and often the only
    // provenance an unsigned Linux binary has.
    if matches!(file_type, FileType::Elf) {
        dwarf_producer(values, &mut id);
    }

    // Interior source identity — a WordPress plugin header or an autoconf
    // AC_INIT read from inside a source archive or a bare PHP file. Weaker
    // than a signed or manifest claim, stronger than the filename below.
    source(values, &mut id);

    // Filename fallback: a source tarball whose interior yields no identity
    // still announces `<name><sep><version>` in the name it travels under —
    // the FTP era's only version resource. The weakest claim there is,
    // filled only when nothing embedded said otherwise.
    filename_fallback(values, &mut id);

    finalize(&mut id);
    id
}

// ---------------------------------------------------------------------
// Binary formats — signature-backed identity.
// ---------------------------------------------------------------------

fn macho(values: &Values, bytes: &[u8], id: &mut Identity) {
    let signed = values
        .lookup(value_key!("macho.code_signature.identifier"))
        .is_some()
        || values
            .lookup(value_key!("macho.code_signature.cdhash"))
            .is_some()
        || values
            .lookup(value_key!("macho.code_signature.flags"))
            .is_some();
    let cms = values.lookup(value_key!("macho.code_signature.cms"));
    // A verified CMS signature binds the CodeDirectory (its messageDigest is
    // the CodeDirectory's hash), so the fields inside it are proven to be the
    // signer's. A CMS that is merely present proves nothing.
    // The CodeDirectory in turn covers the code only through its hash slots,
    // recomputed from this file into `code_pages_verified`; without them a
    // CodeDirectory and signature lifted from another binary vouch for this
    // one. Alternates must also repeat the signed primary's identity.
    let flag = |key| values.lookup(key).and_then(JsonValue::as_bool);
    let code_bound = flag(value_key!("macho.code_signature.code_pages_verified")) == Some(true)
        && flag(value_key!("macho.code_signature.special_slots_verified")) != Some(false)
        && flag(value_key!(
            "macho.code_signature.code_directories_consistent"
        )) != Some(false);
    let cms = cms.and_then(signature);
    let cms_verified = code_bound && cms.as_ref().is_some_and(Signature::is_verified);

    if let Some(ident) = str_value(values, value_key!("macho.code_signature.identifier")) {
        id.identifier = Some(Claim {
            value: ident.to_string(),
            source: "macho.code_signature.identifier".into(),
            verified: cms_verified,
        });
    }
    if let Some(team) = str_value(values, value_key!("macho.code_signature.team_id")) {
        id.team_id = Some(Claim {
            value: team.to_string(),
            source: "macho.code_signature.team_id".into(),
            verified: cms_verified,
        });
    }
    if let Some(cdhash) = str_value(values, value_key!("macho.code_signature.cdhash")) {
        id.unique_ids.insert("cdhash".into(), cdhash.to_string());
    }

    if let Some(mut ci) = cms.as_ref().and_then(CertInfo::from_signature) {
        ci.verified &= code_bound;
        record_signer(id, ci, "macho.code_signature.cms");
    }

    // Trust resolution, in precedence order.
    let platform = values
        .lookup(value_key!("macho.code_signature.platform"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(0);
    let ad_hoc =
        str_array(values, value_key!("macho.code_signature.flags")).any(|flag| flag == "ad_hoc");
    if id.trust == Trust::Unsigned && signed {
        // A code signature with no certificate behind it: ad hoc when it
        // says so and its hashes match the code, and otherwise a structure
        // nothing here could verify.
        id.trust = if ad_hoc && code_bound {
            Trust::AdHoc
        } else {
            Trust::Unverified
        };
    }
    // The CodeDirectory's platform byte marks an OS component, but any
    // binary can set it; only Apple's own verified signature over that
    // CodeDirectory makes the claim stick.
    if platform > 0 && id.trust == Trust::Platform {
        id.trust = Trust::System;
    }

    // For a platform/system binary with no CMS organization, infer the
    // vendor from the reverse-DNS identifier (`com.apple.ls` → Apple).
    if id.organization.is_none()
        && id.trust == Trust::System
        && let Some(ident) = str_value(values, value_key!("macho.code_signature.identifier"))
        && let Some(org) = org_from_reverse_dns(ident)
    {
        id.organization = Some(Claim::claimed(org, "macho.code_signature.identifier"));
    }

    // Apple `what(1)` stamp: `@(#)PROGRAM:ls  PROJECT:file_cmds-479`.
    // Gated to Apple binaries — the only ones that carry it — so the
    // overwhelming majority of Mach-O files never pay for the scan.
    let apple = id.trust == Trust::System
        || str_value(values, value_key!("macho.code_signature.identifier"))
            .is_some_and(|i| i.starts_with("com.apple."));
    if apple {
        if let Some(prog) = scan_token(bytes, b"PROGRAM:") {
            id.name = Some(Claim::claimed(prog, "macho:@(#)PROGRAM"));
        }
        if let Some(proj) = scan_token(bytes, b"PROJECT:") {
            id.project = Some(Claim::claimed(proj, "macho:@(#)PROJECT"));
        }
    }

    // Name fallbacks: install-name basename, then identifier tail.
    if id.name.is_none()
        && let Some(install) = str_value(values, value_key!("macho.install_name"))
    {
        let base = install.rsplit('/').next().unwrap_or(install);
        if !base.is_empty() {
            id.name = Some(Claim::claimed(base, "macho.install_name"));
        }
    }
    if id.name.is_none()
        && let Some(ident) = str_value(values, value_key!("macho.code_signature.identifier"))
        && let Some(tail) = ident.rsplit('.').next()
    {
        id.name = Some(Claim::claimed(tail, "macho.code_signature.identifier"));
    }

    if let Some(sv) = str_value(values, value_key!("macho.source_version"))
        && sv != "0.0.0"
    {
        id.version = Some(Claim::claimed(sv, "macho.source_version"));
    }
}

fn pe(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("pe.version.original_filename"))
        .or_else(|| str_value(values, value_key!("pe.version.internal_name")))
    {
        id.name = Some(Claim::claimed(name, "pe.version.original_filename"));
    }
    // ProductName names the larger product/suite the file belongs to —
    // the closest PE analogue to a source project.
    if let Some(product) = str_value(values, value_key!("pe.version.product_name")) {
        id.project = Some(Claim::claimed(product, "pe.version.product_name"));
    }
    if let Some(company) = str_value(values, value_key!("pe.version.company")) {
        id.organization = Some(Claim::claimed(company, "pe.version.company"));
    }
    if let Some(version) = str_value(values, value_key!("pe.version.file_version"))
        .or_else(|| str_value(values, value_key!("pe.version.product_version")))
    {
        id.version = Some(Claim::claimed(version, "pe.version.file_version"));
    }

    let signature = values
        .lookup_at(value_key!("pe.signatures"), "[0]")
        .and_then(signature);
    if let Some(sig) = &signature
        && let Some(mut ci) = CertInfo::from_signature(sig)
    {
        // A signature says nothing about this file unless the image hash it
        // signed is this file's own: one grafted from another binary verifies
        // perfectly while covering that binary. An absent comparison is not a
        // match either, since the Authentihash can be skipped
        // (`pe.image_hash_skipped`).
        ci.verified &= sig.digest_matches == Some(true);
        // A verified signer certificate outranks the self-asserted
        // CompanyName for the organization field.
        record_signer(id, ci, "pe.signatures[0]");
    }
    if let Some(t) = signature.and_then(|s| s.thumbprint_sha256) {
        id.unique_ids
            .insert("authenticode_thumbprint_sha256".into(), t);
    }
}

/// A cabinet's only identity claim is its appended Authenticode signature --
/// CFHEADER carries no publisher, product or version field. The signature blob
/// is published in the PE `signatures[0]` shape, so the mapping is the PE one.
fn cab(values: &Values, id: &mut Identity) {
    let signature = values
        .lookup_at(value_key!("cab.signatures"), "[0]")
        .and_then(signature);
    if let Some(mut ci) = signature.as_ref().and_then(CertInfo::from_signature) {
        // Nothing hashes the cabinet to compare with the digest the
        // signature carries, so however well the signature verifies, nothing
        // shows it was made over this cabinet.
        ci.verified = false;
        record_signer(id, ci, "cab.signatures[0]");
    }
    if let Some(t) = signature.and_then(|s| s.thumbprint_sha256) {
        id.unique_ids
            .insert("authenticode_thumbprint_sha256".into(), t);
    }
}

/// RAR 5 stores the original archive name and (optionally) the time it was
/// created in a main-header extra record. Both are operator-chosen, so they
/// are unverified claims — the same class of provenance as an ISO volume id.
fn rar(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("rar.original_name")) {
        id.name = Some(Claim::claimed(name, "rar.original_name"));
    }
}

/// ISO 9660 records who made the image in the Primary Volume Descriptor:
/// a volume name, a publisher, a data preparer and the authoring application.
/// They are free text an operator fills in, so every claim here is unverified
/// -- but a mastering tool stamps itself consistently, which is what makes a
/// blank or imitated field worth seeing next to a real one.
fn iso(values: &Values, id: &mut Identity) {
    if let Some(volume) = str_value(values, value_key!("iso.volume_id")) {
        id.name = Some(Claim::claimed(volume, "iso.volume_id"));
    }
    if let Some(publisher) = str_value(values, value_key!("iso.publisher_id")) {
        id.organization = Some(Claim::claimed(publisher, "iso.publisher_id"));
    } else if let Some(preparer) = str_value(values, value_key!("iso.preparer_id")) {
        // The preparer is a weaker claim than the publisher, so it only
        // stands in when no publisher was recorded.
        id.organization = Some(Claim::claimed(preparer, "iso.preparer_id"));
    }
    // `iso.builder` is the normalized mastering-tool name; prefer it over the
    // raw application field it was derived from.
    if let Some(builder) = str_value(values, value_key!("iso.builder")) {
        id.producer = Some(Claim::claimed(builder, "iso.builder"));
    } else if let Some(app) = str_value(values, value_key!("iso.application_id")) {
        id.producer = Some(Claim::claimed(app, "iso.application_id"));
    }
    for (key, name) in [
        (value_key!("iso.volume_set_id"), "iso_volume_set_id"),
        (
            value_key!("iso.udf.logical_volume_id"),
            "udf_logical_volume_id",
        ),
        (value_key!("iso.udf.volume_set_id"), "udf_volume_set_id"),
        (
            value_key!("iso.udf.implementation_id"),
            "udf_implementation_id",
        ),
    ] {
        if let Some(v) = str_value(values, key) {
            id.unique_ids.insert(name.into(), v.to_string());
        }
    }
}

/// A disk image names its volume and records the tool that formatted it --
/// the closest thing a DMG has to provenance, since UDIF itself carries no
/// publisher field and the image need not be signed.
fn dmg(values: &Values, id: &mut Identity) {
    if let Some(volume) = str_value(values, value_key!("dmg.volume.name")) {
        id.name = Some(Claim::claimed(volume, "dmg.volume.name"));
    }
    if let Some(tool) = str_value(values, value_key!("dmg.volume.formatted_by")) {
        id.producer = Some(Claim::claimed(tool, "dmg.volume.formatted_by"));
    }
    // `dmg.volume.last_mounted_version` is deliberately NOT a producer. It is
    // the HFS+ `lastMountedVersion` field, which holds an implementation
    // signature such as `HFSJ` or `10.0` -- the thing that last mounted the
    // volume, not the thing that made the image. Mapping it would produce a
    // confident `producer: "HFSJ"`, a fabricated claim, and a wrong identity
    // is worse than an absent one.
}

/// POSIX tar stores the owning user and group *names* beside the numeric ids,
/// so an archive built outside a clean packaging environment carries the
/// build account in it -- the same class of accidental provenance as a PDB
/// path. Recorded as parties rather than as an organization: these name a
/// person or a service account, not a publisher.
fn tar(values: &Values, id: &mut Identity) {
    // Names already recorded, as a set: an archive carries one entry per
    // distinct owner, and scanning `authors` for each made 100k owners
    // quadratic.
    let mut recorded: BTreeSet<String> = id.authors.iter().filter_map(|p| p.name.clone()).collect();
    for key in [
        value_key!("archive.builder.unames"),
        value_key!("archive.builder.gnames"),
    ] {
        let Some(list) = values.lookup(key).and_then(JsonValue::as_array) else {
            continue;
        };
        for name in list.iter().filter_map(JsonValue::as_str) {
            // root/wheel and the like say nothing about who built it.
            if matches!(name, "root" | "wheel" | "staff" | "users" | "nobody" | "") {
                continue;
            }
            if recorded.insert(name.to_string()) {
                id.authors.push(Party {
                    name: Some(name.to_string()),
                    email: None,
                    url: None,
                    role: PartyRole::Builder,
                    source: key.to_string(),
                });
            }
        }
    }
}

/// A Go binary's main module path and version, from its embedded build info
/// (what `go version -m` prints). It names the project the binary was built
/// from — `github.com/gitleaks/gitleaks` — which is often the only identity an
/// unsigned Go tool carries, so it fills `project` and `version` only when a
/// version resource or signature has not already.
fn go_module(key: ValueKey, values: &Values, id: &mut Identity) {
    let Some(module) = values.lookup_at(key, "module") else {
        return;
    };
    let field = |key: &str| {
        module
            .get(key)
            .and_then(JsonValue::as_str)
            .filter(|v| !v.is_empty() && *v != "(devel)")
    };
    if id.project.is_none()
        && let Some(path) = field("path")
    {
        id.project = Some(Claim::claimed(path, format!("{key}.module.path")));
    }
    if id.version.is_none()
        && let Some(version) = field("version")
    {
        id.version = Some(Claim::claimed(version, format!("{key}.module.version")));
    }
}

/// `DW_AT_producer` names the compiler and its flags.
fn dwarf_producer(values: &Values, id: &mut Identity) {
    if id.producer.is_some() {
        return;
    }
    if let Some(p) = values
        .lookup(value_key!("elf.dwarf.producers"))
        .and_then(JsonValue::as_array)
        .and_then(|a| a.first())
        .and_then(JsonValue::as_str)
    {
        id.producer = Some(Claim::claimed(p, "elf.dwarf.producers"));
    }
}

/// Alpine `.PKGINFO` is a publisher manifest in the same family as a wheel's
/// `METADATA` or a gem's `metadata.gz`, so it maps the same way.
fn apk_alpine(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("apk.name")) {
        id.name = Some(Claim::claimed(name, "apk.name"));
    }
    if let Some(version) = str_value(values, value_key!("apk.version")) {
        id.version = Some(Claim::claimed(version, "apk.version"));
    }
    // `origin` names the source build a package came out of -- the project,
    // where `pkgname` may be only one of its subpackages.
    if let Some(origin) = str_value(values, value_key!("apk.origin")) {
        id.project = Some(Claim::claimed(origin, "apk.origin"));
    }
    if let Some(builder) = str_value(values, value_key!("apk.builder")) {
        id.producer = Some(Claim::claimed(builder, "apk.builder"));
    }
    push_people(
        id,
        values,
        value_key!("apk.maintainers"),
        PartyRole::Maintainer,
    );
    push_people(id, values, value_key!("apk.packagers"), PartyRole::Packager);
    if let Some(url) = str_value(values, value_key!("apk.homepage")) {
        push_url(id, UrlKind::Homepage, url, "apk.homepage");
    }
    // The commit the package was built from, and the digest of its data
    // segment: both pin this artifact to a specific build.
    for (key, name) in [
        (value_key!("apk.commit"), "vcs_commit"),
        (value_key!("apk.datahash"), "apk_datahash"),
    ] {
        if let Some(v) = str_value(values, key)
            && v != "unknown"
        {
            id.unique_ids.insert(name.into(), v.to_string());
        }
    }
}

/// An Android app's `package` is its canonical identifier -- the name the
/// platform installs it under and the one a store listing resolves. The v1
/// signing certificate is the only party claim an APK carries; Android itself
/// treats that key, not the package name, as the app's real identity across
/// updates, so the thumbprint is the durable correlator.
fn apk_android(values: &Values, id: &mut Identity) {
    if let Some(pkg) = str_value(values, value_key!("android.package")) {
        id.identifier = Some(Claim::claimed(pkg, "android.package"));
    }
    // The display label is what a user actually sees, which is what makes it
    // the field an impersonating app fills with a brand it does not own -- but
    // most manifests store it as a reference into `resources.arsc` rather than
    // inline. An unresolved `@0x7f0c0043` is a pointer, not a name, and
    // recording it as one would put a meaningless string in front of an
    // analyst on almost every APK. Only an inline label becomes identity.
    if let Some(label) =
        str_value(values, value_key!("android.app_label")).filter(|l| !l.starts_with("@0x"))
    {
        id.name = Some(Claim::claimed(label, "android.app_label"));
    }
    if let Some(version) = str_value(values, value_key!("android.version_name"))
        .or_else(|| str_value(values, value_key!("android.version_code")))
    {
        id.version = Some(Claim::claimed(version, "android.version_name"));
    }
    let signature = values
        .lookup_at(value_key!("android.signatures"), "[0]")
        .and_then(signature);
    if let Some(sig) = &signature
        && let Some(mut ci) = CertInfo::from_signature(sig)
    {
        // The v1 block signs only its `.SF` file, so a block and `.SF` copied
        // from another app verify perfectly while covering that app. The
        // signer is proven only when the `.SF` also binds `MANIFEST.MF` and
        // the manifest every member (`digest_matches`); otherwise it is
        // named, not proven.
        ci.verified &= sig.digest_matches == Some(true);
        record_signer(id, ci, "android.signatures[0]");
    }
    if let Some(t) = signature.and_then(|s| s.thumbprint_sha256) {
        id.unique_ids
            .insert("apk_signer_thumbprint_sha256".into(), t);
    }
}

fn crx(values: &Values, id: &mut Identity) {
    // The id and key are header claims until the developer key's signature
    // over the header and archive checks out. A verified key is still
    // self-asserted: no certificate vouches for who holds it.
    let verified = values
        .lookup(value_key!("crx.signature_verified"))
        .and_then(JsonValue::as_bool)
        == Some(true);
    if let Some(ext_id) = str_value(values, value_key!("crx.extension_id")) {
        id.identifier = Some(Claim {
            value: ext_id.to_string(),
            source: "crx.extension_id".into(),
            verified,
        });
        id.unique_ids.insert("crx_id".into(), ext_id.to_string());
    }
    if let Some(pk) = str_value(values, value_key!("crx.public_key_sha256")) {
        id.unique_ids
            .insert("public_key_sha256".into(), pk.to_string());
        id.trust = if verified {
            Trust::SelfSigned
        } else {
            Trust::Unverified
        };
    }
    // Developer-declared author from the extension manifest.
    push_people(id, values, value_key!("crx.authors"), PartyRole::Author);
    if let Some(home) = str_value(values, value_key!("crx.homepage")) {
        push_url(id, UrlKind::Homepage, home, "crx.homepage");
    }
}

// ---------------------------------------------------------------------
// Package manifests — claimed identity.
// ---------------------------------------------------------------------

fn xpi(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("xpi.name")) {
        id.name = Some(Claim::claimed(name, "xpi.name"));
    }
    if let Some(version) = str_value(values, value_key!("xpi.version")) {
        id.version = Some(Claim::claimed(version, "xpi.version"));
    }
    push_people(id, values, value_key!("xpi.authors"), PartyRole::Author);
    if let Some(home) = str_value(values, value_key!("xpi.homepage")) {
        push_url(id, UrlKind::Homepage, home, "xpi.homepage");
    }
}

fn nupkg(values: &Values, id: &mut Identity) {
    if let Some(pkg_id) = str_value(values, value_key!("nupkg.name")) {
        id.identifier = Some(Claim::claimed(pkg_id, "nupkg.name"));
    }
    if let Some(name) = str_value(values, value_key!("nupkg.title"))
        .or_else(|| str_value(values, value_key!("nupkg.name")))
    {
        id.name = Some(Claim::claimed(name, "nupkg.title"));
    }
    if let Some(version) = str_value(values, value_key!("nupkg.version")) {
        id.version = Some(Claim::claimed(version, "nupkg.version"));
    }
    push_people(id, values, value_key!("nupkg.authors"), PartyRole::Author);
    push_people(id, values, value_key!("nupkg.owners"), PartyRole::Owner);
    if let Some(url) = str_value(values, value_key!("nupkg.homepage")) {
        push_url(id, UrlKind::Homepage, url, "nupkg.homepage");
    }
    if let Some(url) = str_value(values, value_key!("nupkg.repository")) {
        push_url(id, UrlKind::Repository, url, "nupkg.repository");
    }
}

fn vsix(values: &Values, id: &mut Identity) {
    if let Some(ext_id) = str_value_at(values, value_key!("vsix.identity"), "id") {
        id.identifier = Some(Claim::claimed(ext_id, "vsix.identity.id"));
        if id.name.is_none()
            && let Some(tail) = ext_id.rsplit('.').next()
        {
            id.name = Some(Claim::claimed(tail, "vsix.identity.id"));
        }
    }
    if let Some(display) = str_value(values, value_key!("vsix.display_name")) {
        id.name = Some(Claim::claimed(display, "vsix.display_name"));
    }
    if let Some(version) = str_value_at(values, value_key!("vsix.identity"), "version") {
        id.version = Some(Claim::claimed(version, "vsix.identity.version"));
    }
    if let Some(publisher) = str_value_at(values, value_key!("vsix.identity"), "publisher") {
        id.team_id = Some(Claim::claimed(publisher, "vsix.identity.publisher"));
    }
}

fn wheel(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("whl.distribution")) {
        id.name = Some(Claim::claimed(name, "whl.distribution"));
    }
    if let Some(version) = str_value(values, value_key!("whl.version")) {
        id.version = Some(Claim::claimed(version, "whl.version"));
    }
    push_people(id, values, value_key!("whl.authors"), PartyRole::Author);
    push_people(
        id,
        values,
        value_key!("whl.maintainers"),
        PartyRole::Maintainer,
    );
    if let Some(home) = str_value(values, value_key!("whl.homepage")) {
        push_url(id, UrlKind::Homepage, home, "whl.homepage");
    }
}

fn jar(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value_at(values, value_key!("jar.manifest"), "implementation_title")
        .or_else(|| str_value_at(values, value_key!("jar.pom"), "artifact_id"))
    {
        id.name = Some(Claim::claimed(name, "jar.manifest.implementation_title"));
    }
    if let Some(version) =
        str_value_at(values, value_key!("jar.manifest"), "implementation_version")
            .or_else(|| str_value_at(values, value_key!("jar.pom"), "version"))
    {
        id.version = Some(Claim::claimed(
            version,
            "jar.manifest.implementation_version",
        ));
    }
    // Maven coordinates form a stable `group:artifact` identifier.
    if let (Some(group), Some(artifact)) = (
        str_value_at(values, value_key!("jar.pom"), "group_id"),
        str_value_at(values, value_key!("jar.pom"), "artifact_id"),
    ) {
        id.identifier = Some(Claim::claimed(format!("{group}:{artifact}"), "jar.pom"));
    }
    if let Some(vendor) = str_value_at(values, value_key!("jar.manifest"), "implementation_vendor")
        .or_else(|| str_value_at(values, value_key!("jar.manifest"), "bundle_vendor"))
        .or_else(|| str_value_at(values, value_key!("jar.manifest"), "specification_vendor"))
    {
        id.organization = Some(Claim::claimed(vendor, "jar.manifest.implementation_vendor"));
    }
    if let Some(producer) = str_value_at(values, value_key!("jar.manifest"), "created_by") {
        id.producer = Some(Claim::claimed(producer, "jar.manifest.created_by"));
    }
    // `Built-By` is the build account — an origin-host artifact, the JAR
    // analogue of a binary's embedded build path.
    if let Some(built_by) = str_value_at(values, value_key!("jar.manifest"), "built_by") {
        id.unique_ids
            .insert("build_user".into(), built_by.to_string());
    }
}

fn gem(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("gem.name")) {
        id.name = Some(Claim::claimed(name, "gem.name"));
    }
    if let Some(version) = str_value(values, value_key!("gem.version")) {
        id.version = Some(Claim::claimed(version, "gem.version"));
    }
    push_people(id, values, value_key!("gem.authors"), PartyRole::Author);
    if let Some(home) = str_value(values, value_key!("gem.homepage")) {
        push_url(id, UrlKind::Homepage, home, "gem.homepage");
    }
}

fn npm(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("npm.name")) {
        id.name = Some(Claim::claimed(name, "npm.name"));
        id.identifier = Some(Claim::claimed(name, "npm.name"));
    }
    if let Some(version) = str_value(values, value_key!("npm.version")) {
        id.version = Some(Claim::claimed(version, "npm.version"));
    }
    push_people(id, values, value_key!("npm.authors"), PartyRole::Author);
    push_people(
        id,
        values,
        value_key!("npm.maintainers"),
        PartyRole::Maintainer,
    );
    if let Some(repo) = str_value(values, value_key!("npm.repository.url")) {
        push_url(id, UrlKind::Repository, repo, "npm.repository.url");
    }
    if let Some(home) = str_value(values, value_key!("npm.homepage")) {
        push_url(id, UrlKind::Homepage, home, "npm.homepage");
    }
}

fn rust_crate(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("crate.name")) {
        id.name = Some(Claim::claimed(name, "crate.name"));
        id.identifier = Some(Claim::claimed(name, "crate.name"));
    }
    if let Some(version) = str_value(values, value_key!("crate.version")) {
        id.version = Some(Claim::claimed(version, "crate.version"));
    }
    push_people(id, values, value_key!("crate.authors"), PartyRole::Author);
    if let Some(repo) = str_value(values, value_key!("crate.repository")) {
        push_url(id, UrlKind::Repository, repo, "crate.repository");
    }
    if let Some(home) = str_value(values, value_key!("crate.homepage")) {
        push_url(id, UrlKind::Homepage, home, "crate.homepage");
    }
}

fn python_sdist(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("python.name")) {
        id.name = Some(Claim::claimed(name, "python.name"));
        id.identifier = Some(Claim::claimed(name, "python.name"));
    }
    if let Some(version) = str_value(values, value_key!("python.version")) {
        id.version = Some(Claim::claimed(version, "python.version"));
    }
    push_people(id, values, value_key!("python.authors"), PartyRole::Author);
    push_people(
        id,
        values,
        value_key!("python.maintainers"),
        PartyRole::Maintainer,
    );
    if let Some(home) = str_value(values, value_key!("python.homepage")) {
        push_url(id, UrlKind::Homepage, home, "python.homepage");
    }
}

fn oci(values: &Values, id: &mut Identity) {
    // The first image ref is the closest thing an image bundle has to a name;
    // the config/manifest digest is its strongest unique identifier.
    if let Some(first_ref) = str_array(values, value_key!("oci.ref")).next() {
        id.name = Some(Claim::claimed(first_ref, "oci.ref"));
    }
    if let Some(digest) = str_array(values, value_key!("oci.config.digest"))
        .next()
        .or_else(|| str_array(values, value_key!("oci.manifest.digest")).next())
    {
        id.identifier = Some(Claim::claimed(digest, "oci.config.digest"));
        id.unique_ids
            .insert("oci_digest".into(), digest.to_string());
    }
}

fn rpm(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("rpm.name")) {
        id.name = Some(Claim::claimed(name, "rpm.name"));
    }
    if let Some(version) = str_value(values, value_key!("rpm.version")) {
        id.version = Some(Claim::claimed(version, "rpm.version"));
    }
    if let Some(vendor) = str_value(values, value_key!("rpm.vendor")) {
        id.organization = Some(Claim::claimed(vendor, "rpm.vendor"));
    }
    push_people(id, values, value_key!("rpm.packagers"), PartyRole::Packager);
    if let Some(url) = str_value(values, value_key!("rpm.homepage")) {
        push_url(id, UrlKind::Homepage, url, "rpm.homepage");
    }
}

fn deb(values: &Values, id: &mut Identity) {
    if let Some(name) = str_value(values, value_key!("deb.name")) {
        id.name = Some(Claim::claimed(name, "deb.name"));
    }
    if let Some(version) = str_value(values, value_key!("deb.version")) {
        id.version = Some(Claim::claimed(version, "deb.version"));
    }
    push_people(
        id,
        values,
        value_key!("deb.maintainers"),
        PartyRole::Maintainer,
    );
}

/// Self-description keys, one per package format: npm `description`, wheel
/// and sdist `Summary`, crate `description`, gem `summary`, NuGet
/// `<description>`, VSIX `<Description>`, WebExtension `description`, and the
/// deb / rpm / Alpine one-line synopsis, and a PE's `FileDescription`. Each is
/// emitted only by its own format's extractor, so the first present key is the
/// artifact's.
const DESCRIPTION_KEYS: &[ValueKey] = &[
    value_key!("npm.description"),
    value_key!("whl.description"),
    value_key!("python.description"),
    value_key!("crate.description"),
    value_key!("gem.description"),
    value_key!("nupkg.description"),
    value_key!("vsix.description"),
    value_key!("crx.description"),
    value_key!("xpi.description"),
    value_key!("deb.description"),
    value_key!("rpm.description"),
    value_key!("apk.description"),
    value_key!("pe.version.description"),
];

/// Copyright notice fields, as a key and the path below it: a PE's
/// `LegalCopyright`, then a Mach-O's embedded `__info_plist` notice, then that
/// plist's older `CFBundleGetInfoString` (conventionally
/// `"<version>, Copyright <holder>"`).
const COPYRIGHT_FIELDS: &[(ValueKey, &str)] = &[
    (value_key!("pe.version.copyright"), ""),
    (value_key!("macho.info_plist"), "NSHumanReadableCopyright"),
    (value_key!("macho.info_plist"), "CFBundleGetInfoString"),
];

/// Longest self-description kept, in characters: a sentence, not a README.
/// NuGet and VSIX descriptions run to paragraphs; the opening is the claim.
const MAX_DESCRIPTION: usize = 160;

/// The artifact's self-description and copyright notice. Both are text
/// anyone can write, so both are claimed, never verified.
fn description(values: &Values, id: &mut Identity) {
    id.description = first_claim(values, DESCRIPTION_KEYS)
        .and_then(|(raw, src)| Some(Claim::claimed(one_line(raw)?, src)));
    id.copyright = COPYRIGHT_FIELDS
        .iter()
        .find_map(|&(key, field)| Some((str_value_at(values, key, field)?, key, field)))
        .and_then(|(raw, key, field)| {
            let src = if field.is_empty() {
                key.to_string()
            } else {
                format!("{key}.{field}")
            };
            Some(Claim::claimed(one_line(raw)?, src))
        });
}

/// `raw` with whitespace collapsed and cut to [`MAX_DESCRIPTION`], or `None`
/// when nothing, or only a placeholder, remains.
fn one_line(raw: &str) -> Option<String> {
    let mut text = String::with_capacity(raw.len().min(MAX_DESCRIPTION * 4));
    for (i, word) in raw.split_whitespace().enumerate() {
        if i > 0 {
            text.push(' ');
        }
        text.push_str(word);
    }
    // Python metadata writes `UNKNOWN` for a field the author left out.
    if text.is_empty() || text == "UNKNOWN" {
        return None;
    }
    // Cut at the last kept character only when there is one past the limit.
    let mut starts = text.char_indices().map(|(i, _)| i);
    if let (Some(cut), Some(_)) = (starts.nth(MAX_DESCRIPTION - 1), starts.next()) {
        text.truncate(cut);
        text.truncate(text.trim_end().len());
        text.push('…');
    }
    Some(text)
}

// ---------------------------------------------------------------------
// Documents — authored identity.
// ---------------------------------------------------------------------

/// OLE2 (`.doc`/`.xls`/`.ppt`) and OOXML (`.docx`/…) both expose their
/// document properties under the shared `office.*` namespace.
fn office(values: &Values, id: &mut Identity) {
    if let Some(title) = str_value(values, value_key!("office.title")) {
        id.title = Some(Claim::claimed(title, "office.title"));
    }
    if let Some(creator) = str_value(values, value_key!("office.creator")) {
        push_author(
            id,
            Some(creator.to_string()),
            None,
            None,
            PartyRole::Author,
            "office.creator",
        );
    }
    if let Some(modifier) = str_value(values, value_key!("office.last_modified_by")) {
        push_author(
            id,
            Some(modifier.to_string()),
            None,
            None,
            PartyRole::LastModifiedBy,
            "office.last_modified_by",
        );
    }
    if let Some(manager) = str_value(values, value_key!("office.manager")) {
        push_author(
            id,
            Some(manager.to_string()),
            None,
            None,
            PartyRole::Manager,
            "office.manager",
        );
    }
    if let Some(company) = str_value(values, value_key!("office.company")) {
        id.organization = Some(Claim::claimed(company, "office.company"));
    }
    if let Some(app) = str_value(values, value_key!("office.application")) {
        id.producer = Some(Claim::claimed(app, "office.application"));
    }
}

fn pdf(values: &Values, id: &mut Identity) {
    if let Some(title) = str_value_at(values, value_key!("pdf.info"), "title") {
        id.title = Some(Claim::claimed(title, "pdf.info.title"));
    }
    if let Some(author) = str_value_at(values, value_key!("pdf.info"), "author") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            PartyRole::Author,
            "pdf.info.author",
        );
    }
    if let Some(producer) = str_value_at(values, value_key!("pdf.info"), "producer")
        .or_else(|| str_value_at(values, value_key!("pdf.info"), "creator"))
    {
        id.producer = Some(Claim::claimed(producer, "pdf.info.producer"));
    }
}

fn rtf(values: &Values, id: &mut Identity) {
    if let Some(title) = str_value_at(values, value_key!("rtf.info"), "title") {
        id.title = Some(Claim::claimed(title, "rtf.info.title"));
    }
    if let Some(author) = str_value_at(values, value_key!("rtf.info"), "author") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            PartyRole::Author,
            "rtf.info.author",
        );
    }
    if let Some(company) = str_value_at(values, value_key!("rtf.info"), "company") {
        id.organization = Some(Claim::claimed(company, "rtf.info.company"));
    }
}

fn png(values: &Values, id: &mut Identity) {
    if let Some(software) = str_value_at(values, value_key!("png.text"), "software") {
        id.producer = Some(Claim::claimed(software, "png.text.software"));
    }
}

/// A shortcut is a record of the machine that built it. The tracker block is
/// the well-known part, but the LinkInfo volume fields identify that machine
/// just as well and survive on shortcuts that carry no tracker at all: the
/// serial is the NTFS volume id of the drive the target sat on, and the label
/// is whatever its owner named it. Neither is chosen for distribution, which
/// is what makes them useful for grouping a campaign's shortcuts together.
fn lnk(values: &Values, id: &mut Identity) {
    // The build machine's NetBIOS name, when the shortcut carries a tracker.
    // The TrackerDataBlock calls it `MachineID`, so that is the field the
    // extractor writes and the claim this reports.
    if let Some(machine) = str_value_at(values, value_key!("lnk.tracker"), "machine_id") {
        id.unique_ids
            .insert("machine_id".into(), machine.to_string());
    }
    if let Some(mac) = str_value_at(values, value_key!("lnk.tracker"), "mac_address") {
        id.unique_ids.insert("mac_address".into(), mac.to_string());
    }
    if let Some(serial) = values
        .lookup_at(value_key!("lnk.volume"), "serial")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(str::to_string))
        })
    {
        id.unique_ids.insert("lnk_volume_serial".into(), serial);
    }
    if let Some(label) = str_value_at(values, value_key!("lnk.volume"), "name") {
        id.unique_ids
            .insert("lnk_volume_label".into(), label.to_string());
    }
}

// ---------------------------------------------------------------------
// Cross-format: build path.
// ---------------------------------------------------------------------

fn build_path(bytes: &[u8], values: &Values, id: &mut Identity) {
    let candidates: Vec<(&str, &str)> = str_value(values, value_key!("pe.debug.pdb.path"))
        .map(|pdb| (pdb, "pe.debug.pdb.path"))
        .into_iter()
        .chain(
            str_array(values, value_key!("elf.dwarf.comp_dirs"))
                .map(|dir| (dir, "elf.dwarf.comp_dirs")),
        )
        .collect();
    // Prefer a path that reveals a user home — the strongest origin
    // signal — over a generic build directory.
    let pick = candidates
        .iter()
        .find(|(p, _)| reveals_home(p))
        .or_else(|| candidates.first());
    if let Some(&(path, source)) = pick {
        id.build_path = Some(Claim::claimed(path, source));
    } else if let Some(home) = home_path_scan(bytes) {
        // A byte scan only when no structured build path was recorded:
        // debug-stripped binaries are the only ones that scan, and even
        // then it is a single shared-automaton pass.
        id.build_path = Some(Claim::claimed(home, "strings"));
    }
}

// ---------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------

/// Map a reverse-DNS identifier to a vendor name (`com.apple.ls` →
/// `Apple`). Only fires on a recognizable TLD-first shape.
fn org_from_reverse_dns(ident: &str) -> Option<String> {
    let mut parts = ident.split('.');
    let tld = parts.next()?;
    if !matches!(
        tld,
        "com" | "org" | "net" | "io" | "co" | "dev" | "app" | "me" | "gnu"
    ) {
        return None;
    }
    let label = parts.next()?;
    let mut chars = label.chars();
    let first = chars.next()?;
    Some(format!("{}{}", first.to_ascii_uppercase(), chars.as_str()))
}

// ---------------------------------------------------------------------
// Interior source identity — WordPress headers, autoconf AC_INIT.
// ---------------------------------------------------------------------

/// Fold `source.*` values (see `formats::source_meta`) into identity. A
/// WordPress plugin's canonical slug is its text domain (`wp-1-slider`),
/// with the display name ("WP 1 Slider") kept as the title; autoconf gives
/// name and version directly. Never overrides an ecosystem-manifest or
/// signed claim already set.
fn source(values: &Values, id: &mut Identity) {
    // The prose display name, tagged with the field it came from (a theme's
    // is a distinct key), so both the title and the name ladder attribute it
    // correctly.
    let display = first_claim(
        values,
        &[
            value_key!("source.wordpress.plugin_name"),
            value_key!("source.wordpress.theme_name"),
        ],
    );
    if let Some((name, src)) = display {
        id.title.get_or_insert_with(|| Claim::claimed(name, src));
    }
    // Name, strongest first: the distribution slug (the archive's top
    // directory, i.e. the WordPress.org package identity) beats the interior
    // text domain, which beats autoconf's package name; the prose display
    // name is the last resort. A standalone plugin PHP has no slug, so it
    // falls through to text domain / display name.
    let name = first_claim(
        values,
        &[
            value_key!("source.wordpress.slug"),
            value_key!("source.wordpress.text_domain"),
            value_key!("source.autoconf.name"),
        ],
    )
    .or(display);
    if let Some((name, src)) = name {
        id.name.get_or_insert_with(|| Claim::claimed(name, src));
    }
    let version = first_claim(
        values,
        &[
            value_key!("source.wordpress.version"),
            value_key!("source.autoconf.version"),
        ],
    );
    if let Some((v, src)) = version {
        id.version.get_or_insert_with(|| Claim::claimed(v, src));
    }
}

/// The first present key's `(value, key)` — the value plus the field to
/// credit it to, so a claim records where it actually came from.
fn first_claim<'a>(values: &'a Values, keys: &[ValueKey]) -> Option<(&'a str, &'static str)> {
    keys.iter()
        .find_map(|&k| str_value(values, k).map(|v| (v, k.as_str())))
}

fn str_value(values: &Values, key: ValueKey) -> Option<&str> {
    values.lookup(key).and_then(JsonValue::as_str)
}

/// [`str_value`] for the path `rest` below `key`: a field of an object the
/// writer emits whole (`pdf.info` → `title`).
fn str_value_at<'a>(values: &'a Values, key: ValueKey, rest: &str) -> Option<&'a str> {
    values.lookup_at(key, rest).and_then(JsonValue::as_str)
}

fn str_array(values: &Values, key: ValueKey) -> impl Iterator<Item = &str> {
    values
        .lookup(key)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
}

/// Every person a package publishes under `key`, as a party in `role`.
fn push_people(id: &mut Identity, values: &Values, key: ValueKey, role: PartyRole) {
    for person in crate::formats::people::read(values, key) {
        push_author(
            id,
            person.name,
            person.email,
            person.url,
            role,
            key.as_str(),
        );
    }
}

fn push_author(
    id: &mut Identity,
    name: Option<String>,
    email: Option<String>,
    url: Option<String>,
    role: PartyRole,
    source: &str,
) {
    if name.is_none() && email.is_none() {
        return;
    }
    // Drop a duplicate party — the same person often appears under more
    // than one role (NuGet author == owner, npm author == maintainer).
    // The first role seen wins.
    if id
        .authors
        .iter()
        .any(|a| a.name == name && a.email == email)
    {
        return;
    }
    id.authors.push(Party {
        name,
        email,
        url,
        role,
        source: source.into(),
    });
}

/// Record a resolved signer certificate under `source`: the organization it
/// names, which outranks any self-asserted one, the trust it confers, and
/// the signer itself.
fn record_signer(id: &mut Identity, ci: CertInfo, source: &str) {
    if let Some(o) = &ci.o {
        id.organization = Some(Claim {
            value: o.clone(),
            source: source.into(),
            verified: ci.verified,
        });
    }
    id.trust = cert_trust(&ci);
    id.signer = Some(signer_struct(ci, source));
}

fn push_url(id: &mut Identity, kind: UrlKind, url: &str, source: &str) {
    id.urls.push(Url {
        kind,
        url: url.to_string(),
        source: source.into(),
    });
}

/// Roll every distinct author email up into the flat `emails` list.
fn finalize(id: &mut Identity) {
    let mut seen = BTreeSet::new();
    id.emails = id
        .authors
        .iter()
        .filter_map(|author| author.email.as_deref())
        .filter(|email| seen.insert(*email))
        .map(str::to_owned)
        .collect();
}

#[cfg(test)]
mod tests;
