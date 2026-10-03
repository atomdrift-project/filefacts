//! Cross-format identity normalization.
//!
//! Every format extractor writes identity facts into its own corner of
//! the [`Values`] tree — `macho.code_signature.identifier`,
//! `pe.version.company`, `office.creator`, `npm.author.email`, … This
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

use std::collections::BTreeSet;
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use serde_json::Value as JsonValue;

use crate::fileid::FileType;
use crate::output::{Claim, Identity, Party, Signer, Trust, Url, UrlKind, ValueKey, Values};
use crate::value_key;

// TODO(sigstore): external-signature verification seam.
//
// `derive` reads only what is *embedded* in the artifact. Detached
// trust material — a Sigstore bundle (DSSE envelope + Fulcio cert +
// Rekor inclusion proof), a cosign `.sig`, a distro `.asc` — lives
// outside the bytes and must be *fetched*, which filefacts will never
// do (it stays offline so it is deterministic and cacheable across
// hundreds of millions of files). The split: cleave fetches the bundle
// and the trusted root; filefacts gets the bytes and merges them here.
//
// The planned entry point is a separate, opt-in function so the default
// path stays byte-pure and zero-cost:
//
//     pub fn verify_external(base: &Identity, material: &[u8],
//                            roots: &TrustRoots) -> Identity
//
// It parses `material` through the same source-agnostic helpers
// (`cert_from_obj` / `signer_struct` / `cert_trust`), then merges
// additively — an artifact with both an embedded Authenticode signer
// and an external attestation surfaces both. Keyless/OIDC identities
// (Fulcio SAN email or CI workflow) extend `Signer` with an optional
// `identity`/`oidc_issuer` field, and `Trust` gains a `Sigstore` tier;
// both are non-breaking additions (`Trust` is already non-exhaustive).

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
            tar(values, &mut id)
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
        .get_key(value_key!("macho.code_signature.identifier"))
        .is_some()
        || values
            .get_key(value_key!("macho.code_signature.cdhash"))
            .is_some()
        || values
            .get_key(value_key!("macho.code_signature.flags"))
            .is_some();
    let cms = values.get_key(value_key!("macho.code_signature.cms"));
    // A verified CMS signature binds the CodeDirectory (its messageDigest is
    // the CodeDirectory's hash), so the fields inside it are proven to be the
    // signer's. A CMS that is merely present proves nothing.
    // The CodeDirectory in turn covers the code only through its hash slots,
    // recomputed from this file into `code_pages_verified`; without them a
    // CodeDirectory and signature lifted from another binary vouch for this
    // one. Alternates must also repeat the signed primary's identity.
    let flag = |key| values.get_key(key).and_then(JsonValue::as_bool);
    let code_bound = flag(value_key!("macho.code_signature.code_pages_verified")) == Some(true)
        && flag(value_key!("macho.code_signature.special_slots_verified")) != Some(false)
        && flag(value_key!(
            "macho.code_signature.code_directories_consistent"
        )) != Some(false);
    let cms_verified = code_bound
        && cms
            .and_then(|c| c.get("verified"))
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);

    if let Some(ident) = get_str(values, value_key!("macho.code_signature.identifier")) {
        id.identifier = Some(Claim {
            value: ident.to_string(),
            source: "macho.code_signature.identifier".into(),
            verified: cms_verified,
        });
    }
    if let Some(team) = get_str(values, value_key!("macho.code_signature.team_id")) {
        id.team_id = Some(Claim {
            value: team.to_string(),
            source: "macho.code_signature.team_id".into(),
            verified: cms_verified,
        });
    }
    if let Some(cdhash) = get_str(values, value_key!("macho.code_signature.cdhash")) {
        id.unique_ids.insert("cdhash".into(), cdhash.to_string());
    }

    if let Some(mut ci) = cms.and_then(cert_from_obj) {
        ci.verified &= code_bound;
        if let Some(o) = &ci.o {
            id.organization = Some(Claim {
                value: o.clone(),
                source: "macho.code_signature.cms".into(),
                verified: ci.verified,
            });
        }
        id.trust = cert_trust(&ci);
        id.signer = Some(signer_struct(&ci, "macho.code_signature.cms"));
    }

    // Trust resolution, in precedence order.
    let platform = values
        .get_key(value_key!("macho.code_signature.platform"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(0);
    let ad_hoc = flag_set(values, value_key!("macho.code_signature.flags"), "ad_hoc");
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
    if id.organization.is_none() && id.trust == Trust::System {
        if let Some(ident) = get_str(values, value_key!("macho.code_signature.identifier")) {
            if let Some(org) = org_from_reverse_dns(ident) {
                id.organization = Some(Claim::claimed(org, "macho.code_signature.identifier"));
            }
        }
    }

    // Apple `what(1)` stamp: `@(#)PROGRAM:ls  PROJECT:file_cmds-479`.
    // Gated to Apple binaries — the only ones that carry it — so the
    // overwhelming majority of Mach-O files never pay for the scan.
    let apple = id.trust == Trust::System
        || get_str(values, value_key!("macho.code_signature.identifier"))
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
    if id.name.is_none() {
        if let Some(install) = get_str(values, value_key!("macho.install_name")) {
            let base = install.rsplit('/').next().unwrap_or(install);
            if !base.is_empty() {
                id.name = Some(Claim::claimed(base, "macho.install_name"));
            }
        }
    }
    if id.name.is_none() {
        if let Some(ident) = get_str(values, value_key!("macho.code_signature.identifier")) {
            if let Some(tail) = ident.rsplit('.').next() {
                id.name = Some(Claim::claimed(tail, "macho.code_signature.identifier"));
            }
        }
    }

    if let Some(sv) = get_str(values, value_key!("macho.source_version")) {
        if sv != "0.0.0" {
            id.version = Some(Claim::claimed(sv, "macho.source_version"));
        }
    }
}

fn pe(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("pe.version.original_filename"))
        .or_else(|| get_str(values, value_key!("pe.version.internal_name")))
    {
        id.name = Some(Claim::claimed(name, "pe.version.original_filename"));
    }
    // ProductName names the larger product/suite the file belongs to —
    // the closest PE analogue to a source project.
    if let Some(product) = get_str(values, value_key!("pe.version.product_name")) {
        id.project = Some(Claim::claimed(product, "pe.version.product_name"));
    }
    if let Some(company) = get_str(values, value_key!("pe.version.company")) {
        id.organization = Some(Claim::claimed(company, "pe.version.company"));
    }
    if let Some(version) = get_str(values, value_key!("pe.version.file_version"))
        .or_else(|| get_str(values, value_key!("pe.version.product_version")))
    {
        id.version = Some(Claim::claimed(version, "pe.version.file_version"));
    }

    let signature = values.get_key_at(value_key!("pe.signatures"), "[0]");
    if let Some(mut ci) = signature.and_then(cert_from_obj) {
        // A signature says nothing about this file unless the image hash it
        // signed is this file's own: one grafted from another binary verifies
        // perfectly while covering that binary. An absent comparison is not a
        // match either, since the Authentihash can be skipped
        // (`pe.image_hash_skipped`).
        ci.verified &= signature
            .and_then(|s| s.get("digest_matches"))
            .and_then(JsonValue::as_bool)
            == Some(true);
        // A verified signer certificate outranks the self-asserted
        // CompanyName for the organization field.
        if let Some(o) = &ci.o {
            id.organization = Some(Claim {
                value: o.clone(),
                source: "pe.signatures[0]".into(),
                verified: ci.verified,
            });
        }
        id.trust = cert_trust(&ci);
        id.signer = Some(signer_struct(&ci, "pe.signatures[0]"));
    }
    if let Some(t) = get_str_at(values, value_key!("pe.signatures"), "[0].thumbprint_sha256") {
        id.unique_ids
            .insert("authenticode_thumbprint_sha256".into(), t.to_string());
    }
}

/// A cabinet's only identity claim is its appended Authenticode signature --
/// CFHEADER carries no publisher, product or version field. The signature blob
/// is published in the PE `signatures[0]` shape, so the mapping is the PE one.
fn cab(values: &Values, id: &mut Identity) {
    if let Some(mut ci) = values
        .get_key_at(value_key!("cab.signatures"), "[0]")
        .and_then(cert_from_obj)
    {
        // Nothing hashes the cabinet to compare with the digest the
        // signature carries, so however well the signature verifies, nothing
        // shows it was made over this cabinet.
        ci.verified = false;
        if let Some(o) = &ci.o {
            id.organization = Some(Claim {
                value: o.clone(),
                source: "cab.signatures[0]".into(),
                verified: ci.verified,
            });
        }
        id.trust = cert_trust(&ci);
        id.signer = Some(signer_struct(&ci, "cab.signatures[0]"));
    }
    if let Some(t) = get_str_at(
        values,
        value_key!("cab.signatures"),
        "[0].thumbprint_sha256",
    ) {
        id.unique_ids
            .insert("authenticode_thumbprint_sha256".into(), t.to_string());
    }
}

/// RAR 5 stores the original archive name and (optionally) the time it was
/// created in a main-header extra record. Both are operator-chosen, so they
/// are unverified claims — the same class of provenance as an ISO volume id.
fn rar(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("rar.original_name")) {
        id.name = Some(Claim::claimed(name, "rar.original_name"));
    }
}

/// ISO 9660 records who made the image in the Primary Volume Descriptor:
/// a volume name, a publisher, a data preparer and the authoring application.
/// They are free text an operator fills in, so every claim here is unverified
/// -- but a mastering tool stamps itself consistently, which is what makes a
/// blank or imitated field worth seeing next to a real one.
fn iso(values: &Values, id: &mut Identity) {
    if let Some(volume) = get_str(values, value_key!("iso.volume_id")) {
        id.name = Some(Claim::claimed(volume, "iso.volume_id"));
    }
    if let Some(publisher) = get_str(values, value_key!("iso.publisher_id")) {
        id.organization = Some(Claim::claimed(publisher, "iso.publisher_id"));
    } else if let Some(preparer) = get_str(values, value_key!("iso.preparer_id")) {
        // The preparer is a weaker claim than the publisher, so it only
        // stands in when no publisher was recorded.
        id.organization = Some(Claim::claimed(preparer, "iso.preparer_id"));
    }
    // `iso.builder` is the normalized mastering-tool name; prefer it over the
    // raw application field it was derived from.
    if let Some(builder) = get_str(values, value_key!("iso.builder")) {
        id.producer = Some(Claim::claimed(builder, "iso.builder"));
    } else if let Some(app) = get_str(values, value_key!("iso.application_id")) {
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
        if let Some(v) = get_str(values, key) {
            id.unique_ids.insert(name.into(), v.to_string());
        }
    }
}

/// A disk image names its volume and records the tool that formatted it --
/// the closest thing a DMG has to provenance, since UDIF itself carries no
/// publisher field and the image need not be signed.
fn dmg(values: &Values, id: &mut Identity) {
    if let Some(volume) = get_str(values, value_key!("dmg.volume.name")) {
        id.name = Some(Claim::claimed(volume, "dmg.volume.name"));
    }
    if let Some(tool) = get_str(values, value_key!("dmg.volume.formatted_by")) {
        id.producer = Some(Claim::claimed(tool, "dmg.volume.formatted_by"));
    }
    // `dmg.volume.last_mounted_version` is deliberately NOT a producer. It is
    // the HFS+ `lastMountedVersion` field, which holds an implementation
    // signature such as `HFSJ` or `10.0` -- the thing that last mounted the
    // volume, not the thing that made the image. Mapping it produced a
    // confident `producer: "HFSJ"` on real samples, which is a fabricated
    // claim, and a wrong identity is worse than an absent one.
}

/// POSIX tar stores the owning user and group *names* beside the numeric ids,
/// so an archive built outside a clean packaging environment carries the
/// build account in it -- the same class of accidental provenance as a PDB
/// path. Recorded as parties rather than as an organization: these name a
/// person or a service account, not a publisher.
fn tar(values: &Values, id: &mut Identity) {
    for key in [
        value_key!("archive.builder.unames"),
        value_key!("archive.builder.gnames"),
    ] {
        let Some(list) = values.get_key(key).and_then(JsonValue::as_array) else {
            continue;
        };
        for name in list.iter().filter_map(JsonValue::as_str) {
            // root/wheel and the like say nothing about who built it.
            if matches!(name, "root" | "wheel" | "staff" | "users" | "nobody" | "") {
                continue;
            }
            if !id.authors.iter().any(|p| p.name.as_deref() == Some(name)) {
                id.authors.push(Party {
                    name: Some(name.to_string()),
                    email: None,
                    url: None,
                    role: "builder".into(),
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
    let Some(module) = values.get_key_at(key, "module") else {
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
        .get_key(value_key!("elf.dwarf.producers"))
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
    if let Some(name) = get_str(values, value_key!("apk.name")) {
        id.name = Some(Claim::claimed(name, "apk.name"));
    }
    if let Some(version) = get_str(values, value_key!("apk.version")) {
        id.version = Some(Claim::claimed(version, "apk.version"));
    }
    // `origin` names the source build a package came out of -- the project,
    // where `pkgname` may be only one of its subpackages.
    if let Some(origin) = get_str(values, value_key!("apk.origin")) {
        id.project = Some(Claim::claimed(origin, "apk.origin"));
    }
    if let Some(builder) = get_str(values, value_key!("apk.builder")) {
        id.producer = Some(Claim::claimed(builder, "apk.builder"));
    }
    // Both fields carry a `Name <email>` contact, the same shape
    // `split_contact` already unpacks for deb and wheel.
    for (key, role) in [
        (value_key!("apk.maintainer"), "maintainer"),
        (value_key!("apk.packager"), "packager"),
    ] {
        if let Some(raw) = get_str(values, key) {
            let (name, email) = split_contact(None, Some(raw));
            push_author(id, name, email, None, role, key.as_str());
        }
    }
    if let Some(url) = get_str(values, value_key!("apk.homepage")) {
        push_url(id, UrlKind::Homepage, url, "apk.homepage");
    }
    // The commit the package was built from, and the digest of its data
    // segment: both pin this artifact to a specific build.
    for (key, name) in [
        (value_key!("apk.commit"), "vcs_commit"),
        (value_key!("apk.datahash"), "apk_datahash"),
    ] {
        if let Some(v) = get_str(values, key)
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
    if let Some(pkg) = get_str(values, value_key!("android.package")) {
        id.identifier = Some(Claim::claimed(pkg, "android.package"));
    }
    // The display label is what a user actually sees, which is what makes it
    // the field an impersonating app fills with a brand it does not own -- but
    // most manifests store it as a reference into `resources.arsc` rather than
    // inline. An unresolved `@0x7f0c0043` is a pointer, not a name, and
    // recording it as one would put a meaningless string in front of an
    // analyst on almost every APK. Only an inline label becomes identity.
    if let Some(label) =
        get_str(values, value_key!("android.app_label")).filter(|l| !l.starts_with("@0x"))
    {
        id.name = Some(Claim::claimed(label, "android.app_label"));
    }
    if let Some(version) = get_str(values, value_key!("android.version_name"))
        .or_else(|| get_str(values, value_key!("android.version_code")))
    {
        id.version = Some(Claim::claimed(version, "android.version_name"));
    }
    if let Some(ci) = values
        .get_key_at(value_key!("android.signatures"), "[0]")
        .and_then(cert_from_obj)
    {
        if let Some(o) = &ci.o {
            id.organization = Some(Claim {
                value: o.clone(),
                source: "android.signatures[0]".into(),
                verified: ci.verified,
            });
        }
        id.trust = cert_trust(&ci);
        id.signer = Some(signer_struct(&ci, "android.signatures[0]"));
    }
    if let Some(t) = get_str_at(
        values,
        value_key!("android.signatures"),
        "[0].thumbprint_sha256",
    ) {
        id.unique_ids
            .insert("apk_signer_thumbprint_sha256".into(), t.to_string());
    }
}

fn crx(values: &Values, id: &mut Identity) {
    if let Some(ext_id) = get_str(values, value_key!("crx.extension_id")) {
        // CRX3 carries the canonical extension id in SignedData. The parser
        // identifies a matching developer proof key when present, but does not
        // cryptographically verify that proof, so this remains an unverified
        // structural claim.
        id.identifier = Some(Claim {
            value: ext_id.to_string(),
            source: "crx.extension_id".into(),
            verified: false,
        });
        id.unique_ids.insert("crx_id".into(), ext_id.to_string());
    }
    if let Some(pk) = get_str(values, value_key!("crx.public_key_sha256")) {
        id.unique_ids
            .insert("public_key_sha256".into(), pk.to_string());
        id.trust = Trust::Unverified;
    }
    // Developer-declared author from the extension manifest.
    push_author(
        id,
        get_str(values, value_key!("crx.author")).map(str::to_string),
        get_str(values, value_key!("crx.author_email")).map(str::to_string),
        None,
        "author",
        "crx.author",
    );
    if let Some(home) = get_str(values, value_key!("crx.homepage")) {
        push_url(id, UrlKind::Homepage, home, "crx.homepage");
    }
}

// ---------------------------------------------------------------------
// Package manifests — claimed identity.
// ---------------------------------------------------------------------

fn xpi(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("xpi.name")) {
        id.name = Some(Claim::claimed(name, "xpi.name"));
    }
    if let Some(version) = get_str(values, value_key!("xpi.version")) {
        id.version = Some(Claim::claimed(version, "xpi.version"));
    }
    push_author(
        id,
        get_str(values, value_key!("xpi.author")).map(str::to_string),
        None,
        None,
        "author",
        "xpi.author",
    );
    if let Some(home) = get_str(values, value_key!("xpi.homepage")) {
        push_url(id, UrlKind::Homepage, home, "xpi.homepage");
    }
}

fn nupkg(values: &Values, id: &mut Identity) {
    if let Some(pkg_id) = get_str(values, value_key!("nupkg.name")) {
        id.identifier = Some(Claim::claimed(pkg_id, "nupkg.name"));
    }
    if let Some(name) = get_str(values, value_key!("nupkg.title"))
        .or_else(|| get_str(values, value_key!("nupkg.name")))
    {
        id.name = Some(Claim::claimed(name, "nupkg.title"));
    }
    if let Some(version) = get_str(values, value_key!("nupkg.version")) {
        id.version = Some(Claim::claimed(version, "nupkg.version"));
    }
    for author in split_list(get_str(values, value_key!("nupkg.authors"))) {
        push_author(id, Some(author), None, None, "author", "nupkg.authors");
    }
    for owner in split_list(get_str(values, value_key!("nupkg.owners"))) {
        push_author(id, Some(owner), None, None, "owner", "nupkg.owners");
    }
    if let Some(url) = get_str(values, value_key!("nupkg.homepage")) {
        push_url(id, UrlKind::Homepage, url, "nupkg.homepage");
    }
    if let Some(url) = get_str(values, value_key!("nupkg.repository")) {
        push_url(id, UrlKind::Repository, url, "nupkg.repository");
    }
}

fn vsix(values: &Values, id: &mut Identity) {
    if let Some(ext_id) = get_str_at(values, value_key!("vsix.identity"), "id") {
        id.identifier = Some(Claim::claimed(ext_id, "vsix.identity.id"));
        if id.name.is_none() {
            if let Some(tail) = ext_id.rsplit('.').next() {
                id.name = Some(Claim::claimed(tail, "vsix.identity.id"));
            }
        }
    }
    if let Some(display) = get_str(values, value_key!("vsix.display_name")) {
        id.name = Some(Claim::claimed(display, "vsix.display_name"));
    }
    if let Some(version) = get_str_at(values, value_key!("vsix.identity"), "version") {
        id.version = Some(Claim::claimed(version, "vsix.identity.version"));
    }
    if let Some(publisher) = get_str_at(values, value_key!("vsix.identity"), "publisher") {
        id.team_id = Some(Claim::claimed(publisher, "vsix.identity.publisher"));
    }
}

fn wheel(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("whl.distribution")) {
        id.name = Some(Claim::claimed(name, "whl.distribution"));
    }
    if let Some(version) = get_str(values, value_key!("whl.version")) {
        id.version = Some(Claim::claimed(version, "whl.version"));
    }
    // Authorship from the dist-info METADATA. `*-email` fields may carry a
    // bare address or a `Name <email>` pair.
    let (a_name, a_email) = split_contact(
        get_str(values, value_key!("whl.author")),
        get_str(values, value_key!("whl.author_email")),
    );
    push_author(id, a_name, a_email, None, "author", "whl.author");
    let (m_name, m_email) = split_contact(
        get_str(values, value_key!("whl.maintainer")),
        get_str(values, value_key!("whl.maintainer_email")),
    );
    push_author(id, m_name, m_email, None, "maintainer", "whl.maintainer");
    if let Some(home) = get_str(values, value_key!("whl.homepage")) {
        push_url(id, UrlKind::Homepage, home, "whl.homepage");
    }
}

fn jar(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str_at(values, value_key!("jar.manifest"), "implementation_title")
        .or_else(|| get_str_at(values, value_key!("jar.pom"), "artifact_id"))
    {
        id.name = Some(Claim::claimed(name, "jar.manifest.implementation_title"));
    }
    if let Some(version) = get_str_at(values, value_key!("jar.manifest"), "implementation_version")
        .or_else(|| get_str_at(values, value_key!("jar.pom"), "version"))
    {
        id.version = Some(Claim::claimed(
            version,
            "jar.manifest.implementation_version",
        ));
    }
    // Maven coordinates form a stable `group:artifact` identifier.
    if let (Some(group), Some(artifact)) = (
        get_str_at(values, value_key!("jar.pom"), "group_id"),
        get_str_at(values, value_key!("jar.pom"), "artifact_id"),
    ) {
        id.identifier = Some(Claim::claimed(format!("{group}:{artifact}"), "jar.pom"));
    }
    if let Some(vendor) = get_str_at(values, value_key!("jar.manifest"), "implementation_vendor")
        .or_else(|| get_str_at(values, value_key!("jar.manifest"), "bundle_vendor"))
        .or_else(|| get_str_at(values, value_key!("jar.manifest"), "specification_vendor"))
    {
        id.organization = Some(Claim::claimed(vendor, "jar.manifest.implementation_vendor"));
    }
    if let Some(producer) = get_str_at(values, value_key!("jar.manifest"), "created_by") {
        id.producer = Some(Claim::claimed(producer, "jar.manifest.created_by"));
    }
    // `Built-By` is the build account — an origin-host artifact, the JAR
    // analogue of a binary's embedded build path.
    if let Some(built_by) = get_str_at(values, value_key!("jar.manifest"), "built_by") {
        id.unique_ids
            .insert("build_user".into(), built_by.to_string());
    }
}

fn gem(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("gem.name")) {
        id.name = Some(Claim::claimed(name, "gem.name"));
    }
    if let Some(version) = get_str(values, value_key!("gem.version")) {
        id.version = Some(Claim::claimed(version, "gem.version"));
    }
    for author in str_array(values, value_key!("gem.authors")) {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            "author",
            "gem.authors",
        );
    }
    if let Some(home) = get_str(values, value_key!("gem.homepage")) {
        push_url(id, UrlKind::Homepage, home, "gem.homepage");
    }
}

fn npm(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("npm.name")) {
        id.name = Some(Claim::claimed(name, "npm.name"));
        id.identifier = Some(Claim::claimed(name, "npm.name"));
    }
    if let Some(version) = get_str(values, value_key!("npm.version")) {
        id.version = Some(Claim::claimed(version, "npm.version"));
    }
    push_author(
        id,
        get_str_at(values, value_key!("npm.author"), "name").map(str::to_string),
        get_str_at(values, value_key!("npm.author"), "email").map(str::to_string),
        get_str_at(values, value_key!("npm.author"), "url").map(str::to_string),
        "author",
        "npm.author",
    );
    if let Some(JsonValue::Array(maintainers)) = values.get_key(value_key!("npm.maintainers")) {
        for m in maintainers {
            push_author(
                id,
                m.get("name")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                m.get("email")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                m.get("url").and_then(JsonValue::as_str).map(str::to_string),
                "maintainer",
                "npm.maintainers",
            );
        }
    }
    if let Some(repo) = get_str(values, value_key!("npm.repository.url")) {
        push_url(id, UrlKind::Repository, repo, "npm.repository.url");
    }
    if let Some(home) = get_str(values, value_key!("npm.homepage")) {
        push_url(id, UrlKind::Homepage, home, "npm.homepage");
    }
}

fn rust_crate(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("crate.name")) {
        id.name = Some(Claim::claimed(name, "crate.name"));
        id.identifier = Some(Claim::claimed(name, "crate.name"));
    }
    if let Some(version) = get_str(values, value_key!("crate.version")) {
        id.version = Some(Claim::claimed(version, "crate.version"));
    }
    for author in str_array(values, value_key!("crate.authors")) {
        let (name, email, _) = parse_person(author);
        push_author(id, name, email, None, "author", "crate.authors");
    }
    if let Some(repo) = get_str(values, value_key!("crate.repository")) {
        push_url(id, UrlKind::Repository, repo, "crate.repository");
    }
    if let Some(home) = get_str(values, value_key!("crate.homepage")) {
        push_url(id, UrlKind::Homepage, home, "crate.homepage");
    }
}

fn python_sdist(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("python.name")) {
        id.name = Some(Claim::claimed(name, "python.name"));
        id.identifier = Some(Claim::claimed(name, "python.name"));
    }
    if let Some(version) = get_str(values, value_key!("python.version")) {
        id.version = Some(Claim::claimed(version, "python.version"));
    }
    push_author(
        id,
        get_str_at(values, value_key!("python.author"), "name").map(str::to_string),
        get_str_at(values, value_key!("python.author"), "email").map(str::to_string),
        None,
        "author",
        "python.author",
    );
    push_author(
        id,
        get_str_at(values, value_key!("python.maintainer"), "name").map(str::to_string),
        get_str_at(values, value_key!("python.maintainer"), "email").map(str::to_string),
        None,
        "maintainer",
        "python.maintainer",
    );
    if let Some(home) = get_str(values, value_key!("python.homepage")) {
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
    if let Some(name) = get_str(values, value_key!("rpm.name")) {
        id.name = Some(Claim::claimed(name, "rpm.name"));
    }
    if let Some(version) = get_str(values, value_key!("rpm.version")) {
        id.version = Some(Claim::claimed(version, "rpm.version"));
    }
    if let Some(vendor) = get_str(values, value_key!("rpm.vendor")) {
        id.organization = Some(Claim::claimed(vendor, "rpm.vendor"));
    }
    if let Some(packager) = get_str(values, value_key!("rpm.packager")) {
        let (name, email, url) = parse_person(packager);
        push_author(id, name, email, url, "packager", "rpm.packager");
    }
    if let Some(url) = get_str(values, value_key!("rpm.homepage")) {
        push_url(id, UrlKind::Homepage, url, "rpm.homepage");
    }
}

fn deb(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, value_key!("deb.name")) {
        id.name = Some(Claim::claimed(name, "deb.name"));
    }
    if let Some(version) = get_str(values, value_key!("deb.version")) {
        id.version = Some(Claim::claimed(version, "deb.version"));
    }
    if let Some(maintainer) = get_str(values, value_key!("deb.maintainer")) {
        let (name, email, url) = parse_person(maintainer);
        push_author(id, name, email, url, "maintainer", "deb.maintainer");
    }
}

/// Self-description keys, one per package format: npm `description`, wheel
/// and sdist `Summary`, crate `description`, gem `summary`, NuGet
/// `<description>`, VSIX `<Description>`, WebExtension `description`, and the
/// deb / rpm / Alpine one-line synopsis, and a PE's `FileDescription`. Each is
/// emitted only by its own format's extractor, so the first present key is the
/// artifact's.
const DESCRIPTION_KEYS: &[ValueKey] = &[
    value_key!("npm.description"),
    value_key!("whl.summary"),
    value_key!("python.summary"),
    value_key!("crate.description"),
    value_key!("gem.summary"),
    value_key!("nupkg.description"),
    value_key!("vsix.description"),
    value_key!("crx.description"),
    value_key!("xpi.description"),
    value_key!("deb.summary"),
    value_key!("rpm.summary"),
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
        .find_map(|&(key, field)| Some((get_str_at(values, key, field)?, key, field)))
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
    if let Some(title) = get_str(values, value_key!("office.title")) {
        id.title = Some(Claim::claimed(title, "office.title"));
    }
    if let Some(creator) = get_str(values, value_key!("office.creator")) {
        push_author(
            id,
            Some(creator.to_string()),
            None,
            None,
            "author",
            "office.creator",
        );
    }
    if let Some(modifier) = get_str(values, value_key!("office.last_modified_by")) {
        push_author(
            id,
            Some(modifier.to_string()),
            None,
            None,
            "last_modified_by",
            "office.last_modified_by",
        );
    }
    if let Some(manager) = get_str(values, value_key!("office.manager")) {
        push_author(
            id,
            Some(manager.to_string()),
            None,
            None,
            "manager",
            "office.manager",
        );
    }
    if let Some(company) = get_str(values, value_key!("office.company")) {
        id.organization = Some(Claim::claimed(company, "office.company"));
    }
    if let Some(app) = get_str(values, value_key!("office.application")) {
        id.producer = Some(Claim::claimed(app, "office.application"));
    }
}

fn pdf(values: &Values, id: &mut Identity) {
    if let Some(title) = get_str_at(values, value_key!("pdf.info"), "title") {
        id.title = Some(Claim::claimed(title, "pdf.info.title"));
    }
    if let Some(author) = get_str_at(values, value_key!("pdf.info"), "author") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            "author",
            "pdf.info.author",
        );
    }
    if let Some(producer) = get_str_at(values, value_key!("pdf.info"), "producer")
        .or_else(|| get_str_at(values, value_key!("pdf.info"), "creator"))
    {
        id.producer = Some(Claim::claimed(producer, "pdf.info.producer"));
    }
}

fn rtf(values: &Values, id: &mut Identity) {
    if let Some(title) = get_str_at(values, value_key!("rtf.info"), "title") {
        id.title = Some(Claim::claimed(title, "rtf.info.title"));
    }
    if let Some(author) = get_str_at(values, value_key!("rtf.info"), "author") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            "author",
            "rtf.info.author",
        );
    }
    if let Some(company) = get_str_at(values, value_key!("rtf.info"), "company") {
        id.organization = Some(Claim::claimed(company, "rtf.info.company"));
    }
}

fn png(values: &Values, id: &mut Identity) {
    if let Some(software) = get_str_at(values, value_key!("png.text"), "software") {
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
    if let Some(machine) = get_str_at(values, value_key!("lnk.tracker"), "machine_id") {
        id.unique_ids
            .insert("machine_id".into(), machine.to_string());
    }
    if let Some(mac) = get_str_at(values, value_key!("lnk.tracker"), "mac_address") {
        id.unique_ids.insert("mac_address".into(), mac.to_string());
    }
    if let Some(serial) = values
        .get_key_at(value_key!("lnk.volume"), "serial")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(str::to_string))
        })
    {
        id.unique_ids.insert("lnk_volume_serial".into(), serial);
    }
    if let Some(label) = get_str_at(values, value_key!("lnk.volume"), "name") {
        id.unique_ids
            .insert("lnk_volume_label".into(), label.to_string());
    }
}

// ---------------------------------------------------------------------
// Cross-format: build path.
// ---------------------------------------------------------------------

fn build_path(bytes: &[u8], values: &Values, id: &mut Identity) {
    let mut candidates: Vec<(String, &'static str)> = Vec::new();
    if let Some(pdb) = get_str(values, value_key!("pe.debug.pdb.path")) {
        candidates.push((pdb.to_string(), "pe.debug.pdb.path"));
    }
    for dir in str_array(values, value_key!("elf.dwarf.comp_dirs")) {
        candidates.push((dir.to_string(), "elf.dwarf.comp_dirs"));
    }
    // Fall back to a byte scan only when no structured build path was
    // recorded — debug-stripped binaries are the only ones that scan,
    // and even then it is a single shared-automaton pass.
    if candidates.is_empty() {
        if let Some(home) = home_path_scan(bytes) {
            candidates.push((home, "strings"));
        }
    }

    // Prefer a path that reveals a user home — the strongest origin
    // signal — over a generic build directory.
    let pick = candidates
        .iter()
        .find(|(p, _)| reveals_home(p))
        .or_else(|| candidates.first());
    if let Some((path, source)) = pick {
        id.build_path = Some(Claim::claimed(path.clone(), *source));
    }
}

fn reveals_home(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/users/") || lower.contains("/home/") || lower.contains("\\users\\")
}

/// The three home-path prefixes, matched in one pass by a shared
/// automaton. Pattern index 2 (`C:\Users\`) uses the Windows byte
/// class; the others use the Unix class.
fn home_finder() -> &'static AhoCorasick {
    static FINDER: OnceLock<AhoCorasick> = OnceLock::new();
    FINDER.get_or_init(|| {
        AhoCorasick::new(["/Users/", "/home/", "C:\\Users\\"])
            .expect("static home-path patterns are valid")
    })
}

/// Find the first user-home path embedded in the bytes and return it
/// verbatim. A single shared-automaton forward pass over the file.
fn home_path_scan(bytes: &[u8]) -> Option<String> {
    let m = home_finder().find(bytes)?;
    let windows = m.pattern().as_usize() == 2;
    let is_path_byte = if windows {
        is_win_path_byte
    } else {
        is_unix_path_byte
    };
    let path = bytes
        .get(m.start()..)?
        .split(|&b| !is_path_byte(b))
        .next()?;
    // Require at least one path byte past the prefix (a real username).
    if path.len() <= m.len() {
        return None;
    }
    std::str::from_utf8(path).ok().map(str::to_string)
}

fn is_unix_path_byte(b: u8) -> bool {
    matches!(b, b'/' | b'.' | b'-' | b'_' | b'+' | b'~' | b'@') || b.is_ascii_alphanumeric()
}

fn is_win_path_byte(b: u8) -> bool {
    matches!(
        b,
        b'\\' | b':' | b'.' | b'-' | b'_' | b'+' | b'~' | b'@' | b' '
    ) || b.is_ascii_alphanumeric()
}

// ---------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------

/// Resolved fields from a signature / CMS object.
struct CertInfo {
    cn: Option<String>,
    o: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    self_issued: bool,
    verified: bool,
    /// The platform root the verified chain ends at (`chain_anchor`).
    anchor: Option<String>,
    signed_at: Option<String>,
}

fn cert_from_obj(obj: &JsonValue) -> Option<CertInfo> {
    let subject = obj
        .get("subject")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let issuer = obj
        .get("issuer")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    if subject.is_none() && issuer.is_none() {
        return None;
    }
    let cn = subject.as_deref().and_then(|d| dn_attr(d, "CN"));
    let o = subject.as_deref().and_then(|d| dn_attr(d, "O"));
    let self_issued = obj
        .get("self_issued")
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| subject.is_some() && subject == issuer);
    let verified = obj
        .get("verified")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    let anchor = obj
        .get("chain_anchor")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let signed_at = obj
        .get("signing_time")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    Some(CertInfo {
        cn,
        o,
        subject,
        issuer,
        self_issued,
        verified,
        anchor,
        signed_at,
    })
}

fn signer_struct(ci: &CertInfo, source: &str) -> Signer {
    Signer {
        common_name: ci.cn.clone(),
        organization: ci.o.clone(),
        subject: ci.subject.clone(),
        issuer: ci.issuer.clone(),
        signed_at: ci.signed_at.clone(),
        source: source.into(),
    }
}

/// Trust tier of one signature object.
///
/// Only cryptography lifts a signature above `Unverified`: `verified` must be
/// true, which means the signer's key signed the attributes and those bind
/// the signed content. A certificate's names decide nothing on their own,
/// since anyone minting a certificate chooses them, so the vendor tiers also
/// require `chain_anchor`: a verified chain ending at the vendor's own root.
/// Within an anchored chain the leaf's names then pick the tier, by exact
/// match: Apple's `Developer ID ` certificates are `DeveloperId`, and a leaf
/// whose organization is the vendor itself is `Platform`. Every other
/// verified signature, including one under a vendor root issued to a third
/// party, is `CaSigned` — a CA signed it, and which CAs to trust is left to
/// consumers pinning `chain_sha256`.
fn cert_trust(ci: &CertInfo) -> Trust {
    if !ci.verified {
        return Trust::Unverified;
    }
    if ci.self_issued {
        return Trust::SelfSigned;
    }
    let organization = ci.o.as_deref();
    match ci.anchor.as_deref() {
        Some("apple")
            if ci
                .cn
                .as_deref()
                .is_some_and(|cn| cn.starts_with("Developer ID ")) =>
        {
            Trust::DeveloperId
        }
        Some("apple") if organization == Some("Apple Inc.") => Trust::Platform,
        Some("microsoft") if organization == Some("Microsoft Corporation") => Trust::Platform,
        _ => Trust::CaSigned,
    }
}

/// Pull one attribute value out of an RFC 4514 distinguished name.
/// Handles `\`-escaping and `,`/`+` separators.
fn dn_attr(dn: &str, attr: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in dn.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ',' || c == '+' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    for part in parts {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            if key.trim().eq_ignore_ascii_case(attr) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

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

/// Split a `Name <email> (url)` person string into its parts.
fn parse_person(s: &str) -> (Option<String>, Option<String>, Option<String>) {
    let email = between(s, '<', '>');
    let url = between(s, '(', ')');
    let name_end = s.find('<').or_else(|| s.find('(')).unwrap_or(s.len());
    let name = s[..name_end].trim();
    let name = (!name.is_empty()).then(|| name.to_string());
    (name, email, url)
}

fn between(s: &str, open: char, close: char) -> Option<String> {
    let start = s.find(open)?;
    let end = s[start + 1..].find(close)? + start + 1;
    let inner = s[start + 1..end].trim();
    (!inner.is_empty()).then(|| inner.to_string())
}

/// Resolve a separate name field and an email field (which may itself be
/// a bare address or a `Name <email>` pair) into `(name, email)`. The
/// dedicated name field wins; otherwise a name embedded in the email
/// field is used.
fn split_contact(name: Option<&str>, email: Option<&str>) -> (Option<String>, Option<String>) {
    let mut display = name.map(str::to_string);
    let mut addr = None;
    if let Some(raw) = email {
        if let Some(inner) = between(raw, '<', '>') {
            addr = Some(inner);
            if display.is_none() {
                let embedded = raw[..raw.find('<').unwrap_or(raw.len())].trim();
                if !embedded.is_empty() {
                    display = Some(embedded.to_string());
                }
            }
        } else if !raw.is_empty() {
            addr = Some(raw.to_string());
        }
    }
    (display, addr)
}

/// Scan for a `KEY:value` token (Apple `what(1)` stamps), returning the
/// value up to the next whitespace / control byte.
fn scan_token(bytes: &[u8], needle: &[u8]) -> Option<String> {
    let pos = memchr::memmem::find(bytes, needle)?;
    let after = bytes.get(pos + needle.len()..)?;
    let start = after.iter().position(|&b| b != b' ' && b != b'\t')?;
    let token = after
        .get(start..)?
        .split(|&b| b <= b' ' || b == 0x7f)
        .next()?;
    if token.is_empty() {
        return None;
    }
    std::str::from_utf8(token).ok().map(str::to_string)
}

// ---------------------------------------------------------------------
// Interior source identity — WordPress headers, autoconf AC_INIT.
// ---------------------------------------------------------------------

/// Fold `source.*` values (see [`super::source_meta`]) into identity. A
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
        .find_map(|&k| get_str(values, k).map(|v| (v, k.as_str())))
}

// ---------------------------------------------------------------------
// Filename fallback — the FTP era's version resource.
// ---------------------------------------------------------------------

/// Archive extensions whose stems conventionally encode `<name><sep><version>`.
/// Deliberately scoped to source/archive containers: package formats (rpm,
/// whl, nupkg, gem, …) carry real metadata their extractors already surface,
/// and a filename guess must never shadow it. Longest form first so
/// `.tar.gz` wins over `.tar`; matched case-insensitively for the era's
/// `.tar.Z` (compress) spelling.
const ARCHIVE_EXTS: &[&str] = &[
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.z", ".tgz", ".tbz2", ".txz", ".taz",
    ".tar", ".zip",
];

/// Fill `name`/`version` from the artifact's own filename when no embedded
/// source claimed them. `file.basename` is recorded by extraction whenever
/// the caller supplied a path.
fn filename_fallback(values: &Values, id: &mut Identity) {
    if id.name.is_some() {
        return;
    }
    let Some(base) = get_str(values, value_key!("file.basename")) else {
        return;
    };
    let Some((name, version)) = split_name_version(base) else {
        return;
    };
    id.name = Some(Claim::claimed(name, "file.basename"));
    if id.version.is_none() {
        id.version = Some(Claim::claimed(version, "file.basename"));
    }
}

/// Split an archive filename into its conventional `(name, version)`:
/// `wuftpd-10.9.2.tgz` → ("wuftpd", "10.9.2"), covering the hyphen,
/// underscore (`apache_1.3.9`), and dotted (`sendmail.8.9.1`) separators of
/// thirty years of source releases. Conservative by construction: the stem
/// must end in a known archive extension and the boundary is the first
/// separator whose remainder is version-shaped (digit-led after an optional
/// `v`); anything else returns `None` rather than guessing. A leading
/// `YYYY-MM-DD-` disclosure stamp (threat-feed dataset naming) is stripped
/// first, mirroring hopper's pkgparse.
fn split_name_version(base: &str) -> Option<(&str, &str)> {
    // Case-insensitive suffix match without lowercasing the whole name — the
    // era's `.tar.Z` folds onto `.tar.z` here.
    let ext_len = ARCHIVE_EXTS.iter().find_map(|ext| {
        let start = base.len().checked_sub(ext.len())?;
        base.get(start..)?
            .eq_ignore_ascii_case(ext)
            .then_some(ext.len())
    })?;
    let stem = strip_date_prefix(&base[..base.len() - ext_len]);
    // The boundary is the first separator whose remainder is version-shaped:
    // digit-led (after an optional `v`), then the usual version alphabet. A
    // separator at position 0 would leave no name, and one at the end leaves
    // an empty remainder, which is not digit-led.
    for (i, _) in stem.match_indices(['-', '_', '.']).filter(|&(i, _)| i > 0) {
        let rest = &stem[i + 1..];
        let mut tail = rest.strip_prefix('v').unwrap_or(rest).chars();
        if tail.next().is_some_and(|c| c.is_ascii_digit())
            && tail.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-'))
        {
            return Some((&stem[..i], rest));
        }
    }
    None
}

/// Strip a leading `YYYY-MM-DD-` date stamp, digit-bounded so version-like
/// names ("2020-vision") survive intact.
fn strip_date_prefix(stem: &str) -> &str {
    let Some((date, rest)) = stem.as_bytes().split_first_chunk::<11>() else {
        return stem;
    };
    // Shape first — digits where digits belong, dashes at 4, 7 and 10 — then
    // the cheap plausibility bounds: a 1000s/2000s year, month < 20, day < 40.
    let stamped = !rest.is_empty()
        && date.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 | 10 => c == b'-',
            _ => c.is_ascii_digit(),
        })
        && matches!(date[0], b'1' | b'2')
        && date[5] <= b'1'
        && date[8] <= b'3';
    if stamped {
        stem.get(11..).unwrap_or(stem)
    } else {
        stem
    }
}

fn get_str(values: &Values, key: ValueKey) -> Option<&str> {
    values.get_key(key).and_then(JsonValue::as_str)
}

/// [`get_str`] for the path `rest` below `key`: a field of an object the
/// writer emits whole (`pdf.info` → `title`) or an array element
/// (`pe.signatures` → `[0].thumbprint_sha256`).
fn get_str_at<'a>(values: &'a Values, key: ValueKey, rest: &str) -> Option<&'a str> {
    values.get_key_at(key, rest).and_then(JsonValue::as_str)
}

fn str_array(values: &Values, key: ValueKey) -> impl Iterator<Item = &str> {
    values
        .get_key(key)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
}

/// Split a comma-separated field (NuGet `authors`/`owners`) into trimmed,
/// non-empty entries.
fn split_list(value: Option<&str>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn flag_set(values: &Values, key: ValueKey, flag: &str) -> bool {
    values
        .get_key(key)
        .and_then(JsonValue::as_array)
        .is_some_and(|a| a.iter().filter_map(JsonValue::as_str).any(|s| s == flag))
}

fn push_author(
    id: &mut Identity,
    name: Option<String>,
    email: Option<String>,
    url: Option<String>,
    role: &str,
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
        role: role.into(),
        source: source.into(),
    });
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
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut emails: Vec<String> = Vec::new();
    for author in &id.authors {
        if let Some(email) = &author.email {
            if seen.insert(email.as_str()) {
                emails.push(email.clone());
            }
        }
    }
    id.emails = emails;
}

#[cfg(test)]
mod filename_tests {
    use super::split_name_version;

    #[test]
    fn era_conventions_split() {
        // (filename, name, version) — real release names spanning the eras.
        for (base, name, version) in [
            ("wuftpd-10.9.2.tgz", "wuftpd", "10.9.2"),
            ("sendmail-8.9.1.tgz", "sendmail", "8.9.1"),
            ("sendmail.8.9.1.tar.gz", "sendmail", "8.9.1"),
            ("apache_1.3.9.tar.gz", "apache", "1.3.9"),
            ("bind-4.9.5-P1.tar.gz", "bind", "4.9.5-P1"),
            ("ncompress-4.2.4.tar.Z", "ncompress", "4.2.4"),
            ("elm-2.5.8.tar.gz", "elm", "2.5.8"),
            ("R-4.0.0.tar.gz", "R", "4.0.0"),
            ("Template-Toolkit-3.102.tar.gz", "Template-Toolkit", "3.102"),
            ("lodash-4.17.21.tgz", "lodash", "4.17.21"),
            (
                "github.com-gorilla-mux-v1.8.1.zip",
                "github.com-gorilla-mux",
                "v1.8.1",
            ),
            ("2020-vision-1.0.0.tgz", "2020-vision", "1.0.0"),
        ] {
            let got = split_name_version(base);
            assert_eq!(got, Some((name, version)), "split_name_version({base:?})");
        }
    }

    #[test]
    fn date_stamped_dataset_names_shed_the_stamp() {
        assert_eq!(
            split_name_version("2026-03-18-big-nunber-v5.0.5.zip"),
            Some(("big-nunber", "v5.0.5")),
        );
    }

    #[test]
    fn non_conforming_names_yield_nothing() {
        for base in [
            "evil.exe",        // not an archive extension
            "MetaStealer.zip", // no version tail
            "notes.tar",       // no separator+digit boundary
            "60d11b7004c80ae17a900094bbddd0a92273167af2b15f7597b9749d1b5edaa2",
            "backup.tar.gz", // versionless
        ] {
            assert_eq!(split_name_version(base), None, "{base:?} must not split");
        }
    }
}

#[cfg(test)]
mod go_module_identity_tests {
    use super::{Claim, Identity, Values, go_module};
    use crate::value_key;

    fn go_values(prefix: &str, module: &serde_json::Value) -> Values {
        let mut v = Values::default();
        v.insert(
            &format!("{prefix}.go"),
            serde_json::json!({ "module": module }),
        );
        v
    }

    #[test]
    fn go_main_module_names_an_unlabelled_binary() {
        let values = go_values(
            "pe",
            &serde_json::json!({"path": "github.com/gitleaks/gitleaks", "version": "v8.18.0"}),
        );
        let mut id = Identity::default();
        go_module(value_key!("pe.go"), &values, &mut id);
        assert_eq!(id.project.unwrap().value, "github.com/gitleaks/gitleaks");
        assert_eq!(id.version.unwrap().value, "v8.18.0");
    }

    #[test]
    fn go_main_module_yields_to_a_version_resource() {
        let values = go_values(
            "elf",
            &serde_json::json!({"path": "example.com/tool", "version": "(devel)"}),
        );
        let mut id = Identity {
            project: Some(Claim::claimed("Acme Suite", "pe.version.product_name")),
            ..Identity::default()
        };
        go_module(value_key!("elf.go"), &values, &mut id);
        assert_eq!(id.project.unwrap().value, "Acme Suite");
        assert!(id.version.is_none(), "`(devel)` is not a version");
    }
}

#[cfg(test)]
mod container_identity_tests {
    use super::{Identity, Values, dmg, iso, tar};

    fn values_from(pairs: &[(&str, serde_json::Value)]) -> Values {
        let mut v = Values::default();
        for (k, val) in pairs {
            v.insert(k, val.clone());
        }
        v
    }

    #[test]
    fn iso_volume_descriptor_becomes_identity() {
        let values = values_from(&[
            ("iso.volume_id", serde_json::json!("DESKTOP")),
            ("iso.publisher_id", serde_json::json!("ACME LTD")),
            ("iso.preparer_id", serde_json::json!("SHOULD NOT WIN")),
            ("iso.builder", serde_json::json!("imgburn")),
            ("iso.application_id", serde_json::json!("SHOULD NOT WIN")),
            (
                "iso.udf.implementation_id",
                serde_json::json!("*UDF LV Info"),
            ),
        ]);
        let mut id = Identity::default();
        iso(&values, &mut id);
        assert_eq!(id.name.unwrap().value, "DESKTOP");
        // Publisher outranks preparer; the normalized builder outranks the raw
        // application field it was derived from.
        assert_eq!(id.organization.unwrap().value, "ACME LTD");
        assert_eq!(id.producer.unwrap().value, "imgburn");
        assert_eq!(
            id.unique_ids
                .get("udf_implementation_id")
                .map(String::as_str),
            Some("*UDF LV Info")
        );
    }

    #[test]
    fn iso_preparer_stands_in_only_without_a_publisher() {
        let values = values_from(&[("iso.preparer_id", serde_json::json!("PREPARER"))]);
        let mut id = Identity::default();
        iso(&values, &mut id);
        assert_eq!(id.organization.unwrap().value, "PREPARER");
    }

    #[test]
    fn dmg_does_not_invent_a_producer_from_the_hfs_mount_signature() {
        // `HFSJ` / `10.0` are HFS+ lastMountedVersion values, not tools. An
        // earlier draft mapped this field and produced a confident but
        // fabricated `producer` on real samples.
        let values = values_from(&[("dmg.volume.last_mounted_version", serde_json::json!("HFSJ"))]);
        let mut id = Identity::default();
        dmg(&values, &mut id);
        assert!(id.producer.is_none(), "{:?}", id.producer);
    }

    #[test]
    fn tar_owner_names_become_builder_parties_without_generic_accounts() {
        let values = values_from(&[
            (
                "archive.builder.unames",
                serde_json::json!(["jenkins", "root"]),
            ),
            (
                "archive.builder.gnames",
                serde_json::json!(["staff", "devs"]),
            ),
        ]);
        let mut id = Identity::default();
        tar(&values, &mut id);
        let names: Vec<_> = id
            .authors
            .iter()
            .filter_map(|p| p.name.as_deref())
            .collect();
        assert_eq!(names, vec!["jenkins", "devs"]);
        assert!(id.authors.iter().all(|p| p.role == "builder"));
    }
}

#[cfg(test)]
mod android_identity_tests {
    use super::{Identity, Values, apk_android};

    fn values_from(pairs: &[(&str, serde_json::Value)]) -> Values {
        let mut v = Values::default();
        for (k, val) in pairs {
            v.insert(k, val.clone());
        }
        v
    }

    #[test]
    fn package_is_the_identifier_and_inline_label_is_the_name() {
        let values = values_from(&[
            ("android.package", serde_json::json!("com.example.app")),
            ("android.app_label", serde_json::json!("Ameli")),
            ("android.version_name", serde_json::json!("1.2.3")),
        ]);
        let mut id = Identity::default();
        apk_android(&values, &mut id);
        assert_eq!(id.identifier.unwrap().value, "com.example.app");
        assert_eq!(id.name.unwrap().value, "Ameli");
        assert_eq!(id.version.unwrap().value, "1.2.3");
    }

    #[test]
    fn an_unresolved_resource_reference_is_not_a_name() {
        // Most manifests store the label as a pointer into resources.arsc.
        let values = values_from(&[
            ("android.package", serde_json::json!("com.example.app")),
            ("android.app_label", serde_json::json!("@0x7f0c0043")),
        ]);
        let mut id = Identity::default();
        apk_android(&values, &mut id);
        assert!(id.name.is_none(), "{:?}", id.name);
        // The package still identifies it.
        assert_eq!(id.identifier.unwrap().value, "com.example.app");
    }
}

#[cfg(test)]
mod description_tests {
    use super::{FileType, MAX_DESCRIPTION, Values, derive};

    fn describe(file_type: FileType, key: &str, text: &str) -> Option<(String, String)> {
        let mut values = Values::default();
        values.insert(key, serde_json::json!(text));
        derive(file_type, b"", &values)
            .description
            .map(|c| (c.value, c.source))
    }

    #[test]
    fn package_self_description_is_a_claim_with_its_source() {
        let mut values = Values::default();
        values.insert("npm.name", serde_json::json!("@acme/cli-win32-x64"));
        values.insert(
            "npm.description",
            serde_json::json!("Sandbox CLI core binary for Windows x64"),
        );
        let id = derive(FileType::Npm, b"", &values);
        let c = id.description.expect("description");
        assert_eq!(c.value, "Sandbox CLI core binary for Windows x64");
        assert_eq!(c.source, "npm.description");
        assert!(!c.verified);
    }

    #[test]
    fn each_format_contributes_its_own_field() {
        for (file_type, key) in [
            (FileType::PackageJson, "npm.description"),
            (FileType::Whl, "whl.summary"),
            (FileType::PythonSdist, "python.summary"),
            (FileType::Crate, "crate.description"),
            (FileType::Gem, "gem.summary"),
            (FileType::Nupkg, "nupkg.description"),
            (FileType::Vsix, "vsix.description"),
            (FileType::Crx, "crx.description"),
            (FileType::Xpi, "xpi.description"),
            (FileType::Deb, "deb.summary"),
            (FileType::Rpm, "rpm.summary"),
            (FileType::ApkAlpine, "apk.description"),
            (FileType::Pe, "pe.version.description"),
        ] {
            assert_eq!(
                describe(file_type, key, "does a thing"),
                Some(("does a thing".into(), key.into())),
                "{key}"
            );
        }
    }

    #[test]
    fn whitespace_is_collapsed_and_placeholders_dropped() {
        assert_eq!(
            describe(
                FileType::Nupkg,
                "nupkg.description",
                "  Line one.\n\t  Line two.  "
            )
            .map(|(v, _)| v),
            Some("Line one. Line two.".into())
        );
        assert_eq!(
            describe(FileType::PythonSdist, "python.summary", "UNKNOWN"),
            None
        );
        assert_eq!(describe(FileType::Npm, "npm.description", " \n "), None);
    }

    #[test]
    fn binaries_claim_their_copyright_notice() {
        let mut values = Values::default();
        values.insert(
            "pe.version.copyright",
            serde_json::json!("Copyright (C)  2024\tTencent."),
        );
        let c = derive(FileType::Pe, b"", &values)
            .copyright
            .expect("PE copyright");
        assert_eq!(
            (c.value.as_str(), c.source.as_str(), c.verified),
            ("Copyright (C) 2024 Tencent.", "pe.version.copyright", false)
        );

        let mut values = Values::default();
        values.insert(
            "macho.info_plist",
            serde_json::json!({
                "CFBundleGetInfoString": "1.0, Copyright Acme",
                "NSHumanReadableCopyright": "© 2024 Acme Inc.",
            }),
        );
        let c = derive(FileType::MachO, b"", &values)
            .copyright
            .expect("Mach-O copyright");
        assert_eq!(c.value, "© 2024 Acme Inc.");
        assert_eq!(c.source, "macho.info_plist.NSHumanReadableCopyright");

        let mut values = Values::default();
        values.insert("pe.version.copyright", serde_json::json!("  "));
        assert!(derive(FileType::Pe, b"", &values).copyright.is_none());
    }

    #[test]
    fn long_descriptions_are_cut_to_a_sentence() {
        let exact = "é".repeat(MAX_DESCRIPTION);
        assert_eq!(
            describe(FileType::Npm, "npm.description", &exact).map(|(v, _)| v),
            Some(exact.clone()),
            "a description at the limit is kept whole"
        );
        let long = format!("{exact}x");
        let (cut, _) = describe(FileType::Npm, "npm.description", &long).expect("cut");
        assert_eq!(cut.chars().count(), MAX_DESCRIPTION);
        assert!(cut.ends_with('…'));
    }
}

#[cfg(test)]
mod lnk_identity_tests {
    use super::{FileType, Values, derive};

    /// The tracker's NetBIOS name is reported once, as `machine_id`; it
    /// used to be duplicated under `lnk_machine_name`.
    #[test]
    fn tracker_machine_name_is_reported_once() {
        let mut values = Values::default();
        values.insert(
            "lnk.tracker",
            serde_json::json!({"machine_id": "build-host-01", "mac_address": "22:33:44:55:66:77"}),
        );
        values.insert(
            "lnk.volume",
            serde_json::json!({"serial": 3_405_691_582u64, "name": "DATA"}),
        );
        let ids = derive(FileType::Lnk, b"", &values).unique_ids;
        let keys: Vec<&str> = ids.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "lnk_volume_label",
                "lnk_volume_serial",
                "mac_address",
                "machine_id"
            ]
        );
        assert_eq!(ids["machine_id"], "build-host-01");
        assert_eq!(ids["lnk_volume_serial"], "3405691582");
    }
}

#[cfg(test)]
mod trust_tests {
    use super::{FileType, Trust, Values, derive};
    use serde_json::{Value as JsonValue, json};

    fn pe_trust(signature: JsonValue) -> Trust {
        let mut values = Values::default();
        values.insert("pe.signatures", JsonValue::Array(vec![signature]));
        derive(FileType::Pe, &[], &values).trust
    }

    fn signature(o: &str, cn: &str, verified: bool, anchor: Option<&str>) -> JsonValue {
        let mut sig = json!({
            "subject": format!("CN={cn},O={o}"),
            "issuer": "CN=Some CA",
            "verified": verified,
            "digest_matches": true,
        });
        if let Some(anchor) = anchor {
            sig["chain_anchor"] = json!(anchor);
        }
        sig
    }

    /// Names in a certificate are the signer's to choose; without a
    /// verified signature they establish nothing.
    #[test]
    fn unverified_signature_is_unverified_whatever_it_names() {
        for o in ["Applebee's", "Microsoft Corporation", "Apple Inc."] {
            assert_eq!(pe_trust(signature(o, "x", false, None)), Trust::Unverified);
        }
        let mut unsupported = signature("Microsoft Corporation", "x", true, Some("microsoft"));
        unsupported["verified"] = JsonValue::Null;
        assert_eq!(pe_trust(unsupported), Trust::Unverified);
    }

    /// A verified signature naming a vendor, by a chain that does not end
    /// at that vendor's root, is just CA-signed.
    #[test]
    fn vendor_names_need_the_vendor_anchor() {
        assert_eq!(
            pe_trust(signature("Microsoft Corporation", "x", true, None)),
            Trust::CaSigned
        );
        assert_eq!(
            pe_trust(signature("Microsoft Corporation", "x", true, Some("apple"))),
            Trust::CaSigned
        );
        assert_eq!(
            pe_trust(signature("Applebee's", "x", true, Some("apple"))),
            Trust::CaSigned
        );
        assert_eq!(
            pe_trust(signature(
                "Microsoft Corporation",
                "x",
                true,
                Some("microsoft")
            )),
            Trust::Platform
        );
        assert_eq!(
            pe_trust(signature(
                "Apple Inc.",
                "Software Signing",
                true,
                Some("apple")
            )),
            Trust::Platform
        );
    }

    #[test]
    fn developer_id_needs_the_apple_anchor() {
        let cn = "Developer ID Application: Example (TEAM123)";
        assert_eq!(
            pe_trust(signature("Example", cn, true, Some("apple"))),
            Trust::DeveloperId
        );
        assert_eq!(
            pe_trust(signature("Example", cn, true, None)),
            Trust::CaSigned
        );
    }

    /// A Microsoft signature grafted from another binary verifies, but its
    /// image hash is not this file's. Neither a mismatch nor a missing
    /// comparison lets it vouch for the file.
    #[test]
    fn grafted_signature_does_not_vouch_for_the_file() {
        let microsoft = || signature("Microsoft Corporation", "x", true, Some("microsoft"));
        let mut grafted = microsoft();
        grafted["digest_matches"] = json!(false);
        assert_eq!(pe_trust(grafted.clone()), Trust::Unverified);
        let mut unchecked = microsoft();
        unchecked.as_object_mut().unwrap().remove("digest_matches");
        assert_eq!(pe_trust(unchecked), Trust::Unverified);
        assert_eq!(pe_trust(microsoft()), Trust::Platform);

        let mut values = Values::default();
        values.insert("pe.signatures", JsonValue::Array(vec![grafted]));
        let id = derive(FileType::Pe, &[], &values);
        assert_eq!(id.organization.map(|o| o.verified), Some(false));
    }

    /// Nothing checks a cabinet's content against its signature's digest.
    #[test]
    fn cabinet_signatures_stay_unverified() {
        let mut values = Values::default();
        values.insert(
            "cab.signatures",
            JsonValue::Array(vec![signature(
                "Microsoft Corporation",
                "x",
                true,
                Some("microsoft"),
            )]),
        );
        assert_eq!(derive(FileType::Cab, &[], &values).trust, Trust::Unverified);
    }

    fn macho_trust(platform: u64, cms: Option<JsonValue>) -> Trust {
        let mut values = Values::default();
        values.insert("macho.code_signature.cdhash", json!("00"));
        values.insert("macho.code_signature.code_pages_verified", json!(true));
        values.insert("macho.code_signature.platform", json!(platform));
        if let Some(cms) = cms {
            values.insert("macho.code_signature.cms", cms);
        }
        derive(FileType::MachO, &[], &values).trust
    }

    /// Any binary can set the CodeDirectory's platform byte; only Apple's
    /// verified signature over that CodeDirectory makes it a system binary.
    #[test]
    fn platform_byte_alone_is_not_system() {
        let apple =
            |verified, anchor| signature("Apple Inc.", "Software Signing", verified, anchor);
        assert_eq!(macho_trust(0xe, None), Trust::Unverified);
        assert_eq!(
            macho_trust(0xe, Some(apple(false, Some("apple")))),
            Trust::Unverified
        );
        assert_eq!(macho_trust(0xe, Some(apple(true, None))), Trust::CaSigned);
        assert_eq!(
            macho_trust(0xe, Some(apple(true, Some("apple")))),
            Trust::System
        );
        assert_eq!(
            macho_trust(0, Some(apple(true, Some("apple")))),
            Trust::Platform
        );
    }

    /// The CodeDirectory's identifier is proven only by a CMS signature that
    /// verified over it, not by one merely being present.
    #[test]
    fn code_directory_claims_are_verified_only_by_a_verified_cms() {
        for verified in [false, true] {
            let mut values = Values::default();
            values.insert("macho.code_signature.code_pages_verified", json!(true));
            values.insert("macho.code_signature.identifier", json!("com.example.tool"));
            values.insert(
                "macho.code_signature.cms",
                signature("Example", "x", verified, None),
            );
            let id = derive(FileType::MachO, &[], &values);
            assert_eq!(id.identifier.unwrap().verified, verified);
        }
    }

    /// Apple's genuine CodeDirectory and signature, lifted onto other code:
    /// the CMS verifies over the CodeDirectory, but the pages it hashes are
    /// not this file's. Nor does a missing page check, an unbound
    /// entitlements blob, or an alternate CodeDirectory asserting another
    /// identity let the signature vouch for the file.
    #[test]
    fn code_directory_must_hash_to_this_files_code() {
        let apple = signature("Apple Inc.", "Software Signing", true, Some("apple"));
        let trust = |edit: &dyn Fn(&mut Values)| {
            let mut values = Values::default();
            values.insert("macho.code_signature.cdhash", json!("00"));
            values.insert("macho.code_signature.identifier", json!("com.apple.ls"));
            values.insert("macho.code_signature.platform", json!(0xe));
            values.insert("macho.code_signature.cms", apple.clone());
            values.insert("macho.code_signature.code_pages_verified", json!(true));
            edit(&mut values);
            let id = derive(FileType::MachO, &[], &values);
            (id.trust, id.identifier.map(|c| c.verified))
        };
        assert_eq!(trust(&|_| {}), (Trust::System, Some(true)));
        let unbound = [
            ("macho.code_signature.code_pages_verified", json!(false)),
            ("macho.code_signature.special_slots_verified", json!(false)),
            (
                "macho.code_signature.code_directories_consistent",
                json!(false),
            ),
        ];
        for (key, value) in unbound {
            let got = trust(&|v: &mut Values| v.insert(key, value.clone()));
            assert_eq!(got, (Trust::Unverified, Some(false)), "{key}");
        }
        let unchecked = trust(&|v: &mut Values| {
            *v = Values::from_json(json!({"macho": {"code_signature": {
                "cdhash": "00", "platform": 14, "cms": apple.clone(),
            }}}));
        });
        assert_eq!(unchecked.0, Trust::Unverified);
    }

    /// Ad hoc claims integrity, so it needs the page hashes to match too.
    #[test]
    fn ad_hoc_needs_matching_pages() {
        for (pages, want) in [(true, Trust::AdHoc), (false, Trust::Unverified)] {
            let mut values = Values::default();
            values.insert("macho.code_signature.cdhash", json!("00"));
            values.insert("macho.code_signature.flags", json!(["ad_hoc"]));
            values.insert("macho.code_signature.code_pages_verified", json!(pages));
            assert_eq!(derive(FileType::MachO, &[], &values).trust, want);
        }
    }
}
