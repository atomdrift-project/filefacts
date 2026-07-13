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
use crate::output::{Claim, Identity, Party, Signer, Trust, Url, UrlKind, Values};

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
        FileType::Ooxml | FileType::OleDoc => office(values, &mut id),
        FileType::Pdf => pdf(values, &mut id),
        FileType::Rtf => rtf(values, &mut id),
        FileType::Png => png(values, &mut id),
        FileType::Lnk => lnk(values, &mut id),
        FileType::Rpm => rpm(values, &mut id),
        FileType::Deb => deb(values, &mut id),
        _ => {}
    }

    // Build-time source path — an origin artifact carried by native
    // executables regardless of format.
    if matches!(file_type, FileType::Pe | FileType::Elf | FileType::MachO) {
        build_path(bytes, values, &mut id);
    }

    finalize(&mut id);
    id
}

// ---------------------------------------------------------------------
// Binary formats — signature-backed identity.
// ---------------------------------------------------------------------

fn macho(values: &Values, bytes: &[u8], id: &mut Identity) {
    let signed = values.get("macho.code_signature.identifier").is_some()
        || values.get("macho.code_signature.cdhash").is_some()
        || values.get("macho.code_signature.flags").is_some();
    let cms = values.get("macho.code_signature.cms");
    let cms_present = cms.is_some();

    if let Some(ident) = get_str(values, "macho.code_signature.identifier") {
        // The identifier lives in the CodeDirectory, which the signature
        // covers — but only a real CMS chain *proves* who set it.
        id.identifier = Some(Claim {
            value: ident.to_string(),
            source: "macho.code_signature.identifier".into(),
            verified: cms_present,
        });
    }
    if let Some(team) = get_str(values, "macho.code_signature.team_id") {
        id.team_id = Some(Claim {
            value: team.to_string(),
            source: "macho.code_signature.team_id".into(),
            verified: cms_present,
        });
    }
    if let Some(cdhash) = get_str(values, "macho.code_signature.cdhash") {
        id.unique_ids.insert("cdhash".into(), cdhash.to_string());
    }

    if let Some(ci) = cms.and_then(cert_from_obj) {
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
        .get("macho.code_signature.platform")
        .and_then(JsonValue::as_u64)
        .unwrap_or(0);
    let ad_hoc = flag_set(values, "macho.code_signature.flags", "ad_hoc");
    if id.trust == Trust::Unsigned && signed {
        id.trust = if ad_hoc {
            Trust::AdHoc
        } else {
            Trust::CaSigned
        };
    }
    if platform > 0 {
        // A platform binary is trusted by the OS via the system trust
        // cache — the strongest first-party signal, even when ad-hoc.
        id.trust = Trust::System;
    }

    // For a platform/system binary with no CMS organization, infer the
    // vendor from the reverse-DNS identifier (`com.apple.ls` → Apple).
    if id.organization.is_none() && id.trust == Trust::System {
        if let Some(ident) = get_str(values, "macho.code_signature.identifier") {
            if let Some(org) = org_from_reverse_dns(ident) {
                id.organization = Some(Claim::claimed(org, "macho.code_signature.identifier"));
            }
        }
    }

    // Apple `what(1)` stamp: `@(#)PROGRAM:ls  PROJECT:file_cmds-479`.
    // Gated to Apple binaries — the only ones that carry it — so the
    // overwhelming majority of Mach-O files never pay for the scan.
    let apple = id.trust == Trust::System
        || get_str(values, "macho.code_signature.identifier")
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
        if let Some(install) = get_str(values, "macho.install_name") {
            let base = install.rsplit('/').next().unwrap_or(install);
            if !base.is_empty() {
                id.name = Some(Claim::claimed(base, "macho.install_name"));
            }
        }
    }
    if id.name.is_none() {
        if let Some(ident) = get_str(values, "macho.code_signature.identifier") {
            if let Some(tail) = ident.rsplit('.').next() {
                id.name = Some(Claim::claimed(tail, "macho.code_signature.identifier"));
            }
        }
    }

    if let Some(sv) = get_str(values, "macho.source_version") {
        if sv != "0.0.0" {
            id.version = Some(Claim::claimed(sv, "macho.source_version"));
        }
    }
}

fn pe(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "pe.version.original_filename")
        .or_else(|| get_str(values, "pe.version.internal_name"))
    {
        id.name = Some(Claim::claimed(name, "pe.version.original_filename"));
    }
    // ProductName names the larger product/suite the file belongs to —
    // the closest PE analogue to a source project.
    if let Some(product) = get_str(values, "pe.version.product_name") {
        id.project = Some(Claim::claimed(product, "pe.version.product_name"));
    }
    if let Some(company) = get_str(values, "pe.version.company") {
        id.organization = Some(Claim::claimed(company, "pe.version.company"));
    }
    if let Some(version) = get_str(values, "pe.version.file_version")
        .or_else(|| get_str(values, "pe.version.product_version"))
    {
        id.version = Some(Claim::claimed(version, "pe.version.file_version"));
    }

    if let Some(ci) = values.get("pe.signatures[0]").and_then(cert_from_obj) {
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
    if let Some(t) = get_str(values, "pe.signatures[0].thumbprint_sha256") {
        id.unique_ids
            .insert("authenticode_thumbprint_sha256".into(), t.to_string());
    }
}

fn crx(values: &Values, id: &mut Identity) {
    if let Some(ext_id) = get_str(values, "crx.extension_id") {
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
    if let Some(pk) = get_str(values, "crx.public_key_sha256") {
        id.unique_ids
            .insert("public_key_sha256".into(), pk.to_string());
        id.trust = Trust::Unverified;
    }
    // Developer-declared author from the extension manifest.
    push_author(
        id,
        get_str(values, "crx.author").map(str::to_string),
        get_str(values, "crx.author_email").map(str::to_string),
        None,
        "author",
        "crx.author",
    );
    if let Some(home) = get_str(values, "crx.homepage_url") {
        push_url(id, UrlKind::Homepage, home, "crx.homepage_url");
    }
}

// ---------------------------------------------------------------------
// Package manifests — claimed identity.
// ---------------------------------------------------------------------

fn xpi(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "xpi.name") {
        id.name = Some(Claim::claimed(name, "xpi.name"));
    }
    if let Some(version) = get_str(values, "xpi.version") {
        id.version = Some(Claim::claimed(version, "xpi.version"));
    }
    push_author(
        id,
        get_str(values, "xpi.author").map(str::to_string),
        None,
        None,
        "author",
        "xpi.author",
    );
    if let Some(home) = get_str(values, "xpi.homepage_url") {
        push_url(id, UrlKind::Homepage, home, "xpi.homepage_url");
    }
}

fn nupkg(values: &Values, id: &mut Identity) {
    if let Some(pkg_id) = get_str(values, "nupkg.id") {
        id.identifier = Some(Claim::claimed(pkg_id, "nupkg.id"));
    }
    if let Some(name) = get_str(values, "nupkg.title").or_else(|| get_str(values, "nupkg.id")) {
        id.name = Some(Claim::claimed(name, "nupkg.title"));
    }
    if let Some(version) = get_str(values, "nupkg.version") {
        id.version = Some(Claim::claimed(version, "nupkg.version"));
    }
    for author in split_list(get_str(values, "nupkg.authors")) {
        push_author(id, Some(author), None, None, "author", "nupkg.authors");
    }
    for owner in split_list(get_str(values, "nupkg.owners")) {
        push_author(id, Some(owner), None, None, "owner", "nupkg.owners");
    }
    if let Some(url) = get_str(values, "nupkg.project_url") {
        push_url(id, UrlKind::Homepage, url, "nupkg.project_url");
    }
    if let Some(url) = get_str(values, "nupkg.repository_url") {
        push_url(id, UrlKind::Repository, url, "nupkg.repository_url");
    }
}

fn vsix(values: &Values, id: &mut Identity) {
    if let Some(ext_id) = get_str(values, "vsix.identity.id") {
        id.identifier = Some(Claim::claimed(ext_id, "vsix.identity.id"));
        if id.name.is_none() {
            if let Some(tail) = ext_id.rsplit('.').next() {
                id.name = Some(Claim::claimed(tail, "vsix.identity.id"));
            }
        }
    }
    if let Some(display) = get_str(values, "vsix.display_name") {
        id.name = Some(Claim::claimed(display, "vsix.display_name"));
    }
    if let Some(version) = get_str(values, "vsix.identity.version") {
        id.version = Some(Claim::claimed(version, "vsix.identity.version"));
    }
    if let Some(publisher) = get_str(values, "vsix.identity.publisher") {
        id.team_id = Some(Claim::claimed(publisher, "vsix.identity.publisher"));
    }
}

fn wheel(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "whl.distribution") {
        id.name = Some(Claim::claimed(name, "whl.distribution"));
    }
    if let Some(version) = get_str(values, "whl.version") {
        id.version = Some(Claim::claimed(version, "whl.version"));
    }
    // Authorship from the dist-info METADATA. `*-email` fields may carry a
    // bare address or a `Name <email>` pair.
    let (a_name, a_email) = split_contact(
        get_str(values, "whl.author"),
        get_str(values, "whl.author_email"),
    );
    push_author(id, a_name, a_email, None, "author", "whl.author");
    let (m_name, m_email) = split_contact(
        get_str(values, "whl.maintainer"),
        get_str(values, "whl.maintainer_email"),
    );
    push_author(id, m_name, m_email, None, "maintainer", "whl.maintainer");
    if let Some(home) = get_str(values, "whl.home_page") {
        push_url(id, UrlKind::Homepage, home, "whl.home_page");
    }
}

fn jar(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "jar.manifest.implementation_title")
        .or_else(|| get_str(values, "jar.pom.artifact_id"))
    {
        id.name = Some(Claim::claimed(name, "jar.manifest.implementation_title"));
    }
    if let Some(version) = get_str(values, "jar.manifest.implementation_version")
        .or_else(|| get_str(values, "jar.pom.version"))
    {
        id.version = Some(Claim::claimed(
            version,
            "jar.manifest.implementation_version",
        ));
    }
    // Maven coordinates form a stable `group:artifact` identifier.
    if let (Some(group), Some(artifact)) = (
        get_str(values, "jar.pom.group_id"),
        get_str(values, "jar.pom.artifact_id"),
    ) {
        id.identifier = Some(Claim::claimed(format!("{group}:{artifact}"), "jar.pom"));
    }
    if let Some(vendor) = get_str(values, "jar.manifest.implementation_vendor")
        .or_else(|| get_str(values, "jar.manifest.bundle_vendor"))
        .or_else(|| get_str(values, "jar.manifest.specification_vendor"))
    {
        id.organization = Some(Claim::claimed(vendor, "jar.manifest.implementation_vendor"));
    }
    if let Some(producer) = get_str(values, "jar.manifest.created_by") {
        id.producer = Some(Claim::claimed(producer, "jar.manifest.created_by"));
    }
    // `Built-By` is the build account — an origin-host artifact, the JAR
    // analogue of a binary's embedded build path.
    if let Some(built_by) = get_str(values, "jar.manifest.built_by") {
        id.unique_ids
            .insert("build_user".into(), built_by.to_string());
    }
}

fn gem(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "gem.name") {
        id.name = Some(Claim::claimed(name, "gem.name"));
    }
    if let Some(version) = get_str(values, "gem.version") {
        id.version = Some(Claim::claimed(version, "gem.version"));
    }
    for author in str_array(values, "gem.authors") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            "author",
            "gem.authors",
        );
    }
    if let Some(home) = get_str(values, "gem.homepage") {
        push_url(id, UrlKind::Homepage, home, "gem.homepage");
    }
}

fn npm(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "npm.name") {
        id.name = Some(Claim::claimed(name, "npm.name"));
        id.identifier = Some(Claim::claimed(name, "npm.name"));
    }
    if let Some(version) = get_str(values, "npm.version") {
        id.version = Some(Claim::claimed(version, "npm.version"));
    }
    push_author(
        id,
        get_str(values, "npm.author.name").map(str::to_string),
        get_str(values, "npm.author.email").map(str::to_string),
        get_str(values, "npm.author.url").map(str::to_string),
        "author",
        "npm.author",
    );
    if let Some(JsonValue::Array(maintainers)) = values.get("npm.maintainers") {
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
    if let Some(repo) = get_str(values, "npm.repository.url") {
        push_url(id, UrlKind::Repository, repo, "npm.repository.url");
    }
    if let Some(home) = get_str(values, "npm.homepage") {
        push_url(id, UrlKind::Homepage, home, "npm.homepage");
    }
}

fn rust_crate(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "crate.name") {
        id.name = Some(Claim::claimed(name, "crate.name"));
        id.identifier = Some(Claim::claimed(name, "crate.name"));
    }
    if let Some(version) = get_str(values, "crate.version") {
        id.version = Some(Claim::claimed(version, "crate.version"));
    }
    for author in str_array(values, "crate.authors") {
        let (name, email, _) = parse_person(author);
        push_author(id, name, email, None, "author", "crate.authors");
    }
    if let Some(repo) = get_str(values, "crate.repository") {
        push_url(id, UrlKind::Repository, repo, "crate.repository");
    }
    if let Some(home) = get_str(values, "crate.homepage") {
        push_url(id, UrlKind::Homepage, home, "crate.homepage");
    }
}

fn python_sdist(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "python.name") {
        id.name = Some(Claim::claimed(name, "python.name"));
        id.identifier = Some(Claim::claimed(name, "python.name"));
    }
    if let Some(version) = get_str(values, "python.version") {
        id.version = Some(Claim::claimed(version, "python.version"));
    }
    push_author(
        id,
        get_str(values, "python.author.name").map(str::to_string),
        get_str(values, "python.author.email").map(str::to_string),
        None,
        "author",
        "python.author",
    );
    push_author(
        id,
        get_str(values, "python.maintainer.name").map(str::to_string),
        get_str(values, "python.maintainer.email").map(str::to_string),
        None,
        "maintainer",
        "python.maintainer",
    );
    if let Some(home) = get_str(values, "python.homepage") {
        push_url(id, UrlKind::Homepage, home, "python.homepage");
    }
}

fn oci(values: &Values, id: &mut Identity) {
    // The first image ref is the closest thing an image bundle has to a name;
    // the config/manifest digest is its strongest unique identifier.
    if let Some(first_ref) = str_array(values, "oci.ref").next() {
        id.name = Some(Claim::claimed(first_ref, "oci.ref"));
    }
    if let Some(digest) = str_array(values, "oci.config.digest")
        .next()
        .or_else(|| str_array(values, "oci.manifest.digest").next())
    {
        id.identifier = Some(Claim::claimed(digest, "oci.config.digest"));
        id.unique_ids
            .insert("oci_digest".into(), digest.to_string());
    }
}

fn rpm(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "rpm.name") {
        id.name = Some(Claim::claimed(name, "rpm.name"));
    }
    if let Some(version) = get_str(values, "rpm.version") {
        id.version = Some(Claim::claimed(version, "rpm.version"));
    }
    if let Some(vendor) = get_str(values, "rpm.vendor") {
        id.organization = Some(Claim::claimed(vendor, "rpm.vendor"));
    }
    if let Some(packager) = get_str(values, "rpm.packager") {
        let (name, email, url) = parse_person(packager);
        push_author(id, name, email, url, "packager", "rpm.packager");
    }
    if let Some(url) = get_str(values, "rpm.url") {
        push_url(id, UrlKind::Homepage, url, "rpm.url");
    }
}

fn deb(values: &Values, id: &mut Identity) {
    if let Some(name) = get_str(values, "deb.package") {
        id.name = Some(Claim::claimed(name, "deb.package"));
    }
    if let Some(version) = get_str(values, "deb.version") {
        id.version = Some(Claim::claimed(version, "deb.version"));
    }
    if let Some(maintainer) = get_str(values, "deb.maintainer") {
        let (name, email, url) = parse_person(maintainer);
        push_author(id, name, email, url, "maintainer", "deb.maintainer");
    }
}

// ---------------------------------------------------------------------
// Documents — authored identity.
// ---------------------------------------------------------------------

/// OLE2 (`.doc`/`.xls`/`.ppt`) and OOXML (`.docx`/…) both expose their
/// document properties under the shared `office.*` namespace.
fn office(values: &Values, id: &mut Identity) {
    if let Some(title) = get_str(values, "office.title") {
        id.title = Some(Claim::claimed(title, "office.title"));
    }
    if let Some(creator) = get_str(values, "office.creator") {
        push_author(
            id,
            Some(creator.to_string()),
            None,
            None,
            "author",
            "office.creator",
        );
    }
    if let Some(modifier) = get_str(values, "office.last_modified_by") {
        push_author(
            id,
            Some(modifier.to_string()),
            None,
            None,
            "last_modified_by",
            "office.last_modified_by",
        );
    }
    if let Some(manager) = get_str(values, "office.manager") {
        push_author(
            id,
            Some(manager.to_string()),
            None,
            None,
            "manager",
            "office.manager",
        );
    }
    if let Some(company) = get_str(values, "office.company") {
        id.organization = Some(Claim::claimed(company, "office.company"));
    }
    if let Some(app) = get_str(values, "office.application") {
        id.producer = Some(Claim::claimed(app, "office.application"));
    }
}

fn pdf(values: &Values, id: &mut Identity) {
    if let Some(title) = get_str(values, "pdf.info.title") {
        id.title = Some(Claim::claimed(title, "pdf.info.title"));
    }
    if let Some(author) = get_str(values, "pdf.info.author") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            "author",
            "pdf.info.author",
        );
    }
    if let Some(producer) =
        get_str(values, "pdf.info.producer").or_else(|| get_str(values, "pdf.info.creator"))
    {
        id.producer = Some(Claim::claimed(producer, "pdf.info.producer"));
    }
}

fn rtf(values: &Values, id: &mut Identity) {
    if let Some(title) = get_str(values, "rtf.info.title") {
        id.title = Some(Claim::claimed(title, "rtf.info.title"));
    }
    if let Some(author) = get_str(values, "rtf.info.author") {
        push_author(
            id,
            Some(author.to_string()),
            None,
            None,
            "author",
            "rtf.info.author",
        );
    }
    if let Some(company) = get_str(values, "rtf.info.company") {
        id.organization = Some(Claim::claimed(company, "rtf.info.company"));
    }
}

fn png(values: &Values, id: &mut Identity) {
    if let Some(software) = get_str(values, "png.text.software") {
        id.producer = Some(Claim::claimed(software, "png.text.software"));
    }
}

fn lnk(values: &Values, id: &mut Identity) {
    if let Some(machine) = get_str(values, "lnk.tracker.machine_id") {
        id.unique_ids
            .insert("machine_id".into(), machine.to_string());
    }
    if let Some(mac) = get_str(values, "lnk.tracker.mac_address") {
        id.unique_ids.insert("mac_address".into(), mac.to_string());
    }
}

// ---------------------------------------------------------------------
// Cross-format: build path.
// ---------------------------------------------------------------------

fn build_path(bytes: &[u8], values: &Values, id: &mut Identity) {
    let mut candidates: Vec<(String, &'static str)> = Vec::new();
    if let Some(pdb) = get_str(values, "pe.debug.pdb.path") {
        candidates.push((pdb.to_string(), "pe.debug.pdb.path"));
    }
    for dir in str_array(values, "elf.dwarf.comp_dirs") {
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
    let tail = &bytes[m.start()..];
    let is_path_byte = if windows {
        is_win_path_byte
    } else {
        is_unix_path_byte
    };
    let end = tail
        .iter()
        .position(|&b| !is_path_byte(b))
        .unwrap_or(tail.len());
    // Require at least one path byte past the prefix (a real username).
    if end <= m.end() - m.start() {
        return None;
    }
    std::str::from_utf8(&tail[..end]).ok().map(str::to_string)
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

fn cert_trust(ci: &CertInfo) -> Trust {
    if ci.self_issued {
        return Trust::SelfSigned;
    }
    if ci
        .cn
        .as_deref()
        .is_some_and(|cn| cn.starts_with("Developer ID"))
    {
        return Trust::DeveloperId;
    }
    let hay = format!(
        "{} {} {}",
        ci.o.as_deref().unwrap_or(""),
        ci.subject.as_deref().unwrap_or(""),
        ci.issuer.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    if hay.contains("apple") || hay.contains("microsoft") {
        return Trust::Platform;
    }
    Trust::CaSigned
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
    let after = &bytes[pos + needle.len()..];
    let start = after.iter().position(|&b| b != b' ' && b != b'\t')?;
    let value = &after[start..];
    let end = value
        .iter()
        .position(|&b| b <= b' ' || b == 0x7f)
        .unwrap_or(value.len());
    let token = &value[..end];
    if token.is_empty() {
        return None;
    }
    std::str::from_utf8(token).ok().map(str::to_string)
}

fn get_str<'a>(values: &'a Values, key: &str) -> Option<&'a str> {
    values.get(key).and_then(JsonValue::as_str)
}

fn str_array<'a>(values: &'a Values, key: &str) -> impl Iterator<Item = &'a str> {
    values
        .get(key)
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

fn flag_set(values: &Values, key: &str, flag: &str) -> bool {
    values
        .get(key)
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
