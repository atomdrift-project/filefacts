mod filename_tests {
    use super::super::split_name_version;

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

mod go_module_identity_tests {
    use super::super::{Claim, Identity, Values, go_module};
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

mod container_identity_tests {
    use super::super::{Identity, Values, dmg, iso, tar};

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
        // `HFSJ` / `10.0` are HFS+ lastMountedVersion values, not tools;
        // mapping the field would fabricate a confident `producer`.
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
        assert!(
            id.authors
                .iter()
                .all(|p| p.role == crate::output::PartyRole::Builder)
        );
    }

    #[test]
    #[ignore = "wall-clock bound; run with --ignored"]
    fn many_tar_owner_names_are_deduplicated_in_linear_time() {
        // Checking each name against every party already recorded would make
        // an archive with 100k distinct owners quadratic.
        let names: Vec<String> = (0..50_000).map(|i| format!("user{i}")).collect();
        let values = values_from(&[
            ("archive.builder.unames", serde_json::json!(names)),
            ("archive.builder.gnames", serde_json::json!(names)),
        ]);
        let mut id = Identity::default();
        let started = std::time::Instant::now();
        tar(&values, &mut id);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(id.authors.len(), 50_000);
        assert_eq!(id.authors[0].source, "archive.builder.unames");
    }
}

mod android_identity_tests {
    use super::super::{Identity, Values, apk_android};

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

mod description_tests {
    use super::super::{FileType, MAX_DESCRIPTION, Values, derive};

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
            (FileType::Whl, "whl.description"),
            (FileType::PythonSdist, "python.description"),
            (FileType::Crate, "crate.description"),
            (FileType::Gem, "gem.description"),
            (FileType::Nupkg, "nupkg.description"),
            (FileType::Vsix, "vsix.description"),
            (FileType::Crx, "crx.description"),
            (FileType::Xpi, "xpi.description"),
            (FileType::Deb, "deb.description"),
            (FileType::Rpm, "rpm.description"),
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
            describe(FileType::PythonSdist, "python.description", "UNKNOWN"),
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

mod lnk_identity_tests {
    use super::super::{FileType, Values, derive};

    /// The tracker's NetBIOS name is reported once, as `machine_id`, and
    /// not repeated under another key.
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

mod trust_tests {
    use super::super::{FileType, Trust, Values, derive};
    use serde_json::{Value as JsonValue, json};

    fn pe_trust(signature: JsonValue) -> Trust {
        let mut values = Values::default();
        values.insert("pe.signatures", JsonValue::Array(vec![signature]));
        derive(FileType::Pe, &[], &values).trust
    }

    /// A code-signing leaf's published signature: its EKU names
    /// `codeSigning`, as every vendor code-signing certificate's does.
    fn signature(o: &str, cn: &str, verified: bool, anchor: Option<&str>) -> JsonValue {
        let mut sig = json!({
            "subject": format!("CN={cn},O={o}"),
            "issuer": "CN=Some CA",
            "verified": verified,
            "digest_matches": true,
            "eku_code_signing": true,
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

    /// A vendor root also issues TLS, mail and timestamping certificates; a
    /// leaf under it that is not for code signing signs code as any CA's
    /// customer would, not as the vendor.
    #[test]
    fn vendor_tiers_need_the_code_signing_purpose() {
        for (o, cn, anchor) in [
            ("Microsoft Corporation", "x", "microsoft"),
            ("Apple Inc.", "Software Signing", "apple"),
            (
                "Example",
                "Developer ID Application: Example (TEAM123)",
                "apple",
            ),
        ] {
            let mut sig = signature(o, cn, true, Some(anchor));
            sig["eku_code_signing"] = json!(false);
            assert_eq!(pe_trust(sig.clone()), Trust::CaSigned, "{o}");
            sig.as_object_mut().unwrap().remove("eku_code_signing");
            assert_eq!(pe_trust(sig), Trust::CaSigned, "{o} without an EKU");
        }
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
