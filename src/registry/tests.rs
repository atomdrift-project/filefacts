use super::*;

#[test]
fn with_age_derives_cadence_relative_to_now() {
    let day = 86_400u64;
    let now = 100 * day;
    let reg = Registry {
        published_at: Some(now),                  // this release: right now
        first_published_at: Some(now - 74 * day), // package born 74d ago
        previous_published_at: Some(now - 2 * day),
        // three releases inside 48h (one inside 24h), plus older ones
        release_times: vec![now, now - 2 * day, now - 30 * day, now - 74 * day],
        ..Registry::new(Ecosystem::Pypi, "widget")
    }
    .with_age(now);

    assert_eq!(reg.age_days, Some(0), "this version is brand new");
    assert_eq!(reg.package_age_days, Some(74), "package is 74 days old");
    assert_eq!(reg.releases_24h, Some(1), "only the current release in 24h");
    assert_eq!(reg.releases_48h, Some(2), "current + the 2-days-ago one");
}

#[test]
fn write_facts_routes_counts_to_metrics_and_identity_to_values() {
    let day = 86_400u64;
    let now = 100 * day;
    let reg = Registry {
        published_at: Some(now),
        previous_published_at: Some(now - 5 * day),
        first_published_at: Some(now - 40 * day),
        release_count: Some(12),
        publisher: Some("attacker".into()),
        publisher_email_domain: Some("gmail.com".into()),
        publisher_in_maintainers: Some(false),
        publisher_verified: Some(false),
        security_hold: Some(false),
        version_removed: Some(true),
        unpacked_size: Some(4096),
        file_count: Some(3),
        has_install_script: Some(true),
        vulnerability_count: Some(0),
        ..Registry::new(Ecosystem::Npm, "widget")
    }
    .with_age(now);

    let mut values = Values::new();
    let mut metrics = Metrics::new();
    reg.write_facts(&mut values, &mut metrics);

    // Identity → values.
    assert_eq!(
        values.get("registry.publisher").and_then(|v| v.as_str()),
        Some("attacker")
    );
    assert_eq!(
        values
            .get("registry.publisher_email_domain")
            .and_then(|v| v.as_str()),
        Some("gmail.com")
    );
    // Counts / measures / derived deltas / flags → metrics.
    assert_eq!(metrics.get("registry.release_count"), Some(12.0));
    assert_eq!(metrics.get("registry.package_age_days"), Some(40.0));
    assert_eq!(
        metrics.get("registry.days_since_previous_release"),
        Some(5.0)
    );
    assert_eq!(metrics.get("registry.unpacked_size"), Some(4096.0));
    assert_eq!(metrics.get("registry.file_count"), Some(3.0));
    assert_eq!(metrics.get("registry.has_install_script"), Some(1.0));
    assert_eq!(metrics.get("registry.publisher_in_maintainers"), Some(0.0));
    assert_eq!(metrics.get("registry.publisher_verified"), Some(0.0));
    assert_eq!(metrics.get("registry.security_hold"), Some(0.0));
    assert_eq!(metrics.get("registry.version_removed"), Some(1.0));
    // A present-but-zero count is still emitted (0 vulns is a real fact).
    assert_eq!(metrics.get("registry.vulnerability_count"), Some(0.0));
    // Publisher identity never leaks into metrics; counts never into values.
    assert!(metrics.get("registry.publisher").is_none());
    assert!(values.get("registry.release_count").is_none());
    // No deprecation notice was reported, so nothing is claimed either way.
    assert!(metrics.get("registry.is_deprecated").is_none());
}

#[test]
fn ecosystem_labels_round_trip_and_unknown_labels_survive() {
    for ecosystem in NAMED {
        let json = serde_json::to_value(ecosystem).unwrap();
        assert_eq!(json, ecosystem.as_str());
        assert_eq!(
            &serde_json::from_value::<Ecosystem>(json).unwrap(),
            ecosystem
        );
    }
    assert_eq!(Ecosystem::from_label("PyPI"), Ecosystem::Pypi);
    let other: Ecosystem = serde_json::from_str(r#""Pkgsrc-Next""#).unwrap();
    assert_eq!(other, Ecosystem::Other("Pkgsrc-Next".into()));
    assert_eq!(serde_json::to_string(&other).unwrap(), r#""Pkgsrc-Next""#);
}
