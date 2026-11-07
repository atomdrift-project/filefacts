use super::*;

fn metrics_of(pkg_info: &str, requires_txt: Option<&str>) -> Metrics {
    let mut metrics = Metrics::new();
    core_metadata(&CoreMetadata::parse(pkg_info), requires_txt, &mut metrics);
    metrics
}

#[test]
fn edit_distance_is_at_most_one() {
    assert!(within_one_edit("requests", "requests"));
    assert!(within_one_edit("rsquests", "requests")); // substitution
    assert!(within_one_edit("requets", "requests")); // deletion
    assert!(within_one_edit("requestss", "requests")); // insertion
    assert!(within_one_edit("colotama", "colorama"));
    assert!(!within_one_edit("reqeusts", "requests")); // transposition is two
    assert!(!within_one_edit("req", "requests"));
}

#[test]
fn typosquat_flags_a_near_miss_but_not_the_real_package() {
    let squat = metrics_of("Metadata-Version: 2.1\nName: colotama\n", None);
    assert_eq!(squat.get("consistency.name_typosquat"), Some(1.0));
    let real = metrics_of("Metadata-Version: 2.1\nName: colorama\n", None);
    assert_eq!(real.get("consistency.name_typosquat"), Some(0.0));
    // PEP 503: case and separators do not make a different name.
    let spelled = metrics_of("Metadata-Version: 2.1\nName: Python_DateUtil\n", None);
    assert_eq!(spelled.get("consistency.name_typosquat"), Some(0.0));
    // No name, nothing judged.
    let nameless = metrics_of("Metadata-Version: 2.1\nSummary: x\n", None);
    assert_eq!(nameless.get("consistency.name_typosquat"), None);
}

#[test]
fn identity_mismatch_needs_two_fields_agreeing_on_another_name() {
    let copied = metrics_of(
        "Name: ether-account\nSummary: eth-account: Sign Ethereum transactions\n\
         Home-page: https://github.com/ethereum/eth-account\n",
        None,
    );
    assert_eq!(
        copied.get("consistency.metadata_identity_mismatch"),
        Some(2.0)
    );
    // One mismatching field is ordinary.
    let one = metrics_of(
        "Name: scikit-learn\nHome-page: https://github.com/scikit-learn/sklearn\n",
        None,
    );
    assert_eq!(one.get("consistency.metadata_identity_mismatch"), Some(0.0));
    // Both fields naming the package itself is consistent.
    let own = metrics_of(
        "Name: eth-account\nSummary: eth-account: x\nHome-page: https://github.com/ethereum/eth_account\n",
        None,
    );
    assert_eq!(own.get("consistency.metadata_identity_mismatch"), Some(0.0));
}

#[test]
fn cloned_summary_is_a_popular_tagline_under_another_name() {
    let clone = metrics_of(
        "Name: fluxhttp\nSummary: Async  HTTP client/server framework (asyncio)\n",
        None,
    );
    assert_eq!(clone.get("consistency.cloned_summary"), Some(1.0));
    let owner = metrics_of(
        "Name: aiohttp\nSummary: Async http client/server framework (asyncio)\n",
        None,
    );
    assert_eq!(owner.get("consistency.cloned_summary"), Some(0.0));
    let no_summary = metrics_of("Name: fluxhttp\n", None);
    assert_eq!(no_summary.get("consistency.cloned_summary"), None);
}

#[test]
fn self_dependency_counts_only_unconditional_requirements() {
    let itself = metrics_of(
        "Name: base58-core\nRequires-Dist: requests\nRequires-Dist: Base58_Core>=1.0\n",
        None,
    );
    assert_eq!(itself.get("consistency.self_dependency"), Some(1.0));
    // An extra aggregating the package's own extras is the ordinary pattern.
    let extras = metrics_of(
        "Name: foo\nRequires-Dist: foo[a,b]; extra == \"all\"\nRequires-Dist: bar\n",
        None,
    );
    assert_eq!(extras.get("consistency.self_dependency"), Some(0.0));
    // Other markers keep a requirement unconditional for this purpose.
    let marked = metrics_of(
        "Name: foo\nRequires-Dist: foo ; python_version < \"3.9\"\n",
        None,
    );
    assert_eq!(marked.get("consistency.self_dependency"), Some(1.0));
    // No requirements declared: nothing to judge.
    let none = metrics_of("Name: foo\n", None);
    assert_eq!(none.get("consistency.self_dependency"), None);
}

#[test]
fn self_dependency_reads_the_leading_block_of_requires_txt() {
    let requires = "requests>=2\nmy-pkg==1.0\n\n[dev]\nmy-pkg[test]\n";
    let metrics = metrics_of("Name: my_pkg\n", Some(requires));
    assert_eq!(metrics.get("consistency.self_dependency"), Some(1.0));
    let optional_only = metrics_of("Name: my_pkg\n", Some("[dev]\nmy-pkg[test]\n"));
    assert_eq!(optional_only.get("consistency.self_dependency"), Some(0.0));
}

#[test]
fn npm_self_dependency_reads_runtime_dependencies() {
    let manifest =
        |json: &str| -> serde_json::Map<String, JsonValue> { serde_json::from_str(json).unwrap() };
    assert_eq!(
        npm_self_dependencies(&manifest(
            r#"{"name":"pucuk","dependencies":{"pucuk":"*","x":"1"}}"#
        )),
        Some(1)
    );
    assert_eq!(
        npm_self_dependencies(&manifest(r#"{"name":"a","dependencies":{"b":"1"}}"#)),
        Some(0)
    );
    assert_eq!(
        npm_self_dependencies(&manifest(r#"{"name":"a","devDependencies":{"a":"1"}}"#)),
        None
    );
}

#[test]
fn requirement_names_end_at_the_first_non_name_character() {
    assert_eq!(requirement_name("foo>=1.0"), "foo");
    assert_eq!(
        requirement_name(" foo[extra] >= 1 ; python_version < '3'"),
        "foo"
    );
    assert_eq!(requirement_name("foo (>=1.0)"), "foo");
    assert_eq!(requirement_name("zope.interface==5"), "zope.interface");
    assert_eq!(requirement_name("my_pkg~=2"), "my_pkg");
}

#[test]
fn requirement_commas_stay_inside_the_requirement() {
    // Extras and version ranges carry commas; neither starts a requirement.
    let ranged = metrics_of(
        "Name: foo\nRequires-Dist: bar>=1,<2\nRequires-Dist: baz[x,foo]\n",
        None,
    );
    assert_eq!(ranged.get("consistency.self_dependency"), Some(0.0));
}
