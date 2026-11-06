use super::*;

#[test]
fn popular_list_is_sorted_for_binary_search() {
    assert!(TERRAFORM_POPULAR.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn flags_a_namespace_one_edit_from_a_popular_provider() {
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "kreuzwenker/docker"),
        Some(1.0)
    );
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "Kreuzwenker/Docker"),
        Some(1.0)
    );
    // Swap, insertion, deletion.
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "hashicrop/aws"),
        Some(1.0)
    );
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "hashicorpp/aws"),
        Some(1.0)
    );
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "hashcorp/aws"),
        Some(1.0)
    );
}

#[test]
fn leaves_the_real_provider_forks_and_other_ecosystems_alone() {
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "kreuzwerker/docker"),
        Some(0.0)
    );
    // Two edits: a legitimate fork, not a squat.
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "cnrancher/rancher2"),
        Some(0.0)
    );
    // A popular type under an unrelated namespace is ordinary.
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "gocommunity-io/docker"),
        Some(0.0)
    );
    // A lookalike namespace with a different type is not this shape.
    assert_eq!(
        name_lookalike(&Ecosystem::Terraform, "hashicrop/dockerd"),
        Some(0.0)
    );
    assert_eq!(name_lookalike(&Ecosystem::Npm, "kreuzwenker/docker"), None);
}

/// A Terraform name is checked whatever its shape: one without a namespace
/// is not a lookalike, and that is a result, not "no list".
#[test]
fn a_name_without_a_namespace_is_checked_and_clean() {
    assert_eq!(name_lookalike(&Ecosystem::Terraform, "docker"), Some(0.0));
}

/// The ecosystem is Terraform by its label, however the value was built.
#[test]
fn terraform_spelled_as_another_label_is_still_checked() {
    for label in ["terraform", "Terraform"] {
        assert_eq!(
            name_lookalike(&Ecosystem::Other(label.into()), "kreuzwenker/docker"),
            Some(1.0),
            "{label}"
        );
    }
}

#[test]
fn one_edit_is_exactly_one() {
    for (a, b) in [
        ("ab", "ba"),
        ("abc", "abd"),
        ("abc", "ab"),
        ("ab", "abc"),
        ("a", ""),
    ] {
        assert!(one_edit(a, b), "{a} vs {b}");
    }
    for (a, b) in [
        ("abc", "abc"),
        ("abc", "cba"),
        ("abcd", "badc"),
        ("abc", "a"),
        ("", ""),
    ] {
        assert!(!one_edit(a, b), "{a} vs {b}");
    }
}
