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
    assert_eq!(name_lookalike(&Ecosystem::Terraform, "docker"), None);
    assert_eq!(name_lookalike(&Ecosystem::Npm, "kreuzwenker/docker"), None);
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
