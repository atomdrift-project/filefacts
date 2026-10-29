use super::*;

/// `as_str` spells every role exactly as serde does.
#[test]
fn party_role_names_match_serde() {
    for role in [
        PartyRole::Author,
        PartyRole::Maintainer,
        PartyRole::Owner,
        PartyRole::Packager,
        PartyRole::Builder,
        PartyRole::LastModifiedBy,
        PartyRole::Manager,
    ] {
        assert_eq!(
            serde_json::to_value(role).unwrap(),
            role.as_str(),
            "{role:?}"
        );
    }
}
