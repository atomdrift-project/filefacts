use super::*;

fn person(name: Option<&str>, email: Option<&str>, url: Option<&str>) -> Person {
    Person {
        name: name.map(str::to_string),
        email: email.map(str::to_string),
        url: url.map(str::to_string),
    }
}

#[test]
fn person_strings_split_into_their_parts() {
    assert_eq!(
        Person::parse("Ada Lovelace <ada@example.org> (https://example.org/ada)"),
        person(
            Some("Ada Lovelace"),
            Some("ada@example.org"),
            Some("https://example.org/ada")
        )
    );
    assert_eq!(
        Person::parse("<ada@example.org>"),
        person(None, Some("ada@example.org"), None)
    );
    assert_eq!(Person::parse("Ada"), person(Some("Ada"), None, None));
    assert_eq!(Person::parse("  "), Person::default());
}

/// Core Metadata puts a `Name <email>` pair in `Author-email` when `Author`
/// is empty; the dedicated name field wins when both carry one.
#[test]
fn separate_fields_resolve_an_embedded_name() {
    assert_eq!(
        Person::from_fields(None, Some("Ada <ada@example.org>")),
        person(Some("Ada"), Some("ada@example.org"), None)
    );
    assert_eq!(
        Person::from_fields(Some("Ada Lovelace"), Some("Ada <ada@example.org>")),
        person(Some("Ada Lovelace"), Some("ada@example.org"), None)
    );
    assert_eq!(
        Person::from_fields(Some("Ada"), Some("ada@example.org")),
        person(Some("Ada"), Some("ada@example.org"), None)
    );
}

#[test]
fn published_people_drop_empties_and_repeats_and_read_back() {
    let mut values = Values::new();
    let key = crate::value_key!("npm.maintainers");
    put(
        &mut values,
        key,
        [
            Person::parse("Ada <ada@example.org>"),
            Person::default(),
            Person::parse("Ada <ada@example.org>"),
            Person::parse("Grace"),
        ],
    );
    assert_eq!(
        values.get("npm.maintainers"),
        Some(&serde_json::json!([
            {"name": "Ada", "email": "ada@example.org"},
            {"name": "Grace"},
        ]))
    );
    let back: Vec<Person> = read(&values, key).collect();
    assert_eq!(
        back,
        [
            person(Some("Ada"), Some("ada@example.org"), None),
            person(Some("Grace"), None, None)
        ]
    );

    let mut empty = Values::new();
    put(&mut empty, key, [Person::default()]);
    assert!(empty.get("npm.maintainers").is_none());
}
