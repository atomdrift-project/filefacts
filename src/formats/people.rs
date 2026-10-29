//! The people a package names, in one shape for every ecosystem.
//!
//! Each format publishes `<fmt>.authors`, `<fmt>.maintainers`, `<fmt>.owners`
//! and `<fmt>.packagers` as lists of `{name, email, url}` objects, with absent
//! fields omitted, however its manifest spells them: npm's `author` object or
//! `"Name <email> (url)"` string, Cargo's `authors` array, a Debian
//! `Maintainer` line, Core Metadata's separate `Author` and `Author-email`
//! headers, NuGet's comma-separated `authors`. The identity view reads them
//! back through [`read`].

use serde_json::{Map, Value as JsonValue};

use crate::output::{ValueKey, Values};

/// One person: any of a display name, an email address and a URL.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Person {
    pub(crate) name: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) url: Option<String>,
}

impl Person {
    /// Split the npm/Cargo/Debian person string `"Name <email> (url)"`; any
    /// part may be missing.
    pub(crate) fn parse(s: &str) -> Self {
        let name_end = s.find(['<', '(']).unwrap_or(s.len());
        Self {
            name: nonempty(s.get(..name_end).unwrap_or_default()),
            email: between(s, '<', '>'),
            url: between(s, '(', ')'),
        }
    }

    /// A person from separate name and email fields. The email field may
    /// itself be a bare address or a `Name <email>` pair (Core Metadata's
    /// `Author-email`); the dedicated name field wins over an embedded one.
    pub(crate) fn from_fields(name: Option<&str>, email: Option<&str>) -> Self {
        let embedded = email.map(Self::parse).unwrap_or_default();
        let email = match (embedded.email, email) {
            (Some(inner), _) => Some(inner),
            (None, Some(raw)) => nonempty(raw),
            (None, None) => None,
        };
        Self {
            name: name.and_then(nonempty).or(embedded.name),
            email,
            url: None,
        }
    }

    /// A person from a JSON value: a person string, or an object with
    /// `name`, `email` and `url` string fields.
    pub(crate) fn from_json(value: &JsonValue) -> Self {
        match value {
            JsonValue::String(s) => Self::parse(s),
            JsonValue::Object(o) => {
                let field = |k: &str| o.get(k).and_then(JsonValue::as_str).and_then(nonempty);
                Self {
                    name: field("name"),
                    email: field("email"),
                    url: field("url"),
                }
            }
            _ => Self::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.name.is_none() && self.email.is_none() && self.url.is_none()
    }

    fn into_json(self) -> JsonValue {
        let mut obj = Map::new();
        for (k, v) in [
            ("name", self.name),
            ("email", self.email),
            ("url", self.url),
        ] {
            if let Some(v) = v {
                obj.insert(k.into(), JsonValue::String(v));
            }
        }
        JsonValue::Object(obj)
    }
}

/// Publish `people` under `key`, dropping empty entries and repeats; nothing
/// is written when none remain.
pub(crate) fn put(values: &mut Values, key: ValueKey, people: impl IntoIterator<Item = Person>) {
    let mut kept: Vec<Person> = Vec::new();
    for person in people {
        if !person.is_empty() && !kept.contains(&person) {
            kept.push(person);
        }
    }
    if !kept.is_empty() {
        let list = kept.into_iter().map(Person::into_json).collect();
        values.insert_key(key, JsonValue::Array(list));
    }
}

/// The people published under `key`.
pub(crate) fn read(values: &Values, key: ValueKey) -> impl Iterator<Item = Person> + '_ {
    values
        .get_key(key)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .map(Person::from_json)
        .filter(|p| !p.is_empty())
}

fn between(s: &str, open: char, close: char) -> Option<String> {
    let (_, rest) = s.split_once(open)?;
    let (inner, _) = rest.split_once(close)?;
    nonempty(inner)
}

fn nonempty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(test)]
mod tests;
