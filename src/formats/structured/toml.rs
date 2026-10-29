//! TOML documents, converted into the JSON tree `values` holds.

use serde_json::{Map, Value as JsonValue};

pub(super) fn toml_to_json(value: ::toml::Value) -> JsonValue {
    use ::toml::Value as T;
    match value {
        T::String(s) => JsonValue::String(s),
        T::Integer(i) => JsonValue::Number(i.into()),
        T::Float(f) => serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        T::Boolean(b) => JsonValue::Bool(b),
        T::Datetime(dt) => JsonValue::String(dt.to_string()),
        T::Array(arr) => JsonValue::Array(arr.into_iter().map(toml_to_json).collect()),
        T::Table(tab) => {
            let mut obj = Map::new();
            for (k, v) in tab {
                obj.insert(k, toml_to_json(v));
            }
            JsonValue::Object(obj)
        }
    }
}
