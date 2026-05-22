//! Structural key-value data extracted from a file.

use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

/// Structural key-value data extracted from a file.
///
/// `Values` is the natural-shape projection of whatever a format defines:
/// header fields, manifest data, archive index entries, version-info
/// resources. The internal representation is a JSON object (`{}` at the
/// root) so the same data prints, serialises, and navigates uniformly
/// across every supported format.
///
/// Typed fact families are deliberately not mirrored here: strings, sections,
/// imports, exports, functions, AST projections, and recoverable parse
/// errors have their own views. Values is for residual format structure and
/// derived format-specific facts that do not yet have a typed home.
///
/// Keys are format-conventional. A PE file's machine type lives at
/// `pe.coff.machine`. An ELF's needed-library list lives at
/// `elf.dynamic.needed[]`. A JSON manifest's parsed content is exposed
/// directly without a synthetic prefix — `fileid` already tells consumers
/// which manifest format they're looking at.
///
/// # Example
///
/// ```
/// # use serde_json::json;
/// # use filefacts::Values;
/// let mut v = Values::new();
/// v.insert("pe.coff.machine", json!("x86_64"));
/// v.insert("pe.coff.timestamp_unix", json!(1_700_000_000_i64));
///
/// assert_eq!(v.get("pe.coff.machine").and_then(|x| x.as_str()), Some("x86_64"));
/// ```
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Values(JsonValue);

impl Values {
    /// Build an empty `Values` object.
    pub fn new() -> Self {
        Self(JsonValue::Object(Map::new()))
    }

    /// Wrap an existing JSON value as a `Values` view. The caller is
    /// responsible for ensuring the top-level value is an object; if it
    /// isn't, accessor methods will return `None` / behave as if empty.
    pub(crate) fn from_json(value: JsonValue) -> Self {
        Self(value)
    }

    /// Insert a value at a dot-delimited path, creating intermediate
    /// objects as needed.
    ///
    /// Existing values at intermediate keys that are not objects are
    /// overwritten. Existing values at the leaf are replaced. Path
    /// segments containing `[`, `]`, or `.` are not supported — those
    /// characters are reserved for the lookup grammar.
    pub fn insert(&mut self, path: &str, value: JsonValue) {
        let JsonValue::Object(ref mut root) = self.0 else {
            self.0 = JsonValue::Object(Map::new());
            return self.insert(path, value);
        };
        insert_path(root, path, value);
    }

    /// Look up a value by dot-delimited path. Supports `[N]` index access
    /// for array elements but not the `[*]` wildcard (callers wanting
    /// wildcard semantics should iterate the array directly).
    pub fn get(&self, path: &str) -> Option<&JsonValue> {
        navigate(&self.0, path)
    }

    /// Borrow the underlying JSON representation. Useful when integrating
    /// with downstream tools that already expect `serde_json::Value`.
    pub fn as_json(&self) -> &JsonValue {
        &self.0
    }

    /// Consume the `Values` and return the underlying JSON.
    pub fn into_json(self) -> JsonValue {
        self.0
    }

    /// Iterate top-level (key, value) pairs. Returns an empty iterator if
    /// the root is not an object.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &JsonValue)> {
        self.0
            .as_object()
            .into_iter()
            .flat_map(|m| m.iter().map(|(k, v)| (k.as_str(), v)))
    }

    /// `true` when the values object has no top-level keys.
    pub fn is_empty(&self) -> bool {
        self.0.as_object().is_none_or(Map::is_empty)
    }
}

fn insert_path(root: &mut Map<String, JsonValue>, path: &str, value: JsonValue) {
    let mut segments = path.split('.').peekable();
    let mut cur = root;
    while let Some(seg) = segments.next() {
        if segments.peek().is_none() {
            cur.insert(seg.to_string(), value);
            return;
        }
        let entry = cur
            .entry(seg.to_string())
            .or_insert_with(|| JsonValue::Object(Map::new()));
        if !entry.is_object() {
            *entry = JsonValue::Object(Map::new());
        }
        cur = entry
            .as_object_mut()
            .expect("just ensured the entry is an object");
    }
}

fn navigate<'a>(value: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = value;
    for raw in path.split('.') {
        let (key, idx) = split_index(raw);
        if !key.is_empty() {
            cur = cur.as_object()?.get(key)?;
        }
        if let Some(i) = idx {
            cur = cur.as_array()?.get(i)?;
        }
    }
    Some(cur)
}

/// Split a path segment into its key part and an optional `[N]` index.
/// Segments without brackets return `(segment, None)`. Malformed brackets
/// (`a[`, `a[b]`) return `(segment, None)` and let `navigate` fail on the
/// non-object lookup — matching the principle that path parsing is
/// forgiving but lookups are strict.
fn split_index(segment: &str) -> (&str, Option<usize>) {
    let Some(open) = segment.find('[') else {
        return (segment, None);
    };
    if !segment.ends_with(']') {
        return (segment, None);
    }
    let key = &segment[..open];
    let idx_str = &segment[open + 1..segment.len() - 1];
    match idx_str.parse::<usize>() {
        Ok(i) => (key, Some(i)),
        Err(_) => (segment, None),
    }
}

#[cfg(test)]
mod split_index_tests {
    use super::split_index;

    #[test]
    fn plain_key() {
        assert_eq!(split_index("plain"), ("plain", None));
    }

    #[test]
    fn indexed_key() {
        assert_eq!(split_index("members[0]"), ("members", Some(0)));
        assert_eq!(split_index("a[42]"), ("a", Some(42)));
    }

    #[test]
    fn malformed_falls_through() {
        // Strict parsing here would force every caller to handle the
        // "malformed input" case. Returning the segment unchanged lets
        // `navigate` fail naturally on the subsequent object lookup.
        assert_eq!(split_index("members["), ("members[", None));
        assert_eq!(split_index("members[a]"), ("members[a]", None));
    }
}

#[cfg(test)]
mod tests {
    use super::Values;
    use serde_json::json;

    #[test]
    fn insert_and_get_top_level() {
        let mut v = Values::new();
        v.insert("name", json!("filefacts"));
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("filefacts"));
    }

    #[test]
    fn insert_creates_nested_objects() {
        let mut v = Values::new();
        v.insert("pe.coff.machine", json!("x86_64"));
        assert_eq!(
            v.get("pe.coff.machine").and_then(|x| x.as_str()),
            Some("x86_64")
        );
        assert!(v.get("pe.coff").unwrap().is_object());
    }

    #[test]
    fn insert_overwrites_non_object_intermediate() {
        // Setting a leaf, then nesting under the same key, should not
        // panic — the leaf is overwritten with an object.
        let mut v = Values::new();
        v.insert("pe", json!("leaf"));
        v.insert("pe.coff.machine", json!("x86_64"));
        assert_eq!(
            v.get("pe.coff.machine").and_then(|x| x.as_str()),
            Some("x86_64")
        );
    }

    #[test]
    fn get_missing_returns_none() {
        let v = Values::new();
        assert!(v.get("nope").is_none());
        assert!(v.get("a.b.c").is_none());
    }

    #[test]
    fn iter_yields_top_level() {
        let mut v = Values::new();
        v.insert("a", json!(1));
        v.insert("b", json!(2));
        let keys: Vec<&str> = v.iter().map(|(k, _)| k).collect();
        assert!(keys.contains(&"a"));
        assert!(keys.contains(&"b"));
    }

    #[test]
    fn is_empty_works() {
        let v = Values::new();
        assert!(v.is_empty());
        let mut v = Values::new();
        v.insert("x", json!(1));
        assert!(!v.is_empty());
    }

    #[test]
    fn serializes_as_json_object() {
        let mut v = Values::new();
        v.insert("pe.coff.machine", json!("x86_64"));
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"pe":{"coff":{"machine":"x86_64"}}}"#);
    }
}
