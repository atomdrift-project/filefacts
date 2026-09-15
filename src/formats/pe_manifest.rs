//! PE side-by-side manifest (RT_MANIFEST) extractor.
//!
//! Win32 binaries embed an XML manifest in the `RT_MANIFEST` resource
//! that declares the OS / DPI / privilege requirements the loader
//! applies before transferring control. The forensically interesting
//! attributes:
//!
//! - `requestedExecutionLevel` (`asInvoker`, `requireAdministrator`,
//!   `highestAvailable`) — privilege the binary expects.
//! - `uiAccess` — UI-automation bypass capability.
//! - `supportedOS@Id` GUID list — Windows versions the binary
//!   declares support for.
//! - `dpiAware` / `dpiAwareness` — high-DPI handling.
//!
//! We extract these by *byte-level pattern matching* rather than a
//! real XML parse. Manifests are tiny (a few hundred bytes typically),
//! have a fixed attribute vocabulary, and a real XML parser would
//! pull a heavyweight dep for negligible benefit. The patterns we
//! match are the actual Win32 manifest schema attribute names.

use serde_json::Value as JsonValue;

use crate::formats::common::put_str;
use crate::output::Values;

#[allow(dead_code)]
pub(super) fn extract(manifest_bytes: &[u8], values: &mut Values) {
    extract_at(manifest_bytes, None, values);
}

pub(super) fn extract_at(manifest_bytes: &[u8], file_offset: Option<u64>, values: &mut Values) {
    let Ok(text) = std::str::from_utf8(manifest_bytes) else {
        return;
    };

    if let Some((level, rel)) =
        attribute_value_with_offset(text, "requestedExecutionLevel", "level")
    {
        put_str_at(
            values,
            "pe.manifest.requested_execution_level",
            level,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }
    if let Some((ui, rel)) =
        attribute_value_with_offset(text, "requestedExecutionLevel", "uiAccess")
    {
        put_str_at(
            values,
            "pe.manifest.ui_access",
            ui,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }

    // Top-level `<assemblyIdentity>` describes the assembly itself.
    // Manifests can carry several `<assemblyIdentity>` nodes — one at
    // the root and one inside each `<dependentAssembly>`. The first
    // occurrence in document order is the canonical "this assembly"
    // record; later occurrences are dependency declarations.
    if let Some((tag, tag_start)) = first_tag_with_offset(text, "assemblyIdentity") {
        if let Some((name, rel)) = attr_value_in_tag_with_offset(tag, "name") {
            put_str_at(
                values,
                "pe.manifest.assembly_identity.name",
                name,
                file_offset,
                manifest_bytes,
                Some(tag_start + 1 + rel),
            );
        }
        if let Some((version, rel)) = attr_value_in_tag_with_offset(tag, "version") {
            put_str_at(
                values,
                "pe.manifest.assembly_identity.version",
                version,
                file_offset,
                manifest_bytes,
                Some(tag_start + 1 + rel),
            );
        }
    }

    // Dependencies live as `<dependentAssembly><assemblyIdentity
    // name="…" version="…" />…</dependentAssembly>` blocks. Emit each
    // as `"name@version"` to mirror the `elf.needed_versions` shape.
    let deps = dependencies(text);
    if !deps.is_empty() {
        values.insert(
            "pe.manifest.dependencies",
            JsonValue::Array(deps.into_iter().map(JsonValue::String).collect()),
        );
    }

    // Free-text `<description>` element. Many real-world manifests
    // omit it; UAC installers and Microsoft inbox tools tend to set
    // it to a recognisable string.
    if let Some((desc, rel)) = element_text_with_offset(text, "description") {
        put_str_at(
            values,
            "pe.manifest.description",
            desc,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }

    let supported: Vec<JsonValue> = supported_os_ids(text)
        .into_iter()
        .map(JsonValue::String)
        .collect();
    if !supported.is_empty() {
        values.insert("pe.manifest.supported_os", JsonValue::Array(supported));
    }

    // `dpiAware` and `dpiAwareness` are element text nodes, not
    // attributes, but they live inside `<application>` and the
    // simple-grep approach still works.
    if let Some((v, rel)) = element_text_with_offset(text, "dpiAware") {
        put_str_at(
            values,
            "pe.manifest.dpi_aware",
            v,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }
    if let Some((v, rel)) = element_text_with_offset(text, "dpiAwareness") {
        put_str_at(
            values,
            "pe.manifest.dpi_awareness",
            v,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }
    if let Some((v, rel)) = element_text_with_offset(text, "longPathAware") {
        put_str_at(
            values,
            "pe.manifest.long_path_aware",
            v,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }
    if let Some((v, rel)) = element_text_with_offset(text, "autoElevate") {
        put_str_at(
            values,
            "pe.manifest.auto_elevate",
            v,
            file_offset,
            manifest_bytes,
            Some(rel),
        );
    }
}

/// Store a manifest value and, when the resource parser gave us the resource's
/// file offset, store the exact byte offset of the value's first UTF-8 byte.
/// The offset is intentionally omitted when the enclosing resource could not be
/// mapped back to the input buffer; a semantic label is safer than a guessed
/// header offset in that degraded case.
fn put_str_at(
    values: &mut Values,
    path: &str,
    value: String,
    file_offset: Option<u64>,
    manifest_bytes: &[u8],
    relative_offset: Option<usize>,
) {
    let value_offset = file_offset.and_then(|base| {
        relative_offset
            .filter(|&relative| {
                relative <= manifest_bytes.len()
                    && value.len() <= manifest_bytes.len().saturating_sub(relative)
            })
            .map(|relative| base.saturating_add(relative as u64))
    });
    put_str(values, path, value);
    if let Some(offset) = value_offset {
        values.insert(
            &format!("{path}_offset"),
            serde_json::Value::Number(offset.into()),
        );
    }
}

/// Return the value of `attr` on the first `<elem ... attr="value" …>`
/// tag in the input. Trims whitespace. Returns `None` when the element
/// or attribute is not present.
fn attribute_value_with_offset(text: &str, elem: &str, attr: &str) -> Option<(String, usize)> {
    let tag_start = find_open_tag(text, elem)?;
    let tag_end = text[tag_start..]
        .find('>')
        .map_or(text.len(), |n| tag_start + n);
    let tag = &text[tag_start..tag_end];
    let (value, relative) = attr_value_in_tag_with_offset(tag, attr)?;
    Some((value, tag_start + relative))
}

fn attr_value_in_tag(tag: &str, attr: &str) -> Option<String> {
    attr_value_in_tag_with_offset(tag, attr).map(|(value, _)| value)
}

fn attr_value_in_tag_with_offset(tag: &str, attr: &str) -> Option<(String, usize)> {
    let pattern = format!("{attr}=");
    let mut search_from = 0;
    while let Some(rel) = tag[search_from..].find(&pattern) {
        let idx = search_from + rel;
        // The attribute name must begin a token — preceded by tag
        // whitespace, the opening `<`, or a `/` (for empty elements).
        // Otherwise we'd accept `Id=` matching the tail of `someId=`.
        let preceded_by_boundary = idx == 0
            || matches!(
                tag.as_bytes()[idx - 1],
                b' ' | b'\t' | b'\r' | b'\n' | b'<' | b'/'
            );
        if !preceded_by_boundary {
            search_from = idx + pattern.len();
            continue;
        }
        let raw_after = &tag[idx + pattern.len()..];
        let after = raw_after.trim_start();
        let leading_whitespace = raw_after.len() - after.len();
        let quote = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let rest = &after[1..];
        let end = rest.find(quote)?;
        let value_start = idx + pattern.len() + leading_whitespace + quote.len_utf8();
        return Some((rest[..end].to_string(), value_start));
    }
    None
}

/// Find the first `<elem` occurrence. Tolerates whitespace and
/// namespace prefixes (e.g. `<asmv3:requestedExecutionLevel`).
fn find_open_tag(text: &str, elem: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(open) = text[search_from..].find('<') {
        let abs = search_from + open + 1;
        if abs >= text.len() {
            return None;
        }
        let after = &text[abs..];
        // Skip namespace prefix if present.
        let rest = match after.find(':') {
            Some(colon) if colon < after.len() && colon < 16 => &after[colon + 1..],
            _ => after,
        };
        if rest.starts_with(elem) {
            // Confirm the next character is whitespace, `>`, or `/`.
            let next = rest.as_bytes().get(elem.len()).copied().unwrap_or(b' ');
            if next.is_ascii_whitespace() || next == b'>' || next == b'/' {
                return Some(abs - 1);
            }
        }
        search_from = abs;
    }
    None
}

/// Extract the text content of every `<supportedOS Id="…">` element.
/// Windows OS GUIDs are the only canonical signal here; e.g.
/// `{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}` is Windows 10/11.
fn supported_os_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = find_open_tag(&text[from..], "supportedOS") {
        let abs = from + start;
        let tag_end = text[abs..].find('>').map_or(text.len(), |n| abs + n);
        let tag = &text[abs..tag_end];
        if let Some(id) = attr_value_in_tag(tag, "Id") {
            out.push(id);
        }
        from = tag_end + 1;
        if from >= text.len() {
            break;
        }
    }
    out
}

/// Return the contents of the first `<elem … >` start tag (everything
/// between `<` and `>`, exclusive of those delimiters). Used when the
/// caller wants to scan multiple attributes off the same element.
fn first_tag<'a>(text: &'a str, elem: &str) -> Option<&'a str> {
    first_tag_with_offset(text, elem).map(|(tag, _)| tag)
}

fn first_tag_with_offset<'a>(text: &'a str, elem: &str) -> Option<(&'a str, usize)> {
    let open = find_open_tag(text, elem)?;
    let after = open + 1;
    let close = after + text[after..].find('>')?;
    Some((&text[after..close], open))
}

/// Walk every `<dependentAssembly>` block and pull the `name@version`
/// pair from the `<assemblyIdentity>` child inside it.
fn dependencies(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = find_open_tag(&text[from..], "dependentAssembly") {
        let abs = from + start;
        let close_marker = "</dependentAssembly";
        let end_rel = text[abs..].find(close_marker);
        let block_end = match end_rel {
            Some(n) => abs + n,
            None => text.len(),
        };
        let block = &text[abs..block_end];
        if let Some(tag) = first_tag(block, "assemblyIdentity") {
            let name = attr_value_in_tag(tag, "name").unwrap_or_default();
            let version = attr_value_in_tag(tag, "version").unwrap_or_default();
            if !name.is_empty() {
                if version.is_empty() {
                    out.push(name);
                } else {
                    out.push(format!("{name}@{version}"));
                }
            }
        }
        from = block_end + close_marker.len();
        if from >= text.len() {
            break;
        }
    }
    out
}

/// Return the text content and byte-relative value start of the first
/// `<elem>…</elem>` pair. The offset points to the first non-whitespace byte
/// of the text content, matching the value emitted to the fact map.
fn element_text_with_offset(text: &str, elem: &str) -> Option<(String, usize)> {
    let open = find_open_tag(text, elem)?;
    let tag_end = text[open..].find('>').map(|n| open + n + 1)?;
    let close_marker = format!("</{elem}");
    let close = text[tag_end..].find(&close_marker)?;
    let raw = &text[tag_end..tag_end + close];
    let value = raw.trim();
    if value.is_empty() {
        None
    } else {
        let leading_whitespace = raw.len() - raw.trim_start().len();
        Some((value.to_string(), tag_end + leading_whitespace))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>"#;

    #[test]
    fn parses_execution_level() {
        let mut v = crate::Values::new();
        extract(SAMPLE.as_bytes(), &mut v);
        assert_eq!(
            v.get("pe.manifest.requested_execution_level")
                .and_then(|x| x.as_str()),
            Some("requireAdministrator")
        );
        assert_eq!(
            v.get("pe.manifest.ui_access").and_then(|x| x.as_str()),
            Some("false")
        );
    }

    #[test]
    fn offsets_anchor_manifest_values_to_their_exact_bytes() {
        let base = 0x4000_u64;
        let mut v = crate::Values::new();
        extract_at(SAMPLE.as_bytes(), Some(base), &mut v);

        let checks = [
            (
                "pe.manifest.requested_execution_level",
                "requireAdministrator",
                0,
            ),
            ("pe.manifest.ui_access", "false", 0),
            ("pe.manifest.dpi_aware", "true", 0),
            ("pe.manifest.long_path_aware", "true", 1),
        ];
        for (path, value, occurrence) in checks {
            assert_eq!(v.get(path).and_then(|x| x.as_str()), Some(value));
            let offset = v
                .get(&format!("{path}_offset"))
                .and_then(|x| x.as_u64())
                .unwrap();
            let relative = SAMPLE
                .match_indices(value)
                .nth(occurrence)
                .map(|(offset, _)| offset)
                .unwrap();
            assert_eq!(offset, base + relative as u64);
        }
    }

    #[test]
    fn parses_supported_os_ids() {
        let mut v = crate::Values::new();
        extract(SAMPLE.as_bytes(), &mut v);
        let arr = v
            .get("pe.manifest.supported_os")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2);
        assert!(
            arr.iter()
                .any(|x| x.as_str() == Some("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"))
        );
    }

    const SAMPLE_WITH_DEPS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Microsoft.Windows.SampleApp" version="1.0.0.0" processorArchitecture="amd64" />
  <description>A sample application manifest</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="amd64" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.VC90.CRT" version="9.0.21022.8" processorArchitecture="amd64" publicKeyToken="1fc8b3b9a1e18e3b" />
    </dependentAssembly>
  </dependency>
</assembly>"#;

    #[test]
    fn parses_assembly_identity() {
        let mut v = crate::Values::new();
        extract(SAMPLE_WITH_DEPS.as_bytes(), &mut v);
        assert_eq!(
            v.get("pe.manifest.assembly_identity.name")
                .and_then(|x| x.as_str()),
            Some("Microsoft.Windows.SampleApp")
        );
        assert_eq!(
            v.get("pe.manifest.assembly_identity.version")
                .and_then(|x| x.as_str()),
            Some("1.0.0.0")
        );
    }

    #[test]
    fn parses_description() {
        let mut v = crate::Values::new();
        extract(SAMPLE_WITH_DEPS.as_bytes(), &mut v);
        assert_eq!(
            v.get("pe.manifest.description").and_then(|x| x.as_str()),
            Some("A sample application manifest")
        );
    }

    #[test]
    fn parses_dependencies() {
        let mut v = crate::Values::new();
        extract(SAMPLE_WITH_DEPS.as_bytes(), &mut v);
        let deps = v
            .get("pe.manifest.dependencies")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(
            deps[0].as_str(),
            Some("Microsoft.Windows.Common-Controls@6.0.0.0")
        );
        assert_eq!(deps[1].as_str(), Some("Microsoft.VC90.CRT@9.0.21022.8"));
    }

    #[test]
    fn parses_dpi_aware() {
        let mut v = crate::Values::new();
        extract(SAMPLE.as_bytes(), &mut v);
        assert_eq!(
            v.get("pe.manifest.dpi_aware").and_then(|x| x.as_str()),
            Some("true")
        );
        assert_eq!(
            v.get("pe.manifest.long_path_aware")
                .and_then(|x| x.as_str()),
            Some("true")
        );
    }
}
