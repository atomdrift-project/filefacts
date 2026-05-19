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

pub(super) fn extract(manifest_bytes: &[u8], values: &mut Values) {
    let Ok(text) = std::str::from_utf8(manifest_bytes) else {
        return;
    };

    if let Some(level) = attribute_value(text, "requestedExecutionLevel", "level") {
        put_str(values, "pe.manifest.requested_execution_level", level);
    }
    if let Some(ui) = attribute_value(text, "requestedExecutionLevel", "uiAccess") {
        put_str(values, "pe.manifest.ui_access", ui);
    }

    // Top-level `<assemblyIdentity>` describes the assembly itself.
    // Manifests can carry several `<assemblyIdentity>` nodes — one at
    // the root and one inside each `<dependentAssembly>`. The first
    // occurrence in document order is the canonical "this assembly"
    // record; later occurrences are dependency declarations.
    if let Some(tag) = first_tag(text, "assemblyIdentity") {
        if let Some(name) = attr_value_in_tag(tag, "name") {
            put_str(values, "pe.manifest.assembly_identity.name", name);
        }
        if let Some(version) = attr_value_in_tag(tag, "version") {
            put_str(values, "pe.manifest.assembly_identity.version", version);
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
    if let Some(desc) = element_text(text, "description") {
        put_str(values, "pe.manifest.description", desc);
    }

    let supported: Vec<JsonValue> = supported_os_ids(text)
        .into_iter()
        .map(JsonValue::String)
        .collect();
    if !supported.is_empty() {
        values.insert(
            "pe.manifest.supported_os",
            JsonValue::Array(supported),
        );
    }

    // `dpiAware` and `dpiAwareness` are element text nodes, not
    // attributes, but they live inside `<application>` and the
    // simple-grep approach still works.
    if let Some(v) = element_text(text, "dpiAware") {
        put_str(values, "pe.manifest.dpi_aware", v);
    }
    if let Some(v) = element_text(text, "dpiAwareness") {
        put_str(values, "pe.manifest.dpi_awareness", v);
    }
    if let Some(v) = element_text(text, "longPathAware") {
        put_str(values, "pe.manifest.long_path_aware", v);
    }
    if let Some(v) = element_text(text, "autoElevate") {
        put_str(values, "pe.manifest.auto_elevate", v);
    }
}

/// Return the value of `attr` on the first `<elem ... attr="value" …>`
/// tag in the input. Trims whitespace. Returns `None` when the element
/// or attribute is not present.
fn attribute_value(text: &str, elem: &str, attr: &str) -> Option<String> {
    let tag_start = find_open_tag(text, elem)?;
    let tag_end = text[tag_start..]
        .find('>')
        .map_or(text.len(), |n| tag_start + n);
    let tag = &text[tag_start..tag_end];
    attr_value_in_tag(tag, attr)
}

fn attr_value_in_tag(tag: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=");
    let idx = tag.find(&pattern)?;
    let after = &tag[idx + pattern.len()..];
    let after = after.trim_start();
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value_start = after.len() - after[1..].len();
    let rest = &after[value_start..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
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
    let open = find_open_tag(text, elem)?;
    let after = open + 1;
    let close = after + text[after..].find('>')?;
    Some(&text[after..close])
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

/// Return the text content of the first `<elem>…</elem>` pair.
fn element_text(text: &str, elem: &str) -> Option<String> {
    let open = find_open_tag(text, elem)?;
    let tag_end = text[open..].find('>').map(|n| open + n + 1)?;
    let close_marker = format!("</{elem}");
    let close = text[tag_end..].find(&close_marker)?;
    let value = text[tag_end..tag_end + close].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
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
    fn parses_supported_os_ids() {
        let mut v = crate::Values::new();
        extract(SAMPLE.as_bytes(), &mut v);
        let arr = v
            .get("pe.manifest.supported_os")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr
            .iter()
            .any(|x| x.as_str() == Some("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}")));
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
            v.get("pe.manifest.assembly_identity.name").and_then(|x| x.as_str()),
            Some("Microsoft.Windows.SampleApp")
        );
        assert_eq!(
            v.get("pe.manifest.assembly_identity.version").and_then(|x| x.as_str()),
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
        let deps = v.get("pe.manifest.dependencies").and_then(|x| x.as_array()).unwrap();
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
            v.get("pe.manifest.long_path_aware").and_then(|x| x.as_str()),
            Some("true")
        );
    }
}
