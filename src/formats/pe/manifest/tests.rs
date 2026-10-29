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
    extract(SAMPLE.as_bytes(), None, &mut v);
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
    extract(SAMPLE.as_bytes(), Some(base), &mut v);

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
    extract(SAMPLE.as_bytes(), None, &mut v);
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
    extract(SAMPLE_WITH_DEPS.as_bytes(), None, &mut v);
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
    extract(SAMPLE_WITH_DEPS.as_bytes(), None, &mut v);
    assert_eq!(
        v.get("pe.manifest.description").and_then(|x| x.as_str()),
        Some("A sample application manifest")
    );
}

#[test]
fn parses_dependencies() {
    let mut v = crate::Values::new();
    extract(SAMPLE_WITH_DEPS.as_bytes(), None, &mut v);
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

/// A resource of nothing but `<` is not XML: it is refused at the first
/// byte that cannot open a tag, in time linear in its size, and yields the
/// parse error rather than values.
#[test]
fn non_xml_manifest_is_refused_quickly() {
    let mut text = "<".repeat(256 * 1024);
    text.push_str("<asmv3:dpiAware>true</dpiAware>");
    let mut v = crate::Values::new();
    extract(text.as_bytes(), None, &mut v);
    assert!(v.get("pe.manifest.dpi_aware").is_none());
    assert!(v.get("pe.manifest.parse_error").is_some());
}

/// A decoy `requestedExecutionLevel` placed first inside a comment is not
/// an element: the loader honours the real one after it, and so must the
/// facts. A text search read the comment's `asInvoker` and hid both the
/// elevation and the UI-access bypass.
#[test]
fn commented_out_execution_level_does_not_hide_the_real_one() {
    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <!-- <requestedExecutionLevel level="asInvoker" uiAccess="false" /> -->
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="true" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#;
    let mut v = crate::Values::new();
    extract(manifest.as_bytes(), Some(0), &mut v);
    assert_eq!(
        v.get("pe.manifest.requested_execution_level")
            .and_then(|x| x.as_str()),
        Some("requireAdministrator")
    );
    assert_eq!(
        v.get("pe.manifest.ui_access").and_then(|x| x.as_str()),
        Some("true")
    );
    let offset = v
        .get("pe.manifest.requested_execution_level_offset")
        .and_then(|x| x.as_u64())
        .unwrap();
    assert_eq!(
        manifest.find("requireAdministrator").map(|at| at as u64),
        Some(offset)
    );
}

/// Elements match by local name under any declared namespace prefix, and a
/// byte-order mark does not shift the offsets off the resource's bytes.
#[test]
fn prefixed_elements_and_a_bom_are_located_exactly() {
    let manifest = "\u{FEFF}<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" \
        xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">\
        <asmv3:application><asmv3:windowsSettings>\
        <dpiAware>true</dpiAware></asmv3:windowsSettings></asmv3:application></assembly>";
    let base = 0x100_u64;
    let mut v = crate::Values::new();
    extract(manifest.as_bytes(), Some(base), &mut v);
    assert_eq!(
        v.get("pe.manifest.dpi_aware").and_then(|x| x.as_str()),
        Some("true")
    );
    let offset = v
        .get("pe.manifest.dpi_aware_offset")
        .and_then(|x| x.as_u64())
        .unwrap();
    assert_eq!(
        &manifest.as_bytes()[(offset - base) as usize..][..4],
        b"true"
    );
}

#[test]
fn parses_dpi_aware() {
    let mut v = crate::Values::new();
    extract(SAMPLE.as_bytes(), None, &mut v);
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
