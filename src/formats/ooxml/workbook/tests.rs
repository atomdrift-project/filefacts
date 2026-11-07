use super::*;

#[test]
fn remote_targets() {
    for remote in [
        "http://evil.example/t.dotm",
        "HTTPS://evil.example/x",
        "\\\\host\\share\\t.dotm",
        "//host/share",
        "file://host/share/t.dotm",
        "smb://host/s",
    ] {
        assert!(is_remote_target(remote), "{remote}");
    }
    for local in [
        "file:///C:/Templates/t.dotm",
        "file:///home/x",
        "file://localhost/x",
        "file://C:/x",
        "C:\\Templates\\t.dotm",
        "../media/image1.png",
        "mailto:a@example.com",
    ] {
        assert!(!is_remote_target(local), "{local}");
    }
}

#[test]
fn sheets_and_defined_names() {
    let xml = r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="Sheet1" sheetId="1"/>
    <sheet name="Data" sheetId="2" state="hidden"/>
    <sheet name="Macro1" sheetId="3" state="veryHidden"/>
  </sheets>
  <definedNames><definedName name="_xlnm.Auto_open">Macro1!$A$1</definedName></definedNames>
</workbook>"#;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let book = parse(&doc);
    let (mut values, mut metrics, mut features) = (Values::new(), Metrics::new(), Vec::new());
    emit(book, &mut values, &mut metrics, &mut features);
    assert_eq!(
        values.get("office.sheet_names"),
        Some(&serde_json::json!(["Sheet1", "Data", "Macro1"]))
    );
    assert_eq!(
        values.get("office.names"),
        Some(&serde_json::json!(["_xlnm.Auto_open"]))
    );
    assert_eq!(metrics.get("office.sheet_count"), Some(3.0));
    assert_eq!(metrics.get("office.hidden_sheet_count"), Some(2.0));
    assert_eq!(metrics.get("office.xlm.very_hidden_sheet_count"), Some(1.0));
    assert_eq!(features, vec!["veryhidden_sheets"]);
}

#[test]
fn xlm_calls_sum_over_macro_sheets() {
    let mut calls = XlmCalls::default();
    calls.add("<f>EXEC(\"calc\")</f><f>RUN(A5)</f><f>CHAR(65)&amp;CHAR(66)</f>");
    calls.add("<f>GET.CELL(1)</f><f>IF(DAY(NOW())&gt;1,HALT())</f><f>FORMULA.FILL(\"x\",B1)</f>");
    assert_eq!(
        calls,
        XlmCalls {
            char: 2,
            day_now: 1,
            formula_fill: 1,
            get_cell: 1,
            run: 1
        }
    );
    assert!(is_macrosheet("xl/macrosheets/sheet1.xml"));
    assert!(!is_macrosheet("xl/worksheets/sheet1.xml"));
}
