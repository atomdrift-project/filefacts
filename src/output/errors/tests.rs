use super::*;

#[test]
fn errors_push_and_iterate() {
    let mut errs = Errors::new();
    errs.record_panic(Stage::PeResourceWalk, "out of range");
    errs.record_fallback(Stage::PeParse, "permissive mode succeeded");
    assert_eq!(errs.len(), 2);
    let kinds: Vec<DiagnosticKind> = errs.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![DiagnosticKind::Panic, DiagnosticKind::Fallback]);
}

#[test]
fn errors_serialize_omits_empty_message() {
    let mut errs = Errors::new();
    errs.record_panic(Stage::MachoParse, String::new());
    let json = serde_json::to_value(&errs).unwrap();
    let arr = json.as_array().unwrap();
    let obj = arr[0].as_object().unwrap();
    assert!(!obj.contains_key("message"));
    assert_eq!(obj.get("kind").and_then(|v| v.as_str()), Some("panic"));
    assert_eq!(
        obj.get("stage").and_then(|v| v.as_str()),
        Some("macho-parse")
    );
}

#[test]
fn errors_serialize_as_bare_array() {
    let mut errs = Errors::new();
    errs.record_malformed(Stage::ElfParse, "bad magic");
    let json = serde_json::to_string(&errs).unwrap();
    // `#[serde(transparent)]` means the collection serializes as
    // a bare JSON array, not `{ "0": [...] }`.
    assert!(json.starts_with('['));
    assert!(json.contains("\"kind\":\"malformed\""));
    assert!(json.contains("\"stage\":\"elf-parse\""));
}

#[test]
fn display_tags_match_the_wire_form() {
    let stages = [
        Stage::Identify,
        Stage::PeParse,
        Stage::PeResourceWalk,
        Stage::ElfParse,
        Stage::MachoParse,
        Stage::OoxmlParse,
        Stage::Ole2Parse,
        Stage::ZipParse,
        Stage::TarParse,
        Stage::ClassParse,
        Stage::PdfParse,
        Stage::RpmParse,
        Stage::WasmParse,
        Stage::SevenZipParse,
        Stage::SourceParse,
        Stage::SourceExtract,
        Stage::SourceAstWalk,
        Stage::FormatExtract,
    ];
    for stage in stages {
        assert_eq!(serde_json::to_value(stage).unwrap(), stage.as_str());
    }
    let kinds = [
        DiagnosticKind::Panic,
        DiagnosticKind::Malformed,
        DiagnosticKind::Truncated,
        DiagnosticKind::Fallback,
    ];
    for kind in kinds {
        assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
    }
}

#[test]
fn diagnostic_displays_kind_stage_and_message() {
    let mut errs = Errors::new();
    errs.record_malformed(Stage::ZipParse, "bad entry");
    errs.record_fallback(Stage::PeParse, "");
    let shown: Vec<String> = errs.iter().map(ToString::to_string).collect();
    assert_eq!(
        shown,
        ["malformed in zip-parse: bad entry", "fallback in pe-parse"]
    );
    let _: &dyn std::error::Error = errs.as_slice().first().unwrap();
}
