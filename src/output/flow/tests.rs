use super::*;

/// Every kind with the JSON string it has always serialized as.
const KINDS: [(FlowKind, &str); 10] = [
    (FlowKind::Literal, "literal"),
    (FlowKind::Parameter, "parameter"),
    (FlowKind::Call, "call"),
    (FlowKind::Member, "member"),
    (FlowKind::Merge, "merge"),
    (FlowKind::Concat, "concat"),
    (FlowKind::Alternative, "alternative"),
    (FlowKind::Object, "object"),
    (FlowKind::Keyword, "keyword"),
    (FlowKind::Unknown, "unknown"),
];

#[test]
fn kind_serializes_as_its_former_string() {
    for (kind, name) in KINDS {
        assert_eq!(serde_json::to_value(kind).unwrap(), name);
        assert_eq!(kind.as_str(), name);
        assert_eq!(kind.to_string(), name);
        let back: FlowKind = serde_json::from_value(serde_json::json!(name)).unwrap();
        assert_eq!(back, kind);
    }
    assert!(serde_json::from_str::<FlowKind>("\"Call\"").is_err());
}

#[test]
fn value_json_is_unchanged() {
    let value = FlowValue {
        kind: FlowKind::Call,
        offset: 7,
        literal: None,
        target: Some("fetch".into()),
        inputs: vec![1, 2],
        receiver: None,
        fields: BTreeMap::new(),
        module_level: false,
    };
    assert_eq!(
        serde_json::to_string(&value).unwrap(),
        r#"{"kind":"call","offset":7,"target":"fetch","inputs":[1,2]}"#
    );
    let back: FlowValue = serde_json::from_str(&serde_json::to_string(&value).unwrap()).unwrap();
    assert_eq!(back.kind, FlowKind::Call);
}

/// Keyword entries are reached only by name, object entries also
/// positionally; alternatives are complete values, merges are not.
#[test]
fn traversal_reads_kinds() {
    let literal = |offset| FlowValue {
        kind: FlowKind::Literal,
        offset,
        literal: Some(Arg::String {
            value: offset.to_string(),
        }),
        target: None,
        inputs: Vec::new(),
        receiver: None,
        fields: BTreeMap::new(),
        module_level: false,
    };
    let node = |kind, inputs: Vec<usize>, fields: &[(&str, usize)]| FlowValue {
        kind,
        offset: 0,
        literal: None,
        target: None,
        inputs,
        receiver: None,
        fields: fields.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        module_level: false,
    };
    let flow = Flow {
        values: vec![
            literal(0),
            literal(1),
            node(FlowKind::Alternative, vec![0, 1], &[]),
            node(FlowKind::Merge, vec![0, 1], &[]),
            node(FlowKind::Keyword, Vec::new(), &[("a", 0)]),
            node(FlowKind::Object, Vec::new(), &[("a", 1)]),
        ],
        ..Flow::default()
    };
    let complete = flow.complete_values(2, None, 100);
    assert_eq!(complete.values.len(), 2);
    assert!(!complete.incomplete);
    assert!(flow.complete_values(3, None, 100).incomplete);
    let ids = |o: FlowOrigins| o.values.into_iter().map(|v| v.value).collect::<Vec<_>>();
    assert_eq!(ids(flow.complete_values(4, Some("a"), 100)), [0]);
    assert_eq!(ids(flow.origins(4, &[], 100)), [4]);
    assert_eq!(ids(flow.origins(5, &[], 100)), [1, 5]);
}

/// `as_str` spells every reason exactly as serde does.
#[test]
fn limitation_names_match_serde() {
    for limitation in [
        Limitation::SourceLocalMayFlowNotReachability,
        Limitation::ScriptBlockLocalFlowOnly,
        Limitation::NodeBudget,
        Limitation::AnalysisBudget,
        Limitation::SourceByteBudget,
        Limitation::BindingBudget,
        Limitation::ConstantStringBudget,
        Limitation::SymbolLiteralBudget,
        Limitation::MarkupEntityBudget,
        Limitation::ExpressionDepth,
        Limitation::ExpressionParts,
        Limitation::BranchDepth,
        Limitation::BranchAlternatives,
        Limitation::HttpParentDepth,
        Limitation::ParseError,
        Limitation::MalformedExpression,
        Limitation::MalformedInterpolation,
        Limitation::MalformedAttributes,
        Limitation::UnbalancedBranch,
        Limitation::UnclosedBranch,
        Limitation::UnbalancedHttpParent,
        Limitation::UnclosedHttpParent,
        Limitation::MarkupSyntaxUnavailable,
        Limitation::MarkupNamedEntityUnavailable,
        Limitation::FunctionBodyUnavailable,
        Limitation::ScriptStatementSyntaxOrBudget,
        Limitation::ScriptStatementFlowUnavailable,
        Limitation::ScriptCallSyntaxOrBudget,
        Limitation::ConditionCallSyntaxOrBudget,
        Limitation::SyntaxBytes,
        Limitation::SyntaxTags,
        Limitation::SyntaxCommentDepth,
        Limitation::SyntaxTruncated,
        Limitation::SyntaxScript,
        Limitation::SyntaxEncrypted,
        Limitation::AnonymousFunction,
        Limitation::NestedFunction,
        Limitation::AmbiguousHelper,
        Limitation::ClassInitializersUnmodeled,
        Limitation::TemplateInstantiationUnmodeled,
        Limitation::CompoundAssignmentTarget,
        Limitation::UnresolvedObjectField,
        Limitation::UnmodeledIfBody,
        Limitation::UnsupportedExpression,
        Limitation::UnsupportedAssignment,
        Limitation::UnsupportedAssignmentTarget,
        Limitation::UnsupportedCallTarget,
        Limitation::UnsupportedIndexedMember,
        Limitation::UnsupportedTag,
        Limitation::UnresolvedExplicitVariable,
        Limitation::UnresolvedScopeLookup,
        Limitation::ImplicitScopeRuntimeDependent,
        Limitation::DynamicScopeSetting,
        Limitation::QueryOutputScopeUnavailable,
        Limitation::DynamicFileResultAttributes,
        Limitation::DynamicFileResultBinding,
        Limitation::DynamicFileResultAction,
    ] {
        assert_eq!(
            serde_json::to_value(limitation).unwrap(),
            limitation.as_str(),
            "{limitation:?}"
        );
    }
}
