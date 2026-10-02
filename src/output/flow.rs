//! Shared, policy-free value relationships and traversal.
//! Producers extract evidence; consumers supply library transfer models.
use crate::Arg;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const STEP_LIMIT: usize = 100_000;

/// What a [`FlowValue`] is. Serialized as the lowercase name (`"call"`).
///
/// Only [`Alternative`](Self::Alternative) denotes whole values chosen by
/// control flow; [`Merge`](Self::Merge) may combine arbitrary dependencies.
/// [`Object`](Self::Object) and [`Keyword`](Self::Keyword) carry their
/// entries in [`FlowValue::fields`]. New kinds may be added in a minor
/// release, so a `match` outside this crate needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FlowKind {
    /// A constant; its value is in [`FlowValue::literal`].
    Literal,
    /// A local helper's parameter, listed in [`FlowFunction::parameters`].
    Parameter,
    /// A call: [`FlowValue::target`] when static, arguments in
    /// [`FlowValue::inputs`], receiver in [`FlowValue::receiver`].
    Call,
    /// A member read; [`FlowValue::target`] is its canonical path.
    Member,
    /// Any combination of its inputs, such as an assignment that may keep
    /// the previous value or a binary operation.
    Merge,
    /// String concatenation or interpolation of its inputs, in order.
    Concat,
    /// Exactly one of its inputs, chosen by control flow.
    Alternative,
    /// An object or map literal; entries in [`FlowValue::fields`].
    Object,
    /// Named arguments: a keyword argument, or a CFML tag's attributes.
    /// Entries in [`FlowValue::fields`], reached only by name.
    Keyword,
    /// A value the producer could not model.
    Unknown,
}

impl FlowKind {
    /// The serialized name, such as `"call"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Parameter => "parameter",
            Self::Call => "call",
            Self::Member => "member",
            Self::Merge => "merge",
            Self::Concat => "concat",
            Self::Alternative => "alternative",
            Self::Object => "object",
            Self::Keyword => "keyword",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for FlowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One value in a file-local graph. IDs are indexes, local to this graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FlowValue {
    /// What this value is; see [`FlowKind`].
    pub kind: FlowKind,
    /// File byte offset, never a trait ID or virtual address.
    pub offset: u64,
    /// Original argument shape/value, using the existing symbol vocabulary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub literal: Option<Arg>,
    /// Static call target or canonical member-read path; absent when computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Ordered call arguments, or merged value inputs.
    pub inputs: Vec<usize>,
    /// Receiver value, separate from positional arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<usize>,
    /// Named object fields, kept separate to prevent headers/body confusion.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, usize>,
}

/// A local helper's parameter and return relationships.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FlowFunction {
    /// Parameter value IDs in declaration order.
    pub parameters: Vec<usize>,
    /// Returned value IDs; multiple values are conservative alternatives.
    pub returns: Vec<usize>,
}

/// Versioned value relationships, independent of the producing file format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Flow {
    /// Schema version, independent of local trait names.
    pub version: u32,
    /// Analyzer that produced these relationships (for example, `tree-sitter`).
    pub producer: String,
    /// Language name when known; empty when not applicable.
    pub language: String,
    /// Indexed values. Relationships never cross files implicitly.
    pub values: Vec<FlowValue>,
    /// Unambiguous local helper definitions.
    pub functions: BTreeMap<String, FlowFunction>,
    /// Known omissions/limits. Empty does not prove runtime reachability.
    pub limitations: BTreeSet<String>,
}

/// A declarative library model: which inputs may contribute to a return value.
/// The caller compiles selectors once, outside the per-value walk.
#[derive(Debug)]
#[non_exhaustive]
pub struct FlowTransfer {
    /// Canonical target selected by the caller. No regex engine or rule schema
    /// is required by the traversal itself.
    pub call: String,
    /// Zero-based contributing argument positions.
    pub arguments: Vec<usize>,
    /// Whether the receiver contributes to the return value.
    pub receiver: bool,
}

impl FlowTransfer {
    /// A model for `call`: the argument positions and whether the receiver
    /// contribute to its return value.
    #[must_use]
    pub fn new(call: impl Into<String>, arguments: Vec<usize>, receiver: bool) -> Self {
        Self {
            call: call.into(),
            arguments,
            receiver,
        }
    }
}

/// A value observation in a particular local-helper invocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct FlowOrigin {
    /// Index into the graph's values.
    pub value: usize,
    // Preserve parameter substitutions for subsequent argument inspection.
    bindings: BTreeMap<usize, usize>,
}

/// Origin observations and whether traversal exhausted its budget.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct FlowOrigins {
    /// Values encountered, including intermediate calls and caller context.
    pub values: BTreeSet<FlowOrigin>,
    /// Missing dynamic targets, malformed references, or traversal limits.
    pub incomplete: bool,
}

impl Flow {
    /// Return proven complete literal values, optionally projected from a
    /// named field. Unlike provenance, concatenation operands and modeled
    /// call inputs are not complete return values. Producers may attach a
    /// computed literal to a concat node. Unsupported shapes remain opaque.
    #[must_use]
    pub fn complete_values(&self, start: usize, field: Option<&str>, budget: usize) -> FlowOrigins {
        let mut out = FlowOrigins::default();
        let mut pending = vec![(start, field, 0usize)];
        let mut seen = BTreeSet::new();
        let mut left = budget.min(STEP_LIMIT);
        while let Some((id, field, depth)) = pending.pop() {
            if left == 0 || depth > 64 {
                out.incomplete = true;
                break;
            }
            left -= 1;
            if !seen.insert((id, field)) {
                continue;
            }
            let Some(value) = self.values.get(id) else {
                out.incomplete = true;
                continue;
            };
            if field.is_none()
                && matches!(
                    value.literal.as_ref(),
                    Some(Arg::String { .. } | Arg::Number { .. } | Arg::Bool { .. } | Arg::Null)
                )
            {
                out.values.insert(FlowOrigin {
                    value: id,
                    bindings: BTreeMap::new(),
                });
            } else if value.kind == FlowKind::Alternative {
                if value.inputs.len().saturating_add(pending.len()) > left {
                    out.incomplete = true;
                    break;
                }
                pending.extend(value.inputs.iter().map(|id| (*id, field, depth + 1)));
            } else if let Some(field) = field {
                if matches!(value.kind, FlowKind::Object | FlowKind::Keyword) {
                    if let Some(id) = value.fields.get(field) {
                        pending.push((*id, None, depth + 1));
                    }
                } else {
                    out.incomplete = true;
                }
            } else {
                out.incomplete = true;
            }
        }
        out
    }
    /// Walk value dependencies using only declared library transfers and local
    /// helper bodies. Contextual parameter substitution prevents callers of an
    /// identity helper from contaminating each other's return values.
    #[must_use]
    pub fn origins(&self, start: usize, transfers: &[FlowTransfer], budget: usize) -> FlowOrigins {
        self.walk(start, BTreeMap::new(), transfers, budget, None)
    }

    /// Project a named object field through local helper calls, parameters and
    /// alternatives before walking its provenance. Other fields never enter
    /// the walk. External return shapes remain opaque, even with value models.
    #[must_use]
    pub fn field_origins(
        &self,
        start: usize,
        field: &str,
        transfers: &[FlowTransfer],
        budget: usize,
    ) -> FlowOrigins {
        self.walk(start, BTreeMap::new(), transfers, budget, Some(field))
    }

    /// Inspect a call's argument in the same invocation that reached the sink.
    /// Starting a fresh walk would mix arguments from unrelated helper calls.
    #[must_use]
    pub fn argument_origins(
        &self,
        origin: &FlowOrigin,
        argument: usize,
        transfers: &[FlowTransfer],
        budget: usize,
    ) -> FlowOrigins {
        let Some(start) = self
            .values
            .get(origin.value)
            .and_then(|v| v.inputs.get(argument))
        else {
            return FlowOrigins {
                incomplete: true,
                ..Default::default()
            };
        };
        self.walk(*start, origin.bindings.clone(), transfers, budget, None)
    }

    fn walk(
        &self,
        start: usize,
        bindings: BTreeMap<usize, usize>,
        transfers: &[FlowTransfer],
        budget: usize,
        field: Option<&str>,
    ) -> FlowOrigins {
        let mut out = FlowOrigins::default();
        let mut pending = vec![(start, bindings, 0usize, field)];
        let mut seen = BTreeSet::new();
        let mut left = budget.min(STEP_LIMIT);
        while let Some((id, bindings, depth, field)) = pending.pop() {
            if left == 0 || depth > 64 {
                out.incomplete = true;
                break;
            }
            left -= 1;
            if !seen.insert((id, bindings.clone(), field)) {
                continue;
            }
            let Some(value) = self.values.get(id) else {
                out.incomplete = true;
                continue;
            };
            if let Some(field) = field {
                if matches!(value.kind, FlowKind::Object | FlowKind::Keyword) {
                    if let Some(id) = value.fields.get(field) {
                        pending.push((*id, bindings, depth + 1, None));
                    }
                    continue;
                }
                if value.kind == FlowKind::Literal {
                    continue;
                }
            } else {
                out.values.insert(FlowOrigin {
                    value: id,
                    bindings: bindings.clone(),
                });
            }
            let mut next = Vec::new();
            match value.kind {
                FlowKind::Object => next.extend(value.fields.values().copied()),
                // Keyword arguments require explicit projection by name. They
                // are not positional object payloads (headers != data/json).
                FlowKind::Keyword => {}
                FlowKind::Merge | FlowKind::Concat | FlowKind::Alternative => {
                    next.extend(value.inputs.iter().copied());
                }
                FlowKind::Parameter => {
                    if let Some(actual) = bindings.get(&id) {
                        next.push(*actual);
                    } else {
                        // A sink in a helper can be reached by callers of that
                        // helper. Bound parameters above never take this path.
                        for (name, function) in &self.functions {
                            let Some(remaining) = left.checked_sub(1 + function.parameters.len())
                            else {
                                out.incomplete = true;
                                return out;
                            };
                            left = remaining;
                            if let Some(position) =
                                function.parameters.iter().position(|p| *p == id)
                            {
                                for call in &self.values {
                                    if left == 0 {
                                        out.incomplete = true;
                                        return out;
                                    }
                                    left -= 1;
                                    if call.kind == FlowKind::Call
                                        && call.target.as_deref() == Some(name)
                                    {
                                        if let Some(actual) = call.inputs.get(position) {
                                            next.push(*actual);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                FlowKind::Call => {
                    if let Some(function) =
                        value.target.as_ref().and_then(|t| self.functions.get(t))
                    {
                        let mut frame = bindings.clone();
                        if frame.len() + function.parameters.len() > 256 {
                            out.incomplete = true;
                            continue;
                        }
                        for (param, actual) in function.parameters.iter().zip(&value.inputs) {
                            frame.insert(*param, bindings.get(actual).copied().unwrap_or(*actual));
                        }
                        pending.extend(
                            function
                                .returns
                                .iter()
                                .map(|r| (*r, frame.clone(), depth + 1, field)),
                        );
                    } else {
                        if field.is_some() {
                            out.incomplete = true;
                            continue;
                        }
                        let mut modeled = false;
                        for model in transfers {
                            if value.target.as_deref() == Some(model.call.as_str()) {
                                modeled = true;
                                next.extend(
                                    model
                                        .arguments
                                        .iter()
                                        .filter_map(|i| value.inputs.get(*i))
                                        .copied(),
                                );
                                if model.receiver {
                                    next.extend(value.receiver);
                                }
                            }
                        }
                        // Unmodeled external calls remain observable origins,
                        // but their return values are opaque.
                        if !modeled {
                            out.incomplete = true;
                        }
                    }
                }
                FlowKind::Unknown => out.incomplete = true,
                FlowKind::Literal | FlowKind::Member => {}
            }
            pending.extend(
                next.into_iter()
                    .map(|id| (id, bindings.clone(), depth + 1, field)),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
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
        };
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"kind":"call","offset":7,"target":"fetch","inputs":[1,2]}"#
        );
        let back: FlowValue =
            serde_json::from_str(&serde_json::to_string(&value).unwrap()).unwrap();
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
        };
        let node = |kind, inputs: Vec<usize>, fields: &[(&str, usize)]| FlowValue {
            kind,
            offset: 0,
            literal: None,
            target: None,
            inputs,
            receiver: None,
            fields: fields.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
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
}
