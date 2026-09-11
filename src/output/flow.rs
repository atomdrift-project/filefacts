//! Shared, policy-free value relationships and traversal.
//! Producers extract evidence; consumers supply library transfer models.
use crate::Arg;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const STEP_LIMIT: usize = 100_000;

/// One value in a file-local graph. IDs are indexes, local to this graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowValue {
    /// `literal`, `parameter`, `call`, `merge`, or `unknown`.
    pub kind: String,
    /// File byte offset, never a trait ID or virtual address.
    pub offset: usize,
    /// Original argument shape/value, using the existing symbol vocabulary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub literal: Option<Arg>,
    /// Static call target; absent for a computed callee.
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
pub struct FlowFunction {
    /// Parameter value IDs in declaration order.
    pub parameters: Vec<usize>,
    /// Returned value IDs; multiple values are conservative alternatives.
    pub returns: Vec<usize>,
}

/// Versioned value relationships, independent of the producing file format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
pub struct FlowTransfer {
    /// Canonical target selected by the caller. No regex engine or rule schema
    /// is required by the traversal itself.
    pub call: String,
    /// Zero-based contributing argument positions.
    pub arguments: Vec<usize>,
    /// Whether the receiver contributes to the return value.
    pub receiver: bool,
}

/// A value observation in a particular local-helper invocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowOrigin {
    /// Index into the graph's values.
    pub value: usize,
    // Preserve parameter substitutions for subsequent argument inspection.
    bindings: BTreeMap<usize, usize>,
}

/// Origin observations and whether traversal exhausted its budget.
#[derive(Debug, Default)]
pub struct FlowOrigins {
    /// Values encountered, including intermediate calls and caller context.
    pub values: BTreeSet<FlowOrigin>,
    /// Missing dynamic targets, malformed references, or traversal limits.
    pub incomplete: bool,
}

impl Flow {
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
                if matches!(value.kind.as_str(), "object" | "keyword") {
                    if let Some(id) = value.fields.get(field) {
                        pending.push((*id, bindings, depth + 1, None));
                    }
                    continue;
                }
                if value.kind == "literal" {
                    continue;
                }
            } else {
                out.values.insert(FlowOrigin {
                    value: id,
                    bindings: bindings.clone(),
                });
            }
            let mut next = Vec::new();
            match value.kind.as_str() {
                "object" => next.extend(value.fields.values().copied()),
                // Keyword arguments require explicit projection by name. They
                // are not positional object payloads (headers != data/json).
                "keyword" => {}
                "merge" => next.extend(value.inputs.iter().copied()),
                "parameter" => {
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
                                    if call.kind == "call" && call.target.as_deref() == Some(name) {
                                        if let Some(actual) = call.inputs.get(position) {
                                            next.push(*actual);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                "call" => {
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
                "unknown" => out.incomplete = true,
                _ => {}
            }
            pending.extend(
                next.into_iter()
                    .map(|id| (id, bindings.clone(), depth + 1, field)),
            );
        }
        out
    }
}
