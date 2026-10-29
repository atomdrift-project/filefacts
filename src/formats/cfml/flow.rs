//! Policy-free relationships for the supported CFML tag subset.
use super::{Dialect, Limit, Tag, attributes, scan};
use crate::{Arg, ArgShape, Flow, FlowKind, FlowValue, Limitation, Symbol, Symbols};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

const MAX_VALUES: usize = 20_000;
const MAX_BINDINGS: usize = 512;
const MAX_BRANCHES: usize = 32;
const MAX_EXPR_DEPTH: usize = 32;
const MAX_EXPR_PARTS: usize = 64;
type Bindings = BTreeMap<String, usize>;
/// An open `<cfhttp>`'s object, when one was recorded, and the
/// `(offset, object)` of each `<cfhttpparam>` seen inside it.
type HttpParent = (Option<usize>, Vec<(usize, usize)>);

// Variables is the default template assignment scope. Functions are not
// analyzed here, so local/arguments aliases must not be guessed.
fn normalize_binding(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    name.strip_prefix("variables.")
        .filter(|s| !s.contains('.'))
        .unwrap_or(&name)
        .to_string()
}

fn defined_guard(bytes: &[u8], range: Range<usize>) -> Option<(String, String)> {
    let text = std::str::from_utf8(bytes.get(range)?).ok()?.trim();
    if text.len() > 256 {
        return None;
    }
    let text = text.to_ascii_lowercase();
    let arg = text
        .strip_prefix("isdefined")?
        .trim()
        .strip_prefix('(')?
        .trim()
        .strip_suffix(')')?
        .trim();
    let quote = arg.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || arg.as_bytes().last() != Some(&quote) || arg.len() < 3 {
        return None;
    }
    let path = &arg[1..arg.len() - 1];
    let (scope, short) = path.split_once('.')?;
    if !matches!(scope, "form" | "url" | "cgi" | "cookie" | "client")
        || short.is_empty()
        || !short
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    Some((short.to_string(), path.to_string()))
}

pub(crate) struct Parsed {
    pub symbols: Symbols,
    pub flow: Flow,
}
struct Branch {
    entry: Bindings,
    alternatives: Vec<Bindings>,
    has_else: bool,
    guard: Option<(String, String)>,
}
struct Builder<'a> {
    bytes: &'a [u8],
    result: Parsed,
    bindings: Bindings,
    branches: Vec<Branch>,
    implicit_scope: bool,
    folded_bytes: usize,
    symbol_literal_bytes: usize,
}

impl Builder<'_> {
    fn condition_calls(&mut self, range: Range<usize>) {
        let (calls, limited) = super::script::calls(self.bytes, range);
        if limited {
            self.gap(Limitation::ConditionCallSyntaxOrBudget);
        }
        for call in calls {
            self.expr(call, 0);
        }
    }
    // A CFIF/CFELSEIF tag with a simple inequality has three syntax operands.
    // Keep identifier spelling separate from values: a quoted name is not a read.
    fn condition_comparison(&mut self, tag: &Tag, target: &str) {
        let r = self.trim(tag.body.clone());
        let text = String::from_utf8_lossy(self.bytes.get(r.clone()).unwrap_or_default());
        let mut parts = text.split_ascii_whitespace();
        let words = (parts.next(), parts.next(), parts.next(), parts.next());
        let operands = if let (Some(left), Some(op), Some(right), None) = words
            && (op.eq_ignore_ascii_case("neq") || op == "!=")
        {
            Some((left, right))
        } else if let Some((left, right)) = text.split_once("!=") {
            Some((left.trim(), right.trim()))
        } else {
            None
        };
        let Some((left, right)) = operands else {
            return;
        };
        let identifier = |s: &str| {
            !s.is_empty()
                && s.split('.').all(|part| {
                    part.as_bytes()
                        .first()
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        };
        if !identifier(left) || !identifier(right) {
            return;
        }
        let left_name = left.to_ascii_lowercase();
        let right_name = right.to_ascii_lowercase();
        let left_range = r.start..r.start + left.len();
        let right_range = r.end - right.len()..r.end;
        let operator_offset = left_range.end
            + self
                .bytes
                .get(left_range.end..right_range.start)
                .and_then(|between| between.iter().position(|b| !b.is_ascii_whitespace()))
                .unwrap_or(0);
        let left_value = self.expr(left_range, 0);
        let right_value = self.expr(right_range, 0);
        let operator = self.add(FlowKind::Literal, operator_offset, Vec::new());
        if operator == 0 {
            return;
        }
        if let Some(value) = self.result.flow.values.get_mut(operator) {
            value.literal = Some(Arg::String {
                value: "neq".into(),
            });
        }
        let call = self.add(
            FlowKind::Call,
            tag.span.start,
            vec![left_value, operator, right_value],
        );
        if call == 0 {
            return;
        }
        if let Some(value) = self.result.flow.values.get_mut(call) {
            value.target = Some(target.into());
        }
        self.result.symbols.push(Symbol::Call {
            target: Some(target.into()),
            args: vec![
                Arg::Identifier { name: left_name },
                Arg::String {
                    value: "neq".into(),
                },
                Arg::Identifier { name: right_name },
            ],
            offset: Some(tag.span.start as u64),
        });
    }
    fn indexed_member(&mut self, r: Range<usize>) -> usize {
        let bytes = self.bytes;
        // Input through the range end; a range past the input stops with it.
        let text = bytes.get(..r.end).unwrap_or(bytes);
        let mut at = r.start;
        let mut path = String::new();
        while let Some(&byte) = text.get(at)
            && (byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            path.push((byte as char).to_ascii_lowercase());
            at += 1;
        }
        if path.is_empty()
            || path.split('.').any(|s| {
                s.is_empty()
                    || !s
                        .as_bytes()
                        .first()
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            })
        {
            self.gap(Limitation::UnsupportedIndexedMember);
            return 0;
        }
        let mut parts = 0;
        while at < r.end {
            while text.get(at).is_some_and(u8::is_ascii_whitespace) {
                at += 1;
            }
            let Some(&byte) = text.get(at) else {
                break;
            };
            parts += 1;
            if parts > MAX_EXPR_PARTS {
                self.gap(Limitation::ExpressionParts);
                return 0;
            }
            if byte == b'.' {
                at += 1;
                let start = at;
                while text
                    .get(at)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    at += 1;
                }
                if start == at
                    || !text
                        .get(start)
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                {
                    self.gap(Limitation::UnsupportedIndexedMember);
                    return 0;
                }
                path.push('.');
                path.push_str(
                    &String::from_utf8_lossy(text.get(start..at).unwrap_or_default())
                        .to_ascii_lowercase(),
                );
                continue;
            }
            if byte != b'[' {
                self.gap(Limitation::UnsupportedIndexedMember);
                return 0;
            }
            let start = at + 1;
            let mut depth = 1;
            at += 1;
            while depth > 0
                && let Some(&byte) = text.get(at)
            {
                match byte {
                    b'\'' | b'"' => {
                        if !super::quoted(text, &mut at) {
                            self.gap(Limitation::MalformedExpression);
                            return 0;
                        }
                        continue;
                    }
                    b'[' => {
                        depth += 1;
                        if depth > MAX_EXPR_DEPTH {
                            self.gap(Limitation::ExpressionDepth);
                            return 0;
                        }
                    }
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                at += 1;
            }
            if depth != 0 {
                self.gap(Limitation::MalformedExpression);
                return 0;
            }
            let key = self.trim(start..at);
            let raw = bytes.get(key).unwrap_or_default();
            if let [quote @ (b'\'' | b'"'), inner @ .., last] = raw
                && last == quote
                && !inner.is_empty()
                && inner
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                path.push('.');
                path.push_str(&String::from_utf8_lossy(inner).to_ascii_lowercase());
            } else if raw.is_empty() {
                self.gap(Limitation::MalformedExpression);
                return 0;
            } else {
                path.push_str("[*]");
            }
            at += 1;
        }
        let path = normalize_binding(&path);
        if let Some(id) = self.bindings.get(&path) {
            return *id;
        }
        let id = self.add(FlowKind::Member, r.start, Vec::new());
        if id != 0
            && let Some(value) = self.result.flow.values.get_mut(id)
        {
            value.target = Some(path);
        }
        id
    }
    // Locate syntax only at the current nesting level. Strings and their
    // interpolation are opaque here; recursive expression parsing is bounded.
    fn separators(&mut self, r: Range<usize>, delimiter: u8) -> Option<Vec<usize>> {
        let bytes = self.bytes;
        let text = bytes.get(..r.end).unwrap_or(bytes);
        let mut positions = Vec::new();
        let mut nesting = 0usize;
        let mut at = r.start;
        while let Some(&byte) = text.get(at) {
            if matches!(byte, b'\'' | b'"') {
                if !super::quoted(text, &mut at) {
                    self.gap(Limitation::MalformedExpression);
                    return None;
                }
                continue;
            }
            if nesting == 0 && byte == delimiter {
                if positions.len() == MAX_EXPR_PARTS {
                    self.gap(Limitation::ExpressionParts);
                    return None;
                }
                positions.push(at);
            }
            match byte {
                b'(' => {
                    nesting += 1;
                    if nesting > MAX_EXPR_DEPTH {
                        self.gap(Limitation::ExpressionDepth);
                        return None;
                    }
                }
                b')' if nesting > 0 => nesting -= 1,
                b')' => {
                    self.gap(Limitation::MalformedExpression);
                    return None;
                }
                _ => {}
            }
            at += 1;
        }
        if nesting != 0 {
            self.gap(Limitation::MalformedExpression);
            None
        } else {
            Some(positions)
        }
    }

    fn add(&mut self, kind: FlowKind, offset: usize, inputs: Vec<usize>) -> usize {
        if self.result.flow.values.len() >= MAX_VALUES {
            self.gap(Limitation::NodeBudget);
            return 0;
        }
        let id = self.result.flow.values.len();
        self.result.flow.values.push(FlowValue {
            kind,
            offset: offset as u64,
            inputs,
            literal: None,
            target: None,
            receiver: None,
            fields: BTreeMap::new(),
            // Not tracked for CFML; `false` claims nothing.
            module_level: false,
        });
        id
    }
    /// Record that the graph is incomplete, logging each reason once.
    fn gap(&mut self, limitation: Limitation) {
        if self.result.flow.limitations.insert(limitation) {
            tracing::debug!(
                target: "filefacts::cfml",
                format = "cfml",
                stage = "flow",
                ?limitation,
                values = self.result.flow.values.len(),
                "CFML flow incomplete",
            );
        }
    }
    fn trim(&self, mut r: Range<usize>) -> Range<usize> {
        while r.start < r.end && self.bytes.get(r.start).is_some_and(u8::is_ascii_whitespace) {
            r.start += 1;
        }
        while r.start < r.end
            && self
                .bytes
                .get(r.end - 1)
                .is_some_and(u8::is_ascii_whitespace)
        {
            r.end -= 1;
        }
        r
    }
    fn concat(&mut self, offset: usize, inputs: Vec<usize>) -> usize {
        if let [only] = inputs.as_slice() {
            return *only;
        }
        let total = inputs.iter().try_fold(0usize, |total, id| {
            match self
                .result
                .flow
                .values
                .get(*id)
                .and_then(|v| v.literal.as_ref())
            {
                Some(Arg::String { value }) => total.checked_add(value.len()),
                _ => None,
            }
        });
        let id = self.add(FlowKind::Concat, offset, inputs);
        if id == 0 {
            return 0;
        }
        if let Some(total) = total {
            if total > super::MAX_BYTES - self.folded_bytes {
                self.gap(Limitation::ConstantStringBudget);
                return id;
            }
            let mut value = String::with_capacity(total);
            let values = &self.result.flow.values;
            let inputs = values
                .get(id)
                .map(|v| v.inputs.as_slice())
                .unwrap_or_default();
            for input in inputs {
                if let Some(Arg::String { value: part }) =
                    values.get(*input).and_then(|v| v.literal.as_ref())
                {
                    value.push_str(part);
                }
            }
            self.folded_bytes += total;
            if let Some(concat) = self.result.flow.values.get_mut(id) {
                concat.literal = Some(Arg::String { value });
            }
        }
        id
    }
    fn string_literal(&mut self, r: Range<usize>, quote: Option<u8>) -> usize {
        let id = self.add(FlowKind::Literal, r.start, Vec::new());
        if id != 0
            && let Some(entry) = self.result.flow.values.get_mut(id)
        {
            let raw =
                String::from_utf8_lossy(self.bytes.get(r).unwrap_or_default()).replace("##", "#");
            let value = match quote {
                Some(b'\'') => raw.replace("''", "'"),
                Some(b'"') => raw.replace("\"\"", "\""),
                _ => raw,
            };
            entry.literal = Some(Arg::String { value });
        }
        id
    }
    fn string(&mut self, r: Range<usize>, depth: usize, quote: Option<u8>) -> usize {
        let bytes = self.bytes;
        let text = bytes.get(..r.end).unwrap_or(bytes);
        let mut inputs = Vec::new();
        let mut at = r.start;
        let mut text_start = r.start;
        while let Some(&byte) = text.get(at) {
            if byte != b'#' {
                at += 1;
                continue;
            }
            if bytes.get(at + 1) == Some(&b'#') {
                at += 2;
                continue;
            }
            if inputs.len() >= MAX_EXPR_PARTS - 2 {
                self.gap(Limitation::ExpressionParts);
                return 0;
            }
            let begin = at + 1;
            if text_start < at {
                inputs.push(self.string_literal(text_start..at, quote));
            }
            at += 1;
            if !super::interpolation(text, &mut at) {
                self.gap(Limitation::MalformedInterpolation);
                return 0;
            }
            inputs.push(self.expr(begin..at - 1, depth + 1));
            text_start = at;
        }
        if inputs.is_empty() {
            self.string_literal(r, quote)
        } else {
            if text_start < r.end {
                inputs.push(self.string_literal(text_start..r.end, quote));
            }
            self.concat(r.start, inputs)
        }
    }
    fn expr(&mut self, r: Range<usize>, depth: usize) -> usize {
        if depth > MAX_EXPR_DEPTH {
            self.gap(Limitation::ExpressionDepth);
            return 0;
        }
        let r = self.trim(r);
        let bytes = self.bytes;
        let Some(raw @ [first, ..]) = bytes.get(r.clone()) else {
            return 0;
        };
        let first = *first;
        if first == b'#' && raw.last() == Some(&b'#') {
            return self.expr(r.start + 1..r.end - 1, depth + 1);
        }
        let Some(parts) = self.separators(r.clone(), b'&') else {
            return 0;
        };
        if !parts.is_empty() {
            let mut start = r.start;
            let mut inputs = Vec::new();
            for end in parts.into_iter().chain(std::iter::once(r.end)) {
                if self.trim(start..end).is_empty() {
                    self.gap(Limitation::MalformedExpression);
                    return 0;
                }
                inputs.push(self.expr(start..end, depth + 1));
                start = end + 1;
            }
            return self.concat(r.start, inputs);
        }
        if matches!(first, b'\'' | b'"') {
            let mut end = r.start;
            if !bytes
                .get(..r.end)
                .is_some_and(|text| super::quoted(text, &mut end))
                || end != r.end
            {
                self.gap(Limitation::UnsupportedExpression);
                return 0;
            }
            return self.string(r.start + 1..r.end - 1, depth, Some(first));
        }
        if raw.last() == Some(&b')') {
            let Some(opens) = self.separators(r.clone(), b'(') else {
                return 0;
            };
            if let Some(&open) = opens.last() {
                if open == r.start && opens.len() == 1 {
                    return self.expr(open + 1..r.end - 1, depth + 1);
                }
                let prefix = self.trim(r.start..open);
                let prefix_bytes = bytes.get(prefix.clone()).unwrap_or_default();
                let prefix_text = String::from_utf8_lossy(prefix_bytes);
                let valid_name = |s: &str| {
                    !s.is_empty()
                        && s.split('.').all(|part| {
                            part.as_bytes()
                                .first()
                                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        })
                };
                let static_name = if valid_name(&prefix_text) {
                    Some(prefix_text.to_ascii_lowercase())
                } else if prefix_text.split('.').take(MAX_EXPR_PARTS + 1).count() <= MAX_EXPR_PARTS
                    && prefix_text.split('.').all(|part| valid_name(part.trim()))
                {
                    Some(
                        prefix_text
                            .split('.')
                            .map(str::trim)
                            .collect::<Vec<_>>()
                            .join(".")
                            .to_ascii_lowercase(),
                    )
                } else {
                    None
                };
                let (target, receiver) = if let Some(target) = static_name {
                    (target, None)
                } else if let Some((_, method)) = prefix_text.rsplit_once('.') {
                    let method = method.trim();
                    if !valid_name(method) || method.contains('.') {
                        self.gap(Limitation::UnsupportedCallTarget);
                        return 0;
                    }
                    let method = method.to_ascii_lowercase();
                    // Offset of the `.` in the source bytes. Its offset in
                    // `prefix_text` differs once lossy decoding has widened an
                    // invalid byte to U+FFFD, and could overrun the input.
                    let dot = prefix_bytes
                        .iter()
                        .rposition(|&b| b == b'.')
                        .unwrap_or_default();
                    let receiver = self.expr(prefix.start..prefix.start + dot, depth + 1);
                    let Some(parent) = self
                        .result
                        .flow
                        .values
                        .get(receiver)
                        .and_then(|v| v.target.clone())
                    else {
                        self.gap(Limitation::UnsupportedCallTarget);
                        return 0;
                    };
                    (format!("{parent}.{method}"), Some(receiver))
                } else {
                    self.gap(Limitation::UnsupportedCallTarget);
                    return 0;
                };
                let args = open + 1..r.end - 1;
                let Some(commas) = self.separators(args.clone(), b',') else {
                    return 0;
                };
                let mut inputs = Vec::new();
                if !self.trim(args.clone()).is_empty() {
                    let mut start = args.start;
                    for end in commas.into_iter().chain(std::iter::once(args.end)) {
                        if self.trim(start..end).is_empty() {
                            self.gap(Limitation::MalformedExpression);
                            return 0;
                        }
                        inputs.push(self.expr(start..end, depth + 1));
                        start = end + 1;
                    }
                }
                let id = self.add(FlowKind::Call, r.start, inputs);
                if id != 0 {
                    let mut truncated = false;
                    let values = &self.result.flow.values;
                    let args = values
                        .get(id)
                        .map(|v| v.inputs.as_slice())
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|input| values.get(*input))
                        .map(|value| {
                            if let Some(Arg::String { value: text }) = &value.literal {
                                if text.len() > super::MAX_BYTES - self.symbol_literal_bytes {
                                    truncated = true;
                                    return Arg::Expression;
                                }
                                self.symbol_literal_bytes += text.len();
                            }
                            value.literal.clone().unwrap_or_else(|| {
                                if value.kind == FlowKind::Call {
                                    Arg::Call
                                } else {
                                    Arg::Expression
                                }
                            })
                        })
                        .collect();
                    if truncated {
                        self.gap(Limitation::SymbolLiteralBudget);
                    }
                    self.result.symbols.push(Symbol::Call {
                        target: Some(target.clone()),
                        args,
                        offset: Some(r.start as u64),
                    });
                    if let Some(value) = self.result.flow.values.get_mut(id) {
                        value.target = Some(target);
                        value.receiver = receiver;
                    }
                }
                return id;
            }
        }
        if !first.is_ascii_alphabetic() && first != b'_' {
            self.gap(Limitation::UnsupportedExpression);
            return 0;
        }
        if raw.contains(&b'[') {
            return self.indexed_member(r);
        }
        if !raw
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        {
            self.gap(Limitation::UnsupportedExpression);
            return 0;
        }
        let name = normalize_binding(&String::from_utf8_lossy(raw));
        if let Some(id) = self.bindings.get(&name) {
            return *id;
        }
        if raw
            .get(..10)
            .is_some_and(|scope| scope.eq_ignore_ascii_case(b"variables."))
        {
            self.gap(Limitation::UnresolvedExplicitVariable);
            return 0;
        }
        if name.split('.').any(str::is_empty) {
            self.gap(Limitation::UnsupportedExpression);
            return 0;
        }
        if name.contains('.') {
            let id = self.add(FlowKind::Member, r.start, Vec::new());
            if id != 0
                && let Some(value) = self.result.flow.values.get_mut(id)
            {
                value.target = Some(name);
            }
            id
        } else {
            if self.implicit_scope {
                let origin = self
                    .branches
                    .iter()
                    .rev()
                    .filter_map(|b| b.guard.as_ref())
                    .find(|(short, _)| short == &name)
                    .map(|(_, path)| path.clone());
                if let Some(path) = origin {
                    self.gap(Limitation::ImplicitScopeRuntimeDependent);
                    // A known assignment to the explicit scope also shadows its
                    // original external value; an existence guard is not a write.
                    if let Some(id) = self.bindings.get(&path) {
                        return *id;
                    }
                    let id = self.add(FlowKind::Member, r.start, Vec::new());
                    if id != 0
                        && let Some(value) = self.result.flow.values.get_mut(id)
                    {
                        value.target = Some(path);
                    }
                    return id;
                }
            }
            self.gap(Limitation::UnresolvedScopeLookup);
            0
        }
    }
    fn script_statement(&mut self, range: Range<usize>, assignments: bool) {
        let range = self.trim(range);
        if range.is_empty() {
            return;
        }
        if assignments {
            if let Some(equals) = self.separators(range.clone(), b'=') {
                if let Some(&eq) = equals.first() {
                    let lhs = self.trim(range.start..eq);
                    let text = self.bytes.get(lhs.clone()).unwrap_or_default();
                    let simple = !text.is_empty()
                        && text.split(|b| *b == b'.').all(|part| {
                            part.first()
                                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                                && part.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                        });
                    if simple && equals.len() == 1 && self.bytes.get(eq + 1) != Some(&b'=') {
                        let before = self.result.symbols.len();
                        self.assignment(&Tag {
                            name: lhs,
                            body: range.clone(),
                            span: range.clone(),
                            closing: false,
                        });
                        // Preserve lexical call observations even when a complex
                        // RHS remains opaque to value analysis. Avoid duplicates.
                        let seen: BTreeSet<_> = self
                            .result
                            .symbols
                            .iter()
                            .skip(before)
                            .filter_map(|s| match s {
                                Symbol::Call { offset, .. } => *offset,
                                _ => None,
                            })
                            .collect();
                        let (calls, limited) = super::script::calls(self.bytes, eq + 1..range.end);
                        if limited {
                            self.gap(Limitation::ScriptCallSyntaxOrBudget);
                        }
                        for call in calls {
                            if !seen.contains(&(call.start as u64)) {
                                self.expr(call, 0);
                            }
                        }
                        return;
                    }
                }
            }
        }
        let (calls, limited) = super::script::calls(self.bytes, range.clone());
        // A complete standalone call does not itself define a local variable.
        // Unsupported statements/control headers cannot preserve stale aliases.
        if !assignments || !matches!(calls.as_slice(), [only] if *only == range) {
            self.bindings.clear();
            self.gap(Limitation::ScriptStatementFlowUnavailable);
        }
        if limited {
            self.gap(Limitation::ScriptCallSyntaxOrBudget);
        }
        for call in calls {
            self.expr(call, 0);
        }
    }
    fn assignment(&mut self, tag: &Tag) {
        let mut r = self.trim(tag.body.clone());
        // XML-style CFSET closes with />. The slash is tag syntax, not
        // part of its RHS expression; preserve every expression offset.
        if r.end > r.start && self.bytes.get(r.end - 1) == Some(&b'/') {
            r = self.trim(r.start..r.end - 1);
        }
        let Some(eq) = self
            .bytes
            .get(r.clone())
            .and_then(|body| body.iter().position(|b| *b == b'='))
        else {
            self.gap(Limitation::UnsupportedAssignment);
            self.bindings.clear();
            return;
        };
        let lhs = self.trim(r.start..r.start + eq);
        let name = normalize_binding(&String::from_utf8_lossy(
            self.bytes.get(lhs.clone()).unwrap_or_default(),
        ));
        if name.is_empty()
            || name.split('.').any(|part| {
                !part
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            })
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        {
            self.gap(Limitation::UnsupportedAssignmentTarget);
            self.bindings.clear();
            return;
        }
        let rhs = self.trim(r.start + eq + 1..r.end);
        let value = self.expr(rhs.clone(), 0);
        let raw = self.bytes.get(rhs.clone()).unwrap_or_default();
        let mut shape = ArgShape::Expression;
        if raw.first().is_some_and(|b| matches!(b, b'\'' | b'"')) {
            let mut end = rhs.start;
            if self
                .bytes
                .get(..rhs.end)
                .is_some_and(|text| super::quoted(text, &mut end))
                && end == rhs.end
            {
                shape = ArgShape::String;
                let mut at = rhs.start + 1;
                while at + 1 < rhs.end {
                    if self.bytes.get(at) == Some(&b'#') {
                        if self.bytes.get(at + 1) == Some(&b'#') {
                            at += 2;
                            continue;
                        }
                        shape = ArgShape::Template;
                        break;
                    }
                    at += 1;
                }
            }
        } else if raw.eq_ignore_ascii_case(b"true") || raw.eq_ignore_ascii_case(b"false") {
            shape = ArgShape::Bool;
        } else if raw
            .first()
            .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.'))
            && std::str::from_utf8(raw)
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
                .is_some_and(f64::is_finite)
        {
            shape = ArgShape::Number;
        } else if !raw.is_empty()
            && raw.split(|b| *b == b'.').all(|part| {
                part.first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                    && part.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
            })
        {
            shape = ArgShape::Identifier;
        } else if self
            .result
            .flow
            .values
            .get(value)
            .is_some_and(|v| v.kind == FlowKind::Call && v.offset == rhs.start as u64)
        {
            shape = ArgShape::Call;
        }
        self.result.symbols.push(Symbol::Bind {
            target: name.clone(),
            shape,
            offset: lhs.start as u64,
        });
        if !self.bindings.contains_key(&name) && self.bindings.len() == MAX_BINDINGS {
            self.gap(Limitation::BindingBudget);
            self.bindings.clear();
            return;
        }
        self.bindings.insert(name, value);
    }
    // Attribute values are complete strings, never contributing fragments.
    fn tag_string(&self, object: usize, field: &str) -> Option<String> {
        let values = self
            .result
            .flow
            .complete_values(object, Some(field), MAX_EXPR_PARTS);
        if values.incomplete || values.values.len() != 1 {
            return None;
        }
        let value = values.values.iter().next()?;
        match self
            .result
            .flow
            .values
            .get(value.value)
            .and_then(|v| v.literal.as_ref())
        {
            Some(Arg::String { value }) if value.len() <= 256 => Some(value.clone()),
            _ => None,
        }
    }
    fn file_result(&mut self, object: usize, call: usize) {
        if self
            .result
            .flow
            .values
            .get(object)
            .is_some_and(|v| v.fields.contains_key("attributecollection"))
        {
            self.bindings.clear();
            self.gap(Limitation::DynamicFileResultAttributes);
            return;
        }
        let action = self
            .tag_string(object, "action")
            .map(|s| s.to_ascii_lowercase());
        if action
            .as_deref()
            .is_some_and(|s| !matches!(s, "read" | "readbinary"))
        {
            return;
        }
        if !self
            .result
            .flow
            .values
            .get(object)
            .is_some_and(|v| v.fields.contains_key("variable"))
        {
            return;
        }
        let name = self
            .tag_string(object, "variable")
            .map(|s| normalize_binding(&s));
        let Some(name) = name.filter(|name| {
            name.as_bytes()
                .first()
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
                && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        }) else {
            self.bindings.clear();
            self.gap(Limitation::DynamicFileResultBinding);
            return;
        };
        // Dynamic actions may overwrite this result name. Do not retain its
        // previous value, or claim a definite read-result value in that case.
        if action.is_none() {
            self.bindings.remove(&name);
            self.gap(Limitation::DynamicFileResultAction);
            return;
        }
        if !self.bindings.contains_key(&name) && self.bindings.len() == MAX_BINDINGS {
            self.bindings.clear();
            self.gap(Limitation::BindingBudget);
            return;
        }
        let Some(offset) = self
            .result
            .flow
            .values
            .get(call)
            .and_then(|v| usize::try_from(v.offset).ok())
        else {
            return;
        };
        let result = self.add(FlowKind::Call, offset, vec![object]);
        if result == 0 {
            self.bindings.remove(&name);
            return;
        }
        // Dedicated result identity prevents ordinary calls named cffile from
        // masquerading as a proven tag read operation in downstream selectors.
        if let Some(value) = self.result.flow.values.get_mut(result) {
            value.target = Some("cffile:read-result".into());
        }
        self.result.symbols.push(Symbol::Bind {
            target: name.clone(),
            shape: ArgShape::Call,
            offset: offset as u64,
        });
        self.bindings.insert(name, result);
    }
    // Distinct from an ordinary source function named cfoutput. The scanner
    // supplies only template output expressions, in source order.
    fn output(&mut self, range: Range<usize>, known_scope: bool) {
        let offset = range.start;
        let value = self.expr(range, 0);
        let value = if known_scope { value } else { 0 };
        let call = self.add(FlowKind::Call, offset, vec![value]);
        if call == 0 {
            return;
        }
        let target = "cfoutput:expression".to_string();
        if let Some(value) = self.result.flow.values.get_mut(call) {
            value.target = Some(target.clone());
        }
        self.result.symbols.push(Symbol::Call {
            target: Some(target),
            args: vec![Arg::Expression],
            offset: Some(offset as u64),
        });
    }
    fn tag_call(&mut self, tag: &Tag, name: String, html: bool, interpolate: bool) -> usize {
        let dialect = if html {
            Dialect::Html { interpolate }
        } else {
            Dialect::Cfml
        };
        let Some(attrs) = attributes(self.bytes, tag, dialect) else {
            if name == "cffile" {
                self.bindings.clear();
            }
            self.gap(Limitation::MalformedAttributes);
            return 0;
        };
        let mut fields = BTreeMap::new();
        for attr in attrs {
            let key = String::from_utf8_lossy(self.bytes.get(attr.name).unwrap_or_default())
                .to_ascii_lowercase();
            // Ordinary tag attributes are text, with #...# interpolation,
            // whether or not their outer quotes are present. Bare names are
            // not variable reads (unlike CFSET expression RHS syntax).
            let quote = if !html && attr.quoted {
                let open = attr.value.start.checked_sub(1);
                open.and_then(|open| self.bytes.get(open)).copied()
            } else {
                None
            };
            let mut value = if html && !interpolate {
                let id = self.add(FlowKind::Literal, attr.value.start, Vec::new());
                if id != 0
                    && let Some(entry) = self.result.flow.values.get_mut(id)
                {
                    entry.literal = Some(Arg::String {
                        value: String::from_utf8_lossy(
                            self.bytes.get(attr.value.clone()).unwrap_or_default(),
                        )
                        .into_owned(),
                    });
                }
                id
            } else {
                self.string(attr.value.clone(), 0, quote)
            };
            if html {
                let literal = self
                    .result
                    .flow
                    .values
                    .get(value)
                    .and_then(|v| v.literal.as_ref());
                if let Some(Arg::String { value: text }) = literal {
                    if text.contains('&')
                        && text.len().saturating_add(self.folded_bytes) > super::MAX_BYTES
                    {
                        self.gap(Limitation::MarkupEntityBudget);
                        value = 0;
                    } else {
                        match super::markup::decode_references(text) {
                            Ok(Some(decoded)) => {
                                self.folded_bytes += decoded.len();
                                let id = self.add(FlowKind::Concat, attr.value.start, vec![value]);
                                if id != 0
                                    && let Some(entry) = self.result.flow.values.get_mut(id)
                                {
                                    entry.literal = Some(Arg::String { value: decoded });
                                }
                                value = id;
                            }
                            Err(()) => {
                                self.gap(Limitation::MarkupNamedEntityUnavailable);
                                value = 0;
                            }
                            Ok(None) => {}
                        }
                    }
                }
            }
            fields.insert(key, value);
        }
        let object = self.add(FlowKind::Keyword, tag.span.start, Vec::new());
        if object == 0 {
            return 0;
        }
        if let Some(value) = self.result.flow.values.get_mut(object) {
            value.fields = fields;
        }
        let call = self.add(FlowKind::Call, tag.span.start, vec![object]);
        if call == 0 {
            return 0;
        }
        if let Some(value) = self.result.flow.values.get_mut(call) {
            value.target = Some(name.clone());
        }
        if name == "cffile" {
            self.file_result(object, call);
        }
        self.result.symbols.push(Symbol::Call {
            target: Some(name),
            args: vec![Arg::Object],
            offset: Some(tag.span.start as u64),
        });
        object
    }
    fn end_branch(&mut self, offset: usize) {
        let Some(mut branch) = self.branches.pop() else {
            self.gap(Limitation::UnbalancedBranch);
            self.bindings.clear();
            return;
        };
        branch.alternatives.push(std::mem::take(&mut self.bindings));
        if !branch.has_else {
            branch.alternatives.push(branch.entry);
        }
        let keys: BTreeSet<_> = branch
            .alternatives
            .iter()
            .flat_map(|b| b.keys().cloned())
            .collect();
        if keys.len() > MAX_BINDINGS {
            self.gap(Limitation::BindingBudget);
            self.bindings.clear();
            return;
        }
        for key in keys {
            let ids: BTreeSet<_> = branch
                .alternatives
                .iter()
                .map(|b| b.get(&key).copied().unwrap_or(0))
                .collect();
            let id = match ids.first() {
                Some(&only) if ids.len() == 1 => only,
                _ => self.add(FlowKind::Alternative, offset, ids.into_iter().collect()),
            };
            self.bindings.insert(key, id);
        }
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Parsed {
    let syntax = scan(bytes);
    let masked = if syntax.scripts.is_empty() {
        None
    } else {
        Some(super::script::mask_comments(bytes, &syntax.scripts))
    };
    let expression_bytes = masked.as_deref().unwrap_or(bytes);
    let mut b = Builder {
        bytes: expression_bytes,
        bindings: Bindings::new(),
        branches: Vec::new(),
        implicit_scope: true,
        folded_bytes: 0,
        symbol_literal_bytes: 0,
        result: Parsed {
            symbols: Symbols::new(),
            flow: Flow {
                version: 1,
                producer: "cfml-tags".into(),
                language: "cfml".into(),
                ..Flow::default()
            },
        },
    };
    b.add(FlowKind::Unknown, 0, Vec::new());
    // The scope of every graph rather than a gap in this one.
    b.result
        .flow
        .limitations
        .insert(Limitation::SourceLocalMayFlowNotReachability);
    if let Some(limit) = syntax.limitation {
        b.gap(match limit {
            Limit::Bytes => Limitation::SyntaxBytes,
            Limit::Tags => Limitation::SyntaxTags,
            Limit::CommentDepth => Limitation::SyntaxCommentDepth,
            Limit::Truncated => Limitation::SyntaxTruncated,
            Limit::Script => Limitation::SyntaxScript,
            Limit::Encrypted => Limitation::SyntaxEncrypted,
        });
    }
    if !syntax.scripts.is_empty() {
        b.gap(Limitation::ScriptBlockLocalFlowOnly);
    }
    if syntax.markup_limited {
        b.gap(Limitation::MarkupSyntaxUnavailable);
    }
    let mut output_expressions = syntax.output_expressions.into_iter().peekable();
    let mut script_ranges = syntax.scripts.into_iter();
    let mut function_depth = 0usize;
    let mut http_parents: Vec<HttpParent> = Vec::new();
    let mut opaque_http_depth = 0usize;
    let mut output_depth = 0usize;
    let mut output_scopes = Vec::new();
    let mut unknown_output_scopes = 0usize;
    for tag in syntax.tags {
        while let Some(range) = output_expressions.next_if(|r| r.start < tag.span.start) {
            if function_depth == 0 {
                b.output(range, unknown_output_scopes == 0);
            }
        }
        let name = String::from_utf8_lossy(bytes.get(tag.name.clone()).unwrap_or_default())
            .to_ascii_lowercase();
        let script_range = if name == "cfscript" && !tag.closing {
            script_ranges.next()
        } else {
            None
        };
        if name == "cffunction" {
            b.gap(Limitation::FunctionBodyUnavailable);
            if tag.closing {
                function_depth = function_depth.saturating_sub(1);
            } else {
                function_depth += 1;
            }
            continue;
        }
        if function_depth > 0 {
            continue;
        }
        match (name.as_str(), tag.closing) {
            ("cfscript", false) => {
                b.bindings.clear();
                if let Some(range) = script_range {
                    let (events, limited) = super::script::statements(expression_bytes, range);
                    if limited {
                        b.gap(Limitation::ScriptStatementSyntaxOrBudget);
                    }
                    let implicit = b.implicit_scope;
                    b.implicit_scope = false;
                    for event in events {
                        match event {
                            super::script::Event::Statement(range, allowed) => {
                                b.script_statement(range, allowed)
                            }
                            super::script::Event::Barrier => b.bindings.clear(),
                        }
                    }
                    b.bindings.clear();
                    b.implicit_scope = implicit;
                }
            }
            ("cfhttp", false) => {
                let object = b.tag_call(&tag, name, false, true);
                let self_closed = bytes.get(tag.span.clone()).is_some_and(|raw| {
                    raw.get(..raw.len().saturating_sub(1))
                        .is_some_and(|prefix| {
                            prefix.iter().rev().find(|c| !c.is_ascii_whitespace()) == Some(&b'/')
                        })
                });
                if !self_closed {
                    if http_parents.len() >= MAX_BRANCHES || opaque_http_depth > 0 {
                        opaque_http_depth = opaque_http_depth.saturating_add(1);
                        b.gap(Limitation::HttpParentDepth);
                    } else {
                        http_parents.push(((object != 0).then_some(object), Vec::new()));
                    }
                }
            }
            ("cfhttp", true) => {
                if opaque_http_depth > 0 {
                    opaque_http_depth -= 1;
                } else if let Some((parent, parameters)) = http_parents.pop() {
                    if let Some(parent) = parent {
                        for (offset, object) in parameters {
                            let call = b.add(FlowKind::Call, offset, vec![object, parent]);
                            if call != 0
                                && let Some(value) = b.result.flow.values.get_mut(call)
                            {
                                value.target = Some("cfhttp:param".into());
                                b.result.symbols.push(Symbol::Call {
                                    target: Some("cfhttp:param".into()),
                                    args: vec![Arg::Object, Arg::Object],
                                    offset: Some(offset as u64),
                                });
                            }
                        }
                    }
                } else {
                    b.gap(Limitation::UnbalancedHttpParent);
                }
            }
            ("cfhttpparam", false) => {
                let object = b.tag_call(&tag, name, false, true);
                if object != 0
                    && opaque_http_depth == 0
                    && let Some((Some(_), parameters)) = http_parents.last_mut()
                {
                    // Keep the child's source-time attributes. Emit containment
                    // only when the nearest owner's closing tag is observed.
                    parameters.push((tag.span.start, object));
                }
            }
            ("cfset", false) => b.assignment(&tag),
            ("cfif", false) => {
                if b.branches.len() == MAX_BRANCHES {
                    b.gap(Limitation::BranchDepth);
                    break;
                }
                b.condition_calls(tag.body.clone());
                b.condition_comparison(&tag, "cfif");
                b.branches.push(Branch {
                    entry: b.bindings.clone(),
                    alternatives: Vec::new(),
                    has_else: false,
                    guard: defined_guard(bytes, tag.body.clone()),
                });
            }
            ("cfelse" | "cfelseif", false) => {
                let Some(branch) = b.branches.last_mut() else {
                    b.gap(Limitation::UnbalancedBranch);
                    break;
                };
                if branch.has_else || branch.alternatives.len() >= 64 {
                    b.gap(Limitation::BranchAlternatives);
                    break;
                }
                branch.alternatives.push(std::mem::take(&mut b.bindings));
                b.bindings = branch.entry.clone();
                branch.has_else = name == "cfelse";
                branch.guard = if name == "cfelseif" {
                    defined_guard(bytes, tag.body.clone())
                } else {
                    None
                };
                if name == "cfelseif" {
                    b.condition_calls(tag.body.clone());
                    b.condition_comparison(&tag, "cfelseif");
                }
            }
            ("cfif", true) => b.end_branch(tag.span.start),
            (
                "cfexecute" | "cffile" | "cfdirectory" | "cfinput" | "cftextarea" | "cfselect"
                | "cfheader" | "cfcontent",
                false,
            ) => {
                b.tag_call(&tag, name, false, true);
            }
            ("input" | "textarea" | "select" | "button", false) => {
                b.tag_call(&tag, format!("html:{name}"), true, output_depth > 0);
            }
            ("cfapplication", false) => {
                if let Some(attrs) = attributes(bytes, &tag, Dialect::Cfml) {
                    for attr in attrs {
                        if bytes
                            .get(attr.name)
                            .is_some_and(|name| name.eq_ignore_ascii_case(b"searchimplicitscopes"))
                        {
                            let value =
                                String::from_utf8_lossy(bytes.get(attr.value).unwrap_or_default())
                                    .to_ascii_lowercase();
                            b.implicit_scope = b.branches.is_empty()
                                && matches!(value.as_str(), "true" | "yes" | "1");
                            if !matches!(
                                value.as_str(),
                                "true" | "yes" | "1" | "false" | "no" | "0"
                            ) {
                                b.gap(Limitation::DynamicScopeSetting);
                            }
                        }
                    }
                } else {
                    b.implicit_scope = false;
                    b.gap(Limitation::MalformedAttributes);
                }
            }
            ("cfoutput", false) => {
                output_depth = output_depth.saturating_add(1);
                let unknown = attributes(bytes, &tag, Dialect::Cfml).is_none_or(|attrs| {
                    attrs.iter().any(|a| {
                        [b"query".as_slice(), b"group", b"attributecollection"]
                            .iter()
                            .any(|name| {
                                bytes
                                    .get(a.name.clone())
                                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
                            })
                    })
                });
                output_scopes.push(unknown);
                if unknown {
                    unknown_output_scopes += 1;
                    b.gap(Limitation::QueryOutputScopeUnavailable);
                }
            }
            ("cfoutput", true) => {
                output_depth = output_depth.saturating_sub(1);
                if output_scopes.pop() == Some(true) {
                    unknown_output_scopes -= 1;
                }
            }
            ("cfapplication", true)
            | (
                "cfexecute" | "cffile" | "cfdirectory" | "cfinput" | "cftextarea" | "cfselect"
                | "cfheader" | "cfcontent",
                true,
            ) => {}
            // Do not let unknown control flow or calls preserve stale aliases.
            _ => {
                b.gap(Limitation::UnsupportedTag);
                b.bindings.clear();
            }
        }
    }
    for range in output_expressions {
        if function_depth == 0 {
            b.output(range, unknown_output_scopes == 0);
        }
    }
    if !http_parents.is_empty() || opaque_http_depth > 0 {
        b.gap(Limitation::UnclosedHttpParent);
    }
    if !b.branches.is_empty() {
        b.gap(Limitation::UnclosedBranch);
    }
    b.result
}

#[cfg(test)]
mod tests;
