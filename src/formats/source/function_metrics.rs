//! Function metrics.
//!
//! Collects every node of the language's
//! [`function_kinds`](super::langs::LangConfig::function_kinds) during the
//! shared walk ([`super::visit`]) and emits `functions.*` keys describing
//! count, size distribution, name shape, anonymous/async/generator counts,
//! parameter shape, and nesting depth.

use crate::metric;
use tree_sitter::Node;

use crate::output::Metrics;

use super::ast_walk::MAX_AST_DEPTH;
use super::identifier_metrics::string_entropy;
use super::visit::{NodeIds, Visit};

/// Per-function info collected during the AST walk.
#[derive(Default)]
struct FunctionInfo {
    name: String,
    line_count: u32,
    start_line: u32,
    end_line: u32,
    param_count: u32,
    param_names: Vec<String>,
    is_anonymous: bool,
    nesting_depth: u32,
    contains_nested_functions: bool,
}

/// The function-definition nodes of one walk, in source order.
#[derive(Default)]
pub(super) struct Collector {
    functions: Vec<FunctionInfo>,
    /// The collected functions enclosing the walk's current node, innermost
    /// last: index into `functions`, and tree depth.
    open: Vec<(usize, u32)>,
    /// The tree reached [`MAX_AST_DEPTH`], below which no function is
    /// collected.
    capped: bool,
}

impl Collector {
    pub(super) fn enter(&mut self, visit: &Visit<'_>, source: &str, ids: &NodeIds) {
        // Nothing useful lives past the AST walk's depth cap, and a tree this
        // deep is itself an anti-analysis signal — record that we truncated.
        if visit.depth >= MAX_AST_DEPTH {
            self.capped = true;
        }
        // Named only: Python's `lambda` keyword token shares its kind name
        // with the expression it starts.
        if !visit.named || !ids.function.contains(visit.kind_id) {
            return;
        }
        // A function anywhere inside another, however deep, makes the
        // enclosing one nested. Marking the innermost enclosing function is
        // enough: it marks its own enclosing function in turn.
        if let Some(outer) = self
            .open
            .last()
            .and_then(|&(outer, _)| self.functions.get_mut(outer))
        {
            outer.contains_nested_functions = true;
        }
        if visit.depth < MAX_AST_DEPTH {
            let nesting_depth = u32::try_from(self.open.len()).unwrap_or(u32::MAX);
            self.open.push((self.functions.len(), visit.depth));
            self.functions
                .push(build_info(visit.node, source, nesting_depth));
        }
    }

    pub(super) fn exit(&mut self, visit: &Visit<'_>) {
        if self
            .open
            .last()
            .is_some_and(|&(_, depth)| depth == visit.depth)
        {
            self.open.pop();
        }
    }
}

/// Emit `functions.*` metrics for what `collector` gathered. Returns the
/// number of functions found, for the caller's ratios.
pub(super) fn emit(collector: Collector, total_lines: u32, metrics: &mut Metrics) -> usize {
    let Collector {
        functions, capped, ..
    } = collector;
    // Surface the truncation as the shared anti-analysis signal *before* the
    // empty-functions early return: a function-free but pathologically deep
    // tree (a giant `a+b+c+…` chain) caps here while producing no functions, so
    // emitting after the return would drop exactly the case worth flagging.
    if capped {
        metrics.insert(metric!("ast.depth_capped"), 1.0);
    }
    if functions.is_empty() {
        return 0;
    }
    emit_metrics(&functions, total_lines, metrics);
    functions.len()
}

/// A function's info, without [`FunctionInfo::contains_nested_functions`],
/// which the walk sets when it meets a nested function.
fn build_info(node: Node<'_>, source: &str, depth: u32) -> FunctionInfo {
    let bytes = source.as_bytes();
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(str::to_string)
        .unwrap_or_default();
    let is_anonymous = name.is_empty();

    let start_line = crate::bytes::sat_u32(node.start_position().row);
    let end_line = crate::bytes::sat_u32(node.end_position().row);
    let line_count = end_line.saturating_sub(start_line) + 1;

    // Every grammar here names the list `parameters`. A shell function has
    // none (it reads `$1`, `$@`), so it counts zero parameters.
    let (param_count, param_names) = node
        .child_by_field_name("parameters")
        .map(|params| collect_param_names(params, source))
        .unwrap_or((0, Vec::new()));

    FunctionInfo {
        name,
        line_count,
        start_line,
        end_line,
        param_count,
        param_names,
        is_anonymous,
        nesting_depth: depth,
        contains_nested_functions: false,
    }
}

fn collect_param_names(params: Node<'_>, source: &str) -> (u32, Vec<String>) {
    let bytes = source.as_bytes();
    let mut count = 0u32;
    let mut names = Vec::new();
    let mut cursor = params.walk();
    for param in params.named_children(&mut cursor) {
        count += 1;
        // Most grammars name the parameter via a `name` or `pattern`
        // field or an identifier child; otherwise the whole parameter text
        // stands in for the name.
        let name = param
            .child_by_field_name("name")
            .or_else(|| param.child_by_field_name("pattern"))
            .or_else(|| first_identifier(param))
            .and_then(|n| n.utf8_text(bytes).ok())
            .unwrap_or_else(|| param.utf8_text(bytes).unwrap_or(""))
            .to_string();
        if !name.is_empty() {
            names.push(name);
        }
    }
    (count, names)
}

fn first_identifier<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return Some(child);
        }
    }
    None
}

fn emit_metrics(functions: &[FunctionInfo], total_lines: u32, metrics: &mut Metrics) {
    // `functions.count` is emitted by `lib.rs::extract_all` once
    // (cross-format: source-language counts and binary-disassembled
    // counts share the same canonical path). We compute the local
    // total here only for the ratio metrics below.
    let total = crate::bytes::sat_u32(functions.len());

    let mut anonymous = 0u32;
    let mut nested_functions = 0u32;
    let mut over_100 = 0u32;
    let mut over_500 = 0u32;
    let mut one_liners = 0u32;
    let mut no_params = 0u32;
    let mut many_params = 0u32;
    let mut single_char_names = 0u32;
    let mut high_entropy_names = 0u32;
    let mut numeric_suffix_names = 0u32;

    let mut lengths: Vec<u32> = Vec::with_capacity(functions.len());
    let mut param_counts: Vec<u32> = Vec::with_capacity(functions.len());
    let mut name_lengths: Vec<usize> = Vec::with_capacity(functions.len());
    let mut nesting_depths: Vec<u32> = Vec::with_capacity(functions.len());
    // Source-ordered spans can overlap through nesting or share a line.
    // Count their union rather than repeatedly counting enclosing bodies.
    let mut covered_lines = 0u64;
    let mut covered_until = 0u64;
    let mut all_param_names: Vec<String> = Vec::new();

    for func in functions {
        lengths.push(func.line_count);
        param_counts.push(func.param_count);
        nesting_depths.push(func.nesting_depth);
        let start = u64::from(func.start_line).min(u64::from(total_lines));
        let end = (u64::from(func.end_line) + 1).min(u64::from(total_lines));
        covered_lines += end.saturating_sub(start.max(covered_until));
        covered_until = covered_until.max(end);
        if !func.name.is_empty() {
            name_lengths.push(func.name.len());
        }
        all_param_names.extend(func.param_names.iter().cloned());

        if func.is_anonymous {
            anonymous += 1;
        }
        if func.contains_nested_functions {
            nested_functions += 1;
        }
        if func.line_count > 100 {
            over_100 += 1;
        }
        if func.line_count > 500 {
            over_500 += 1;
        }
        if func.line_count <= 1 {
            one_liners += 1;
        }
        if func.param_count == 0 {
            no_params += 1;
        }
        if func.param_count > 7 {
            many_params += 1;
        }
        if !func.name.is_empty() {
            if func.name.len() == 1 {
                single_char_names += 1;
            }
            if string_entropy(&func.name) > 3.5 {
                high_entropy_names += 1;
            }
            if has_numeric_suffix(&func.name) {
                numeric_suffix_names += 1;
            }
        }
    }

    if anonymous > 0 {
        metrics.insert(metric!("functions.anonymous"), f64::from(anonymous));
    }
    if nested_functions > 0 {
        metrics.insert(metric!("functions.nested"), f64::from(nested_functions));
    }
    if over_100 > 0 {
        metrics.insert(metric!("functions.over_100_lines"), f64::from(over_100));
    }
    if over_500 > 0 {
        metrics.insert(metric!("functions.over_500_lines"), f64::from(over_500));
    }
    if one_liners > 0 {
        metrics.insert(metric!("functions.one_liners"), f64::from(one_liners));
    }
    if no_params > 0 {
        metrics.insert(metric!("functions.no_params_count"), f64::from(no_params));
    }
    if many_params > 0 {
        metrics.insert(
            metric!("functions.many_params_count"),
            f64::from(many_params),
        );
    }
    if single_char_names > 0 {
        metrics.insert(
            metric!("functions.single_char_names"),
            f64::from(single_char_names),
        );
    }
    if high_entropy_names > 0 {
        metrics.insert(
            metric!("functions.high_entropy_names"),
            f64::from(high_entropy_names),
        );
    }
    if numeric_suffix_names > 0 {
        metrics.insert(
            metric!("functions.numeric_suffix_names"),
            f64::from(numeric_suffix_names),
        );
    }

    if !lengths.is_empty() {
        let sum: u64 = lengths.iter().map(|&n| u64::from(n)).sum();
        let avg = sum as f64 / lengths.len() as f64;
        metrics.insert(metric!("functions.avg_length_lines"), avg);
        metrics.insert(
            metric!("functions.max_length_lines"),
            f64::from(*lengths.iter().max().unwrap_or(&0)),
        );
        metrics.insert(
            metric!("functions.min_length_lines"),
            f64::from(*lengths.iter().min().unwrap_or(&0)),
        );
        let variance: f64 = lengths
            .iter()
            .map(|&len| {
                let diff = f64::from(len) - avg;
                diff * diff
            })
            .sum::<f64>()
            / lengths.len() as f64;
        let stddev = variance.sqrt();
        if stddev > 0.0 {
            metrics.insert(metric!("functions.length_stddev"), stddev);
        }
    }

    if !param_counts.is_empty() {
        let sum: u32 = param_counts.iter().sum();
        let avg = f64::from(sum) / param_counts.len() as f64;
        if avg > 0.0 {
            metrics.insert(metric!("functions.avg_params"), avg);
        }
        let max = *param_counts.iter().max().unwrap_or(&0);
        if max > 0 {
            metrics.insert(metric!("functions.max_params"), f64::from(max));
        }
    }

    if !all_param_names.is_empty() {
        let total_len: usize = all_param_names.iter().map(String::len).sum();
        let avg = total_len as f64 / all_param_names.len() as f64;
        if avg > 0.0 {
            metrics.insert(metric!("functions.avg_param_name_length"), avg);
        }
        let single = all_param_names.iter().filter(|s| s.len() == 1).count();
        if single > 0 {
            metrics.insert(metric!("functions.single_char_params"), single as f64);
        }
    }

    if !name_lengths.is_empty() {
        let sum: usize = name_lengths.iter().sum();
        let avg = sum as f64 / name_lengths.len() as f64;
        metrics.insert(metric!("functions.avg_name_length"), avg);
    }

    if !nesting_depths.is_empty() {
        let max = *nesting_depths.iter().max().unwrap_or(&0);
        if max > 0 {
            metrics.insert(metric!("functions.max_nesting_depth"), f64::from(max));
        }
        let sum: u32 = nesting_depths.iter().sum();
        let avg = f64::from(sum) / nesting_depths.len() as f64;
        if avg > 0.0 {
            metrics.insert(metric!("functions.avg_nesting_depth"), avg);
        }
    }

    if total_lines > 0 {
        metrics.insert(
            metric!("functions.density"),
            (f64::from(total) / f64::from(total_lines)) * 100.0,
        );
        metrics.insert(
            metric!("functions.code_ratio"),
            covered_lines as f64 / f64::from(total_lines),
        );
    }
}

fn has_numeric_suffix(name: &str) -> bool {
    let mut chars = name.chars().rev();
    matches!(
        (chars.next(), chars.next()),
        (Some(last), Some(second_last))
            if last.is_ascii_digit() && second_last.is_ascii_alphabetic()
    )
}

#[cfg(test)]
mod tests;
