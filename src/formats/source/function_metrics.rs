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
struct FunctionInfo<'t> {
    /// Empty for an anonymous function.
    name: &'t str,
    line_count: u32,
    start_line: u32,
    end_line: u32,
    param_count: u32,
    /// Byte length of each parameter's name, for those that have one.
    param_name_lens: Vec<usize>,
    nesting_depth: u32,
    contains_nested_functions: bool,
}

/// The function-definition nodes of one walk, in source order.
#[derive(Default)]
pub(super) struct Collector<'t> {
    functions: Vec<FunctionInfo<'t>>,
    /// The collected functions enclosing the walk's current node, innermost
    /// last: index into `functions`, and tree depth.
    open: Vec<(usize, u32)>,
    /// The tree reached [`MAX_AST_DEPTH`], below which no function is
    /// collected.
    capped: bool,
    /// Monotonic byte offset in `source` and 0-based line number up to that
    /// byte, so function line ranges reflect the original `source` even when
    /// `parser_source` coalesced comment-run newlines.
    line_byte: usize,
    line_row: u32,
}

impl<'t> Collector<'t> {
    pub(super) fn enter(&mut self, visit: &Visit<'t>, source: &'t str, ids: &NodeIds) {
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
            let bytes = source.as_bytes();
            let start_byte = visit.node.start_byte().min(bytes.len());
            let end_byte = visit.node.end_byte().min(bytes.len());
            let start_line = if start_byte >= self.line_byte {
                let delta = memchr::memchr_iter(
                    b'\n',
                    bytes.get(self.line_byte..start_byte).unwrap_or_default(),
                )
                .count();
                self.line_row = self.line_row.saturating_add(crate::bytes::sat_u32(delta));
                self.line_byte = start_byte;
                self.line_row
            } else {
                crate::bytes::sat_u32(visit.node.start_position().row)
            };
            let body_newlines = memchr::memchr_iter(
                b'\n',
                bytes
                    .get(start_byte..end_byte.max(start_byte))
                    .unwrap_or_default(),
            )
            .count();
            let end_line = start_line.saturating_add(crate::bytes::sat_u32(body_newlines));
            self.open.push((self.functions.len(), visit.depth));
            self.functions.push(build_info(
                visit.node,
                source,
                nesting_depth,
                start_line,
                end_line,
            ));
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
pub(super) fn emit(collector: Collector<'_>, total_lines: u32, metrics: &mut Metrics) -> usize {
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
fn build_info<'t>(
    node: Node<'t>,
    source: &'t str,
    depth: u32,
    start_line: u32,
    end_line: u32,
) -> FunctionInfo<'t> {
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        .unwrap_or_default();

    let line_count = end_line.saturating_sub(start_line) + 1;

    // Every grammar here names the list `parameters`. A shell function has
    // none (it reads `$1`, `$@`), so it counts zero parameters.
    let (param_count, param_name_lens) = node
        .child_by_field_name("parameters")
        .map_or((0, Vec::new()), |params| param_name_lens(params, source));

    FunctionInfo {
        name,
        line_count,
        start_line,
        end_line,
        param_count,
        param_name_lens,
        nesting_depth: depth,
        contains_nested_functions: false,
    }
}

/// The number of parameters in `params`, and the byte length of each one's
/// name.
fn param_name_lens(params: Node<'_>, source: &str) -> (u32, Vec<usize>) {
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
            .unwrap_or_else(|| param.utf8_text(bytes).unwrap_or(""));
        if !name.is_empty() {
            names.push(name.len());
        }
    }
    (count, names)
}

fn first_identifier(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| child.kind() == "identifier")
}

fn emit_metrics(functions: &[FunctionInfo<'_>], total_lines: u32, metrics: &mut Metrics) {
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
    let mut param_names = 0usize;
    let mut param_name_bytes = 0usize;
    let mut single_char_params = 0usize;

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
        param_names += func.param_name_lens.len();
        param_name_bytes += func.param_name_lens.iter().sum::<usize>();
        single_char_params += func.param_name_lens.iter().filter(|&&len| len == 1).count();

        if func.name.is_empty() {
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
            if string_entropy(func.name) > 3.5 {
                high_entropy_names += 1;
            }
            if has_numeric_suffix(func.name) {
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

    if param_names > 0 {
        let avg = param_name_bytes as f64 / param_names as f64;
        if avg > 0.0 {
            metrics.insert(metric!("functions.avg_param_name_length"), avg);
        }
        if single_char_params > 0 {
            metrics.insert(
                metric!("functions.single_char_params"),
                single_char_params as f64,
            );
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
