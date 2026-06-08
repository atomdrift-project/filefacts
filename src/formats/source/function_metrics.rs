//! Function metrics ported from cleave.
//!
//! Walks the tree once collecting every function-definition node and
//! emits `functions.*` keys describing count, size distribution, name
//! shape, anonymous/async/generator counts, parameter shape, and
//! nesting depth. Recursion counts stay zero — cleave's original
//! analyzer left those for language-specific extractors that never
//! materialised, so behaviour is preserved.

use tree_sitter::Node;

use crate::output::Metrics;

use super::ast_walk::MAX_AST_DEPTH;
use super::identifier_metrics::string_entropy;
use super::langs::LangConfig;

/// Per-function info collected during the AST walk.
#[derive(Default)]
struct FunctionInfo {
    name: String,
    line_count: u32,
    param_count: u32,
    param_names: Vec<String>,
    is_anonymous: bool,
    nesting_depth: u32,
    contains_nested_functions: bool,
}

/// Walk the tree, collect function info, and emit `functions.*` metrics.
pub(super) fn emit(
    root: Node<'_>,
    source: &str,
    config: &LangConfig,
    total_lines: u32,
    metrics: &mut Metrics,
) {
    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut capped = false;
    collect(root, source, config, 0, 0, &mut functions, &mut capped);
    // Surface the truncation as the shared anti-analysis signal *before* the
    // empty-functions early return: a function-free but pathologically deep
    // tree (a giant `a+b+c+…` chain) caps here while producing no functions, so
    // emitting after the return would drop exactly the case worth flagging.
    if capped {
        metrics.insert("ast.depth_capped", 1.0);
    }
    if functions.is_empty() {
        return;
    }
    emit_metrics(&functions, total_lines, metrics);
}

/// Function-defining node kinds per language. Mirrors the
/// `function_node_types` used by cleave's UnifiedSourceAnalyzer for the
/// subset of languages that filefacts currently parses.
fn function_kinds_for(lang: &str) -> &'static [&'static str] {
    match lang {
        "python" => &["function_definition", "async_function_definition"],
        "javascript" | "typescript" => &[
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
            "generator_function_declaration",
        ],
        "go" => &["function_declaration", "method_declaration"],
        "rust" => &["function_item"],
        "java" => &["method_declaration", "constructor_declaration"],
        "bash" => &["function_definition"],
        "php" => &["function_definition", "method_declaration"],
        _ => &[],
    }
}

/// Field name on the function-definition node holding the parameter list.
fn function_params_field(lang: &str) -> &'static str {
    match lang {
        "rust" => "parameters",
        "go" => "parameters",
        "javascript" | "typescript" => "parameters",
        "python" => "parameters",
        "java" => "parameters",
        "php" => "parameters",
        "bash" => "body",
        _ => "parameters",
    }
}

fn collect(
    node: Node<'_>,
    source: &str,
    config: &LangConfig,
    depth: u32,
    tree_depth: u32,
    out: &mut Vec<FunctionInfo>,
    capped: &mut bool,
) {
    // This recurses one frame per *tree* level (every child), while `depth`
    // only tracks function nesting — so a function-free but deeply nested tree
    // (e.g. a `a+b+c+…` chain thousands long) would recurse unbounded and
    // overflow the worker stack with `depth` stuck at 0. Stop at the same cap
    // the AST walk uses; nothing useful lives past it, and a tree this deep is
    // itself an anti-analysis signal — record that we truncated.
    if tree_depth >= MAX_AST_DEPTH {
        *capped = true;
        return;
    }
    let is_fn = function_kinds_for(config.name).contains(&node.kind());
    if is_fn {
        let info = build_info(node, source, config, depth);
        out.push(info);
    }
    let new_depth = if is_fn { depth + 1 } else { depth };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect(
            child,
            source,
            config,
            new_depth,
            tree_depth + 1,
            out,
            capped,
        );
    }
}

fn build_info(node: Node<'_>, source: &str, config: &LangConfig, depth: u32) -> FunctionInfo {
    let bytes = source.as_bytes();
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(str::to_string)
        .unwrap_or_default();
    let is_anonymous = name.is_empty();

    let start_line = node.start_position().row as u32;
    let end_line = node.end_position().row as u32;
    let line_count = end_line.saturating_sub(start_line) + 1;

    let (param_count, param_names) = node
        .child_by_field_name(function_params_field(config.name))
        .map(|params| collect_param_names(params, source))
        .unwrap_or((0, Vec::new()));

    let contains_nested = has_nested_function(node, config);

    FunctionInfo {
        name,
        line_count,
        param_count,
        param_names,
        is_anonymous,
        nesting_depth: depth,
        contains_nested_functions: contains_nested,
    }
}

fn collect_param_names(params: Node<'_>, source: &str) -> (u32, Vec<String>) {
    let bytes = source.as_bytes();
    let mut count = 0u32;
    let mut names = Vec::new();
    let mut cursor = params.walk();
    for param in params.named_children(&mut cursor) {
        count += 1;
        // Most grammars name the parameter via an `identifier` / `name`
        // / `pattern` child. We fall back to the whole parameter text
        // truncated; cleave's original behaviour was identical.
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

fn has_nested_function(node: Node<'_>, config: &LangConfig) -> bool {
    let kinds = function_kinds_for(config.name);
    let mut cursor = node.walk();
    let mut stack: Vec<Node<'_>> = node.children(&mut cursor).collect();
    while let Some(n) = stack.pop() {
        if kinds.contains(&n.kind()) {
            return true;
        }
        let mut c = n.walk();
        stack.extend(n.children(&mut c));
    }
    false
}

fn emit_metrics(functions: &[FunctionInfo], total_lines: u32, metrics: &mut Metrics) {
    // `functions.count` is emitted by `lib.rs::extract_all` once
    // (cross-format: source-language counts and binary-disassembled
    // counts share the same canonical path). We compute the local
    // total here only for the ratio metrics below.
    let total = functions.len() as u32;

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
    let mut total_lines_in_functions: u32 = 0;
    let mut all_param_names: Vec<String> = Vec::new();

    for func in functions {
        lengths.push(func.line_count);
        param_counts.push(func.param_count);
        nesting_depths.push(func.nesting_depth);
        total_lines_in_functions += func.line_count;
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
        metrics.insert("functions.anonymous", f64::from(anonymous));
    }
    if nested_functions > 0 {
        metrics.insert("functions.nested_functions", f64::from(nested_functions));
    }
    if over_100 > 0 {
        metrics.insert("functions.over_100_lines", f64::from(over_100));
    }
    if over_500 > 0 {
        metrics.insert("functions.over_500_lines", f64::from(over_500));
    }
    if one_liners > 0 {
        metrics.insert("functions.one_liners", f64::from(one_liners));
    }
    if no_params > 0 {
        metrics.insert("functions.no_params_count", f64::from(no_params));
    }
    if many_params > 0 {
        metrics.insert("functions.many_params_count", f64::from(many_params));
    }
    if single_char_names > 0 {
        metrics.insert("functions.single_char_names", f64::from(single_char_names));
    }
    if high_entropy_names > 0 {
        metrics.insert(
            "functions.high_entropy_names",
            f64::from(high_entropy_names),
        );
    }
    if numeric_suffix_names > 0 {
        metrics.insert(
            "functions.numeric_suffix_names",
            f64::from(numeric_suffix_names),
        );
    }

    if !lengths.is_empty() {
        let sum: u32 = lengths.iter().sum();
        let avg = f64::from(sum) / lengths.len() as f64;
        metrics.insert("functions.avg_length_lines", avg);
        metrics.insert(
            "functions.max_length_lines",
            f64::from(*lengths.iter().max().unwrap_or(&0)),
        );
        metrics.insert(
            "functions.min_length_lines",
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
            metrics.insert("functions.length_stddev", stddev);
        }
    }

    if !param_counts.is_empty() {
        let sum: u32 = param_counts.iter().sum();
        let avg = f64::from(sum) / param_counts.len() as f64;
        if avg > 0.0 {
            metrics.insert("functions.avg_params", avg);
        }
        let max = *param_counts.iter().max().unwrap_or(&0);
        if max > 0 {
            metrics.insert("functions.max_params", f64::from(max));
        }
    }

    if !all_param_names.is_empty() {
        let total_len: usize = all_param_names.iter().map(String::len).sum();
        let avg = total_len as f64 / all_param_names.len() as f64;
        if avg > 0.0 {
            metrics.insert("functions.avg_param_name_length", avg);
        }
        let single = all_param_names.iter().filter(|s| s.len() == 1).count();
        if single > 0 {
            metrics.insert("functions.single_char_params", single as f64);
        }
    }

    if !name_lengths.is_empty() {
        let sum: usize = name_lengths.iter().sum();
        let avg = sum as f64 / name_lengths.len() as f64;
        metrics.insert("functions.avg_name_length", avg);
    }

    if !nesting_depths.is_empty() {
        let max = *nesting_depths.iter().max().unwrap_or(&0);
        if max > 0 {
            metrics.insert("functions.max_nesting_depth", f64::from(max));
        }
        let sum: u32 = nesting_depths.iter().sum();
        let avg = f64::from(sum) / nesting_depths.len() as f64;
        if avg > 0.0 {
            metrics.insert("functions.avg_nesting_depth", avg);
        }
    }

    if total_lines > 0 {
        metrics.insert(
            "functions.density_per_100_lines",
            (f64::from(total) / f64::from(total_lines)) * 100.0,
        );
        metrics.insert(
            "functions.code_in_functions_ratio",
            f64::from(total_lines_in_functions) / f64::from(total_lines),
        );
    }
}

fn has_numeric_suffix(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    let last = chars[chars.len() - 1];
    let second_last = chars[chars.len() - 2];
    last.is_ascii_digit() && second_last.is_ascii_alphabetic()
}
