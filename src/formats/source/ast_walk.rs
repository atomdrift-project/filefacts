//! Tree-sitter symbol collection that emits unified [`Symbol`] facts.
//!
//! [`State`] collects during the shared walk ([`super::visit`]); [`finish`]
//! then pushes, in source order:
//!
//! - one [`Symbol::Call`] per call site,
//! - one [`Symbol::Bind`] per static assignment,
//! - one [`Symbol::Member`] per unique dotted member-access chain.
//!
//! Numeric tally features are written into the caller's [`Metrics`]
//! map as `ast.*` keys. Counts and depths live there, not on the
//! symbol records.
//!
//! The walker is driven by the [`LangConfig`] passed in: its node-kind and
//! field tables decide what is a call, a member access, a literal or an
//! argument, and its methods resolve each call's callee and argument list. A
//! few grammar quirks the tables cannot express are handled here, keyed on
//! [`Lang`]:
//!
//! - Bash: a command whose name starts with `-` records no call.
//! - Perl: a leaf `function` node and a plain `$scalar` receiver are static
//!   names; a method chosen at run time (`$obj->$m()`) is not.
//! - Rust: a `scoped_identifier` (`a::b`) is already a static path, and a
//!   `&x` argument is shaped as `x`.
//! - Zig: positional arguments are the call's named children after the callee.
//!
//! The node kinds the shape detectors below look for (function definitions,
//! loops, assignments, subscripts) are matched across all grammars at once.

use crate::metric;
use std::collections::{BTreeMap, HashSet};

use tree_sitter::{Node, TreeCursor};

use crate::output::{Arg, ArgShape, Metrics, Symbol, Symbols};

use super::decode_string_literal;
use super::langs::{Lang, LangConfig};
use super::visit::{self, NodeIds, Visit};

/// Hard cap on AST recursion depth.
///
/// tree-sitter trees can be arbitrarily deep on generated or adversarial
/// source (thousands of nested brackets, binary expressions, etc.). The
/// symbol walk once recursed one stack frame per level, and the chain helpers
/// below still recurse per link, so an unbounded walk would overflow the
/// worker thread's stack and abort the whole process. The walk passes no
/// node below this depth to [`State::visit`]. Real source is rarely more
/// than a few dozen levels deep; anything past this is machine-generated and
/// yields no useful symbols. `ast.max_depth` saturates at this value, which is itself
/// a usable "pathologically nested" signal.
pub(super) const MAX_AST_DEPTH: u32 = 1000;

/// Walk `root` for this module alone and emit its symbols and metrics. The
/// extraction walk in `super::extract` normally collects the [`State`] along
/// with everything else; this is the path when it did not.
pub(super) fn walk(
    root: Node<'_>,
    source: &str,
    config: &'static LangConfig,
    symbols_out: &mut Symbols,
    metrics: &mut Metrics,
) {
    let mut collectors = visit::Collectors {
        ast: Some(State::default()),
        ..visit::Collectors::default()
    };
    visit::walk(root, source, config, &mut collectors);
    if let Some(state) = collectors.ast {
        finish(state, config, symbols_out, metrics);
    }
}

/// Emit what a walk collected into `state`: its symbols, then the `ast.*`
/// metrics.
pub(super) fn finish(
    state: State,
    config: &LangConfig,
    symbols_out: &mut Symbols,
    metrics: &mut Metrics,
) {
    // Drain the per-symbol-kind buffers into the unified Symbols view.
    let call_count = state.calls.len() as u64;
    let member_count = state.members.len() as u64;
    // Classify each call's command-name target (obfuscated vs dynamic) before
    // the buffer is drained into `symbols_out`.
    super::call_target_metrics::emit(&state.calls, config.lang, metrics);
    for c in state.calls {
        symbols_out.push(c);
    }
    for b in state.binds {
        symbols_out.push(b);
    }
    for (path, offset) in state.members {
        symbols_out.push(Symbol::Member {
            path,
            offset: Some(offset),
        });
    }
    for (name, offset) in state.identifiers {
        symbols_out.push(Symbol::Identifier {
            name,
            offset: Some(offset),
        });
    }

    metrics.insert(metric!("ast.node_count"), state.node_count as f64);
    metrics.insert(metric!("ast.max_depth"), f64::from(state.max_depth));
    // Reaching the recursion cap means the tree (and any member/concat/subscript
    // chain inside it) was truncated — deeper nodes were not analysed. A
    // pathologically deep tree is itself a generated/obfuscated-source signal,
    // so surface it as a metric *and* warn once: the same depth that trips this
    // is what used to overflow the worker stack and abort the process, so an
    // operator seeing a flood of these knows the inputs are hostile-shaped.
    if state.max_depth >= MAX_AST_DEPTH {
        metrics.insert(metric!("ast.depth_capped"), 1.0);
        tracing::warn!(
            lang = config.name(),
            node_count = state.node_count,
            max_depth = state.max_depth,
            cap = MAX_AST_DEPTH,
            "AST walk hit the recursion depth cap; deeper nodes and chains were \
             truncated (generated or adversarial source)",
        );
    }
    metrics.insert(metric!("ast.call_count"), call_count as f64);
    if state.max_member_chain_depth > 0 {
        metrics.insert(
            metric!("ast.max_member_depth"),
            f64::from(state.max_member_chain_depth),
        );
    }
    if state.max_string_concat_chain > 1 {
        metrics.insert(
            metric!("ast.max_concat_chain"),
            f64::from(state.max_string_concat_chain),
        );
    }
    if state.max_array_literal_length > 0 {
        metrics.insert(
            metric!("ast.max_array_length"),
            f64::from(state.max_array_literal_length),
        );
    }
    if state.max_numeric_array_length > 0 {
        metrics.insert(
            metric!("ast.max_numeric_array"),
            f64::from(state.max_numeric_array_length),
        );
    }

    if member_count > 0 {
        metrics.insert(metric!("ast.member_count"), member_count as f64);
    }

    // Per-operator counts: `ast.op.<name>` (e.g. `ast.op.xor`). Raw integer
    // counts keyed by the canonical operator name; matched O(1) via
    // `type: metrics, field: 'ast.op.xor', min: N`.
    for (op, count) in &state.op_counts {
        metrics.insert(crate::ast_op(op), f64::from(*count));
    }
    // Per-operator density: `ast.op_density.<name>` = count / node_count. A
    // scale-invariant signal that an operator dominates the parse tree
    // (e.g. an obfuscated array packed with `number - number` subtractions),
    // independent of file size — unlike the raw count, which simply grows
    // with the file. Emitted only when there is a node to divide by.
    if state.node_count > 0 {
        let nodes = state.node_count as f64;
        for (op, count) in &state.op_counts {
            metrics.insert(crate::ast_op_density(op), f64::from(*count) / nodes);
        }
    }
    // `ast.sequence_count` follows the node-kind-count convention (cf.
    // `ast.member_count` from `member_expression`).
    if state.sequence_expr_count > 0 {
        metrics.insert(
            metric!("ast.sequence_count"),
            f64::from(state.sequence_expr_count),
        );
    }
    if state.identity_fn_count > 0 {
        metrics.insert(
            metric!("ast.identity_function_count"),
            f64::from(state.identity_fn_count),
        );
    }
    if state.string_return_fn_count > 0 {
        metrics.insert(
            metric!("ast.string_return_function_count"),
            f64::from(state.string_return_fn_count),
        );
    }
    // Scale-invariant companion to `ast.string_return_function_count`: the
    // fraction of all functions whose body is a single `return "<literal>"`.
    // A substitution-table decoder is almost entirely such functions; a large
    // hand-written module has a handful, so the ratio separates them where the
    // raw count cannot.
    if state.function_count > 0 && state.string_return_fn_count > 0 {
        metrics.insert(
            metric!("ast.string_return_function_ratio"),
            f64::from(state.string_return_fn_count) / f64::from(state.function_count),
        );
    }
    if state.xor_mod_loop_count > 0 {
        metrics.insert(
            metric!("ast.xor_mod_loop_count"),
            f64::from(state.xor_mod_loop_count),
        );
    }
    if state.max_numeric_sequence_length > 0 {
        metrics.insert(
            metric!("ast.max_numeric_sequence"),
            f64::from(state.max_numeric_sequence_length),
        );
    }
    if state.const_return_fn_count > 0 {
        metrics.insert(
            metric!("ast.const_return_function_count"),
            f64::from(state.const_return_fn_count),
        );
    }
    // Scale-invariant companion to `ast.const_return_function_count`: the
    // fraction of all functions that are parameterless constant-return padding.
    // Opaque-padding obfuscation makes most functions this shape; a normal
    // large module has many real functions diluting them, so gate on the ratio
    // (with a count floor) rather than the size-scaling raw count.
    if state.function_count > 0 && state.const_return_fn_count > 0 {
        metrics.insert(
            metric!("ast.const_return_function_ratio"),
            f64::from(state.const_return_fn_count) / f64::from(state.function_count),
        );
    }
    if state.self_compare_count > 0 {
        metrics.insert(
            metric!("ast.self_compare_count"),
            f64::from(state.self_compare_count),
        );
    }
    if state.infinite_loop_count > 0 {
        metrics.insert(
            metric!("ast.infinite_loop_count"),
            f64::from(state.infinite_loop_count),
        );
    }
}

/// Canonical, language-agnostic name for an operator token, or `None` for
/// tokens that aren't meaningful operators (assignment `=`, separators, …).
/// Normalizes per-grammar spellings to one semantic name so density metrics
/// (`ast.op.xor`, `ast.op.sub`, …) are key-safe and consistent across
/// languages — JS `^`, Python `^`, and PowerShell `-bxor` all become `xor`.
/// Compound assignments fold to their base op (`^=` → `xor`).
fn canonical_op(tok: &str) -> Option<&'static str> {
    Some(match tok {
        // bitwise
        "^" | "^=" | "-bxor" => "xor",
        "&" | "&=" | "-band" => "band",
        "|" | "|=" | "-bor" => "bor",
        "~" | "-bnot" => "bnot",
        "<<" | "<<=" | "-shl" => "shl",
        ">>" | ">>=" | "-shr" => "shr",
        ">>>" | ">>>=" => "ushr",
        // arithmetic
        "+" | "+=" => "add",
        "-" | "-=" => "sub",
        "*" | "*=" => "mul",
        "/" | "/=" => "div",
        "%" | "%=" | "-mod" => "mod",
        "**" | "**=" => "pow",
        "//" | "//=" => "floordiv",
        // comparison
        "==" | "===" | "-eq" => "eq",
        "!=" | "!==" | "<>" | "-ne" => "ne",
        "<" | "-lt" => "lt",
        ">" | "-gt" => "gt",
        "<=" | "-le" => "le",
        ">=" | "-ge" => "ge",
        // logical
        "&&" | "and" | "-and" => "land",
        "||" | "or" | "-or" => "lor",
        "!" | "not" | "-not" => "lnot",
        // string / collection
        "." | ".=" => "concat", // PHP string concatenation
        "-join" => "join",
        "-split" => "split",
        "-match" => "match",
        "-replace" => "replace",
        "??" | "??=" => "coalesce",
        _ => return None,
    })
}

/// True when `node`'s subtree (within `depth` levels) contains a `%` (modulo)
/// operator — used to recognize the rolling-XOR decode shape `a[i] ^ b[i % n]`
/// when called on the enclosing `^` binary node. Bounded depth keeps it O(1)
/// amortized over the walk.
fn subtree_has_mod(node: Node<'_>, source: &str, depth: u32) -> bool {
    if depth == 0 {
        return false;
    }
    if let Some(op) = node.child_by_field_name("operator") {
        if let Ok(t) = op.utf8_text(source.as_bytes()) {
            if canonical_op(t) == Some("mod") {
                return true;
            }
        }
    }
    let mut cur = node.walk();
    for child in node.named_children(&mut cur) {
        if subtree_has_mod(child, source, depth - 1) {
            return true;
        }
    }
    false
}

/// Function definitions across the grammars: declarations, expressions,
/// arrows, methods, lambdas and Rust `fn` items. The shape detectors below
/// and their ratio denominator (`State::function_count`) share this one
/// predicate, so no shape is counted for a kind the denominator leaves out.
/// Named nodes only: Python's `lambda` keyword token shares its kind name
/// with the expression it starts.
fn is_function_definition(node: Node<'_>) -> bool {
    node.is_named() && FUNCTION_DEFINITION_KINDS.contains(&node.kind())
}

/// The kinds [`is_function_definition`] accepts, when named.
pub(super) const FUNCTION_DEFINITION_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "arrow_function",
    "function_definition",
    "lambda",
    "method_definition",
    "function_item",
];

/// The only kinds [`is_infinite_loop`] can accept.
pub(super) const INFINITE_LOOP_KINDS: &[&str] = &[
    "for_statement",
    "while_statement",
    "while",
    "while_modifier",
    "do_statement",
];

/// True when `node` is a function whose entire body is `return <ident>` and
/// `<ident>` names one of the function's own parameters — the identity-proxy
/// obfuscation shape (`function(x){ return x }`, `lambda x: x`). The
/// param↔return backreference is why a regex can't express this.
fn is_identity_function(node: Node<'_>, source: &str) -> bool {
    if !is_function_definition(node) {
        return false;
    }
    let bytes = source.as_bytes();
    // Collect parameter identifier names.
    let Some(params) = node.child_by_field_name("parameters") else {
        return false;
    };
    let mut pcur = params.walk();
    let param_names: Vec<&str> = params
        .named_children(&mut pcur)
        .filter_map(|p| {
            let id = if p.kind() == "identifier" {
                p
            } else {
                first_named_child(p)?
            };
            id.utf8_text(bytes)
                .ok()
                .filter(|_| id.kind() == "identifier")
        })
        .collect();
    if param_names.is_empty() {
        return false;
    }
    // The body must be (or wrap) a single `return <identifier>`.
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let returned = returned_identifier(body, bytes);
    returned.is_some_and(|r| param_names.contains(&r))
}

/// The argument node of a block body's lone `return <expr>`, if the block
/// holds exactly one non-comment statement and it is a `return` carrying an
/// argument. `None` otherwise. Comments don't count toward the statement total,
/// so a documented one-liner still qualifies. This single-return shape is what
/// the obfuscation-decoder detectors below all key on.
fn sole_return_argument(body: Node<'_>) -> Option<Node<'_>> {
    // Exactly one non-comment statement, and it must be a `return` carrying an
    // argument — a second statement, zero statements, or a non-return all
    // disqualify (the second `next()` short-circuits multi-statement bodies).
    let mut cur = body.walk();
    let mut stmts = body
        .named_children(&mut cur)
        .filter(|c| c.kind() != "comment");
    let stmt = stmts.next()?;
    if stmts.next().is_some() || stmt.kind() != "return_statement" {
        return None;
    }
    let mut rcur = stmt.walk();
    stmt.named_children(&mut rcur).next()
}

/// The single identifier returned by a function body, if the body is exactly
/// one `return <identifier>` (JS `{ return x }` / arrow `x` / Python `return x`).
fn returned_identifier<'a>(body: Node<'_>, bytes: &'a [u8]) -> Option<&'a str> {
    // Arrow-function expression body: the body *is* the identifier.
    if body.kind() == "identifier" {
        return body.utf8_text(bytes).ok();
    }
    // Block body: a lone `return <identifier>`.
    let arg = sole_return_argument(body)?;
    if arg.kind() == "identifier" {
        arg.utf8_text(bytes).ok()
    } else {
        None
    }
}

/// True when `node` is a function whose entire body is a single
/// `return <string-literal>` (or an arrow whose expression body is a string).
/// The substitution-table obfuscation shape — decoder functions that just
/// return a fixed string — replaces tree-sitter `(function_declaration body:
/// (statement_block (return_statement (string))))` queries.
fn is_string_return_function(node: Node<'_>) -> bool {
    if !is_function_definition(node) {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    // Arrow expression body: the body *is* the string.
    if is_static_string_literal(body) {
        return true;
    }
    // Block body: a lone `return <string-literal>`.
    sole_return_argument(body).is_some_and(is_static_string_literal)
}

/// A function that returns a **static** string literal is the substitution-table
/// obfuscation shape. An interpolated template (`` `https://…${id}` ``) is a
/// *computed* value — a URL builder, not a decoder table entry — so a template
/// carrying any `${…}` substitution does not count.
fn is_static_string_literal(node: Node<'_>) -> bool {
    match node.kind() {
        "string" | "raw_string" => true,
        "template_string" | "template_literal" => {
            let mut cur = node.walk();
            !node
                .named_children(&mut cur)
                .any(|c| c.kind() == "template_substitution")
        }
        _ => false,
    }
}

/// A single literal value or bare identifier — the only things a
/// constant-return padding helper hands back.
fn is_literal_or_identifier(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "number"
            | "integer"
            | "float"
            | "string"
            | "raw_string"
            | "true"
            | "false"
            | "null"
            | "True"
            | "False"
            | "None"
            | "none"
            | "nil"
            | "identifier"
    )
}

/// True when `node` is a **parameterless** function whose entire body is a
/// single `return <literal-or-identifier>` (or an arrow whose expression body
/// is such). The dead-code / opaque padding shape — many of these in one file
/// dilute static and ML analysis. Parameterless distinguishes it from an
/// identity proxy (`function(x){ return x }`).
fn is_const_return_function(node: Node<'_>) -> bool {
    if !is_function_definition(node) {
        return false;
    }
    // Parameterless: a `parameters`/`formal_parameters` node with no named
    // children. Python's `lambda: 0` has no parameter list at all, while a
    // JS `x => 0` keeps its lone parameter under `parameter` instead.
    let parameterless = match node.child_by_field_name("parameters") {
        Some(params) => params.named_child_count() == 0,
        None => node.kind() == "lambda",
    };
    if !parameterless {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    // Arrow expression body: the body *is* the literal/identifier.
    if is_literal_or_identifier(body) {
        return true;
    }
    // Block body: a lone `return <literal/identifier>`.
    sole_return_argument(body).is_some_and(is_literal_or_identifier)
}

/// True when `node` is a loop with a literally-true condition: `while true`,
/// `while (1)`, `while (!![])`, or a C-style `for (;;)`. Recognized across
/// grammars by inspecting the condition text (parens/whitespace stripped) — a
/// node-scoped check, so a bare `while true` in prose or a comment never fires.
fn is_infinite_loop(node: Node<'_>, source: &str) -> bool {
    let kind = node.kind();
    let bytes = source.as_bytes();
    // C-style `for (;;)`: a for_statement with neither condition nor update.
    if kind == "for_statement"
        && node.child_by_field_name("condition").is_none()
        && node.child_by_field_name("initializer").is_none()
        && node.child_by_field_name("update").is_none()
    {
        // Only C-style fors have these fields; for-in/for-of lack them too, so
        // require the literal `for (;;)`/`for(;;)` spelling to avoid those.
        if let Ok(t) = node.utf8_text(bytes) {
            let head: String = t.chars().take(12).filter(|c| !c.is_whitespace()).collect();
            return head.starts_with("for(;;)");
        }
        return false;
    }
    if !matches!(
        kind,
        "while_statement" | "while" | "while_modifier" | "do_statement"
    ) {
        return false;
    }
    let cond = node
        .child_by_field_name("condition")
        .or_else(|| first_named_child(node));
    let Some(cond) = cond else { return false };
    let Ok(text) = cond.utf8_text(bytes) else {
        return false;
    };
    // Strip whitespace and one layer of wrapping parens.
    let mut t = text.trim();
    while let Some(inner) = t.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        t = inner.trim();
    }
    matches!(t, "true" | "True" | "1" | "!![]" | "!0" | "1==1" | "1===1")
}

/// What one walk collects for [`finish`].
#[derive(Default)]
pub(super) struct State {
    calls: Vec<Symbol>,
    binds: Vec<Symbol>,
    members: BTreeMap<String, u64>,
    /// Ids of member/subscript nodes inside a chain whose outermost node
    /// already recorded their paths; the walk skips each as it passes.
    resolved_links: HashSet<usize>,
    /// Dedup'd bare-identifier names with first-seen byte offset.
    /// Captures every identifier-kind token across the file — variable
    /// references, parameter names, type names, function-call targets,
    /// etc. — so naming-pattern rules (`c2_server`, `BackdoorListener`,
    /// `xmrig`) can fire via `type: name, kind: identifier`.
    identifiers: BTreeMap<String, u64>,
    /// Per-operator occurrence counts keyed by canonical name (`xor` → 12,
    /// `mod` → 3, …), tallied during the single existing walk. Emitted as
    /// `ast.op.<name>` metrics so density rules match O(1) via `type: metrics`
    /// with no per-occurrence facts — the lowest-overhead operator-density form.
    op_counts: BTreeMap<&'static str, u32>,
    node_count: u64,
    max_depth: u32,
    max_member_chain_depth: u32,
    max_string_concat_chain: u32,
    max_array_literal_length: u32,
    /// Max length of an all-numeric-literal array
    /// (`ast.max_numeric_array`).
    max_numeric_array_length: u32,
    /// Count of statement-level comma sequences (`a, b, c;`) — a density
    /// signal for comma-sequence obfuscation (`ast.sequence_expression_count`).
    sequence_expr_count: u32,
    /// Count of identity-proxy functions (`function(x){ return x }`) — the
    /// backreference (return == param) can't be expressed in a regex, so the
    /// walker checks it here and exposes only the count
    /// (`ast.identity_function_count`).
    identity_fn_count: u32,
    /// Count of functions whose entire body is `return <string-literal>` —
    /// the substitution-table obfuscation shape (`ast.string_return_function_count`).
    string_return_fn_count: u32,
    /// Count of `^` expressions whose operand subtree contains a `%` — the
    /// rolling-XOR decode shape `data[i] ^ key[i % n]` (`ast.xor_mod_loop_count`).
    xor_mod_loop_count: u32,
    /// Max count of numeric literals in a comma `sequence_expression`
    /// (`(1, 2, 3)`) — comma-constant obfuscation
    /// (`ast.max_numeric_sequence`).
    max_numeric_sequence_length: u32,
    /// Count of parameterless functions whose body is a single
    /// `return <literal>` — dead-code / opaque padding helpers
    /// (`ast.const_return_function_count`).
    const_return_fn_count: u32,
    /// Count of all function-definition nodes (declarations, expressions,
    /// arrows, methods, lambdas) — the denominator for the const-return /
    /// string-return *ratio* metrics. A raw count of decoder/padding helpers
    /// grows with file size; the obfuscation signal is the *fraction* of a
    /// file's functions that take that shape, so density beats count.
    function_count: u32,
    /// Count of binary expressions whose left and right operands are textually
    /// identical (`5 - 5`, `x === x`) — the useless-arithmetic / opaque-predicate
    /// shape (`#eq? @left @right`, a backreference no regex expresses). Excludes
    /// `!=`/`!==`/`<>` since `x !== x` is the legitimate NaN test
    /// (`ast.self_compare_count`).
    self_compare_count: u32,
    /// Count of loops with a literally-true condition (`while true`,
    /// `while (1)`, `for (;;)`) — infinite-loop obfuscation/rotators, matched
    /// on the loop node so it never fires on prose (`ast.infinite_loop_count`).
    infinite_loop_count: u32,
}

impl State {
    /// Record `visit`'s node. The walk passes every node down to
    /// [`MAX_AST_DEPTH`] in pre-order, left to right; a node at the cap only
    /// counts, and nothing below it is passed.
    pub(super) fn visit<'t>(
        &mut self,
        visit: &Visit<'t>,
        source: &str,
        config: &LangConfig,
        ids: &NodeIds,
        scratch: &mut TreeCursor<'t>,
    ) {
        let node = visit.node;
        let kind = visit.kind_id;
        let depth = visit.depth;
        self.node_count += 1;
        if depth > self.max_depth {
            self.max_depth = depth;
        }
        // Stop before a pathologically deep tree overflows the stack.
        if depth >= MAX_AST_DEPTH {
            return;
        }

        // A member chain resolves once, at its outermost node, which also
        // records every static prefix on its receiver side (`a.b` of
        // `a.b.c`). The walk still descends through the chain for the calls
        // and literals inside it, but does not resolve those prefixes again.
        // Subscript-with-string-index (`obj["constructor"]`) folds into the
        // same path, so a JS sandbox-escape pattern like
        // `obj["constructor"]["constructor"]("...")` lands as a member chain
        // instead of dropping out as a dynamic access.
        if ids.member_or_subscript.contains(kind) && !self.resolved_links.remove(&node.id()) {
            self.record_member_chain(node, source, config, depth);
        }

        if ids.call.contains(kind) {
            self.record_call(node, source, config, scratch);
        }

        if ids.assignment.contains(kind) {
            self.record_assignment(node, source, config);
        }

        if ids.array.contains(kind) {
            let len = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
            if len > self.max_array_literal_length {
                self.max_array_literal_length = len;
            }
            // Numeric-array length: arrays whose elements are *all* numeric
            // literals — the byte-packing obfuscation shape (`[112,97,121,...]`),
            // distinct from a generic long array of mixed/string data. Lets
            // `ast.max_numeric_array` keeps that specificity that a plain
            // array-length metric would lose.
            if len >= 2 {
                let all_numeric = node
                    .named_children(scratch)
                    .all(|c| ids.number.contains(c.kind_id()));
                if all_numeric && len > self.max_numeric_array_length {
                    self.max_numeric_array_length = len;
                }
            }
        }

        // Bare-identifier capture: every identifier-kind leaf node
        // contributes its name to the dedup'd identifiers set, keyed
        // by name with the first-seen byte offset. Filter to leaf
        // identifiers (no named children) to skip e.g. qualified
        // identifier wrappers — we want `os` and `path`, not the
        // combined `os.path` node which member-chain extraction
        // handles separately.
        if ids.identifier.contains(kind) && node.named_child_count() == 0 {
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                if !text.is_empty() {
                    self.identifiers
                        .entry(text.to_string())
                        .or_insert(node.start_byte() as u64);
                }
            }
        }

        // Operator density: tally the `operator` token of any node that has
        // one (binary expressions, augmented assignments, unary ops across all
        // grammars), normalized to a canonical semantic name (`^` → `xor`,
        // PowerShell `-bxor` → `xor`, …). Counted inline in this single walk
        // and emitted as `ast.op.<name>` metrics — language-agnostic, key-safe,
        // O(1) to match, no per-occurrence facts.
        let op_node = ids
            .operator_field
            .and_then(|field| node.child_by_field_id(field));
        if let Some(op_node) = op_node {
            if let Ok(op) = op_node.utf8_text(source.as_bytes()) {
                if let Some(name) = canonical_op(op) {
                    *self.op_counts.entry(name).or_insert(0) += 1;
                    // Rolling-XOR decode shape: an `^` whose operand subtree
                    // contains a `%` (cyclic key index, `data[i] ^ key[i % n]`).
                    // Recognized across JS / Python / Go without a per-language
                    // query; emitted as `ast.xor_mod_loop_count`.
                    if name == "xor" && subtree_has_mod(node, source, 6) {
                        self.xor_mod_loop_count += 1;
                    }
                }
                // Self-compare: identical left/right operands (`5 - 5`,
                // `x === x`) — useless arithmetic / opaque predicate. Skip the
                // NaN idiom `x !== x` (`ne` maps inequality ops to one name).
                if !matches!(op, "!=" | "!==" | "<>") {
                    let field = |id: Option<u16>| id.and_then(|id| node.child_by_field_id(id));
                    if let (Some(l), Some(r)) = (field(ids.left_field), field(ids.right_field)) {
                        if let (Ok(lt), Ok(rt)) = (
                            l.utf8_text(source.as_bytes()),
                            r.utf8_text(source.as_bytes()),
                        ) {
                            if lt == rt && !lt.is_empty() {
                                self.self_compare_count += 1;
                            }
                        }
                    }
                }
            }
        }

        // Statement-level comma sequences (`a, b, c;`) — density signal for
        // comma-sequence obfuscation.
        if ids.sequence.contains(kind) {
            self.sequence_expr_count += 1;
            // All-numeric comma sequence (`(1, 2, 3, …)`) — comma-constant
            // obfuscation. Mirror the numeric-array shape: count the numeric
            // members when every member is a numeric literal.
            let mut members = 0usize;
            let mut all_numeric = true;
            for member in node.named_children(scratch) {
                members += 1;
                all_numeric &= ids.number.contains(member.kind_id());
            }
            if members >= 2 && all_numeric {
                let len = u32::try_from(members).unwrap_or(u32::MAX);
                if len > self.max_numeric_sequence_length {
                    self.max_numeric_sequence_length = len;
                }
            }
        }

        if visit.named && ids.function_definition.contains(kind) {
            // Tally every function-definition node so the const/string-return
            // shapes can be reported as a fraction of all functions, not a raw
            // count that simply grows with the file.
            self.function_count += 1;

            // Identity-proxy functions (`function(x){ return x }`): the return
            // must reference the *same* identifier as a parameter — a
            // backreference no regex can express, so check it here.
            if is_identity_function(node, source) {
                self.identity_fn_count += 1;
            }

            // String-return functions (`function(){ return "..." }`): a
            // function whose entire body is a single `return <string-literal>`.
            // Many of these in one file is the substitution-table obfuscation
            // shape (decoder functions that just hand back a fixed string).
            if is_string_return_function(node) {
                self.string_return_fn_count += 1;
            }

            // Constant-return padding functions (`function(){ return 0 }` /
            // `function(){ return "x" }` with no parameters): dead-code/opaque
            // padding. Parameterless distinguishes it from an identity proxy.
            if is_const_return_function(node) {
                self.const_return_fn_count += 1;
            }
        }

        // Infinite loops with a literally-true condition (`while true`,
        // `while (1)`, `for (;;)`). Node-scoped so a bare `while true` in prose
        // or a comment never matches.
        if ids.infinite_loop_candidate.contains(kind) && is_infinite_loop(node, source) {
            self.infinite_loop_count += 1;
        }

        // String concatenation chains: `a + b + c + ...` builds
        // left-leaning nested binary expressions in every grammar we
        // support. Measure the chain length once, at the *outermost* node
        // (the one whose parent isn't also a binary expression); the walk
        // still visits the inner links, which are not roots.
        if ids.binary_op.contains(kind)
            && op_node.is_some_and(|op| op.kind() == "+")
            && !visit
                .parent_kind_id
                .is_some_and(|parent| ids.binary_op.contains(parent))
        {
            let len = string_concat_chain_length(node, config);
            if len > self.max_string_concat_chain {
                self.max_string_concat_chain = len;
            }
        }
    }

    /// Record the static path of the chain rooted at `node`, at walk depth
    /// `depth`, and of each member/subscript prefix inside it.
    fn record_member_chain(
        &mut self,
        node: Node<'_>,
        source: &str,
        config: &LangConfig,
        depth: u32,
    ) {
        let mut path = String::new();
        let mut links = Vec::new();
        if chain_into(node, source, config, 0, 0, &mut path, Some(&mut links)).is_none() {
            return;
        }
        // Every prefix has fewer links than the full path.
        let depth_n = u32::try_from(path.matches('.').count()).unwrap_or(u32::MAX) + 1;
        if depth_n > self.max_member_chain_depth {
            self.max_member_chain_depth = depth_n;
        }
        for link in links {
            // The walk never reaches a link past the depth cap, so it gets no
            // member of its own.
            if depth + link.level >= MAX_AST_DEPTH {
                continue;
            }
            if link.level > 0 {
                self.resolved_links.insert(link.id);
            }
            // A path seen more than once keeps its first offset in source
            // order, whichever chain reached it first.
            let prefix = &path[..link.path_len];
            match self.members.get_mut(prefix) {
                Some(offset) => *offset = (*offset).min(link.offset),
                None => {
                    self.members.insert(prefix.to_string(), link.offset);
                }
            }
        }
    }

    /// `scratch` iterates the arguments, so no cursor is allocated per call.
    fn record_call<'t>(
        &mut self,
        node: Node<'t>,
        source: &str,
        config: &LangConfig,
        scratch: &mut TreeCursor<'t>,
    ) {
        let callee = config.callee(node).or_else(|| first_named_child(node));
        let args_node = config.argument_list(node);

        let target = callee.and_then(|c| static_dotted_chain(c, source, config, 0));
        // A Bash "command" whose name starts with `-` is an option word, not a
        // program, so it records no call.
        if config.lang == Lang::Bash && target.as_deref().is_some_and(|t| t.starts_with('-')) {
            return;
        }

        let mut args: Vec<Arg> = Vec::new();
        if config.lang == Lang::Zig {
            // Zig's call_expression grammar exposes the callee as a named
            // `function` field, but positional arguments are anonymous
            // expression children (there is no named `arguments` wrapper).
            // The first named child is the callee; the remaining named
            // children are the arguments in source order.
            let callee_start = callee.map(|c| c.start_byte());
            for arg in node.named_children(scratch) {
                if Some(arg.start_byte()) == callee_start {
                    continue;
                }
                args.push(build_arg(arg, source, config));
            }
        } else if config.arguments_field == "argument" {
            for arg in node.children_by_field_name(config.arguments_field, scratch) {
                args.push(build_arg(arg, source, config));
            }
        } else if let Some(args_root) = args_node {
            if config.is_single_argument(args_root) {
                args.push(build_arg(args_root, source, config));
            } else {
                for arg in args_root.named_children(scratch) {
                    if arg.kind() == "command_argument_sep" {
                        continue;
                    }
                    args.push(build_arg(arg, source, config));
                }
            }
        }

        self.calls.push(Symbol::Call {
            target,
            args,
            offset: Some(node.start_byte() as u64),
        });
    }

    fn record_assignment(&mut self, node: Node<'_>, source: &str, config: &LangConfig) {
        let Some(target_node) = assignment_target(node) else {
            return;
        };
        let Some(value_node) = assignment_value(node) else {
            return;
        };
        let Some(target) = static_dotted_chain(target_node, source, config, 0) else {
            return;
        };
        self.binds.push(Symbol::Bind {
            target,
            shape: arg_shape(value_node, config),
            offset: target_node.start_byte() as u64,
        });
    }
}

fn arg_shape(node: Node<'_>, config: &LangConfig) -> ArgShape {
    let k = node.kind();
    if config.string_kinds.contains(&k) {
        ArgShape::String
    } else if config.number_kinds.contains(&k) {
        ArgShape::Number
    } else if config.bool_kinds.contains(&k) {
        ArgShape::Bool
    } else if config.null_kinds.contains(&k) {
        ArgShape::Null
    } else if config.identifier_kinds.contains(&k) {
        ArgShape::Identifier
    } else if config.object_kinds.contains(&k) {
        ArgShape::Object
    } else if config.array_kinds.contains(&k) {
        ArgShape::Array
    } else if config.function_kinds.contains(&k) {
        ArgShape::Function
    } else if config.template_kinds.contains(&k) {
        ArgShape::Template
    } else if config.call_kinds.contains(&k) {
        ArgShape::Call
    } else {
        ArgShape::Expression
    }
}

/// Build an [`Arg`] for a single argument-position node, capturing the
/// literal value when the shape is a value-carrying kind (String,
/// Number, Identifier, Bool, Template).
///
/// Falls back to the shape-only [`Arg::Object`] / `Array` / `Function`
/// / `Call` / `Expression` variants when the argument has no
/// statically-recoverable value.
pub(super) fn build_arg(node: Node<'_>, source: &str, config: &LangConfig) -> Arg {
    // PHP (and a few other grammars) wrap each call argument in an `argument`
    // node whose child is the real expression, and PHP double-quoted strings
    // are `encapsed_string` wrapping a `string_content`. Without unwrapping,
    // every PHP arg would classify as `Expression` and its string/number value
    // would be lost — so `arg: { kind: string, ... }` rules could never match.
    // Descend through these wrappers to the inner value before shaping.
    let mut node = node;
    while node.kind() == "argument"
        || (config.lang == Lang::Rust && node.kind() == "reference_expression")
    {
        match first_named_child(node) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    // PHP double-quoted strings are `encapsed_string` (quoted, so `decode`
    // works) but aren't in `string_kinds`, so shape them as String directly.
    if node.kind() == "encapsed_string" {
        return match decode_string_literal(node, source, config) {
            Some(value) => Arg::String { value },
            None => Arg::Expression,
        };
    }
    match arg_shape(node, config) {
        ArgShape::String => match decode_string_literal(node, source, config) {
            Some(value) => Arg::String { value },
            None => Arg::Expression,
        },
        ArgShape::Number => match parse_numeric_literal_node(node, source) {
            Some((text, value, radix)) => Arg::Number { text, value, radix },
            None => Arg::Expression,
        },
        ArgShape::Identifier => match node.utf8_text(source.as_bytes()).ok() {
            Some(name) if !name.is_empty() => Arg::Identifier {
                name: name.to_string(),
            },
            _ => Arg::Expression,
        },
        ArgShape::Bool => Arg::Bool {
            value: matches!(
                node.utf8_text(source.as_bytes()).unwrap_or(""),
                "true" | "True" | "yes" | "on"
            ),
        },
        ArgShape::Template => Arg::Template {
            value: node
                .utf8_text(source.as_bytes())
                .map(str::to_string)
                .unwrap_or_default(),
        },
        ArgShape::Null => Arg::Null,
        ArgShape::Object => Arg::Object,
        ArgShape::Array => Arg::Array,
        ArgShape::Function => Arg::Function,
        ArgShape::Call => Arg::Call,
        ArgShape::Expression => Arg::Expression,
    }
}

/// Parse a numeric-literal node into `(source_text, value, radix)`.
/// Recognises `0x` / `0o` / `0b` prefixes; strips digit separators
/// and integer suffixes. Returns `None` for floats / unparseable.
fn parse_numeric_literal_node(node: Node<'_>, source: &str) -> Option<(String, i64, u32)> {
    let text = node.utf8_text(source.as_bytes()).ok()?.to_string();
    if text.contains('.') {
        return None;
    }
    let (rest, radix) = if let Some(s) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
    {
        (s, 16u32)
    } else if let Some(s) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        (s, 8u32)
    } else if let Some(s) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        (s, 2u32)
    } else {
        (text.as_str(), 10u32)
    };
    let cleaned: String = rest
        .chars()
        .take_while(|c| c.is_digit(radix) || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    let value = i64::from_str_radix(&cleaned, radix).ok()?;
    Some((text, value, radix))
}

/// Resolve a callee or member-access node into its static dotted path,
/// `a.b.c`. Returns `None` for any chain that contains a non-static
/// element (computed property, call result, parenthesised expression
/// other than the leftmost root, …).
///
/// **String-subscript normalisation:** `obj["constructor"]` and
/// `obj['constructor']` (computed access with a string-literal index)
/// fold into `obj.constructor` so member-chain rules catch the canonical
/// JS sandbox-escape pattern. Numeric or identifier indices stay
/// computed (returns `None` for that path) since their values aren't
/// statically resolvable to a property name.
pub(super) fn static_dotted_chain(
    node: Node<'_>,
    source: &str,
    config: &LangConfig,
    depth: u32,
) -> Option<String> {
    let mut path = String::new();
    chain_into(node, source, config, depth, 0, &mut path, None)?;
    Some(path)
}

/// A member or subscript node on the receiver side of a chain resolved by
/// [`chain_into`], `level` tree levels below the chain's root. Its own path
/// is the first `path_len` bytes of the root's.
struct ChainLink {
    id: usize,
    offset: u64,
    level: u32,
    path_len: usize,
}

/// [`static_dotted_chain`], appending the path to `path` and, when `links` is
/// given, reporting every member/subscript node it resolved on the way. On
/// `None`, `path` and `links` hold partial output.
fn chain_into(
    node: Node<'_>,
    source: &str,
    config: &LangConfig,
    depth: u32,
    level: u32,
    path: &mut String,
    mut links: Option<&mut Vec<ChainLink>>,
) -> Option<()> {
    // A member/subscript/call chain (`a.b.c…`, `obj["x"]["y"]…`, `f()()…`) is
    // a left-leaning tree as deep as it is long, and this function recurses
    // one frame per link. An adversarial chain thousands deep would overflow
    // the stack before the walk's own depth guard applies. Bail at the
    // shared cap and treat the chain as non-static (dynamic access) — the
    // conservative, no-symbol outcome.
    if depth >= MAX_AST_DEPTH {
        return None;
    }
    let text = || node.utf8_text(source.as_bytes()).ok();
    if config.lang == Lang::Rust && node.kind() == "scoped_identifier" {
        path.push_str(text()?);
        return Some(());
    }
    // Perl aliases both bareword callees and builtin names to `function`.
    // A leaf is a static name; non-leaf forms can dereference a code variable
    // (`&$callback`) and must remain unresolved rather than becoming symbols.
    if config.lang == Lang::Perl && node.kind() == "function" && node.named_child_count() == 0 {
        path.push_str(text()?);
        return Some(());
    }
    // A simple Perl scalar is a lexical receiver spelling, not a resolved
    // runtime type. Dereferences and computed variable names stay unknown.
    if config.lang == Lang::Perl && node.kind() == "scalar" {
        let name = node.named_child(0)?;
        if name.kind() == "varname" && name.named_child_count() == 0 {
            let value = name.utf8_text(source.as_bytes()).ok()?;
            if !value.is_empty()
                && value
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
            {
                path.push_str(text()?);
                return Some(());
            }
        }
        return None;
    }
    if config.identifier_kinds.contains(&node.kind()) {
        path.push_str(text()?);
        return Some(());
    }
    if config.member_kinds.contains(&node.kind()) {
        let object = node.child_by_field_name(config.member_object_field)?;
        let prop = node.child_by_field_name(config.member_property_field)?;
        // `$receiver->$method(...)` has a scalar child inside `method`;
        // unlike a bareword method, its name is chosen at runtime.
        if config.lang == Lang::Perl && prop.named_child_count() != 0 {
            return None;
        }
        chain_into(
            object,
            source,
            config,
            depth + 1,
            level + 1,
            path,
            links.as_deref_mut(),
        )?;
        let prop_text = prop.utf8_text(source.as_bytes()).ok()?;
        if prop_text.is_empty() {
            return None;
        }
        path.push('.');
        path.push_str(prop_text);
        push_link(links, node, level, path);
        return Some(());
    }
    if is_subscript_kind(node.kind()) {
        let (path_len, links_len) = (path.len(), links.as_ref().map_or(0, |l| l.len()));
        if fold_string_subscript_into(
            node,
            source,
            config,
            depth + 1,
            level,
            path,
            links.as_deref_mut(),
        )
        .is_some()
        {
            push_link(links, node, level, path);
            return Some(());
        }
        path.truncate(path_len);
        if let Some(links) = links.as_deref_mut() {
            links.truncate(links_len);
        }
    }
    // A call in receiver position contributes the name of what it called, and
    // nothing else: `open(p).read()` is `open.read`.
    //
    // This used to append `()`, which read as "a call happened here" but was
    // really positional — the outermost call is named by `record_call` from
    // its callee and never got parens, so `platform.system()` was
    // `platform.system` while `open(p).read()` was `open().read`. One call,
    // two spellings, depending on where it sat. Rule authors reasonably wrote
    // `.system()` and matched nothing.
    //
    // Without the parens a symbol is one thing everywhere: a dotted path of
    // identifiers, the same shape a stripped binary's symbol table yields.
    if config.call_kinds.contains(&node.kind()) {
        let callee = node
            .child_by_field_name(config.callee_field)
            .or_else(|| first_named_child(node))?;
        return chain_into(callee, source, config, depth + 1, level + 1, path, links);
    }
    // Constructor type names: Java `type_identifier` / `scoped_type_identifier`
    // (`new ProcessBuilder()`, `new java.io.File()`) and similar type-name
    // nodes aren't in `identifier_kinds`, so a `new X()` callee resolved here
    // would otherwise drop to `None`. The node text is already the
    // (possibly dotted) type name, so emit it directly — this is what makes
    // `new ProcessBuilder(...)` a `kind: call` fact with target `ProcessBuilder`.
    if node.kind().ends_with("type_identifier") || node.kind() == "qualified_name" {
        // `qualified_name` covers C# `new System.Random()` — its text is the
        // already-dotted type name. Together with the `type_identifier` arm
        // this resolves constructor callees that aren't bare identifiers.
        path.push_str(text().filter(|s| !s.is_empty())?);
        return Some(());
    }
    None
}

fn push_link(links: Option<&mut Vec<ChainLink>>, node: Node<'_>, level: u32, path: &str) {
    if let Some(links) = links {
        links.push(ChainLink {
            id: node.id(),
            offset: node.start_byte() as u64,
            level,
            path_len: path.len(),
        });
    }
}

/// Tree-sitter node kinds for subscript / index access across our
/// grammars. Generic enough to avoid per-language config: every
/// supported source language uses one of these stem names for
/// `obj[idx]`-style access.
#[inline]
fn is_subscript_kind(kind: &str) -> bool {
    SUBSCRIPT_KINDS.contains(&kind)
}

/// The kinds [`is_subscript_kind`] accepts.
pub(super) const SUBSCRIPT_KINDS: &[&str] = &[
    "subscript_expression",
    "subscript",
    "index_expression",
    "element_access_expression",
];

/// Fold `obj["constructor"]` → `obj.constructor` when the subscript
/// index is a string literal. The canonical JS sandbox-escape pattern
/// (`obj["constructor"]["constructor"]("...")()`) becomes a normal
/// member chain so trait authors can match it with `type: member,
/// path: …` rules instead of reaching for a tree-sitter escape hatch.
///
/// Returns `None` for non-literal indices (variable, expression,
/// numeric) — those genuinely are dynamic accesses.
fn fold_string_subscript_into(
    node: Node<'_>,
    source: &str,
    config: &LangConfig,
    depth: u32,
    level: u32,
    path: &mut String,
    links: Option<&mut Vec<ChainLink>>,
) -> Option<()> {
    // Mutually recursive with `chain_into` for nested subscripts
    // (`obj["x"]["y"]…`); share its depth budget so the pair can't outrun the
    // cap between them.
    if depth >= MAX_AST_DEPTH {
        return None;
    }
    // First named child is the object; second is the index expression.
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    let object = children.next()?;
    let index = children.next()?;
    if !config.string_kinds.contains(&index.kind()) {
        return None;
    }
    chain_into(object, source, config, depth + 1, level + 1, path, links)?;
    let prop = decode_string_literal(index, source, config)?;
    // Conservative: only fold string indices whose content looks like
    // an identifier (alphanumeric + underscore, no leading digit).
    // Skips `"foo bar"` or `"123"` that wouldn't be valid as dotted
    // property access in any language we care about.
    let mut chars = prop.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return None,
    }
    if !chars.all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    path.push('.');
    path.push_str(&prop);
    Some(())
}

/// Node kinds that bind a value to a target, recorded as `Symbol::Bind`.
pub(super) const ASSIGNMENT_KINDS: &[&str] = &[
    "assignment",
    "let_declaration",
    "assignment_expression",
    "augmented_assignment",
    "assignment_statement",
    "variable_declarator",
    "variable_assignment",
    "operator_assignment",
    "global_variable",
];

fn assignment_target(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| node.child_by_field_name("variable"))
}

fn assignment_value(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child(0)
}

fn string_concat_chain_length(node: Node<'_>, config: &LangConfig) -> u32 {
    // Count leaves under a nested `+` chain. The chain looks like
    // `(a + b) + c + d` → BinaryExpr(BinaryExpr(BinaryExpr(a, b), c), d).
    fn descend(node: Node<'_>, config: &LangConfig, acc: &mut u32, depth: u32) {
        // A `+` chain of N terms nests N deep; stop at the shared cap so a
        // pathological `a+b+c+…` (thousands of terms) can't overflow the stack
        // before the walk's depth guard applies. The length saturates, which is
        // all `ast.max_concat_chain` needs.
        if depth >= MAX_AST_DEPTH {
            return;
        }
        if config.binary_op_kinds.contains(&node.kind()) {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                descend(child, config, acc, depth + 1);
            }
        } else {
            *acc += 1;
        }
    }
    let mut acc = 0;
    descend(node, config, &mut acc, 0);
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk_state(path: &str, src: &str) -> State {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(src.as_bytes());
        let ast = parsed.source_ast().expect("parsed source");
        let config = super::super::langs::config_for(ast.file_type).expect("language config");
        let mut collectors = visit::Collectors {
            ast: Some(State::default()),
            ..visit::Collectors::default()
        };
        visit::walk(ast.tree.root_node(), ast.source, config, &mut collectors);
        collectors.ast.expect("ast collector")
    }

    /// `function_count` is the denominator of the const/string-return ratios,
    /// so every kind the shape detectors accept must be counted, Rust `fn`
    /// items included.
    #[test]
    fn rust_fn_items_count_toward_the_function_total() {
        let state = walk_state(
            "lib.rs",
            "fn a() {}\nfn b() -> u8 { 1 }\nimpl X { fn c(&self) {} }\n",
        );
        assert_eq!(state.function_count, 3);
    }

    /// Python lambdas are counted as functions (once each, not again for the
    /// `lambda` keyword), so the shape detectors must see them too.
    /// `lambda: 0` has no parameter list at all.
    #[test]
    fn python_lambdas_take_constant_and_string_return_shapes() {
        let state = walk_state(
            "shapes.py",
            "a = lambda: 0\nb = lambda: None\nc = lambda x: 0\nd = lambda: 'x'\ne = lambda x: x\n",
        );
        assert_eq!(state.function_count, 5);
        assert_eq!(state.const_return_fn_count, 3);
        assert_eq!(state.string_return_fn_count, 1);
        assert_eq!(state.identity_fn_count, 1);
        // A JavaScript arrow's lone parameter sits outside `parameters`.
        assert_eq!(walk_state("a.js", "f = x => 0;\n").const_return_fn_count, 0);
    }
}
