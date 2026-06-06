//! Single-pass tree-sitter walker that emits unified [`Symbol`] facts.
//!
//! Walks the entire tree once and pushes, in source order:
//!
//! - one [`Symbol::Call`] per call site,
//! - one [`Symbol::Bind`] per static assignment,
//! - one [`Symbol::Member`] per unique dotted member-access chain.
//!
//! Numeric tally features are written into the caller's [`Metrics`]
//! map as `ast.*` keys. Counts and depths live there, not on the
//! symbol records.
//!
//! The walker is language-driven by the [`LangConfig`] passed in; it
//! contains no language-specific code itself.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use crate::output::{Arg, ArgShape, Metrics, Symbol, Symbols};

use super::langs::LangConfig;

/// Hard cap on AST recursion depth.
///
/// tree-sitter trees can be arbitrarily deep on generated or adversarial
/// source (thousands of nested brackets, binary expressions, etc.).
/// `walk_node` recurses one stack frame per level, so an unbounded walk
/// overflows the worker thread's stack and aborts the whole process. We
/// stop descending here instead. Real source is rarely more than a few
/// dozen levels deep; anything past this is machine-generated and yields no
/// useful symbols. `ast.max_depth` saturates at this value, which is itself
/// a usable "pathologically nested" signal.
pub(super) const MAX_AST_DEPTH: u32 = 1000;

pub(super) fn walk(
    root: Node<'_>,
    source: &str,
    config: &LangConfig,
    symbols_out: &mut Symbols,
    metrics: &mut Metrics,
) {
    let mut state = State::default();
    state.walk_node(root, source, config, 0);

    // Drain the per-symbol-kind buffers into the unified Symbols view.
    let call_count = state.calls.len() as u64;
    let bind_count = state.binds.len() as u64;
    let member_count = state.members.len() as u64;
    for c in state.calls {
        symbols_out.push(c);
    }
    for b in state.binds {
        symbols_out.push(b);
    }
    for chain in state.members {
        symbols_out.push(Symbol::Member { path: chain });
    }
    let identifier_count = state.identifiers.len() as u64;
    for (name, offset) in state.identifiers {
        symbols_out.push(Symbol::Identifier {
            name,
            offset: Some(offset),
        });
    }

    metrics.insert("ast.node_count", state.node_count as f64);
    metrics.insert("ast.max_depth", f64::from(state.max_depth));
    metrics.insert("ast.call_count", call_count as f64);
    if state.max_member_chain_depth > 0 {
        metrics.insert(
            "ast.member_depth_max",
            f64::from(state.max_member_chain_depth),
        );
    }
    if state.max_string_concat_chain > 1 {
        metrics.insert(
            "ast.string_concat_chain_max_length",
            f64::from(state.max_string_concat_chain),
        );
    }
    if state.max_array_literal_length > 0 {
        metrics.insert(
            "ast.array_literal_max_length",
            f64::from(state.max_array_literal_length),
        );
    }
    if state.max_numeric_array_length > 0 {
        metrics.insert(
            "ast.numeric_array_max_length",
            f64::from(state.max_numeric_array_length),
        );
    }
    if bind_count > 0 {
        metrics.insert("ast.bind_count", bind_count as f64);
    }
    if member_count > 0 {
        metrics.insert("ast.member_count", member_count as f64);
    }
    if identifier_count > 0 {
        metrics.insert("ast.identifier_count", identifier_count as f64);
    }
    // Per-operator counts: `ast.op.<name>` (e.g. `ast.op.xor`). Raw integer
    // counts keyed by the canonical operator name; matched O(1) via
    // `type: metrics, field: 'ast.op.xor', min: N`.
    for (op, count) in &state.op_counts {
        metrics.insert(format!("ast.op.{op}"), f64::from(*count));
    }
    // Per-operator density: `ast.op_density.<name>` = count / node_count. A
    // scale-invariant signal that an operator dominates the parse tree
    // (e.g. an obfuscated array packed with `number - number` subtractions),
    // independent of file size — unlike the raw count, which simply grows
    // with the file. Emitted only when there is a node to divide by.
    if state.node_count > 0 {
        let nodes = state.node_count as f64;
        for (op, count) in &state.op_counts {
            metrics.insert(format!("ast.op_density.{op}"), f64::from(*count) / nodes);
        }
    }
    // `ast.sequence_count` follows the node-kind-count convention (cf.
    // `ast.member_count` from `member_expression`).
    if state.sequence_expr_count > 0 {
        metrics.insert(
            "ast.sequence_count".to_string(),
            f64::from(state.sequence_expr_count),
        );
    }
    if state.identity_fn_count > 0 {
        metrics.insert(
            "ast.identity_function_count".to_string(),
            f64::from(state.identity_fn_count),
        );
    }
    if state.string_return_fn_count > 0 {
        metrics.insert(
            "ast.string_return_function_count".to_string(),
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
            "ast.string_return_function_ratio".to_string(),
            f64::from(state.string_return_fn_count) / f64::from(state.function_count),
        );
    }
    if state.xor_mod_loop_count > 0 {
        metrics.insert(
            "ast.xor_mod_loop_count".to_string(),
            f64::from(state.xor_mod_loop_count),
        );
    }
    if state.max_numeric_sequence_length > 0 {
        metrics.insert(
            "ast.numeric_sequence_max_length".to_string(),
            f64::from(state.max_numeric_sequence_length),
        );
    }
    if state.const_return_fn_count > 0 {
        metrics.insert(
            "ast.const_return_function_count".to_string(),
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
            "ast.const_return_function_ratio".to_string(),
            f64::from(state.const_return_fn_count) / f64::from(state.function_count),
        );
    }
    if state.self_compare_count > 0 {
        metrics.insert(
            "ast.self_compare_count".to_string(),
            f64::from(state.self_compare_count),
        );
    }
    if state.infinite_loop_count > 0 {
        metrics.insert(
            "ast.infinite_loop_count".to_string(),
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

/// True when `node` is a function whose entire body is `return <ident>` and
/// `<ident>` names one of the function's own parameters — the identity-proxy
/// obfuscation shape (`function(x){ return x }`, `lambda x: x`). The
/// param↔return backreference is why a regex can't express this.
fn is_identity_function(node: Node<'_>, source: &str) -> bool {
    if !matches!(
        node.kind(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "function_definition"
            | "lambda"
            | "method_definition"
    ) {
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

/// The single identifier returned by a function body, if the body is exactly
/// one `return <identifier>` (JS `{ return x }` / arrow `x` / Python `return x`).
fn returned_identifier<'a>(body: Node<'_>, bytes: &'a [u8]) -> Option<&'a str> {
    // Arrow-function expression body: the body *is* the identifier.
    if body.kind() == "identifier" {
        return body.utf8_text(bytes).ok();
    }
    // Block body: find a lone return_statement with an identifier argument.
    let mut cur = body.walk();
    let mut ret_id = None;
    let mut stmt_count = 0u32;
    for child in body.named_children(&mut cur) {
        if child.kind() == "comment" {
            continue;
        }
        stmt_count += 1;
        if child.kind() == "return_statement" {
            let mut rcur = child.walk();
            if let Some(arg) = child.named_children(&mut rcur).next() {
                if arg.kind() == "identifier" {
                    ret_id = arg.utf8_text(bytes).ok();
                }
            }
        }
    }
    if stmt_count == 1 { ret_id } else { None }
}

/// True when `node` is a function whose entire body is a single
/// `return <string-literal>` (or an arrow whose expression body is a string).
/// The substitution-table obfuscation shape — decoder functions that just
/// return a fixed string — replaces tree-sitter `(function_declaration body:
/// (statement_block (return_statement (string))))` queries.
fn is_string_return_function(node: Node<'_>, source: &str) -> bool {
    if !matches!(
        node.kind(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "function_definition"
            | "method_definition"
    ) {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    // Arrow expression body: the body *is* the string.
    if is_static_string_literal(body) {
        return true;
    }
    // Block body: a lone return_statement whose argument is a string literal.
    let _ = source;
    let mut cur = body.walk();
    let mut stmt_count = 0u32;
    let mut returns_string = false;
    for child in body.named_children(&mut cur) {
        if child.kind() == "comment" {
            continue;
        }
        stmt_count += 1;
        if child.kind() == "return_statement" {
            let mut rcur = child.walk();
            if let Some(arg) = child.named_children(&mut rcur).next() {
                if is_static_string_literal(arg) {
                    returns_string = true;
                }
            }
        }
    }
    stmt_count == 1 && returns_string
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
fn is_const_return_function(node: Node<'_>, source: &str) -> bool {
    if !matches!(
        node.kind(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "function_definition"
            | "method_definition"
    ) {
        return false;
    }
    let _ = source;
    // Parameterless: a `parameters`/`formal_parameters` node with no named children.
    let Some(params) = node.child_by_field_name("parameters") else {
        return false;
    };
    if params.named_child_count() != 0 {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    // Arrow expression body: the body *is* the literal/identifier.
    if is_literal_or_identifier(body) {
        return true;
    }
    // Block body: a lone return_statement whose argument is a literal/identifier.
    let mut cur = body.walk();
    let mut stmt_count = 0u32;
    let mut const_return = false;
    for child in body.named_children(&mut cur) {
        if child.kind() == "comment" {
            continue;
        }
        stmt_count += 1;
        if child.kind() == "return_statement" {
            let mut rcur = child.walk();
            if let Some(arg) = child.named_children(&mut rcur).next() {
                if is_literal_or_identifier(arg) {
                    const_return = true;
                }
            }
        }
    }
    stmt_count == 1 && const_return
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

#[derive(Default)]
struct State {
    calls: Vec<Symbol>,
    binds: Vec<Symbol>,
    members: BTreeSet<String>,
    /// Dedup'd bare-identifier names with first-seen byte offset.
    /// Captures every identifier-kind token across the file — variable
    /// references, parameter names, type names, function-call targets,
    /// etc. — so naming-pattern rules (`c2_server`, `BackdoorListener`,
    /// `xmrig`) can fire via `type: name, kind: identifier`.
    identifiers: BTreeMap<String, u64>,
    /// Every operator occurrence (`^`, `%`, `<<=`, …) with its byte offset,
    /// in source order. Emitted as [`Symbol::Op`] so density rules can count
    /// Per-operator occurrence counts keyed by canonical name (`xor` → 12,
    /// `mod` → 3, …), tallied during the single existing walk. Emitted as
    /// `ast.op.<name>` metrics so density rules match O(1) via `type: metrics`
    /// with no per-occurrence facts — the lowest-overhead operator-density form.
    op_counts: BTreeMap<String, u32>,
    node_count: u64,
    max_depth: u32,
    max_member_chain_depth: u32,
    max_string_concat_chain: u32,
    max_array_literal_length: u32,
    /// Max length of an all-numeric-literal array (`ast.numeric_array_max_length`).
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
    /// (`(1, 2, 3)`) — comma-constant obfuscation (`ast.numeric_sequence_max_length`).
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
    fn walk_node(&mut self, node: Node<'_>, source: &str, config: &LangConfig, depth: u32) {
        self.node_count += 1;
        if depth > self.max_depth {
            self.max_depth = depth;
        }
        // Stop before a pathologically deep tree overflows the stack.
        if depth >= MAX_AST_DEPTH {
            return;
        }


        // Member chains we treat as a property of the *outermost* member
        // expression in a chain — descending into nested member nodes
        // would duplicate the chain prefix. Subscript-with-string-index
        // (`obj["constructor"]`) folds into the same path via
        // `static_dotted_chain`'s normalisation, so a JS sandbox-escape
        // pattern like `obj["constructor"]["constructor"]("...")` lands
        // as a member chain instead of dropping out as a dynamic access.
        if config.member_kinds.contains(&node.kind()) || is_subscript_kind(node.kind()) {
            if let Some(chain) = static_dotted_chain(node, source, config) {
                let depth_n = u32::try_from(chain.matches('.').count()).unwrap_or(u32::MAX) + 1;
                if depth_n > self.max_member_chain_depth {
                    self.max_member_chain_depth = depth_n;
                }
                self.members.insert(chain);
            }
            // Continue walking children so we still find string
            // literals, call expressions, etc. inside member chains.
        }

        if config.call_kinds.contains(&node.kind()) {
            self.record_call(node, source, config);
        }

        if is_assignment_kind(node.kind()) {
            self.record_assignment(node, source, config);
        }

        if config.array_kinds.contains(&node.kind()) {
            let len = u32::try_from(node.named_child_count()).unwrap_or(u32::MAX);
            if len > self.max_array_literal_length {
                self.max_array_literal_length = len;
            }
            // Numeric-array length: arrays whose elements are *all* numeric
            // literals — the byte-packing obfuscation shape (`[112,97,121,...]`),
            // distinct from a generic long array of mixed/string data. Lets
            // `ast.numeric_array_max_length` keep that specificity that a plain
            // array-length metric would lose.
            if len >= 2 {
                let mut cur = node.walk();
                let all_numeric = node
                    .named_children(&mut cur)
                    .all(|c| config.number_kinds.contains(&c.kind()));
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
        if config.identifier_kinds.contains(&node.kind()) && node.named_child_count() == 0 {
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
        if let Some(op_node) = node.child_by_field_name("operator") {
            if let Ok(op) = op_node.utf8_text(source.as_bytes()) {
                if let Some(name) = canonical_op(op) {
                    *self.op_counts.entry(name.to_string()).or_insert(0) += 1;
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
                    if let (Some(l), Some(r)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
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
        if node.kind() == "sequence_expression" {
            self.sequence_expr_count += 1;
            // All-numeric comma sequence (`(1, 2, 3, …)`) — comma-constant
            // obfuscation. Mirror the numeric-array shape: count the numeric
            // members when every member is a numeric literal.
            let mut cur = node.walk();
            let members: Vec<Node<'_>> = node.named_children(&mut cur).collect();
            if members.len() >= 2
                && members
                    .iter()
                    .all(|c| config.number_kinds.contains(&c.kind()))
            {
                let len = u32::try_from(members.len()).unwrap_or(u32::MAX);
                if len > self.max_numeric_sequence_length {
                    self.max_numeric_sequence_length = len;
                }
            }
        }

        // Tally every function-definition node so the const/string-return
        // shapes can be reported as a fraction of all functions, not a raw
        // count that simply grows with the file.
        if matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "function_definition"
                | "lambda"
                | "method_definition"
        ) {
            self.function_count += 1;
        }

        // Identity-proxy functions (`function(x){ return x }`): the return
        // must reference the *same* identifier as a parameter — a
        // backreference no regex can express, so check it here.
        if is_identity_function(node, source) {
            self.identity_fn_count += 1;
        }

        // String-return functions (`function(){ return "..." }`): a function
        // whose entire body is a single `return <string-literal>`. Many of
        // these in one file is the substitution-table obfuscation shape
        // (decoder functions that just hand back a fixed string).
        if is_string_return_function(node, source) {
            self.string_return_fn_count += 1;
        }

        // Constant-return padding functions (`function(){ return 0 }` /
        // `function(){ return "x" }` with no parameters): dead-code/opaque
        // padding. Parameterless distinguishes it from an identity proxy.
        if is_const_return_function(node, source) {
            self.const_return_fn_count += 1;
        }

        // Infinite loops with a literally-true condition (`while true`,
        // `while (1)`, `for (;;)`). Node-scoped so a bare `while true` in prose
        // or a comment never matches.
        if is_infinite_loop(node, source) {
            self.infinite_loop_count += 1;
        }

        // String concatenation chains: `a + b + c + ...` builds
        // left-leaning nested binary expressions in every grammar we
        // support. Measure the chain length when we hit the *outermost*
        // node (the one whose parent isn't also a `+` binary
        // expression), then skip recursion into the chain.
        if is_string_concat_root(node, config) {
            let len = string_concat_chain_length(node, config);
            if len > self.max_string_concat_chain {
                self.max_string_concat_chain = len;
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_node(child, source, config, depth + 1);
        }

    }

    fn record_call(&mut self, node: Node<'_>, source: &str, config: &LangConfig) {
        let callee = node
            .child_by_field_name(config.callee_field)
            .or_else(|| first_named_child(node));
        let args_node = node.child_by_field_name(config.arguments_field);

        let target = callee.and_then(|c| static_dotted_chain(c, source, config));
        if config.name == "bash" && target.as_deref().is_some_and(|t| t.starts_with('-')) {
            return;
        }

        let mut args: Vec<Arg> = Vec::new();
        if config.arguments_field == "argument" {
            let mut cursor = node.walk();
            for arg in node.children_by_field_name(config.arguments_field, &mut cursor) {
                args.push(build_arg(arg, source, config));
            }
        } else if let Some(args_root) = args_node {
            let mut cursor = args_root.walk();
            for arg in args_root.named_children(&mut cursor) {
                if arg.kind() == "command_argument_sep" {
                    continue;
                }
                args.push(build_arg(arg, source, config));
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
        let Some(target) = static_dotted_chain(target_node, source, config) else {
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
fn build_arg(node: Node<'_>, source: &str, config: &LangConfig) -> Arg {
    // PHP (and a few other grammars) wrap each call argument in an `argument`
    // node whose child is the real expression, and PHP double-quoted strings
    // are `encapsed_string` wrapping a `string_content`. Without unwrapping,
    // every PHP arg would classify as `Expression` and its string/number value
    // would be lost — so `arg: { kind: string, ... }` rules could never match.
    // Descend through these wrappers to the inner value before shaping.
    let mut node = node;
    while node.kind() == "argument" {
        match first_named_child(node) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    // PHP double-quoted strings are `encapsed_string` (quoted, so `decode`
    // works) but aren't in `string_kinds`, so shape them as String directly.
    if node.kind() == "encapsed_string" {
        return match decode_string_literal(node, source) {
            Some(value) => Arg::String { value },
            None => Arg::Expression,
        };
    }
    match arg_shape(node, config) {
        ArgShape::String => match decode_string_literal(node, source) {
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
fn static_dotted_chain(node: Node<'_>, source: &str, config: &LangConfig) -> Option<String> {
    if config.identifier_kinds.contains(&node.kind()) {
        return node.utf8_text(source.as_bytes()).ok().map(str::to_string);
    }
    if config.member_kinds.contains(&node.kind()) {
        let object = node.child_by_field_name(config.member_object_field)?;
        let prop = node.child_by_field_name(config.member_property_field)?;
        let object_path = static_dotted_chain(object, source, config)?;
        let prop_text = prop.utf8_text(source.as_bytes()).ok()?;
        if prop_text.is_empty() {
            return None;
        }
        return Some(format!("{object_path}.{prop_text}"));
    }
    if is_subscript_kind(node.kind()) {
        if let Some(folded) = try_fold_string_subscript(node, source, config) {
            return Some(folded);
        }
    }
    if config.call_kinds.contains(&node.kind()) {
        let callee = node
            .child_by_field_name(config.callee_field)
            .or_else(|| first_named_child(node))?;
        let target = static_dotted_chain(callee, source, config)?;
        return Some(format!("{target}()"));
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
        return node
            .utf8_text(source.as_bytes())
            .ok()
            .map(str::to_string)
            .filter(|s| !s.is_empty());
    }
    None
}

/// Tree-sitter node kinds for subscript / index access across our
/// grammars. Generic enough to avoid per-language config: every
/// supported source language uses one of these stem names for
/// `obj[idx]`-style access.
#[inline]
fn is_subscript_kind(kind: &str) -> bool {
    kind == "subscript_expression"
        || kind == "subscript"
        || kind == "index_expression"
        || kind == "element_access_expression"
}

/// Fold `obj["constructor"]` → `obj.constructor` when the subscript
/// index is a string literal. The canonical JS sandbox-escape pattern
/// (`obj["constructor"]["constructor"]("...")()`) becomes a normal
/// member chain so trait authors can match it with `type: member,
/// path: …` rules instead of reaching for a tree-sitter escape hatch.
///
/// Returns `None` for non-literal indices (variable, expression,
/// numeric) — those genuinely are dynamic accesses.
fn try_fold_string_subscript(node: Node<'_>, source: &str, config: &LangConfig) -> Option<String> {
    // First named child is the object; second is the index expression.
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    let object = children.next()?;
    let index = children.next()?;
    if !config.string_kinds.contains(&index.kind()) {
        return None;
    }
    let object_path = static_dotted_chain(object, source, config)?;
    let prop = decode_string_literal(index, source)?;
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
    Some(format!("{object_path}.{prop}"))
}

fn decode_string_literal(node: Node<'_>, source: &str) -> Option<String> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    let bytes = raw.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let open = bytes[0];
    if !matches!(open, b'"' | b'\'' | b'`') || bytes[bytes.len() - 1] != open {
        return None;
    }
    std::str::from_utf8(&bytes[1..bytes.len() - 1])
        .ok()
        .map(str::to_string)
}

fn is_assignment_kind(kind: &str) -> bool {
    matches!(
        kind,
        "assignment"
            | "assignment_expression"
            | "augmented_assignment"
            | "assignment_statement"
            | "variable_declarator"
            | "variable_assignment"
            | "operator_assignment"
            | "global_variable"
    )
}

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
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn is_string_concat_root(node: Node<'_>, config: &LangConfig) -> bool {
    if !config.binary_op_kinds.contains(&node.kind()) {
        return false;
    }
    let op_text = node
        .child_by_field_name("operator")
        .and_then(NodeOpExt::utf8_text_lossy_static)
        .unwrap_or("");
    if op_text != "+" {
        return false;
    }
    // Root only if the parent isn't also a `+` binary expression
    // (otherwise we'd record the chain at every level).
    !matches!(
        node.parent(),
        Some(p) if config.binary_op_kinds.contains(&p.kind())
    )
}

fn string_concat_chain_length(node: Node<'_>, config: &LangConfig) -> u32 {
    // Count leaves under a nested `+` chain. The chain looks like
    // `(a + b) + c + d` → BinaryExpr(BinaryExpr(BinaryExpr(a, b), c), d).
    fn descend(node: Node<'_>, config: &LangConfig, acc: &mut u32) {
        if config.binary_op_kinds.contains(&node.kind()) {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                descend(child, config, acc);
            }
        } else {
            *acc += 1;
        }
    }
    let mut acc = 0;
    descend(node, config, &mut acc);
    acc
}

/// Helper trait for nodes that lets us pull the operator text without
/// importing tree-sitter throughout this module.
trait NodeOpExt {
    fn utf8_text_lossy_static(self) -> Option<&'static str>;
}

impl NodeOpExt for Node<'_> {
    fn utf8_text_lossy_static(self) -> Option<&'static str> {
        // The `operator` field on binary-expression nodes is an
        // anonymous node whose kind name *is* the operator string in
        // every grammar we use. `kind()` returns a `&'static str`.
        Some(self.kind())
    }
}
