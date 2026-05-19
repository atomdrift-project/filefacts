//! AST projection view.
//!
//! `Ast` is a curated set of projections of a parsed source-code AST.
//! It is *not* a serialised AST — projections are chosen because they
//! answer the forensically relevant questions about a program
//! (*what does it call, what does it touch, what literals does it
//! feed those calls?*) cheaply and uniformly across languages.
//!
//! `Ast` carries **facts**, not interpretations. Complexity, depth,
//! and counts are numeric features and live in [`crate::Metrics`];
//! "is this obfuscated" judgments live in downstream rule engines.

use serde::Serialize;

/// One observed call site in source order.
///
/// `target` is the dotted-static path resolved from the call's callee
/// chain — `"fetch"`, `"chrome.cookies.getAll"`. It is `None` when the
/// callee is computed (`obj[varName]()`, an anonymous function call,
/// a method on a call result, …). The `None` case is itself a signal
/// worth distinguishing from "no calls".
///
/// `args` describes the *shape* of each argument, not its value.
/// Literal-string arguments have their value carried separately in
/// [`Ast::call_string_args`] so consumers can match on it without
/// re-walking the AST.
#[derive(Debug, Clone, Serialize)]
pub struct Call {
    /// Static dotted path to the function being called, or `None` for
    /// dynamic targets.
    pub target: Option<String>,
    /// Argument shapes, in call order.
    pub args: Vec<ArgShape>,
}

/// Shape category for a call argument.
///
/// The set is closed and intentionally small — distinguishing "what
/// kind of thing is this argument" is enough to support every trait
/// query that doesn't need the literal value, and the literal-value
/// case is served by [`Ast::call_string_args`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ArgShape {
    /// String literal (after un-quoting).
    String,
    /// Numeric literal.
    Number,
    /// Boolean literal.
    Bool,
    /// Null / nil / None literal.
    Null,
    /// Bare identifier reference.
    Identifier,
    /// Object / map / dict / struct literal.
    Object,
    /// Array / list / slice literal.
    Array,
    /// Function / lambda / closure literal (anonymous callable).
    Function,
    /// Template / formatted / interpolated string.
    Template,
    /// Result of another call expression.
    Call,
    /// Any expression that doesn't fit one of the above.
    Expression,
}

/// AST projection view.
///
/// Empty when the file is not source code expose can parse. For
/// supported source files, the view is populated by a single walk of
/// the tree-sitter tree; the same tree backs the `values`/`strings`
/// extraction for source files, so no duplicate work is performed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Ast {
    /// Every call site in source order. Preserves multiplicity (a
    /// function called twice appears twice) so the array is faithful
    /// to the source's structure.
    pub calls: Vec<Call>,

    /// Sorted, deduplicated list of every static call target. The
    /// natural index for "did this file ever call X?" queries.
    pub call_targets: Vec<String>,

    /// Sorted, deduplicated list of every dotted member-access chain
    /// observed *in any position*, called or not. `window.localStorage`
    /// appears here whether the code reads it, writes it, or just
    /// passes it as a value.
    pub member_chains: Vec<String>,

    /// Map of call target → string-literal arguments observed at any
    /// argument position across all call sites with that target.
    /// Targets with no string-literal arguments do not appear in the
    /// map.
    pub call_string_args: std::collections::BTreeMap<String, Vec<String>>,
}

impl Ast {
    /// Construct an empty `Ast` view.
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when the view contains no calls, member chains, or
    /// literal-argument observations.
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
            && self.call_targets.is_empty()
            && self.member_chains.is_empty()
            && self.call_string_args.is_empty()
    }
}
