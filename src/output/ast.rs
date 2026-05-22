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
/// [`Ast::call_strings`] so consumers can match on it without
/// re-walking the AST.
#[derive(Debug, Clone, Serialize)]
pub struct Call {
    /// Static dotted path to the function being called, or `None` for
    /// dynamic targets.
    pub target: Option<String>,
    /// Argument shapes, in call order.
    pub args: Vec<ArgShape>,
}

/// One static assignment/binding observed in source code.
///
/// The projection is intentionally shallow: it records the assigned
/// target, coarse value shape, lexical scope, and direct string literal
/// value when there is one. It does not attempt constant propagation or
/// language-specific type inference.
#[derive(Debug, Clone, Serialize)]
pub struct Assignment {
    /// Static identifier/member path being assigned, such as
    /// `API_URL`, `self.path`, or `exports.token`.
    pub target: String,
    /// Coarse lexical scope for the assignment: `module`, `class`, or
    /// `function`.
    pub scope: &'static str,
    /// Shape of the assigned expression.
    pub shape: ArgShape,
    /// Direct string literal value when the right-hand side is a
    /// literal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
    /// Byte offset where the assignment target starts.
    pub offset: u64,
}

/// Shape category for a call argument.
///
/// The set is closed and intentionally small — distinguishing "what
/// kind of thing is this argument" is enough to support every trait
/// query that doesn't need the literal value, and the literal-value
/// case is served by [`Ast::call_strings`].
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
/// Empty when the file is not source code filefacts can parse. For
/// supported source files, the view is populated by a single walk of
/// the tree-sitter tree; the same parse backs all source-driven views,
/// so no duplicate work is performed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Ast {
    /// Every call site in source order. Preserves multiplicity (a
    /// function called twice appears twice) so the array is faithful
    /// to the source's structure.
    pub calls: Vec<Call>,

    /// Sorted, deduplicated list of every static call target. The
    /// natural index for "did this file ever call X?" queries.
    pub targets: Vec<String>,

    /// Sorted, deduplicated list of every dotted member-access chain
    /// observed *in any position*, called or not. `window.localStorage`
    /// appears here whether the code reads it, writes it, or just
    /// passes it as a value.
    pub members: Vec<String>,

    /// Map of call target → string-literal arguments observed at any
    /// argument position across all call sites with that target.
    /// Targets with no string-literal arguments do not appear in the
    /// map.
    pub call_strings: std::collections::BTreeMap<String, Vec<String>>,

    /// Static bindings observed in source order.
    pub binds: Vec<Assignment>,
}

impl Ast {
    /// Construct an empty `Ast` view.
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when the view contains no calls, members, or
    /// literal-argument observations.
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
            && self.targets.is_empty()
            && self.members.is_empty()
            && self.call_strings.is_empty()
            && self.binds.is_empty()
    }
}
