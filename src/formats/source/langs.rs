//! Per-language configuration for tree-sitter extractors.

// Many of the queries in this file embed `"` inside their bodies, which
// forces the `r#"..."#` raw form. Holding the others to a different
// shape would split the file's visual rhythm without buying anything.
#![allow(clippy::needless_raw_string_hashes)]
//!
//! Every supported source language declares one [`LangConfig`] entry
//! covering three concerns:
//!
//! 1. **Grammar binding** — the `tree_sitter::Language` constructor.
//! 2. **Surface extraction** — tree-sitter queries for imports,
//!    function-definition names, and class-definition names. These
//!    feed `values.imports` / `values.functions` / `values.classes`.
//! 3. **AST walk** — node-kind names and field names the
//!    language-agnostic AST walker uses to project the tree into
//!    `ast.calls`, `ast.member_chains`, and `ast.call_string_args`.
//!
//! Adding a language is a single entry here plus a Cargo dependency.

use crate::fileid::FileType;

/// Configuration for one source language.
pub(super) struct LangConfig {
    /// Stable label exposed under `values.source.language`.
    pub(super) name: &'static str,
    /// Grammar constructor. Called once per parse.
    pub(super) language: fn() -> tree_sitter::Language,

    // ------------------------------------------------------------------
    // Surface-extraction queries
    // ------------------------------------------------------------------
    pub(super) string_kinds: &'static [&'static str],
    pub(super) import_query: &'static str,
    pub(super) function_query: &'static str,
    pub(super) class_query: &'static str,

    // ------------------------------------------------------------------
    // AST-walk node-kind sets and field names
    // ------------------------------------------------------------------
    /// Node-kind names that are call expressions.
    pub(super) call_kinds: &'static [&'static str],
    /// Field name on a call-expression node that holds the callee.
    pub(super) callee_field: &'static str,
    /// Field name on a call-expression node that holds the argument
    /// list.
    pub(super) arguments_field: &'static str,
    /// Node-kind names for dotted member-access expressions.
    pub(super) member_kinds: &'static [&'static str],
    /// Field on a member-access node that holds the object (`a` in
    /// `a.b`).
    pub(super) member_object_field: &'static str,
    /// Field on a member-access node that holds the property (`b` in
    /// `a.b`).
    pub(super) member_property_field: &'static str,
    /// Node-kind names for identifiers.
    pub(super) identifier_kinds: &'static [&'static str],
    /// Node-kind names for numeric literals.
    pub(super) number_kinds: &'static [&'static str],
    /// Node-kind names for boolean literals.
    pub(super) bool_kinds: &'static [&'static str],
    /// Node-kind names for null / nil / None literals.
    pub(super) null_kinds: &'static [&'static str],
    /// Node-kind names for object / map / dict / struct literals.
    pub(super) object_kinds: &'static [&'static str],
    /// Node-kind names for array / list / slice literals.
    pub(super) array_kinds: &'static [&'static str],
    /// Node-kind names for function / lambda / closure literals.
    pub(super) function_kinds: &'static [&'static str],
    /// Node-kind names for template / formatted / interpolated strings.
    pub(super) template_kinds: &'static [&'static str],
    /// Node-kind names for binary-operator expressions.
    pub(super) binary_op_kinds: &'static [&'static str],
}

pub(super) fn config_for(file_type: FileType) -> Option<&'static LangConfig> {
    Some(match file_type {
        FileType::JavaScript => &JAVASCRIPT,
        FileType::TypeScript => &TYPESCRIPT,
        FileType::Python => &PYTHON,
        FileType::Go => &GO,
        FileType::Rust => &RUST,
        FileType::Java => &JAVA,
        FileType::Shell => &BASH,
        FileType::Php => &PHP,
        _ => return None,
    })
}

static JAVASCRIPT: LangConfig = LangConfig {
    name: "javascript",
    language: || tree_sitter_javascript::LANGUAGE.into(),
    string_kinds: &["string", "template_string"],
    import_query: r#"
        (import_statement source: (string) @import)
        (call_expression
            function: (identifier) @_fn
            arguments: (arguments (string) @import)
            (#eq? @_fn "require"))
    "#,
    function_query: r#"
        (function_declaration name: (identifier) @fn)
        (method_definition name: (property_identifier) @fn)
        (generator_function_declaration name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (identifier) @class)
    "#,
    call_kinds: &["call_expression", "new_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["member_expression"],
    member_object_field: "object",
    member_property_field: "property",
    identifier_kinds: &[
        "identifier",
        "property_identifier",
        "shorthand_property_identifier",
    ],
    number_kinds: &["number"],
    bool_kinds: &["true", "false"],
    null_kinds: &["null", "undefined"],
    object_kinds: &["object"],
    array_kinds: &["array"],
    function_kinds: &[
        "function_expression",
        "arrow_function",
        "generator_function",
    ],
    template_kinds: &["template_string"],
    binary_op_kinds: &["binary_expression"],
};

static TYPESCRIPT: LangConfig = LangConfig {
    name: "typescript",
    language: || tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    string_kinds: &["string", "template_string"],
    import_query: r#"
        (import_statement source: (string) @import)
        (call_expression
            function: (identifier) @_fn
            arguments: (arguments (string) @import)
            (#eq? @_fn "require"))
    "#,
    function_query: r#"
        (function_declaration name: (identifier) @fn)
        (method_definition name: (property_identifier) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (type_identifier) @class)
        (interface_declaration name: (type_identifier) @class)
    "#,
    call_kinds: &["call_expression", "new_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["member_expression"],
    member_object_field: "object",
    member_property_field: "property",
    identifier_kinds: &["identifier", "property_identifier", "type_identifier"],
    number_kinds: &["number"],
    bool_kinds: &["true", "false"],
    null_kinds: &["null", "undefined"],
    object_kinds: &["object"],
    array_kinds: &["array"],
    function_kinds: &["function_expression", "arrow_function"],
    template_kinds: &["template_string"],
    binary_op_kinds: &["binary_expression"],
};

static PYTHON: LangConfig = LangConfig {
    name: "python",
    language: || tree_sitter_python::LANGUAGE.into(),
    string_kinds: &["string"],
    import_query: r#"
        (import_statement name: (dotted_name) @import)
        (import_from_statement module_name: (dotted_name) @import)
        (import_from_statement module_name: (relative_import) @import)
    "#,
    function_query: r#"
        (function_definition name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_definition name: (identifier) @class)
    "#,
    call_kinds: &["call"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["attribute"],
    member_object_field: "object",
    member_property_field: "attribute",
    identifier_kinds: &["identifier"],
    number_kinds: &["integer", "float"],
    bool_kinds: &["true", "false"],
    null_kinds: &["none"],
    object_kinds: &["dictionary"],
    array_kinds: &["list", "tuple", "set"],
    function_kinds: &["lambda"],
    template_kinds: &["string"],
    binary_op_kinds: &["binary_operator"],
};

static GO: LangConfig = LangConfig {
    name: "go",
    language: || tree_sitter_go::LANGUAGE.into(),
    string_kinds: &["interpreted_string_literal", "raw_string_literal"],
    import_query: r#"
        (import_spec path: (interpreted_string_literal) @import)
    "#,
    function_query: r#"
        (function_declaration name: (identifier) @fn)
        (method_declaration name: (field_identifier) @fn)
    "#,
    class_query: r#"
        (type_spec name: (type_identifier) @class type: (struct_type))
        (type_spec name: (type_identifier) @class type: (interface_type))
    "#,
    call_kinds: &["call_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["selector_expression"],
    member_object_field: "operand",
    member_property_field: "field",
    identifier_kinds: &[
        "identifier",
        "field_identifier",
        "type_identifier",
        "package_identifier",
    ],
    number_kinds: &["int_literal", "float_literal", "imaginary_literal"],
    bool_kinds: &["true", "false"],
    null_kinds: &["nil"],
    object_kinds: &["composite_literal"],
    array_kinds: &["composite_literal"],
    function_kinds: &["func_literal"],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static RUST: LangConfig = LangConfig {
    name: "rust",
    language: || tree_sitter_rust::LANGUAGE.into(),
    string_kinds: &["string_literal", "raw_string_literal"],
    import_query: r#"
        (use_declaration argument: (scoped_identifier path: (identifier) @import))
        (use_declaration argument: (identifier) @import)
    "#,
    function_query: r#"
        (function_item name: (identifier) @fn)
    "#,
    class_query: r#"
        (struct_item name: (type_identifier) @class)
        (enum_item name: (type_identifier) @class)
        (trait_item name: (type_identifier) @class)
    "#,
    call_kinds: &["call_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["field_expression"],
    member_object_field: "value",
    member_property_field: "field",
    identifier_kinds: &["identifier", "field_identifier", "type_identifier"],
    number_kinds: &["integer_literal", "float_literal"],
    bool_kinds: &["boolean_literal"],
    null_kinds: &[],
    object_kinds: &["struct_expression"],
    array_kinds: &["array_expression"],
    function_kinds: &["closure_expression"],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static JAVA: LangConfig = LangConfig {
    name: "java",
    language: || tree_sitter_java::LANGUAGE.into(),
    string_kinds: &["string_literal"],
    import_query: r#"
        (import_declaration (scoped_identifier) @import)
        (import_declaration (identifier) @import)
    "#,
    function_query: r#"
        (method_declaration name: (identifier) @fn)
        (constructor_declaration name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (identifier) @class)
        (interface_declaration name: (identifier) @class)
        (enum_declaration name: (identifier) @class)
        (record_declaration name: (identifier) @class)
    "#,
    call_kinds: &["method_invocation", "object_creation_expression"],
    callee_field: "name",
    arguments_field: "arguments",
    member_kinds: &["field_access"],
    member_object_field: "object",
    member_property_field: "field",
    identifier_kinds: &["identifier"],
    number_kinds: &[
        "decimal_integer_literal",
        "hex_integer_literal",
        "decimal_floating_point_literal",
    ],
    bool_kinds: &["true", "false"],
    null_kinds: &["null_literal"],
    object_kinds: &[],
    array_kinds: &["array_initializer"],
    function_kinds: &["lambda_expression"],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static BASH: LangConfig = LangConfig {
    name: "bash",
    language: || tree_sitter_bash::LANGUAGE.into(),
    string_kinds: &["string", "raw_string"],
    import_query: r#"
        (command
            name: (command_name) @_cmd
            argument: [(word) (string) (raw_string)] @import
            (#match? @_cmd "^(source|\\.)$"))
    "#,
    function_query: r#"
        (function_definition name: (word) @fn)
    "#,
    class_query: "",
    // Bash's command-execution AST shape doesn't fit the
    // callee/arguments-field model the walker expects; we leave the
    // AST-walk fields empty and `ast` stays empty for bash files. The
    // surface extraction (imports/functions) still works via queries.
    call_kinds: &[],
    callee_field: "",
    arguments_field: "",
    member_kinds: &[],
    member_object_field: "",
    member_property_field: "",
    identifier_kinds: &["word", "variable_name"],
    number_kinds: &["number"],
    bool_kinds: &[],
    null_kinds: &[],
    object_kinds: &[],
    array_kinds: &["array"],
    function_kinds: &[],
    template_kinds: &[],
    binary_op_kinds: &[],
};

static PHP: LangConfig = LangConfig {
    name: "php",
    language: || tree_sitter_php::LANGUAGE_PHP.into(),
    string_kinds: &["string", "string_content", "heredoc_body"],
    import_query: r#"
        (namespace_use_clause (qualified_name) @import)
        (namespace_use_clause (name) @import)
        (require_expression (string) @import)
        (require_once_expression (string) @import)
        (include_expression (string) @import)
        (include_once_expression (string) @import)
    "#,
    function_query: r#"
        (function_definition name: (name) @fn)
        (method_declaration name: (name) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (name) @class)
        (interface_declaration name: (name) @class)
        (trait_declaration name: (name) @class)
    "#,
    call_kinds: &[
        "function_call_expression",
        "member_call_expression",
        "scoped_call_expression",
    ],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["member_access_expression"],
    member_object_field: "object",
    member_property_field: "name",
    identifier_kinds: &["name", "variable_name"],
    number_kinds: &["integer", "float"],
    bool_kinds: &["boolean"],
    null_kinds: &["null"],
    object_kinds: &["array_creation_expression"],
    array_kinds: &["array_creation_expression"],
    function_kinds: &["anonymous_function_creation_expression", "arrow_function"],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};
