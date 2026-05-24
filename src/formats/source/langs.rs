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
//!    feed the typed imports/functions views.
//! 3. **AST walk** — node-kind names and field names the
//!    language-agnostic AST walker uses to project the tree into
//!    `ast.calls`, `ast.members`, and `ast.call_strings`.
//!
//! Adding a language is a single entry here plus a Cargo dependency.

use crate::fileid::FileType;

use super::comment_metrics::CommentStyle;

/// Configuration for one source language.
pub(super) struct LangConfig {
    /// Stable label exposed under `values.source.language`.
    pub(super) name: &'static str,
    /// Grammar constructor. Called once per parse.
    pub(super) language: fn() -> tree_sitter::Language,
    /// Comment-extraction style for `comments.*` metrics.
    pub(super) comment_style: CommentStyle,

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
        FileType::Ruby => &RUBY,
        FileType::Lua => &LUA,
        FileType::CSharp => &CSHARP,
        FileType::C => &C,
        FileType::Scala => &SCALA,
        FileType::ObjectiveC => &OBJC,
        FileType::Kotlin => &KOTLIN,
        FileType::Swift => &SWIFT,
        FileType::PowerShell => &POWERSHELL,
        FileType::Perl => &PERL,
        FileType::Groovy => &GROOVY,
        FileType::Zig => &ZIG,
        FileType::Elixir => &ELIXIR,
        FileType::Makefile => &MAKEFILE,
        _ => return None,
    })
}

static JAVASCRIPT: LangConfig = LangConfig {
    name: "javascript",
    language: || tree_sitter_javascript::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
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
    comment_style: CommentStyle::CStyle,
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
    comment_style: CommentStyle::Hash,
    string_kinds: &["string"],
    import_query: r#"
        (import_statement name: (aliased_import) @import)
        (import_statement name: (dotted_name) @import)
        (import_from_statement module_name: (dotted_name) @import)
        (import_from_statement module_name: (relative_import) @import)
        (import_from_statement name: (aliased_import) @import)
        (import_from_statement name: (dotted_name) @import)
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
    comment_style: CommentStyle::CStyle,
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
    comment_style: CommentStyle::CStyle,
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
    comment_style: CommentStyle::CStyle,
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
    comment_style: CommentStyle::Hash,
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
    call_kinds: &["command"],
    callee_field: "name",
    arguments_field: "argument",
    member_kinds: &[],
    member_object_field: "",
    member_property_field: "",
    identifier_kinds: &["command_name", "word", "variable_name"],
    number_kinds: &["number"],
    bool_kinds: &[],
    null_kinds: &[],
    object_kinds: &[],
    array_kinds: &["array"],
    function_kinds: &[],
    template_kinds: &[],
    binary_op_kinds: &[],
};

static RUBY: LangConfig = LangConfig {
    name: "ruby",
    language: || tree_sitter_ruby::LANGUAGE.into(),
    comment_style: CommentStyle::Hash,
    string_kinds: &["string", "string_array", "symbol_array", "heredoc_body"],
    import_query: r#"
        (call
            method: (identifier) @_fn
            arguments: (argument_list (string (string_content) @import))
            (#match? @_fn "^(require|require_relative|load|autoload)$"))
    "#,
    function_query: r#"
        (method name: (identifier) @fn)
        (singleton_method name: (identifier) @fn)
    "#,
    class_query: r#"
        (class name: (constant) @class)
        (module name: (constant) @class)
    "#,
    call_kinds: &["call"],
    callee_field: "method",
    arguments_field: "arguments",
    member_kinds: &["call"],
    member_object_field: "receiver",
    member_property_field: "method",
    identifier_kinds: &[
        "identifier",
        "constant",
        "instance_variable",
        "class_variable",
    ],
    number_kinds: &["integer", "float"],
    bool_kinds: &["true", "false"],
    null_kinds: &["nil"],
    object_kinds: &["hash"],
    array_kinds: &["array"],
    function_kinds: &["lambda", "block", "do_block"],
    template_kinds: &["string"],
    binary_op_kinds: &["binary"],
};

static LUA: LangConfig = LangConfig {
    name: "lua",
    language: || tree_sitter_lua::LANGUAGE.into(),
    comment_style: CommentStyle::DoubleDash,
    string_kinds: &["string"],
    import_query: r#"
        (function_call
            name: (identifier) @_fn
            arguments: (arguments (string (string_content) @import))
            (#eq? @_fn "require"))
    "#,
    function_query: r#"
        (function_declaration name: (identifier) @fn)
        (function_declaration name: (dot_index_expression field: (identifier) @fn))
    "#,
    class_query: "",
    call_kinds: &["function_call"],
    callee_field: "name",
    arguments_field: "arguments",
    member_kinds: &["dot_index_expression"],
    member_object_field: "table",
    member_property_field: "field",
    identifier_kinds: &["identifier"],
    number_kinds: &["number"],
    bool_kinds: &["true", "false"],
    null_kinds: &["nil"],
    object_kinds: &["table_constructor"],
    array_kinds: &["table_constructor"],
    function_kinds: &["function_definition"],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static CSHARP: LangConfig = LangConfig {
    name: "csharp",
    language: || tree_sitter_c_sharp::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &[
        "string_literal",
        "verbatim_string_literal",
        "raw_string_literal",
        "interpolated_string_expression",
    ],
    import_query: r#"
        (using_directive (identifier) @import)
        (using_directive (qualified_name) @import)
    "#,
    function_query: r#"
        (method_declaration name: (identifier) @fn)
        (constructor_declaration name: (identifier) @fn)
        (local_function_statement name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (identifier) @class)
        (interface_declaration name: (identifier) @class)
        (struct_declaration name: (identifier) @class)
        (record_declaration name: (identifier) @class)
        (enum_declaration name: (identifier) @class)
    "#,
    call_kinds: &["invocation_expression", "object_creation_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["member_access_expression"],
    member_object_field: "expression",
    member_property_field: "name",
    identifier_kinds: &["identifier"],
    number_kinds: &["integer_literal", "real_literal"],
    bool_kinds: &["boolean_literal"],
    null_kinds: &["null_literal"],
    object_kinds: &[
        "anonymous_object_creation_expression",
        "initializer_expression",
    ],
    array_kinds: &[
        "array_creation_expression",
        "implicit_array_creation_expression",
    ],
    function_kinds: &["lambda_expression", "anonymous_method_expression"],
    template_kinds: &["interpolated_string_expression"],
    binary_op_kinds: &["binary_expression"],
};

static C: LangConfig = LangConfig {
    name: "c",
    language: || tree_sitter_c::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &["string_literal"],
    import_query: r#"
        (preproc_include path: (system_lib_string) @import)
        (preproc_include path: (string_literal) @import)
    "#,
    function_query: r#"
        (function_definition
            declarator: (function_declarator declarator: (identifier) @fn))
        (function_definition
            declarator: (pointer_declarator
                declarator: (function_declarator declarator: (identifier) @fn)))
    "#,
    class_query: r#"
        (struct_specifier name: (type_identifier) @class)
        (union_specifier name: (type_identifier) @class)
        (enum_specifier name: (type_identifier) @class)
    "#,
    call_kinds: &["call_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    // C has no `a.b` member-access node-kind separate from struct-field
    // dereferences (`field_expression`) but field-access is only one
    // dotted-form so we wire it up:
    member_kinds: &["field_expression"],
    member_object_field: "argument",
    member_property_field: "field",
    identifier_kinds: &["identifier", "field_identifier", "type_identifier"],
    number_kinds: &["number_literal"],
    bool_kinds: &["true", "false"],
    null_kinds: &["null"],
    object_kinds: &["initializer_list"],
    array_kinds: &["initializer_list"],
    function_kinds: &[],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static SCALA: LangConfig = LangConfig {
    name: "scala",
    language: || tree_sitter_scala::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &["string", "interpolated_string_expression"],
    import_query: r#"
        (import_declaration (identifier) @import)
    "#,
    function_query: r#"
        (function_definition name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_definition name: (identifier) @class)
        (object_definition name: (identifier) @class)
        (trait_definition name: (identifier) @class)
    "#,
    call_kinds: &["call_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["field_expression"],
    member_object_field: "value",
    member_property_field: "field",
    identifier_kinds: &["identifier", "type_identifier"],
    number_kinds: &["integer_literal", "floating_point_literal"],
    bool_kinds: &["boolean_literal"],
    null_kinds: &["null_literal"],
    object_kinds: &[],
    array_kinds: &[],
    function_kinds: &["lambda_expression"],
    template_kinds: &["interpolated_string_expression"],
    binary_op_kinds: &["infix_expression"],
};

static OBJC: LangConfig = LangConfig {
    name: "objc",
    language: || tree_sitter_objc::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &["string_literal"],
    import_query: r#"
        (preproc_include path: (system_lib_string) @import)
        (preproc_include path: (string_literal) @import)
    "#,
    function_query: r#"
        (function_definition
            declarator: (function_declarator declarator: (identifier) @fn))
        (method_definition (identifier) @fn)
    "#,
    class_query: r#"
        (class_interface (identifier) @class)
        (class_implementation (identifier) @class)
    "#,
    call_kinds: &["call_expression", "message_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["field_expression"],
    member_object_field: "argument",
    member_property_field: "field",
    identifier_kinds: &["identifier", "field_identifier", "type_identifier"],
    number_kinds: &["number_literal"],
    bool_kinds: &["true", "false"],
    null_kinds: &["null", "nil"],
    object_kinds: &["dictionary_literal", "initializer_list"],
    array_kinds: &["array_literal", "initializer_list"],
    function_kinds: &["block_expression"],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static KOTLIN: LangConfig = LangConfig {
    name: "kotlin",
    language: || tree_sitter_kotlin_ng::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &["string_literal", "character_literal"],
    import_query: r#"
        (import (qualified_identifier) @import)
    "#,
    function_query: r#"
        (function_declaration name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (identifier) @class)
        (object_declaration name: (identifier) @class)
    "#,
    call_kinds: &["call_expression"],
    callee_field: "",
    arguments_field: "",
    member_kinds: &["navigation_expression"],
    member_object_field: "",
    member_property_field: "",
    identifier_kinds: &["identifier", "simple_identifier"],
    number_kinds: &["number_literal", "real_literal"],
    bool_kinds: &["boolean_literal"],
    null_kinds: &["null_literal"],
    object_kinds: &[],
    array_kinds: &[],
    function_kinds: &["lambda_literal", "anonymous_function"],
    template_kinds: &["string_literal"],
    binary_op_kinds: &["binary_expression", "infix_expression"],
};

static SWIFT: LangConfig = LangConfig {
    name: "swift",
    language: || tree_sitter_swift::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &[
        "line_string_literal",
        "multi_line_string_literal",
        "raw_string_literal",
    ],
    import_query: r#"
        (import_declaration (identifier) @import)
    "#,
    function_query: r#"
        (function_declaration name: (simple_identifier) @fn)
        (init_declaration "init" @fn)
    "#,
    class_query: r#"
        (class_declaration name: (type_identifier) @class)
        (protocol_declaration name: (type_identifier) @class)
    "#,
    call_kinds: &["call_expression"],
    callee_field: "",
    arguments_field: "",
    member_kinds: &["navigation_expression"],
    member_object_field: "target",
    member_property_field: "suffix",
    identifier_kinds: &["simple_identifier", "type_identifier"],
    number_kinds: &["integer_literal", "real_literal", "hex_literal"],
    bool_kinds: &["boolean_literal"],
    null_kinds: &["nil"],
    object_kinds: &["dictionary_literal"],
    array_kinds: &["array_literal"],
    function_kinds: &["lambda_literal"],
    template_kinds: &["line_string_literal"],
    binary_op_kinds: &[
        "additive_expression",
        "multiplicative_expression",
        "comparison_expression",
    ],
};

static POWERSHELL: LangConfig = LangConfig {
    name: "powershell",
    language: || tree_sitter_powershell::LANGUAGE.into(),
    comment_style: CommentStyle::Hash,
    string_kinds: &[
        "string_literal",
        "expandable_string_literal",
        "verbatim_string_characters",
    ],
    // PowerShell loads modules via the `Import-Module` cmdlet and
    // dot-sources scripts via the `.` invocation operator. The grammar
    // models a cmdlet invocation as a `command` node where
    // `command_name` carries the cmdlet name and `command_elements`
    // holds the arguments.
    import_query: r#"
        (command
            command_name: (command_name) @_cmd
            command_elements: (command_elements) @import
            (#match? @_cmd "^(Import-Module|Add-PSSnapin|Using)$"))
    "#,
    function_query: r#"
        (function_statement (function_name) @fn)
    "#,
    class_query: r#"
        (class_statement (simple_name) @class)
    "#,
    call_kinds: &["command"],
    callee_field: "command_name",
    arguments_field: "command_elements",
    member_kinds: &[],
    member_object_field: "",
    member_property_field: "",
    identifier_kinds: &["variable", "simple_name", "generic_token", "command_name"],
    number_kinds: &["integer_literal", "real_literal", "decimal_integer_literal"],
    bool_kinds: &[],
    null_kinds: &[],
    object_kinds: &["hash_literal_expression"],
    array_kinds: &["array_expression", "array_literal_expression"],
    function_kinds: &["script_block_expression"],
    template_kinds: &["expandable_string_literal"],
    binary_op_kinds: &[
        "additive_expression",
        "multiplicative_expression",
        "comparison_expression",
    ],
};

static PHP: LangConfig = LangConfig {
    name: "php",
    language: || tree_sitter_php::LANGUAGE_PHP.into(),
    comment_style: CommentStyle::CStyle,
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

static PERL: LangConfig = LangConfig {
    name: "perl",
    language: || ts_parser_perl::LANGUAGE.into(),
    comment_style: CommentStyle::Hash,
    string_kinds: &["string_literal", "interpolated_string_literal", "heredoc_content"],
    import_query: r#"
        (use_statement (package) @import)
        (require_expression (bareword) @import)
    "#,
    function_query: r#"
        (subroutine_declaration_statement name: (bareword) @fn)
    "#,
    class_query: r#"
        (package_statement (package) @class)
        (class_statement (package) @class)
    "#,
    call_kinds: &["function_call_expression", "method_call_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["method_call_expression"],
    member_object_field: "invocant",
    member_property_field: "method",
    identifier_kinds: &["scalar_variable", "array_variable", "hash_variable", "bareword"],
    number_kinds: &["number"],
    bool_kinds: &["boolean"],
    null_kinds: &["undef_expression"],
    object_kinds: &["anonymous_hash_expression", "hash"],
    array_kinds: &["anonymous_array_expression", "array"],
    function_kinds: &["anonymous_subroutine_expression"],
    template_kinds: &["interpolated_string_literal"],
    binary_op_kinds: &["binary_expression"],
};

static GROOVY: LangConfig = LangConfig {
    name: "groovy",
    language: || tree_sitter_groovy::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &["string_literal"],
    import_query: r#"
        (import_declaration (scoped_identifier) @import)
        (import_declaration (identifier) @import)
    "#,
    function_query: r#"
        (method_declaration name: (identifier) @fn)
        (function_definition name: (identifier) @fn)
    "#,
    class_query: r#"
        (class_declaration name: (identifier) @class)
    "#,
    call_kinds: &["method_invocation", "juxt_function_call"],
    callee_field: "name",
    arguments_field: "arguments",
    member_kinds: &["method_invocation"],
    member_object_field: "object",
    member_property_field: "name",
    identifier_kinds: &["identifier"],
    number_kinds: &[
        "decimal_integer_literal",
        "hex_integer_literal",
        "decimal_floating_point_literal",
    ],
    bool_kinds: &["true", "false"],
    null_kinds: &["null_literal"],
    object_kinds: &["map"],
    array_kinds: &["list", "array_literal"],
    function_kinds: &["closure"],
    template_kinds: &["string_interpolation"],
    binary_op_kinds: &["binary_expression"],
};

static ZIG: LangConfig = LangConfig {
    name: "zig",
    language: || tree_sitter_zig::LANGUAGE.into(),
    comment_style: CommentStyle::CStyle,
    string_kinds: &["string", "multiline_string"],
    import_query: r#"
        (builtin_function
            (builtin_identifier) @_fn
            (arguments (string (string_content) @import))
            (#any-of? @_fn "@import" "@cImport"))
    "#,
    function_query: r#"
        (function_declaration name: (identifier) @fn)
    "#,
    class_query: "",
    call_kinds: &["call_expression"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &["field_expression"],
    member_object_field: "object",
    member_property_field: "field",
    identifier_kinds: &["identifier", "builtin_identifier"],
    number_kinds: &["integer", "float"],
    bool_kinds: &["true", "false"],
    null_kinds: &["null"],
    object_kinds: &["struct_initializer", "anonymous_struct_initializer"],
    array_kinds: &[],
    function_kinds: &[],
    template_kinds: &[],
    binary_op_kinds: &["binary_expression"],
};

static ELIXIR: LangConfig = LangConfig {
    name: "elixir",
    language: || tree_sitter_elixir::LANGUAGE.into(),
    comment_style: CommentStyle::Hash,
    string_kinds: &["string", "charlist"],
    import_query: r#"
        (call
            target: (identifier) @_fn
            (arguments (alias) @import)
            (#any-of? @_fn "alias" "import" "require" "use"))
    "#,
    function_query: r#"
        (call
            target: (identifier) @_fn
            (arguments (call target: (identifier) @fn))
            (#any-of? @_fn "def" "defp" "defmacro" "defmacrop"))
    "#,
    class_query: r#"
        (call
            target: (identifier) @_fn
            (arguments (alias) @class)
            (#eq? @_fn "defmodule"))
    "#,
    call_kinds: &["call"],
    callee_field: "target",
    arguments_field: "arguments",
    member_kinds: &["dot"],
    member_object_field: "left",
    member_property_field: "right",
    identifier_kinds: &["identifier", "alias", "atom"],
    number_kinds: &["integer", "float"],
    bool_kinds: &["boolean"],
    null_kinds: &["nil"],
    object_kinds: &["map", "struct"],
    array_kinds: &["list", "tuple"],
    function_kinds: &["anonymous_function"],
    template_kinds: &["interpolation"],
    binary_op_kinds: &["binary_operator"],
};

static MAKEFILE: LangConfig = LangConfig {
    name: "makefile",
    language: || tree_sitter_make::LANGUAGE.into(),
    comment_style: CommentStyle::Hash,
    string_kinds: &["string"],
    import_query: r#"
        (include_directive (list (word) @import))
    "#,
    // Rules in Make are the closest analogue to "functions" — the
    // target name(s) of each rule.
    function_query: r#"
        (rule (targets (word) @fn))
    "#,
    class_query: "",
    call_kinds: &["function_call", "shell_function"],
    callee_field: "function",
    arguments_field: "arguments",
    member_kinds: &[],
    member_object_field: "",
    member_property_field: "",
    identifier_kinds: &["word", "variable_reference"],
    number_kinds: &[],
    bool_kinds: &[],
    null_kinds: &[],
    object_kinds: &[],
    array_kinds: &["list"],
    function_kinds: &[],
    template_kinds: &[],
    binary_op_kinds: &[],
};
