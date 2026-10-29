#[test]
fn code_ratio_counts_nested_and_same_line_functions_once() {
    for (source, expected) in [
        (
            "function outer() {\n  function inner() { return 1; }\n  return inner;\n}\nconst outside = 1;\n",
            4.0 / 5.0,
        ),
        (
            "const a = () => 1; const b = () => 2;\nconst outside = 1;\n",
            0.5,
        ),
        ("function a() {}\n\nfunction b() {}\n", 2.0 / 3.0),
    ] {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("coverage.js"))
            .open(source.as_bytes());
        assert_eq!(
            parsed.metrics().get("functions.code_ratio"),
            Some(expected),
            "{source}"
        );
    }
}

#[test]
fn code_ratio_counts_nested_python_functions_once() {
    let source = b"def outer():\n    def inner():\n        return 1\n    return inner\nvalue = 1\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("coverage.py"))
        .open(source);
    assert_eq!(parsed.metrics().get("functions.code_ratio"), Some(0.8));
}

/// A shell function has no parameter list; the statements in its body
/// must not be counted as parameters.
#[test]
fn shell_function_statements_are_not_parameters() {
    let src = b"greet() {\n  echo a\n  echo b\n  echo c\n}\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("f.sh"))
        .open(src);
    let metrics = parsed.metrics();
    assert_eq!(metrics.get("functions.no_params_count"), Some(1.0));
    assert_eq!(metrics.get("functions.max_params"), None);
    assert_eq!(metrics.get("functions.avg_params"), None);
}
