use super::*;

/// RFC 4514 writes a special or non-ASCII byte in a value as `\` and
/// two hex digits, or as `\` and the character itself.
#[test]
fn dn_values_are_unescaped() {
    let attr = |dn: &str, a: &str| dn_attr(dn, a);
    assert_eq!(
        attr("CN=Example\\2C Inc.,O=Example", "CN").as_deref(),
        Some("Example, Inc.")
    );
    assert_eq!(attr("CN=Caf\\C3\\A9,O=X", "CN").as_deref(), Some("Café"));
    assert_eq!(attr("O=Acme\\, Ltd.", "O").as_deref(), Some("Acme, Ltd."));
    assert_eq!(attr("CN=a\\+b+O=c", "O").as_deref(), Some("c"));
    assert_eq!(attr("CN=a\\+b+O=c", "CN").as_deref(), Some("a+b"));
    assert_eq!(attr("CN=\\4ao\\5c", "CN").as_deref(), Some("Jo\\"));
    assert_eq!(attr("CN=x\\", "CN").as_deref(), Some("x"));
    assert_eq!(attr("CN=", "CN"), None);
}

/// Names as `x509-cert` renders a certificate's subject, which is what
/// `dn_attr` reads: attribute values escaped, most specific RDN first.
fn rendered(dn: &str) -> String {
    use std::str::FromStr;
    x509_cert::name::RdnSequence::from_str(dn)
        .unwrap()
        .to_string()
}

/// A value the signer chose cannot pass for another attribute, and is read
/// back exactly: an escaped `,O=` inside a common name stays in the common
/// name, and spaces at a value's ends are part of it, so `Microsoft
/// Corporation ` is not `Microsoft Corporation`.
#[test]
fn dn_values_cannot_pose_as_other_attributes() {
    let dn = rendered("CN=x\\,O=Microsoft Corporation,O=Example");
    assert_eq!(dn_attr(&dn, "O").as_deref(), Some("Example"));
    assert_eq!(
        dn_attr(&dn, "CN").as_deref(),
        Some("x,O=Microsoft Corporation")
    );
    let dn = rendered("CN=x+O=Microsoft Corporation\\ ");
    assert_eq!(dn_attr(&dn, "O").as_deref(), Some("Microsoft Corporation "));
    let dn = rendered("O=\\ Apple Inc.");
    assert_eq!(dn_attr(&dn, "O").as_deref(), Some(" Apple Inc."));
}
