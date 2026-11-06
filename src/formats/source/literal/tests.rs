use crate::FileType;

/// The literal tier of `src` parsed as `file_type`.
fn literals(file_type: FileType, name: &str, src: &str) -> Vec<String> {
    let parsed = crate::OpenOptions::new()
        .cache(false)
        .path(std::path::Path::new(name))
        .file_type(file_type)
        .open(src.as_bytes());
    parsed.literals().iter().map(|l| l.value.clone()).collect()
}

#[test]
fn python_triple_quotes_and_prefixes() {
    let src = r#"a = """hello"""
b = '''x\ty'''
c = rb"""\x41"""
d = f'''v{x}'''
e = u"""u"""
f = R'''\d'''
g = """"""
h = b'\x42'
"#;
    assert_eq!(
        literals(FileType::Python, "t.py", src),
        ["hello", "x\ty", r"\x41", "v{x}", "u", r"\d", "", "B"]
    );
}

#[test]
fn scala_triple_quotes_are_raw_and_interpolators_follow_their_rules() {
    let src = r#"object A {
  val a = """C:\temp"""
  val b = "x\ty"
  val c = s"v\t$x"
  val d = raw"\d"
  val e = s"""t\n"""
}"#;
    assert_eq!(
        literals(FileType::Scala, "t.scala", src),
        [r"C:\temp", "x\ty", "v\t$x", r"\d", "t\n"]
    );
}

#[test]
fn swift_raw_and_multi_line_literals() {
    let src = "let a = \"\"\"\n    l1\n      l2\n    \"\"\"\n\
        let b = #\"r\\n\"#\n\
        let c = ##\"a\"#b\"##\n\
        let d = #\"tab\\#t\"#\n\
        let e = \"x\\ty\"\n";
    assert_eq!(
        literals(FileType::Swift, "t.swift", src),
        ["l1\n  l2", r"r\n", "a\"#b", "tab\t", "x\ty"]
    );
}

#[test]
fn rust_raw_byte_and_c_strings() {
    let src = r####"fn f() {
    let a = r#"q "x""#;
    let b = br##"x"#y"##;
    let c = b"\x41";
    let d = c"hi\n";
    let e = r"\d";
    let g = r###"\n"###;
}"####;
    assert_eq!(
        literals(FileType::Rust, "t.rs", src),
        ["q \"x\"", "x\"#y", "A", "hi\n", r"\d", r"\n"]
    );
}

#[test]
fn csharp_verbatim_interpolated_and_raw_literals() {
    let src = "class A {\n\
        string a = @\"C:\\t\"\"q\"\"\";\n\
        string b = $\"v{x}\\t\";\n\
        string c = $@\"C:\\{x}\";\n\
        string d = \"\"\"raw \"q\" \\n\"\"\";\n\
        string e = \"\"\"\n    l1\n      l2\n    \"\"\";\n\
        string f = \"x\\ty\"u8;\n\
        string g = @$\"y\\\";\n\
        string h = $$\"\"\"\"{{x}} \"\"\" \"\"\"\";\n\
    }";
    assert_eq!(
        literals(FileType::CSharp, "t.cs", src),
        [
            "C:\\t\"q\"",
            "v{x}\t",
            "C:\\{x}",
            "raw \"q\" \\n",
            "l1\n  l2",
            "x\ty",
            "y\\",
            "{{x}} \"\"\" ",
        ]
    );
}

#[test]
fn c_family_prefixes() {
    assert_eq!(
        literals(
            FileType::C,
            "t.c",
            "char *a = \"x\\ty\"; wchar_t *b = L\"w\";"
        ),
        ["x\ty", "w"]
    );
    assert_eq!(
        literals(
            FileType::ObjectiveC,
            "t.m",
            "int main() { NSString *s = @\"o\\tc\"; }"
        ),
        ["o\tc"]
    );
}
