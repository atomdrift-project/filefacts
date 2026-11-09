use crate::OpenOptions;

fn data_only(name: &str, source: &str) -> bool {
    let parsed = OpenOptions::new()
        .path(std::path::Path::new(name))
        .open(source.as_bytes());
    parsed.metrics().get("source.data_only") == Some(1.0)
}

fn js(source: &str) -> bool {
    data_only("catalog.js", source)
}

fn py(source: &str) -> bool {
    data_only("catalog.py", source)
}

#[test]
fn javascript_constant_catalogs_are_data() {
    assert!(js(
        "// example\nconst example = 'require(\"https\").get(url);';"
    ));
    assert!(js("const a='hello', b='world'; const c='\\u0061';"));
    assert!(js("module.exports = 'require(\"https\").get(url);';"));
    assert!(js(
        "// template\nmodule.exports = 'postcss([helper(options)])';"
    ));
}

#[test]
fn javascript_that_runs_or_computes_is_not_data() {
    for source in [
        "module.exports = 'example'; eval(module.exports);",
        "module.exports = loadCode();",
        "module.exports = `prefix ${loadCode()}`;",
        "const example='dangerous()';eval(example);",
        "const example='dangerous()';module.exports=example;",
        "const example=loadCode();",
        "const example=`${loadCode()}`;",
        "let example='hello'; example=loadCode();",
        "const example='hello'; startup();",
        "const example = 'broken",
    ] {
        assert!(!js(source), "{source}");
    }
}

#[test]
fn python_string_catalogs_are_data() {
    assert!(py("# example\nexample = 'exec(payload)'\n"));
    assert!(py(
        "\"\"\"A module docstring.\"\"\"\nexample = r'exec(payload)'\n"
    ));
    assert!(py("one = 'hello'\ntwo = b'world'\n"));
}

#[test]
fn python_that_runs_or_computes_is_not_data() {
    for source in [
        "example='exec(payload)'\nexec(example)\n",
        "example='exec(payload)'\nmain()\n",
        "example=load_code()\n",
        "example=f'{load_code()}'\n",
        "example: load_type() = 'text'\n",
    ] {
        assert!(!py(source), "{source}");
    }
}

#[test]
fn other_languages_are_never_data_only() {
    assert!(!data_only("catalog.sh", "EXAMPLE='rm -rf /'\n"));
}
