use super::*;
use crate::FlowTransfer;
fn graph(path: &str, source: &str) -> Flow {
    let file = crate::OpenOptions::new()
        .path(std::path::Path::new(path))
        .open(source.as_bytes());
    file.flow().unwrap().clone()
}
#[test]
fn branch_merges_number_values_the_same_way_every_time() {
    // Branch bindings were merged in HashMap order, so value ids changed
    // from one build to the next.
    let source = "def f(c):\n    a = 1\n    b = 2\n    d = 3\n    if c:\n        a = x()\n        b = y()\n        d = z()\n    else:\n        a = u()\n        b = v()\n        d = w()\n    return a, b, d\n";
    let first = serde_json::to_string(&graph("m.py", source)).unwrap();
    for _ in 0..20 {
        assert_eq!(
            serde_json::to_string(&graph("m.py", source)).unwrap(),
            first
        );
    }
}
fn reaches(flow: &Flow, sink: &str, source: &str) -> bool {
    flow.values
        .iter()
        .filter(|v| v.target.as_deref() == Some(sink))
        .any(|v| {
            v.inputs.iter().any(|id| {
                flow.origins(*id, &[], 1000)
                    .values
                    .iter()
                    .any(|id| flow.values[id.value].target.as_deref() == Some(source))
            })
        })
}
#[test]
fn anonymous_function_limitations_survive_named_function_boundaries() {
    for (path, source) in [
        ("a.js", "register(() => send(acquire()));"),
        (
            "a.js",
            "function activate(){register(() => send(acquire()));}",
        ),
        (
            "a.js",
            "function activate(){register(function(){send(acquire());});}",
        ),
        (
            "a.ts",
            "function activate(){register(() => send(acquire()));}",
        ),
        (
            "a.py",
            "def activate():\n register(lambda: send(acquire()))\n",
        ),
        (
            "a.go",
            "package p\nfunc activate(){register(func(){send(acquire())})}",
        ),
    ] {
        let flow = graph(path, source);
        assert!(
            !flow.limitations.contains("parse-error"),
            "{path}: {flow:?}"
        );
        assert!(
            flow.limitations.contains("anonymous-function"),
            "{path}: {flow:?}"
        );
        assert!(
            flow.values
                .iter()
                .any(|v| v.target.as_deref() == Some("register")),
            "{path}"
        );
        // This diagnostic repair must not invent a modeled callback body.
        assert!(
            !flow
                .values
                .iter()
                .any(|v| v.target.as_deref() == Some("send")),
            "{path}"
        );
    }
    let direct = graph("a.js", "function activate(){send(acquire());}");
    assert!(!direct.limitations.contains("anonymous-function"));
    assert!(reaches(&direct, "send", "acquire"));
    assert!(!direct.limitations.contains("nested-function"));
    let nested = graph(
        "a.js",
        "function outer(){function inner(){register(() => send(acquire()));} inner();}",
    );
    assert!(nested.limitations.contains("nested-function"));
    assert!(!nested.functions.contains_key("inner"));
    assert!(
        !nested
            .values
            .iter()
            .any(|v| v.target.as_deref() == Some("send"))
    );
}
#[test]
fn shared_assignment_and_helper_contract() {
    for (path, source) in [
        (
            "a.py",
            "def identity(x):\n return x\ndef main():\n value=acquire()\n send(identity(value))\n",
        ),
        (
            "a.js",
            "function identity(x){return x} function main(){let value=acquire();send(identity(value));}",
        ),
        (
            "a.ts",
            "function identity(x:string){return x} function main(){let value=acquire();send(identity(value));}",
        ),
        (
            "a.rs",
            "fn identity(x:Data)->Data{x} fn main(){let value=acquire();send(identity(value));}",
        ),
        (
            "a.go",
            "package p\nfunc identity(x string)string{return x}\nfunc main(){value:=acquire();send(identity(value))}",
        ),
        (
            "a.c",
            "char *identity(char *x){return x;} void run(){char *value=acquire();send(identity(value));}",
        ),
    ] {
        let flow = graph(path, source);
        assert!(reaches(&flow, "send", "acquire"), "{path}: {flow:?}");
    }
}

#[test]
fn compound_assignments_preserve_both_operands_and_later_overwrites() {
    for (path, prefix, initial, suffix) in [
        ("a.js", "function run(){", "let value=left();", "}"),
        ("a.ts", "function run(){", "let value=left();", "}"),
        ("a.py", "def run():\n ", "value=left();", "\n"),
        ("a.go", "package p\nfunc run(){", "value:=left();", "}"),
        ("a.rs", "fn run(){", "let mut value=left();", "}"),
        ("a.c", "void run(){", "int value=left();", "}"),
    ] {
        for (tail, left_expected, right_expected) in [
            ("value+=right();send(value);", true, true),
            ("value=right();send(value);", false, true),
            ("value+=right();value=0;send(value);", false, false),
            ("value+=right();send(0);", false, false),
            ("value+=opaque(right());send(value);", true, false),
        ] {
            let source = format!("{prefix}{initial}{tail}{suffix}");
            let flow = graph(path, &source);
            assert!(
                !flow.limitations.contains("parse-error"),
                "{path}: {source}"
            );
            assert_eq!(
                reaches(&flow, "send", "left"),
                left_expected,
                "{path}: {source}"
            );
            assert_eq!(
                reaches(&flow, "send", "right"),
                right_expected,
                "{path}: {source}"
            );
        }
    }
    let ordered = graph(
        "a.js",
        "function run(){let value=left();value+=(value=right());send(value);}",
    );
    assert!(reaches(&ordered, "send", "left"));
    assert!(reaches(&ordered, "send", "right"));
    for target in ["left", "right"] {
        assert_eq!(
            ordered
                .values
                .iter()
                .filter(|v| v.target.as_deref() == Some(target))
                .count(),
            1
        );
    }
    let member = graph(
        "a.js",
        "function run(){let obj={};obj.value+=right();send(obj.value);}",
    );
    assert!(member.limitations.contains("compound-assignment-target"));
    assert!(!reaches(&member, "send", "right"));
}

#[test]
fn go_if_initializers_preserve_flow_and_lexical_scope() {
    for (body, sink, expected) in [
        (
            "if value := acquire(); value != nil { send(value) }",
            "send",
            true,
        ),
        ("if value := acquire(); check(value) {}", "check", true),
        (
            "if value := acquire(); flag { } else { send(value) }",
            "send",
            true,
        ),
        (
            "if value := acquire(); flag { } else if other { send(value) }",
            "send",
            true,
        ),
        (
            "if value, ok := acquire(); ok { send(value) }",
            "send",
            true,
        ),
        (
            "value := \"public\"; if value = acquire(); flag {}; send(value)",
            "send",
            true,
        ),
        (
            "value := \"public\"; if value := acquire(); flag { check(value) }; send(value)",
            "send",
            false,
        ),
        (
            "value := acquire(); if value := \"public\"; flag { check(value) }; send(value)",
            "send",
            true,
        ),
        (
            "if value := acquire(); flag { value = \"public\"; send(value) }",
            "send",
            false,
        ),
        (
            "if value := acquire(); flag { value := \"public\"; send(value) }",
            "send",
            false,
        ),
    ] {
        let source = format!("package p\nfunc run(){{ {body} }}");
        let flow = graph("a.go", &source);
        assert!(!flow.limitations.contains("parse-error"), "{body}");
        assert_eq!(reaches(&flow, sink, "acquire"), expected, "{body}");
        assert_eq!(
            flow.values
                .iter()
                .filter(|v| v.target.as_deref() == Some("acquire"))
                .count(),
            1,
            "initializer calls must be retained exactly once: {body}",
        );
    }
}
/// A prefixed Python string is a constant, but an f-string's
/// interpolations still carry the values they embed.
#[test]
fn python_prefixed_strings_are_literals_but_interpolations_flow() {
    let flow = graph("a.py", "def run():\n send(f\"{acquire()}\")\n");
    assert!(reaches(&flow, "send", "acquire"), "{flow:?}");
    let flow = graph("a.py", "def run():\n send(b\"\\x41\")\n");
    let sink = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("send"))
        .unwrap();
    assert!(
        matches!(
            &flow.values[sink.inputs[0]].literal,
            Some(Arg::String { value }) if value == "A"
        ),
        "{flow:?}"
    );
}

#[test]
fn helper_calls_do_not_contaminate_each_other() {
    let flow = graph(
        "a.js",
        "function identity(x){return x} function main(){identity(acquire());send(identity('constant'));}",
    );
    assert!(!reaches(&flow, "send", "acquire"));
    let flow = graph(
        "a.js",
        "function main(){let x='constant';{let x=acquire();}send(x);}",
    );
    assert!(!reaches(&flow, "send", "acquire"));
    let flow = graph(
        "a.js",
        "function main(){let x=acquire();{let x='constant';}send(x);}",
    );
    assert!(reaches(&flow, "send", "acquire"));
    let flow = graph(
        "a.js",
        "function main(){let x=acquire();x='constant';send(x);}",
    );
    assert!(!reaches(&flow, "send", "acquire"));
    let flow = graph("a.js", "function main(){send(opaque(acquire()));}");
    assert!(!reaches(&flow, "send", "acquire"));
}

#[test]
fn transfer_models_and_budgets_are_explicit() {
    let flow = graph("a.js", "function run(){send(wrap(acquire()));}");
    let sink = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("send"))
        .unwrap()
        .inputs[0];
    let models = [FlowTransfer {
        call: "wrap".into(),
        arguments: vec![0],
        receiver: false,
    }];
    let found = flow.origins(sink, &models, 1000);
    assert!(
        found
            .values
            .iter()
            .any(|i| flow.values[i.value].target.as_deref() == Some("acquire"))
    );
    assert!(flow.origins(sink, &models, 0).incomplete);
    assert!(flow.origins(usize::MAX, &[], 1).incomplete);
}

#[test]
fn object_fields_keep_authentication_separate_from_body() {
    let flow = graph(
        "a.js",
        "function run(){let token=acquire();send({headers:{Authorization:token},body:'status'});}",
    );
    let sink = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("send"))
        .unwrap();
    let object = &flow.values[sink.inputs[0]];
    let body = object.fields["body"];
    assert!(
        !flow
            .origins(body, &[], 1000)
            .values
            .iter()
            .any(|i| flow.values[i.value].target.as_deref() == Some("acquire"))
    );
}

#[test]
fn helper_returned_fields_preserve_invocation_and_ignore_headers() {
    for (path, source) in [
        (
            "a.js",
            "function options(name){return {headers:{Authorization:acquire('TOKEN')},body:acquire(name)}} function run(){options('TOKEN');send(options('PUBLIC'))}",
        ),
        (
            "a.ts",
            "function options(name:string){return {headers:{Authorization:acquire('TOKEN')},body:acquire(name)}} function run(){options('TOKEN');send(options('PUBLIC'))}",
        ),
        (
            "a.py",
            "def options(name):\n    return {'headers': {'Authorization': acquire('TOKEN')}, 'body': acquire(name)}\ndef run():\n    options('TOKEN')\n    send(options('PUBLIC'))\n",
        ),
    ] {
        let flow = graph(path, source);
        let sink = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("send"))
            .unwrap();
        let models = [FlowTransfer {
            call: "acquire".into(),
            arguments: vec![],
            receiver: false,
        }];
        let found = flow.field_origins(sink.inputs[0], "body", &models, 1000);
        assert!(!found.incomplete, "{path}: {found:?}");
        let mut literals = Vec::new();
        for origin in &found.values {
            if flow.values[origin.value].target.as_deref() == Some("acquire") {
                for argument in flow.argument_origins(origin, 0, &models, 1000).values {
                    if let Some(Arg::String { value }) = &flow.values[argument.value].literal {
                        literals.push(value.as_str());
                    }
                }
            }
        }
        assert_eq!(literals, ["PUBLIC"], "{path}");
        assert!(
            flow.field_origins(sink.inputs[0], "body", &models, 0)
                .incomplete
        );
    }
}

#[test]
fn external_field_shapes_are_opaque_even_with_value_transfer_models() {
    let flow = graph("a.js", "function run(){send(opaque({body:acquire()}));}");
    let sink = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("send"))
        .unwrap();
    let models = [FlowTransfer {
        call: "opaque".into(),
        arguments: vec![0],
        receiver: false,
    }];
    let found = flow.field_origins(sink.inputs[0], "body", &models, 1000);
    assert!(found.incomplete);
    assert!(found.values.is_empty());
}

/// A method on a call result is its own value with its own target, and its
/// receiver points at the inner call. The target is a plain dotted path —
/// `acquire.unwrap`, not `acquire().unwrap` — because a call contributes
/// only the name of what it called; the receiver link, not the spelling,
/// is what records that a call sat in the middle.
#[test]
fn chained_calls_have_distinct_targets_and_receivers() {
    let flow = graph("a.rs", "fn run(){send(acquire(\"key\").unwrap());}");
    let outer = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("acquire.unwrap"))
        .unwrap();
    let inner = &flow.values[outer.receiver.unwrap()];
    assert_eq!(inner.offset, outer.offset);
    assert_eq!(inner.target.as_deref(), Some("acquire"));
    assert_eq!(inner.inputs.len(), 1);
    assert!(outer.inputs.is_empty());
}

#[test]
fn argument_observations_preserve_helper_invocation_context() {
    for literal in ["PRIVATE", "PUBLIC"] {
        let source = format!(
            "function read(name){{return acquire(name)}} function run(){{read('OTHER');send(read('{literal}'));}}"
        );
        let flow = graph("a.js", &source);
        let sink = flow
            .values
            .iter()
            .find(|v| v.target.as_deref() == Some("send"))
            .unwrap()
            .inputs[0];
        let origins = flow.origins(sink, &[], 1000);
        let acquire = origins
            .values
            .iter()
            .find(|v| flow.values[v.value].target.as_deref() == Some("acquire"))
            .unwrap();
        let arguments = flow.argument_origins(acquire, 0, &[], 1000);
        let strings: Vec<_> = arguments
            .values
            .iter()
            .filter_map(|v| match flow.values[v.value].literal.as_ref() {
                Some(Arg::String { value }) => Some(value.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(strings, vec![literal]);
    }
}

#[test]
fn flow_is_lazy_cached_and_uses_the_existing_parse() {
    let file = crate::OpenOptions::new()
        .path(std::path::Path::new("a.py"))
        .open(b"send(acquire())\n");
    file.symbols();
    assert!(file.flow.get().is_none());
    let first = file.flow().unwrap();
    assert!(std::ptr::eq(first, file.flow().unwrap()));
    assert_eq!(file.parse_count(), 1);
    assert!(
        file.values().get("source.value_flow").is_none(),
        "typed facts must not be duplicated into values"
    );
}

/// Run `f` on a thread with a 2 MiB stack, the size of a rayon worker's, so a
/// recursion that only fits the 8 MiB main stack fails here.
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn deep_declarator_chains_bind_without_recursing() {
    // `int ****…p` nests one pointer_declarator per `*`; binding the
    // parameter walked the chain recursively and overflowed the stack.
    let flow = on_small_stack(|| {
        let source = format!("void f(int {}p){{ send(p); }}\n", "*".repeat(60_000));
        graph("a.c", &source)
    });
    assert!(flow.limitations.contains("analysis-budget"));
}

#[test]
fn shallow_declarator_chains_still_bind_their_name() {
    let flow = graph("a.c", "void f(int ***p){ send(p); }\n");
    let send = flow
        .values
        .iter()
        .find(|v| v.target.as_deref() == Some("send"))
        .unwrap();
    let param = flow.functions["f"].parameters[0];
    assert_eq!(send.inputs, vec![param]);
}

#[test]
fn functions_read_globals_without_leaking_their_own_bindings() {
    // Function bodies layer over the module bindings instead of copying
    // them; a function's rebinding must stay inside that function. Functions
    // are evaluated last-defined first, so `rebind` runs before `read` and a
    // leak would hand `read` the value of `other()`.
    let source = "token = acquire()\ndef read():\n    send(token)\ndef rebind():\n    token = other()\n    send(token)\n";
    let flow = graph("m.py", source);
    let mut targets: Vec<_> = flow
        .values
        .iter()
        .filter(|v| v.target.as_deref() == Some("send"))
        .map(|send| flow.values[send.inputs[0]].target.as_deref())
        .collect();
    targets.sort_unstable();
    assert_eq!(targets, vec![Some("acquire"), Some("other")]);
}

#[test]
fn block_scoped_shadows_restore_the_global_binding() {
    let flow = graph(
        "a.js",
        "var x = acquire();\nfunction f(){ { let x = other(); } send(x); }\n",
    );
    assert!(reaches(&flow, "send", "acquire"));
    assert!(!reaches(&flow, "send", "other"));
}

#[test]
fn branch_merges_see_globals_changed_in_one_branch() {
    // A global rebound in one branch merges with the untouched value from
    // the other, though only the branch's layer records the name.
    let source = "x = acquire()\ndef f(c):\n    if c:\n        x = other()\n    else:\n        pass\n    send(x)\n";
    let flow = graph("m.py", source);
    assert!(reaches(&flow, "send", "acquire"));
    assert!(reaches(&flow, "send", "other"));
}

#[test]
fn branches_and_blocks_do_not_copy_every_binding() {
    // Each `if` branch started from a copy of every binding in scope, and
    // each block saved one to restore its declarations: 5k module bindings
    // then 5k `if`s took 90 s.
    let bindings: String = (0..2_000)
        .map(|i| format!("var v{i} = acquire();\n"))
        .collect();
    let source = format!(
        "{bindings}{}if (c) {{ x = other(); }} else {{ if (d) {{ x = third(); }} }}\nsend(v0);\nsink(x);\n",
        "if (c) { let v0 = shadow(); }\n".repeat(2_000)
    );
    let file = crate::OpenOptions::new()
        .path(std::path::Path::new("a.js"))
        .open(source.as_bytes());
    file.metrics();
    let started = std::time::Instant::now();
    let flow = file.flow().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(!flow.limitations.contains("analysis-budget"));
    assert!(reaches(flow, "send", "acquire"));
    assert!(!reaches(flow, "send", "shadow"));
    assert!(reaches(flow, "sink", "other"));
    assert!(reaches(flow, "sink", "third"));
}
#[test]
fn calls_record_whether_they_run_at_load_time() {
    let flow = graph(
        "a.js",
        "const cp = require('child_process');\n\
         if (ready) { cp.execSync('id'); }\n\
         function later() { cp.spawnSync('ls'); }\n",
    );
    let module_level = |target: &str| {
        flow.values
            .iter()
            .find(|v| v.target.as_deref() == Some(target))
            .map(|v| v.module_level)
    };
    assert_eq!(module_level("require"), Some(true));
    // Inside a block, but still load-time code.
    assert_eq!(module_level("cp.execSync"), Some(true));
    assert_eq!(module_level("cp.spawnSync"), Some(false));
}
