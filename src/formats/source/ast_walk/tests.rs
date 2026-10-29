use super::*;

fn walk_state(path: &str, src: &str) -> State {
    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new(path))
        .open(src.as_bytes());
    let ast = parsed.source_ast().expect("parsed source");
    let config = super::super::langs::config_for(ast.file_type).expect("language config");
    let mut collectors = visit::Collectors {
        ast: Some(State::default()),
        ..visit::Collectors::default()
    };
    visit::walk(ast.tree.root_node(), ast.source, config, &mut collectors);
    collectors.ast.expect("ast collector")
}

/// `function_count` is the denominator of the const/string-return ratios,
/// so every kind the shape detectors accept must be counted, Rust `fn`
/// items included.
#[test]
fn rust_fn_items_count_toward_the_function_total() {
    let state = walk_state(
        "lib.rs",
        "fn a() {}\nfn b() -> u8 { 1 }\nimpl X { fn c(&self) {} }\n",
    );
    assert_eq!(state.function_count, 3);
}

/// Python lambdas are counted as functions (once each, not again for the
/// `lambda` keyword), so the shape detectors must see them too.
/// `lambda: 0` has no parameter list at all.
#[test]
fn python_lambdas_take_constant_and_string_return_shapes() {
    let state = walk_state(
        "shapes.py",
        "a = lambda: 0\nb = lambda: None\nc = lambda x: 0\nd = lambda: 'x'\ne = lambda x: x\n",
    );
    assert_eq!(state.function_count, 5);
    assert_eq!(state.const_return_fn_count, 3);
    assert_eq!(state.string_return_fn_count, 1);
    assert_eq!(state.identity_fn_count, 1);
    // A JavaScript arrow's lone parameter sits outside `parameters`.
    assert_eq!(walk_state("a.js", "f = x => 0;\n").const_return_fn_count, 0);
}

/// Each chain is resolved once, at its outermost node, and every call and
/// member inside it reads its path from that one resolution. Resolving the
/// rest of the chain again at each link is quadratic in the chain's length,
/// which the joint count, bounded here by the node count, would show
/// whatever the machine's load.
#[test]
fn long_chains_resolve_in_linear_work() {
    let calls: String = (0..80)
        .map(|i| format!("x = a{i}{};\n", ".b()".repeat(450)))
        .collect();
    let members: String = (0..40)
        .map(|i| format!("y = c{i}{};\n", ".d".repeat(3_000)))
        .collect();
    let source = calls + &members;
    let state = walk_state("chain.js", &source);
    let joints: usize = state.spines.iter().map(|spine| spine.joints.len()).sum();
    assert!(
        joints as u64 <= state.node_count,
        "{joints} joints for {} nodes",
        state.node_count
    );

    let parsed = crate::OpenOptions::new()
        .path(std::path::Path::new("chain.js"))
        .open(source.as_bytes());
    let targets: Vec<Option<&str>> = parsed
        .symbols()
        .iter_kind(crate::SymbolKind::Call)
        .filter_map(|s| match s {
            crate::Symbol::Call { target, .. } => Some(target.as_deref()),
            _ => None,
        })
        .collect();
    // Every call keeps its own path.
    assert_eq!(targets.len(), 80 * 450);
    assert!(targets.iter().all(Option::is_some));
    let longest = format!("a0{}", ".b".repeat(450));
    assert!(targets.contains(&Some(longest.as_str())));
    assert!(targets.contains(&Some("a0.b")));
    assert!(targets.contains(&Some("a79.b.b")));
    // A member chain past the cap has no static path; the call chains'
    // members do.
    let metrics = parsed.metrics();
    assert_eq!(metrics.get("ast.depth_capped"), Some(1.0));
    assert_eq!(metrics.get("ast.max_member_depth"), Some(451.0));
}
