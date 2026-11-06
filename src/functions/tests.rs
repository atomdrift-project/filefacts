use super::*;

fn function(entry: u64, blocks: u32, refs: Vec<binform::Ref>) -> binform::Function {
    let mut function = binform::Function::default();
    function.entry = entry;
    function.size = 16;
    function.blocks = blocks;
    function.complexity = 1;
    function.refs = refs;
    function
}

fn recovery(functions: Vec<binform::Function>) -> binform::Recovery {
    let mut recovery = binform::Recovery::default();
    recovery.functions = functions;
    recovery.code = 100;
    recovery.covered = 100;
    recovery
}

#[test]
fn calls_are_named_by_import_symbol_or_address() {
    let call = |from, to| binform::Ref::new(from, binform::Dest::Code(to), binform::RefKind::Call);
    let mut named = function(0x2000, 1, Vec::new());
    named.name = Some("helper".into());
    let caller = function(
        0x1000,
        2,
        vec![
            call(0x1004, 0x2000),
            call(0x1008, 0x3000),
            call(0x100c, 0x9000),
            call(0x1010, 0x7777),
        ],
    );
    let functions = Functions {
        recovery: recovery(vec![caller, named, function(0x3000, 1, Vec::new())]),
        targets: HashMap::from([(0x9000, "connect".to_string())]),
    };
    let mut symbols = crate::Symbols::default();
    let mut metrics = Metrics::default();
    assert_eq!(functions.apply(&mut symbols, &mut metrics), 3);
    let first = symbols.iter().next().and_then(|s| match s {
        crate::output::Symbol::Function { name, callees, .. } => {
            Some((name.clone(), callees.clone()))
        }
        _ => None,
    });
    assert_eq!(
        first,
        Some((
            "fcn.00001000".to_string(),
            vec![
                "helper".to_string(),
                "fcn.00003000".to_string(),
                "connect".to_string()
            ]
        ))
    );
    assert_eq!(
        metrics.lookup(&metric!("binary.leaf_function_count")),
        Some(2.0)
    );
    assert_eq!(
        metrics.lookup(&metric!("binary.tiny_function_count")),
        Some(2.0)
    );
}

fn sized(entry: u64, size: u64) -> binform::Function {
    let mut function = function(entry, 1, Vec::new());
    function.size = size;
    function
}

/// Every small function holding a connect site is a wrapper, overlapping
/// ones included; a function ending at the site, or one too large to be a
/// wrapper, is not.
#[test]
fn connect_wrappers_are_the_small_functions_holding_the_site() {
    let recovery = recovery(vec![
        sized(0x1000, 0x1000),
        sized(0x1608, 0x200),
        sized(0x1700, 0x200),
        sized(0x1800, 0x40),
        sized(0x1810, 0x10),
    ]);
    assert_eq!(
        connect_wrappers(&recovery, [0x1808]),
        HashSet::from([0x1700, 0x1800])
    );
    assert!(connect_wrappers(&recovery, []).is_empty());
}

/// A connect site is matched against the functions that could hold it, not
/// against every function: a quarter-million sites in a quarter-million
/// functions is a few million steps, not sixty billion.
#[test]
fn connect_wrappers_scale_with_the_sites() {
    const N: u64 = 1 << 18;
    let recovery = recovery((0..N).map(|i| sized(i * 16, 16)).collect());
    let sites = (0..N).map(|i| i * 16 + 4);
    assert_eq!(connect_wrappers(&recovery, sites).len(), 1 << 18);
}

/// Extents that run on through shared tails sum to many times the code;
/// binform's call walk costs that sum in time and in call records, so past
/// the factor each function is walked only up to the next one's entry.
#[test]
fn overlapping_extents_are_walked_to_the_next_entry() {
    let mut tails = recovery(vec![
        sized(0x1000, 0x30_0000),
        sized(0x1100, 0x20_0000),
        sized(0x1200, 0x100),
    ]);
    tails.code = 0x300;
    let walked = walkable(&tails);
    let sizes: Vec<u64> = walked.functions.iter().map(|f| f.size).collect();
    assert_eq!(sizes, [0x100, 0x100, 0x100]);

    // Extents within the factor are walked as recovered.
    let ordinary = recovery(vec![sized(0x1000, 0x40), sized(0x1030, 0x20)]);
    assert!(matches!(walkable(&ordinary), std::borrow::Cow::Borrowed(_)));
}
