use super::*;

/// A query that stops compiling after a grammar bump only logs at runtime
/// and drops that language's symbols, so compile every one here and name
/// each failure.
#[test]
fn every_language_query_compiles() {
    let mut failures = Vec::new();
    for config in &ALL {
        for kind in QueryKind::ALL {
            let source = config.query_source(kind);
            if source.is_empty() {
                continue;
            }
            if let Err(error) = Query::new(&(config.language)(), source) {
                failures.push(format!("{} {} query: {error}", config.name(), kind.label()));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Per-language behaviour is keyed on `Lang`, and its label is the
/// published `source.language` value, so each must belong to exactly one
/// configuration.
#[test]
fn every_config_has_its_own_language_and_label() {
    let langs: std::collections::HashSet<Lang> = ALL.iter().map(|c| c.lang).collect();
    let names: std::collections::HashSet<&str> = ALL.iter().map(|c| c.name()).collect();
    assert_eq!(langs.len(), ALL.len());
    assert_eq!(names.len(), ALL.len());
}

/// Labels resolve to individual dialects. File types select a default;
/// C++ is the fallback dialect of the shared C-family file type.
#[test]
fn file_types_and_labels_resolve_to_their_config() {
    for config in ALL {
        let file_type = config.lang.file_type();
        assert!(std::ptr::eq(config_named(config.name()).unwrap(), config));
        if config.lang == Lang::Cpp {
            assert_eq!(config_for(file_type).unwrap().lang, Lang::C);
        } else {
            assert!(std::ptr::eq(config_for(file_type).unwrap(), config));
        }
        assert_eq!(file_type_named(config.name()), Some(file_type));
    }
    assert_eq!(file_type_named("cobol"), None);
}

#[test]
fn query_cache_compiles_once_and_skips_absent_queries() {
    let first = PYTHON
        .query(QueryKind::Imports)
        .expect("python import query");
    let again = PYTHON
        .query(QueryKind::Imports)
        .expect("python import query");
    assert!(std::ptr::eq(first, again));
    assert!(BASH.query(QueryKind::Classes).is_none());
}
