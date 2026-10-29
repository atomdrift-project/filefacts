//! Compiles the generated Clojure parser. The grammar has no external scanner.

fn main() {
    let src = std::path::Path::new("grammar-src/src");
    cc::Build::new()
        .include(src)
        .file(src.join("parser.c"))
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-but-set-variable")
        .flag_if_supported("-Wno-trigraphs")
        .compile("tree-sitter-clojure");
    println!("cargo:rerun-if-changed=grammar-src/src");
}
