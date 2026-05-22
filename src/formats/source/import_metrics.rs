//! Import metrics ported from cleave.
//!
//! Takes the list of import names already extracted by the
//! tree-sitter query in [`super::extract`] and emits `imports.*`
//! keys: total, unique, stdlib/third-party split, relative imports,
//! wildcard/dynamic/aliased imports, and their ratios.

use std::collections::HashSet;

use crate::output::Metrics;

/// Emit `imports.*` metrics. `language` is the canonical name from
/// [`super::langs::LangConfig::name`] — `"python"`, `"javascript"`,
/// `"go"`, etc.
pub(super) fn emit(imports: &[&str], language: &str, metrics: &mut Metrics) {
    if imports.is_empty() {
        return;
    }

    // `imports.count` is emitted by `lib.rs::extract_all` once
    // (cross-format). We compute the local total here only for
    // the ratio metrics below.
    let total = imports.len() as u32;

    let mut unique_modules: HashSet<&str> = HashSet::new();
    let mut stdlib_count = 0u32;
    let mut third_party_count = 0u32;
    let mut relative_count = 0u32;
    let mut dynamic_count = 0u32;
    let mut wildcard_count = 0u32;
    let mut aliased_count = 0u32;

    for module in imports {
        unique_modules.insert(*module);

        if module.starts_with('.') || module.starts_with("./") || module.starts_with("../") {
            relative_count += 1;
        }
        if is_stdlib_module(module, language) {
            stdlib_count += 1;
        } else {
            third_party_count += 1;
        }
        if module.contains("__import__")
            || module.contains("importlib")
            || module.contains("require")
        {
            dynamic_count += 1;
        }
        if module.contains('*') || module.ends_with(".*") {
            wildcard_count += 1;
        }
        if module.contains(" as ") {
            aliased_count += 1;
        }
    }

    metrics.insert("imports.unique_modules", unique_modules.len() as f64);
    if stdlib_count > 0 {
        metrics.insert("imports.stdlib_count", f64::from(stdlib_count));
    }
    if third_party_count > 0 {
        metrics.insert("imports.third_party_count", f64::from(third_party_count));
    }
    if relative_count > 0 {
        metrics.insert("imports.relative_imports", f64::from(relative_count));
    }
    if dynamic_count > 0 {
        metrics.insert("imports.dynamic_imports", f64::from(dynamic_count));
    }
    if wildcard_count > 0 {
        metrics.insert("imports.wildcard_imports", f64::from(wildcard_count));
    }
    if aliased_count > 0 {
        metrics.insert("imports.aliased_imports", f64::from(aliased_count));
    }
    let total_f = f64::from(total);
    if total_f > 0.0 {
        if stdlib_count > 0 {
            metrics.insert("imports.stdlib_ratio", f64::from(stdlib_count) / total_f);
        }
        if third_party_count > 0 {
            metrics.insert(
                "imports.third_party_ratio",
                f64::from(third_party_count) / total_f,
            );
        }
        if relative_count > 0 {
            metrics.insert(
                "imports.relative_ratio",
                f64::from(relative_count) / total_f,
            );
        }
    }
}

fn is_stdlib_module(module: &str, language: &str) -> bool {
    match language {
        "python" => is_python_stdlib(module),
        "javascript" | "typescript" => is_node_stdlib(module),
        "go" => is_go_stdlib(module),
        _ => false,
    }
}

fn is_python_stdlib(module: &str) -> bool {
    let top_level = module.split('.').next().unwrap_or(module);
    matches!(
        top_level,
        "abc"
            | "argparse"
            | "array"
            | "ast"
            | "asyncio"
            | "base64"
            | "binascii"
            | "builtins"
            | "bz2"
            | "calendar"
            | "collections"
            | "concurrent"
            | "configparser"
            | "copy"
            | "csv"
            | "ctypes"
            | "dataclasses"
            | "datetime"
            | "decimal"
            | "difflib"
            | "dis"
            | "email"
            | "enum"
            | "errno"
            | "faulthandler"
            | "fcntl"
            | "filecmp"
            | "fnmatch"
            | "functools"
            | "gc"
            | "getpass"
            | "glob"
            | "gzip"
            | "hashlib"
            | "hmac"
            | "http"
            | "importlib"
            | "inspect"
            | "io"
            | "ipaddress"
            | "itertools"
            | "json"
            | "logging"
            | "math"
            | "mimetypes"
            | "multiprocessing"
            | "operator"
            | "os"
            | "pathlib"
            | "pickle"
            | "platform"
            | "pprint"
            | "pwd"
            | "queue"
            | "random"
            | "re"
            | "resource"
            | "select"
            | "shlex"
            | "shutil"
            | "signal"
            | "socket"
            | "sqlite3"
            | "ssl"
            | "stat"
            | "string"
            | "struct"
            | "subprocess"
            | "sys"
            | "syslog"
            | "tarfile"
            | "tempfile"
            | "textwrap"
            | "threading"
            | "time"
            | "timeit"
            | "traceback"
            | "types"
            | "typing"
            | "unittest"
            | "urllib"
            | "uuid"
            | "warnings"
            | "weakref"
            | "xml"
            | "zipfile"
            | "zlib"
    )
}

fn is_node_stdlib(module: &str) -> bool {
    let module = module.strip_prefix("node:").unwrap_or(module);
    matches!(
        module,
        "assert"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "dns"
            | "domain"
            | "events"
            | "fs"
            | "http"
            | "http2"
            | "https"
            | "inspector"
            | "module"
            | "net"
            | "os"
            | "path"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "repl"
            | "stream"
            | "string_decoder"
            | "sys"
            | "timers"
            | "tls"
            | "tty"
            | "url"
            | "util"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
}

fn is_go_stdlib(module: &str) -> bool {
    let top_level = module.split('/').next().unwrap_or(module);
    matches!(
        top_level,
        "archive"
            | "bufio"
            | "bytes"
            | "compress"
            | "container"
            | "context"
            | "crypto"
            | "database"
            | "debug"
            | "encoding"
            | "errors"
            | "expvar"
            | "flag"
            | "fmt"
            | "go"
            | "hash"
            | "html"
            | "image"
            | "index"
            | "io"
            | "log"
            | "math"
            | "mime"
            | "net"
            | "os"
            | "path"
            | "plugin"
            | "reflect"
            | "regexp"
            | "runtime"
            | "sort"
            | "strconv"
            | "strings"
            | "sync"
            | "syscall"
            | "testing"
            | "text"
            | "time"
            | "unicode"
            | "unsafe"
    )
}
