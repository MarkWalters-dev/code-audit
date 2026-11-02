//! Ghost (phantom) dependency detection: source files importing packages
//! that no manifest declares. Each ecosystem wires [`scan`] with its own
//! import extractor and manifest/transitive membership tests; this module
//! owns the tree walk, the stdlib/builtin exclusion sets, and notice
//! construction. Local-only: no network, no cache.
//!
//! Matching is deliberately conservative — stdlib, builtins, relative
//! imports, and first-party modules are excluded before any manifest
//! test, and ecosystems with lossy import-to-package maps (Kotlin)
//! only flag zero-overlap imports. A flagged import is either a true
//! phantom (works today via a transitive dependency) or a missing
//! dependency entirely; the notice says which.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::discover::skip_dir_name;
use crate::ecosystem::{Notice, NoticeCheck};

/// Files larger than this are skipped (generated bundles, minified
/// assets): import scanning them is noise, not signal.
const MAX_SCAN_BYTES: u64 = 1024 * 1024;

/// Source files under `root` with one of `exts`, sorted for deterministic
/// output. Skips dependency/tool trees via [`skip_dir_name`].
pub fn walk_sources(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !skip_dir_name(&name) {
                    stack.push(path);
                }
                continue;
            }
            let wanted = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.contains(&e));
            if !wanted {
                continue;
            }
            if entry
                .metadata()
                .map(|m| m.len() > MAX_SCAN_BYTES)
                .unwrap_or(true)
            {
                continue;
            }
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Scan `root` for phantom imports. `extract` yields (specifier, line)
/// per file; `direct` tests manifest membership; `transitive` tests
/// lockfile-only membership for the explanatory suffix. One notice per
/// (file, specifier), at the first importing line.
pub fn scan<D, T>(
    root: &Path,
    exts: &[&str],
    extract: fn(&str) -> Vec<(String, u32)>,
    direct: D,
    transitive: T,
) -> Vec<Notice>
where
    D: Fn(&str) -> bool,
    T: Fn(&str) -> bool,
{
    let mut seen = HashSet::new();
    let mut notices = Vec::new();
    for path in walk_sources(root, exts) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let display = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());
        for (spec, line) in extract(&text) {
            if direct(&spec) || !seen.insert((display.clone(), spec.clone())) {
                continue;
            }
            let message = if transitive(&spec) {
                format!("'{spec}' is imported but not declared (present transitively)")
            } else {
                format!("'{spec}' is imported but not declared")
            };
            notices.push(Notice {
                check: NoticeCheck::Ghost,
                name: spec,
                message,
                file: Some(display.clone()),
                line: Some(line),
            });
        }
    }
    notices.sort_by_key(|n| (n.file.clone(), n.line));
    notices
}

/// Root segment of a dotted import (`os.path` -> `os`).
pub fn root_segment(spec: &str) -> &str {
    spec.split('.').next().unwrap_or(spec)
}

// ---------------------------------------------------------------------------
// Extractors: (specifier, 1-based line) per source file.
// ---------------------------------------------------------------------------

/// `import a[.b] [as x], ...` and `from a[.b] import ...`. Relative
/// imports (leading dots) are first-party by construction and skipped.
pub fn python_imports(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let rest = if let Some(r) = line.strip_prefix("import ") {
            r
        } else if let Some(r) = line.strip_prefix("from ") {
            match r.split_whitespace().next() {
                Some(module) if !module.starts_with('.') => {
                    out.push((module.to_string(), idx as u32 + 1));
                    continue;
                }
                _ => continue,
            }
        } else {
            continue;
        };
        for part in rest.split(',') {
            let name = part.split_whitespace().next().unwrap_or("");
            if !name.is_empty() && !name.starts_with('.') {
                out.push((name.to_string(), idx as u32 + 1));
            }
        }
    }
    out
}

/// `import ... from 'x'`, `export ... from 'x'`, `require('x')`,
/// `import('x')`. Relative paths are first-party and skipped.
pub fn node_imports(text: &str) -> Vec<(String, u32)> {
    static FROM_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?:import\s*['"]([^'"]+)['"]|(?:import|export)[^'"]*?from\s*['"]([^'"]+)['"])"#)
            .unwrap()
    });
    static REQ_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?:require|import)\s*\(\s*['"]([^'"]+)['"]"#).unwrap()
    });
    // Multi-line `import { ... } from "spec"`: the closing line carries
    // `from` without the `import` keyword. `} from "x"` is unambiguous.
    static MULTILINE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"^\s*\}\s*from\s*['"]([^'"]+)['"]"#).unwrap()
    });
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("");
        for caps in MULTILINE_RE.captures_iter(line) {
            let spec = caps.get(1).unwrap().as_str().to_string();
            if !spec.starts_with('.') && !spec.starts_with('/') && !spec.is_empty() {
                out.push((spec, idx as u32 + 1));
            }
        }
        for caps in FROM_RE.captures_iter(line) {
            let spec = caps
                .get(1)
                .or_else(|| caps.get(2))
                .unwrap()
                .as_str()
                .to_string();
            if !spec.starts_with('.') && !spec.starts_with('/') && !spec.is_empty() {
                out.push((spec, idx as u32 + 1));
            }
        }
        for caps in REQ_RE.captures_iter(line) {
            // `require(`/`import(` as a method call (`ObjC.import("x")`
            // in a JXA template string) is not a module load.
            let start = caps.get(0).unwrap().start();
            if start > 0
                && let Some(prev) = line[..start].chars().last()
                && (prev.is_alphanumeric() || matches!(prev, '_' | '$' | '.'))
            {
                continue;
            }
            let spec = caps.get(1).unwrap().as_str().to_string();
            if !spec.starts_with('.') && !spec.starts_with('/') && !spec.is_empty() {
                out.push((spec, idx as u32 + 1));
            }
        }
    }
    out
}

/// Package name from a module specifier: `@scope/name/...` keeps two
/// segments, anything else the first.
pub fn node_package(spec: &str) -> &str {
    let bare = spec.strip_prefix("node:").unwrap_or(spec);
    if let Some(rest) = bare.strip_prefix('@') {
        let mut parts = rest.splitn(3, '/');
        match (parts.next(), parts.next()) {
            (Some(scope), Some(name)) => &bare[..1 + scope.len() + 1 + name.len()],
            _ => bare,
        }
    } else {
        bare.split('/').next().unwrap_or(bare)
    }
}

/// `use foo[::...] [as x];`, `use foo::{...};`, `extern crate foo;`.
/// `crate`/`self`/`super` roots are first-party and skipped.
pub fn rust_imports(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("").trim();
        let rest = if let Some(r) = line.strip_prefix("use ") {
            r.trim_end_matches(';').trim()
        } else if let Some(r) = line.strip_prefix("extern crate ") {
            r.trim_end_matches(';').trim()
        } else {
            continue;
        };
        let root = rest.split([':', ' ', '{', ';']).next().unwrap_or("").trim();
        if !root.is_empty() && !matches!(root, "crate" | "self" | "super" | "Self") {
            out.push((root.to_string(), idx as u32 + 1));
        }
    }
    out
}

/// Quoted import paths from `import "..."` / `import (...)` blocks.
/// Only double-quoted paths; backquoted and `import C` are excluded by
/// the caller (`C` is cgo, never a module).
pub fn go_imports(text: &str) -> Vec<(String, u32)> {
    static PATH_RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r#""([^"]+)""#).unwrap());
    let mut out = Vec::new();
    let mut in_block = false;
    for (idx, raw) in text.lines().enumerate() {
        let stripped = raw.split("//").next().unwrap_or("");
        let line = stripped.trim();
        if line.starts_with("import") && line.contains('(') {
            in_block = true;
        }
        let single = line.starts_with("import ") && !line.contains('(');
        if single || in_block {
            for caps in PATH_RE.captures_iter(stripped) {
                let spec = caps.get(1).unwrap().as_str().to_string();
                if !spec.is_empty() {
                    out.push((spec, idx as u32 + 1));
                }
            }
        }
        if in_block && line.contains(')') {
            in_block = false;
        }
    }
    out
}

/// `import a.b.C` lines in Kotlin/Java sources (the `package` line is
/// not an import and never matches).
pub fn kotlin_imports(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if let Some(rest) = line.strip_prefix("import ") {
            let spec = rest.trim().trim_end_matches(';').trim();
            if !spec.is_empty() {
                out.push((spec.to_string(), idx as u32 + 1));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Exclusion sets: what is never a ghost.
// ---------------------------------------------------------------------------

/// Top-level stdlib modules (3.11–3.14 union): importing these never
/// needs a declared dependency.
pub const PYTHON_STDLIB: &[&str] = &[
    "__future__",
    "_thread",
    "abc",
    "aifc",
    "annotationlib",
    "argparse",
    "array",
    "ast",
    "asynchat",
    "asyncio",
    "asyncore",
    "atexit",
    "audioop",
    "base64",
    "bdb",
    "binascii",
    "binhex",
    "bisect",
    "builtins",
    "bz2",
    "cProfile",
    "calendar",
    "cgi",
    "cgitb",
    "chunk",
    "cmath",
    "cmd",
    "code",
    "codecs",
    "codeop",
    "collections",
    "colorsys",
    "compileall",
    "compression",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "crypt",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "doctest",
    "email",
    "encodings",
    "ensurepip",
    "enum",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "grp",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "idlelib",
    "imaplib",
    "imghdr",
    "imp",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "lib2to3",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "mailcap",
    "marshal",
    "math",
    "mimetypes",
    "mmap",
    "modulefinder",
    "msvcrt",
    "multiprocessing",
    "netrc",
    "nis",
    "nntplib",
    "numbers",
    "operator",
    "optparse",
    "os",
    "ossaudiodev",
    "parser",
    "pathlib",
    "pdb",
    "pickle",
    "pickletools",
    "pipes",
    "pkgutil",
    "platform",
    "plistlib",
    "poplib",
    "posix",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "queue",
    "quopri",
    "random",
    "re",
    "readline",
    "reprlib",
    "resource",
    "rlcompleter",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtpd",
    "smtplib",
    "sndhdr",
    "socket",
    "socketserver",
    "sqlite3",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "sunau",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tabnanny",
    "tarfile",
    "telnetlib",
    "tempfile",
    "termios",
    "test",
    "textwrap",
    "threading",
    "time",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "uu",
    "uuid",
    "venv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "winreg",
    "winsound",
    "wsgiref",
    "xdrlib",
    "xml",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "zoneinfo",
];

/// Import root -> distribution name where they differ (normalized form).
/// Covers the common mismatches; anything else compares literally.
pub const PYTHON_ALIASES: &[(&str, &str)] = &[
    ("attr", "attrs"),
    ("bs4", "beautifulsoup4"),
    ("cv2", "opencv-python"),
    ("dateutil", "python-dateutil"),
    ("dotenv", "python-dotenv"),
    ("git", "gitpython"),
    ("jwt", "pyjwt"),
    ("magic", "python-magic"),
    ("openssl", "pyopenssl"),
    ("pil", "pillow"),
    ("serial", "pyserial"),
    ("sklearn", "scikit-learn"),
    ("usb", "pyusb"),
    ("yaml", "pyyaml"),
];

/// Node builtins (bare and `node:`-prefixed forms both reduce here).
pub const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "bun",
    "child_process",
    "cluster",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "sea",
    "sqlite",
    "stream",
    "string_decoder",
    "sys",
    "test",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Crates that need no manifest entry.
pub const RUST_STDLIB: &[&str] = &["std", "core", "alloc", "test", "proc_macro"];

/// PEP 503 normalization for distribution-name comparison.
pub fn normalize_dist(name: &str) -> String {
    name.to_lowercase().replace(['-', '_', '.'], "-")
}

/// Crate-name comparison: `-` and `_` are interchangeable.
pub fn normalize_crate(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Directories under `root` (including `root` itself) matching
/// `is_manifest`: nested same-ecosystem manifests whose declarations
/// union into the project's declared set (monorepos suppress nested
/// projects, so the parent must cover member manifests or every
/// member-only import false-positives).
pub fn find_manifest_dirs(root: &Path, is_manifest: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if skip_dir_name(&name) {
                continue;
            }
            if is_manifest(&path) {
                out.push(path.clone());
            }
            stack.push(path);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// First-party top-level modules: `x.py` stems and `x/__init__.py`
/// packages directly under `root`.
pub fn local_python_modules(root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() {
            if path.join("__init__.py").is_file() {
                out.insert(name);
            }
        } else if let Some(stem) = name.strip_suffix(".py") {
            out.insert(stem.to_string());
        }
    }
    out
}

/// Declared transitive-only names, for the explanatory suffix.
pub fn transitive_names(
    inventory: &[crate::ecosystem::Dep],
    normalize: fn(&str) -> String,
) -> HashSet<String> {
    inventory
        .iter()
        .filter(|d| !d.direct)
        .map(|d| normalize(&d.name))
        .collect()
}

/// Alias map as a lookup table.
pub fn alias_map() -> HashMap<&'static str, &'static str> {
    PYTHON_ALIASES.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_extracts_roots_and_skips_relative() {
        let src = "import os\nimport a.b as c, d\nfrom x.y import z\nfrom . import q\nfrom .w import e\n# import nope\n";
        let got = python_imports(src);
        assert_eq!(
            got,
            vec![
                ("os".to_string(), 1),
                ("a.b".to_string(), 2),
                ("d".to_string(), 2),
                ("x.y".to_string(), 3),
            ]
        );
    }

    #[test]
    fn node_extracts_specifiers_and_skips_relative() {
        let src = "import x from 'lodash';\nconst y = require(\"./local\");\nimport('fs');\nexport { z } from \"@scope/pkg/sub\";\nObjC.import(\"AppKit\");\nfoo.require(\"bar\");\n";
        let got = node_imports(src);
        assert_eq!(
            got,
            vec![
                ("lodash".to_string(), 1),
                ("fs".to_string(), 3),
                ("@scope/pkg/sub".to_string(), 4),
            ]
        );
        assert_eq!(node_package("@scope/pkg/sub"), "@scope/pkg");
        assert_eq!(node_package("lodash/fp"), "lodash");
        assert_eq!(node_package("node:fs"), "fs");
    }

    #[test]
    fn rust_extracts_crate_roots() {
        let src = "use serde::{Serialize, Deserialize};\nuse crate::util;\nuse super::x;\nextern crate foo;\nuse std::collections::HashMap; // comment\n";
        let got = rust_imports(src);
        assert_eq!(
            got,
            vec![
                ("serde".to_string(), 1),
                ("foo".to_string(), 4),
                ("std".to_string(), 5),
            ]
        );
    }

    #[test]
    fn go_extracts_quoted_paths_in_imports() {
        let src = "package main\n\nimport (\n\t\"fmt\"\n\talias \"github.com/x/y\"\n)\n\nvar s = \"not an import\"\nimport \"os\"\n";
        let got = go_imports(src);
        assert_eq!(
            got,
            vec![
                ("fmt".to_string(), 4),
                ("github.com/x/y".to_string(), 5),
                ("os".to_string(), 9),
            ]
        );
    }

    #[test]
    fn kotlin_extracts_imports_not_package() {
        let src = "package com.example\n\nimport androidx.core.app.AppCompatActivity\nimport java.util.List\n";
        let got = kotlin_imports(src);
        assert_eq!(
            got,
            vec![
                ("androidx.core.app.AppCompatActivity".to_string(), 3),
                ("java.util.List".to_string(), 4),
            ]
        );
    }

    #[test]
    fn scan_flags_only_undeclared_with_transitive_note() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.py"),
            "import os\nimport ghost1\nimport ghost1\nimport transit\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("b.py"), "import ghost2\n").unwrap();
        let direct = |s: &str| s == "os";
        let transitive = |s: &str| s == "transit";
        let notices = scan(dir.path(), &["py"], python_imports, direct, transitive);
        assert_eq!(notices.len(), 3);
        assert_eq!(notices[0].file.as_deref(), Some("a.py"));
        assert_eq!(notices[0].line, Some(2));
        assert_eq!(notices[0].check, NoticeCheck::Ghost);
        assert!(notices[0].message.contains("not declared"));
        assert!(!notices[0].message.contains("transitively"));
        assert!(notices[1].message.contains("present transitively"));
        assert_eq!(notices[2].file.as_deref(), Some("b.py"));
    }
}
