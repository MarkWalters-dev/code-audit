//! Dead code and zombie asset detection: source files nothing imports
//! and media files nothing references. Each ecosystem contributes its
//! own entry-point rules (what is reachable without being imported) and
//! import-graph edges; shared tree walking comes from [`ghost`].
//! Local-only: no network, no cache.
//!
//! All matching errs toward silence: an ambiguous file is reported live,
//! never dead. A flagged file is either truly orphaned or reachable only
//! through a mechanism below the scanner's sight (reflection, codegen,
//! dynamic imports) — the notice is a prompt to look, not proof.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ecosystem::{Notice, NoticeCheck};
use crate::ghost::{find_manifest_dirs, walk_sources};

/// Notice for one dead file or asset.
fn dead_notice(rel: &str, message: String) -> Notice {
    Notice {
        check: NoticeCheck::DeadCode,
        name: rel.to_string(),
        message,
        file: Some(rel.to_string()),
        line: None,
    }
}

/// Root-relative display path.
fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// Single-pass foreign-mention index.
// ---------------------------------------------------------------------------

/// Which needle patterns appear in a file other than their owner's, via
/// one Aho-Corasick pass over the joined texts. This replaces the old
/// per-candidate full-corpus scan: candidates × corpus bytes was
/// quadratic (minutes on monorepos), this is linear.
///
/// `texts` are the corpus files in order; each owner is
/// `(owner_file, needles)` where `owner_file` is the owner's own index
/// into `texts` (`None` when the owner is not a corpus file, e.g. an
/// asset). Returns per-owner liveness: true when any needle occurs in
/// any file other than the owner's own.
fn foreign_mentioned(texts: &[String], owners: &[(Option<usize>, Vec<String>)]) -> Vec<bool> {
    let mut patterns: Vec<&str> = Vec::new();
    let mut pattern_owner: Vec<usize> = Vec::new();
    for (owner_idx, (_, needles)) in owners.iter().enumerate() {
        for needle in needles {
            if !needle.is_empty() {
                patterns.push(needle.as_str());
                pattern_owner.push(owner_idx);
            }
        }
    }
    let Ok(ac) = aho_corasick::AhoCorasick::new(&patterns) else {
        return naive_foreign_mentioned(texts, owners);
    };
    // Joined haystack with file-start boundaries for match attribution.
    let mut joined = String::new();
    let mut starts: Vec<usize> = Vec::with_capacity(texts.len());
    for text in texts {
        starts.push(joined.len());
        joined.push_str(text);
        joined.push('\n');
    }
    let mut foreign = vec![false; owners.len()];
    let mut unresolved = owners.len();
    for mat in ac.find_overlapping_iter(&joined) {
        let owner = pattern_owner[mat.pattern().as_usize()];
        if foreign[owner] {
            continue;
        }
        // File holding the match start (boundaries are sorted).
        let file = starts
            .partition_point(|&s| s <= mat.start())
            .saturating_sub(1);
        // A match outside the owner's own file (or the owner has no
        // corpus file, e.g. an asset): resolved, never revisited.
        if owners[owner].0.is_none_or(|own| own != file) {
            foreign[owner] = true;
            unresolved -= 1;
            if unresolved == 0 {
                break;
            }
        }
    }
    foreign
}

/// Correctness fallback when the automaton cannot be built
/// (essentially unreachable at our pattern counts): the naive
/// per-owner scan with identical semantics.
fn naive_foreign_mentioned(texts: &[String], owners: &[(Option<usize>, Vec<String>)]) -> Vec<bool> {
    owners
        .iter()
        .map(|(owner_file, needles)| {
            texts.iter().enumerate().any(|(i, text)| {
                owner_file.is_none_or(|own| own != i)
                    && needles.iter().any(|n| !n.is_empty() && text.contains(n))
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Python: modules nothing imports.
// ---------------------------------------------------------------------------

/// Python files never imported by anyone, excluding entry points
/// (`__init__`, `__main__`, `__main__`-guarded scripts, runners,
/// tests). A nested `pkg/mod.py` provides both `pkg.mod` and `mod`;
/// `from pkg import mod` expands to `pkg.mod`.
pub fn python_dead(root: &Path) -> Vec<Notice> {
    let files = walk_sources(root, &["py"]);
    let mut imported = HashSet::new();
    let mut texts: Vec<(PathBuf, String)> = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        imported.extend(python_import_candidates(&text));
        texts.push((path.clone(), text));
    }
    let manifest_dirs = find_manifest_dirs(root, &|d| {
        d.join("pyproject.toml").is_file() || d.join("setup.py").is_file()
    });
    let mut out = Vec::new();
    for (path, text) in &texts {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if is_python_entry(name, text) {
            continue;
        }
        let provides = python_provides(&manifest_dirs, path);
        if provides.iter().any(|p| imported.contains(p)) {
            continue;
        }
        out.push(dead_notice(
            &rel_path(root, path),
            "unreferenced module (never imported)".to_string(),
        ));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Module paths plus `from x import y` expansions (`x.y`).
fn python_import_candidates(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if let Some(rest) = line.strip_prefix("import ") {
            for part in rest.split(',') {
                let name = part.split_whitespace().next().unwrap_or("");
                if !name.is_empty() && !name.starts_with('.') {
                    out.insert(name.to_string());
                }
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            let mut words = rest.split_whitespace();
            let module = words.next().unwrap_or("");
            if module.is_empty() || module.starts_with('.') {
                continue;
            }
            out.insert(module.to_string());
            if words.next() == Some("import") {
                for name in words {
                    let clean = name.trim_matches(|c| c == '(' || c == ')' || c == ',');
                    if clean.is_empty() || clean == "*" {
                        continue;
                    }
                    out.insert(format!("{module}.{clean}"));
                }
            }
        }
    }
    out
}

/// Entry points: package markers, runners, `__main__` guards, tests.
fn is_python_entry(file_name: &str, text: &str) -> bool {
    matches!(
        file_name,
        "__init__.py"
            | "__main__.py"
            | "conftest.py"
            | "setup.py"
            | "manage.py"
            | "wsgi.py"
            | "asgi.py"
    ) || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || (text.contains("__name__") && text.contains("__main__"))
}

/// Dotted names a file provides, relative to each manifest dir that
/// contains it (plus the bare stem, conservatively).
fn python_provides(manifest_dirs: &[PathBuf], path: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        out.insert(stem.to_string());
    }
    for dir in manifest_dirs {
        let Ok(rel) = path.strip_prefix(dir) else {
            continue;
        };
        let mut parts: Vec<&str> = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        let Some(last) = parts.pop() else { continue };
        let stem = last.strip_suffix(".py").unwrap_or(last);
        if stem == "__init__" {
            if !parts.is_empty() {
                out.insert(parts.join("."));
            }
        } else {
            parts.push(stem);
            out.insert(parts.join("."));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Node: files nothing relatively imports.
// ---------------------------------------------------------------------------

/// Files no relative import reaches, excluding tests, configs, type
/// declarations, framework entries, and manifest entry points. Alias
/// imports (`@/...`) resolve through tsconfig `paths` when available.
/// Anything left is checked once against a whole-tree string corpus so
/// files referenced by path strings (workers, router maps, plugins)
/// are not flagged.
pub fn node_dead(
    root: &Path,
    aliases: &[(String, Vec<String>)],
    entries: &HashSet<PathBuf>,
) -> Vec<Notice> {
    let exts = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];
    let files = walk_sources(root, &exts);
    // Metro platform variants (`.ios.`/`.android.`/...) exist only in
    // React Native trees: skip the 32-probe platform check per import
    // when the tree has none.
    let has_platform_files = files.iter().any(|p| {
        p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n.contains(".ios.")
                || n.contains(".android.")
                || n.contains(".native.")
                || n.contains(".web.")
        })
    });
    let mut texts: Vec<(&PathBuf, String)> = Vec::with_capacity(files.len());
    let mut used: HashSet<PathBuf> = HashSet::new();
    // Barrel and utility imports repeat hundreds of times: resolve each
    // (importer dir, spec) once.
    let mut memo: HashMap<(PathBuf, String), Vec<PathBuf>> = HashMap::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(dir) = path.parent() {
            for spec in node_all_imports(&text) {
                let key = (dir.to_path_buf(), spec.clone());
                let targets = memo.entry(key).or_insert_with_key(|(dir, spec)| {
                    resolve_import(root, dir, spec, aliases, &exts, has_platform_files)
                });
                for target in targets {
                    used.insert(target.clone());
                }
            }
        }
        texts.push((path, text));
    }
    let conventions = node_conventions(root, &files);
    // Config/markup references count too (app.json plugins, index.html
    // entry scripts, tsconfig file lists): corpus only, never candidates.
    let mut corpus: Vec<String> = texts.iter().map(|(_, t)| t.clone()).collect();
    for path in walk_sources(root, &["json", "html", "htm"]) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            corpus.push(text);
        }
    }
    // Survivors of the graph checks become mention-index owners: the
    // basename, plus the stem for extensionless refs (`./plugins/foo`
    // in app.json) when long enough to not match prose by accident.
    let mut candidates: Vec<usize> = Vec::new();
    let mut owners: Vec<(Option<usize>, Vec<String>)> = Vec::new();
    for (idx, (path, text)) in texts.iter().enumerate() {
        if used.contains(*path)
            || entries.contains(*path)
            || is_node_entry(path, text, &conventions)
        {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let mut needles = vec![name.to_string()];
        if let Some((stem, _)) = name.rsplit_once('.')
            && stem.len() >= 8
        {
            needles.push(stem.to_string());
        }
        candidates.push(idx);
        owners.push((Some(idx), needles));
    }
    let mentioned = foreign_mentioned(&corpus, &owners);
    let mut out = Vec::new();
    for (candidate_pos, idx) in candidates.iter().enumerate() {
        // Referenced by a bare path string somewhere else (worker URL,
        // plugin map, dynamic segment)? Occurrences beyond the file's own
        // text mean another file mentions it.
        if mentioned[candidate_pos] {
            continue;
        }
        out.push(dead_notice(
            &rel_path(root, texts[*idx].0),
            "unreferenced file (never imported)".to_string(),
        ));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Precomputed framework-entry markers for [`node_dead`].
struct NodeConventions {
    /// Subtrees that are file routers (expo `app/` with `_layout`, …).
    router_roots: Vec<PathBuf>,
    /// Nuxt auto-import dirs apply (components/composables/…) when set.
    nuxt: bool,
}

/// Framework entries: expo-router roots (a dir containing `_layout.*`),
/// plus whether Nuxt auto-import conventions apply anywhere.
fn node_conventions(root: &Path, files: &[PathBuf]) -> NodeConventions {
    let mut router_roots = Vec::new();
    for path in files {
        if path
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s == "_layout")
            && let Some(dir) = path.parent()
        {
            router_roots.push(dir.to_path_buf());
        }
    }
    // `find_manifest_dirs` always includes `root` itself, so test the
    // predicate directly: root plus any matching subdir.
    let has_nuxt_config = |d: &Path| {
        d.join("nuxt.config.ts").is_file()
            || d.join("nuxt.config.js").is_file()
            || d.join("nuxt.config.mjs").is_file()
    };
    let nuxt = has_nuxt_config(root) || find_manifest_dirs(root, &has_nuxt_config).len() > 1;
    NodeConventions { router_roots, nuxt }
}

/// Never dead: tests, fixtures, stories, runner dirs, file-router
/// subtrees, framework entries, configs, ambient declarations,
/// shebang CLIs.
fn is_node_entry(path: &Path, text: &str, conventions: &NodeConventions) -> bool {
    if text.starts_with("#!") {
        return true;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.contains(".test.")
        || name.contains(".spec.")
        || name.contains(".stories.")
        || name.contains(".fixture.")
        || name.contains(".config.")
        || name.ends_with(".d.ts")
        || name.starts_with('+')
        || matches!(
            name,
            "eslint.config.js"
                | "eslint.config.mjs"
                | "eslint.config.cjs"
                | "eslint.config.ts"
                | "postcss.config.js"
                | "tailwind.config.js"
                | "tailwind.config.ts"
                | "prettier.config.js"
                | "commitlint.config.js"
        )
    {
        return true;
    }
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let mut under_app = false;
    for comp in path.components() {
        let s = comp.as_os_str().to_string_lossy();
        let lower = s.to_lowercase();
        // Runner, test, fixture, and story trees hold entries by nature.
        if matches!(
            lower.as_str(),
            "test"
                | "tests"
                | "__tests__"
                | "e2e"
                | "fixtures"
                | "__fixtures__"
                | "mocks"
                | "__mocks__"
                | "stories"
                | "__stories__"
                | "scripts"
        ) {
            return true;
        }
        // File-router subtrees (Next/Remix/TanStack/Astro/Gatsby pages
        // and routes) are loaded by glob, never imported.
        if lower == "pages" || lower == "routes" {
            return true;
        }
        if lower == "app" {
            under_app = true;
        }
        // Nuxt auto-imports these dirs without import statements.
        if conventions.nuxt
            && matches!(
                lower.as_str(),
                "components"
                    | "composables"
                    | "utils"
                    | "layouts"
                    | "middleware"
                    | "plugins"
                    | "server"
            )
        {
            return true;
        }
    }
    // Expo-router root (dir with `_layout.*`): the whole subtree.
    if conventions
        .router_roots
        .iter()
        .any(|router| path.starts_with(router))
    {
        return true;
    }
    // Next app-router segments and framework shell files.
    if (under_app
        && matches!(
            stem,
            "page"
                | "layout"
                | "loading"
                | "error"
                | "not-found"
                | "route"
                | "template"
                | "default"
        ))
        || matches!(
            stem,
            "_app" | "_document" | "_error" | "middleware" | "instrumentation"
        )
        || (conventions.nuxt && matches!(stem, "app" | "error"))
    {
        return true;
    }
    false
}

/// All static import specifiers, relative ones included.
fn node_all_imports(text: &str) -> Vec<String> {
    // One pass per line: side-effect imports, `from` imports/exports,
    // `require`/`import()` calls, and multi-line `} from "x"` closers.
    static COMBINED_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(concat!(
            r#"(?:import\s*['"](?P<side>[^'"]+)['"]"#,
            r#"|(?:import|export)[^'"]*?from\s*['"](?P<from>[^'"]+)['"]"#,
            r#"|(?:require|import)\s*\(\s*['"](?P<reqspec>[^'"]+)['"]"#,
            r#"|^\s*\}\s*from\s*['"](?P<multi>[^'"]+)['"])"#,
        ))
        .unwrap()
    });
    let mut out = Vec::new();
    for raw in text.lines() {
        // Every branch needs one of these literals; memchr-fast reject.
        if !raw.contains("import")
            && !raw.contains("export")
            && !raw.contains("require")
            && !raw.contains("from")
        {
            continue;
        }
        let line = raw.split("//").next().unwrap_or("");
        for caps in COMBINED_RE.captures_iter(line) {
            let spec = caps
                .name("side")
                .or_else(|| caps.name("from"))
                .or_else(|| caps.name("multi"))
                .or_else(|| caps.name("reqspec"));
            let Some(spec) = spec else { continue };
            // `require(`/`import(` as a method call (`ObjC.import("x")`)
            // is not a module load.
            if caps.name("reqspec").is_some() {
                let start = caps.get(0).unwrap().start();
                if start > 0
                    && let Some(prev) = line[..start].chars().last()
                    && (prev.is_alphanumeric() || matches!(prev, '_' | '$' | '.'))
                {
                    continue;
                }
            }
            // Side-effect `import` must be a standalone keyword:
            // `value="import" class="…"` (JSX), `"agents-import", …`
            // (strings), and `` `import "…" `` (templates) are not imports.
            if caps.name("side").is_some() {
                let start = caps.get(0).unwrap().start();
                if start > 0
                    && let Some(prev) = line[..start].chars().last()
                    && (prev.is_alphanumeric()
                        || matches!(prev, '_' | '$' | '.' | '"' | '\'' | '`' | '-' | '/' | ':'))
                {
                    continue;
                }
            }
            out.push(spec.as_str().to_string());
        }
    }
    out
}

/// Lexically resolve `.`/`..` segments (no I/O). `is_file` follows
/// `..` on disk, but the returned path would keep it lexically and
/// never match the walked path set, so normalize before resolving.
fn normalize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

/// Resolve an import to live source files: relative paths against the
/// importer dir, aliases through tsconfig targets, bare package
/// imports to nothing (not first-party files). The primary hit plus
/// any Metro platform variants (`x.ios.*`, …) all count as live.
fn resolve_import(
    root: &Path,
    importer_dir: &Path,
    spec: &str,
    aliases: &[(String, Vec<String>)],
    exts: &[&str],
    probe_platforms: bool,
) -> Vec<PathBuf> {
    fn collect(base: &Path, exts: &[&str], probe_platforms: bool, out: &mut Vec<PathBuf>) {
        if let Some(found) = resolve_file(base, exts) {
            out.push(found);
        }
        if probe_platforms {
            out.extend(platform_variants(base, exts));
        }
    }
    let mut out = Vec::new();
    if spec.starts_with('.') {
        collect(
            &normalize_lexical(&importer_dir.join(spec)),
            exts,
            probe_platforms,
            &mut out,
        );
        return out;
    }
    // `~/...` (nuxt/vite convention) is scan-root relative.
    if let Some(rest) = spec.strip_prefix("~/") {
        collect(&root.join(rest), exts, probe_platforms, &mut out);
    }
    for (prefix, targets) in aliases {
        let rest = if spec == prefix {
            Some("")
        } else {
            spec.strip_prefix(&format!("{prefix}/"))
        };
        let Some(rest) = rest else { continue };
        for target in targets {
            let mapped = target.replace('*', rest);
            let base = PathBuf::from(&mapped);
            // Absolute (tsconfig-absolutized) or root-relative (tests).
            let base = if base.is_absolute() {
                base
            } else {
                root.join(mapped.trim_start_matches("./"))
            };
            collect(&base, exts, probe_platforms, &mut out);
        }
    }
    out
}

/// A path with extension probing (`x`, `x.ts`, `x/index.ts`, ...).
/// Probe order matters: exact, then appended, then replaced. A dotted
/// spec (`./foo.types` -> `foo.types.ts`) must not resolve to the
/// sibling `foo.ts` via extension replacement.
fn resolve_file(base: &Path, exts: &[&str]) -> Option<PathBuf> {
    if base.is_file() {
        return Some(base.to_path_buf());
    }
    if base.extension().is_none() {
        // Extensionless: append and replace coincide (`x` -> `x.ts`).
        for ext in exts {
            let appended =
                PathBuf::from(base.as_os_str().to_string_lossy().into_owned() + "." + ext);
            if appended.is_file() {
                return Some(appended);
            }
        }
    } else {
        // Dotted spec: appended first (`x.types` -> `x.types.ts`),
        // replaced second (`x.js` -> `x.ts`, TS source for JS output).
        for ext in exts {
            let appended =
                PathBuf::from(base.as_os_str().to_string_lossy().into_owned() + "." + ext);
            if appended.is_file() {
                return Some(appended);
            }
        }
        for ext in exts {
            let replaced = base.with_extension(ext);
            if replaced.is_file() {
                return Some(replaced);
            }
        }
    }
    if base.is_dir() {
        for ext in exts {
            let index = base.join(format!("index.{ext}"));
            if index.is_file() {
                return Some(index);
            }
        }
    }
    None
}

/// Metro/React Native platform variants of an extensionless base:
/// `x` also brings `x.ios.*`, `x.android.*`, `x.native.*`, `x.web.*`
/// to life. All existing variants are returned; liveness is a set.
fn platform_variants(base: &Path, exts: &[&str]) -> Vec<PathBuf> {
    const PLATS: &[&str] = &["ios", "android", "native", "web"];
    if base.extension().is_some() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for plat in PLATS {
        let stem = base.as_os_str().to_string_lossy().into_owned() + "." + plat;
        for ext in exts {
            let candidate = PathBuf::from(stem.clone() + "." + ext);
            if candidate.is_file() {
                out.push(candidate);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Go: packages nothing imports.
// ---------------------------------------------------------------------------

/// Module subpackages no own-module import reaches, excluding `main`
/// packages and test-only packages. `module_dirs` maps module path ->
/// directory for every go.mod under the root.
pub fn go_dead(root: &Path, module_dirs: &[(String, PathBuf)]) -> Vec<Notice> {
    let files = walk_sources(root, &["go"]);
    let mut used: HashSet<PathBuf> = HashSet::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (spec, _) in crate::ghost::go_imports(&text) {
            for (module, dir) in module_dirs {
                if let Some(rest) = spec.strip_prefix(module.as_str()) {
                    let rel = rest.trim_start_matches('/');
                    let target = if rel.is_empty() {
                        dir.clone()
                    } else {
                        dir.join(rel)
                    };
                    used.insert(target);
                }
            }
        }
    }
    // Candidate package dirs: any dir holding non-test `.go` files.
    let mut packages: HashMap<PathBuf, bool> = HashMap::new();
    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with("_test.go") {
            continue;
        }
        if let Some(dir) = path.parent() {
            packages.entry(dir.to_path_buf()).or_insert(false);
        }
    }
    // `main` packages are entries, never candidates.
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let is_main = text
            .lines()
            .map(str::trim)
            .any(|l| l == "package main" || l.starts_with("package main "));
        if is_main && let Some(dir) = path.parent() {
            packages.remove(dir);
        }
    }
    let mut out = Vec::new();
    for dir in packages.keys() {
        if used.contains(dir) {
            continue;
        }
        out.push(dead_notice(
            &rel_path(root, dir),
            "unreferenced package (never imported)".to_string(),
        ));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ---------------------------------------------------------------------------
// Android: classes nothing references.
// ---------------------------------------------------------------------------

/// Source files whose top-level declarations are never referenced,
/// excluding tests and manifest-registered components. One alternation
/// regex over all sources counts references in a single pass.
pub fn android_dead(root: &Path) -> Vec<Notice> {
    let files = walk_sources(root, &["kt", "kts", "java"]);
    let mut texts: Vec<(PathBuf, String)> = Vec::new();
    for path in &files {
        if let Ok(text) = std::fs::read_to_string(path) {
            texts.push((path.clone(), text));
        }
    }
    let entries = manifest_classes(root);
    // Declared top-level names per file.
    static DECL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?m)^\s*(?:public\s+|internal\s+|open\s+|abstract\s+|sealed\s+|data\s+|enum\s+|annotation\s+)*(?:class|interface|object|enum class|annotation class|fun|val|var)\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        .unwrap()
    });
    let mut declared: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, (_, text)) in texts.iter().enumerate() {
        for caps in DECL_RE.captures_iter(text) {
            declared
                .entry(caps.get(1).unwrap().as_str().to_string())
                .or_default()
                .push(i);
        }
    }
    if declared.is_empty() {
        return Vec::new();
    }
    // Single pass: count whole-word references per name.
    let mut names: Vec<&str> = declared.keys().map(|s| s.as_str()).collect();
    names.sort();
    let pattern = format!(r"\b(?:{})\b", names.join("|"));
    let Ok(refs) = regex::Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (_, text) in &texts {
        for m in refs.find_iter(text) {
            *counts.entry(m.as_str()).or_default() += 1;
        }
    }
    let mut out = Vec::new();
    for (i, (path, _)) in texts.iter().enumerate() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains("Test.") || name.contains("Test_") {
            continue;
        }
        // A file is live when any of its declarations is an entry or is
        // referenced beyond its own declaration.
        let mut live = false;
        for (decl, files_idx) in &declared {
            if !files_idx.contains(&i) {
                continue;
            }
            if entries.contains(decl) || counts.get(decl.as_str()).copied().unwrap_or(0) > 1 {
                live = true;
                break;
            }
        }
        if !live && declared.values().any(|v| v.contains(&i)) {
            out.push(dead_notice(
                &rel_path(root, path),
                "unreferenced file (no references found)".to_string(),
            ));
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Component simple names from every `AndroidManifest.xml`
/// (`android:name`, relative names resolved against `package=`).
fn manifest_classes(root: &Path) -> HashSet<String> {
    static NAME_RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r#"android:name="([^"]+)""#).unwrap());
    let mut out = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !crate::discover::skip_dir_name(&name) {
                    stack.push(path);
                }
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) != Some("AndroidManifest.xml") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for caps in NAME_RE.captures_iter(&text) {
                let full = caps.get(1).unwrap().as_str();
                let simple = full.rsplit('.').next().unwrap_or(full);
                if !simple.is_empty() {
                    out.insert(simple.to_string());
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Zombie assets: media nothing references.
// ---------------------------------------------------------------------------

/// Media, font, and document files whose basename (or stem) appears
/// nowhere in textual sources. Runs once per project: asset references
/// do not respect ecosystem boundaries. `done` holds assets already
/// examined by an ancestor project (nested projects share subtrees):
/// they are skipped, and every examined asset is recorded.
pub fn zombie_assets(root: &Path, done: &mut HashSet<PathBuf>) -> Vec<Notice> {
    const ASSET_EXTS: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "mp3", "wav", "ogg",
        "mp4", "webm", "mov", "pdf", "ttf", "otf", "woff", "woff2",
    ];
    const SOURCE_EXTS: &[&str] = &[
        "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "rb", "php", "sh", "env",
        "json", "yaml", "yml", "toml", "xml", "html", "htm", "css", "scss", "less", "md", "txt",
        "rst", "java", "kt", "kts", "go", "rs", "gradle", "plist",
    ];
    // Implicitly fetched: never flag these.
    const IMPLICIT: &[&str] = &["favicon.ico", "robots.txt", "CNAME", ".nojekyll"];
    let assets = walk_sources(root, ASSET_EXTS);
    if assets.is_empty() {
        return Vec::new();
    }
    let mut corpus = Vec::new();
    for path in walk_sources(root, SOURCE_EXTS) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            corpus.push(text);
        }
    }
    let mut candidates: Vec<(&PathBuf, String)> = Vec::new();
    let mut owners: Vec<(Option<usize>, Vec<String>)> = Vec::new();
    for path in assets.iter().take(5000) {
        // Already examined by an ancestor project's scan.
        if !done.insert(path.clone()) {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if IMPLICIT.contains(&name) {
            continue;
        }
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
        let mut needles = vec![name.to_string()];
        if !stem.is_empty() {
            needles.push(stem.to_string());
        }
        candidates.push((path, name.to_string()));
        owners.push((None, needles));
    }
    let mentioned = foreign_mentioned(&corpus, &owners);
    let mut out = Vec::new();
    for (i, (path, name)) in candidates.iter().enumerate() {
        if !mentioned[i] {
            out.push(dead_notice(
                &rel_path(root, path),
                format!("unreferenced asset '{name}'"),
            ));
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(notices: &[Notice]) -> Vec<&str> {
        notices.iter().map(|n| n.name.as_str()).collect()
    }

    #[test]
    fn python_flags_only_orphans() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.py"),
            "if __name__ == \"__main__\":\n    import used\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("used.py"), "X = 1\n").unwrap();
        std::fs::write(dir.path().join("orphan.py"), "Y = 2\n").unwrap();
        std::fs::write(dir.path().join("test_orphan.py"), "Z = 3\n").unwrap();
        assert_eq!(names(&python_dead(dir.path())), vec!["orphan.py"]);
    }

    #[test]
    fn node_resolves_relative_and_aliases() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("index.js"),
            "import './src/used.js';\nimport '@/src/aliased.js';\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/used.js"), "export const a = 1;\n").unwrap();
        std::fs::write(dir.path().join("src/aliased.js"), "export const b = 2;\n").unwrap();
        std::fs::write(dir.path().join("src/dead.js"), "export const c = 3;\n").unwrap();
        let aliases = vec![("@".to_string(), vec!["./*".to_string()])];
        let entries: HashSet<PathBuf> = [dir.path().join("index.js")].into_iter().collect();
        assert_eq!(
            names(&node_dead(dir.path(), &aliases, &entries)),
            vec!["src/dead.js"]
        );
    }

    #[test]
    fn node_resolves_parent_relative_imports() {
        // Regression: `../components/X` resolved on disk but the returned
        // path kept the lexical `..`, so it never matched the walked path
        // and every cross-directory import looked dead.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src/routes")).unwrap();
        std::fs::create_dir_all(dir.path().join("src/components")).unwrap();
        std::fs::write(
            dir.path().join("src/routes/index.tsx"),
            "import { LandingPage } from \"../components/LandingPage\";\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/components/LandingPage.tsx"),
            "export const LandingPage = 1;\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/components/Dead.tsx"),
            "export const Dead = 2;\n",
        )
        .unwrap();
        let aliases: Vec<(String, Vec<String>)> = Vec::new();
        let entries: HashSet<PathBuf> = HashSet::new();
        let notices = node_dead(dir.path(), &aliases, &entries);
        let dead = names(&notices);
        assert!(
            !dead.contains(&"src/components/LandingPage.tsx"),
            "{dead:?}"
        );
        assert!(dead.contains(&"src/components/Dead.tsx"), "{dead:?}");
    }

    #[test]
    fn node_follows_multiline_imports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.js"),
            "import {\n  x,\n  y,\n} from \"./b\";\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("b.js"), "export const x = 1;\n").unwrap();
        std::fs::write(dir.path().join("dead.js"), "export const z = 2;\n").unwrap();
        let aliases: Vec<(String, Vec<String>)> = Vec::new();
        let entries: HashSet<PathBuf> = [dir.path().join("a.js")].into_iter().collect();
        let notices = node_dead(dir.path(), &aliases, &entries);
        assert_eq!(names(&notices), vec!["dead.js"]);
    }

    #[test]
    fn node_honors_entry_conventions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Router, story, script, fixture, worker-by-string, shebang CLI:
        // all entries by convention, plus one genuinely dead file.
        for d in ["app", "pages", "scripts", "tests", "stories"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("index.js"), "import './live.js';\n").unwrap();
        std::fs::write(root.join("live.js"), "export const a = 1;\n").unwrap();
        std::fs::write(root.join("dead.js"), "export const b = 2;\n").unwrap();
        std::fs::write(root.join("app/_layout.tsx"), "export default 1;\n").unwrap();
        std::fs::write(root.join("app/settings.tsx"), "export default 2;\n").unwrap();
        std::fs::write(root.join("pages/about.tsx"), "export default 3;\n").unwrap();
        std::fs::write(root.join("scripts/seed.ts"), "console.log(1);\n").unwrap();
        std::fs::write(root.join("tests/x.test.ts"), "console.log(1);\n").unwrap();
        std::fs::write(root.join("foo.stories.tsx"), "export default 4;\n").unwrap();
        std::fs::write(
            root.join("cli.mjs"),
            "#!/usr/bin/env node\nconsole.log(1);\n",
        )
        .unwrap();
        std::fs::write(root.join("worker.js"), "onmessage = 1;\n").unwrap();
        std::fs::write(
            root.join("main.js"),
            "new Worker(\"./worker.js\");\nimport './index.js';\n",
        )
        .unwrap();
        // `main.js` is the manifest entry; everything else unreferenced
        // must be a convention entry except `dead.js`.
        let entries: HashSet<PathBuf> = [root.join("main.js")].into_iter().collect();
        let notices = node_dead(root, &[], &entries);
        assert_eq!(names(&notices), vec!["dead.js"]);
    }

    #[test]
    fn node_follows_import_type_and_dotted_specs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.ts"),
            "import type { X } from \"./b.types\";\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("b.types.ts"), "export type X = 1;\n").unwrap();
        std::fs::write(dir.path().join("dead.ts"), "export const z = 2;\n").unwrap();
        let entries: HashSet<PathBuf> = [dir.path().join("a.ts")].into_iter().collect();
        let notices = node_dead(dir.path(), &[], &entries);
        assert_eq!(names(&notices), vec!["dead.ts"]);
    }

    #[test]
    fn node_prefers_appended_over_replaced_extension() {
        // `foo.types` must reach `foo.types.ts`, not the sibling `foo.ts`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.ts"), "import \"./foo.types\";\n").unwrap();
        std::fs::write(dir.path().join("foo.types.ts"), "export const t = 1;\n").unwrap();
        std::fs::write(dir.path().join("foo.ts"), "export const f = 2;\n").unwrap();
        let entries: HashSet<PathBuf> = [dir.path().join("a.ts")].into_iter().collect();
        let notices = node_dead(dir.path(), &[], &entries);
        assert_eq!(names(&notices), vec!["foo.ts"]);
    }

    #[test]
    fn node_marks_platform_variants_live() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.ts"), "import \"./button\";\n").unwrap();
        std::fs::write(dir.path().join("button.ios.tsx"), "export const b = 1;\n").unwrap();
        std::fs::write(
            dir.path().join("button.android.tsx"),
            "export const b = 2;\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("dead.tsx"), "export const d = 3;\n").unwrap();
        let entries: HashSet<PathBuf> = [dir.path().join("a.ts")].into_iter().collect();
        let notices = node_dead(dir.path(), &[], &entries);
        assert_eq!(names(&notices), vec!["dead.tsx"]);
    }

    #[test]
    fn node_sees_json_and_html_references() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            "<script src=\"/src/main.tsx\"></script>\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.tsx"), "console.log(1);\n").unwrap();
        std::fs::write(
            dir.path().join("app.json"),
            "{\"plugins\":[\"./plugins/with-long-name\"]}\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("plugins")).unwrap();
        std::fs::write(
            dir.path().join("plugins/with-long-name.js"),
            "module.exports = 1;\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("dead.js"), "export const d = 1;\n").unwrap();
        let notices = node_dead(dir.path(), &[], &HashSet::new());
        assert_eq!(names(&notices), vec!["dead.js"]);
    }

    #[test]
    fn go_skips_main_and_test_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("used")).unwrap();
        std::fs::create_dir_all(dir.path().join("dead")).unwrap();
        std::fs::create_dir_all(dir.path().join("testonly")).unwrap();
        std::fs::write(
            dir.path().join("main.go"),
            "package main\n\nimport \"example.com/app/used\"\n\nfunc main() {}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("used/u.go"), "package used\n").unwrap();
        std::fs::write(dir.path().join("dead/d.go"), "package dead\n").unwrap();
        std::fs::write(dir.path().join("testonly/t_test.go"), "package testonly\n").unwrap();
        let modules = vec![("example.com/app".to_string(), dir.path().to_path_buf())];
        assert_eq!(names(&go_dead(dir.path(), &modules)), vec!["dead"]);
    }

    #[test]
    fn android_honors_manifest_and_references() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("AndroidManifest.xml"),
            "<manifest><application><activity android:name=\".MainActivity\" /></application></manifest>\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("MainActivity.kt"),
            "class MainActivity(val u: User)\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("Used.kt"), "class Used\n").unwrap();
        std::fs::write(dir.path().join("User.kt"), "class User(val u: Used)\n").unwrap();
        std::fs::write(dir.path().join("Dead.kt"), "class Dead\n").unwrap();
        assert_eq!(names(&android_dead(dir.path())), vec!["Dead.kt"]);
    }

    #[test]
    fn assets_flag_only_unreferenced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<img src=\"logo.png\">\n").unwrap();
        std::fs::write(dir.path().join("logo.png"), "fake").unwrap();
        std::fs::write(dir.path().join("old.svg"), "fake").unwrap();
        std::fs::write(dir.path().join("favicon.ico"), "fake").unwrap();
        assert_eq!(
            names(&zombie_assets(dir.path(), &mut HashSet::new())),
            vec!["old.svg"]
        );
    }
}
