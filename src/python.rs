//! Python ecosystem, pure Rust: inventory from installed metadata or
//! requirement declarations, latest versions from the PyPI JSON API.
//!
//! Sources, in order of preference:
//! 1. Installed environment (`.venv`, `$VIRTUAL_ENV`): `*.dist-info/METADATA`
//!    scan — no interpreter needed. Direct deps are computed as the roots of
//!    the `Requires-Dist` graph.
//! 2. Lockfiles (`uv.lock`, `poetry.lock`, `pdm.lock`): pinned name+version.
//! 3. Declarations (`requirements*.txt`, `pyproject.toml`, `Pipfile`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use pep440_rs::{Version, VersionSpecifiers};
use serde::Deserialize;

use crate::ecosystem::{
    Ctx, Dep, EcosystemChecker, Gap, GapCheck, Inventory, LatestInfo, Notice, NoticeCheck,
    OutdatedDep,
};
use crate::http;
use crate::toolchains::{self, ToolId, ToolPin};

pub struct Python;

impl EcosystemChecker for Python {
    fn id(&self) -> &'static str {
        "python"
    }

    fn display(&self) -> &'static str {
        "Python"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "PyPI"
    }

    fn detect(&self, root: &Path) -> bool {
        const MARKERS: &[&str] = &[
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
            "pdm.lock",
        ];
        if root.join(".venv").is_dir() {
            return true;
        }
        if MARKERS.iter().any(|m| root.join(m).is_file()) {
            return true;
        }
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.starts_with("requirements")
                        && (lower.ends_with(".txt") || lower.ends_with(".in"))
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn enumerate(&self, root: &Path) -> Result<Inventory, String> {
        let mut gaps = Vec::new();
        if let Some(deps) = enumerate_installed(root)
            && !deps.is_empty()
        {
            return Ok(Inventory { deps, gaps, notes: Vec::new() });
        }
        for lock in ["uv.lock", "poetry.lock", "pdm.lock"] {
            let path = root.join(lock);
            if path.is_file() {
                let deps = parse_lockfile(&path);
                return Ok(Inventory { deps, gaps, notes: Vec::new() });
            }
        }
        let mut deps = Vec::new();
        deps.extend(parse_requirements_files(root));
        deps.extend(parse_pyproject(root));
        deps.extend(parse_pipfile(root));
        // Deduplicate by name, preferring entries with a known version.
        let mut by_name: HashMap<String, Dep> = HashMap::new();
        for dep in deps {
            match by_name.get(&dep.name) {
                Some(existing) if existing.version.is_some() => {}
                _ => {
                    by_name.insert(dep.name.clone(), dep);
                }
            }
        }
        let mut deps: Vec<Dep> = by_name.into_values().collect();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        gaps.extend(setup_py_gaps(root));
        Ok(Inventory { deps, gaps, notes: Vec::new() })
    }

    fn fetch_latest(&self, _ctx: &Ctx, dep: &Dep) -> Result<LatestInfo, String> {
        #[derive(Deserialize)]
        struct Info {
            version: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            info: Info,
        }
        let url = format!("https://pypi.org/pypi/{}/json", dep.name);
        match http::get_json_retry::<Resp>(&url) {
            Ok(r) => Ok(LatestInfo::simple(r.info.version)),
            Err(e) => Err(toolchains::request_reason("PyPI", &e)),
        }
    }

    fn resolve_version(&self, dep: &Dep) -> Result<Option<String>, String> {
        // No installed/locked version: resolve the spec to the newest release
        // a fresh `pip install` would pick (releases without files are skipped).
        let Some(spec) = dep.spec.as_ref() else {
            return Ok(None);
        };
        let Ok(spec) = spec.parse::<VersionSpecifiers>() else {
            return Ok(None);
        };
        #[derive(Deserialize)]
        struct Resp {
            releases: HashMap<String, Vec<serde_json::Value>>,
        }
        let url = format!("https://pypi.org/pypi/{}/json", dep.name);
        let resp: Resp = match http::get_json_retry(&url) {
            Ok(r) => r,
            Err(e) => return Err(toolchains::request_reason("PyPI", &e)),
        };
        Ok(resp
            .releases
            .into_iter()
            .filter(|(_, files)| !files.is_empty())
            .filter_map(|(v, _)| v.parse::<Version>().ok())
            .filter(|v| spec.contains(v))
            .max()
            .map(|v| v.to_string()))
    }

    fn enumerate_tools(&self, root: &Path) -> Vec<ToolPin> {
        let mut pins = Vec::new();
        // requires-python from pyproject / setup.py / setup.cfg.
        if let Ok(text) = std::fs::read_to_string(root.join("pyproject.toml"))
            && let Ok(doc) = toml::from_str::<toml::Value>(&text)
            && let Some(req) = doc
                .get("project")
                .and_then(|p| p.get("requires-python"))
                .and_then(|v| v.as_str())
        {
            pins.push(ToolPin {
                tool: ToolId::Python,
                display: "python (requires-python)".to_string(),
                version: pin_from_spec(req),
                spec: Some(req.to_string()),
            });
        }
        if let Ok(text) = std::fs::read_to_string(root.join("setup.py"))
            && let Some(req) = setup_python_requires(&text)
        {
            pins.push(ToolPin {
                tool: ToolId::Python,
                display: "python (setup.py python_requires)".to_string(),
                version: pin_from_spec(&req),
                spec: Some(req),
            });
        }
        if let Ok(text) = std::fs::read_to_string(root.join("setup.cfg"))
            && let Some(req) = setup_cfg_python_requires(&text)
        {
            pins.push(ToolPin {
                tool: ToolId::Python,
                display: "python (setup.cfg python_requires)".to_string(),
                version: pin_from_spec(&req),
                spec: Some(req),
            });
        }
        // .python-version (uv / pyenv).
        if let Ok(text) = std::fs::read_to_string(root.join(".python-version")) {
            let version = text.trim().to_string();
            if !version.is_empty() {
                pins.push(ToolPin {
                    tool: ToolId::Python,
                    display: "python (.python-version)".to_string(),
                    version: Some(version),
                    spec: None,
                });
            }
        }
        // Version managers.
        for (source, map) in [
            (".tool-versions", toolchains::parse_tool_versions(root)),
            ("mise", toolchains::parse_mise_toml(root)),
        ] {
            if let Some(version) = map.get("python") {
                pins.push(ToolPin {
                    tool: ToolId::Python,
                    display: format!("python ({source})"),
                    version: Some(version.clone()),
                    spec: None,
                });
            }
        }
        pins
    }

    fn outdated(&self, dep: &Dep, latest: &str) -> Option<OutdatedDep> {
        match &dep.version {
            Some(current) => {
                if pep440_is_newer(current, latest) {
                    Some(OutdatedDep {
                        name: dep.display.clone(),
                        current: current.clone(),
                        latest: latest.to_string(),
                        detail: dep.detail.clone(),
                        blocked: None,
                        stale: None,
                        current_released: None,
                        latest_released: None,
                        days_behind: None,
                    })
                } else {
                    None
                }
            }
            None => Some(OutdatedDep {
                name: dep.display.clone(),
                current: dep
                    .spec
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string()),
                latest: latest.to_string(),
                detail: Some("not installed; latest available".to_string()),
                blocked: None,
                stale: None,
                current_released: None,
                latest_released: None,
                days_behind: None,
            }),
        }
    }

    fn release_dates(
        &self,
        ctx: &Ctx,
        name: &str,
        current: &str,
        latest: &str,
    ) -> (Option<String>, Option<String>) {
        pypi_release_dates(ctx, name, current, latest)
    }

    fn lint(
        &self,
        ctx: &Ctx,
        root: &Path,
        vulns: &[crate::osv::FoundVuln],
    ) -> crate::lint::LintOutcome {
        crate::lint::audit_python(ctx, root, vulns)
    }

    fn dep_licenses(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
        pypi_facts(ctx, name, version).licenses
    }

    fn dep_notice(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<Notice> {
        let facts = pypi_facts(ctx, name, version);
        let mut notices =
            crate::licenses::license_notices(&ctx.license_policy, name, version, &facts.licenses);
        if facts.yanked {
            let message = match &facts.yanked_reason {
                Some(reason) if !reason.is_empty() => {
                    format!("{version} is yanked on PyPI: {reason}")
                }
                _ => format!("{version} is yanked on PyPI"),
            };
            notices.push(Notice {
                check: NoticeCheck::Yanked,
                name: name.to_string(),
                message,
                file: None,
                line: None,
            });
        }
        if let Some(notice) = crate::licenses::eol_notice(ctx, "python", name, version) {
            notices.push(notice);
        }
        notices
    }

    fn project_notices(&self, _ctx: &Ctx, root: &Path, inventory: &[Dep]) -> Vec<Notice> {
        let declared = manifest_names(root);
        let local = local_modules(root);
        let transitive = crate::ghost::transitive_names(inventory, crate::ghost::normalize_dist);
        let stdlib: HashSet<&str> = crate::ghost::PYTHON_STDLIB.iter().copied().collect();
        let aliases = crate::ghost::alias_map();
        let mut notices = crate::ghost::scan(
            root,
            &["py"],
            crate::ghost::python_imports,
            |spec| {
                let r = crate::ghost::root_segment(spec);
                stdlib.contains(r)
                    || local.contains(r)
                    || declared.contains(&resolve_dist(r, &aliases))
            },
            |spec| transitive.contains(&resolve_dist(crate::ghost::root_segment(spec), &aliases)),
        );
        notices.extend(crate::deadcode::python_dead(root));
        notices
    }

    fn update_command(&self, root: &Path, outdated: &[OutdatedDep]) -> Option<String> {
        // Upgrade the environment in place. Run from the project root so the
        // project's own .venv is used; pin files still need manual edits.
        let installer = if root.join("uv.lock").is_file() {
            "uv pip install"
        } else {
            "pip install"
        };
        let pkgs = outdated
            .iter()
            .map(|d| format!("{}=={}", d.name, d.latest))
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!("{installer} -U {pkgs}"))
    }
}

fn pep440_is_newer(current: &str, latest: &str) -> bool {
    match (Version::from_str(current), Version::from_str(latest)) {
        (Ok(a), Ok(b)) => a < b,
        _ => current != latest,
    }
}

/// PEP 503 normalization for registry lookups and name comparison.
fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut dash = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !dash {
                out.push('-');
            }
            dash = true;
        } else {
            dash = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Installed environments: dist-info / egg-info scan
// ---------------------------------------------------------------------------

fn site_package_dirs(root: &Path) -> Vec<PathBuf> {
    let mut venvs = Vec::new();
    let local = root.join(".venv");
    if local.is_dir() {
        venvs.push(local);
    }
    if let Some(env) = std::env::var_os("VIRTUAL_ENV").map(PathBuf::from)
        && env.is_dir()
        && !venvs.contains(&env)
    {
        venvs.push(env);
    }
    let mut dirs = Vec::new();
    for venv in venvs {
        #[cfg(windows)]
        {
            let win = venv.join("Lib").join("site-packages");
            if win.is_dir() {
                dirs.push(win);
            }
        }
        let lib = venv.join("lib");
        if let Ok(entries) = std::fs::read_dir(&lib) {
            for entry in entries.flatten() {
                let site = entry.path().join("site-packages");
                if site.is_dir() {
                    dirs.push(site);
                }
            }
        }
    }
    dirs
}

fn enumerate_installed(root: &Path) -> Option<Vec<Dep>> {
    // (name, version, requires, editable)
    let mut dists: Vec<(String, String, Vec<String>, bool)> = Vec::new();
    let project = project_name(root);
    for site in site_package_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&site) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let (meta, dist_dir) = if file_name.ends_with(".dist-info") {
                (entry.path().join("METADATA"), entry.path())
            } else if file_name.ends_with(".egg-info") {
                let dir_meta = entry.path().join("PKG-INFO");
                if dir_meta.is_file() {
                    (dir_meta, entry.path())
                } else {
                    continue;
                }
            } else {
                continue;
            };
            if let Some((name, version, requires)) = parse_metadata(&meta) {
                if project.as_deref() == Some(normalize(&name).as_str()) {
                    continue; // the project itself is not its own dependency
                }
                dists.push((name, version, requires, is_editable(&dist_dir)));
            }
        }
    }
    if dists.is_empty() {
        return None;
    }
    // Direct = graph roots. Edges out of editable installs are the project's
    // own declarations, not real reverse dependencies: counting them would
    // mark every direct dep transitive.
    let required: HashSet<String> = dists
        .iter()
        .filter(|(_, _, _, editable)| !editable)
        .flat_map(|(_, _, reqs, _)| reqs.iter().cloned())
        .collect();
    let mut deps: Vec<Dep> = dists
        .into_iter()
        .map(|(name, version, _, _)| {
            let direct = !required.contains(&normalize(&name));
            let mut dep = Dep::new(normalize(&name));
            dep.display = name;
            dep.version = Some(version);
            dep.direct = direct;
            if !direct {
                dep.detail = Some("transitive".to_string());
            }
            dep
        })
        .collect();
    deps.sort_by(|a, b| a.name.cmp(&b.name));
    Some(deps)
}

/// Parse `Name:`, `Version:` and `Requires-Dist:` from a METADATA/PKG-INFO file.
fn parse_metadata(path: &Path) -> Option<(String, String, Vec<String>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut version = None;
    let mut requires = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break; // end of headers
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim().to_lowercase().as_str() {
            "name" if name.is_none() => name = Some(value.trim().to_string()),
            "version" if version.is_none() => version = Some(value.trim().to_string()),
            "requires-dist" => {
                // Extra-gated requirements (test extras, ...) are not
                // installed by default: never reverse-dependency edges.
                if has_extra_marker(value.trim()) {
                    continue;
                }
                if let Some(req) = requirement_name(value.trim()) {
                    requires.push(normalize(&req));
                }
            }
            _ => {}
        }
    }
    Some((name?, version?, requires))
}

/// Whether a requirement string is gated on an `extra ==` marker.
fn has_extra_marker(req: &str) -> bool {
    req.split_once(';')
        .is_some_and(|(_, marker)| marker_is_extra(marker))
}

fn marker_is_extra(marker: &str) -> bool {
    let flat: String = marker
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .collect();
    flat.to_lowercase().contains("extra==")
}

/// Whether a dist-info/egg-info directory is an editable install
/// (`direct_url.json` with `dir_info.editable`).
fn is_editable(dist_dir: &Path) -> bool {
    std::fs::read_to_string(dist_dir.join("direct_url.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v.get("dir_info")?.get("editable")?.as_bool())
        .unwrap_or(false)
}

/// Normalized `[project].name` (or Poetry name) for self-detection.
fn project_name(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("pyproject.toml")).ok()?;
    let doc = toml::from_str::<toml::Value>(&text).ok()?;
    doc.get("project")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .or_else(|| doc.get("tool")?.get("poetry")?.get("name")?.as_str())
        .map(normalize)
}

/// Extract the bare package name from a requirement string.
fn requirement_name(req: &str) -> Option<String> {
    let before_markers = req.split(';').next().unwrap_or(req);
    let before_url = before_markers.split('@').next().unwrap_or(before_markers);
    let name: String = before_url
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

// ---------------------------------------------------------------------------
// Requirements files
// ---------------------------------------------------------------------------

fn requirements_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            let lower = name.to_lowercase();
            if lower.starts_with("requirements")
                && (lower.ends_with(".txt") || lower.ends_with(".in"))
            {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

fn parse_requirements_files(root: &Path) -> Vec<Dep> {
    let mut deps = Vec::new();
    let mut visited = HashSet::new();
    for file in requirements_files(root) {
        parse_requirements_file(&file, &mut visited, &mut deps);
    }
    deps
}

fn parse_requirements_file(path: &Path, visited: &mut HashSet<PathBuf>, deps: &mut Vec<Dep>) {
    if !visited.insert(path.to_path_buf()) {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    // Join backslash continuations.
    let mut logical = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim_end();
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
        } else {
            current.push_str(trimmed);
            logical.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        logical.push(current);
    }
    for line in logical {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Includes.
        if let Some(rest) = line
            .strip_prefix("-r")
            .or_else(|| line.strip_prefix("--requirement"))
        {
            let rest = rest.trim_start_matches([' ', '=']).trim();
            let include = rest.split_whitespace().next().unwrap_or("");
            if !include.is_empty() {
                let resolved = path.parent().unwrap_or(Path::new(".")).join(include);
                parse_requirements_file(&resolved, visited, deps);
            }
            continue;
        }
        if line.starts_with('-') {
            continue; // options (-e, --index-url, -c, ...)
        }
        let code = line.split('#').next().unwrap_or(line).trim();
        if code.is_empty() {
            continue;
        }
        if let Some(dep) = parse_requirement(code) {
            deps.push(dep);
        }
    }
}

/// Parse one requirement line (`name[extras]spec`, `name @ url`) into a Dep.
fn parse_requirement(line: &str) -> Option<Dep> {
    let before_markers = line.split(';').next().unwrap_or(line).trim();
    let name = requirement_name(before_markers)?;
    let mut dep = Dep::new(normalize(&name));
    dep.display = name.clone();
    // Remainder after the name (and optional extras) is the version spec.
    let mut rest = before_markers[name.len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix('[')
        && let Some(end) = stripped.find(']')
    {
        rest = stripped[end + 1..].trim_start();
    }
    if rest.starts_with('@') {
        dep.spec = Some(rest.to_string()); // direct URL reference
        return Some(dep);
    }
    if !rest.is_empty() {
        dep.spec = Some(rest.to_string());
        if let Some(pin) = pin_from_spec(rest) {
            dep.version = Some(pin);
        }
    }
    Some(dep)
}

/// Gaps for `setup.py` dependencies, which need execution to resolve and are
/// only covered when mirrored in requirements/pyproject/lockfiles.
fn setup_py_gaps(root: &Path) -> Vec<Gap> {
    if !root.join("setup.py").is_file() {
        return Vec::new();
    }
    let reason =
        "install_requires needs execution; mirror it in requirements.txt or pyproject.toml"
            .to_string();
    vec![
        Gap {
            name: "setup.py".to_string(),
            check: GapCheck::Outdated,
            reason: reason.clone(),
        },
        Gap {
            name: "setup.py".to_string(),
            check: GapCheck::Vulns,
            reason,
        },
    ]
}

/// Best-effort `python_requires="..."` extraction from setup.py source.
fn setup_python_requires(text: &str) -> Option<String> {
    let key = text.find("python_requires")?;
    let rest = &text[key + "python_requires".len()..];
    let eq = rest.find('=')?;
    let value = rest[eq + 1..].trim_start();
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    value[1..].split(quote).next().map(str::to_string)
}

/// `python_requires = ...` from a setup.cfg `[options]` section.
fn setup_cfg_python_requires(text: &str) -> Option<String> {
    let mut in_options = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_options = trimmed == "[options]";
            continue;
        }
        if in_options
            && let Some((key, value)) = trimmed.split_once('=')
            && key.trim() == "python_requires"
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Extract an exact pin from a spec (`==1.2.3`, but not `==1.0.*`).
fn pin_from_spec(spec: &str) -> Option<String> {
    let pin = spec
        .strip_prefix("===")
        .or_else(|| spec.strip_prefix("=="))
        .map(str::trim)?;
    if pin.is_empty() || pin.contains(['*', ' ', '\t', ',']) || pin.contains("==") {
        return None;
    }
    Some(pin.to_string())
}

// ---------------------------------------------------------------------------
// pyproject.toml / Pipfile / lockfiles
// ---------------------------------------------------------------------------

fn parse_pyproject(root: &Path) -> Vec<Dep> {
    let mut deps = Vec::new();
    let path = root.join("pyproject.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return deps;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return deps;
    };
    // PEP 621 [project].
    if let Some(project) = doc.get("project") {
        if let Some(list) = project.get("dependencies").and_then(|v| v.as_array()) {
            for item in list.iter().filter_map(|v| v.as_str()) {
                if let Some(dep) = parse_requirement(item) {
                    deps.push(dep);
                }
            }
        }
        if let Some(groups) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for list in groups.values().filter_map(|v| v.as_array()) {
                for item in list.iter().filter_map(|v| v.as_str()) {
                    if let Some(mut dep) = parse_requirement(item) {
                        dep.detail = Some("optional".to_string());
                        deps.push(dep);
                    }
                }
            }
        }
    }
    // PEP 735 dependency groups.
    if let Some(groups) = doc.get("dependency-groups").and_then(|v| v.as_table()) {
        for list in groups.values().filter_map(|v| v.as_array()) {
            for item in list.iter().filter_map(|v| v.as_str()) {
                if item.trim().starts_with('{') {
                    continue; // include-group tables need full resolution; skip
                }
                if let Some(dep) = parse_requirement(item) {
                    deps.push(dep);
                }
            }
        }
    }
    // Poetry [tool.poetry.dependencies] (+ groups).
    if let Some(poetry) = doc.get("tool").and_then(|t| t.get("poetry")) {
        if let Some(table) = poetry.get("dependencies").and_then(|v| v.as_table()) {
            deps.extend(parse_poetry_table(table));
        }
        if let Some(groups) = poetry.get("group").and_then(|v| v.as_table()) {
            for group in groups.values() {
                if let Some(table) = group.get("dependencies").and_then(|v| v.as_table()) {
                    deps.extend(parse_poetry_table(table));
                }
            }
        }
    }
    deps
}

fn parse_poetry_table(table: &toml::map::Map<String, toml::Value>) -> Vec<Dep> {
    let mut deps = Vec::new();
    for (name, value) in table {
        if name == "python" {
            continue;
        }
        let mut dep = Dep::new(normalize(name));
        dep.display = name.clone();
        match value {
            toml::Value::String(spec) => {
                dep.spec = Some(spec.clone());
                if let Some(pin) = pin_from_spec(spec) {
                    dep.version = Some(pin);
                }
            }
            toml::Value::Table(t) => {
                if let Some(spec) = t.get("version").and_then(|v| v.as_str()) {
                    dep.spec = Some(spec.to_string());
                    if let Some(pin) = pin_from_spec(spec) {
                        dep.version = Some(pin);
                    }
                } else {
                    dep.spec = Some("git/path dependency".to_string());
                }
            }
            toml::Value::Array(_) => {
                dep.spec = Some("multiple constraints".to_string());
            }
            _ => {}
        }
        deps.push(dep);
    }
    deps
}

fn parse_pipfile(root: &Path) -> Vec<Dep> {
    let mut deps = Vec::new();
    let path = root.join("Pipfile");
    let Ok(text) = std::fs::read_to_string(path) else {
        return deps;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return deps;
    };
    for section in ["packages", "dev-packages"] {
        if let Some(table) = doc.get(section).and_then(|v| v.as_table()) {
            for (name, value) in table {
                let mut dep = Dep::new(normalize(name));
                dep.display = name.clone();
                match value {
                    toml::Value::String(spec) if spec != "*" => {
                        dep.spec = Some(spec.clone());
                        if let Some(pin) = pin_from_spec(spec) {
                            dep.version = Some(pin);
                        }
                    }
                    toml::Value::Table(t) => {
                        if let Some(spec) = t.get("version").and_then(|v| v.as_str())
                            && spec != "*"
                        {
                            dep.spec = Some(spec.to_string());
                        }
                    }
                    _ => {}
                }
                deps.push(dep);
            }
        }
    }
    deps
}

/// Parse `uv.lock` / `poetry.lock` / `pdm.lock`: `[[package]]` name+version,
/// with direct deps computed as graph roots from `dependencies` edges.
fn parse_lockfile(path: &Path) -> Vec<Dep> {
    let mut deps = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return deps;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return deps;
    };
    let Some(packages) = doc.get("package").and_then(|v| v.as_array()) else {
        return deps;
    };
    let project = path.parent().and_then(project_name);
    let mut required: HashSet<String> = HashSet::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    for pkg in packages {
        let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        // The lock records the project itself (uv: editable source): it is
        // not its own dependency, and its edges would mark every direct
        // dep transitive.
        if project.as_deref() == Some(normalize(name).as_str()) {
            continue;
        }
        entries.push((name.to_string(), version.to_string()));
        // Edges: array of requirement strings or {name} tables, or a table.
        if let Some(list) = pkg.get("dependencies").and_then(|v| v.as_array()) {
            for item in list {
                match item {
                    toml::Value::String(req) => {
                        if has_extra_marker(req) {
                            continue;
                        }
                        if let Some(n) = requirement_name(req) {
                            required.insert(normalize(&n));
                        }
                    }
                    toml::Value::Table(t) => {
                        if t.get("optional").and_then(|v| v.as_bool()) == Some(true) {
                            continue;
                        }
                        let marker = t
                            .get("marker")
                            .and_then(|v| v.as_str())
                            .or_else(|| t.get("markers").and_then(|v| v.as_str()))
                            .unwrap_or("");
                        if marker_is_extra(marker) {
                            continue;
                        }
                        if let Some(n) = t.get("name").and_then(|v| v.as_str()) {
                            required.insert(normalize(n));
                        }
                    }
                    _ => {}
                }
            }
        } else if let Some(table) = pkg.get("dependencies").and_then(|v| v.as_table()) {
            for (key, value) in table {
                if let toml::Value::Table(spec) = value {
                    if spec.get("optional").and_then(|v| v.as_bool()) == Some(true) {
                        continue;
                    }
                    if let Some(m) = spec.get("markers").and_then(|v| v.as_str())
                        && marker_is_extra(m)
                    {
                        continue;
                    }
                }
                required.insert(normalize(key));
            }
        }
    }
    for (name, version) in entries {
        let direct = !required.contains(&normalize(&name));
        let mut dep = Dep::new(normalize(&name));
        dep.display = name;
        dep.version = Some(version);
        dep.direct = direct;
        if !direct {
            dep.detail = Some("transitive".to_string());
        }
        deps.push(dep);
    }
    deps.sort_by(|a, b| a.name.cmp(&b.name));
    deps
}

/// Release dates from the PyPI project document: one response holds every
/// version's file list, so both dates come from a single fetch. Failures
/// yield `None`, never gaps — dates are annotations, not checks.
fn pypi_release_dates(
    ctx: &Ctx,
    name: &str,
    current: &str,
    latest: &str,
) -> (Option<String>, Option<String>) {
    use crate::ecosystem::{cached_release_date, release_date_key};
    let cached = |version: &str| cached_release_date(ctx, "python", name, version);
    let current_date = cached(current);
    let latest_date = cached(latest);
    if current_date.is_some() && latest_date.is_some() {
        return (current_date, latest_date);
    }
    #[derive(Deserialize)]
    struct File {
        upload_time_iso_8601: Option<String>,
    }
    #[derive(Deserialize)]
    struct Resp {
        releases: HashMap<String, Vec<File>>,
    }
    let url = format!("https://pypi.org/pypi/{name}/json");
    if let Ok(resp) = http::get_json_retry::<Resp>(&url) {
        for (version, files) in &resp.releases {
            let date = files
                .iter()
                .filter_map(|f| f.upload_time_iso_8601.as_deref())
                .filter_map(crate::dates::iso_date)
                .next();
            if let Some(date) = date {
                ctx.cache
                    .set(&release_date_key("python", name, version), &date);
            }
        }
    }
    (
        current_date.or_else(|| cached(current)),
        latest_date.or_else(|| cached(latest)),
    )
}

/// License + yanked facts for one used release from its version-specific
/// PyPI document. Licenses cache forever (a published release never
/// changes); yanked state is re-checked on the version TTL. Yanked
/// notices need positive evidence: lookup failures assume not yanked.
struct PypiFacts {
    licenses: Vec<String>,
    yanked: bool,
    yanked_reason: Option<String>,
}

/// Manifest-declared distribution names (normalized): requirements
/// files, pyproject (`[project]` + Poetry) and Pipfile sections,
/// unioned over nested manifests (monorepo members share the parent
/// project's source scan).
pub(crate) fn manifest_names(root: &Path) -> HashSet<String> {
    crate::ghost::find_manifest_dirs(root, &|d| {
        d.join("pyproject.toml").is_file()
            || d.join("setup.py").is_file()
            || d.join("setup.cfg").is_file()
            || d.join("Pipfile").is_file()
            || !requirements_files(d).is_empty()
    })
    .iter()
    .flat_map(|dir| {
        parse_requirements_files(dir)
            .into_iter()
            .chain(parse_pyproject(dir))
            .chain(parse_pipfile(dir))
    })
    .map(|d| crate::ghost::normalize_dist(&d.name))
    .collect()
}

/// First-party modules unioned over manifest dirs (plus their `src/`
/// layouts): member-local packages resolve too.
fn local_modules(root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    for dir in crate::ghost::find_manifest_dirs(root, &|d| {
        d.join("pyproject.toml").is_file() || !requirements_files(d).is_empty()
    }) {
        out.extend(crate::ghost::local_python_modules(&dir));
        let src = dir.join("src");
        if src.is_dir() {
            out.extend(crate::ghost::local_python_modules(&src));
        }
    }
    out
}

/// Import root -> normalized distribution name, through the alias map
/// (`yaml` -> `pyyaml`, `PIL` -> `pillow`, ...).
fn resolve_dist(root: &str, aliases: &HashMap<&str, &str>) -> String {
    let lower = root.to_lowercase();
    let dist = aliases.get(lower.as_str()).copied().unwrap_or(root);
    crate::ghost::normalize_dist(dist)
}

/// SPDX ids from `License :: ...` classifiers only. Other facets
/// (`Topic :: ... :: Utilities`) carry single words that would leak
/// into the license list, so they are ignored.
fn classifier_licenses(classifiers: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for classifier in classifiers {
        let mut segments = classifier.split("::").map(str::trim);
        if segments.next() != Some("License") {
            continue;
        }
        if let Some(last) = segments.last() {
            out.extend(crate::licenses::normalize_spdx(last));
        }
    }
    out
}

fn pypi_facts(ctx: &Ctx, name: &str, version: &str) -> PypiFacts {
    let lkey = format!("v1:license:python:{name}:{version}");
    let ykey = format!("v1:yanked:python:{name}:{version}");
    let cached_licenses: Option<Vec<String>> =
        ctx.cache.license_resolution(&lkey, "python", name, version);
    let cached_yanked: Option<(bool, Option<String>)> =
        ctx.cache.get(&ykey, ctx.cache.versions_ttl());
    if let (Some(licenses), Some((yanked, yanked_reason))) = (&cached_licenses, &cached_yanked) {
        return PypiFacts {
            licenses: licenses.clone(),
            yanked: *yanked,
            yanked_reason: yanked_reason.clone(),
        };
    }
    #[derive(Deserialize)]
    struct Info {
        #[serde(default)]
        license: Option<String>,
        #[serde(default)]
        classifiers: Vec<String>,
        #[serde(default)]
        yanked: bool,
        #[serde(default)]
        yanked_reason: Option<String>,
    }
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        info: Option<Info>,
    }
    let url = format!("https://pypi.org/pypi/{name}/{version}/json");
    let mut facts = PypiFacts {
        licenses: cached_licenses.clone().unwrap_or_default(),
        yanked: cached_yanked.clone().map(|(y, _)| y).unwrap_or(false),
        yanked_reason: cached_yanked.and_then(|(_, r)| r),
    };
    // Stale yanked state beats none (a yank is rarely lifted).
    if facts.yanked_reason.is_none()
        && let Some((y, r)) = ctx.cache.get_stale::<(bool, Option<String>)>(&ykey)
    {
        facts.yanked = y;
        facts.yanked_reason = r;
    }
    if let Ok(resp) = http::get_json_retry::<Resp>(&url)
        && let Some(info) = resp.info
    {
        let mut licenses = classifier_licenses(&info.classifiers);
        if let Some(declared) = &info.license {
            licenses.extend(crate::licenses::normalize_spdx(declared));
        }
        licenses.sort();
        licenses.dedup();
        facts.licenses = licenses.clone();
        facts.yanked = info.yanked;
        facts.yanked_reason = info.yanked_reason.clone();
        ctx.cache
            .store_license_resolution(&lkey, "python", name, version, &licenses);
        ctx.cache.set(&ykey, &(info.yanked, info.yanked_reason));
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::ecosystem::release_date_key;

    fn date_ctx() -> Ctx {
        Ctx {
            verbose: false,
            deep: false,
            check_outdated: true,
            check_vulns: false,
            cache: std::sync::Arc::new(Cache::for_test()),
            android_sdk_cap: None,
            lint: false,
            lint_config_order: crate::lint::DEFAULT_ORDER,
            check_notices: false,
            license_policy: crate::licenses::Policy::default(),
        }
    }

    #[test]
    fn release_dates_serves_cached_dates() {
        let ctx = date_ctx();
        ctx.cache.set(
            &release_date_key("python", "six", "1.15.0"),
            &"2020-05-21".to_string(),
        );
        ctx.cache.set(
            &release_date_key("python", "six", "1.17.0"),
            &"2024-12-04".to_string(),
        );
        assert_eq!(
            Python.release_dates(&ctx, "six", "1.15.0", "1.17.0"),
            (
                Some("2020-05-21".to_string()),
                Some("2024-12-04".to_string())
            )
        );
    }

    #[test]
    fn parses_requirement_lines() {
        let d = parse_requirement("six==1.15.0").unwrap();
        assert_eq!(d.name, "six");
        assert_eq!(d.version.as_deref(), Some("1.15.0"));

        let d = parse_requirement("requests[security]>=2.8.1,<3").unwrap();
        assert_eq!(d.name, "requests");
        assert_eq!(d.version, None);
        assert_eq!(d.spec.as_deref(), Some(">=2.8.1,<3"));

        let d = parse_requirement("foo==1.0.*").unwrap();
        assert_eq!(d.version, None); // prefix match is not a pin

        let d = parse_requirement("bar @ https://example.com/bar.zip").unwrap();
        assert_eq!(d.name, "bar");
        assert_eq!(d.version, None);

        let d = parse_requirement("Baz_Qux==2.0").unwrap();
        assert_eq!(d.name, "baz-qux");
        assert_eq!(d.display, "Baz_Qux");
    }

    #[test]
    fn requirements_file_include_and_options() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.txt"), "six==1.15.0\n").unwrap();
        std::fs::write(
            dir.path().join("requirements.txt"),
            "# comment\n-r base.txt\n--index-url https://x\nrequests>=2\n",
        )
        .unwrap();
        let deps = parse_requirements_files(dir.path());
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "six"));
        assert!(deps.iter().any(|d| d.name == "requests"));
    }

    #[test]
    fn pep440_ordering() {
        assert!(pep440_is_newer("1.15.0", "1.17.0"));
        assert!(!pep440_is_newer("1.17.0", "1.15.0"));
        assert!(!pep440_is_newer("2.0", "2.0"));
        assert!(pep440_is_newer("1.0a1", "1.0"));
        assert!(pep440_is_newer("1.0", "1.0.post1"));
    }

    #[test]
    fn installed_env_roots_are_direct() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir
            .path()
            .join(".venv")
            .join("lib")
            .join("python3.14")
            .join("site-packages");
        std::fs::create_dir_all(site.join("app-1.0.dist-info")).unwrap();
        std::fs::create_dir_all(site.join("lib-2.0.dist-info")).unwrap();
        std::fs::write(
            site.join("app-1.0.dist-info").join("METADATA"),
            "Name: app\nVersion: 1.0\nRequires-Dist: lib>=2\n",
        )
        .unwrap();
        std::fs::write(
            site.join("lib-2.0.dist-info").join("METADATA"),
            "Name: lib\nVersion: 2.0\n",
        )
        .unwrap();
        let deps = Python.enumerate(dir.path()).unwrap().deps;
        assert_eq!(deps.len(), 2);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        let lib = deps.iter().find(|d| d.name == "lib").unwrap();
        assert!(app.direct);
        assert!(!lib.direct);
        assert_eq!(lib.version.as_deref(), Some("2.0"));
    }

    #[test]
    fn editable_self_neither_inventoried_nor_poisoning() {
        // The project's own editable install must not appear as a dependency,
        // and its Requires-Dist must not mark real direct deps transitive.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"paylocity-scraper\"\n",
        )
        .unwrap();
        let site = dir
            .path()
            .join(".venv")
            .join("lib")
            .join("python3.14")
            .join("site-packages");
        for dist in [
            "paylocity_scraper-0.1.0.dist-info",
            "playwright-1.63.0.dist-info",
        ] {
            std::fs::create_dir_all(site.join(dist)).unwrap();
        }
        std::fs::write(
            site.join("paylocity_scraper-0.1.0.dist-info")
                .join("METADATA"),
            "Name: paylocity-scraper\nVersion: 0.1.0\nRequires-Dist: playwright>=1.40\n",
        )
        .unwrap();
        std::fs::write(
            site.join("paylocity_scraper-0.1.0.dist-info")
                .join("direct_url.json"),
            "{\"url\":\"file:///x\",\"dir_info\":{\"editable\":true}}",
        )
        .unwrap();
        std::fs::write(
            site.join("playwright-1.63.0.dist-info").join("METADATA"),
            "Name: playwright\nVersion: 1.63.0\n",
        )
        .unwrap();
        let deps = Python.enumerate(dir.path()).unwrap().deps;
        assert!(deps.iter().all(|d| d.name != "paylocity-scraper"));
        let playwright = deps.iter().find(|d| d.name == "playwright").unwrap();
        assert!(playwright.direct);
    }

    #[test]
    fn extra_markers_ignored_for_directness() {
        // pluggy's testing extra requires pytest, but that must not mark
        // an installed pytest transitive: extras are never auto-installed.
        assert!(!has_extra_marker("pytest>=8"));
        assert!(has_extra_marker("pytest; extra == \"testing\""));
        let dir = tempfile::tempdir().unwrap();
        let site = dir
            .path()
            .join(".venv")
            .join("lib")
            .join("python3.14")
            .join("site-packages");
        for dist in ["pluggy-1.6.0.dist-info", "pytest-9.1.1.dist-info"] {
            std::fs::create_dir_all(site.join(dist)).unwrap();
        }
        std::fs::write(
            site.join("pluggy-1.6.0.dist-info").join("METADATA"),
            "Name: pluggy\nVersion: 1.6.0\nRequires-Dist: pytest; extra == \"testing\"\n",
        )
        .unwrap();
        std::fs::write(
            site.join("pytest-9.1.1.dist-info").join("METADATA"),
            "Name: pytest\nVersion: 9.1.1\n",
        )
        .unwrap();
        let deps = Python.enumerate(dir.path()).unwrap().deps;
        assert!(deps.iter().find(|d| d.name == "pytest").unwrap().direct);
    }

    #[test]
    fn lock_self_and_markers_ignored_for_directness() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"demo\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("uv.lock"),
            "[[package]]\nname = \"demo\"\nversion = \"0.1\"\n\
             dependencies = [{ name = \"playwright\" }]\n\
             [[package]]\nname = \"playwright\"\nversion = \"1.63.0\"\n\
             dependencies = [{ name = \"pyee\" }]\n\
             [[package]]\nname = \"pyee\"\nversion = \"13.0.1\"\n\
             dependencies = [{ name = \"pytest\", marker = \"extra == 'testing'\" }]\n\
             [[package]]\nname = \"pytest\"\nversion = \"9.1.1\"\n",
        )
        .unwrap();
        let deps = Python.enumerate(dir.path()).unwrap().deps;
        assert!(deps.iter().all(|d| d.name != "demo"));
        assert!(deps.iter().find(|d| d.name == "playwright").unwrap().direct);
        assert!(!deps.iter().find(|d| d.name == "pyee").unwrap().direct);
        assert!(deps.iter().find(|d| d.name == "pytest").unwrap().direct);
    }

    #[test]
    fn enumerates_tool_pins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"x\"\nrequires-python = \">=3.9\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join(".python-version"), "3.11\n").unwrap();
        std::fs::write(
            dir.path().join("setup.py"),
            "setup(name='x', python_requires='>=3.8')\n",
        )
        .unwrap();
        let pins = Python.enumerate_tools(dir.path());
        assert_eq!(pins.len(), 3);
        assert!(pins.iter().any(|p| p.spec.as_deref() == Some(">=3.9")));
        assert!(pins.iter().any(|p| p.version.as_deref() == Some("3.11")));
        assert!(pins.iter().any(|p| p.spec.as_deref() == Some(">=3.8")));
    }

    #[test]
    fn setup_py_is_a_gap_without_lock_or_env() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.py"), "setup(name='x')\n").unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "six==1.15.0\n").unwrap();
        let inventory = Python.enumerate(dir.path()).unwrap();
        assert_eq!(inventory.deps.len(), 1);
        assert_eq!(inventory.gaps.len(), 2);
        assert!(inventory.gaps.iter().all(|g| g.name == "setup.py"));
    }

    #[test]
    fn detects_python_markers() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!Python.detect(dir.path()));
        std::fs::write(dir.path().join("requirements.txt"), "six\n").unwrap();
        assert!(Python.detect(dir.path()));
    }

    #[test]
    fn update_command_prefers_uv_with_lockfile() {
        let out = [OutdatedDep {
            name: "ruff".to_string(),
            current: "0.16.8".to_string(),
            latest: "0.17.3".to_string(),
            detail: None,
            blocked: None,
            stale: None,
            current_released: None,
            latest_released: None,
            days_behind: None,
        }];
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Python.update_command(dir.path(), &out).as_deref(),
            Some("pip install -U ruff==0.17.3")
        );
        std::fs::write(dir.path().join("uv.lock"), "").unwrap();
        assert_eq!(
            Python.update_command(dir.path(), &out).as_deref(),
            Some("uv pip install -U ruff==0.17.3")
        );
    }

    #[test]
    fn classifier_licenses_ignores_non_license_facets() {
        let classifiers = [
            "License :: OSI Approved :: MIT License".to_string(),
            "Development Status :: 5 - Production/Stable".to_string(),
            "Intended Audience :: Developers".to_string(),
            "Programming Language :: Python :: 2".to_string(),
            "Programming Language :: Python :: 3".to_string(),
            "Topic :: Software Development :: Libraries".to_string(),
            "Topic :: Utilities".to_string(),
        ];
        assert_eq!(classifier_licenses(&classifiers), vec!["MIT".to_string()]);
    }

    #[test]
    fn resolve_dist_maps_aliases_and_normalizes() {
        let aliases = crate::ghost::alias_map();
        assert_eq!(resolve_dist("yaml", &aliases), "pyyaml");
        assert_eq!(resolve_dist("PIL", &aliases), "pillow");
        assert_eq!(resolve_dist("dateutil", &aliases), "python-dateutil");
        assert_eq!(resolve_dist("requests", &aliases), "requests");
    }

    #[test]
    fn manifest_names_covers_requirements_and_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "requests==2.31.0\n").unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\ndependencies = [\"PyYAML>=6\"]\n",
        )
        .unwrap();
        let names = manifest_names(dir.path());
        assert!(names.contains("requests"));
        assert!(names.contains("pyyaml"));
    }
}
