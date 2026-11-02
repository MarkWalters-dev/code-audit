//! Go ecosystem, pure Rust: `require` directives from `go.mod`, latest
//! versions from a Go module proxy (`@v/list`, default proxy.golang.org).
//!
//! Outdated rule: the pinned `go.mod` version is compared against the newest
//! stable version the proxy knows. `// indirect` requirements are transitive.
//! Modules matched by `GOPRIVATE`/`GONOSUMDB` are skipped (unresolvable
//! without the private proxy), as are `replace` targets pointing at local
//! paths.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ecosystem::{
    Ctx, Dep, EcosystemChecker, Gap, GapCheck, Inventory, LatestInfo, Notice, OutdatedDep,
};
use crate::toolchains::{self, ToolId, ToolPin};
use crate::{http, version};

pub struct GoLang;

impl EcosystemChecker for GoLang {
    fn id(&self) -> &'static str {
        "go"
    }

    fn display(&self) -> &'static str {
        "Go"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "Go"
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("go.mod").is_file()
    }

    fn enumerate(&self, root: &Path) -> Result<Inventory, String> {
        let text = std::fs::read_to_string(root.join("go.mod"))
            .map_err(|e| format!("cannot read go.mod: {e}"))?;
        let mut requires: Vec<(String, String, bool)> = Vec::new(); // (path, version, direct)
        let mut replaces: HashMap<String, (String, Option<String>)> = HashMap::new();
        let mut section: Option<&str> = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if let Some(rest) = line.strip_prefix("require ") {
                if rest.trim() == "(" {
                    section = Some("require");
                } else if let Some(req) = parse_require_line(rest) {
                    requires.push(req);
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("replace ") {
                if rest.trim() == "(" {
                    section = Some("replace");
                } else if let Some((old, new)) = parse_replace_line(rest) {
                    replaces.insert(old, new);
                }
                continue;
            }
            if line == ")" {
                section = None;
                continue;
            }
            match section {
                Some("require") => {
                    if let Some(req) = parse_require_line(line) {
                        requires.push(req);
                    }
                }
                Some("replace") => {
                    if let Some((old, new)) = parse_replace_line(line) {
                        replaces.insert(old, new);
                    }
                }
                _ => {}
            }
        }

        let mut deps = Vec::new();
        let mut gaps = Vec::new();
        for (path, ver, direct) in requires {
            if let Some((new_path, new_ver)) = replaces.get(&path) {
                if is_local_path(new_path) {
                    let reason = format!("replaced by local path {new_path}");
                    gaps.push(Gap {
                        name: path.clone(),
                        check: GapCheck::Outdated,
                        reason: reason.clone(),
                    });
                    gaps.push(Gap {
                        name: path,
                        check: GapCheck::Vulns,
                        reason,
                    });
                    continue;
                }
                let mut dep = Dep::new(new_path.clone());
                dep.display = format!("{path} => {new_path}");
                dep.version = Some(new_ver.clone().unwrap_or(ver));
                dep.direct = direct;
                if !direct {
                    dep.detail = Some("indirect".to_string());
                }
                deps.push(dep);
            } else {
                let mut dep = Dep::new(path);
                dep.version = Some(ver);
                dep.direct = direct;
                if !direct {
                    dep.detail = Some("indirect".to_string());
                }
                deps.push(dep);
            }
        }
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Inventory { deps, gaps, notes: Vec::new() })
    }

    fn fetch_latest(&self, _ctx: &Ctx, dep: &Dep) -> Result<LatestInfo, String> {
        if is_private(&dep.name) {
            return Err("matched by GOPRIVATE/GONOSUMDB; skipped".to_string());
        }
        let base = proxy_base().ok_or_else(|| "GOPROXY=off".to_string())?;
        let escaped = escape_module_path(&dep.name);
        let url = format!("{base}/{escaped}/@v/list");
        let list = match http::get_text_retry(&url) {
            Ok(l) => l,
            Err(e) => return Err(crate::toolchains::request_reason("module proxy", &e)),
        };
        let mut versions: Vec<String> = list
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if versions.is_empty() {
            // Fall back to @latest (single JSON document).
            #[derive(Deserialize)]
            struct Latest {
                #[serde(rename = "Version")]
                version: String,
            }
            let url = format!("{base}/{escaped}/@latest");
            match http::get_json_retry::<Latest>(&url) {
                Ok(latest) => return Ok(LatestInfo::simple(latest.version)),
                Err(e) => return Err(crate::toolchains::request_reason("module proxy", &e)),
            }
        }
        versions.sort();
        versions.dedup();
        pick_latest(dep.version.as_deref().unwrap_or(""), &versions)
            .map(LatestInfo::simple)
            .ok_or_else(|| "no versions on proxy".to_string())
    }

    fn enumerate_tools(&self, root: &Path) -> Vec<ToolPin> {
        let mut pins = Vec::new();
        if let Ok(text) = std::fs::read_to_string(root.join("go.mod")) {
            for raw in text.lines() {
                let line = raw.trim();
                if let Some(version) = line
                    .strip_prefix("go ")
                    .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
                {
                    if !version.is_empty() {
                        pins.push(ToolPin {
                            tool: ToolId::Go,
                            display: "go (go.mod)".to_string(),
                            version: None,
                            spec: Some(version),
                        });
                    }
                } else if let Some(version) = line
                    .strip_prefix("toolchain ")
                    .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
                {
                    let version = version.trim_start_matches("go").to_string();
                    if !version.is_empty() {
                        pins.push(ToolPin {
                            tool: ToolId::Go,
                            display: "go (toolchain directive)".to_string(),
                            version: Some(version),
                            spec: None,
                        });
                    }
                }
            }
        }
        // Version managers.
        for (source, map) in [
            (".tool-versions", toolchains::parse_tool_versions(root)),
            ("mise", toolchains::parse_mise_toml(root)),
        ] {
            for key in ["go", "golang"] {
                if let Some(version) = map.get(key) {
                    pins.push(ToolPin {
                        tool: ToolId::Go,
                        display: format!("go ({source})"),
                        version: Some(version.clone()),
                        spec: None,
                    });
                }
            }
        }
        pins
    }

    fn outdated(&self, dep: &Dep, latest: &str) -> Option<OutdatedDep> {
        let current = dep
            .version
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        if version::compare(&current, latest) == std::cmp::Ordering::Less {
            Some(OutdatedDep {
                name: dep.display.clone(),
                current,
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

    fn release_dates(
        &self,
        ctx: &Ctx,
        name: &str,
        current: &str,
        latest: &str,
    ) -> (Option<String>, Option<String>) {
        (
            go_version_date(ctx, name, current),
            go_version_date(ctx, name, latest),
        )
    }

    fn lint(
        &self,
        ctx: &Ctx,
        root: &Path,
        vulns: &[crate::osv::FoundVuln],
    ) -> crate::lint::LintOutcome {
        crate::lint::audit_go(ctx, root, vulns)
    }

    fn dep_licenses(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
        module_licenses(ctx, name, version)
    }

    fn project_notices(&self, _ctx: &Ctx, root: &Path, inventory: &[Dep]) -> Vec<Notice> {
        // Nested modules share the parent's source scan (same-eco nesting
        // is suppressed), so their requirements union into matching.
        let mut direct: HashSet<String> = inventory
            .iter()
            .filter(|d| d.direct)
            .map(|d| d.name.clone())
            .collect();
        let mut transitive: HashSet<String> = inventory
            .iter()
            .filter(|d| !d.direct)
            .map(|d| d.name.clone())
            .collect();
        for dir in crate::ghost::find_manifest_dirs(root, &|d| d.join("go.mod").is_file()) {
            if dir == root {
                continue;
            }
            if let Ok(inv) = self.enumerate(&dir) {
                for dep in &inv.deps {
                    if dep.direct {
                        direct.insert(dep.name.clone());
                    } else {
                        transitive.insert(dep.name.clone());
                    }
                }
            }
        }
        let direct_ref: HashSet<&str> = direct.iter().map(|s| s.as_str()).collect();
        let transitive_ref: HashSet<&str> = transitive.iter().map(|s| s.as_str()).collect();
        let own = module_path(root);
        let module_dirs: Vec<(String, PathBuf)> =
            crate::ghost::find_manifest_dirs(root, &|d| d.join("go.mod").is_file())
                .into_iter()
                .filter_map(|d| module_path(&d).map(|m| (m, d)))
                .collect();
        let mut notices = crate::ghost::scan(
            root,
            &["go"],
            crate::ghost::go_imports,
            |spec| {
                if spec == "C" {
                    return true; // cgo
                }
                if let Some(own) = &own
                    && (spec == own || spec.starts_with(&format!("{own}/")))
                {
                    return true; // first-party
                }
                if spec.split('/').next().is_some_and(|s| !s.contains('.')) {
                    return true; // stdlib: no dot in the first segment
                }
                provided_by(spec, &direct_ref)
            },
            |spec| provided_by(spec, &transitive_ref),
        );
        notices.extend(crate::deadcode::go_dead(root, &module_dirs));
        notices
    }

    fn update_command(&self, _root: &Path, outdated: &[OutdatedDep]) -> Option<String> {
        let pkgs = outdated
            .iter()
            .map(|d| format!("{}@{}", d.name, d.latest))
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!("go get {pkgs}"))
    }
}

/// This module's own path (`module example.com/app`): imports under it
/// are first-party.
fn module_path(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("go.mod")).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("module")
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_string)
    })
}

/// Whether `spec` falls under one of `modules` (exact or subpackage).
fn provided_by(spec: &str, modules: &HashSet<&str>) -> bool {
    modules
        .iter()
        .any(|m| spec == *m || spec.starts_with(&format!("{m}/")))
}

/// Parse `module/path v1.2.3 // indirect?` inside or outside a block.
fn parse_require_line(line: &str) -> Option<(String, String, bool)> {
    let mut parts = line.split_whitespace();
    let path = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    if !version.starts_with('v') && !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let rest: Vec<&str> = parts.collect();
    let indirect = rest.iter().any(|p| p.contains("indirect"));
    Some((path, version, !indirect))
}

/// Parse `old/path [v] => new/path-or-local [v]`.
fn parse_replace_line(line: &str) -> Option<(String, (String, Option<String>))> {
    let (left, right) = line.split_once("=>")?;
    let old: Vec<&str> = left.split_whitespace().collect();
    let new: Vec<&str> = right.split_whitespace().collect();
    if old.is_empty() || new.is_empty() {
        return None;
    }
    let version = new.get(1).map(|s| s.to_string());
    Some((old[0].to_string(), (new[0].to_string(), version)))
}

fn is_local_path(p: &str) -> bool {
    p.starts_with('.') || p.starts_with('/') || !p.contains('.')
}

/// Module proxy base from `GOPROXY` (first URL entry), defaulting to the
/// public proxy. `GOPROXY=off` disables lookups.
fn proxy_base() -> Option<String> {
    if let Some(value) = std::env::var_os("GOPROXY").and_then(|v| v.into_string().ok()) {
        for entry in value.split(',') {
            let entry = entry.trim();
            if entry == "off" {
                return None;
            }
            if entry == "direct" {
                continue;
            }
            if entry.starts_with("http://") || entry.starts_with("https://") {
                return Some(entry.trim_end_matches('/').to_string());
            }
        }
    }
    Some("https://proxy.golang.org".to_string())
}

/// Whether `module` matches `GOPRIVATE`/`GONOSUMDB`/`GONOSUMCHECK` patterns
/// (prefix match, `*` supported as a trailing wildcard).
fn is_private(module: &str) -> bool {
    let mut patterns = Vec::new();
    for var in ["GOPRIVATE", "GONOSUMDB", "GONOSUMCHECK"] {
        if let Some(value) = std::env::var_os(var).and_then(|v| v.into_string().ok()) {
            patterns.extend(value.split(',').map(|p| p.trim().to_string()));
        }
    }
    // GOSUMDB=off implies fully private operation.
    if std::env::var_os("GOSUMDB").is_some_and(|v| v == "off") {
        return true;
    }
    patterns.iter().any(|pat| {
        if pat.is_empty() {
            return false;
        }
        if let Some(prefix) = pat.strip_suffix('*') {
            module.starts_with(prefix)
        } else {
            module == pat || module.starts_with(&format!("{pat}/"))
        }
    })
}

/// Proxy protocol escaping: uppercase letters become `!` + lowercase.
fn escape_module_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Newest stable version (no `-suffix`), or newest overall when `current`
/// is itself a pre-release/pseudo-version.
fn pick_latest(current: &str, candidates: &[String]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let current_unstable = current.contains('-');
    let pool: Vec<&String> = if current_unstable {
        candidates.iter().collect()
    } else {
        let stable: Vec<&String> = candidates.iter().filter(|v| !v.contains('-')).collect();
        if stable.is_empty() {
            candidates.iter().collect()
        } else {
            stable
        }
    };
    pool.into_iter()
        .max_by(|a, b| version::compare(a, b))
        .cloned()
}

/// Release date of one module version from the proxy's `.info`
/// document. Private modules and `GOPROXY=off` yield `None`, never gaps.
fn go_version_date(ctx: &Ctx, module: &str, version: &str) -> Option<String> {
    use crate::ecosystem::{cached_release_date, release_date_key};
    if is_private(module) {
        return None;
    }
    if let Some(date) = cached_release_date(ctx, "go", module, version) {
        return Some(date);
    }
    #[derive(Deserialize)]
    struct Info {
        #[serde(rename = "Time")]
        time: String,
    }
    let base = proxy_base()?;
    let escaped = escape_module_path(module);
    let url = format!("{base}/{escaped}/@v/{version}.info");
    let date = http::get_json_retry::<Info>(&url)
        .ok()
        .and_then(|info| crate::dates::iso_date(&info.time))?;
    ctx.cache
        .set(&release_date_key("go", module, version), &date);
    Some(date)
}

/// Licenses of one used module version. The local module cache answers
/// first (read-only, instant, and safe for private modules); otherwise
/// the proxy's content-hashed zip is fetched and its license files
/// fingerprinted. A published version never changes: cached forever.
fn module_licenses(ctx: &Ctx, module: &str, version: &str) -> Vec<String> {
    let key = format!("v1:license:go:{module}:{version}");
    if let Some(licenses) = ctx.cache.license_resolution(&key, "go", module, version) {
        return licenses;
    }
    if let Some(licenses) = modcache_licenses(module, version) {
        ctx.cache
            .store_license_resolution(&key, "go", module, version, &licenses);
        return licenses;
    }
    // Private modules never touch the network; unknown without a cache hit.
    if is_private(module) {
        return Vec::new();
    }
    if proxy_base().is_none() {
        return Vec::new();
    }
    // Cache successes even when empty (a content-hashed zip without
    // license files is definitively unlicensed); failures stay uncached.
    match proxy_zip_licenses(module, version) {
        Some(licenses) => {
            ctx.cache
                .store_license_resolution(&key, "go", module, version, &licenses);
            licenses
        }
        None => Vec::new(),
    }
}

/// License files from the extracted module in the local module cache.
/// `None` = not cached (unresolved); `Some` (even empty) is a resolution.
fn modcache_licenses(module: &str, version: &str) -> Option<Vec<String>> {
    let gopath = std::env::var_os("GOPATH")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("go")))?;
    // Module cache escaping differs from the proxy's: `!` + lowercase.
    let escaped: String = module
        .chars()
        .flat_map(|c| {
            if c.is_ascii_uppercase() {
                vec!['!', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect();
    let dir = gopath.join("pkg/mod").join(format!("{escaped}@{version}"));
    if !dir.is_dir() {
        return None;
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        if !is_license_file(&entry.file_name().to_string_lossy()) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            for id in crate::licenses::classify_license_text(&text) {
                if !out.contains(&id) {
                    out.push(id);
                }
            }
        }
    }
    Some(out)
}

/// License files from the proxy's module zip. Reads only small
/// license-named entries, never the whole tree into structured form.
fn proxy_zip_licenses(module: &str, version: &str) -> Option<Vec<String>> {
    let base = proxy_base()?;
    let url = format!("{base}/{}/@v/{version}.zip", escape_module_path(module));
    let bytes = http::get_bytes_retry(&url).ok()?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).ok()?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).ok()?;
        let name = file.name().map(|n| n.into_owned()).unwrap_or_default();
        let base_name = name.rsplit('/').next().unwrap_or(&name);
        // Cap entry size: license files are small, module zips are not.
        if !is_license_file(base_name) || file.size() > 200_000 {
            continue;
        }
        let mut text = String::new();
        if file.read_to_string(&mut text).is_err() {
            continue;
        }
        for id in crate::licenses::classify_license_text(&text) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    Some(out)
}

fn is_license_file(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.starts_with("LICENSE")
        || upper.starts_with("LICENCE")
        || upper.starts_with("COPYING")
        || upper.starts_with("COPYRIGHT")
        || upper == "NOTICE"
        || upper.starts_with("NOTICE.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::ecosystem::release_date_key;

    #[test]
    fn release_dates_serves_cached_dates() {
        let ctx = Ctx {
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
        };
        ctx.cache.set(
            &release_date_key("go", "github.com/fatih/color", "v1.13.0"),
            &"2021-09-21".to_string(),
        );
        ctx.cache.set(
            &release_date_key("go", "github.com/fatih/color", "v1.19.0"),
            &"2026-03-20".to_string(),
        );
        assert_eq!(
            GoLang.release_dates(&ctx, "github.com/fatih/color", "v1.13.0", "v1.19.0"),
            (
                Some("2021-09-21".to_string()),
                Some("2026-03-20".to_string())
            )
        );
    }

    #[test]
    fn parses_go_mod() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/probe\n\ngo 1.21\n\nrequire (\n\tgithub.com/fatih/color v1.13.0\n\tgithub.com/mattn/go-isatty v0.0.14 // indirect\n\texample.com/localmod v0.0.0\n)\n\nrequire github.com/solo/single v2.0.0\n\nreplace example.com/localmod => ../local\n",
        )
        .unwrap();
        let inventory = GoLang.enumerate(dir.path()).unwrap();
        let mut deps = inventory.deps;
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(deps.len(), 3);
        // The locally-replaced module is reported as a gap, not silently dropped.
        assert_eq!(inventory.gaps.len(), 2);
        assert!(
            inventory
                .gaps
                .iter()
                .all(|g| g.name == "example.com/localmod")
        );
        let color = deps
            .iter()
            .find(|d| d.name == "github.com/fatih/color")
            .unwrap();
        assert!(color.direct);
        assert_eq!(color.version.as_deref(), Some("v1.13.0"));
        let indirect = deps
            .iter()
            .find(|d| d.name == "github.com/mattn/go-isatty")
            .unwrap();
        assert!(!indirect.direct);
    }

    #[test]
    fn enumerates_tool_pins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/x\n\ngo 1.21\ntoolchain go1.22.0\n",
        )
        .unwrap();
        let pins = GoLang.enumerate_tools(dir.path());
        assert_eq!(pins.len(), 2);
        assert!(pins.iter().any(|p| p.spec.as_deref() == Some("1.21")));
        assert!(pins.iter().any(|p| p.version.as_deref() == Some("1.22.0")));
    }

    #[test]
    fn module_path_escaping() {
        assert_eq!(
            escape_module_path("github.com/Azure/go-amqp"),
            "github.com/!azure/go-amqp"
        );
        assert_eq!(escape_module_path("golang.org/x/sys"), "golang.org/x/sys");
    }

    #[test]
    fn stable_preferred_over_pseudo() {
        let candidates = ["v1.13.0", "v1.19.0", "v1.20.0-0.20230101-abcdef"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            pick_latest("v1.13.0", &candidates).as_deref(),
            Some("v1.19.0")
        );
        // Pseudo-only modules still resolve.
        let pseudos = ["v0.0.0-20220101-aaaaaa", "v0.0.0-20230101-bbbbbb"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            pick_latest("v0.0.0-20220101-aaaaaa", &pseudos).as_deref(),
            Some("v0.0.0-20230101-bbbbbb")
        );
    }

    #[test]
    fn update_command_gets_pinned_versions() {
        let out = [OutdatedDep {
            name: "example.com/mod".to_string(),
            current: "v1.2.2".to_string(),
            latest: "v1.2.3".to_string(),
            detail: None,
            blocked: None,
            stale: None,
            current_released: None,
            latest_released: None,
            days_behind: None,
        }];
        assert_eq!(
            GoLang.update_command(Path::new("."), &out).as_deref(),
            Some("go get example.com/mod@v1.2.3")
        );
    }

    #[test]
    fn module_prefix_matching() {
        let modules: HashSet<&str> = ["github.com/fatih/color"].into_iter().collect();
        assert!(provided_by("github.com/fatih/color", &modules));
        assert!(provided_by("github.com/fatih/color/sub", &modules));
        assert!(!provided_by("github.com/spf13/cobra", &modules));
        assert!(!provided_by("github.com/fatih/colorx", &modules));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.21\n",
        )
        .unwrap();
        assert_eq!(module_path(dir.path()).as_deref(), Some("example.com/app"));
    }
}
