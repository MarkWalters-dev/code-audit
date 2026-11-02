//! Rust ecosystem, pure Rust: dependencies from `Cargo.toml` manifests
//! (workspace-aware, incl. `workspace = true` inheritance), current versions
//! from `Cargo.lock`, latest versions from the crates.io API.
//!
//! Outdated rule: with a lockfile entry the locked version is compared
//! against latest; otherwise latest must satisfy the declared requirement
//! (same answer `cargo` would resolve to).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use semver::{Version, VersionReq};
use serde::Deserialize;

use crate::ecosystem::{
    Ctx, Dep, EcosystemChecker, Gap, GapCheck, Inventory, LatestInfo, Notice, NoticeCheck,
    OutdatedDep,
};
use crate::http;
use crate::toolchains::{self, ToolId, ToolPin};

pub struct RustLang;

impl EcosystemChecker for RustLang {
    fn id(&self) -> &'static str {
        "rust"
    }

    fn display(&self) -> &'static str {
        "Rust"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "crates.io"
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("Cargo.toml").is_file()
    }

    fn enumerate(&self, root: &Path) -> Result<Inventory, String> {
        let manifests = collect_manifests(root);
        if manifests.is_empty() {
            return Err("cannot parse Cargo.toml".to_string());
        }
        let mut gaps = Vec::new();
        let mut gapped: HashSet<(String, String)> = HashSet::new();
        // Record (once per name+source) dependencies without published versions.
        let mut gap_for = |name: &str, entry: &toml::Value, gaps: &mut Vec<Gap>| {
            let Some(source) = skipped_source(entry) else {
                return;
            };
            if gapped.insert((name.to_string(), source.to_string())) {
                let reason = format!("{source} dependency has no published version");
                gaps.push(Gap {
                    name: name.to_string(),
                    check: GapCheck::Outdated,
                    reason: reason.clone(),
                });
                gaps.push(Gap {
                    name: name.to_string(),
                    check: GapCheck::Vulns,
                    reason,
                });
            }
        };
        let locked = parse_lockfile(&root.join("Cargo.lock"));
        let member_names: HashSet<String> = manifests
            .iter()
            .filter_map(|m| {
                m.doc
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
            })
            .collect();
        // Workspace tables for inheritance live in the root manifest.
        let root_doc = manifests
            .iter()
            .find(|m| m.is_root)
            .map(|m| &m.doc)
            .unwrap_or(&manifests[0].doc);

        let mut by_name: HashMap<String, Dep> = HashMap::new();
        for manifest in &manifests {
            for (section, kind) in [
                ("dependencies", None),
                ("dev-dependencies", Some("dev")),
                ("build-dependencies", Some("build")),
            ] {
                let Some(table) = manifest.doc.get(section).and_then(|v| v.as_table()) else {
                    continue;
                };
                for (name, entry) in table {
                    let Some(req) = resolve_requirement(root_doc, name, entry) else {
                        gap_for(name, entry, &mut gaps);
                        continue;
                    };
                    let mut dep = Dep::new(req.lookup_name);
                    dep.spec = Some(req.spec);
                    if let Some(k) = kind {
                        dep.detail = Some(k.to_string());
                    }
                    // Prefer entries that carry a kind-less (normal) declaration.
                    match by_name.get(&dep.name) {
                        Some(existing) if existing.detail.is_none() => {}
                        _ => {
                            by_name.insert(dep.name.clone(), dep);
                        }
                    }
                }
            }
            // Target-specific dependencies.
            if let Some(targets) = manifest.doc.get("target").and_then(|v| v.as_table()) {
                for target in targets.values() {
                    for (section, kind) in [
                        ("dependencies", Some("target")),
                        ("dev-dependencies", Some("target dev")),
                        ("build-dependencies", Some("target build")),
                    ] {
                        let Some(table) = target.get(section).and_then(|v| v.as_table()) else {
                            continue;
                        };
                        for (name, entry) in table {
                            let Some(req) = resolve_requirement(root_doc, name, entry) else {
                                gap_for(name, entry, &mut gaps);
                                continue;
                            };
                            by_name.entry(req.lookup_name.clone()).or_insert_with(|| {
                                let mut dep = Dep::new(req.lookup_name.clone());
                                dep.spec = Some(req.spec.clone());
                                dep.detail = Some(kind.unwrap_or("target").to_string());
                                dep
                            });
                        }
                    }
                }
            }
        }

        // Attach locked versions; anything locked but not declared is transitive.
        for dep in by_name.values_mut() {
            if let Some(versions) = locked.get(&dep.name) {
                dep.version = Some(versions[0].clone());
                if versions.len() > 1 {
                    let extra = format!("{} versions locked", versions.len());
                    dep.detail = Some(match dep.detail.take() {
                        Some(d) => format!("{d}; {extra}"),
                        None => extra,
                    });
                }
            }
        }
        for (name, versions) in &locked {
            if member_names.contains(name) || by_name.contains_key(name) {
                continue;
            }
            let mut dep = Dep::new(name.clone());
            dep.version = Some(versions[0].clone());
            dep.direct = false;
            dep.detail = Some("transitive".to_string());
            by_name.insert(name.clone(), dep);
        }

        let mut deps: Vec<Dep> = by_name.into_values().collect();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Inventory {
            deps,
            gaps,
            notes: Vec::new(),
        })
    }

    fn fetch_latest(&self, _ctx: &Ctx, dep: &Dep) -> Result<LatestInfo, String> {
        match crates_latest(&dep.name) {
            Ok(v) => Ok(LatestInfo::simple(v)),
            Err(e) => Err(crate::toolchains::request_reason("crates.io", &e)),
        }
    }

    fn resolve_version(&self, dep: &Dep) -> Result<Option<String>, String> {
        // No lockfile entry: resolve the requirement to the newest matching,
        // non-yanked release (what a fresh `cargo` resolve would pick).
        let Some(spec) = dep.spec.as_ref() else {
            return Ok(None);
        };
        let Ok(req) = spec.parse::<VersionReq>() else {
            return Ok(None);
        };
        let first_url = format!(
            "https://crates.io/api/v1/crates/{}/versions?per_page=100",
            dep.name
        );
        let mut last_err = None;
        let resolved =
            resolve_from_pages(
                &req,
                &dep.name,
                &first_url,
                |url| match http::get_json_retry(url) {
                    Ok(resp) => Some(resp),
                    Err(e) => {
                        last_err = Some(e);
                        None
                    }
                },
            );
        match resolved {
            Some(v) => Ok(Some(v)),
            None => match last_err {
                Some(e) => Err(crate::toolchains::request_reason("crates.io", &e)),
                None => Ok(None),
            },
        }
    }

    fn enumerate_tools(&self, root: &Path) -> Vec<ToolPin> {
        let mut pins = Vec::new();
        // MSRV floor from the root manifest.
        if let Ok(text) = std::fs::read_to_string(root.join("Cargo.toml"))
            && let Ok(doc) = toml::from_str::<toml::Value>(&text)
            && let Some(msrv) = doc
                .get("package")
                .and_then(|p| p.get("rust-version"))
                .and_then(|v| v.as_str())
        {
            pins.push(ToolPin {
                tool: ToolId::Rust,
                display: "rust (MSRV)".to_string(),
                version: None,
                spec: Some(msrv.to_string()),
            });
        }
        // Pinned toolchain.
        if let Ok(text) = std::fs::read_to_string(root.join("rust-toolchain.toml"))
            && let Ok(doc) = toml::from_str::<toml::Value>(&text)
        {
            let channel = doc
                .get("toolchain")
                .and_then(|t| t.get("channel"))
                .or_else(|| doc.get("channel"))
                .and_then(|v| v.as_str());
            if let Some(channel) = channel {
                match channel {
                    // Rolling channels cannot be outdated.
                    "stable" | "beta" | "nightly" => {}
                    dated if dated.starts_with("nightly-") => {
                        // Dated nightlies go stale fast: flag unless pinned today.
                        let date = dated.trim_start_matches("nightly-");
                        if date < toolchains::today_string().as_str() {
                            pins.push(ToolPin {
                                tool: ToolId::Rust,
                                display: format!("rust (rust-toolchain.toml: {dated})"),
                                version: Some(dated.to_string()),
                                spec: None,
                            });
                        }
                    }
                    pinned => pins.push(ToolPin {
                        tool: ToolId::Rust,
                        display: "rust (rust-toolchain.toml)".to_string(),
                        version: Some(pinned.to_string()),
                        spec: None,
                    }),
                }
            }
        }
        // Version managers.
        for (source, map) in [
            (".tool-versions", toolchains::parse_tool_versions(root)),
            ("mise", toolchains::parse_mise_toml(root)),
        ] {
            if let Some(version) = map.get("rust") {
                pins.push(ToolPin {
                    tool: ToolId::Rust,
                    display: format!("rust ({source})"),
                    version: Some(version.clone()),
                    spec: None,
                });
            }
        }
        pins
    }

    fn outdated(&self, dep: &Dep, latest: &str) -> Option<OutdatedDep> {
        let current = dep
            .version
            .clone()
            .or_else(|| dep.spec.clone())
            .unwrap_or_else(|| "unspecified".to_string());
        let is_outdated = match (&dep.version, &dep.spec) {
            (Some(locked), _) => semver_is_newer(locked, latest),
            (None, Some(req)) => !req_satisfies(req, latest),
            (None, None) => true,
        };
        if is_outdated {
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
        crates_release_dates(ctx, name, current, latest)
    }

    fn lint(
        &self,
        ctx: &Ctx,
        root: &Path,
        vulns: &[crate::osv::FoundVuln],
    ) -> crate::lint::LintOutcome {
        crate::lint::audit_rust(ctx, root, vulns)
    }

    fn dep_licenses(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
        crate_licenses(ctx, name, version)
    }

    fn dep_notice(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<Notice> {
        let mut notices = crate::licenses::license_notices(
            &ctx.license_policy,
            name,
            version,
            &self.dep_licenses(ctx, name, version),
        );
        if crate_yanked(ctx, name, version) {
            notices.push(Notice {
                check: NoticeCheck::Yanked,
                name: name.to_string(),
                message: format!("{version} is yanked on crates.io"),
                file: None,
                line: None,
            });
        }
        notices
    }

    fn project_notices(&self, _ctx: &Ctx, root: &Path, inventory: &[Dep]) -> Vec<Notice> {
        let mut notices =
            crate::ecosystem::bloat_notices(&parse_lockfile(&root.join("Cargo.lock")));
        let declared = manifest_keys(root);
        let transitive = crate::ghost::transitive_names(inventory, crate::ghost::normalize_crate);
        let std: HashSet<&str> = crate::ghost::RUST_STDLIB.iter().copied().collect();
        notices.extend(crate::ghost::scan(
            root,
            &["rs"],
            crate::ghost::rust_imports,
            |spec| std.contains(spec) || declared.contains(&crate::ghost::normalize_crate(spec)),
            |spec| transitive.contains(&crate::ghost::normalize_crate(spec)),
        ));
        notices
    }

    fn update_command(&self, _root: &Path, outdated: &[OutdatedDep]) -> Option<String> {
        // Requires cargo-edit: bumps Cargo.toml requirements to the reported
        // latests, including incompatible and pinned ones.
        let pkgs = outdated
            .iter()
            .map(|d| format!("-p {}", d.name))
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!("cargo upgrade --incompatible --pinned {pkgs}"))
    }
}

/// Newest stable release of a crate (shared by the outdated check and the
/// vulnerability-alternative resolver).
pub(crate) fn crates_latest(name: &str) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct CrateInfo {
        max_stable_version: Option<String>,
    }
    #[derive(Deserialize)]
    struct Resp {
        #[serde(rename = "crate")]
        crate_info: CrateInfo,
    }
    let url = format!("https://crates.io/api/v1/crates/{name}");
    let resp: Resp = http::get_json_retry(&url)?;
    resp.crate_info
        .max_stable_version
        .ok_or_else(|| anyhow::anyhow!("no stable releases on crates.io"))
}

/// Walk cursor-paginated version listings, keeping every non-yanked match.
/// A failed page ends the walk but keeps earlier matches: a transient
/// failure must not wipe out an already-found resolution.
fn resolve_from_pages(
    req: &VersionReq,
    crate_name: &str,
    first_url: &str,
    mut fetch: impl FnMut(&str) -> Option<VersionsResp>,
) -> Option<String> {
    let mut matches: Vec<Version> = Vec::new();
    let mut url = first_url.to_string();
    for _ in 0..8 {
        let Some(resp) = fetch(&url) else {
            break;
        };
        if resp.versions.is_empty() {
            break;
        }
        for v in resp.versions {
            if v.yanked {
                continue;
            }
            let Ok(ver) = v.num.parse::<Version>() else {
                continue;
            };
            if req.matches(&ver) {
                matches.push(ver);
            }
        }
        let Some(next) = resp.meta.and_then(|m| m.next_page) else {
            break;
        };
        url = join_next_page(crate_name, &next);
    }
    // Prefer stable releases; allow pre-releases only when nothing stable matches.
    let stable: Vec<&Version> = matches.iter().filter(|v| v.pre.is_empty()).collect();
    let pool = if stable.is_empty() {
        matches.iter().collect()
    } else {
        stable
    };
    pool.into_iter().max().map(ToString::to_string)
}

/// Join a `meta.next_page` cursor, which is usually a bare query string.
fn join_next_page(crate_name: &str, next: &str) -> String {
    if next.starts_with("http") {
        next.to_string()
    } else if next.starts_with('/') {
        format!("https://crates.io{next}")
    } else {
        format!("https://crates.io/api/v1/crates/{crate_name}/versions{next}")
    }
}

#[derive(Debug, Deserialize)]
struct VersionsResp {
    #[serde(default)]
    versions: Vec<VersionEntry>,
    #[serde(default)]
    meta: Option<VersionsMeta>,
}

#[derive(Debug, Deserialize)]
struct VersionsMeta {
    next_page: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VersionEntry {
    num: String,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    created_at: Option<String>,
}

fn semver_is_newer(current: &str, latest: &str) -> bool {
    match (current.parse::<Version>(), latest.parse::<Version>()) {
        (Ok(a), Ok(b)) => a < b,
        _ => current != latest,
    }
}

fn req_satisfies(req: &str, latest: &str) -> bool {
    let (Ok(req), Ok(version)) = (req.parse::<VersionReq>(), latest.parse::<Version>()) else {
        return false;
    };
    req.matches(&version)
}

/// Why a dependency entry carries no published version (for gap reporting).
fn skipped_source(entry: &toml::Value) -> Option<&'static str> {
    let table = entry.as_table()?;
    if table.contains_key("path") {
        Some("path")
    } else if table.contains_key("git") {
        Some("git")
    } else {
        None
    }
}

struct Requirement {
    /// Crate name on the registry (rename-aware).
    lookup_name: String,
    spec: String,
}

/// Resolve a dependency entry to a registry requirement.
/// Returns `None` for path/git-only dependencies (no published version).
fn resolve_requirement(
    root_doc: &toml::Value,
    name: &str,
    entry: &toml::Value,
) -> Option<Requirement> {
    match entry {
        toml::Value::String(req) => Some(Requirement {
            lookup_name: name.to_string(),
            spec: req.clone(),
        }),
        toml::Value::Table(t) => {
            // `foo.workspace = true` inherits from [workspace.dependencies].
            if t.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
                let inherited = root_doc
                    .get("workspace")
                    .and_then(|w| w.get("dependencies"))
                    .and_then(|d| d.get(name))?;
                return resolve_requirement(root_doc, name, inherited);
            }
            // Renamed dependency: actual crate is `package`.
            let lookup = t
                .get("package")
                .and_then(|v| v.as_str())
                .unwrap_or(name)
                .to_string();
            // Explicit version, possibly inherited from [workspace.package].
            if let Some(v) = t.get("version") {
                if let Some(req) = v.as_str() {
                    return Some(Requirement {
                        lookup_name: lookup,
                        spec: req.to_string(),
                    });
                }
                if v.get("workspace").and_then(|w| w.as_bool()) == Some(true) {
                    let req = root_doc
                        .get("workspace")
                        .and_then(|w| w.get("package"))
                        .and_then(|p| p.get("version"))
                        .and_then(|v| v.as_str())?;
                    return Some(Requirement {
                        lookup_name: lookup,
                        spec: req.to_string(),
                    });
                }
            }
            None // path/git-only
        }
        _ => None,
    }
}

struct ManifestDoc {
    doc: toml::Value,
    is_root: bool,
}

/// Root manifest plus all workspace member manifests (nested included).
fn collect_manifests(root: &Path) -> Vec<ManifestDoc> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    let root_manifest = root.join("Cargo.toml");
    let Ok(text) = std::fs::read_to_string(&root_manifest) else {
        return out;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return out;
    };
    // The root doc always stays: members inherit tables from it, and a virtual
    // manifest contributes no dependencies of its own.
    out.push(ManifestDoc {
        doc: doc.clone(),
        is_root: true,
    });
    visited.insert(root_manifest);
    expand_workspace_members(root, &doc, &mut visited, &mut out);
    out
}

fn expand_workspace_members(
    dir: &Path,
    doc: &toml::Value,
    visited: &mut HashSet<PathBuf>,
    out: &mut Vec<ManifestDoc>,
) {
    let Some(workspace) = doc.get("workspace") else {
        return;
    };
    let members = workspace
        .get("members")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let exclude: HashSet<String> = workspace
        .get("exclude")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    for pattern in members.iter().filter_map(|v| v.as_str()) {
        if exclude.contains(pattern) {
            continue;
        }
        for member_dir in expand_member_pattern(dir, pattern) {
            if exclude.iter().any(|e| member_dir.ends_with(e)) {
                continue;
            }
            let manifest = member_dir.join("Cargo.toml");
            if !visited.insert(manifest.clone()) || !manifest.is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
                continue;
            };
            let is_package = doc.get("package").is_some();
            if is_package {
                out.push(ManifestDoc {
                    doc: doc.clone(),
                    is_root: false,
                });
            }
            expand_workspace_members(&member_dir, &doc, visited, out);
        }
    }
}

/// Expand one workspace member pattern: exact path or single-`*` glob.
fn expand_member_pattern(dir: &Path, pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') {
        let candidate = dir.join(pattern);
        return if candidate.is_dir() {
            vec![candidate]
        } else {
            Vec::new()
        };
    }
    let (prefix, suffix) = pattern.split_once('*').unwrap_or((pattern, ""));
    // Only single-level globs (`crates/*`) are supported.
    if prefix.contains('*') || suffix.contains('*') || suffix.contains('/') {
        return Vec::new();
    }
    let base = dir.join(prefix);
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(suffix))
        })
        .collect()
}

/// Manifest dependency-table keys (the names `use` sees, including
/// renames): normal, dev, build, and per-target tables, unioned over
/// workspace members.
pub(crate) fn manifest_keys(root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    for dir in crate::ghost::find_manifest_dirs(root, &|d| d.join("Cargo.toml").is_file()) {
        manifest_keys_in(&dir, &mut out);
    }
    out
}

fn manifest_keys_in(dir: &Path, out: &mut HashSet<String>) {
    let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
        return;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return;
    };
    let mut tables = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        tables.push(doc.get(section));
    }
    if let Some(targets) = doc.get("target").and_then(|t| t.as_table()) {
        for table in targets.values() {
            tables.push(table.get("dependencies"));
        }
    }
    for table in tables.into_iter().flatten() {
        if let Some(map) = table.as_table() {
            out.extend(map.keys().map(|k| crate::ghost::normalize_crate(k)));
        }
    }
}

/// `Cargo.lock` name -> locked versions (ascending semver).
fn parse_lockfile(path: &Path) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return map;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return map;
    };
    if let Some(packages) = doc.get("package").and_then(|v| v.as_array()) {
        for pkg in packages {
            if let (Some(name), Some(version)) = (
                pkg.get("name").and_then(|v| v.as_str()),
                pkg.get("version").and_then(|v| v.as_str()),
            ) {
                map.entry(name.to_string())
                    .or_default()
                    .push(version.to_string());
            }
        }
    }
    for versions in map.values_mut() {
        versions.sort_by(|a, b| match (a.parse::<Version>(), b.parse::<Version>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => a.cmp(b),
        });
        versions.dedup();
    }
    map
}

/// Release dates from the cursor-paginated version listing: each entry
/// carries its `created_at` timestamp. The walk stops once both dates are
/// found (usually the first page). Failures yield `None`, never gaps.
fn crates_release_dates(
    ctx: &Ctx,
    name: &str,
    current: &str,
    latest: &str,
) -> (Option<String>, Option<String>) {
    use crate::ecosystem::cached_release_date;
    let cached = |version: &str| cached_release_date(ctx, "rust", name, version);
    let current_date = cached(current);
    let latest_date = cached(latest);
    if current_date.is_some() && latest_date.is_some() {
        return (current_date, latest_date);
    }
    cache_version_facts(ctx, name, || {
        cached(current).is_some() && cached(latest).is_some()
    });
    (
        current_date.or_else(|| cached(current)),
        latest_date.or_else(|| cached(latest)),
    )
}

fn yanked_key(name: &str, version: &str) -> String {
    format!("v1:yanked:rust:{name}:{version}")
}

/// Walk the versions listing caching release dates (forever) and yanked
/// flags (re-checked on the version TTL) until `stop` holds.
fn cache_version_facts(ctx: &Ctx, name: &str, stop: impl Fn() -> bool) {
    use crate::ecosystem::release_date_key;
    let mut url = format!("https://crates.io/api/v1/crates/{name}/versions?per_page=100");
    for _ in 0..8 {
        let Ok(resp) = http::get_json_retry::<VersionsResp>(&url) else {
            break;
        };
        if resp.versions.is_empty() {
            break;
        }
        for v in &resp.versions {
            if let Some(date) = v.created_at.as_deref().and_then(crate::dates::iso_date) {
                ctx.cache
                    .set(&release_date_key("rust", name, &v.num), &date);
            }
            ctx.cache.set(&yanked_key(name, &v.num), &v.yanked);
        }
        if stop() {
            break;
        }
        let Some(next) = resp.meta.and_then(|m| m.next_page) else {
            break;
        };
        url = join_next_page(name, &next);
    }
}

/// Whether a used version is yanked. Needs positive evidence: failures
/// and absences assume not yanked.
fn crate_yanked(ctx: &Ctx, name: &str, version: &str) -> bool {
    let key = yanked_key(name, version);
    if let Some(yanked) = ctx.cache.get(&key, ctx.cache.versions_ttl()) {
        return yanked;
    }
    cache_version_facts(ctx, name, || {
        ctx.cache.get::<bool>(&key, u64::MAX).is_some()
    });
    ctx.cache
        .get(&key, ctx.cache.versions_ttl())
        .or_else(|| ctx.cache.get_stale(&key))
        .unwrap_or(false)
}

/// Exact license of a used version from the local registry sources
/// (read-only): the unpacked Cargo.toml the build itself used. `None`
/// means no manifest was found (unresolved); `Some` (even empty) is a
/// resolution and caches forever.
fn registry_src_license(name: &str, version: &str) -> Option<Vec<String>> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cargo")))?;
    let indexes = std::fs::read_dir(cargo_home.join("registry/src")).ok()?;
    for index in indexes.flatten() {
        let dir = index.path().join(format!("{name}-{version}"));
        let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        let Some(package) = doc.get("package") else {
            continue;
        };
        if let Some(declared) = package.get("license").and_then(|l| l.as_str()) {
            return Some(crate::licenses::normalize_spdx(declared));
        }
        if let Some(file) = package.get("license-file").and_then(|l| l.as_str())
            && let Ok(text) = std::fs::read_to_string(dir.join(file))
        {
            return Some(crate::licenses::classify_license_text(&text));
        }
        // A manifest without license keys still answers: unknown.
        return Some(Vec::new());
    }
    None
}

/// Per-version document from `/crates/{name}/{version}`. Crate-level
/// documents carry no usable license, so the used version is queried.
#[derive(Deserialize)]
struct LicenseDoc {
    #[serde(default)]
    version: Option<LicenseVersion>,
}

#[derive(Deserialize)]
struct LicenseVersion {
    #[serde(default)]
    license: Option<String>,
}

/// License ids from a parsed per-version document. `None` means the
/// document has no version license (genuinely unknown).
fn version_doc_license(doc: &LicenseDoc) -> Option<Vec<String>> {
    doc.version
        .as_ref()?
        .license
        .as_deref()
        .map(crate::licenses::normalize_spdx)
}

/// Exact license of the used version from the API, only when the
/// registry sources are unavailable. A published version is immutable,
/// so successes (even empty) cache forever; failures stay uncached.
fn crates_api_license(ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    let key = format!("v1:license:rust:{name}:{version}");
    // Fetch/parse failures (offline, rate limit, short body) stay
    // uncached for retry.
    let Ok(text) = http::get_text_retry(&url) else {
        return Vec::new();
    };
    let Ok(doc) = serde_json::from_str::<LicenseDoc>(&text) else {
        return Vec::new();
    };
    match version_doc_license(&doc) {
        Some(licenses) => {
            ctx.cache
                .store_license_resolution(&key, "rust", name, version, &licenses);
            licenses
        }
        // A fetched version without a license key is definitively
        // unknown (published versions are immutable).
        None => {
            ctx.cache
                .store_license_resolution(&key, "rust", name, version, &[]);
            Vec::new()
        }
    }
}

fn crate_licenses(ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
    let exact_key = format!("v1:license:rust:{name}:{version}");
    // `Some` (even empty) means resolved: unknown stays unknown.
    if let Some(licenses) = ctx
        .cache
        .license_resolution(&exact_key, "rust", name, version)
    {
        return licenses;
    }
    if let Some(licenses) = registry_src_license(name, version) {
        ctx.cache
            .store_license_resolution(&exact_key, "rust", name, version, &licenses);
        return licenses;
    }
    crates_api_license(ctx, name, version)
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
            &release_date_key("rust", "serde", "1.0.100"),
            &"2019-09-08".to_string(),
        );
        ctx.cache.set(
            &release_date_key("rust", "serde", "1.0.229"),
            &"2026-07-18".to_string(),
        );
        assert_eq!(
            RustLang.release_dates(&ctx, "serde", "1.0.100", "1.0.229"),
            (
                Some("2019-09-08".to_string()),
                Some("2026-07-18".to_string())
            )
        );
    }

    fn page(nums: &[(&str, bool)], next: Option<&str>) -> VersionsResp {
        VersionsResp {
            versions: nums
                .iter()
                .map(|(num, yanked)| VersionEntry {
                    num: num.to_string(),
                    yanked: *yanked,
                    created_at: None,
                })
                .collect(),
            meta: Some(VersionsMeta {
                next_page: next.map(str::to_string),
            }),
        }
    }

    #[test]
    fn joins_relative_next_page() {
        assert_eq!(
            join_next_page("regex", "?per_page=100&seek=abc"),
            "https://crates.io/api/v1/crates/regex/versions?per_page=100&seek=abc"
        );
        assert_eq!(
            join_next_page("regex", "https://other.example/x"),
            "https://other.example/x"
        );
        assert_eq!(
            join_next_page("regex", "/api/v1/crates/regex/versions?seek=abc"),
            "https://crates.io/api/v1/crates/regex/versions?seek=abc"
        );
    }

    #[test]
    fn keeps_earlier_matches_when_page_fails() {
        let req: VersionReq = ">=1.5.0, <1.5.5".parse().unwrap();
        let mut calls = 0;
        let got = resolve_from_pages(&req, "regex", "https://first", |url| {
            calls += 1;
            if url == "https://first" {
                Some(page(
                    &[("1.13.1", false), ("1.5.4", false)],
                    Some("?seek=next"),
                ))
            } else {
                assert_eq!(
                    url,
                    "https://crates.io/api/v1/crates/regex/versions?seek=next"
                );
                None // second page fails: earlier match must survive
            }
        });
        assert_eq!(got.as_deref(), Some("1.5.4"));
        assert_eq!(calls, 2);
    }

    #[test]
    fn prefers_max_stable_match() {
        let req: VersionReq = "^1".parse().unwrap();
        let got = resolve_from_pages(&req, "demo", "https://only", |_| {
            Some(page(
                &[("1.5.4", false), ("1.6.0-beta.1", false), ("1.5.5", true)],
                None,
            ))
        });
        assert_eq!(got.as_deref(), Some("1.5.4")); // yanked + pre-release skipped
    }

    #[test]
    fn enumerates_tool_pins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\nrust-version = \"1.70\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.75.0\"\n",
        )
        .unwrap();
        let pins = RustLang.enumerate_tools(dir.path());
        assert_eq!(pins.len(), 2);
        assert!(pins.iter().any(|p| p.display == "rust (MSRV)"));
        assert!(pins.iter().any(|p| p.version.as_deref() == Some("1.75.0")));
    }

    #[test]
    fn skips_rolling_toolchain_channels() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        std::fs::write(
            dir.path().join("rust-toolchain.toml"),
            "channel = \"stable\"\n",
        )
        .unwrap();
        assert!(RustLang.enumerate_tools(dir.path()).is_empty());
    }

    #[test]
    fn req_semantics() {
        assert!(req_satisfies("^1.0", "1.5.0"));
        assert!(req_satisfies("1.0", "1.5.0"));
        assert!(!req_satisfies("1.0", "2.0.0"));
        assert!(req_satisfies("*", "9.9.9"));
        assert!(!req_satisfies("=1.0.100", "1.0.229"));
    }

    #[test]
    fn manifest_lock_and_transitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\n\n[[package]]\nname = \"serde_core\"\nversion = \"1.0.100\"\n",
        )
        .unwrap();
        let deps = RustLang.enumerate(dir.path()).unwrap().deps;
        // Own package excluded; serde direct+locked; serde_core transitive.
        assert_eq!(deps.len(), 2);
        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert!(serde.direct);
        assert_eq!(serde.version.as_deref(), Some("1.0.100"));
        let core = deps.iter().find(|d| d.name == "serde_core").unwrap();
        assert!(!core.direct);
    }

    #[test]
    fn workspace_inheritance_and_members() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("crates").join("a")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n[workspace.dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("crates").join("a").join("Cargo.toml"),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[dependencies]\nserde.workspace = true\nlocal = { path = \"../b\" }\n",
        )
        .unwrap();
        let inventory = RustLang.enumerate(dir.path()).unwrap();
        assert_eq!(inventory.deps.len(), 1);
        assert_eq!(inventory.deps[0].name, "serde");
        assert_eq!(inventory.deps[0].spec.as_deref(), Some("1"));
        // The path-only dep is reported as a gap, not silently dropped.
        assert_eq!(inventory.gaps.len(), 2);
        assert!(inventory.gaps.iter().all(|g| g.name == "local"));
    }

    #[test]
    fn update_command_pins_packages() {
        let out = ["a", "b"]
            .into_iter()
            .map(|n| OutdatedDep {
                name: n.to_string(),
                current: "1.0".to_string(),
                latest: "1.1".to_string(),
                detail: None,
                blocked: None,
                stale: None,
                current_released: None,
                latest_released: None,
                days_behind: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            RustLang.update_command(Path::new("."), &out).as_deref(),
            Some("cargo upgrade --incompatible --pinned -p a -p b")
        );
    }

    #[test]
    fn version_doc_license_reads_per_version_field() {
        // Crate-level documents carry no license; only the nested
        // per-version license counts (regression: `crate.license`
        // silently resolved everything to unknown).
        let doc: LicenseDoc =
            serde_json::from_str(r#"{"version":{"num":"1.12.0","license":"MIT OR Apache-2.0"}}"#)
                .unwrap();
        assert_eq!(
            version_doc_license(&doc).unwrap(),
            vec!["MIT".to_string(), "Apache-2.0".to_string()]
        );
        let doc: LicenseDoc = serde_json::from_str(r#"{"version":{"num":"1.0.0"}}"#).unwrap();
        assert!(version_doc_license(&doc).is_none());
        let doc: LicenseDoc =
            serde_json::from_str(r#"{"crate":{"id":"regex","license":"MIT"}}"#).unwrap();
        assert!(version_doc_license(&doc).is_none());
    }

    #[test]
    fn bloat_flags_multi_version_crates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"

[[package]]
name = "serde"
version = "1.0.100"

[[package]]
name = "regex"
version = "1.12.0"
"#,
        )
        .unwrap();
        let notices =
            crate::ecosystem::bloat_notices(&parse_lockfile(&dir.path().join("Cargo.lock")));
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].check, NoticeCheck::Bloat);
        assert_eq!(notices[0].name, "serde");
        assert_eq!(notices[0].message, "2 locked versions: 1.0.100, 1.0.228");
    }

    #[test]
    fn manifest_keys_covers_all_tables_with_renames() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n\
             [dependencies]\nserde = \"1\"\nold = { package = \"serde\", version = \"1\" }\n\n\
             [dev-dependencies]\npretty = \"0.1\"\n\n\
             [target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
        )
        .unwrap();
        let keys = manifest_keys(dir.path());
        assert!(keys.contains("serde"));
        assert!(keys.contains("old"));
        assert!(keys.contains("pretty"));
        assert!(keys.contains("libc"));
    }
}
