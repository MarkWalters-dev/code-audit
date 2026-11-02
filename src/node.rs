//! JavaScript/TypeScript ecosystem, pure Rust: specs from `package.json`,
//! latest versions from the npm registry (`/<pkg>/latest`).
//!
//! Outdated rule: with an installed copy in `node_modules` the installed
//! version is compared against latest; otherwise latest must satisfy the
//! declared range (same answer `npm install` would converge to).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use node_semver::{Range, Version as NpmVersion};
use serde::Deserialize;

use crate::ecosystem::{
    Ctx, Dep, EcosystemChecker, Gap, GapCheck, Inventory, LatestInfo, Notice, NoticeCheck,
    OutdatedDep,
};
use crate::http;
use crate::toolchains::{self, ToolId, ToolPin};

pub struct Node;

impl EcosystemChecker for Node {
    fn id(&self) -> &'static str {
        "node"
    }

    fn display(&self) -> &'static str {
        "JavaScript"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("package.json").is_file()
    }

    fn enumerate(&self, root: &Path) -> Result<Inventory, String> {
        let manifest = read_manifest(root)?;
        let locked = locked_versions(root);
        // `catalog:` specs resolve through the workspace catalogs when no
        // lockfile or install pins the version (both pnpm and bun agree
        // on the `catalog:` / `catalog:<name>` spellings).
        let mut catalogs = pnpm_catalogs(root);
        if let Some(lock_path) = find_up(root, "bun.lock") {
            if let Some(lock_dir) = lock_path.parent() {
                for (k, v) in bun_catalogs(lock_dir) {
                    catalogs.entry(k).or_insert(v);
                }
            }
        }
        let mut deps = Vec::new();
        let mut first_party = 0;
        for (section, detail) in [
            (manifest.dependencies, None),
            (manifest.dev_dependencies, Some("dev")),
            (manifest.peer_dependencies, Some("peer")),
            (manifest.optional_dependencies, Some("optional")),
        ] {
            for (name, spec) in section {
                // First-party specs have no upstream to check.
                if spec.starts_with("workspace:")
                    || spec.starts_with("link:")
                    || spec.starts_with("file:")
                {
                    first_party += 1;
                    continue;
                }
                let mut dep = Dep::new(name.clone());
                dep.spec = Some(spec.clone());
                if let Some(kind) = detail {
                    dep.detail = Some(kind.to_string());
                }
                // Installed version wins, then the lockfile, then a
                // resolved `catalog:` spec.
                if let Some(installed) = installed_version(root, &name) {
                    dep.version = Some(installed);
                } else if let Some(pinned) = locked.get(&name) {
                    dep.version = Some(pinned.clone());
                } else if let Some(pinned) = resolve_catalog_spec(&spec, &name, &catalogs) {
                    dep.version = Some(pinned);
                }
                deps.push(dep);
            }
        }
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        let mut notes = Vec::new();
        if first_party == 1 {
            notes.push("1 first-party dependency skipped (workspace:/link:/file: spec)".to_string());
        } else if first_party > 1 {
            notes.push(format!(
                "{first_party} first-party dependencies skipped (workspace:/link:/file: specs)"
            ));
        }
        let mut gaps = Vec::new();
        let has_text_lock = root.join("package-lock.json").is_file()
            || root.join("bun.lock").is_file()
            || root.join("yarn.lock").is_file()
            || find_up(root, "pnpm-lock.yaml").is_some();
        if root.join("bun.lockb").is_file() && !has_text_lock {
            // Versions still resolve via node_modules or specs, but the
            // binary lockfile itself is never read: name it so the gap is
            // visible rather than silent.
            gaps.push(Gap {
                name: "bun.lockb".to_string(),
                check: GapCheck::Outdated,
                reason: "binary lockfile with no stable spec; versions come from node_modules or specs (run `bun install` to generate bun.lock)".to_string(),
            });
        }
        Ok(Inventory { deps, gaps, notes })
    }

    fn fetch_latest(&self, _ctx: &Ctx, dep: &Dep) -> Result<LatestInfo, String> {
        #[derive(Deserialize)]
        struct Latest {
            version: String,
        }
        // Scoped names go on the wire as @scope%2fname.
        let encoded = dep.name.replace('/', "%2f");
        let url = format!("https://registry.npmjs.org/{encoded}/latest");
        match http::get_json_retry::<Latest>(&url) {
            Ok(r) => Ok(LatestInfo::simple(r.version)),
            Err(e) => Err(toolchains::request_reason("npm registry", &e)),
        }
    }

    fn resolve_version(&self, dep: &Dep) -> Result<Option<String>, String> {
        // An exact spec is already a version (also enables vuln queries).
        let Some(spec) = dep.spec.as_ref() else {
            return Ok(None);
        };
        Ok(spec.parse::<NpmVersion>().ok().map(|_| spec.clone()))
    }

    fn enumerate_tools(&self, root: &Path) -> Vec<ToolPin> {
        let mut pins = Vec::new();
        if let Ok(manifest) = read_manifest(root) {
            for (name, spec) in &manifest.engines {
                if let Some(tool) = engine_tool(name) {
                    pins.push(ToolPin {
                        tool,
                        display: format!("{} (engines)", tool.display()),
                        version: None,
                        spec: Some(spec.clone()),
                    });
                }
            }
            // Corepack field: "pnpm@9.1.0".
            if let Some(pm) = &manifest.package_manager
                && let Some((name, version)) = pm.rsplit_once('@')
                && let Some(tool) = engine_tool(name)
            {
                pins.push(ToolPin {
                    tool,
                    display: format!("{} (packageManager)", tool.display()),
                    version: Some(version.to_string()),
                    spec: None,
                });
            }
            for (name, version) in &manifest.volta {
                if let Some(tool) = engine_tool(name) {
                    pins.push(ToolPin {
                        tool,
                        display: format!("{} (volta)", tool.display()),
                        version: Some(version.clone()),
                        spec: None,
                    });
                }
            }
        }
        for file in [".nvmrc", ".node-version"] {
            if let Ok(text) = std::fs::read_to_string(root.join(file)) {
                let version = text.trim().trim_start_matches('v').to_string();
                if !version.is_empty() {
                    pins.push(ToolPin {
                        tool: ToolId::Node,
                        display: format!("node ({file})"),
                        version: Some(version),
                        spec: None,
                    });
                }
            }
        }
        // Version managers.
        for (source, managers) in [
            (".tool-versions", toolchains::parse_tool_versions(root)),
            ("mise", toolchains::parse_mise_toml(root)),
        ] {
            for (key, tool) in [
                ("node", ToolId::Node),
                ("nodejs", ToolId::Node),
                ("npm", ToolId::Npm),
                ("pnpm", ToolId::Pnpm),
                ("yarn", ToolId::Yarn),
                ("bun", ToolId::Bun),
            ] {
                if let Some(version) = managers.get(key) {
                    pins.push(ToolPin {
                        tool,
                        display: format!("{} ({source})", tool.display()),
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
            .or_else(|| dep.spec.clone())
            .unwrap_or_else(|| "unspecified".to_string());
        let is_outdated = match (&dep.version, &dep.spec) {
            // Installed copy: outdated when latest is strictly newer.
            (Some(installed), _) => npm_is_newer(installed, latest),
            // Spec only: outdated when latest falls outside the range.
            (None, Some(spec)) => !range_satisfies(spec, latest),
            (None, None) => true,
        };
        if is_outdated {
            let mut detail = dep.detail.clone();
            if dep.version.is_none() {
                detail = Some(match detail {
                    Some(d) => format!("{d}; not installed"),
                    None => "not installed".to_string(),
                });
            }
            Some(OutdatedDep {
                name: dep.display.clone(),
                current,
                latest: latest.to_string(),
                detail,
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
        npm_release_dates(ctx, name, current, latest)
    }

    fn lint(
        &self,
        ctx: &Ctx,
        root: &Path,
        vulns: &[crate::osv::FoundVuln],
    ) -> crate::lint::LintOutcome {
        crate::lint::audit_node(ctx, root, vulns)
    }

    fn dep_licenses(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
        npm_facts(ctx, name, version).licenses
    }

    fn dep_notice(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<Notice> {
        let facts = npm_facts(ctx, name, version);
        let mut notices =
            crate::licenses::license_notices(&ctx.license_policy, name, version, &facts.licenses);
        if let Some(reason) = &facts.deprecated {
            let message = if reason.is_empty() {
                format!("{version} is deprecated on npm")
            } else {
                format!("{version} is deprecated on npm: {reason}")
            };
            notices.push(Notice {
                check: NoticeCheck::Yanked,
                name: name.to_string(),
                message,
                file: None,
                line: None,
            });
        }
        if let Some(notice) = crate::licenses::eol_notice(ctx, "node", name, version) {
            notices.push(notice);
        }
        notices
    }

    fn project_notices(&self, _ctx: &Ctx, root: &Path, inventory: &[Dep]) -> Vec<Notice> {
        let mut notices = crate::ecosystem::bloat_notices(&lock_versions(root));
        let dirs = crate::ghost::find_manifest_dirs(root, &|d| d.join("package.json").is_file());
        let declared: HashSet<String> = dirs.iter().flat_map(|d| manifest_keys(d)).collect();
        let transitive = crate::ghost::transitive_names(inventory, str::to_string);
        let builtins: HashSet<&str> = crate::ghost::NODE_BUILTINS.iter().copied().collect();
        let aliases = tsconfig_aliases(root);
        notices.extend(crate::ghost::scan(
            root,
            &["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"],
            crate::ghost::node_imports,
            |spec| {
                if is_alias_import(spec, &aliases) {
                    return true;
                }
                let pkg = crate::ghost::node_package(spec);
                builtins.contains(pkg) || declared.contains(pkg)
            },
            |spec| transitive.contains(crate::ghost::node_package(spec)),
        ));
        notices.extend(crate::deadcode::node_dead(
            root,
            &tsconfig_paths(root),
            &manifest_entries(root),
        ));
        notices
    }

    fn update_command(&self, root: &Path, outdated: &[OutdatedDep]) -> Option<String> {
        let pkgs = outdated
            .iter()
            .map(|d| format!("{}@{}", d.name, d.latest))
            .collect::<Vec<_>>()
            .join(" ");
        if root.join("pnpm-lock.yaml").is_file() {
            Some(format!("pnpm update {pkgs}"))
        } else if root.join("yarn.lock").is_file() {
            if root.join(".yarnrc.yml").is_file() {
                Some(format!("yarn up {pkgs}"))
            } else {
                Some(format!("yarn upgrade {pkgs}"))
            }
        } else {
            Some(format!("npm install {pkgs}"))
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct Manifest {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies: HashMap<String, String>,
    #[serde(rename = "peerDependencies", default)]
    peer_dependencies: HashMap<String, String>,
    #[serde(rename = "optionalDependencies", default)]
    optional_dependencies: HashMap<String, String>,
    #[serde(default)]
    engines: HashMap<String, String>,
    #[serde(default, rename = "packageManager")]
    package_manager: Option<String>,
    #[serde(default)]
    volta: HashMap<String, String>,
    #[serde(default)]
    main: Option<String>,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    types: Option<String>,
    #[serde(default)]
    bin: serde_json::Value,
    #[serde(default)]
    exports: serde_json::Value,
    #[serde(default)]
    scripts: HashMap<String, String>,
}

fn engine_tool(name: &str) -> Option<ToolId> {
    match name {
        "node" => Some(ToolId::Node),
        "npm" => Some(ToolId::Npm),
        "pnpm" => Some(ToolId::Pnpm),
        "yarn" => Some(ToolId::Yarn),
        "bun" => Some(ToolId::Bun),
        _ => None,
    }
}

fn read_manifest(root: &Path) -> Result<Manifest, String> {
    let raw = std::fs::read_to_string(root.join("package.json"))
        .map_err(|e| format!("cannot read package.json: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid package.json: {e}"))
}

/// Path mappings from tsconfig/jsconfig `compilerOptions.paths`,
/// unioned over member configs: (prefix minus trailing `/*`, targets).
/// tsconfig is JSONC, like bun.lock.
fn tsconfig_paths(root: &Path) -> Vec<(String, Vec<String>)> {
    #[derive(Deserialize, Default)]
    struct Paths {
        #[serde(default)]
        paths: HashMap<String, Vec<String>>,
    }
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct Config {
        #[serde(default)]
        compiler_options: Paths,
    }
    let mut out = Vec::new();
    for dir in crate::ghost::find_manifest_dirs(root, &|d| {
        d.join("tsconfig.json").is_file() || d.join("jsconfig.json").is_file()
    }) {
        for file in ["tsconfig.json", "jsconfig.json"] {
            let Ok(raw) = std::fs::read_to_string(dir.join(file)) else {
                continue;
            };
            let Ok(config) = serde_json::from_str::<Config>(&jsonc_to_json(&raw)) else {
                continue;
            };
            for (key, targets) in &config.compiler_options.paths {
                let prefix = key.trim_end_matches("/*").trim_end_matches('*');
                if prefix.is_empty() || targets.is_empty() {
                    continue;
                }
                // Targets are relative to their own tsconfig dir, not the
                // scan root: absolutize now so monorepo aliases resolve to
                // the owning member. The `*` stays for rest substitution.
                let absolutized = targets
                    .iter()
                    .map(|t| {
                        dir.join(t.trim_start_matches("./"))
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect();
                out.push((prefix.to_string(), absolutized));
            }
        }
    }
    out
}

/// Path-alias prefixes for first-party matching.
fn tsconfig_aliases(root: &Path) -> HashSet<String> {
    tsconfig_paths(root)
        .into_iter()
        .map(|(prefix, _)| prefix)
        .collect()
}

/// Manifest entry files (main/module/types/bin/exports) resolved to
/// source paths: built-output dirs (`dist/`, `lib/`, `build/`) map back
/// to sources, and `.js` swaps to sibling `.ts`/`.tsx`/`.mts`/`.cts`.
fn manifest_entries(root: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    for dir in crate::ghost::find_manifest_dirs(root, &|d| d.join("package.json").is_file()) {
        let Ok(manifest) = read_manifest(&dir) else {
            continue;
        };
        let mut values = Vec::new();
        values.extend(manifest.main);
        values.extend(manifest.module);
        values.extend(manifest.types);
        collect_export_paths(&manifest.bin, &mut values);
        collect_export_paths(&manifest.exports, &mut values);
        // Files run by npm scripts (`tsx scripts/foo.ts`, `--config
        // ./vitest.config.ts`) are entries even though nothing imports
        // them.
        for script in manifest.scripts.values() {
            values.extend(script_file_refs(script));
        }
        for value in values {
            for candidate in entry_candidates(&dir, &value) {
                out.insert(candidate);
            }
        }
    }
    out
}

/// String leaves of `bin` / `exports` maps (arbitrary nesting).
fn collect_export_paths(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_export_paths(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_export_paths(v, out);
            }
        }
        _ => {}
    }
}

/// Source files an entry value could mean.
fn entry_candidates(dir: &Path, value: &str) -> Vec<PathBuf> {
    let value = value.trim_start_matches("./");
    let mut bases = vec![value.to_string()];
    for built in ["dist/", "lib/", "build/", "out/"] {
        if let Some(rest) = value.strip_prefix(built) {
            bases.push(rest.to_string());
            bases.push(format!("src/{rest}"));
        }
    }
    let mut out = Vec::new();
    for base in &bases {
        let path = dir.join(base);
        if path.is_file() {
            out.push(path);
        }
        // `.js` entry -> sibling TypeScript source.
        if base.ends_with(".js") || base.ends_with(".mjs") || base.ends_with(".cjs") {
            let stem = base.rsplit_once('.').map(|(s, _)| s).unwrap_or(base);
            for ext in ["ts", "tsx", "mts", "cts", "js", "jsx"] {
                let sibling = dir.join(format!("{stem}.{ext}"));
                if sibling.is_file() {
                    out.push(sibling);
                }
            }
        }
    }
    out
}

/// Source-file tokens inside one npm script command: whitespace- and
/// shell-splitter-separated words ending in a source extension.
/// Flags, URLs, and bare package names never match the suffix test.
fn script_file_refs(script: &str) -> Vec<String> {
    const EXTS: &[&str] = &[
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts",
    ];
    script
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '&' | '|' | '(' | ')'))
        .filter(|token| {
            let token = token.trim_start_matches("./");
            EXTS.iter()
                .any(|ext| token.ends_with(ext) && token.len() > ext.len())
                && !token.contains("://")
                && !token.starts_with('-')
        })
        .map(|token| token.trim_start_matches("./").to_string())
        .collect()
}

/// First-party by construction: tsconfig path aliases, `@/` (never a
/// valid package name), `~/`, `#` subpath imports, and `scheme:` imports.
fn is_alias_import(spec: &str, aliases: &HashSet<String>) -> bool {
    spec.starts_with("@/")
        || spec.starts_with("~/")
        || spec.starts_with('#')
        || spec
            .split('/')
            .next()
            .is_some_and(|first| first.contains(':'))
        || aliases
            .iter()
            .any(|a| spec == a || spec.starts_with(&format!("{a}/")))
}

/// Manifest-declared package names across all four dependency sections.
pub(crate) fn manifest_keys(root: &Path) -> HashSet<String> {
    let Ok(manifest) = read_manifest(root) else {
        return HashSet::new();
    };
    manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
        .chain(manifest.peer_dependencies.keys())
        .chain(manifest.optional_dependencies.keys())
        .cloned()
        .collect()
}

/// Locked versions from the first available lockfile: `package-lock.json`
/// (this dir), `pnpm-lock.yaml` (nearest up, workspace-aware),
/// `bun.lock` (nearest up, workspace-aware), or `yarn.lock` (this dir).
/// A `bun.lockb` without any of those is reported as a gap by the caller:
/// it is binary with no stable spec, so versions fall back to the
/// installed tree.
fn locked_versions(root: &Path) -> HashMap<String, String> {
    let npm = read_package_lock(root);
    if !npm.is_empty() {
        return npm;
    }
    if let Some(pnpm) = read_pnpm_lock(root) {
        if !pnpm.is_empty() {
            return pnpm;
        }
    }
    if let Some(bun) = read_bun_lock(root) {
        if !bun.is_empty() {
            return bun;
        }
    }
    read_yarn_lock(root)
}

/// Nearest `file` walking up from `root` (capped): (lock dir, path).
fn find_up(root: &Path, file: &str) -> Option<PathBuf> {
    let mut dir = root.to_path_buf();
    for _ in 0..10 {
        let candidate = dir.join(file);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
    None
}

/// Importer key for `root` under `lock_dir`: `.` for the lockfile's own
/// directory, otherwise the posix relative path.
fn importer_key(lock_dir: &Path, root: &Path) -> String {
    root.strip_prefix(lock_dir)
        .ok()
        .filter(|rel| !rel.as_os_str().is_empty())
        .map(|rel| {
            rel.components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| ".".to_string())
}

/// Clean a locked version: strip quotes, cut peer/patch suffixes at the
/// first `(`, and accept only values starting with a digit (`link:`,
/// `file:`, tarballs, and ranges are not comparable versions).
fn clean_locked(raw: &str) -> Option<String> {
    let mut value = raw.trim().trim_matches('"').trim_matches('\'').trim();
    if let Some(cut) = value.find('(') {
        value = value[..cut].trim();
    }
    if value.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        Some(value.to_string())
    } else {
        None
    }
}

/// Strip YAML quoting and trailing comments from a scalar.
fn yaml_scalar(raw: &str) -> String {
    let mut value = raw.trim();
    // Trailing ` # comment` outside quotes (lockfiles never nest `#` in
    // the scalars we read, so a naive split is safe here).
    if let Some(cut) = value.find(" #") {
        value = value[..cut].trim();
    }
    value.trim_matches('"').trim_matches('\'').trim().to_string()
}

/// Locked versions from `pnpm-lock.yaml`'s `importers:` map for this
/// project's importer. Hand-rolled YAML: pnpm is machine-generated with
/// stable 2-space indentation, and only this section's shape is read.
fn read_pnpm_lock(root: &Path) -> Option<HashMap<String, String>> {
    let lock_path = find_up(root, "pnpm-lock.yaml")?;
    let lock_dir = lock_path.parent()?;
    let want = importer_key(lock_dir, root);
    let text = std::fs::read_to_string(&lock_path).ok()?;
    let mut out = HashMap::new();
    let mut in_importers = false;
    let mut in_want = false;
    let mut in_section = false;
    let mut current_name: Option<String> = None;
    for raw in text.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if indent == 0 {
            in_importers = line == "importers:";
            in_want = false;
            in_section = false;
            current_name = None;
            continue;
        }
        if !in_importers {
            continue;
        }
        if indent == 2 {
            in_want = line.trim_end_matches(':') == want;
            in_section = false;
            current_name = None;
            continue;
        }
        if !in_want {
            continue;
        }
        if indent == 4 {
            // Any `*ependencies:` section (dependencies, dev, peer,
            // optional, config, packageManager).
            in_section = line.ends_with("ependencies:");
            current_name = None;
            continue;
        }
        if !in_section {
            continue;
        }
        if indent == 6 {
            let name = yaml_scalar(line.trim_end_matches(':'));
            current_name = if name.is_empty() { None } else { Some(name) };
            continue;
        }
        if indent >= 8 && let Some(name) = current_name.clone() {
            if let Some(value) = line.strip_prefix("version:") {
                if let Some(version) = clean_locked(&yaml_scalar(value)) {
                    out.insert(name, version);
                }
                current_name = None;
            }
        }
    }
    Some(out)
}

/// Locked versions from `bun.lock`'s `workspaces:` map. The file is JSONC
/// (comments, trailing commas), so it is normalized before parsing.
/// `catalog:` values resolve through the lock dir's root `package.json`.
fn read_bun_lock(root: &Path) -> Option<HashMap<String, String>> {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct Workspace {
        #[serde(default)]
        dependencies: HashMap<String, String>,
        #[serde(default)]
        dev_dependencies: HashMap<String, String>,
        #[serde(default)]
        peer_dependencies: HashMap<String, String>,
        #[serde(default)]
        optional_dependencies: HashMap<String, String>,
    }
    #[derive(Deserialize)]
    struct BunLock {
        #[serde(default)]
        workspaces: HashMap<String, Workspace>,
    }
    let lock_path = find_up(root, "bun.lock")?;
    let lock_dir = lock_path.parent()?;
    let key = importer_key(lock_dir, root);
    let key = if key == "." { String::new() } else { key };
    let raw = std::fs::read_to_string(&lock_path).ok()?;
    let lock: BunLock = serde_json::from_str(&jsonc_to_json(&raw)).ok()?;
    let workspace = lock.workspaces.get(&key)?;
    let catalogs = bun_catalogs(lock_dir);
    let mut out = HashMap::new();
    for section in [
        &workspace.dependencies,
        &workspace.dev_dependencies,
        &workspace.peer_dependencies,
        &workspace.optional_dependencies,
    ] {
        for (name, value) in section {
            if let Some(version) = bun_locked_value(name, value, &catalogs) {
                out.insert(name.clone(), version);
            }
        }
    }
    Some(out)
}

/// One `bun.lock` workspace value: resolved versions pass through,
/// `catalog:` specs resolve, first-party/local specs are skipped.
fn bun_locked_value(
    name: &str,
    value: &str,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    let value = value.trim();
    // `catalog:` (default) or `catalog:<name>` (named).
    if let Some(rest) = value.strip_prefix("catalog:") {
        let catalog = if rest.is_empty() { "default" } else { rest };
        return catalogs
            .get(catalog)
            .and_then(|map| map.get(name))
            .and_then(|v| clean_locked(v));
    }
    if value.starts_with("workspace:")
        || value.starts_with("link:")
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
    {
        return None;
    }
    clean_locked(value)
}

/// `catalog` / `catalogs` maps from a bun workspace root `package.json`.
fn bun_catalogs(lock_dir: &Path) -> HashMap<String, HashMap<String, String>> {
    #[derive(Deserialize, Default)]
    struct RootManifest {
        #[serde(default)]
        catalog: HashMap<String, String>,
        #[serde(default)]
        catalogs: HashMap<String, HashMap<String, String>>,
    }
    let mut out = HashMap::new();
    let Ok(raw) = std::fs::read_to_string(lock_dir.join("package.json")) else {
        return out;
    };
    let Ok(manifest) = serde_json::from_str::<RootManifest>(&raw) else {
        return out;
    };
    if !manifest.catalog.is_empty() {
        out.insert("default".to_string(), manifest.catalog);
    }
    out.extend(manifest.catalogs);
    out
}

/// JSONC -> JSON: strip `//` line comments and trailing commas. The
/// scanner is string-aware, so URLs and quoted commas survive.
fn jsonc_to_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ',' => {
                // Trailing comma when only whitespace/comment follows
                // before a closing bracket.
                let mut lookahead = chars.clone();
                let mut trailing = false;
                loop {
                    match lookahead.next() {
                        Some(n) if n.is_whitespace() => continue,
                        Some('}') | Some(']') => {
                            trailing = true;
                            break;
                        }
                        _ => break,
                    }
                }
                if !trailing {
                    out.push(',');
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Locked versions from a v1 `yarn.lock` in this directory: `"name@spec":`
/// headers with `version "x"` (v1) or `version: x` (berry) bodies.
fn read_yarn_lock(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(root.join("yarn.lock")) else {
        return out;
    };
    let mut names: Vec<String> = Vec::new();
    for raw in text.lines() {
        if raw.starts_with('#') || raw.trim().is_empty() {
            continue;
        }
        if !raw.starts_with([' ', '\t']) {
            names.clear();
            let header = raw.trim().trim_end_matches(':');
            for part in header.split(", ") {
                let part = part.trim().trim_matches('"');
                // Scoped names keep their leading `@`: cut at the last `@`.
                let name = match part.rsplit_once('@') {
                    Some(("", _)) => continue,
                    Some((n, _)) if !n.is_empty() => n,
                    _ => continue,
                };
                names.push(name.to_string());
            }
            continue;
        }
        let line = raw.trim();
        let value = line
            .strip_prefix("version")
            .and_then(|v| v.trim_start().strip_prefix(['"', ':']))
            .map(|v| v.trim().trim_matches('"').trim_matches('\'').trim());
        if let (Some(value), true) = (value, !names.is_empty()) {
            if let Some(version) = clean_locked(value) {
                for name in &names {
                    out.entry(name.clone()).or_insert(version.clone());
                }
            }
            names.clear();
        }
    }
    out
}

/// `catalog:` / `catalogs:` maps from the nearest `pnpm-workspace.yaml`
/// (`"default"` key holds the unnamed catalog). Only these two
/// sections are read; the rest of the workspace file is ignored.
fn pnpm_catalogs(root: &Path) -> HashMap<String, HashMap<String, String>> {
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    let Some(ws_path) = find_up(root, "pnpm-workspace.yaml") else {
        return out;
    };
    let Ok(text) = std::fs::read_to_string(&ws_path) else {
        return out;
    };
    let mut section = "";
    let mut named = String::new();
    for raw in text.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if indent == 0 {
            section = if line == "catalog:" {
                "catalog"
            } else if line == "catalogs:" {
                "catalogs"
            } else {
                ""
            };
            named.clear();
            continue;
        }
        match (section, indent) {
            ("catalog", 2) => {
                if let Some((k, v)) = line.split_once(':') {
                    out.entry("default".to_string())
                        .or_default()
                        .insert(yaml_scalar(k), yaml_scalar(v));
                }
            }
            ("catalogs", 2) => {
                named = yaml_scalar(line.trim_end_matches(':'));
            }
            ("catalogs", 4) if !named.is_empty() => {
                if let Some((k, v)) = line.split_once(':') {
                    out.entry(named.clone())
                        .or_default()
                        .insert(yaml_scalar(k), yaml_scalar(v));
                }
            }
            _ => {}
        }
    }
    out
}

/// Resolve a `catalog:` / `catalog:<name>` spec through the workspace
/// catalogs (pnpm) or root manifest catalogs (bun).
fn resolve_catalog_spec(
    spec: &str,
    name: &str,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    let rest = spec.strip_prefix("catalog:")?;
    let catalog = if rest.is_empty() { "default" } else { rest };
    catalogs
        .get(catalog)
        .and_then(|map| map.get(name))
        .and_then(|v| clean_locked(v))
}

/// Locked versions from `package-lock.json` (v2/v3 `packages` or v1 `dependencies`).
fn read_package_lock(root: &Path) -> HashMap<String, String> {
    #[derive(Deserialize)]
    struct Lock {
        #[serde(default)]
        packages: HashMap<String, LockEntry>,
        #[serde(default)]
        dependencies: HashMap<String, LockEntry>,
    }
    #[derive(Deserialize)]
    struct LockEntry {
        #[serde(default)]
        version: Option<String>,
    }
    let mut out = HashMap::new();
    let Ok(raw) = std::fs::read_to_string(root.join("package-lock.json")) else {
        return out;
    };
    let Ok(lock) = serde_json::from_str::<Lock>(&raw) else {
        return out;
    };
    for (key, entry) in lock.packages {
        if let (Some(name), Some(version)) = (key.strip_prefix("node_modules/"), entry.version) {
            // Skip nested paths (node_modules/a/node_modules/b).
            if !name.contains("node_modules/") {
                out.entry(name.to_string()).or_insert(version);
            }
        }
    }
    for (name, entry) in lock.dependencies {
        if let Some(version) = entry.version {
            out.entry(name).or_insert(version);
        }
    }
    out
}

/// All locked versions per package: v2/v3 `packages` at every depth
/// (`node_modules/a/node_modules/b` is a real second copy) plus v1
/// nested `dependencies`, walked recursively.
fn lock_versions(root: &Path) -> HashMap<String, Vec<String>> {
    // v2/v3 entries: `dependencies` here is a SPEC map (name -> range
    // string), not nested locks, so it is deliberately not parsed;
    // nested copies surface as their own `node_modules/a/...` keys.
    #[derive(Deserialize)]
    struct LockEntry {
        #[serde(default)]
        version: Option<String>,
    }
    // v1 entries: `dependencies` holds nested lock objects.
    #[derive(Deserialize)]
    struct LockEntryV1 {
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        dependencies: HashMap<String, LockEntryV1>,
    }
    #[derive(Deserialize)]
    struct Lock {
        #[serde(default)]
        packages: HashMap<String, LockEntry>,
        #[serde(default)]
        dependencies: HashMap<String, LockEntryV1>,
    }
    fn walk(entry: &LockEntryV1, name: &str, out: &mut HashMap<String, Vec<String>>) {
        if let Some(version) = entry.version.as_deref() {
            out.entry(name.to_string())
                .or_default()
                .push(version.to_string());
        }
        for (child, sub) in &entry.dependencies {
            walk(sub, child, out);
        }
    }
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let Ok(raw) = std::fs::read_to_string(root.join("package-lock.json")) else {
        return out;
    };
    let Ok(lock) = serde_json::from_str::<Lock>(&raw) else {
        return out;
    };
    for (key, entry) in &lock.packages {
        // Name after the last `node_modules/`; scoped names survive.
        if let Some(name) = key.rsplit("node_modules/").next()
            && key.starts_with("node_modules/")
            && let Some(version) = entry.version.as_deref()
        {
            out.entry(name.to_string())
                .or_default()
                .push(version.to_string());
        }
    }
    for (name, entry) in &lock.dependencies {
        walk(entry, name, &mut out);
    }
    merge_pnpm_packages(root, &mut out);
    merge_yarn_versions(root, &mut out);
    merge_bun_workspaces(root, &mut out);
    for versions in out.values_mut() {
        versions.sort_by(
            |a, b| match (a.parse::<NpmVersion>(), b.parse::<NpmVersion>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.cmp(b),
            },
        );
        versions.dedup();
    }
    out
}

/// pnpm `packages:` keys (`'name@version':`) across the whole lockfile:
/// every version pnpm materialized, including peer-suffixed variants.
fn merge_pnpm_packages(root: &Path, out: &mut HashMap<String, Vec<String>>) {
    let Some(lock_path) = find_up(root, "pnpm-lock.yaml") else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(&lock_path) else {
        return;
    };
    let mut in_packages = false;
    for raw in text.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if indent == 0 {
            in_packages = line == "packages:";
            continue;
        }
        if !in_packages || indent != 2 {
            continue;
        }
        let key = yaml_scalar(line.trim_end_matches(':'));
        if let Some((name, version)) = key.rsplit_once('@')
            && !name.is_empty()
            && let Some(version) = clean_locked(version)
        {
            out.entry(name.to_string()).or_default().push(version);
        }
    }
}

/// yarn.lock entries: each `"name@spec"` header with its `version`.
fn merge_yarn_versions(root: &Path, out: &mut HashMap<String, Vec<String>>) {
    let Ok(text) = std::fs::read_to_string(root.join("yarn.lock")) else {
        return;
    };
    let mut names: Vec<String> = Vec::new();
    for raw in text.lines() {
        if raw.starts_with('#') || raw.trim().is_empty() {
            continue;
        }
        if !raw.starts_with([' ', '\t']) {
            names.clear();
            for part in raw.trim().trim_end_matches(':').split(", ") {
                let part = part.trim().trim_matches('"');
                if let Some((n, _)) = part.rsplit_once('@')
                    && !n.is_empty()
                {
                    names.push(n.to_string());
                }
            }
            continue;
        }
        if let Some(value) = raw
            .trim()
            .strip_prefix("version")
            .and_then(|v| v.trim_start().strip_prefix(['"', ':']))
            && let Some(version) = clean_locked(value.trim().trim_matches('"'))
            && !names.is_empty()
        {
            for name in &names {
                out.entry(name.clone()).or_default().push(version.clone());
            }
            names.clear();
        }
    }
}

/// bun.lock workspace values across every workspace: resolved versions
/// (including `catalog:` resolutions), first-party specs skipped.
fn merge_bun_workspaces(root: &Path, out: &mut HashMap<String, Vec<String>>) {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct Workspace {
        #[serde(default)]
        dependencies: HashMap<String, String>,
        #[serde(default)]
        dev_dependencies: HashMap<String, String>,
        #[serde(default)]
        peer_dependencies: HashMap<String, String>,
        #[serde(default)]
        optional_dependencies: HashMap<String, String>,
    }
    #[derive(Deserialize)]
    struct BunLock {
        #[serde(default)]
        workspaces: HashMap<String, Workspace>,
    }
    let Some(lock_path) = find_up(root, "bun.lock") else {
        return;
    };
    let lock_dir = lock_path.parent().unwrap_or(root);
    let Ok(raw) = std::fs::read_to_string(&lock_path) else {
        return;
    };
    let Ok(lock) = serde_json::from_str::<BunLock>(&jsonc_to_json(&raw)) else {
        return;
    };
    let catalogs = bun_catalogs(lock_dir);
    for workspace in lock.workspaces.values() {
        for section in [
            &workspace.dependencies,
            &workspace.dev_dependencies,
            &workspace.peer_dependencies,
            &workspace.optional_dependencies,
        ] {
            for (name, value) in section {
                if let Some(version) = bun_locked_value(name, value, &catalogs) {
                    out.entry(name.clone()).or_default().push(version);
                }
            }
        }
    }
}

fn installed_version(root: &Path, name: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Pkg {
        version: String,
    }
    let raw =
        std::fs::read_to_string(root.join("node_modules").join(name).join("package.json")).ok()?;
    serde_json::from_str::<Pkg>(&raw).ok().map(|p| p.version)
}

fn npm_is_newer(current: &str, latest: &str) -> bool {
    match (current.parse::<NpmVersion>(), latest.parse::<NpmVersion>()) {
        (Ok(a), Ok(b)) => a < b,
        _ => current != latest,
    }
}

/// Whether `latest` satisfies an npm range (`^2.0.0`, `>=1 <3`, `*`, ...).
/// Unparseable specs (tags, aliases, URLs) count as not satisfied so the
/// latest release is surfaced.
fn range_satisfies(spec: &str, latest: &str) -> bool {
    let (Ok(range), Ok(version)) = (spec.parse::<Range>(), latest.parse::<NpmVersion>()) else {
        return false;
    };
    range.satisfies(&version)
}

/// Release dates from the full registry document's `time` map: one
/// response holds every version's publish time, so both dates come from a
/// single fetch. Failures yield `None`, never gaps.
fn npm_release_dates(
    ctx: &Ctx,
    name: &str,
    current: &str,
    latest: &str,
) -> (Option<String>, Option<String>) {
    use crate::ecosystem::{cached_release_date, release_date_key};
    let cached = |version: &str| cached_release_date(ctx, "node", name, version);
    let current_date = cached(current);
    let latest_date = cached(latest);
    if current_date.is_some() && latest_date.is_some() {
        return (current_date, latest_date);
    }
    #[derive(Deserialize)]
    struct Resp {
        time: HashMap<String, String>,
    }
    // Scoped names go on the wire as @scope%2fname.
    let encoded = name.replace('/', "%2f");
    let url = format!("https://registry.npmjs.org/{encoded}");
    if let Ok(resp) = http::get_json_retry::<Resp>(&url) {
        for (version, stamp) in &resp.time {
            if let Some(date) = crate::dates::iso_date(stamp) {
                ctx.cache
                    .set(&release_date_key("node", name, version), &date);
            }
        }
    }
    (
        current_date.or_else(|| cached(current)),
        latest_date.or_else(|| cached(latest)),
    )
}

/// License + deprecation facts for one used version from its
/// version-specific registry document. Licenses cache forever; the
/// deprecation flag (mutable) re-checks on the version TTL.
struct NpmFacts {
    licenses: Vec<String>,
    deprecated: Option<String>,
}

fn npm_facts(ctx: &Ctx, name: &str, version: &str) -> NpmFacts {
    let lkey = format!("v1:license:node:{name}:{version}");
    let ykey = format!("v1:yanked:node:{name}:{version}");
    let cached_licenses: Option<Vec<String>> =
        ctx.cache.license_resolution(&lkey, "node", name, version);
    let cached_deprecated: Option<Option<String>> = ctx.cache.get(&ykey, ctx.cache.versions_ttl());
    if let (Some(licenses), Some(deprecated)) = (&cached_licenses, &cached_deprecated) {
        return NpmFacts {
            licenses: licenses.clone(),
            deprecated: deprecated.clone(),
        };
    }
    let mut facts = NpmFacts {
        licenses: cached_licenses.clone().unwrap_or_default(),
        deprecated: cached_deprecated
            .clone()
            .unwrap_or_else(|| ctx.cache.get_stale(&ykey).unwrap_or(None)),
    };
    let encoded = name.replace('/', "%2f");
    let url = format!("https://registry.npmjs.org/{encoded}/{version}");
    if let Ok(doc) = http::get_json_retry::<serde_json::Value>(&url) {
        let mut licenses = Vec::new();
        match doc.get("license") {
            Some(serde_json::Value::String(s)) => {
                licenses.extend(crate::licenses::normalize_spdx(s));
            }
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    if let Some(t) = item.get("type").and_then(|t| t.as_str()) {
                        licenses.extend(crate::licenses::normalize_spdx(t));
                    }
                }
            }
            Some(other) => {
                if let Some(t) = other.get("type").and_then(|t| t.as_str()) {
                    licenses.extend(crate::licenses::normalize_spdx(t));
                }
            }
            None => {}
        }
        let deprecated = doc
            .get("deprecated")
            .and_then(|d| d.as_str())
            .map(str::to_string);
        facts.licenses = licenses.clone();
        facts.deprecated = deprecated.clone();
        ctx.cache
            .store_license_resolution(&lkey, "node", name, version, &licenses);
        ctx.cache.set(&ykey, &deprecated);
    }
    facts
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
            &release_date_key("node", "is-odd", "2.0.0"),
            &"2017-11-01".to_string(),
        );
        ctx.cache.set(
            &release_date_key("node", "is-odd", "3.0.1"),
            &"2018-05-31".to_string(),
        );
        assert_eq!(
            Node.release_dates(&ctx, "is-odd", "2.0.0", "3.0.1"),
            (
                Some("2017-11-01".to_string()),
                Some("2018-05-31".to_string())
            )
        );
    }

    #[test]
    fn range_semantics() {
        assert!(range_satisfies("^2.0.0", "2.5.0"));
        assert!(!range_satisfies("^2.0.0", "3.0.1"));
        assert!(range_satisfies("2.0.0", "2.0.0"));
        assert!(!range_satisfies("2.0.0", "2.5.0"));
        assert!(range_satisfies("*", "9.9.9"));
        assert!(!range_satisfies("latest", "3.0.1")); // tag: surface latest
    }

    #[test]
    fn outdated_rules() {
        let node = Node;
        // Installed older -> outdated.
        let mut dep = Dep::new("is-odd");
        dep.version = Some("2.0.0".to_string());
        dep.spec = Some("^2.0.0".to_string());
        let o = node.outdated(&dep, "3.0.1").unwrap();
        assert_eq!(o.current, "2.0.0");
        assert_eq!(o.latest, "3.0.1");
        // Installed current -> fresh.
        dep.version = Some("3.0.1".to_string());
        assert!(node.outdated(&dep, "3.0.1").is_none());
        // Spec-only, latest in range -> fresh.
        let mut dep = Dep::new("x");
        dep.spec = Some("^2.0.0".to_string());
        assert!(node.outdated(&dep, "2.5.0").is_none());
        // Spec-only, major bump available -> outdated.
        assert!(node.outdated(&dep, "3.0.1").is_some());
    }

    #[test]
    fn enumerates_tool_pins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"engines":{"node":">=18","bun":"1.1.0"},"packageManager":"pnpm@9.1.0","volta":{"yarn":"1.22.0"}}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(".nvmrc"), "v20\n").unwrap();
        let pins = Node.enumerate_tools(dir.path());
        assert_eq!(pins.len(), 5);
        assert!(pins.iter().any(|p| p.display == "node (engines)"));
        assert!(
            pins.iter()
                .any(|p| p.display == "pnpm (packageManager)"
                    && p.version.as_deref() == Some("9.1.0"))
        );
        assert!(pins.iter().any(|p| p.display == "node (.nvmrc)"));
    }

    #[test]
    fn enumerates_manifest_and_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"a":"^1.0.0"},"devDependencies":{"b":"2.0.0"}}"#,
        )
        .unwrap();
        let mod_dir = dir.path().join("node_modules").join("a");
        std::fs::create_dir_all(&mod_dir).unwrap();
        std::fs::write(mod_dir.join("package.json"), r#"{"version":"1.2.3"}"#).unwrap();
        let deps = Node.enumerate(dir.path()).unwrap().deps;
        assert_eq!(deps.len(), 2);
        let a = deps.iter().find(|d| d.name == "a").unwrap();
        assert_eq!(a.version.as_deref(), Some("1.2.3"));
        let b = deps.iter().find(|d| d.name == "b").unwrap();
        assert_eq!(b.version, None);
        assert_eq!(b.detail.as_deref(), Some("dev"));
    }

    #[test]
    fn update_command_matches_package_manager() {
        let out = [OutdatedDep {
            name: "left-pad".to_string(),
            current: "1.0.0".to_string(),
            latest: "1.3.0".to_string(),
            detail: None,
            blocked: None,
            stale: None,
            current_released: None,
            latest_released: None,
            days_behind: None,
        }];
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Node.update_command(dir.path(), &out).as_deref(),
            Some("npm install left-pad@1.3.0")
        );
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(
            Node.update_command(dir.path(), &out).as_deref(),
            Some("pnpm update left-pad@1.3.0")
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("yarn.lock"), "").unwrap();
        assert_eq!(
            Node.update_command(dir.path(), &out).as_deref(),
            Some("yarn upgrade left-pad@1.3.0")
        );
        std::fs::write(dir.path().join(".yarnrc.yml"), "").unwrap();
        assert_eq!(
            Node.update_command(dir.path(), &out).as_deref(),
            Some("yarn up left-pad@1.3.0")
        );
    }

    #[test]
    fn tsconfig_paths_absolutize_to_member_dir() {
        // Regression: alias targets are relative to their own tsconfig
        // dir; joining them to the scan root breaks every monorepo alias.
        let dir = tempfile::tempdir().unwrap();
        let member = dir.path().join("apps/mobile");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("tsconfig.json"),
            r#"{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}"#,
        )
        .unwrap();
        let paths = tsconfig_paths(dir.path());
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].0, "@");
        assert_eq!(
            PathBuf::from(&paths[0].1[0]),
            member.join("src/*"),
            "{paths:?}"
        );
    }

    #[test]
    fn script_file_refs_picks_runners_not_flags() {
        let refs = script_file_refs("tsx scripts/seed.ts --config ./vitest.setup.ts && echo done");
        assert_eq!(refs, vec!["scripts/seed.ts", "vitest.setup.ts"]);
        assert!(script_file_refs("eslint . --ext .ts").is_empty());
        assert!(script_file_refs("node https://x/y.mjs").is_empty());
    }

    #[test]
    fn lock_versions_collects_every_depth() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "name": "bloatjs",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "^4.17.21"}},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/app": {"version": "1.0.0", "dependencies": {"lodash": "^4.17.20"}},
                    "node_modules/app/node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/@scope/pkg": {"version": "2.0.0"}
                }
            }"#,
        )
        .unwrap();
        let versions = lock_versions(dir.path());
        assert_eq!(
            versions.get("lodash").unwrap(),
            &vec!["4.17.20".to_string(), "4.17.21".to_string()]
        );
        assert_eq!(
            versions.get("@scope/pkg").unwrap(),
            &vec!["2.0.0".to_string()]
        );
        assert!(!versions.contains_key(""));
    }

    #[test]
    fn lock_versions_walks_v1_nesting() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "dependencies": {
                    "app": {
                        "version": "1.0.0",
                        "dependencies": {"lodash": {"version": "4.17.20"}}
                    },
                    "lodash": {"version": "4.17.21"}
                }
            }"#,
        )
        .unwrap();
        let versions = lock_versions(dir.path());
        assert_eq!(
            versions.get("lodash").unwrap(),
            &vec!["4.17.20".to_string(), "4.17.21".to_string()]
        );
    }

    #[test]
    fn pnpm_importers_strip_peer_suffixes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      root-pkg:\n        specifier: ^1.0.0\n        version: 1.2.3\n\n  apps/web:\n    dependencies:\n      '@clerk/electron':\n        specifier: 0.1.3\n        version: 0.1.3(@clerk/other@0.0.3)(react@19.3.0)\n      local-pkg:\n        specifier: link:../local\n        version: link:../local\n    devDependencies:\n      typescript:\n        specifier: ^5.0.0\n        version: 5.9.3\n\npackages:\n\n  '@clerk/electron@0.1.3':\n    resolution: {integrity: sha512-abc==}\n",
        )
        .unwrap();
        let locked = read_pnpm_lock(&dir.path().join("apps/web")).unwrap();
        assert_eq!(locked.get("@clerk/electron").unwrap(), "0.1.3");
        assert_eq!(locked.get("typescript").unwrap(), "5.9.3");
        assert!(!locked.contains_key("local-pkg"));
        assert!(!locked.contains_key("root-pkg"));
        let root_locked = read_pnpm_lock(dir.path()).unwrap();
        assert_eq!(root_locked.get("root-pkg").unwrap(), "1.2.3");
    }

    #[test]
    fn pnpm_catalogs_parse_default_and_named() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - apps/*\n\ncatalog:\n  \"@clerk/react\": 6.18.0\n  left-pad: '1.3.0'\n\ncatalogs:\n  react19:\n    react: 19.3.0\n",
        )
        .unwrap();
        let catalogs = pnpm_catalogs(&dir.path().join("apps/web"));
        assert_eq!(
            resolve_catalog_spec("catalog:", "@clerk/react", &catalogs).as_deref(),
            Some("6.18.0")
        );
        assert_eq!(
            resolve_catalog_spec("catalog:react19", "react", &catalogs).as_deref(),
            Some("19.3.0")
        );
        assert!(resolve_catalog_spec("catalog:", "missing", &catalogs).is_none());
    }

    #[test]
    fn bun_lock_parses_jsonc_and_catalogs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name": "root", "catalog": {"left-pad": "1.3.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("bun.lock"),
            "{\n  // bun lockfile\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"root\",\n      \"dependencies\": {\n        \"lodash\": \"4.17.21\",\n        \"left-pad\": \"catalog:\",\n        \"mine\": \"workspace:*\",\n      },\n    },\n  },\n}\n",
        )
        .unwrap();
        let locked = read_bun_lock(dir.path()).unwrap();
        assert_eq!(locked.get("lodash").unwrap(), "4.17.21");
        assert_eq!(locked.get("left-pad").unwrap(), "1.3.0");
        assert!(!locked.contains_key("mine"));
    }

    #[test]
    fn yarn_lock_v1_parses_multi_spec_headers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("yarn.lock"),
            "# yarn lockfile v1\n\n\n\"@scope/pkg@^1.0.0\", \"@scope/pkg@^1.2.0\":\n  version \"1.2.3\"\n  resolved \"https://registry.npmjs.org/x\"\n\nleft-pad@^1.0.0:\n  version \"1.3.0\"\n",
        )
        .unwrap();
        let locked = read_yarn_lock(dir.path());
        assert_eq!(locked.get("@scope/pkg").unwrap(), "1.2.3");
        assert_eq!(locked.get("left-pad").unwrap(), "1.3.0");
    }

    #[test]
    fn clean_locked_rejects_non_versions() {
        assert_eq!(clean_locked("1.2.3(peer@2)").as_deref(), Some("1.2.3"));
        assert_eq!(clean_locked("'2.0.0'").as_deref(), Some("2.0.0"));
        assert!(clean_locked("link:../x").is_none());
        assert!(clean_locked("https://example.com/x.tgz").is_none());
        assert!(clean_locked("^1.2.3").is_none());
    }

    #[test]
    fn manifest_keys_covers_all_sections() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0"}, "devDependencies": {"b": "1.0.0"},
                "peerDependencies": {"c": "1.0.0"}, "optionalDependencies": {"d": "1.0.0"}}"#,
        )
        .unwrap();
        let keys = manifest_keys(dir.path());
        assert_eq!(keys.len(), 4);
        assert!(keys.contains("a") && keys.contains("d"));
    }
}
