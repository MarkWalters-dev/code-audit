//! Android/Gradle ecosystem, pure Rust: pinned versions parsed from
//! `gradle/libs.versions.toml`, `build.gradle(.kts)` dependency strings and
//! known plugin ids (AGP, Kotlin, ...), compared against the newest stable
//! release on Maven Central and Google Maven.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::cache::TTL_FOREVER_SECS;
use crate::ecosystem::{
    BlockedUpdate, Ctx, Dep, EcosystemChecker, Gap, GapCheck, Inventory, LatestInfo, Notice,
    OutdatedDep,
};
use crate::toolchains::{self, ToolId, ToolPin};
use crate::{http, version};

use serde::{Deserialize, Serialize};

pub struct Android;

const GRADLE_FILES: &[&str] = &[
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
];

impl EcosystemChecker for Android {
    fn id(&self) -> &'static str {
        "android"
    }

    fn display(&self) -> &'static str {
        "Android"
    }

    fn osv_ecosystem(&self) -> &'static str {
        "Maven"
    }

    fn detect(&self, root: &Path) -> bool {
        if root.join("gradle").join("libs.versions.toml").is_file() {
            return true;
        }
        GRADLE_FILES.iter().any(|f| root.join(f).is_file())
    }

    fn enumerate(&self, root: &Path) -> Result<Inventory, String> {
        let (declared, gaps) = collect_declared(root);
        let mut deps: Vec<Dep> = declared
            .into_iter()
            .map(|d| {
                let mut dep = Dep::new(format!("{}:{}", d.group, d.name));
                dep.version = Some(d.current);
                dep
            })
            .collect();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Inventory { deps, gaps, notes: Vec::new() })
    }

    fn fetch_latest(&self, ctx: &Ctx, dep: &Dep) -> Result<LatestInfo, String> {
        let Some((group, name)) = dep.name.split_once(':') else {
            return Err("malformed coordinate".to_string());
        };
        let current = dep.version.as_deref().unwrap_or("");
        let candidates = fetch_versions(group, name)?;
        let pool = candidate_pool(current, &candidates);
        let Some(newest) = pool.first() else {
            return Err("no releases listed".to_string());
        };
        let Some(cap) = ctx.android_sdk_cap else {
            return Ok(LatestInfo::simple(newest.clone()));
        };
        if version::compare(current, newest) != std::cmp::Ordering::Less {
            return Ok(LatestInfo::simple(newest.clone()));
        }
        let mut memo = HashMap::new();
        let mut stack = HashSet::new();
        Ok(select_compatible(current, &pool, cap, |v| {
            effective_min_sdk(ctx, group, name, v, &mut memo, &mut stack)
                .map_err(|e| format!("SDK compatibility unverified: {e}"))
        }))
    }

    fn latest_cache_key(&self, ctx: &Ctx, dep: &Dep) -> String {
        match ctx.android_sdk_cap {
            Some(cap) => format!("v1:latest:{}:{}:sdk{cap}", self.id(), dep.name),
            None => format!("v1:latest:{}:{}", self.id(), dep.name),
        }
    }

    fn release_dates(
        &self,
        ctx: &Ctx,
        name: &str,
        current: &str,
        latest: &str,
    ) -> (Option<String>, Option<String>) {
        let Some((group, artifact)) = name.split_once(':') else {
            return (None, None);
        };
        (
            maven_version_date(ctx, group, artifact, current),
            maven_version_date(ctx, group, artifact, latest),
        )
    }

    fn lint(
        &self,
        ctx: &Ctx,
        root: &Path,
        vulns: &[crate::osv::FoundVuln],
    ) -> crate::lint::LintOutcome {
        crate::lint::audit_android(ctx, root, vulns)
    }

    fn dep_licenses(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<String> {
        let Some((group, artifact)) = name.split_once(':') else {
            return Vec::new();
        };
        pom_licenses(ctx, group, artifact, version)
    }

    fn project_notices(&self, _ctx: &Ctx, root: &Path, _inventory: &[Dep]) -> Vec<Notice> {
        // Import-to-artifact mapping is heuristic (packages do not name
        // their artifact), so only zero-overlap imports flag: a shared
        // token past the TLD segment counts as provided.
        let (declared, _) = collect_declared(root);
        let artifacts: Vec<HashSet<String>> = declared.iter().map(artifact_tokens).collect();
        let own = own_packages(root);
        let mut notices = crate::ghost::scan(
            root,
            &["kt", "kts", "java"],
            crate::ghost::kotlin_imports,
            |spec| kotlin_satisfied(spec, &artifacts, &own),
            |_| false,
        );
        notices.extend(crate::deadcode::android_dead(root));
        notices
    }

    fn enumerate_tools(&self, root: &Path) -> Vec<ToolPin> {
        let mut pins = Vec::new();
        // Gradle wrapper pin.
        if let Ok(text) =
            std::fs::read_to_string(root.join("gradle/wrapper/gradle-wrapper.properties"))
            && let Some(version) = gradle_wrapper_version(&text)
        {
            pins.push(ToolPin {
                tool: ToolId::Gradle,
                display: "gradle (wrapper)".to_string(),
                version: Some(version),
                spec: None,
            });
        }
        // Kotlin plugin declarations (inline and shorthand forms).
        for path in find_files(root, GRADLE_FILES, true) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let text = strip_line_comments(&text);
                for (id, version) in parse_kotlin_plugin_versions(&text) {
                    pins.push(ToolPin {
                        tool: ToolId::Kotlin,
                        display: format!("kotlin ({id})"),
                        version: Some(version),
                        spec: None,
                    });
                }
            }
        }
        // Kotlin plugin declarations via the version catalog.
        for (id, version) in parse_catalog_plugins(&root.join("gradle/libs.versions.toml")) {
            if id.starts_with("org.jetbrains.kotlin") {
                pins.push(ToolPin {
                    tool: ToolId::Kotlin,
                    display: format!("kotlin ({id})"),
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
            for (key, tool) in [("gradle", ToolId::Gradle), ("kotlin", ToolId::Kotlin)] {
                if let Some(version) = map.get(key) {
                    pins.push(ToolPin {
                        tool,
                        display: format!("{} ({source})", tool.display()),
                        version: Some(version.clone()),
                        spec: None,
                    });
                }
            }
        }
        // Same version declared in several modules: report once.
        let mut seen = HashSet::new();
        pins.into_iter()
            .filter(|p| {
                seen.insert((
                    format!("{:?}", p.tool),
                    p.version.clone().unwrap_or_default(),
                ))
            })
            .collect()
    }

    fn outdated(&self, dep: &Dep, latest: &str) -> Option<OutdatedDep> {
        let current = dep
            .version
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        if version::is_newer(&current, latest) {
            Some(OutdatedDep {
                name: dep.display.clone(),
                current,
                latest: latest.to_string(),
                detail: None,
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
}

// ---------------------------------------------------------------------------
// Declaration parsing
// ---------------------------------------------------------------------------

/// Well-known Gradle plugin id -> Maven coordinate, so build-plugin versions
/// (AGP, Kotlin, ...) are checked like libraries.
fn known_plugin_artifact(id: &str) -> Option<(&'static str, &'static str)> {
    match id {
        "com.android.application"
        | "com.android.library"
        | "com.android.test"
        | "com.android.feature"
        | "com.android.dynamic-feature"
        | "com.android.asset-pack" => Some(("com.android.tools.build", "gradle")),
        "org.jetbrains.kotlin.android" | "org.jetbrains.kotlin.jvm" => {
            Some(("org.jetbrains.kotlin", "kotlin-gradle-plugin"))
        }
        "com.google.gms.google-services" => Some(("com.google.gms", "google-services")),
        "com.google.firebase.crashlytics" => {
            Some(("com.google.firebase", "firebase-crashlytics-gradle"))
        }
        "com.google.dagger.hilt.android" => {
            Some(("com.google.dagger", "hilt-android-gradle-plugin"))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Declared {
    group: String,
    name: String,
    current: String,
}

/// Gather pinned `group:name:version` declarations from the version catalog,
/// build files and plugin blocks.
fn collect_declared(root: &Path) -> (Vec<Declared>, Vec<Gap>) {
    let mut out = Vec::new();
    let mut gaps = Vec::new();
    let mut gapped = HashSet::new();
    let catalog = root.join("gradle").join("libs.versions.toml");
    let mut aliases: HashMap<String, Declared> = HashMap::new();
    if catalog.is_file() {
        let (libs, alias_map) = parse_version_catalog(&catalog);
        out.extend(libs);
        aliases = alias_map;
        // Build plugins declared in the catalog (AGP, ...). Kotlin plugin
        // versions are reported as tools instead (see enumerate_tools).
        for (id, version) in parse_catalog_plugins(&catalog) {
            if id.starts_with("org.jetbrains.kotlin") {
                continue;
            }
            if let Some((group, name)) = known_plugin_artifact(&id) {
                out.push(Declared {
                    group: group.to_string(),
                    name: name.to_string(),
                    current: version,
                });
            }
        }
    }
    for path in find_files(root, GRADLE_FILES, true) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let text = strip_line_comments(&text);
        out.extend(parse_dependency_strings(&text));
        out.extend(parse_plugin_versions(&text));
        let (resolved, missed) = resolve_catalog_accessors(&text, &aliases);
        out.extend(resolved);
        for accessor in missed {
            if gapped.insert(format!("libs.{accessor}")) {
                let reason = "no matching libs.versions.toml entry".to_string();
                gaps.push(Gap {
                    name: format!("libs.{accessor}"),
                    check: GapCheck::Outdated,
                    reason: reason.clone(),
                });
                gaps.push(Gap {
                    name: format!("libs.{accessor}"),
                    check: GapCheck::Vulns,
                    reason,
                });
            }
        }
    }
    // Drop dynamic/unresolvable versions (reported as gaps) and duplicates.
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for d in out {
        let key = (d.group.clone(), d.name.clone(), d.current.clone());
        if !seen.insert(key) {
            continue;
        }
        if is_pinned(&d.current) {
            kept.push(d);
        } else if gapped.insert(format!("{}:{}:{}", d.group, d.name, d.current)) {
            let reason = format!("dynamic version '{}' cannot be compared", d.current);
            let name = format!("{}:{}", d.group, d.name);
            gaps.push(Gap {
                name: name.clone(),
                check: GapCheck::Outdated,
                reason: reason.clone(),
            });
            gaps.push(Gap {
                name,
                check: GapCheck::Vulns,
                reason,
            });
        }
    }
    (kept, gaps)
}

fn is_pinned(v: &str) -> bool {
    !(v.is_empty()
        || v.contains('$')
        || v.contains('+')
        || v.to_lowercase().starts_with("latest.")
        || v.starts_with('[')
        || v.starts_with('(')
        || v.contains(','))
}

/// Parse `gradle/libs.versions.toml` -> (libraries, alias->Declared map).
fn parse_version_catalog(path: &Path) -> (Vec<Declared>, HashMap<String, Declared>) {
    let mut libs = Vec::new();
    let mut aliases = HashMap::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return (libs, aliases),
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return (libs, aliases);
    };
    let versions = doc
        .get("versions")
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_default();
    let version_string = |key: &str| -> Option<String> {
        let v = versions.get(key)?;
        if let Some(s) = v.as_str() {
            return Some(s.to_string());
        }
        v.get("require")
            .or_else(|| v.get("strictly"))
            .or_else(|| v.get("prefer"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
    };
    let Some(table) = doc.get("libraries").and_then(|v| v.as_table()) else {
        return (libs, aliases);
    };
    for (alias, entry) in table {
        let declared = match entry {
            toml::Value::String(s) => {
                // Short form: "group:name:version".
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() == 3 {
                    Some(Declared {
                        group: parts[0].to_string(),
                        name: parts[1].to_string(),
                        current: parts[2].to_string(),
                    })
                } else {
                    None
                }
            }
            toml::Value::Table(t) => {
                let (group, name) = if let Some(module) = t.get("module").and_then(|m| m.as_str()) {
                    let parts: Vec<&str> = module.split(':').collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    (parts[0].to_string(), parts[1].to_string())
                } else {
                    match (
                        t.get("group").and_then(|g| g.as_str()),
                        t.get("name").and_then(|n| n.as_str()),
                    ) {
                        (Some(g), Some(n)) => (g.to_string(), n.to_string()),
                        _ => continue,
                    }
                };
                let current = match t.get("version") {
                    Some(toml::Value::String(s)) => Some(s.clone()),
                    Some(toml::Value::Table(vt)) => vt
                        .get("ref")
                        .and_then(|r| r.as_str())
                        .and_then(version_string)
                        .or_else(|| {
                            vt.get("require")
                                .or_else(|| vt.get("strictly"))
                                .or_else(|| vt.get("prefer"))
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string())
                        }),
                    _ => None,
                };
                current.map(|current| Declared {
                    group,
                    name,
                    current,
                })
            }
            _ => None,
        };
        if let Some(d) = declared {
            aliases.insert(alias.clone(), d.clone());
            libs.push(d);
        }
    }
    (libs, aliases)
}

/// Strip `//` line comments (ignoring `://` inside URLs) so commented-out
/// declarations are neither inventoried nor reported as gaps.
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| {
            let mut cut = line.len();
            let bytes = line.as_bytes();
            let mut i = 0;
            while i + 1 < bytes.len() {
                if bytes[i] == b'/' && bytes[i + 1] == b'/' && (i == 0 || bytes[i - 1] != b':') {
                    cut = i;
                    break;
                }
                i += 1;
            }
            line[..cut].trim_end()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse quoted `group:name:version` dependency strings in build files.
fn parse_dependency_strings(text: &str) -> Vec<Declared> {
    let re = Regex::new(r#"["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"'$\s]+)["']"#).unwrap();
    re.captures_iter(text)
        .map(|c| Declared {
            group: c[1].to_string(),
            name: c[2].to_string(),
            current: c[3].to_string(),
        })
        .collect()
}

/// Gradle version from wrapper properties' `distributionUrl=...gradle-X-bin.zip`.
/// Shared with the lint gate, which refuses to download a stale distribution.
pub(crate) fn gradle_wrapper_version(text: &str) -> Option<String> {
    let re = Regex::new(r"gradle-([0-9][A-Za-z0-9._+-]*?)-(bin|all)\.zip").unwrap();
    re.captures(text).map(|c| c[1].to_string())
}

/// Kotlin plugin declarations: `id("org.jetbrains.kotlin.*") version` (both
/// syntaxes) plus the `kotlin("...") version` shorthand. Returns (id, version).
fn parse_kotlin_plugin_versions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let kts = Regex::new(r#"id\(\s*"([^"]+)"\s*\)\s*version\s*"([^"]+)""#).unwrap();
    let groovy = Regex::new(r#"id\s*['"]([^'"]+)['"]\s+version\s*['"]([^'"]+)['"]"#).unwrap();
    for caps in kts.captures_iter(text).chain(groovy.captures_iter(text)) {
        if caps[1].starts_with("org.jetbrains.kotlin") {
            out.push((caps[1].to_string(), caps[2].to_string()));
        }
    }
    let shorthand =
        Regex::new(r#"kotlin\(\s*["']([^"']+)["']\s*\)\s*version\s*["']([^"']+)["']"#).unwrap();
    for caps in shorthand.captures_iter(text) {
        out.push((format!("kotlin.{}", &caps[1]), caps[2].to_string()));
    }
    out
}

/// `[plugins]` table of the version catalog as (id, resolved version).
fn parse_catalog_plugins(path: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
        return out;
    };
    let versions = doc
        .get("versions")
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_default();
    let Some(table) = doc.get("plugins").and_then(|v| v.as_table()) else {
        return out;
    };
    for entry in table.values() {
        let (id, version) = match entry {
            toml::Value::String(s) => {
                // Short form: "id:version".
                match s.split_once(':') {
                    Some((id, version)) => (id.to_string(), Some(version.to_string())),
                    None => continue,
                }
            }
            toml::Value::Table(t) => {
                let Some(id) = t.get("id").and_then(|v| v.as_str()) else {
                    continue;
                };
                let version = match t.get("version") {
                    Some(toml::Value::String(s)) => Some(s.clone()),
                    Some(toml::Value::Table(vt)) => vt
                        .get("ref")
                        .and_then(|r| r.as_str())
                        .and_then(|key| {
                            versions.get(key).and_then(|v| {
                                v.as_str().map(str::to_string).or_else(|| {
                                    v.get("require")
                                        .and_then(|x| x.as_str())
                                        .map(str::to_string)
                                })
                            })
                        })
                        .or_else(|| {
                            vt.get("require")
                                .and_then(|x| x.as_str())
                                .map(str::to_string)
                        }),
                    _ => None,
                };
                (id.to_string(), version)
            }
            _ => continue,
        };
        if let Some(version) = version {
            out.push((id, version));
        }
    }
    out
}

/// Parse `plugins { id("...") version "..." }` (kts) / `id '...' version '...'`.
fn parse_plugin_versions(text: &str) -> Vec<Declared> {
    let kts = Regex::new(r#"id\(\s*"([^"]+)"\s*\)\s*version\s*"([^"]+)""#).unwrap();
    let groovy = Regex::new(r#"id\s*['"]([^'"]+)['"]\s+version\s*['"]([^'"]+)['"]"#).unwrap();
    let mut out = Vec::new();
    for caps in kts.captures_iter(text).chain(groovy.captures_iter(text)) {
        // Kotlin plugin versions are reported as tools, not libraries.
        if caps[1].starts_with("org.jetbrains.kotlin") {
            continue;
        }
        if let Some((group, name)) = known_plugin_artifact(&caps[1]) {
            out.push(Declared {
                group: group.to_string(),
                name: name.to_string(),
                current: caps[2].to_string(),
            });
        }
    }
    out
}

/// Resolve `libs.foo.bar` catalog accessors to catalog aliases (`foo-bar`).
/// Returns (matched declarations, accessors with no catalog entry).
fn resolve_catalog_accessors(
    text: &str,
    aliases: &HashMap<String, Declared>,
) -> (Vec<Declared>, Vec<String>) {
    let re = Regex::new(r"libs\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)").unwrap();
    let mut out = Vec::new();
    let mut missed = Vec::new();
    for caps in re.captures_iter(text) {
        let alias = caps[1].replace('.', "-");
        // Also try progressively shorter prefixes (the accessor may carry a
        // trailing configuration, e.g. libs.foo.android).
        let mut candidate = alias.as_str();
        let mut found = None;
        loop {
            if let Some(d) = aliases.get(candidate) {
                found = Some(d.clone());
                break;
            }
            match candidate.rfind('-') {
                Some(i) => candidate = &candidate[..i],
                None => break,
            }
        }
        match found {
            Some(d) => out.push(d),
            None => missed.push(caps[1].to_string()),
        }
    }
    (out, missed)
}

/// Recursively find files with any of `names` under `root`, skipping VCS and
/// tool directories (plus build output when `skip_build`, so generated copies
/// of build files are not parsed as declarations).
fn find_files(root: &Path, names: &[&str], skip_build: bool) -> Vec<PathBuf> {
    const SKIP_ALWAYS: &[&str] = &[
        ".git",
        ".gradle",
        ".idea",
        "target",
        "node_modules",
        ".venv",
    ];
    const SKIP_BUILD: &[&str] = &["build", "out"];
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
                let skip = SKIP_ALWAYS.contains(&name.as_str())
                    || name.starts_with('.')
                    || (skip_build && SKIP_BUILD.contains(&name.as_str()));
                if !skip {
                    stack.push(path);
                }
            } else if names.contains(&name.as_str()) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Registry lookup
// ---------------------------------------------------------------------------

/// All published versions of `group:name`, merged across Maven Central and
/// Google Maven. Both mirrors are always consulted because either one can be
/// stale for a given artifact (e.g. Central's AGP metadata lags far behind).
/// Each mirror fetch is retried: Google's frontends drop connections under
/// burst concurrency, which must not be mistaken for a missing artifact.
pub(crate) fn fetch_versions(group: &str, name: &str) -> Result<Vec<String>, String> {
    let path = format!("{}/{}/maven-metadata.xml", group.replace('.', "/"), name);
    let mut versions = Vec::new();
    let mut errors: Vec<anyhow::Error> = Vec::new();
    // dl.google.com serves the bytes directly; maven.google.com just 301s here.
    for base in MAVEN_BASES {
        let url = format!("{base}/{path}");
        match http::get_text_retry(&url) {
            Ok(body) => versions.extend(all_versions_from_metadata(&body)),
            Err(e) => errors.push(e),
        }
    }
    versions.sort();
    versions.dedup();
    if !versions.is_empty() || errors.len() < 2 {
        // At least one mirror answered (possibly with an empty listing).
        return Ok(versions);
    }
    Err(mirror_failure_reason(&errors))
}

/// Reason when both mirrors failed without yielding versions: 404 on both
/// means the artifact does not exist; anything else is a request failure.
fn mirror_failure_reason(errors: &[anyhow::Error]) -> String {
    const SOURCE: &str = "Maven Central / Google Maven";
    match errors.iter().find(|e| !http::is_not_found(e)) {
        Some(first) => format!("{SOURCE} request failed: {}", http::short_error(first, 100)),
        None => format!("not found on {SOURCE}"),
    }
}

/// Pick the newest stable version, or the newest overall when `current` itself
/// is a pre-release (in which case pre-releases are fair game).
pub(crate) fn pick_latest(current: &str, candidates: &[String]) -> Option<String> {
    candidate_pool(current, candidates).into_iter().next()
}

/// Update candidates newest-first: stable releases only, unless `current`
/// is a pre-release (then pre-releases are fair game too).
fn candidate_pool(current: &str, candidates: &[String]) -> Vec<String> {
    let mut pool: Vec<String> = if is_prerelease(current) {
        candidates.to_vec()
    } else {
        let stable: Vec<String> = candidates
            .iter()
            .filter(|v| !is_prerelease(v))
            .cloned()
            .collect();
        if stable.is_empty() {
            candidates.to_vec()
        } else {
            stable
        }
    };
    pool.sort_by(|a, b| version::compare(a, b));
    pool.dedup();
    pool.reverse();
    pool
}

/// Newest pool entry at or under the compileSdk `cap`, plus the blocked
/// newest release when one exists. `required_sdk` reports each candidate's
/// required compileSdk (`None` = unconstrained); its failures degrade to an
/// unverified result against the newest release rather than an error.
fn select_compatible(
    current: &str,
    pool: &[String],
    cap: u32,
    mut required_sdk: impl FnMut(&str) -> Result<Option<u32>, String>,
) -> LatestInfo {
    let Some(newest) = pool.first() else {
        return LatestInfo::simple(current.to_string());
    };
    let newest_req = match required_sdk(newest) {
        Ok(req) => req,
        Err(e) => {
            return LatestInfo {
                latest: newest.clone(),
                blocked: None,
                unverified: Some(e),
            };
        }
    };
    let need = newest_req.unwrap_or(0);
    if need <= cap {
        return LatestInfo::simple(newest.clone());
    }
    let blocked = BlockedUpdate {
        latest: newest.clone(),
        min_compile_sdk: need,
    };
    for cand in &pool[1..] {
        if version::compare(cand, current) != std::cmp::Ordering::Greater {
            break;
        }
        match required_sdk(cand) {
            Ok(req) if req.unwrap_or(0) <= cap => {
                return LatestInfo {
                    latest: cand.clone(),
                    blocked: Some(blocked),
                    unverified: None,
                };
            }
            Ok(_) => {}
            Err(e) => {
                return LatestInfo {
                    latest: newest.clone(),
                    blocked: None,
                    unverified: Some(e),
                };
            }
        }
    }
    // Nothing newer than current is usable.
    LatestInfo {
        latest: current.to_string(),
        blocked: Some(blocked),
        unverified: None,
    }
}

/// Highest compileSdk the project can build against: the minimum `compileSdk`
/// literal across Gradle files (every module must build). Catalog references
/// and other indirection are not resolved.
pub fn detect_compile_sdk(root: &Path) -> Option<u32> {
    let re = Regex::new(r"(?:^|[^A-Za-z])compileSdk(?:Version)?\s*(?:=\s*)?(\d+)").unwrap();
    let mut found: Option<u32> = None;
    for path in find_files(root, GRADLE_FILES, true) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for caps in re.captures_iter(&strip_line_comments(&text)) {
            if let Ok(v) = caps[1].parse::<u32>() {
                found = Some(found.map_or(v, |m| m.min(v)));
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------
// SDK requirements: AAR metadata + transitive POM closure
// ---------------------------------------------------------------------------

const MAVEN_BASES: [&str; 2] = [
    "https://repo1.maven.org/maven2",
    "https://dl.google.com/dl/android/maven2",
];

const AAR_METADATA_PATH: &str = "META-INF/com/android/build/gradle/aar-metadata.properties";

type ArtifactKey = (String, String, String);

/// Highest compileSdk required by `group:name:version`, itself plus its
/// transitive Maven dependencies. `None` means unconstrained (pure-JVM
/// artifact, or nothing in the closure declares a requirement).
fn effective_min_sdk(
    ctx: &Ctx,
    group: &str,
    name: &str,
    version: &str,
    memo: &mut HashMap<ArtifactKey, Option<u32>>,
    stack: &mut HashSet<ArtifactKey>,
) -> Result<Option<u32>, String> {
    let key = (group.to_string(), name.to_string(), version.to_string());
    if let Some(cached) = memo.get(&key) {
        return Ok(*cached);
    }
    if !stack.insert(key.clone()) {
        return Ok(None); // dependency cycle: break it
    }
    let mut max = aar_min_sdk(ctx, group, name, version)?;
    for dep in pom_deps(ctx, group, name, version)? {
        let req = effective_min_sdk(ctx, &dep.group, &dep.name, &dep.version, memo, stack)?;
        max = max.max(req);
    }
    stack.remove(&key);
    memo.insert(key, max);
    Ok(max)
}

/// `minCompileSdk` declared by the artifact's own AAR, if any. JAR/POM-only
/// artifacts and AARs without the metadata file are unconstrained.
fn aar_min_sdk(ctx: &Ctx, group: &str, name: &str, version: &str) -> Result<Option<u32>, String> {
    let key = format!("v1:sdk-aar:{group}:{name}:{version}");
    if let Some(cached) = ctx.cache.get::<Option<u32>>(&key, TTL_FOREVER_SECS) {
        return Ok(cached);
    }
    let path = format!(
        "{}/{}/{}/{}-{}.aar",
        group.replace('.', "/"),
        name,
        version,
        name,
        version
    );
    let result = match fetch_artifact_bytes(&path)? {
        Some(bytes) => aar_min_sdk_from_bytes(&bytes)?,
        None => None,
    };
    ctx.cache.set(&key, &result);
    Ok(result)
}

/// Direct compile/runtime dependencies from the artifact's POM.
fn pom_deps(ctx: &Ctx, group: &str, name: &str, version: &str) -> Result<Vec<PomDep>, String> {
    let key = format!("v1:sdk-pom:{group}:{name}:{version}");
    if let Some(cached) = ctx.cache.get::<Vec<PomDep>>(&key, TTL_FOREVER_SECS) {
        return Ok(cached);
    }
    let path = format!(
        "{}/{}/{}/{}-{}.pom",
        group.replace('.', "/"),
        name,
        version,
        name,
        version
    );
    let result = match fetch_artifact_text(&path)? {
        Some(pom) => parse_pom_deps(&pom),
        None => Vec::new(),
    };
    ctx.cache.set(&key, &result);
    Ok(result)
}

/// Fetch a file from either Maven mirror. `Ok(None)` = absent on both (404);
/// anything else that fails is an error, never mistaken for absence.
fn fetch_artifact_bytes(path: &str) -> Result<Option<Vec<u8>>, String> {
    for base in MAVEN_BASES {
        let url = format!("{base}/{path}");
        match http::get_bytes_retry(&url) {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(e) if http::is_not_found(&e) => continue,
            Err(e) => {
                return Err(toolchains::request_reason(
                    "Maven Central / Google Maven",
                    &e,
                ));
            }
        }
    }
    Ok(None)
}

fn fetch_artifact_text(path: &str) -> Result<Option<String>, String> {
    for base in MAVEN_BASES {
        let url = format!("{base}/{path}");
        match http::get_text_retry(&url) {
            Ok(text) => return Ok(Some(text)),
            Err(e) if http::is_not_found(&e) => continue,
            Err(e) => {
                return Err(toolchains::request_reason(
                    "Maven Central / Google Maven",
                    &e,
                ));
            }
        }
    }
    Ok(None)
}

fn aar_min_sdk_from_bytes(bytes: &[u8]) -> Result<Option<u32>, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable AAR: {e}"))?;
    let mut file = match zip.by_name(AAR_METADATA_PATH) {
        Ok(file) => file,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(format!("unreadable AAR: {e}")),
    };
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("unreadable AAR: {e}"))?;
    Ok(parse_min_compile_sdk(&text))
}

fn parse_min_compile_sdk(text: &str) -> Option<u32> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("minCompileSdk="))
        .filter_map(|v| v.trim().parse::<u32>().ok())
        .next()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PomDep {
    group: String,
    name: String,
    version: String,
}

/// Compile/runtime dependencies from a POM. Test/provided scopes, optional
/// and BOM-import edges carry nothing onto the compile classpath and are
/// skipped, as are versions that cannot be nailed down (unresolvable
/// properties, ranges, missing).
fn parse_pom_deps(pom: &str) -> Vec<PomDep> {
    // The <parent> block's version is the parent's, not the project's.
    let parent_re = Regex::new(r"(?s)<parent>.*?</parent>").unwrap();
    let stripped = parent_re.replace(pom, "");
    // <dependencyManagement> only pins versions for consumers (a BOM manages
    // hundreds of artifacts it does not itself need): never dependencies.
    let mgmt_re = Regex::new(r"(?s)<dependencyManagement>.*?</dependencyManagement>").unwrap();
    let stripped = mgmt_re.replace(&stripped, "");
    let project_version = tag_content(&stripped, "version").unwrap_or_default();
    let mut props = HashMap::new();
    if let Some(block) = tag_content(&stripped, "properties") {
        let prop_re = Regex::new(r"<([A-Za-z0-9_.-]+)>([^<]*)</").unwrap();
        for caps in prop_re.captures_iter(&block) {
            props.insert(caps[1].to_string(), caps[2].to_string());
        }
    }
    let mut out = Vec::new();
    for block in tag_all(&stripped, "dependency") {
        let scope = tag_content(&block, "scope").unwrap_or_else(|| "compile".to_string());
        if matches!(scope.as_str(), "test" | "provided" | "system" | "import") {
            continue;
        }
        if tag_content(&block, "optional").as_deref() == Some("true") {
            continue;
        }
        if tag_content(&block, "type").as_deref() == Some("test-jar") {
            continue;
        }
        let (Some(group), Some(name)) = (
            tag_content(&block, "groupId"),
            tag_content(&block, "artifactId"),
        ) else {
            continue;
        };
        let Some(raw_version) = tag_content(&block, "version") else {
            continue;
        };
        let version = resolve_pom_props(&raw_version, &props, &project_version);
        if version.is_empty()
            || version.contains('$')
            || version.contains([',', '[', '(', ')', ']'])
        {
            continue;
        }
        out.push(PomDep {
            group,
            name,
            version,
        });
    }
    out
}

/// Expand `${project.version}` and same-POM properties (a few passes for
/// nesting). Anything still containing `${...}` is left for the caller to skip.
fn resolve_pom_props(raw: &str, props: &HashMap<String, String>, project_version: &str) -> String {
    let mut out = raw.to_string();
    for _ in 0..5 {
        if !out.contains("${") {
            break;
        }
        let mut next = out.replace("${project.version}", project_version);
        for (key, value) in props {
            next = next.replace(&format!("${{{key}}}"), value);
        }
        if next == out {
            break;
        }
        out = next;
    }
    out
}

/// Heuristic pre-release detection over dot/dash-separated tokens.
fn is_prerelease(v: &str) -> bool {
    const MARKERS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "milestone",
        "eap",
        "preview",
        "canary",
        "snapshot",
        "dev",
    ];
    v.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .any(|token| MARKERS.iter().any(|m| token.starts_with(m)))
}

/// Extract `<latest>`, `<release>` and every `<version>` entry.
fn all_versions_from_metadata(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tag in ["latest", "release"] {
        if let Some(v) = tag_content(xml, tag)
            && !v.is_empty()
        {
            out.push(v);
        }
    }
    out.extend(tag_all(xml, "version"));
    out
}

/// Lowercase match tokens for one artifact: group segments plus the
/// artifact name split on separators (`androidx.core:core-ktx` ->
/// {androidx, core, ktx}).
fn artifact_tokens(declared: &Declared) -> HashSet<String> {
    declared
        .group
        .split('.')
        .chain(declared.name.split(['-', '_', '.']))
        .map(|t| t.to_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// First-party package prefixes from source roots (`src/*/java|kotlin`
/// directory trees that hold sources): imports under them are the
/// project's own code. Both the root and one level of Gradle module
/// directories (`app/src/...`) are searched.
fn own_packages(root: &Path) -> Vec<String> {
    let mut bases = vec![root.to_path_buf()];
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
                && !crate::discover::skip_dir_name(name)
            {
                bases.push(path);
            }
        }
    }
    let mut out = Vec::new();
    for base in &bases {
        for set in ["main", "test", "androidTest"] {
            for lang in ["java", "kotlin"] {
                let src = base.join("src").join(set).join(lang);
                collect_packages(&src, &src, &mut out);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect_packages(base: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut has_source = false;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "kt" | "kts" | "java"))
        {
            has_source = true;
        }
    }
    if has_source && let Ok(rel) = dir.strip_prefix(base) {
        let dotted = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join(".");
        if !dotted.is_empty() {
            out.push(dotted);
        }
    }
    for sub in subdirs {
        collect_packages(base, &sub, out);
    }
}

/// Import prefixes satisfied by the platform, never by a dependency.
const FRAMEWORK_PREFIXES: &[&str] = &[
    "java.",
    "javax.net.",
    "javax.crypto.",
    "javax.security.",
    "kotlin.",
    "kotlinx.android.synthetic.",
    "android.",
    "androidx.databinding.",
    "dalvik.",
    "org.w3c.",
    "org.xml.",
    "org.json.",
];

/// Whether a Kotlin/Java import is satisfied: generated classes, the
/// platform, first-party packages, or a token shared with a declared
/// artifact past the TLD segment.
fn kotlin_satisfied(spec: &str, artifacts: &[HashSet<String>], own: &[String]) -> bool {
    if spec.contains(".databinding.")
        || spec.ends_with(".R")
        || spec.ends_with(".BuildConfig")
        || spec.ends_with(".BR")
    {
        return true; // generated by the Android Gradle plugin
    }
    if FRAMEWORK_PREFIXES.iter().any(|p| spec.starts_with(p)) {
        return true;
    }
    if own
        .iter()
        .any(|pkg| spec == pkg || spec.starts_with(&format!("{pkg}.")))
    {
        return true;
    }
    let segments: Vec<String> = spec.split('.').skip(1).map(|s| s.to_lowercase()).collect();
    artifacts
        .iter()
        .any(|tokens| segments.iter().any(|s| !s.is_empty() && tokens.contains(s)))
}

fn tag_content(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

fn tag_all(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let from = start + open.len();
        let Some(end) = rest[from..].find(&close) else {
            break;
        };
        out.push(rest[from..from + end].trim().to_string());
        rest = &rest[from + end + close.len()..];
    }
    out
}

/// Release date of one artifact version from the `Last-Modified` of its
/// versioned POM: Maven publishes no per-version date API. Mirrors are
/// tried in order; failures yield `None`, never gaps.
fn maven_version_date(ctx: &Ctx, group: &str, artifact: &str, version: &str) -> Option<String> {
    use crate::ecosystem::{cached_release_date, release_date_key};
    let coord = format!("{group}:{artifact}");
    if let Some(date) = cached_release_date(ctx, "android", &coord, version) {
        return Some(date);
    }
    let path = format!(
        "{}/{}/{version}/{artifact}-{version}.pom",
        group.replace('.', "/"),
        artifact,
    );
    for base in MAVEN_BASES {
        let url = format!("{base}/{path}");
        let fetched = http::head_last_modified_retry(&url)
            .ok()
            .flatten()
            .and_then(|stamp| crate::dates::http_date(&stamp));
        if let Some(date) = fetched {
            ctx.cache
                .set(&release_date_key("android", &coord, version), &date);
            return Some(date);
        }
    }
    None
}

/// Licenses of one used artifact version from its POM `<licenses>`,
/// following `<parent>` up to three levels (ecosystem parents like
/// Spring's declare the license once). Published POMs are immutable:
/// cached forever.
fn pom_licenses(ctx: &Ctx, group: &str, artifact: &str, version: &str) -> Vec<String> {
    let key = format!("v1:license:maven:{group}:{artifact}:{version}");
    let log_name = format!("{group}:{artifact}");
    if let Some(licenses) = ctx
        .cache
        .license_resolution(&key, "android", &log_name, version)
    {
        return licenses;
    }
    let mut coords = (group.to_string(), artifact.to_string(), version.to_string());
    let mut seen = std::collections::HashSet::new();
    let mut fetched_any = false;
    for _ in 0..3 {
        if !seen.insert(coords.clone()) {
            break;
        }
        let path = format!(
            "{}/{}/{}/{}-{}.pom",
            coords.0.replace('.', "/"),
            coords.1,
            coords.2,
            coords.1,
            coords.2
        );
        let Ok(Some(pom)) = fetch_artifact_text(&path) else {
            break;
        };
        fetched_any = true;
        let licenses = parse_pom_licenses(&pom);
        if !licenses.is_empty() {
            ctx.cache
                .store_license_resolution(&key, "android", &log_name, version, &licenses);
            return licenses;
        }
        let Some(parent) = parse_pom_parent(&pom) else {
            break;
        };
        coords = parent;
    }
    // A fetched-but-licenseless chain is definitive (immutable POMs);
    // fetch failures stay uncached for retry.
    if fetched_any {
        ctx.cache
            .store_license_resolution(&key, "android", &log_name, version, &[]);
    }
    Vec::new()
}

/// SPDX ids from a POM's `<licenses>` block.
fn parse_pom_licenses(pom: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(block) = tag_content(pom, "licenses") else {
        return out;
    };
    for entry in tag_all(&block, "license") {
        let name = tag_content(&entry, "name").unwrap_or_default();
        for id in crate::licenses::normalize_spdx(&name) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

/// Literal parent coordinates, if the POM declares any. Property
/// placeholders are not resolved: an unresolvable parent stops the walk.
fn parse_pom_parent(pom: &str) -> Option<(String, String, String)> {
    let block = tag_content(pom, "parent")?;
    let group = tag_content(&block, "groupId")?;
    let artifact = tag_content(&block, "artifactId")?;
    let version = tag_content(&block, "version")?;
    if [group.clone(), artifact.clone(), version.clone()]
        .iter()
        .any(|s| s.contains("${") || s.is_empty())
    {
        return None;
    }
    Some((group, artifact, version))
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
            &release_date_key("android", "junit:junit", "4.13.1"),
            &"2020-10-11".to_string(),
        );
        ctx.cache.set(
            &release_date_key("android", "junit:junit", "4.13.2"),
            &"2021-02-13".to_string(),
        );
        assert_eq!(
            Android.release_dates(&ctx, "junit:junit", "4.13.1", "4.13.2"),
            (
                Some("2020-10-11".to_string()),
                Some("2021-02-13".to_string())
            )
        );
        // Malformed coordinates yield nothing, not an error.
        assert_eq!(
            Android.release_dates(&ctx, "no-colon", "1.0", "2.0"),
            (None, None)
        );
    }

    #[test]
    fn parses_dependency_strings() {
        let text = "implementation(\"androidx.core:core-ktx:1.9.0\")\ntestImplementation 'junit:junit:4.13.2'\n";
        let deps = parse_dependency_strings(text);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].group, "androidx.core");
        assert_eq!(deps[0].current, "1.9.0");
    }

    #[test]
    fn parses_plugin_versions() {
        let text = "plugins {\n  id(\"com.android.application\") version \"8.1.0\"\n}\n";
        let deps = parse_plugin_versions(text);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].group, "com.android.tools.build");
        assert_eq!(deps[0].current, "8.1.0");
    }

    #[test]
    fn parses_version_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libs.versions.toml");
        std::fs::write(
            &path,
            "[versions]\ncoreKtx = \"1.9.0\"\n[libraries]\nandroidx-core-ktx = { group = \"androidx.core\", name = \"core-ktx\", version.ref = \"coreKtx\" }\ngson = \"com.google.code.gson:gson:2.9.0\"\n",
        )
        .unwrap();
        let (libs, aliases) = parse_version_catalog(&path);
        assert_eq!(libs.len(), 2);
        assert_eq!(aliases["androidx-core-ktx"].current, "1.9.0");
        assert_eq!(aliases["gson"].name, "gson");
    }

    #[test]
    fn wrapper_and_kotlin_pins() {
        assert_eq!(
            gradle_wrapper_version(
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n"
            )
            .as_deref(),
            Some("8.5")
        );
        let kotlin = parse_kotlin_plugin_versions(
            "plugins {\n  id(\"org.jetbrains.kotlin.android\") version \"1.9.0\"\n  kotlin(\"jvm\") version \"1.9.0\"\n}\n",
        );
        assert_eq!(kotlin.len(), 2);
        assert!(
            kotlin
                .iter()
                .any(|(id, _)| id == "org.jetbrains.kotlin.android")
        );
        assert!(kotlin.iter().any(|(id, _)| id == "kotlin.jvm"));
        // Kotlin plugin versions are tools, not library deps.
        assert!(
            parse_plugin_versions("id(\"org.jetbrains.kotlin.android\") version \"1.9.0\"")
                .is_empty()
        );
    }

    #[test]
    fn catalog_plugins_split() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libs.versions.toml");
        std::fs::write(
            &path,
            "[versions]\nagp = \"8.1.0\"\nkotlin = \"1.9.0\"\n[plugins]\nandroid-app = { id = \"com.android.application\", version.ref = \"agp\" }\nkotlin-android = { id = \"org.jetbrains.kotlin.android\", version.ref = \"kotlin\" }\n",
        )
        .unwrap();
        let plugins = parse_catalog_plugins(&path);
        assert_eq!(plugins.len(), 2);
        assert!(plugins.contains(&("com.android.application".to_string(), "8.1.0".to_string())));
        assert!(plugins.contains(&(
            "org.jetbrains.kotlin.android".to_string(),
            "1.9.0".to_string()
        )));
    }

    #[test]
    fn dynamic_and_missing_accessors_are_gaps() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("build.gradle"),
            "dependencies {\n  implementation 'com.example:dyn:1.+'\n  implementation libs.missing.dep\n}\n",
        )
        .unwrap();
        let inventory = Android.enumerate(dir.path()).unwrap();
        assert!(inventory.deps.is_empty());
        assert_eq!(inventory.gaps.len(), 4); // 2 checks x 2 gaps
        assert!(inventory.gaps.iter().any(|g| g.name == "com.example:dyn"));
        assert!(inventory.gaps.iter().any(|g| g.name == "libs.missing.dep"));
    }

    #[test]
    fn metadata_version_extraction() {
        let xml = "<metadata><versioning><latest>1.12.0</latest><release>1.12.0</release>\
             <versions><version>1.9.0</version><version>1.12.0</version></versions></versioning></metadata>";
        let versions = all_versions_from_metadata(xml);
        assert!(versions.contains(&"1.9.0".to_string()));
        assert!(versions.contains(&"1.12.0".to_string()));
    }

    #[test]
    fn prerelease_detection() {
        assert!(!is_prerelease("1.12.0"));
        assert!(is_prerelease("9.6.0-alpha01"));
        assert!(is_prerelease("1.0.0-rc1"));
    }

    #[test]
    fn picks_newest_stable() {
        let candidates = ["1.9.0", "2.3.0", "9.5.0", "9.6.0-alpha02"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(pick_latest("8.1.0", &candidates).as_deref(), Some("9.5.0"));
        assert_eq!(
            pick_latest("9.6.0-alpha01", &candidates).as_deref(),
            Some("9.6.0-alpha02")
        );
        let empty: Vec<String> = Vec::new();
        assert_eq!(pick_latest("1.0.0", &empty), None);
    }

    #[test]
    fn mirror_404_on_both_is_not_found() {
        let e404 = || anyhow::anyhow!(ureq::Error::StatusCode(404));
        assert_eq!(
            mirror_failure_reason(&[e404(), e404()]),
            "not found on Maven Central / Google Maven"
        );
    }

    #[test]
    fn mirror_transient_failure_is_not_not_found() {
        // Typical androidx case: Central 404s (expected), Google drops the
        // connection under burst load. Must not be reported as missing.
        let e404 = anyhow::anyhow!(ureq::Error::StatusCode(404));
        let dropped = anyhow::anyhow!("connection closed before message completed");
        let reason = mirror_failure_reason(&[e404, dropped]);
        assert!(
            reason.starts_with("Maven Central / Google Maven request failed: "),
            "{reason}"
        );
    }

    #[test]
    fn detects_compile_sdk_literals() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("build.gradle.kts"),
            "android {\n    compileSdk = 36\n    // compileSdk = 99\n}\n",
        )
        .unwrap();
        assert_eq!(detect_compile_sdk(dir.path()), Some(36));
    }

    #[test]
    fn detects_groovy_compile_sdk_and_takes_minimum() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("build.gradle"),
            "android {\n    compileSdkVersion 36\n    minSdk 33\n    targetSdk 36\n}\n",
        )
        .unwrap();
        let lib = dir.path().join("lib");
        std::fs::create_dir(&lib).unwrap();
        std::fs::write(
            lib.join("build.gradle"),
            "android {\n    compileSdk 35\n}\n",
        )
        .unwrap();
        // minSdk/targetSdk must not match; strictest module wins.
        assert_eq!(detect_compile_sdk(dir.path()), Some(35));
    }

    #[test]
    fn missing_compile_sdk_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("build.gradle.kts"),
            "plugins { id(\"app\") }\n",
        )
        .unwrap();
        assert_eq!(detect_compile_sdk(dir.path()), None);
    }

    #[test]
    fn parses_min_compile_sdk_property() {
        let text = "aarFormatVersion=1.0\naarMetadataVersion=1.0\nminCompileSdk=37\n\
             minCompileMinorSdk=0\nminCompileSdkExtension=0\n";
        assert_eq!(parse_min_compile_sdk(text), Some(37));
        // minCompileSdkExtension must not match the minCompileSdk= prefix.
        assert_eq!(parse_min_compile_sdk("minCompileSdkExtension=0\n"), None);
        assert_eq!(parse_min_compile_sdk(""), None);
    }

    fn zip_with_aar_metadata(with_file: bool) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        if with_file {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file(AAR_METADATA_PATH, options).unwrap();
            use std::io::Write;
            zip.write_all(b"minCompileSdk=36\n").unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_min_sdk_from_aar_bytes() {
        assert_eq!(
            aar_min_sdk_from_bytes(&zip_with_aar_metadata(true)).unwrap(),
            Some(36)
        );
        assert_eq!(
            aar_min_sdk_from_bytes(&zip_with_aar_metadata(false)).unwrap(),
            None
        );
        assert!(aar_min_sdk_from_bytes(b"not a zip").is_err());
    }

    #[test]
    fn parses_pom_dependencies() {
        let pom = r#"
<project>
  <parent><groupId>p</groupId><artifactId>p</artifactId><version>9.9</version></parent>
  <artifactId>demo</artifactId><version>2.11.0</version>
  <properties><core.version>1.19.0</core.version></properties>
  <dependencies>
    <dependency><groupId>androidx.core</groupId><artifactId>core</artifactId><version>${core.version}</version></dependency>
    <dependency><groupId>a</groupId><artifactId>b</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
    <dependency><groupId>c</groupId><artifactId>d</artifactId><version>1.0</version><optional>true</optional></dependency>
    <dependency><groupId>e</groupId><artifactId>f</artifactId><version>[1.0,2.0)</version></dependency>
    <dependency><groupId>g</groupId><artifactId>h</artifactId><version>${unresolvable}</version></dependency>
    <dependency><groupId>i</groupId><artifactId>j</artifactId></dependency>
  </dependencies>
</project>"#;
        assert_eq!(
            parse_pom_deps(pom),
            vec![
                PomDep {
                    group: "androidx.core".to_string(),
                    name: "core".to_string(),
                    version: "1.19.0".to_string()
                },
                PomDep {
                    group: "a".to_string(),
                    name: "b".to_string(),
                    version: "2.11.0".to_string()
                },
            ]
        );
    }

    #[test]
    fn bom_managed_dependencies_are_not_dependencies() {
        let pom = r#"
<project>
  <artifactId>compose-bom</artifactId><version>2026.09.00</version>
  <packaging>pom</packaging>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>androidx.core</groupId><artifactId>core-ktx</artifactId><version>1.19.1</version></dependency>
    </dependencies>
  </dependencyManagement>
</project>"#;
        assert!(parse_pom_deps(pom).is_empty());
    }

    #[test]
    fn candidate_pool_prefers_stable_newest_first() {
        let candidates = ["1.9.0", "2.3.0", "9.6.0-alpha02", "9.5.0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            candidate_pool("8.1.0", &candidates),
            vec![
                "9.5.0".to_string(),
                "2.3.0".to_string(),
                "1.9.0".to_string()
            ]
        );
        assert_eq!(
            candidate_pool("9.6.0-alpha01", &candidates)[0],
            "9.6.0-alpha02".to_string()
        );
    }

    #[test]
    fn select_compatible_walks_below_blocked_newest() {
        let pool = ["1.19.1", "1.19.0", "1.18.0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let req = |v: &str| -> Result<Option<u32>, String> {
            Ok(match v {
                "1.19.1" => Some(37),
                "1.19.0" => Some(36),
                _ => None,
            })
        };
        let info = select_compatible("1.18.0", &pool, 36, req);
        assert_eq!(info.latest, "1.19.0");
        assert_eq!(
            info.blocked,
            Some(BlockedUpdate {
                latest: "1.19.1".to_string(),
                min_compile_sdk: 37
            })
        );
        assert_eq!(info.unverified, None);
    }

    #[test]
    fn select_compatible_reports_fully_blocked() {
        let pool = ["1.19.1", "1.19.0", "1.18.0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let req = |_: &str| -> Result<Option<u32>, String> { Ok(Some(37)) };
        let info = select_compatible("1.18.0", &pool, 36, req);
        assert_eq!(info.latest, "1.18.0");
        assert!(info.blocked.is_some());
        // Walk stops at current: never suggests a downgrade.
        let req_none = |_: &str| -> Result<Option<u32>, String> { Ok(Some(99)) };
        let info = select_compatible("1.18.0", &pool, 36, req_none);
        assert_eq!(info.latest, "1.18.0");
    }

    #[test]
    fn select_compatible_degrades_on_transient_failure() {
        let pool = ["1.19.1", "1.18.0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let req = |_: &str| -> Result<Option<u32>, String> { Err("boom".to_string()) };
        let info = select_compatible("1.18.0", &pool, 36, req);
        assert_eq!(info.latest, "1.19.1");
        assert_eq!(info.blocked, None);
        assert_eq!(info.unverified, Some("boom".to_string()));
    }

    fn test_artifacts() -> Vec<HashSet<String>> {
        [
            ("androidx.core", "core-ktx"),
            ("com.google.code.gson", "gson"),
            ("junit", "junit"),
        ]
        .into_iter()
        .map(|(group, name)| {
            artifact_tokens(&Declared {
                group: group.to_string(),
                name: name.to_string(),
                current: "1.0".to_string(),
            })
        })
        .collect()
    }

    #[test]
    fn kotlin_matching_ignores_tld_and_platform() {
        let artifacts = test_artifacts();
        let own = vec!["com.example.app".to_string()];
        // Declared artifacts, by group or name token.
        assert!(kotlin_satisfied(
            "androidx.core.app.AppCompatActivity",
            &artifacts,
            &own
        ));
        assert!(kotlin_satisfied("com.google.gson.Gson", &artifacts, &own));
        assert!(kotlin_satisfied("org.junit.Test", &artifacts, &own));
        // Platform, generated, first-party.
        assert!(kotlin_satisfied("java.util.List", &artifacts, &own));
        assert!(kotlin_satisfied(
            "kotlin.collections.List",
            &artifacts,
            &own
        ));
        assert!(kotlin_satisfied("android.os.Bundle", &artifacts, &own));
        assert!(kotlin_satisfied("com.example.app.R", &artifacts, &own));
        assert!(kotlin_satisfied("com.example.app.Util", &artifacts, &own));
        // Zero overlap past the TLD: ghosts.
        assert!(!kotlin_satisfied(
            "com.squareup.retrofit2.Retrofit",
            &artifacts,
            &own
        ));
        assert!(!kotlin_satisfied(
            "io.reactivex.Observable",
            &artifacts,
            &own
        ));
    }

    #[test]
    fn own_packages_finds_module_sources() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("app/src/main/java/com/example/app");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("Main.kt"), "package com.example.app\n").unwrap();
        assert_eq!(
            own_packages(dir.path()),
            vec!["com.example.app".to_string()]
        );
    }
}
