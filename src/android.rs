//! Android/Gradle ecosystem.
//!
//! Two strategies:
//! A. When the project already applies the `gradle-versions-plugin`
//!    (`com.github.ben-manes.versions`), run `./gradlew dependencyUpdates`
//!    and parse `build/dependencyUpdates/report.txt`. The plugin is never
//!    added automatically — that would modify the user's build.
//! B. Otherwise, parse declared versions from `gradle/libs.versions.toml` and
//!    `build.gradle(.kts)` dependency strings and compare against the latest
//!    release published on Maven Central / Google Maven.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use regex::Regex;

use crate::ecosystem::{CheckOutcome, Ctx, EcosystemChecker, OutdatedDep};
use crate::{exec, version};

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

    fn detect(&self, root: &Path) -> bool {
        if root.join("gradle").join("libs.versions.toml").is_file() {
            return true;
        }
        GRADLE_FILES.iter().any(|f| root.join(f).is_file())
    }

    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome {
        if uses_versions_plugin(root) {
            match check_via_gradle(ctx, root) {
                Ok(outcome) => return outcome,
                Err(e) => {
                    if ctx.verbose {
                        eprintln!(
                            "gradle dependencyUpdates failed ({e}); falling back to metadata lookup"
                        );
                    }
                    let mut fallback = check_via_metadata(ctx, root);
                    let note = format!(
                        "gradle dependencyUpdates failed ({e}); used metadata lookup instead"
                    );
                    fallback.message = Some(match fallback.message {
                        Some(m) => format!("{note}. {m}"),
                        None => note,
                    });
                    return fallback;
                }
            }
        }
        check_via_metadata(ctx, root)
    }
}

// ---------------------------------------------------------------------------
// Strategy A: gradle-versions-plugin
// ---------------------------------------------------------------------------

fn uses_versions_plugin(root: &Path) -> bool {
    let mut files: Vec<PathBuf> = find_files(root, GRADLE_FILES, true);
    files.push(root.join("gradle").join("libs.versions.toml"));
    files.into_iter().any(|p| {
        std::fs::read_to_string(p)
            .map(|s| s.contains("com.github.ben-manes.versions") || s.contains("ben-manes"))
            .unwrap_or(false)
    })
}

fn check_via_gradle(ctx: &Ctx, root: &Path) -> Result<CheckOutcome, String> {
    #[cfg(windows)]
    let wrapper = root.join("gradlew.bat");
    #[cfg(not(windows))]
    let wrapper = root.join("gradlew");
    let gradle = if wrapper.is_file() {
        wrapper.to_string_lossy().into_owned()
    } else if let Some(g) = exec::resolve_tool("gradle") {
        g
    } else {
        return Err("no gradlew wrapper or gradle binary found".to_string());
    };
    let args = vec![
        "dependencyUpdates".to_string(),
        "--console=plain".to_string(),
    ];
    let out = exec::run(&gradle, &args, root, &Default::default(), ctx.verbose)
        .map_err(|e| format!("{e:#}"))?;
    if !out.success {
        return Err(format!(
            "exited with code {:?}: {}",
            out.code,
            first_lines(&out.stderr, 5)
        ));
    }
    // Multi-module builds write one report per module; merge them all.
    let reports = find_files(root, &["report.txt"], false)
        .into_iter()
        .filter(|p| {
            p.parent()
                .and_then(|d| d.file_name())
                .is_some_and(|n| n == "dependencyUpdates")
        })
        .collect::<Vec<_>>();
    if reports.is_empty() {
        return Err(
            "gradle ran but no build/.../dependencyUpdates/report.txt was produced".to_string(),
        );
    }
    let mut outdated = Vec::new();
    let mut checked = 0;
    for report in &reports {
        let text = std::fs::read_to_string(report)
            .map_err(|e| format!("cannot read {}: {e}", report.display()))?;
        let (o, c) = parse_dependency_updates_report(&text);
        outdated.extend(o);
        checked += c;
    }
    outdated.sort_by(|a, b| a.name.cmp(&b.name));
    outdated.dedup_by(|a, b| a.name == b.name);
    let mut outcome = CheckOutcome::ok("android", "Android", "gradle dependencyUpdates", outdated);
    outcome.checked = Some(checked);
    Ok(outcome)
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

/// Parse `report.txt`: ` - group:name [current -> latest]` lines, skipping
/// sections whose header says versions "exceed the latest" (those are newer
/// than any release, not outdated).
fn parse_dependency_updates_report(text: &str) -> (Vec<OutdatedDep>, usize) {
    let entry = Regex::new(r"^\s*-\s+(\S+)\s*\[([^\s\]]+)\s*->\s*([^\s\]]+)\]").unwrap();
    let bullet = Regex::new(r"^\s*-\s+\S+").unwrap();
    let mut outdated = Vec::new();
    let mut checked = 0;
    let mut skip_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') && !trimmed.starts_with('-') {
            let lower = trimmed.to_lowercase();
            skip_section = lower.contains("exceed the latest");
            continue;
        }
        if bullet.is_match(line) {
            checked += 1;
        }
        if skip_section {
            continue;
        }
        if let Some(caps) = entry.captures(line) {
            outdated.push(OutdatedDep {
                name: caps[1].trim_end_matches(':').to_string(),
                current: caps[2].to_string(),
                latest: caps[3].to_string(),
                detail: None,
            });
        }
    }
    outdated.sort_by(|a, b| a.name.cmp(&b.name));
    (outdated, checked)
}

// ---------------------------------------------------------------------------
// Strategy B: parse declarations, compare with Maven metadata
// ---------------------------------------------------------------------------

/// Well-known Gradle plugin id -> Maven coordinate, so build-plugin versions
/// (AGP, Kotlin, ...) can be checked like libraries.
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

fn check_via_metadata(ctx: &Ctx, root: &Path) -> CheckOutcome {
    let declared = collect_declared(root, ctx.verbose);
    if declared.is_empty() {
        let mut outcome =
            CheckOutcome::ok("android", "Android", "maven-metadata lookup", Vec::new());
        outcome.checked = Some(0);
        outcome.message = Some(
            "no pinned library versions found in libs.versions.toml or build.gradle files"
                .to_string(),
        );
        return outcome;
    }
    // Deduplicate coordinates; query each once.
    let unique: HashSet<(String, String)> = declared
        .iter()
        .map(|d| (d.group.clone(), d.name.clone()))
        .collect();
    let mut versions_of: HashMap<(String, String), Vec<String>> = HashMap::new();
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for (group, name) in &unique {
            let (group, name) = (group.clone(), name.clone());
            handles.push(
                s.spawn(move || ((group.clone(), name.clone()), fetch_versions(&group, &name))),
            );
        }
        for h in handles {
            if let Ok((coord, versions)) = h.join()
                && !versions.is_empty()
            {
                versions_of.insert(coord, versions);
            }
        }
    });

    let mut outdated = Vec::new();
    let mut unresolvable = 0;
    for d in &declared {
        let key = (d.group.clone(), d.name.clone());
        match versions_of.get(&key) {
            Some(candidates) => match pick_latest(&d.current, candidates) {
                Some(latest) if version::is_newer(&d.current, &latest) => {
                    outdated.push(OutdatedDep {
                        name: format!("{}:{}", d.group, d.name),
                        current: d.current.clone(),
                        latest,
                        detail: None,
                    })
                }
                _ => {}
            },
            None => unresolvable += 1,
        }
    }
    outdated.sort_by(|a, b| a.name.cmp(&b.name));
    outdated.dedup_by(|a, b| a.name == b.name);
    let mut outcome = CheckOutcome::ok("android", "Android", "maven-metadata lookup", outdated);
    outcome.checked = Some(declared.len());
    if unresolvable > 0 {
        outcome.message = Some(format!(
            "{unresolvable} artifact(s) not found on Maven Central / Google Maven"
        ));
    }
    outcome
}

/// Gather pinned `group:name:version` declarations from the version catalog,
/// build files and plugin blocks.
fn collect_declared(root: &Path, verbose: bool) -> Vec<Declared> {
    let mut out = Vec::new();
    let catalog = root.join("gradle").join("libs.versions.toml");
    let mut aliases: HashMap<String, Declared> = HashMap::new();
    if catalog.is_file() {
        let (libs, alias_map) = parse_version_catalog(&catalog, verbose);
        out.extend(libs);
        aliases = alias_map;
    }
    for path in find_files(root, GRADLE_FILES, true) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(parse_dependency_strings(&text));
        out.extend(parse_plugin_versions(&text));
        out.extend(resolve_catalog_accessors(&text, &aliases));
    }
    // Drop dynamic/unresolvable versions and duplicates.
    let mut seen = HashSet::new();
    out.into_iter()
        .filter(|d| is_pinned(&d.current))
        .filter(|d| seen.insert((d.group.clone(), d.name.clone(), d.current.clone())))
        .collect()
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
fn parse_version_catalog(path: &Path, verbose: bool) -> (Vec<Declared>, HashMap<String, Declared>) {
    let mut libs = Vec::new();
    let mut aliases = HashMap::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return (libs, aliases),
    };
    let doc: toml::Value = match toml::from_str(&text) {
        Ok(d) => d,
        Err(e) => {
            if verbose {
                eprintln!("cannot parse {}: {e}", path.display());
            }
            return (libs, aliases);
        }
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

/// Parse `plugins { id("...") version "..." }` (kts) / `id '...' version '...'`.
fn parse_plugin_versions(text: &str) -> Vec<Declared> {
    let kts = Regex::new(r#"id\(\s*"([^"]+)"\s*\)\s*version\s*"([^"]+)""#).unwrap();
    let groovy = Regex::new(r#"id\s*['"]([^'"]+)['"]\s+version\s*['"]([^'"]+)['"]"#).unwrap();
    let mut out = Vec::new();
    for caps in kts.captures_iter(text).chain(groovy.captures_iter(text)) {
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
fn parse_catalog_accessors(text: &str, aliases: &HashMap<String, Declared>) -> Vec<Declared> {
    if aliases.is_empty() {
        return Vec::new();
    }
    let re = Regex::new(r"libs\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)").unwrap();
    let mut out = Vec::new();
    for caps in re.captures_iter(text) {
        let alias = caps[1].replace('.', "-");
        // Also try progressively shorter prefixes (accessor may include a
        // trailing configuration, e.g. libs.foo.android).
        let mut candidate = alias.as_str();
        loop {
            if let Some(d) = aliases.get(candidate) {
                out.push(d.clone());
                break;
            }
            match candidate.rfind('-') {
                Some(i) => candidate = &candidate[..i],
                None => break,
            }
        }
    }
    out
}

fn resolve_catalog_accessors(text: &str, aliases: &HashMap<String, Declared>) -> Vec<Declared> {
    parse_catalog_accessors(text, aliases)
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into()
}

/// All published versions of `group:name`, merged across Maven Central and
/// Google Maven. Both mirrors are always consulted because either one can be
/// stale for a given artifact (e.g. Central's AGP metadata lags far behind).
fn fetch_versions(group: &str, name: &str) -> Vec<String> {
    let path = format!("{}/{}/maven-metadata.xml", group.replace('.', "/"), name);
    let mut versions = Vec::new();
    for base in ["https://repo1.maven.org/maven2", "https://maven.google.com"] {
        let url = format!("{base}/{path}");
        match agent()
            .get(&url)
            .header("User-Agent", "freshdeps/0.1")
            .call()
        {
            Ok(mut resp) if resp.status().is_success() => {
                if let Ok(body) = resp.body_mut().read_to_string() {
                    versions.extend(all_versions_from_metadata(&body));
                }
            }
            _ => continue,
        }
    }
    versions.sort();
    versions.dedup();
    versions
}

/// Pick the newest stable version, or the newest overall when `current` itself
/// is a pre-release (in which case pre-releases are fair game).
fn pick_latest(current: &str, candidates: &[String]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let pool: Vec<&String> = if is_prerelease(current) {
        candidates.iter().collect()
    } else {
        let stable: Vec<&String> = candidates.iter().filter(|v| !is_prerelease(v)).collect();
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

fn first_lines(s: &str, n: usize) -> String {
    s.lines().take(n).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dependency_updates_report() {
        let report = r#"------------------------------------------------------------
: Project dependency updates (report to plain text file)
------------------------------------------------------------

The following dependencies are using the latest milestone version:
 - com.example:fresh:2.0.0

The following dependencies have later milestone versions:
 - androidx.core:core-ktx [1.9.0 -> 1.12.0]
 - com.google.code.gson:gson [2.9.0 -> 2.10.1]

The following dependencies exceed the latest version found:
 - com.example:ahead [9.9.9 -> 2.0.0]
"#;
        let (outdated, checked) = parse_dependency_updates_report(report);
        assert_eq!(checked, 4);
        assert_eq!(outdated.len(), 2);
        assert_eq!(outdated[0].name, "androidx.core:core-ktx");
        assert_eq!(outdated[0].current, "1.9.0");
        assert_eq!(outdated[0].latest, "1.12.0");
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
        let (libs, aliases) = parse_version_catalog(&path, false);
        assert_eq!(libs.len(), 2);
        assert_eq!(aliases["androidx-core-ktx"].current, "1.9.0");
        assert_eq!(aliases["gson"].name, "gson");
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
        assert!(!is_prerelease("20260101"));
        assert!(is_prerelease("2.5.0-Beta2"));
        assert!(is_prerelease("9.6.0-alpha01"));
        assert!(is_prerelease("1.0.0-rc1"));
        assert!(is_prerelease("1.2.3-SNAPSHOT"));
    }

    #[test]
    fn picks_newest_stable() {
        let candidates = ["1.9.0", "2.3.0", "9.5.0", "9.6.0-alpha02"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(pick_latest("8.1.0", &candidates).as_deref(), Some("9.5.0"));
        // A pre-release current allows pre-release targets.
        assert_eq!(
            pick_latest("9.6.0-alpha01", &candidates).as_deref(),
            Some("9.6.0-alpha02")
        );
        let empty: Vec<String> = Vec::new();
        assert_eq!(pick_latest("1.0.0", &empty), None);
    }
}
