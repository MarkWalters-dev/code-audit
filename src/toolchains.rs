//! Language/toolchain version checks: latest releases and end-of-life data.
//!
//! Sources: endoflife.date for Python/Node/Go (one document gives both the
//! newest release and per-cycle EOL dates), the npm registry for npm/pnpm/
//! yarn, GitHub releases for Bun, the Rust channel manifest, the Gradle
//! version service, and Maven metadata for Kotlin.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::cache::Cache;
use crate::{http, version};

/// Toolchains with a known "latest release" source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolId {
    Python,
    Node,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Rust,
    Go,
    Gradle,
    Kotlin,
}

impl ToolId {
    pub fn display(self) -> &'static str {
        match self {
            ToolId::Python => "python",
            ToolId::Node => "node",
            ToolId::Npm => "npm",
            ToolId::Pnpm => "pnpm",
            ToolId::Yarn => "yarn",
            ToolId::Bun => "bun",
            ToolId::Rust => "rust",
            ToolId::Go => "go",
            ToolId::Gradle => "gradle",
            ToolId::Kotlin => "kotlin",
        }
    }
}

/// A pinned or floored toolchain discovered in project files.
#[derive(Debug, Clone)]
pub struct ToolPin {
    pub tool: ToolId,
    /// Display name, including where it was found, e.g. `node (engines)`.
    pub display: String,
    /// Exact version when pinned (`.nvmrc`, `packageManager`, ...).
    pub version: Option<String>,
    /// Requirement/floor otherwise (`requires-python`, `engines`, MSRV, ...).
    pub spec: Option<String>,
}

/// Latest release plus EOL state of the caller's current cycle.
pub struct ToolStatus {
    pub latest: String,
    /// End-of-life date of the current cycle, when it is EOL.
    /// `Some(None)` = EOL with unknown date; `None` = still supported.
    pub eol: Option<Option<String>>,
    /// Lookup-failure reason when `latest` comes from stale cache.
    pub stale: Option<String>,
}

/// Resolve the latest release (and EOL state for `current`) for a toolchain.
/// Results are cached; `Err` carries the reason the registry failed.
pub fn tool_status(cache: &Cache, tool: ToolId, current: &str) -> Result<ToolStatus, String> {
    let (latest, stale) = match tool {
        ToolId::Yarn => yarn_latest(cache, current)?,
        _ => tool_latest(cache, tool)?,
    };
    let eol = match tool {
        ToolId::Python | ToolId::Node | ToolId::Go => cycle_eol(cache, tool, current),
        _ => None,
    };
    Ok(ToolStatus { latest, eol, stale })
}

fn tool_latest(cache: &Cache, tool: ToolId) -> Result<(String, Option<String>), String> {
    let key = format!("v1:tool:{:?}", tool);
    if let Some(cached) = cache.get(&key, cache.versions_ttl()) {
        return Ok((cached, None));
    }
    match fetch_tool_latest(cache, tool) {
        Ok(latest) => {
            cache.set(&key, &latest);
            Ok((latest, None))
        }
        Err(e) => match cache.get_stale(&key) {
            Some(stale) => Ok((stale, Some(e))),
            None => Err(e),
        },
    }
}

fn fetch_tool_latest(cache: &Cache, tool: ToolId) -> Result<String, String> {
    let latest = match tool {
        ToolId::Python | ToolId::Node | ToolId::Go => {
            let cycles = eol_table(cache, tool)?;
            newest_cycle_latest(tool, &cycles).ok_or_else(|| "no releases listed".to_string())?
        }
        ToolId::Npm => npm_latest("npm")?,
        ToolId::Pnpm => npm_latest("pnpm")?,
        ToolId::Yarn => npm_latest("yarn")?,
        ToolId::Bun => bun_latest()?,
        ToolId::Rust => rust_latest()?,
        ToolId::Gradle => gradle_latest()?,
        ToolId::Kotlin => kotlin_latest()?,
    };
    Ok(latest)
}

/// Yarn 2+ (berry) lives outside the classic `yarn` package line.
fn yarn_latest(cache: &Cache, current: &str) -> Result<(String, Option<String>), String> {
    let min = spec_min_version(current).unwrap_or_default();
    if min.starts_with('1') || min.is_empty() {
        return tool_latest(cache, ToolId::Yarn);
    }
    let key = "v1:tool:YarnBerry";
    if let Some(cached) = cache.get(key, cache.versions_ttl()) {
        return Ok((cached, None));
    }
    match npm_latest("@yarnpkg/cli").or_else(|_| npm_latest("yarn")) {
        Ok(latest) => {
            cache.set(key, &latest);
            Ok((latest, None))
        }
        Err(e) => match cache.get_stale(key) {
            Some(stale) => Ok((stale, Some(e))),
            None => Err(e),
        },
    }
}

/// EOL date of the cycle `current` belongs to (`Some(None)` = EOL, date
/// unknown; `None` = supported or unknown).
fn cycle_eol(cache: &Cache, tool: ToolId, current: &str) -> Option<Option<String>> {
    let product = match tool {
        ToolId::Python => "python",
        ToolId::Node => "nodejs",
        ToolId::Go => "go",
        _ => return None,
    };
    product_eol(cache, product, current)
}

/// End-of-life state of `current` for any endoflife.date product: unknown
/// products (404) yield `None`, so callers can probe freely.
pub(crate) fn product_eol(cache: &Cache, product: &str, current: &str) -> Option<Option<String>> {
    let cycles = eol_table_for(cache, product).ok()?;
    let baseline = spec_min_version(current).unwrap_or_else(|| current.to_string());
    let cycle = cycles.iter().find(|c| {
        baseline == c.cycle
            || baseline.starts_with(&format!("{}.", c.cycle))
            || c.cycle.starts_with(&format!("{baseline}."))
    })?;
    match &cycle.eol {
        EolValue::Date(d) if d.as_str() < today_string().as_str() => Some(Some(d.clone())),
        EolValue::Flag(true) => Some(None),
        _ => None,
    }
}

/// Newest release across cycles (LTS cycles only for Node).
fn newest_cycle_latest(tool: ToolId, cycles: &[EolCycle]) -> Option<String> {
    let pool: Vec<&EolCycle> = if tool == ToolId::Node {
        let lts: Vec<&EolCycle> = cycles.iter().filter(|c| c.is_lts()).collect();
        if lts.is_empty() {
            cycles.iter().collect()
        } else {
            lts
        }
    } else {
        cycles.iter().collect()
    };
    pool.into_iter()
        .max_by(|a, b| version::compare(&a.cycle, &b.cycle))
        .map(|c| c.latest.clone())
        .filter(|l| !l.is_empty())
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EolCycle {
    cycle: String,
    #[serde(default)]
    eol: EolValue,
    #[serde(default)]
    latest: String,
    #[serde(default)]
    lts: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(untagged)]
enum EolValue {
    Date(String),
    Flag(bool),
    #[default]
    Unknown,
}

impl EolCycle {
    fn is_lts(&self) -> bool {
        matches!(
            &self.lts,
            Some(serde_json::Value::String(_)) | Some(serde_json::Value::Bool(true))
        )
    }
}

fn eol_table(cache: &Cache, tool: ToolId) -> Result<Vec<EolCycle>, String> {
    let product = match tool {
        ToolId::Python => "python",
        ToolId::Node => "nodejs",
        ToolId::Go => "go",
        _ => return Err("no EOL source".to_string()),
    };
    eol_table_for(cache, product)
}

fn eol_table_for(cache: &Cache, product: &str) -> Result<Vec<EolCycle>, String> {
    let key = format!("v1:eol:{product}");
    if let Some(cached) = cache.get(&key, cache.versions_ttl()) {
        return Ok(cached);
    }
    let url = format!("https://endoflife.date/api/{product}.json");
    match http::get_json_retry::<Vec<EolCycle>>(&url) {
        Ok(cycles) => {
            cache.set(&key, &cycles);
            Ok(cycles)
        }
        // Slow-moving data: serve stale silently rather than lose EOL info.
        Err(e) => match cache.get_stale(&key) {
            Some(stale) => Ok(stale),
            None => Err(request_reason("endoflife.date", &e)),
        },
    }
}

fn npm_latest(package: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Latest {
        version: String,
    }
    let encoded = package.replace('/', "%2f");
    let url = format!("https://registry.npmjs.org/{encoded}/latest");
    match http::get_json_retry::<Latest>(&url) {
        Ok(r) => Ok(r.version),
        Err(e) => Err(request_reason("npm registry", &e)),
    }
}

fn bun_latest() -> Result<String, String> {
    #[derive(Deserialize)]
    struct Release {
        tag_name: String,
    }
    let url = "https://api.github.com/repos/oven-sh/bun/releases/latest";
    let release: Release =
        http::get_json_retry(url).map_err(|e| request_reason("GitHub API", &e))?;
    // Tags look like "bun-v1.4.4".
    let version = release
        .tag_name
        .trim_start_matches("bun-v")
        .trim_start_matches("bun-")
        .trim_start_matches('v')
        .to_string();
    spec_min_version(&version)
        .filter(|v| v == &version)
        .ok_or_else(|| format!("unexpected release tag '{}'", release.tag_name))
}

fn rust_latest() -> Result<String, String> {
    let text = http::get_text_retry("https://static.rust-lang.org/dist/channel-rust-stable.toml")
        .map_err(|e| request_reason("static.rust-lang.org", &e))?;
    let doc: toml::Value =
        toml::from_str(&text).map_err(|e| format!("cannot parse channel manifest: {e}"))?;
    let version = doc
        .get("pkg")
        .and_then(|p| p.get("rust"))
        .and_then(|r| r.get("version"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "no version in channel manifest".to_string())?;
    // "1.85.1 (hash date)" -> "1.85.1".
    version
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| "empty version in channel manifest".to_string())
}

fn gradle_latest() -> Result<String, String> {
    #[derive(Deserialize)]
    struct Current {
        version: String,
    }
    let url = "https://services.gradle.org/versions/current";
    match http::get_json_retry::<Current>(url) {
        Ok(r) => Ok(r.version),
        Err(e) => Err(request_reason("services.gradle.org", &e)),
    }
}

fn kotlin_latest() -> Result<String, String> {
    // Kotlin artifacts move in lockstep; the Gradle plugin is the canonical one.
    let candidates =
        crate::android::fetch_versions("org.jetbrains.kotlin", "kotlin-gradle-plugin")?;
    // Any stable baseline selects stable-only candidates.
    crate::android::pick_latest("999", &candidates)
        .or_else(|| candidates.into_iter().max_by(|a, b| version::compare(a, b)))
        .ok_or_else(|| "no releases listed".to_string())
}

/// Human reason for a failed registry request.
pub(crate) fn request_reason(source: &str, e: &anyhow::Error) -> String {
    if http::is_not_found(e) {
        return format!("not found on {source}");
    }
    format!("{source} request failed: {}", http::short_error(e, 100))
}

// ---------------------------------------------------------------------------
// Helpers shared by ecosystems
// ---------------------------------------------------------------------------

/// First dotted-numeric run in a spec (`>=3.9` -> `3.9`, `^20.1.0` -> `20.1.0`).
pub fn spec_min_version(spec: &str) -> Option<String> {
    let re = Regex::new(r"(\d+(?:\.\d+)*)").unwrap();
    re.captures(spec).map(|c| c[1].to_string())
}

/// Parse `.tool-versions` (asdf/mise) into lowercase tool -> version.
pub fn parse_tool_versions(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(root.join(".tool-versions")) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(tool), Some(version)) = (parts.next(), parts.next()) {
            out.insert(tool.to_lowercase(), version.to_string());
        }
    }
    out
}

/// Parse `mise.toml` / `.mise.toml` `[tools]` tables.
pub fn parse_mise_toml(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for file in ["mise.toml", ".mise.toml"] {
        let Ok(text) = std::fs::read_to_string(root.join(file)) else {
            continue;
        };
        let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        if let Some(table) = doc.get("tools").and_then(|v| v.as_table()) {
            for (tool, value) in table {
                match value {
                    toml::Value::String(v) => {
                        out.insert(tool.to_lowercase(), v.clone());
                    }
                    toml::Value::Table(t) => {
                        if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
                            out.insert(tool.to_lowercase(), v.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// Toolchain drift: pinned versions (toolchain files) compared against
/// the host's active binaries. A project pinning node 20 while the host
/// runs node 22 behaves differently here than in CI — that is the finding.
/// Only numeric pins compare (`stable`, `lts/*`, dated nightlies stay
/// silent); a missing host binary is not drift evidence either.
pub fn drift_notices(root: &Path) -> Vec<crate::ecosystem::Notice> {
    let mut out = Vec::new();
    for (tool, display, program, args) in [
        ("node", "node", "node", &["--version"] as &[&str]),
        ("python", "python", "python3", &["--version"] as &[&str]),
        ("go", "go", "go", &["version"] as &[&str]),
        ("rust", "rustc", "rustc", &["--version"] as &[&str]),
    ] {
        let Some((pin, file, line)) = tool_pin(root, tool) else {
            continue;
        };
        let Some(host) = host_version(program, args) else {
            continue;
        };
        if let Some(want) = pin_parts(&pin)
            && version_drift(&want, &host)
        {
            out.push(crate::ecosystem::Notice {
                check: crate::ecosystem::NoticeCheck::Drift,
                name: display.to_string(),
                message: format!("{file} pins {display} {pin}, host {display} is {host}"),
                file: Some(file.to_string()),
                line: Some(line),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Pinned version for `tool` from the first pin file that names it:
/// (pin, file, 1-based line).
fn tool_pin(root: &Path, tool: &str) -> Option<(String, &'static str, u32)> {
    match tool {
        "node" => node_pin(root).or_else(|| manager_pin(root, &["nodejs", "node"])),
        "python" => python_pin(root).or_else(|| manager_pin(root, &["python"])),
        "go" => go_pin(root).or_else(|| manager_pin(root, &["golang", "go"])),
        "rust" => rust_pin(root).or_else(|| manager_pin(root, &["rust"])),
        _ => None,
    }
}

/// First line of `.nvmrc` / `.node-version`.
fn node_pin(root: &Path) -> Option<(String, &'static str, u32)> {
    for file in [".nvmrc", ".node-version"] {
        let Ok(text) = std::fs::read_to_string(root.join(file)) else {
            continue;
        };
        if let Some(pin) = text.lines().next().map(str::trim).filter(|s| !s.is_empty()) {
            return Some((pin.to_string(), file, 1));
        }
    }
    None
}

/// First line of `.python-version` (pyenv may append `:env` labels).
fn python_pin(root: &Path) -> Option<(String, &'static str, u32)> {
    let Ok(text) = std::fs::read_to_string(root.join(".python-version")) else {
        return None;
    };
    text.lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| (s.split(':').next().unwrap_or(s).to_string(), ".python-version", 1))
}

/// The `go` directive's version plus its line number.
fn go_pin(root: &Path) -> Option<(String, &'static str, u32)> {
    let Ok(text) = std::fs::read_to_string(root.join("go.mod")) else {
        return None;
    };
    text.lines().enumerate().find_map(|(i, line)| {
        let mut parts = line.split_whitespace();
        (parts.next() == Some("go"))
            .then(|| parts.next())
            .flatten()
            .map(|v| (v.to_string(), "go.mod", i as u32 + 1))
    })
}

/// `rust-toolchain.toml` channel (or the legacy `rust-toolchain` file,
/// whose whole content is the channel name).
fn rust_pin(root: &Path) -> Option<(String, &'static str, u32)> {
    if let Ok(text) = std::fs::read_to_string(root.join("rust-toolchain.toml")) {
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if let Some(rest) = line.strip_prefix("channel") {
                let value = rest
                    .trim_start_matches([' ', '=', '\t'])
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim();
                if !value.is_empty() {
                    return Some((value.to_string(), "rust-toolchain.toml", i as u32 + 1));
                }
            }
        }
        return None;
    }
    let Ok(text) = std::fs::read_to_string(root.join("rust-toolchain")) else {
        return None;
    };
    text.lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| (s.to_string(), "rust-toolchain", 1))
}

/// `.tool-versions` / `mise.toml` pin for one of `names`, with the file
/// and line it came from.
fn manager_pin(root: &Path, names: &[&str]) -> Option<(String, &'static str, u32)> {
    if let Ok(text) = std::fs::read_to_string(root.join(".tool-versions")) {
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(tool), Some(version)) = (parts.next(), parts.next())
                && names.contains(&tool.to_lowercase().as_str())
            {
                return Some((version.to_string(), ".tool-versions", i as u32 + 1));
            }
        }
    }
    // mise `[tools]` tables do not track lines cheaply; the pin matters,
    // the line is best-effort (first `tool =` occurrence).
    let pins = parse_mise_toml(root);
    for name in names {
        if let Some(pin) = pins.get(*name) {
            let line = mise_pin_line(root, name);
            return Some((pin.clone(), "mise.toml", line));
        }
    }
    None
}

fn mise_pin_line(root: &Path, tool: &str) -> u32 {
    for file in ["mise.toml", ".mise.toml"] {
        let Ok(text) = std::fs::read_to_string(root.join(file)) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let stripped: String = line.split_whitespace().collect();
            if stripped.starts_with(&format!("{tool}=")) || stripped.starts_with(&format!("\"{tool}\"="))
            {
                return i as u32 + 1;
            }
        }
    }
    1
}

/// Host binary's version (`rustc 1.82.0 ...` -> `1.82.0`); `None` when
/// the binary is missing or its output has no version.
fn host_version(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    spec_min_version(&text)
}

/// Numeric prefix of a pin (`v20.11.0` -> [20, 11, 0]); `None` for
/// symbolic pins (`stable`, `lts/*`, dated nightlies).
fn pin_parts(pin: &str) -> Option<Vec<u64>> {
    let pin = pin.trim().strip_prefix('v').unwrap_or(pin.trim());
    let end = pin
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(pin.len());
    if end == 0 {
        return None;
    }
    pin[..end]
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()
        .filter(|v| !v.is_empty())
}

/// Whether the pin disagrees with the host at the pin's precision
/// (a bare `20` only constrains the major version).
fn version_drift(want: &[u64], host: &str) -> bool {
    let have: Vec<u64> = host
        .split('.')
        .filter_map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u64>()
                .ok()
        })
        .collect();
    want.iter()
        .zip(have.iter())
        .any(|(w, h)| w != h)
}

/// Today's date as `YYYY-MM-DD` (for EOL comparison; lexical compare works).
pub fn today_string() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0);
    today_string_from_days(days)
}

/// Calendar date for days since the Unix epoch (shared civil-date math).
pub(crate) fn today_string_from_days(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 -> civil date (Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(18628), (2021, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
        assert_eq!(civil_from_days(19782), (2024, 2, 29)); // leap day
    }

    #[test]
    fn spec_min_extraction() {
        assert_eq!(spec_min_version(">=3.9"), Some("3.9".to_string()));
        assert_eq!(spec_min_version("^20.1.0"), Some("20.1.0".to_string()));
        assert_eq!(spec_min_version("20.x"), Some("20".to_string()));
        assert_eq!(spec_min_version("v22.3"), Some("22.3".to_string()));
        assert_eq!(spec_min_version("stable"), None);
    }

    #[test]
    fn tool_versions_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".tool-versions"),
            "# comment\npython 3.12.1\nnodejs 20.11.0\n",
        )
        .unwrap();
        let map = parse_tool_versions(dir.path());
        assert_eq!(map.get("python").unwrap(), "3.12.1");
        assert_eq!(map.get("nodejs").unwrap(), "20.11.0");
    }

    #[test]
    fn newest_cycle_picks_lts_for_node() {
        let cycles = vec![
            EolCycle {
                cycle: "22".to_string(),
                eol: EolValue::Flag(false),
                latest: "22.12.0".to_string(),
                lts: Some(serde_json::json!("2023-10-24")),
            },
            EolCycle {
                cycle: "23".to_string(),
                eol: EolValue::Date("2025-06-01".to_string()),
                latest: "23.6.0".to_string(),
                lts: Some(serde_json::json!(false)),
            },
        ];
        assert_eq!(
            newest_cycle_latest(ToolId::Node, &cycles).as_deref(),
            Some("22.12.0")
        );
        assert_eq!(
            newest_cycle_latest(ToolId::Go, &cycles).as_deref(),
            Some("23.6.0")
        );
    }

    #[test]
    fn pin_parts_accepts_versions_rejects_symbols() {
        assert_eq!(pin_parts("20"), Some(vec![20]));
        assert_eq!(pin_parts("v20.11.0"), Some(vec![20, 11, 0]));
        assert_eq!(pin_parts("1.82"), Some(vec![1, 82]));
        assert!(pin_parts("stable").is_none());
        assert!(pin_parts("lts/*").is_none());
        assert!(pin_parts("nightly-2024-01-01").is_none());
        assert!(pin_parts("").is_none());
    }

    #[test]
    fn drift_compares_at_pin_precision() {
        assert!(version_drift(&[20], "22.4.0"));
        assert!(!version_drift(&[20], "20.11.0"));
        assert!(version_drift(&[1, 82], "1.85.0"));
        assert!(!version_drift(&[3, 12], "3.12.3"));
        assert!(version_drift(&[3, 12, 3], "3.12.7"));
    }

    #[test]
    fn pin_files_yield_pins_with_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".nvmrc"), "20\n").unwrap();
        std::fs::write(dir.path().join("go.mod"), "module x\n\ngo 1.21\n").unwrap();
        std::fs::write(dir.path().join("rust-toolchain.toml"), "[toolchain]\nchannel = \"1.82\"\n").unwrap();
        assert_eq!(
            node_pin(dir.path()),
            Some(("20".to_string(), ".nvmrc", 1))
        );
        assert_eq!(
            go_pin(dir.path()),
            Some(("1.21".to_string(), "go.mod", 3))
        );
        assert_eq!(
            rust_pin(dir.path()),
            Some(("1.82".to_string(), "rust-toolchain.toml", 2))
        );
        assert!(python_pin(dir.path()).is_none());
    }
}
