//! Linter integration: run each ecosystem's linters, merge their findings.
//!
//! Each ecosystem has one primary linter (ruff, biome, clippy,
//! golangci-lint, Android lint + ktlint), installed globally on first use
//! when missing. Repository-owned setups (a repo's own ESLint, detekt with
//! repo config) are used as-is and never installed into the project.
//!
//! Linter configs resolve across three tiers — the audited project, the
//! user's depaudit config dir, and a system-global dir — in an order the
//! user can override in `depaudit.toml`. The first tier holding a linter's
//! config file wins and is passed explicitly, so a preferred tier always
//! beats a linter's own auto-discovery.
//!
//! Findings from several linters on the same file/line with the same
//! message are merged into one entry naming every source, and lint
//! findings that only repeat an already-reported vulnerability (matched
//! by CVE/GHSA/RUSTSEC-style ids) are suppressed with a count.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;

use crate::ecosystem::{Ctx, Gap, GapCheck};
use crate::osv::FoundVuln;

// ---------------------------------------------------------------------------
// Config tiers
// ---------------------------------------------------------------------------

/// Where a linter's config file can come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// The audited project directory.
    Project,
    /// The user's depaudit config dir (`~/.config/depaudit/lint/`).
    Depaudit,
    /// The system-global dir (`/etc/depaudit/lint/`).
    Global,
}

/// Default search order: project first, then user, then global.
pub const DEFAULT_ORDER: [Tier; 3] = [Tier::Project, Tier::Depaudit, Tier::Global];

/// Validate a `[lint] config_order` value: the three tier names, each once.
pub fn parse_order(names: &[String]) -> Result<[Tier; 3], String> {
    if names.len() != 3 {
        return Err(format!(
            "invalid [lint] config_order: need exactly the three tiers [\"project\", \"depaudit\", \"global\"], got {names:?}"
        ));
    }
    let mut order = [Tier::Project; 3];
    let mut seen = HashSet::new();
    for (i, name) in names.iter().enumerate() {
        let tier = match name.as_str() {
            "project" => Tier::Project,
            "depaudit" => Tier::Depaudit,
            "global" => Tier::Global,
            _ => {
                return Err(format!(
                    "invalid [lint] config_order tier {name:?}: expected \"project\", \"depaudit\" or \"global\""
                ));
            }
        };
        if !seen.insert(tier) {
            return Err(format!(
                "invalid [lint] config_order: tier {name:?} listed twice"
            ));
        }
        order[i] = tier;
    }
    Ok(order)
}

fn tier_dir(tier: Tier) -> Option<PathBuf> {
    match tier {
        Tier::Project => None,
        Tier::Depaudit => config_home().map(|h| h.join("depaudit").join("lint")),
        Tier::Global => Some(global_lint_dir()),
    }
}

fn config_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
            return Some(dir);
        }
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
    }
}

fn global_lint_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("PROGRAMDATA")
            .map(|d| PathBuf::from(d).join("depaudit").join("lint"))
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData\\depaudit\\lint"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/depaudit/lint")
    }
}

/// Linters whose config file participates in tier discovery. Clippy reads
/// `[lints]` from the project's own Cargo.toml, Android lint reads the
/// project's lint.xml/Gradle DSL, and `go vet` takes no config, so those
/// three are intentionally absent here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LintKind {
    Ruff,
    Golangci,
    Biome,
    KtLint,
    Detekt,
    Eslint,
}

impl LintKind {
    fn filenames(self) -> &'static [&'static str] {
        match self {
            LintKind::Ruff => &["ruff.toml", ".ruff.toml", "pyproject.toml"],
            LintKind::Golangci => &[
                ".golangci.yml",
                ".golangci.yaml",
                ".golangci.toml",
                ".golangci.json",
            ],
            LintKind::Biome => &["biome.json", "biome.jsonc"],
            LintKind::KtLint => &[".editorconfig"],
            LintKind::Detekt => &["detekt.yml", "detekt.yaml", "config.yml"],
            LintKind::Eslint => &["eslint.config.js", "eslint.config.mjs", "eslint.config.cjs"],
        }
    }
}

/// Effective config for `kind`: the first tier (in `order`) holding one of
/// its known filenames. A bare `pyproject.toml` only counts for ruff when
/// it actually contains a `[tool.ruff]` section.
pub(crate) fn find_config(kind: LintKind, root: &Path, order: &[Tier; 3]) -> Option<PathBuf> {
    for tier in order {
        let dir = match tier {
            Tier::Project => root.to_path_buf(),
            _ => tier_dir(*tier)?,
        };
        for name in kind.filenames() {
            let path = dir.join(name);
            if !path.is_file() {
                continue;
            }
            if kind == LintKind::Ruff && *name == "pyproject.toml" && !has_ruff_section(&path) {
                continue;
            }
            return Some(path);
        }
    }
    None
}

fn has_ruff_section(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .and_then(|doc| doc.get("tool")?.get("ruff").cloned())
        .is_some()
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// Normalized severity across linters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// One lint finding, possibly merged from several linters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LintFinding {
    /// Path relative to the project root.
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    pub message: String,
    /// Rule ids from every source, deduplicated (`F401`, `clippy::unwrap_used`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    /// Linters that reported this, e.g. `["ruff"]` or `["ktlint", "detekt"]`.
    pub sources: Vec<String>,
    pub severity: Severity,
}

/// Lint result of one ecosystem: findings plus gaps and notes.
#[derive(Debug, Default)]
pub struct LintOutcome {
    pub findings: Vec<LintFinding>,
    pub gaps: Vec<Gap>,
    pub notes: Vec<String>,
}

impl LintOutcome {
    fn gap(tool: &str, reason: String) -> Self {
        Self {
            findings: Vec::new(),
            gaps: vec![Gap {
                name: tool.to_string(),
                check: GapCheck::Lint,
                reason,
            }],
            notes: Vec::new(),
        }
    }
}

/// Merge duplicate findings and suppress ones that repeat reported
/// vulnerabilities. Duplicates are findings on the same file/line/column
/// with the same normalized message; the merged entry keeps every source
/// and rule and the highest severity. Suppression matches CVE/GHSA-style
/// ids in the finding against the reported vulnerability ids and aliases.
pub(crate) fn finalize(
    mut findings: Vec<LintFinding>,
    vulns: &[FoundVuln],
) -> (Vec<LintFinding>, Vec<String>) {
    findings.sort_by(|a, b| {
        (
            &a.file,
            a.line.unwrap_or(0),
            a.column.unwrap_or(0),
            a.sources.join(","),
        )
            .cmp(&(
                &b.file,
                b.line.unwrap_or(0),
                b.column.unwrap_or(0),
                b.sources.join(","),
            ))
    });
    let mut merged: Vec<LintFinding> = Vec::with_capacity(findings.len());
    let mut dupes = 0;
    for finding in findings {
        let same = merged.last().is_some_and(|last: &LintFinding| {
            !finding.file.is_empty()
                && finding.line.is_some()
                && last.file == finding.file
                && last.line == finding.line
                && last.column == finding.column
                && normalize(&last.message) == normalize(&finding.message)
        });
        if same {
            let last = merged.last_mut().unwrap();
            for source in finding.sources {
                if !last.sources.contains(&source) {
                    last.sources.push(source);
                }
            }
            for rule in finding.rules {
                if !last.rules.contains(&rule) {
                    last.rules.push(rule);
                }
            }
            last.severity = last.severity.max(finding.severity);
            dupes += 1;
        } else {
            merged.push(finding);
        }
    }

    let mut suppressed = 0;
    if !vulns.is_empty() {
        let mut ids = HashSet::new();
        for v in vulns {
            ids.insert(v.id.to_uppercase());
            for alias in &v.aliases {
                ids.insert(alias.to_uppercase());
            }
        }
        merged.retain(|f| {
            let haystack = format!("{} {}", f.rules.join(" "), f.message);
            let hit = security_ids(&haystack).iter().any(|id| ids.contains(id));
            if hit {
                suppressed += 1;
            }
            !hit
        });
    }

    let mut notes = Vec::new();
    if dupes > 0 {
        notes.push(if dupes == 1 {
            "1 duplicate lint finding merged".to_string()
        } else {
            format!("{dupes} duplicate lint findings merged")
        });
    }
    if suppressed > 0 {
        notes.push(if suppressed == 1 {
            "1 lint finding suppressed (already reported as a vulnerability)".to_string()
        } else {
            format!("{suppressed} lint findings suppressed (already reported as vulnerabilities)")
        });
    }
    (merged, notes)
}

fn normalize(message: &str) -> String {
    message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Vulnerability ids mentioned in free text (uppercased for comparison).
pub(crate) fn security_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // CVE-2024-1234, GHSA-abcd-efgh-ijkl, RUSTSEC-2024-0001, GO-2024-0001,
    // PYSEC-2026-1994: letters/digits/dashes in known shapes.
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        let upper = word.to_uppercase();
        let is_id = upper.starts_with("CVE-") && upper.len() > 8
            || upper.starts_with("GHSA-") && upper.len() > 10
            || upper.starts_with("RUSTSEC-") && upper.len() > 10
            || upper.starts_with("GO-") && upper.len() > 6
            || upper.starts_with("PYSEC-") && upper.len() > 8;
        if is_id && !out.contains(&upper) {
            out.push(upper);
        }
    }
    out
}

/// Relativize a linter-reported path against the project root, tolerating
/// absolute paths, `./` prefixes and (on mismatch) returning it as-is.
pub(crate) fn relativize(root: &Path, file: &str) -> String {
    let trimmed = file.strip_prefix("./").unwrap_or(file);
    let path = Path::new(trimmed);
    if path.is_absolute()
        && let Ok(rel) = path.strip_prefix(root)
    {
        return rel.to_string_lossy().replace('\\', "/");
    }
    trimmed.replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Tool resolution and global installs
// ---------------------------------------------------------------------------

/// Serializes global installs: ecosystems audit in parallel, and two
/// threads must never install (or half-observe) the same tool at once.
static INSTALL_LOCK: Mutex<()> = Mutex::new(());

const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Locate `name` on PATH plus the well-known user-global install dirs, so
/// tools work even when their installer dir is not on PATH.
fn find_tool(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    if let Some(home) = home_dir() {
        for extra in [".local/bin", "go/bin", ".cargo/bin", ".local/share/pnpm"] {
            let dir = home.join(extra);
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        let dir = xdg.join("pnpm");
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    let mut candidates = vec![name.to_string()];
    for ext in ["exe", "cmd", "bat"] {
        candidates.push(format!("{name}.{ext}"));
    }
    dirs.iter().find_map(|dir| {
        candidates.iter().find_map(|candidate| {
            let path = dir.join(candidate);
            path.is_file().then(|| path.clone())
        })
    })
}

/// Run an installer command, returning stdout on success or a tailed error.
fn run_install(program: &str, args: &[&str], what: &str) -> Result<String, String> {
    crate::progress::note(&format!(
        "depaudit: installing {what} via `{program} {}`...",
        args.join(" ")
    ));
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(std::env::temp_dir());
    match run_command(cmd, INSTALL_TIMEOUT) {
        Ok(out) if out.success => Ok(out.stdout),
        Ok(out) => Err(format!(
            "{what} install failed: {}",
            stderr_tail(&format!("{}\n{}", out.stdout, out.stderr), 3)
        )),
        Err(e) => Err(format!("{what} install failed: {e}")),
    }
}

/// Re-resolve `name` after an install, with a PATH hint when it landed
/// somewhere we cannot see.
fn resolve_after_install(
    name: &str,
    what: &str,
    hint_dir: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(path) = find_tool(name) {
        return Ok(path);
    }
    let mut reason = format!(
        "{what} was installed but `{name}` is still not resolvable; is its install directory on PATH?"
    );
    if let Some(dir) = hint_dir {
        reason.push_str(&format!(" (looked in {})", dir.display()));
    }
    Err(reason)
}

pub(crate) fn ensure_ruff() -> Result<PathBuf, String> {
    if let Some(path) = find_tool("ruff") {
        return Ok(path);
    }
    let _guard = INSTALL_LOCK.lock().unwrap();
    if let Some(path) = find_tool("ruff") {
        return Ok(path);
    }
    if find_tool("uv").is_none() {
        return Err("ruff is not installed and uv was not found; install uv (https://docs.astral.sh/uv/) or install ruff globally yourself (`uv tool install ruff`)".to_string());
    }
    run_install("uv", &["tool", "install", "ruff"], "ruff")?;
    resolve_after_install("ruff", "ruff", home_dir().map(|h| h.join(".local/bin")))
}

pub(crate) fn ensure_cargo_with_clippy() -> Result<PathBuf, String> {
    let cargo = find_tool("cargo").ok_or_else(|| {
        "cargo not found; install the Rust toolchain (https://rustup.rs) for Rust linting"
            .to_string()
    })?;
    if clippy_works(&cargo) {
        return Ok(cargo);
    }
    let _guard = INSTALL_LOCK.lock().unwrap();
    if clippy_works(&cargo) {
        return Ok(cargo);
    }
    if find_tool("rustup").is_none() {
        return Err("clippy is not installed and rustup was not found; install the clippy component for your toolchain manually (`rustup component add clippy`)".to_string());
    }
    run_install("rustup", &["component", "add", "clippy"], "clippy")?;
    if clippy_works(&cargo) {
        Ok(cargo)
    } else {
        Err("clippy install reported success but `cargo clippy --version` still fails".to_string())
    }
}

/// Whether `cargo clippy` resolves, probed outside any project so rustup
/// cannot auto-install a pinned toolchain as a side effect.
fn clippy_works(cargo: &Path) -> bool {
    let mut cmd = Command::new(cargo);
    cmd.args(["clippy", "--version"])
        .current_dir(std::env::temp_dir());
    run_command(cmd, Duration::from_secs(60))
        .map(|out| out.success)
        .unwrap_or(false)
}

pub(crate) fn ensure_golangci() -> Result<PathBuf, String> {
    if let Some(path) = find_tool("golangci-lint") {
        return Ok(path);
    }
    let _guard = INSTALL_LOCK.lock().unwrap();
    if let Some(path) = find_tool("golangci-lint") {
        return Ok(path);
    }
    if find_tool("go").is_none() {
        return Err("golangci-lint is not installed and go was not found; install Go (https://go.dev/dl/) or install golangci-lint globally yourself".to_string());
    }
    run_install(
        "go",
        &[
            "install",
            "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest",
        ],
        "golangci-lint",
    )?;
    resolve_after_install(
        "golangci-lint",
        "golangci-lint",
        home_dir().map(|h| h.join("go/bin")),
    )
}

pub(crate) fn ensure_biome() -> Result<PathBuf, String> {
    if let Some(path) = find_tool("biome") {
        return Ok(path);
    }
    let _guard = INSTALL_LOCK.lock().unwrap();
    if let Some(path) = find_tool("biome") {
        return Ok(path);
    }
    if find_tool("pnpm").is_none() {
        return Err("biome is not installed and pnpm was not found; install pnpm (https://pnpm.io/installation) or install @biomejs/biome globally yourself (`pnpm add -g @biomejs/biome`)".to_string());
    }
    run_install("pnpm", &["add", "-g", "@biomejs/biome"], "biome")?;
    resolve_after_install("biome", "biome", None)
}

/// Latest release (tag + asset download URLs) from the GitHub API.
struct GithubRelease {
    tag: String,
    assets: HashMap<String, String>,
}

fn github_latest_release(repo: &str) -> Result<GithubRelease, String> {
    #[derive(serde::Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
    }
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
        assets: Vec<Asset>,
    }
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let release: Release = crate::http::get_json_retry(&url)
        .map_err(|e| crate::toolchains::request_reason("GitHub API", &e))?;
    Ok(GithubRelease {
        tag: release.tag_name,
        assets: release
            .assets
            .into_iter()
            .map(|a| (a.name, a.browser_download_url))
            .collect(),
    })
}

/// Install one executable file to `~/.local/bin` (created as needed).
fn install_executable(name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let home = home_dir()
        .ok_or_else(|| "cannot determine a home directory for the global install".to_string())?;
    let dir = home.join(".local/bin");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(name);
    std::fs::write(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(path)
}

/// Small Bourne wrapper so a jar (or an unpacked tree's launcher) behaves
/// like a global binary. Windows gets a `.cmd` twin.
fn install_wrapper(name: &str, target: &str, jar: bool) -> Result<PathBuf, String> {
    let home = home_dir()
        .ok_or_else(|| "cannot determine a home directory for the global install".to_string())?;
    let dir = home.join(".local/bin");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let body = if jar {
        format!("#!/bin/sh\nexec java -jar \"{target}\" \"$@\"\n")
    } else {
        format!("#!/bin/sh\nexec \"{target}\" \"$@\"\n")
    };
    let path = dir.join(name);
    std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    #[cfg(windows)]
    {
        let win_body = if jar {
            format!("@echo off\r\njava -jar \"{target}\" %*\r\n")
        } else {
            format!("@echo off\r\n\"{target}\" %*\r\n")
        };
        std::fs::write(dir.join(format!("{name}.cmd")), win_body)
            .map_err(|e| format!("write wrapper: {e}"))?;
    }
    Ok(path)
}

pub(crate) fn ensure_ktlint() -> Result<PathBuf, String> {
    if let Some(path) = find_tool("ktlint") {
        return Ok(path);
    }
    let _guard = INSTALL_LOCK.lock().unwrap();
    if let Some(path) = find_tool("ktlint") {
        return Ok(path);
    }
    crate::progress::note("depaudit: installing ktlint (GitHub release download)...");
    let release = github_latest_release("ktlint/ktlint")
        .map_err(|e| format!("ktlint install failed: {e}"))?;
    let url = release.assets.get("ktlint").ok_or_else(|| {
        format!(
            "ktlint install failed: release {} has no `ktlint` asset",
            release.tag
        )
    })?;
    let bytes = crate::http::get_bytes_retry(url).map_err(|e| {
        format!(
            "ktlint install failed: {}",
            crate::http::short_error(&e, 120)
        )
    })?;
    let path = install_executable("ktlint", &bytes)?;
    // The launcher needs a JVM; verify it actually runs.
    let mut cmd = Command::new(&path);
    cmd.arg("--version").current_dir(std::env::temp_dir());
    match run_command(cmd, Duration::from_secs(120)) {
        Ok(out) if out.success => Ok(path),
        Ok(out) => Err(format!(
            "ktlint was installed to {} but does not run ({}); it needs a Java runtime on PATH",
            path.display(),
            stderr_tail(&out.stderr, 2)
        )),
        Err(e) => Err(format!(
            "ktlint was installed to {} but does not run ({e}); it needs a Java runtime on PATH",
            path.display()
        )),
    }
}

pub(crate) fn ensure_detekt() -> Result<PathBuf, String> {
    if let Some(path) = find_tool("detekt") {
        return Ok(path);
    }
    let _guard = INSTALL_LOCK.lock().unwrap();
    if let Some(path) = find_tool("detekt") {
        return Ok(path);
    }
    if find_tool("java").is_none() {
        return Err("detekt is not installed and no Java runtime was found; install a JVM first, or install detekt globally yourself".to_string());
    }
    crate::progress::note("depaudit: installing detekt (GitHub release download)...");
    let release = github_latest_release("detekt/detekt")
        .map_err(|e| format!("detekt install failed: {e}"))?;
    // Prefer a single executable jar; fall back to the CLI distribution zip.
    if let Some(jar) = release.assets.keys().find(|n| n.ends_with("-all.jar")) {
        let url = release.assets[jar].clone();
        let bytes = crate::http::get_bytes_retry(&url).map_err(|e| {
            format!(
                "detekt install failed: {}",
                crate::http::short_error(&e, 120)
            )
        })?;
        let home = home_dir().ok_or_else(|| {
            "cannot determine a home directory for the global install".to_string()
        })?;
        let jar_path = home.join(".local/bin").join(jar);
        if let Some(parent) = jar_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(&jar_path, bytes)
            .map_err(|e| format!("write {}: {e}", jar_path.display()))?;
        return install_wrapper("detekt", &jar_path.to_string_lossy(), true);
    }
    let zip_name = release
        .assets
        .keys()
        .find(|n| n.starts_with("detekt-cli-") && n.ends_with(".zip"))
        .ok_or_else(|| {
            format!(
                "detekt install failed: release {} has neither an all-in-one jar nor a CLI zip",
                release.tag
            )
        })?;
    let url = release.assets[zip_name].clone();
    let bytes = crate::http::get_bytes_retry(&url).map_err(|e| {
        format!(
            "detekt install failed: {}",
            crate::http::short_error(&e, 120)
        )
    })?;
    install_detekt_zip(&release.tag, &bytes)
}

/// Unpack a detekt CLI zip under `~/.local/share/depaudit/` and wrap its
/// launcher as a global `detekt`.
fn install_detekt_zip(tag: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let home = home_dir()
        .ok_or_else(|| "cannot determine a home directory for the global install".to_string())?;
    let dest = home
        .join(".local/share/depaudit")
        .join(format!("detekt-{tag}"));
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::create_dir_all(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("detekt install failed: bad zip ({e})"))?;
    archive
        .extract(&dest)
        .map_err(|e| format!("detekt install failed: unzip ({e})"))?;
    let launcher = find_detekt_launcher(&dest).ok_or_else(|| {
        "detekt install failed: unpacked zip has no bin/detekt launcher".to_string()
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&launcher)
            .map_err(|e| format!("stat launcher: {e}"))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&launcher, perms).map_err(|e| format!("chmod launcher: {e}"))?;
    }
    install_wrapper("detekt", &launcher.to_string_lossy(), false)
}

fn find_detekt_launcher(dir: &Path) -> Option<PathBuf> {
    // Layout is either `bin/detekt` or `<toplevel>/bin/detekt`.
    let direct = dir.join("bin").join("detekt");
    if direct.is_file() {
        return Some(direct);
    }
    std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let nested = entry.path().join("bin").join("detekt");
        nested.is_file().then_some(nested)
    })
}

// ---------------------------------------------------------------------------
// Running linters
// ---------------------------------------------------------------------------

const LINT_TIMEOUT: Duration = Duration::from_secs(180);
/// Cold builds (clippy compiling dependencies, golangci type-checking,
/// JVM warmup) are slow, not hung: linters that build get 15 minutes.
/// Partial work still counts — cargo/go caches make the next run faster.
const SLOW_LINT_TIMEOUT: Duration = Duration::from_secs(900);
const GRADLE_TIMEOUT: Duration = Duration::from_secs(1800);

struct RunOutput {
    stdout: String,
    stderr: String,
    success: bool,
}

/// Run a command to completion with a timeout. The output is always
/// returned for parsing — linters exit nonzero when they find issues —
/// with `success` recording the exit status for callers that need it
/// (installers, capability probes). Only spawn failures and timeouts fail.
fn run_command(mut cmd: Command, timeout: Duration) -> Result<RunOutput, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start {program}: {e}"))?;
    // Drain both pipes on reader threads: polling the exit status without
    // reading deadlocks once output exceeds the pipe buffer (~64K).
    let stdout_handle = child.stdout.take().unwrap();
    let stderr_handle = child.stderr.take().unwrap();
    let out_reader = std::thread::spawn(move || read_all(stdout_handle));
    let err_reader = std::thread::spawn(move || read_all(stderr_handle));
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = out_reader.join().unwrap_or_default();
                let stderr = err_reader.join().unwrap_or_default();
                return Ok(RunOutput {
                    stdout: String::from_utf8_lossy(&stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr).into_owned(),
                    success: status.success(),
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_reader.join();
                    let _ = err_reader.join();
                    return Err(format!("{program} timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("failed to wait for {program}: {e}")),
        }
    }
}

fn read_all(mut pipe: impl std::io::Read + Send + 'static) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = pipe.read_to_end(&mut buf);
    buf
}

/// Last non-empty lines of stderr, for gap reasons when a linter fails
/// without machine-readable output.
fn stderr_tail(stderr: &str, lines: usize) -> String {
    let kept: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .take(lines)
        .collect();
    if kept.is_empty() {
        "no output".to_string()
    } else {
        kept.into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ")
            .chars()
            .take(300)
            .collect()
    }
}

// Defensive JSON accessors: linter schemas drift across versions, so
// parsing never uses strict structs.

fn json_str<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

fn json_u32(v: &serde_json::Value, key: &str) -> Option<u32> {
    v.get(key)?.as_u64()?.try_into().ok()
}

fn json_arr<'a>(v: &'a serde_json::Value, key: &str) -> Vec<&'a serde_json::Value> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// First human string inside a free-form value (biome wraps messages in
/// nested markup objects): depth-limited walk, joined.
fn deep_message(v: &serde_json::Value) -> Option<String> {
    fn walk(v: &serde_json::Value, depth: usize, out: &mut Vec<String>) {
        if depth > 4 {
            return;
        }
        match v {
            serde_json::Value::String(s) => {
                let clean = s.split_whitespace().collect::<Vec<_>>().join(" ");
                if !clean.is_empty() {
                    out.push(clean);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, depth + 1, out);
                }
            }
            serde_json::Value::Object(map) => {
                // Biome nests the prose under `content`/`text`/`elements`.
                for key in ["content", "text", "elements", "message", "msg"] {
                    if let Some(inner) = map.get(key) {
                        walk(inner, depth + 1, out);
                    }
                }
                // Fall back to every value when no known key matched.
                if !map.keys().any(|k| {
                    ["content", "text", "elements", "message", "msg"].contains(&k.as_str())
                }) {
                    for inner in map.values() {
                        walk(inner, depth + 1, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, 0, &mut out);
    if out.is_empty() {
        None
    } else {
        Some(out.join(" "))
    }
}

fn word_severity(word: &str) -> Severity {
    let lower = word.to_lowercase();
    if lower.starts_with("err") || lower.starts_with("fatal") {
        Severity::Error
    } else if lower.starts_with("warn") {
        Severity::Warning
    } else {
        Severity::Info
    }
}

// ---------------------------------------------------------------------------
// Ruff (Python)
// ---------------------------------------------------------------------------

pub(crate) fn run_ruff(root: &Path, order: &[Tier; 3]) -> Result<Vec<LintFinding>, String> {
    crate::progress::linter("python", "ruff");
    let bin = ensure_ruff()?;
    let mut cmd = Command::new(bin);
    cmd.arg("check")
        .arg("--output-format")
        .arg("json")
        .arg("--no-cache")
        .current_dir(root);
    if let Some(config) = find_config(LintKind::Ruff, root, order) {
        cmd.arg("--config").arg(&config);
    }
    cmd.arg(".");
    let out = run_command(cmd, LINT_TIMEOUT).map_err(|e| format!("ruff failed: {e}"))?;
    let findings = parse_ruff(&out.stdout, root);
    if findings.is_none() {
        return Err(format!(
            "ruff produced no parseable output: {}",
            stderr_tail(&out.stderr, 3)
        ));
    }
    Ok(findings.unwrap_or_default())
}

fn parse_ruff(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    let items: Vec<serde_json::Value> = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    for item in &items {
        let Some(message) = json_str(item, "message") else {
            continue;
        };
        let file = json_str(item, "filename").unwrap_or("");
        let location = item.get("location");
        // E9* are syntax errors; everything else is a warning-grade finding.
        let code = json_str(item, "code").unwrap_or("");
        out.push(LintFinding {
            file: relativize(root, file),
            line: location.and_then(|l| json_u32(l, "row")),
            column: location.and_then(|l| json_u32(l, "column")),
            message: message.to_string(),
            rules: if !code.is_empty() {
                vec![code.to_string()]
            } else {
                Default::default()
            },
            sources: vec!["ruff".to_string()],
            severity: if code.starts_with("E9") {
                Severity::Error
            } else {
                Severity::Warning
            },
        });
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Clippy (Rust)
// ---------------------------------------------------------------------------

pub(crate) fn run_clippy(root: &Path) -> Result<Vec<LintFinding>, String> {
    let cargo = ensure_cargo_with_clippy()?;
    crate::progress::note("depaudit: running cargo clippy (first run compiles dependencies)...");
    let mut cmd = Command::new(cargo);
    cmd.args([
        "clippy",
        "--workspace",
        "--message-format",
        "json",
        "--no-deps",
        "--quiet",
    ])
    .current_dir(root);
    let out =
        run_command(cmd, SLOW_LINT_TIMEOUT).map_err(|e| format!("cargo clippy failed: {e}"))?;
    match parse_clippy(&out.stdout, root) {
        Some(findings) => Ok(findings),
        None => Err(format!(
            "cargo clippy produced no parseable output: {}",
            stderr_tail(&out.stderr, 3)
        )),
    }
}

fn parse_clippy(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let mut out = Vec::new();
    let mut saw_message = false;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let Ok(item) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if json_str(&item, "reason") != Some("compiler-message") {
            continue;
        }
        saw_message = true;
        let Some(msg) = item.get("message") else {
            continue;
        };
        let message = json_str(msg, "message").unwrap_or("").to_string();
        if message.is_empty() {
            continue;
        }
        // Primary span first; only spans inside the project count.
        let spans = json_arr(msg, "spans");
        let span = spans
            .iter()
            .find(|s| s.get("is_primary").and_then(|p| p.as_bool()) == Some(true))
            .or_else(|| spans.first());
        let (file, line_no, col) = match span {
            Some(s) => {
                let name = json_str(s, "file_name").unwrap_or("");
                if !under_root(root, name) {
                    continue;
                }
                (
                    relativize(root, name),
                    json_u32(s, "line_start"),
                    json_u32(s, "column_start"),
                )
            }
            None => continue,
        };
        let code = msg
            .get("code")
            .and_then(|c| json_str(c, "code"))
            .unwrap_or("");
        let level = json_str(msg, "level").unwrap_or("warning");
        out.push(LintFinding {
            file,
            line: line_no,
            column: col,
            message,
            rules: if !code.is_empty() {
                vec![code.to_string()]
            } else {
                Default::default()
            },
            sources: vec!["clippy".to_string()],
            severity: word_severity(level),
        });
    }
    // Empty stdout with no compiler-message lines means something else
    // failed (no workspace, resolution error); the caller gaps on that.
    // But a clean lint also yields no messages — distinguish via the
    // compiler's own artifact lines, which clean runs still emit.
    if !saw_message && !stdout.lines().any(|l| l.trim().starts_with('{')) {
        return None;
    }
    Some(out)
}

/// Whether a compiler-reported path lives under the project root.
fn under_root(root: &Path, file: &str) -> bool {
    let path = Path::new(file);
    if path.is_absolute() {
        path.strip_prefix(root).is_ok()
    } else {
        // Relative spans are already project-relative (or registry noise
        // starting with `registry/`); accept unless obviously foreign.
        !(file.starts_with("registry/") || file.contains("/registry/src/"))
    }
}

// ---------------------------------------------------------------------------
// golangci-lint with `go vet` fallback (Go)
// ---------------------------------------------------------------------------

pub(crate) fn run_go_lints(root: &Path, order: &[Tier; 3]) -> LintOutcome {
    match ensure_golangci() {
        Ok(bin) => {
            crate::progress::note("depaudit: running golangci-lint...");
            match run_golangci(&bin, root, order) {
                Ok(findings) => LintOutcome {
                    findings,
                    gaps: Vec::new(),
                    notes: Vec::new(),
                },
                Err(reason) => vet_fallback(root, reason),
            }
        }
        Err(install_reason) => vet_fallback(root, install_reason),
    }
}

/// golangci-lint as JSON. v2 selects outputs with `--output.*` flags; a
/// pre-existing v1 binary uses `--out-format` instead (retried when the
/// v2 flags are rejected).
fn run_golangci(bin: &Path, root: &Path, order: &[Tier; 3]) -> Result<Vec<LintFinding>, String> {
    let config = find_config(LintKind::Golangci, root, order);
    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("--output.json.path=stdout")
        .arg("--output.text.path=stderr")
        .current_dir(root);
    if let Some(path) = &config {
        cmd.arg("--config").arg(path);
    }
    cmd.arg("./...");
    let out =
        run_command(cmd, SLOW_LINT_TIMEOUT).map_err(|e| format!("golangci-lint failed: {e}"))?;
    if let Some(findings) = parse_golangci(&out.stdout, root) {
        return Ok(findings);
    }
    if mentions_unknown_flag(&out.stderr) {
        let mut retry = Command::new(bin);
        retry
            .arg("run")
            .arg("--out-format")
            .arg("json")
            .current_dir(root);
        if let Some(path) = &config {
            retry.arg("--config").arg(path);
        }
        retry.arg("./...");
        let again =
            run_command(retry, LINT_TIMEOUT).map_err(|e| format!("golangci-lint failed: {e}"))?;
        if let Some(findings) = parse_golangci(&again.stdout, root) {
            return Ok(findings);
        }
    }
    Err(format!(
        "golangci-lint produced no parseable output: {}",
        stderr_tail(&out.stderr, 3)
    ))
}

/// `go vet` when golangci-lint cannot run: ships with Go, instant, and a
/// respectable subset for audit purposes.
fn vet_fallback(root: &Path, golangci_reason: String) -> LintOutcome {
    if find_tool("go").is_none() {
        return LintOutcome::gap("golangci-lint", golangci_reason);
    }
    crate::progress::linter("go", "go vet");
    let mut cmd = Command::new("go");
    cmd.arg("vet").arg("./...").current_dir(root);
    let mut outcome = match run_command(cmd, LINT_TIMEOUT) {
        Ok(out) => {
            let findings = parse_vet(&out.stdout, &out.stderr, root);
            match findings {
                Some(findings) => LintOutcome {
                    findings,
                    gaps: Vec::new(),
                    notes: vec!["golangci-lint unavailable; fell back to go vet".to_string()],
                },
                None => LintOutcome {
                    findings: Vec::new(),
                    gaps: vec![
                        Gap {
                            name: "golangci-lint".to_string(),
                            check: GapCheck::Lint,
                            reason: golangci_reason.clone(),
                        },
                        Gap {
                            name: "go vet".to_string(),
                            check: GapCheck::Lint,
                            reason: format!("no parseable output: {}", stderr_tail(&out.stderr, 3)),
                        },
                    ],
                    notes: Vec::new(),
                },
            }
        }
        Err(e) => LintOutcome {
            findings: Vec::new(),
            gaps: vec![
                Gap {
                    name: "golangci-lint".to_string(),
                    check: GapCheck::Lint,
                    reason: golangci_reason.clone(),
                },
                Gap {
                    name: "go vet".to_string(),
                    check: GapCheck::Lint,
                    reason: e,
                },
            ],
            notes: Vec::new(),
        },
    };
    // The install failure stays visible even when vet succeeds.
    if outcome.gaps.is_empty() {
        outcome.gaps.push(Gap {
            name: "golangci-lint".to_string(),
            check: GapCheck::Lint,
            reason: golangci_reason,
        });
    }
    outcome
}

/// First balanced `{...}` document in free text: some linters append a
/// human summary after their JSON payload.
fn first_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (i, b) in text.bytes().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return text.get(start..=i);
            }
        }
    }
    None
}

fn parse_golangci(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    let doc: serde_json::Value =
        first_json_object(text).and_then(|d| serde_json::from_str(d).ok())?;
    doc.get("Issues")?;
    let mut out = Vec::new();
    for issue in json_arr(&doc, "Issues") {
        let message = json_str(issue, "Text").unwrap_or("").to_string();
        if message.is_empty() {
            continue;
        }
        let pos = issue.get("Pos");
        let file = pos.and_then(|p| json_str(p, "Filename")).unwrap_or("");
        out.push(LintFinding {
            file: relativize(root, file),
            line: pos.and_then(|p| json_u32(p, "Line")),
            column: pos.and_then(|p| json_u32(p, "Column")),
            message,
            rules: json_str(issue, "FromLinter")
                .map(|l| vec![l.to_string()])
                .unwrap_or_default(),
            sources: vec!["golangci-lint".to_string()],
            severity: Severity::Warning,
        });
    }
    Some(out)
}

/// `go vet` prints `file:line:col: message` (colons inside Windows paths
/// aside) plus `# pkg` headers; indented continuations extend the message.
fn parse_vet(stdout: &str, stderr: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let mut out: Vec<LintFinding> = Vec::new();
    // vet writes diagnostics to stderr (stdout carries `go` tool chatter).
    for line in format!("{stdout}\n{stderr}").lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if let Some(last) = out.last_mut() {
                last.message.push(' ');
                last.message.push_str(line.trim());
            }
            continue;
        }
        let Some((file, line_no, col, message)) = split_vet_line(line) else {
            continue;
        };
        out.push(LintFinding {
            file: relativize(root, file),
            line: line_no,
            column: col,
            message: message.to_string(),
            rules: Vec::new(),
            sources: vec!["go vet".to_string()],
            severity: Severity::Warning,
        });
    }
    // No parseable diagnostics at all: distinguish "clean" (vet says
    // nothing on success) from a hard failure via the combined output.
    if out.is_empty() {
        let combined = format!("{stdout}\n{stderr}");
        if combined.trim().is_empty() {
            return Some(Vec::new());
        }
        // Non-diagnostic output only (build errors we could not parse,
        // usage text, ...): unparseable.
        return None;
    }
    Some(out)
}

fn split_vet_line(line: &str) -> Option<(&str, Option<u32>, Option<u32>, &str)> {
    // file:line: message | file:line:col: message (drive letters tolerated).
    let mut rest = line;
    let file_end = rest.find(':')?;
    // `C:\...` on Windows: the drive colon is not a separator.
    let mut file = &rest[..file_end];
    rest = &rest[file_end + 1..];
    if file.len() == 1 && rest.starts_with(['/', '\\']) {
        let next = rest[1..].find(':')?;
        file = &line[..file_end + 1 + 1 + next];
        rest = &rest[1 + next + 1..];
    }
    let (line_part, after_line) = rest.split_once(':')?;
    let line_no: u32 = line_part.trim().parse().ok()?;
    // After the line number comes either the column or the message.
    match after_line.split_once(':') {
        Some((maybe_col, message)) if maybe_col.trim().chars().all(|c| c.is_ascii_digit()) => {
            let col: u32 = maybe_col.trim().parse().ok()?;
            Some((file, Some(line_no), Some(col), message.trim()))
        }
        _ => Some((file, Some(line_no), None, after_line.trim())),
    }
}

// ---------------------------------------------------------------------------
// Biome, or the repo's own ESLint when configured (JavaScript)
// ---------------------------------------------------------------------------

/// Legacy (eslintrc-era) markers that only count in the project itself:
/// auto-discovery consumes them, so they never need a `--config` path.
const ESLINT_LEGACY: &[&str] = &[
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yaml",
    ".eslintrc.yml",
    ".eslintrc",
];

fn eslint_configured(root: &Path, order: &[Tier; 3]) -> Option<Option<PathBuf>> {
    // A flat config in any tier, or legacy markers / package.json config
    // in the project (consumed via auto-discovery).
    if let Some(path) = find_config(LintKind::Eslint, root, order) {
        return Some(Some(path));
    }
    for name in ESLINT_LEGACY {
        if root.join(name).is_file() {
            return Some(None);
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join("package.json"))
        && let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&text)
        && pkg.get("eslintConfig").is_some()
    {
        return Some(None);
    }
    None
}

pub(crate) fn run_js_lints(root: &Path, order: &[Tier; 3]) -> LintOutcome {
    match eslint_configured(root, order) {
        Some(tier_config) => run_eslint(root, tier_config),
        None => match run_biome(root, order) {
            Ok(findings) => LintOutcome {
                findings,
                gaps: Vec::new(),
                notes: Vec::new(),
            },
            Err(reason) => LintOutcome::gap("biome", reason),
        },
    }
}

pub(crate) fn run_biome(root: &Path, order: &[Tier; 3]) -> Result<Vec<LintFinding>, String> {
    crate::progress::linter("node", "biome");
    let bin = ensure_biome()?;
    let config = find_config(LintKind::Biome, root, order);
    let mut cmd = Command::new(&bin);
    biome_args(&mut cmd, &config);
    cmd.current_dir(root).arg(".");
    let out = run_command(cmd, LINT_TIMEOUT).map_err(|e| format!("biome failed: {e}"))?;
    if let Some(findings) = parse_biome(&out.stdout, root) {
        return Ok(findings);
    }
    // Biome 1.x reported via --diagnostic-format instead of --reporter.
    if mentions_unknown_flag(&out.stderr) {
        let mut retry = Command::new(&bin);
        retry
            .arg("lint")
            .arg("--diagnostic-format=json")
            .current_dir(root);
        if let Some(path) = &config
            && let Some(dir) = path.parent()
        {
            retry.arg("--config-path").arg(dir);
        }
        retry.arg(".");
        let again = run_command(retry, LINT_TIMEOUT).map_err(|e| format!("biome failed: {e}"))?;
        if let Some(findings) = parse_biome(&again.stdout, root) {
            return Ok(findings);
        }
    }
    Err(format!(
        "biome produced no parseable output: {}",
        stderr_tail(&out.stderr, 3)
    ))
}

fn biome_args(cmd: &mut Command, config: &Option<PathBuf>) {
    cmd.arg("lint")
        .arg("--reporter=json")
        .arg("--max-diagnostics=none");
    if let Some(path) = config
        && let Some(dir) = path.parent()
    {
        // The config path takes a directory across biome versions; the
        // file's parent always resolves the same biome.json(c).
        cmd.arg("--config-path").arg(dir);
    }
}

fn mentions_unknown_flag(stderr: &str) -> bool {
    stderr.contains("not expected in this context")
        || stderr.contains("unexpected argument")
        || stderr.contains("unrecognized")
}

fn parse_biome(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    // Biome may print several JSON documents (summary + diagnostics);
    // scan every line for the diagnostics payload.
    let mut out = Vec::new();
    let mut saw_payload = false;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // Also accept one pretty-printed document spanning all lines.
        let docs = if doc.get("diagnostics").is_some() {
            vec![doc]
        } else {
            continue;
        };
        for doc in docs {
            saw_payload = true;
            for diag in json_arr(&doc, "diagnostics") {
                let Some(message) = diag.get("message").and_then(deep_message) else {
                    continue;
                };
                let location = diag.get("location");
                // Biome 2 reports `path` as a string with `start.line`;
                // older shapes nest `{file}` and byte `span`s.
                let file = location
                    .and_then(|l| {
                        l.get("path").and_then(|p| {
                            p.as_str()
                                .map(str::to_string)
                                .or_else(|| json_str(p, "file").map(str::to_string))
                        })
                    })
                    .unwrap_or_default();
                let start = location.and_then(|l| l.get("start"));
                let mut line_no = start.and_then(|s| json_u32(s, "line"));
                let mut col = start.and_then(|s| json_u32(s, "column"));
                if line_no.is_none()
                    && let Some((l, c)) = location
                        .and_then(|l| l.get("span"))
                        .and_then(|s| s.as_array())
                        .and_then(|span| span.first()?.as_u64())
                        .and_then(|offset| span_to_line(root, &file, offset))
                {
                    line_no = Some(l);
                    col = Some(c);
                }
                let severity = diag
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .map(word_severity)
                    .unwrap_or(Severity::Warning);
                out.push(LintFinding {
                    file: relativize(root, &file),
                    line: line_no,
                    column: col,
                    message,
                    rules: diag
                        .get("category")
                        .and_then(|c| c.as_str())
                        .map(|c| vec![c.to_string()])
                        .unwrap_or_default(),
                    sources: vec!["biome".to_string()],
                    severity,
                });
            }
        }
    }
    // Pretty-printed single document fallback (a notice may precede it).
    if !saw_payload {
        if let Some(start) = text.find('{')
            && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text[start..])
            && doc.get("diagnostics").is_some()
        {
            return parse_biome(&serde_json::to_string(&doc).unwrap_or_default(), root);
        }
        return None;
    }
    Some(out)
}

/// Byte offset to 1-based (line, column), counted in chars.
fn span_to_line(root: &Path, file: &str, offset: u64) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(root.join(file)).ok()?;
    let offset: usize = offset.try_into().ok()?;
    let prefix = text.get(..offset.min(text.len()))?;
    let line = prefix.chars().filter(|c| *c == '\n').count() as u32 + 1;
    let col = prefix.chars().rev().take_while(|c| *c != '\n').count() as u32 + 1;
    Some((line, col))
}

/// The repo's own ESLint: its version and plugins belong to the project,
/// so it is resolved locally and never installed by depaudit.
fn resolve_eslint(root: &Path) -> Result<Command, String> {
    let local = root.join("node_modules").join(".bin").join("eslint");
    if local.is_file() {
        return Ok(Command::new(local));
    }
    #[cfg(windows)]
    {
        let cmd = local.with_extension("cmd");
        if cmd.is_file() {
            return Ok(Command::new(cmd));
        }
    }
    // `--no-install`/`exec` never download: a missing eslint is a gap.
    if find_tool("npx").is_some() {
        let mut cmd = Command::new("npx");
        cmd.args(["--no-install", "eslint"]);
        return Ok(cmd);
    }
    if find_tool("pnpm").is_some() {
        let mut cmd = Command::new("pnpm");
        cmd.args(["exec", "eslint"]);
        return Ok(cmd);
    }
    Err("eslint is configured but not installed and neither npx nor pnpm is available; run your package manager's install in the project (depaudit never installs project dependencies)".to_string())
}

fn run_eslint(root: &Path, tier_config: Option<PathBuf>) -> LintOutcome {
    crate::progress::linter("node", "eslint");
    let mut cmd = match resolve_eslint(root) {
        Ok(cmd) => cmd,
        Err(reason) => return LintOutcome::gap("eslint", reason),
    };
    cmd.arg("--format").arg("json").current_dir(root);
    if let Some(config) = tier_config {
        cmd.arg("--config").arg(&config);
    }
    cmd.arg(".");
    let out = match run_command(cmd, LINT_TIMEOUT) {
        Ok(out) => out,
        Err(e) => return LintOutcome::gap("eslint", format!("eslint failed: {e}")),
    };
    match parse_eslint(&out.stdout, root) {
        Some(findings) => LintOutcome {
            findings,
            gaps: Vec::new(),
            notes: Vec::new(),
        },
        None => LintOutcome::gap(
            "eslint",
            format!(
                "eslint produced no parseable output: {}",
                stderr_tail(&out.stderr, 3)
            ),
        ),
    }
}

fn parse_eslint(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    let files: Vec<serde_json::Value> = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    for file in &files {
        let path = json_str(file, "filePath").unwrap_or("");
        for msg in json_arr(file, "messages") {
            let message = json_str(msg, "message").unwrap_or("").to_string();
            if message.is_empty() {
                continue;
            }
            let fatal = msg.get("fatal").and_then(|f| f.as_bool()) == Some(true);
            let severity = match msg.get("severity").and_then(|s| s.as_u64()) {
                Some(2) => Severity::Error,
                _ => Severity::Warning,
            };
            out.push(LintFinding {
                file: relativize(root, path),
                line: json_u32(msg, "line"),
                column: json_u32(msg, "column"),
                message,
                rules: json_str(msg, "ruleId")
                    .map(|r| vec![r.to_string()])
                    .unwrap_or_default(),
                sources: vec!["eslint".to_string()],
                severity: if fatal { Severity::Error } else { severity },
            });
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Kotlin sources, ktlint, detekt (Android)
// ---------------------------------------------------------------------------

/// Kotlin sources under the root, skipping dependency and build-output
/// dirs the same way project discovery does.
fn kotlin_sources(root: &Path) -> Vec<PathBuf> {
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
                if path.is_symlink() || crate::discover::skip_dir_name(&name) {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".kt") || name.ends_with(".kts") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

pub(crate) fn run_ktlint(root: &Path, order: &[Tier; 3]) -> Result<Vec<LintFinding>, String> {
    crate::progress::linter("android", "ktlint");
    let sources = kotlin_sources(root);
    if sources.is_empty() {
        return Ok(Vec::new());
    }
    let bin = ensure_ktlint()?;
    let config = find_config(LintKind::KtLint, root, order);
    let mut out = Vec::new();
    // Windows command lines cap at 32K; chunk regardless of platform.
    for chunk in sources.chunks(500) {
        let mut cmd = Command::new(&bin);
        cmd.arg("--reporter=json").current_dir(root);
        // A project .editorconfig is consumed via auto-discovery; the flag
        // only overrides with a preferred-tier config.
        if let Some(path) = &config
            && path.parent() != Some(root)
        {
            cmd.arg("--editorconfig").arg(path);
        }
        for file in chunk {
            cmd.arg(file);
        }
        let result = run_command(cmd, LINT_TIMEOUT).map_err(|e| format!("ktlint failed: {e}"))?;
        match parse_ktlint(&result.stdout, root) {
            Some(findings) => out.extend(findings),
            None => {
                return Err(format!(
                    "ktlint produced no parseable output: {}",
                    stderr_tail(&result.stderr, 3)
                ));
            }
        }
    }
    Ok(out)
}

fn parse_ktlint(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    let files: Vec<serde_json::Value> = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    for file in &files {
        let path = json_str(file, "file").unwrap_or("");
        for err in json_arr(file, "errors") {
            let message = json_str(err, "message").unwrap_or("").to_string();
            if message.is_empty() {
                continue;
            }
            out.push(LintFinding {
                file: relativize(root, path),
                line: json_u32(err, "line"),
                column: json_u32(err, "column"),
                message,
                rules: json_str(err, "rule")
                    .map(|r| vec![r.to_string()])
                    .unwrap_or_default(),
                sources: vec!["ktlint".to_string()],
                severity: Severity::Warning,
            });
        }
    }
    Some(out)
}

/// Detekt only runs when a config exists in some tier: default detekt on
/// a repo that never adopted it is noise, not signal.
pub(crate) fn run_detekt(root: &Path, order: &[Tier; 3]) -> Result<Vec<LintFinding>, String> {
    let Some(config) = find_config(LintKind::Detekt, root, order) else {
        return Ok(Vec::new());
    };
    let sources = kotlin_sources(root);
    if sources.is_empty() {
        return Ok(Vec::new());
    }
    let bin = ensure_detekt()?;
    crate::progress::note("depaudit: running detekt...");
    let work = tempfile::tempdir().map_err(|e| format!("detekt failed: temp dir ({e})"))?;
    let mut out = Vec::new();
    for (i, chunk) in sources.chunks(500).enumerate() {
        let report = work.path().join(format!("detekt-{i}.json"));
        let inputs: Vec<String> = chunk
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let mut cmd = Command::new(&bin);
        cmd.arg("--input")
            .arg(inputs.join(","))
            .arg("--report")
            .arg(format!("json:{}", report.display()))
            .arg("--config")
            .arg(&config)
            .current_dir(root);
        let result =
            run_command(cmd, SLOW_LINT_TIMEOUT).map_err(|e| format!("detekt failed: {e}"))?;
        let text = std::fs::read_to_string(&report).map_err(|_| {
            format!(
                "detekt produced no report: {}",
                stderr_tail(&result.stderr, 3)
            )
        })?;
        match parse_detekt(&text, root) {
            Some(findings) => out.extend(findings),
            None => {
                return Err(format!(
                    "detekt produced no parseable report: {}",
                    stderr_tail(&result.stderr, 3)
                ));
            }
        }
    }
    Ok(out)
}

fn parse_detekt(stdout: &str, root: &Path) -> Option<Vec<LintFinding>> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    doc.get("findings")?;
    let mut out = Vec::new();
    for finding in json_arr(&doc, "findings") {
        let message = match json_str(finding, "message") {
            Some(text) => text.to_string(),
            None => finding
                .get("message")
                .and_then(deep_message)
                .unwrap_or_default(),
        };
        if message.is_empty() {
            continue;
        }
        let entity = finding.get("entity");
        let location = entity.and_then(|e| e.get("location"));
        let path = location
            .and_then(|l| l.get("source"))
            .and_then(|s| json_str(s, "path"))
            .unwrap_or("");
        let text_pos = location.and_then(|l| l.get("text"));
        let rule = json_str(finding, "rule")
            .or_else(|| json_str(finding, "category"))
            .unwrap_or("");
        out.push(LintFinding {
            file: relativize(root, path),
            line: text_pos
                .and_then(|t| json_u32(t, "startLine"))
                .or_else(|| text_pos.and_then(|t| json_u32(t, "line"))),
            column: text_pos.and_then(|t| json_u32(t, "startColumn")),
            message,
            rules: if !rule.is_empty() {
                vec![rule.to_string()]
            } else {
                Default::default()
            },
            sources: vec!["detekt".to_string()],
            severity: finding
                .get("severity")
                .and_then(|s| s.as_str())
                .map(word_severity)
                .unwrap_or(Severity::Warning),
        });
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Android lint via the Gradle wrapper
// ---------------------------------------------------------------------------

/// Gradle wrapper state for the lint gate.
pub(crate) enum GradleGate {
    /// Run lint: wrapper is current, or its state is unknown (offline, ...).
    Run(Option<String>),
    /// Skip lint: a newer Gradle exists — updating first avoids downloading
    /// two distributions.
    Skip(String),
}

/// Decide whether `./gradlew lint` may run. When the wrapper is older than
/// the latest stable Gradle, lint is skipped with an update-first message:
/// running now would download the old distribution, then the new one after
/// the update. Unknown states (offline, unparseable wrapper) run and let
/// Gradle itself fail fast with its own error.
pub(crate) fn gradle_gate(ctx: &Ctx, root: &Path) -> GradleGate {
    let props = root.join("gradle/wrapper/gradle-wrapper.properties");
    let current = std::fs::read_to_string(&props)
        .ok()
        .and_then(|text| crate::android::gradle_wrapper_version(&text));
    let Some(current) = current else {
        return GradleGate::Run(Some(
            "gradle wrapper version unknown; running lint anyway (update the wrapper first if it is old, to avoid downloading two Gradle distributions)".to_string(),
        ));
    };
    let latest = match crate::toolchains::tool_status(
        &ctx.cache,
        crate::toolchains::ToolId::Gradle,
        &current,
    ) {
        Ok(status) => status.latest,
        Err(_) => return GradleGate::Run(None),
    };
    if crate::version::compare(&current, &latest) == std::cmp::Ordering::Less {
        GradleGate::Skip(format!(
            "gradle lint skipped: gradle {current} -> {latest} available; update the wrapper (`./gradlew wrapper --gradle-version {latest}`) and re-run for lint results (skipped to avoid downloading two Gradle distributions)"
        ))
    } else {
        GradleGate::Run(None)
    }
}

pub(crate) fn run_gradle_lint(ctx: &Ctx, root: &Path) -> LintOutcome {
    match gradle_gate(ctx, root) {
        GradleGate::Skip(note) => LintOutcome {
            findings: Vec::new(),
            gaps: Vec::new(),
            notes: vec![note],
        },
        GradleGate::Run(note) => {
            let mut outcome = LintOutcome::default();
            if let Some(note) = note {
                outcome.notes.push(note);
            }
            match gradle_lint_inner(root) {
                Ok(findings) => outcome.findings = findings,
                Err(reason) => outcome.gaps.push(Gap {
                    name: "gradle lint".to_string(),
                    check: GapCheck::Lint,
                    reason,
                }),
            }
            outcome
        }
    }
}

fn gradle_wrapper(root: &Path) -> Option<Command> {
    #[cfg(windows)]
    {
        let bat = root.join("gradlew.bat");
        if bat.is_file() {
            let mut cmd = Command::new(bat);
            cmd.current_dir(root);
            return Some(cmd);
        }
        return None;
    }
    #[cfg(not(windows))]
    {
        let script = root.join("gradlew");
        if !script.is_file() {
            return None;
        }
        let mut cmd = Command::new(&script);
        // A wrapper without its executable bit still runs via `sh`.
        if !is_executable(&script) {
            cmd = Command::new("sh");
            cmd.arg(&script);
        }
        cmd.current_dir(root);
        Some(cmd)
    }
}

#[cfg(not(windows))]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn gradle_lint_inner(root: &Path) -> Result<Vec<LintFinding>, String> {
    let Some(mut cmd) = gradle_wrapper(root) else {
        return Err("no gradle wrapper found; gradle lint needs ./gradlew".to_string());
    };
    crate::progress::note(
        "depaudit: running ./gradlew lint (first run downloads Gradle and dependencies)...",
    );
    cmd.arg("lint").arg("--console=plain");
    let out = run_command(cmd, GRADLE_TIMEOUT).map_err(|e| format!("gradle lint failed: {e}"))?;
    let mut findings = Vec::new();
    for report in find_lint_reports(root) {
        let Ok(text) = std::fs::read_to_string(&report) else {
            continue;
        };
        findings.extend(parse_lint_xml(&text, root));
    }
    if findings.is_empty() && !out.stderr.trim().is_empty() && lint_failed(&out.stderr) {
        return Err(format!(
            "gradle lint failed: {}",
            stderr_tail(&out.stderr, 3)
        ));
    }
    Ok(findings)
}

/// Whether stderr shows a build failure rather than a findings-bearing run.
fn lint_failed(stderr: &str) -> bool {
    stderr.contains("FAILED") || stderr.contains("BUILD FAILED") || stderr.contains("Could not ")
}

fn find_lint_reports(root: &Path) -> Vec<PathBuf> {
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
                if path.is_symlink() || crate::discover::skip_dir_name(&name) {
                    continue;
                }
                stack.push(path);
            } else if name.starts_with("lint-results") && name.ends_with(".xml") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Parse an Android lint XML report with the same regex approach as the
/// Maven/POM readers: first `<location>` per issue wins.
fn parse_lint_xml(text: &str, root: &Path) -> Vec<LintFinding> {
    let mut out = Vec::new();
    // Split into issue blocks without an XML dependency.
    let mut rest = text;
    while let Some(start) = rest.find("<issue ") {
        rest = &rest[start..];
        let block = match rest.find("</issue>") {
            Some(end) => &rest[..end],
            None => rest,
        };
        let id = attr(block, "id").unwrap_or_default();
        let severity = attr(block, "severity")
            .map(|s| word_severity(&s))
            .unwrap_or(Severity::Warning);
        let message = attr(block, "message").unwrap_or_default();
        // First location carries the primary file/line.
        let (file, line, col) = match block.find("<location ") {
            Some(at) => {
                let loc = &block[at..];
                (
                    attr(loc, "file").unwrap_or_default(),
                    attr(loc, "line").and_then(|l| l.parse::<u32>().ok()),
                    attr(loc, "column").and_then(|c| c.parse::<u32>().ok()),
                )
            }
            None => (String::new(), None, None),
        };
        if !message.is_empty() {
            out.push(LintFinding {
                file: relativize(root, &file),
                line,
                column: col,
                message,
                rules: if !id.is_empty() {
                    vec![id]
                } else {
                    Default::default()
                },
                sources: vec!["gradle lint".to_string()],
                severity,
            });
        }
        rest = &block[block.len().min(8)..];
        if rest.len() < 16 {
            break;
        }
    }
    out
}

/// One double- or single-quoted XML attribute, entity-unescaped.
fn attr(block: &str, name: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!("{name}={quote}");
        if let Some(start) = block.find(&needle) {
            let after = &block[start + needle.len()..];
            if let Some(end) = after.find(quote) {
                return Some(xml_unescape(&after[..end]));
            }
        }
    }
    None
}

fn xml_unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

// ---------------------------------------------------------------------------
// Per-ecosystem entry points
// ---------------------------------------------------------------------------

pub fn audit_python(ctx: &Ctx, root: &Path, vulns: &[FoundVuln]) -> LintOutcome {
    let mut outcome = LintOutcome::default();
    match run_ruff(root, &ctx.lint_config_order) {
        Ok(findings) => outcome.findings = findings,
        Err(reason) => outcome.gaps.push(Gap {
            name: "ruff".to_string(),
            check: GapCheck::Lint,
            reason,
        }),
    }
    let (findings, mut notes) = finalize(outcome.findings, vulns);
    outcome.findings = findings;
    outcome.notes.append(&mut notes);
    outcome
}

pub fn audit_node(ctx: &Ctx, root: &Path, vulns: &[FoundVuln]) -> LintOutcome {
    let mut outcome = run_js_lints(root, &ctx.lint_config_order);
    let (findings, mut notes) = finalize(outcome.findings, vulns);
    outcome.findings = findings;
    outcome.notes.append(&mut notes);
    outcome
}

pub fn audit_rust(_ctx: &Ctx, root: &Path, vulns: &[FoundVuln]) -> LintOutcome {
    let mut outcome = LintOutcome::default();
    match run_clippy(root) {
        Ok(findings) => outcome.findings = findings,
        Err(reason) => outcome.gaps.push(Gap {
            name: "clippy".to_string(),
            check: GapCheck::Lint,
            reason,
        }),
    }
    let (findings, mut notes) = finalize(outcome.findings, vulns);
    outcome.findings = findings;
    outcome.notes.append(&mut notes);
    outcome
}

pub fn audit_go(ctx: &Ctx, root: &Path, vulns: &[FoundVuln]) -> LintOutcome {
    let mut outcome = run_go_lints(root, &ctx.lint_config_order);
    let (findings, mut notes) = finalize(outcome.findings, vulns);
    outcome.findings = findings;
    outcome.notes.append(&mut notes);
    outcome
}

pub fn audit_android(ctx: &Ctx, root: &Path, vulns: &[FoundVuln]) -> LintOutcome {
    let mut outcome = run_gradle_lint(ctx, root);
    match run_ktlint(root, &ctx.lint_config_order) {
        Ok(findings) => outcome.findings.extend(findings),
        Err(reason) => outcome.gaps.push(Gap {
            name: "ktlint".to_string(),
            check: GapCheck::Lint,
            reason,
        }),
    }
    match run_detekt(root, &ctx.lint_config_order) {
        Ok(findings) => outcome.findings.extend(findings),
        Err(reason) => outcome.gaps.push(Gap {
            name: "detekt".to_string(),
            check: GapCheck::Lint,
            reason,
        }),
    }
    let (findings, mut notes) = finalize(outcome.findings, vulns);
    outcome.findings = findings;
    outcome.notes.append(&mut notes);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(tool: &str, file: &str, line: u32, message: &str) -> LintFinding {
        LintFinding {
            file: file.to_string(),
            line: Some(line),
            column: Some(1),
            message: message.to_string(),
            rules: vec![format!("{tool}-rule")],
            sources: vec![tool.to_string()],
            severity: Severity::Warning,
        }
    }

    #[test]
    fn order_parsing_validates_tiers() {
        let names = ["project", "depaudit", "global"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_order(&names).unwrap(),
            [Tier::Project, Tier::Depaudit, Tier::Global]
        );
        let flipped = ["depaudit", "global", "project"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_order(&flipped).unwrap(),
            [Tier::Depaudit, Tier::Global, Tier::Project]
        );
        for bad in [
            vec!["project", "project", "global"],
            vec!["project", "global"],
            vec!["project", "depaudit", "global", "global"],
            vec!["project", "home", "global"],
        ] {
            let names: Vec<String> = bad.into_iter().map(str::to_string).collect();
            assert!(parse_order(&names).is_err(), "{names:?}");
        }
    }

    #[test]
    fn config_discovery_honors_order() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        let user = dir.path().join("user");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        std::fs::write(proj.join("ruff.toml"), "[lint]\n").unwrap();
        std::fs::write(user.join("ruff.toml"), "[lint]\n").unwrap();
        // Project tier resolves against the passed root either way.
        assert_eq!(
            find_config(LintKind::Ruff, &proj, &DEFAULT_ORDER),
            Some(proj.join("ruff.toml"))
        );
        // A bare pyproject.toml without [tool.ruff] does not count.
        let bare = dir.path().join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::write(bare.join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        // (Cannot assert None: the real ~/.config and /etc tiers may hold a
        // ruff config on any machine. Assert the project file is skipped by
        // checking the returned path is never the bare one.)
        if let Some(found) = find_config(LintKind::Ruff, &bare, &DEFAULT_ORDER) {
            assert_ne!(found, bare.join("pyproject.toml"));
        }
        std::fs::write(
            bare.join("pyproject.toml"),
            "[project]\nname = \"x\"\n[tool.ruff]\nline-length = 100\n",
        )
        .unwrap();
        assert_eq!(
            find_config(LintKind::Ruff, &bare, &DEFAULT_ORDER),
            Some(bare.join("pyproject.toml"))
        );
    }

    #[test]
    fn parses_ruff_json() {
        let root = Path::new("/proj");
        let findings = parse_ruff(
            r#"[{"code":"F401","message":"`os` imported but unused","filename":"src/a.py","location":{"row":12,"column":8}},{"code":"E999","message":"SyntaxError: bad","filename":"src/b.py","location":{"row":1,"column":1}}]"#,
            root,
        )
        .unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].file, "src/a.py");
        assert_eq!(findings[0].line, Some(12));
        assert_eq!(findings[0].rules, vec!["F401".to_string()]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[1].severity, Severity::Error);
        assert!(parse_ruff("", root).is_none());
        assert!(parse_ruff("not json", root).is_none());
    }

    #[test]
    fn parses_clippy_lines() {
        let root = Path::new("/proj");
        let line = r#"{"reason":"compiler-message","message":{"message":"this could be `const`","code":{"code":"clippy::missing_const_for_fn"},"level":"warning","spans":[{"file_name":"/proj/src/main.rs","line_start":7,"column_start":1,"is_primary":true}]}}"#;
        let foreign = r#"{"reason":"compiler-message","message":{"message":"in a dependency","level":"warning","spans":[{"file_name":"/root/.cargo/registry/src/x.rs","line_start":1,"is_primary":true}]}}"#;
        let findings = parse_clippy(&format!("{line}\n{foreign}\n"), root).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "src/main.rs");
        assert_eq!(findings[0].line, Some(7));
        assert_eq!(
            findings[0].rules,
            vec!["clippy::missing_const_for_fn".to_string()]
        );
        assert!(parse_clippy("cargo failed loudly\n", root).is_none());
    }

    #[test]
    fn parses_golangci_and_vet() {
        let root = Path::new("/proj");
        let findings = parse_golangci(
            r#"{"Issues":[{"Text":"unused variable x","FromLinter":"unused","Pos":{"Filename":"main.go","Line":3,"Column":6}}]}"#,
            root,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "main.go");
        assert_eq!(findings[0].rules, vec!["unused".to_string()]);
        // A human summary after the JSON payload is tolerated.
        let findings = parse_golangci("{\"Issues\":[]}\n1 issues:\n* govet: 1\n", root).unwrap();
        assert!(findings.is_empty());
        assert!(parse_golangci("", root).is_none());
        assert!(parse_golangci("oops", root).is_none());

        let findings =
            parse_vet("", "# example.com/m\nm/main.go:9:3: missing return\n", root).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "m/main.go");
        assert_eq!(findings[0].line, Some(9));
        assert_eq!(findings[0].column, Some(3));
        // Clean vet is silent on both streams.
        assert_eq!(parse_vet("", "", root).unwrap(), Vec::new());
        // Usage text alone is unparseable.
        assert!(parse_vet("usage: go vet flags", "", root).is_none());
    }

    #[test]
    fn parses_biome_and_eslint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "let x = 1;\nlet y = 2;\n").unwrap();
        // Biome 2 shape: string path, start line/column.
        let findings = parse_biome(
            r#"{"diagnostics":[{"category":"lint/style/useConst","severity":"warning","message":"Use const.","location":{"path":"a.js","start":{"line":1,"column":1}}}]}"#,
            dir.path(),
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "a.js");
        assert_eq!(findings[0].line, Some(1));
        assert_eq!(findings[0].column, Some(1));
        assert_eq!(findings[0].rules, vec!["lint/style/useConst".to_string()]);
        // Older span shape still resolves via the file bytes.
        let findings = parse_biome(
            r#"{"diagnostics":[{"category":"lint/correctness/noUnusedVariables","severity":"warning","message":{"content":"unused"},"location":{"path":{"file":"a.js"},"span":[14,15]}}]}"#,
            dir.path(),
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, Some(2));
        assert!(parse_biome("", dir.path()).is_none());

        let findings = parse_eslint(
            r#"[{"filePath":"/proj/a.js","messages":[{"ruleId":"no-unused-vars","severity":2,"message":"'y' is defined but never used.","line":2,"column":5}]}]"#,
            Path::new("/proj"),
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "a.js");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(parse_eslint("", Path::new("/proj")).is_none());
    }

    #[test]
    fn parses_ktlint_detekt_and_gradle_xml() {
        let root = Path::new("/proj");
        let findings = parse_ktlint(
            r#"[{"file":"src/A.kt","errors":[{"line":3,"column":1,"message":"Missing newline","rule":"final-newline"}]}]"#,
            root,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "src/A.kt");
        assert_eq!(findings[0].rules, vec!["final-newline".to_string()]);
        assert!(parse_ktlint("", root).is_none());

        let findings = parse_detekt(
            r#"{"findings":[{"category":"style","message":"Too generic exception","severity":"warning","rule":"TooGenericExceptionCaught","entity":{"location":{"source":{"path":"/proj/src/A.kt"},"text":{"startLine":9,"startColumn":11}}}}]}"#,
            root,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "src/A.kt");
        assert_eq!(findings[0].line, Some(9));
        assert!(parse_detekt("{}", root).is_none());

        let findings = parse_lint_xml(
            r#"<issues><issue id="HardcodedText" severity="Warning" message="Hardcoded &quot;text&quot;"><location file="/proj/app/src/main/res/a.xml" line="4" column="8"/></issue></issues>"#,
            root,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "app/src/main/res/a.xml");
        assert_eq!(findings[0].message, "Hardcoded \"text\"".to_string());
        assert_eq!(findings[0].rules, vec!["HardcodedText".to_string()]);
    }

    #[test]
    fn finalize_merges_dupes_and_suppresses_vulns() {
        // Same file/line/message from two linters merges, keeping the max
        // severity and every source and rule.
        let mut second = finding("detekt", "a.kt", 3, "Missing  NEWLINE");
        second.severity = Severity::Error;
        let findings = vec![finding("ktlint", "a.kt", 3, "missing newline"), second];
        let (merged, notes) = finalize(findings, &[]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].sources,
            vec!["detekt".to_string(), "ktlint".to_string()]
        );
        assert_eq!(merged[0].rules.len(), 2);
        assert_eq!(merged[0].severity, Severity::Error);
        assert_eq!(notes, vec!["1 duplicate lint finding merged".to_string()]);

        // Different messages on the same line stay separate.
        let findings = vec![
            finding("ktlint", "a.kt", 3, "missing newline"),
            finding("detekt", "a.kt", 3, "wildcard import"),
        ];
        let (merged, _) = finalize(findings, &[]);
        assert_eq!(merged.len(), 2);

        // A lint finding naming an already-reported CVE is suppressed.
        let vulns = vec![FoundVuln {
            name: "lib".to_string(),
            version: "1.0".to_string(),
            id: "GHSA-abcd-efgh-ijkl".to_string(),
            aliases: vec!["CVE-2024-1234".to_string()],
            summary: String::new(),
            severity: None,
            fixed: None,
            alternatives: Vec::new(),
        }];
        let findings = vec![
            finding("detekt", "a.kt", 5, "uses lib with CVE-2024-1234"),
            finding("ktlint", "a.kt", 6, "missing newline"),
        ];
        let (merged, notes) = finalize(findings, &vulns);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].line, Some(6));
        assert_eq!(
            notes,
            vec!["1 lint finding suppressed (already reported as a vulnerability)".to_string()]
        );
    }

    #[test]
    fn extracts_security_ids() {
        assert_eq!(
            security_ids("hit CVE-2024-1234 and ghsa-abcd-efgh-ijkl twice CVE-2024-1234"),
            vec![
                "CVE-2024-1234".to_string(),
                "GHSA-ABCD-EFGH-IJKL".to_string()
            ]
        );
        assert!(security_ids("nothing here").is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn large_output_does_not_deadlock() {
        // 200KB on each pipe: far past the ~64K buffer that deadlocks
        // exit-polling without concurrent reads.
        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            "head -c 200000 /dev/zero | tr '\\0' a; head -c 200000 /dev/zero | tr '\\0' b >&2",
        ]);
        let out = run_command(cmd, Duration::from_secs(30)).unwrap();
        assert_eq!(out.stdout.len(), 200000);
        assert_eq!(out.stderr.len(), 200000);
        assert!(out.success);
    }

    #[test]
    fn relativizes_paths() {
        let root = Path::new("/proj");
        assert_eq!(relativize(root, "/proj/src/a.py"), "src/a.py");
        assert_eq!(relativize(root, "./src/a.py"), "src/a.py");
        assert_eq!(relativize(root, "src/a.py"), "src/a.py");
        assert_eq!(relativize(root, "/elsewhere/a.py"), "/elsewhere/a.py");
    }

    #[test]
    fn gradle_gate_skips_outdated_wrappers() {
        use crate::cache::Cache;
        let dir = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("gradle/wrapper");
        std::fs::create_dir_all(&wrapper).unwrap();
        // Pretend the latest Gradle is 9.0 by planting the toolchain cache.
        let ctx = Ctx {
            verbose: false,
            deep: false,
            check_outdated: true,
            check_vulns: true,
            cache: std::sync::Arc::new(Cache::for_test()),
            android_sdk_cap: None,
            lint: true,
            lint_config_order: DEFAULT_ORDER,
            check_notices: false,
            license_policy: crate::licenses::Policy::default(),
        };
        ctx.cache.set(
            &format!("v1:tool:{:?}", crate::toolchains::ToolId::Gradle),
            &"9.0.0".to_string(),
        );
        std::fs::write(
            wrapper.join("gradle-wrapper.properties"),
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.1-bin.zip\n",
        )
        .unwrap();
        match gradle_gate(&ctx, dir.path()) {
            GradleGate::Skip(note) => assert!(note.contains("8.1 -> 9.0.0"), "{note}"),
            GradleGate::Run(_) => panic!("outdated wrapper should skip"),
        }
        std::fs::write(
            wrapper.join("gradle-wrapper.properties"),
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.0-bin.zip\n",
        )
        .unwrap();
        assert!(matches!(
            gradle_gate(&ctx, dir.path()),
            GradleGate::Run(None)
        ));
    }
}
