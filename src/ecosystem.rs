//! Shared types for ecosystem checkers and the checker registry.
//!
//! Every checker is pure Rust: [`EcosystemChecker::enumerate`] builds the
//! dependency inventory from project files, [`EcosystemChecker::fetch_latest`]
//! resolves the newest release from the ecosystem's registry, and the default
//! [`EcosystemChecker::check`] adds vulnerability data from OSV. No external
//! tools or toolchains are required.

use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::cache::{Cache, TTL_FOREVER_SECS, TTL_VULNS_SECS};
use crate::dates;
use crate::osv::{self, FoundVuln};
use crate::toolchains::{self, ToolPin};

/// Cache key for one published version's release date. Release dates
/// never change, so these entries live forever and are never evicted.
pub(crate) fn release_date_key(eco: &str, name: &str, version: &str) -> String {
    format!("v1:released:{eco}:{name}:{version}")
}

/// Last-known release date of one published version, if ever fetched.
pub(crate) fn cached_release_date(
    ctx: &Ctx,
    eco: &str,
    name: &str,
    version: &str,
) -> Option<String> {
    ctx.cache
        .get(&release_date_key(eco, name, version), TTL_FOREVER_SECS)
}

/// Fill the date fields of one line; days only when both dates are known.
fn fill_dates(
    current_released: &mut Option<String>,
    latest_released: &mut Option<String>,
    days_behind: &mut Option<i64>,
    current: Option<String>,
    latest: Option<String>,
) {
    if let (Some(a), Some(b)) = (current.as_deref(), latest.as_deref()) {
        *days_behind = dates::days_between(a, b);
    }
    *current_released = current;
    *latest_released = latest;
}

/// One dependency found in a project.
#[derive(Debug, Clone)]
pub struct Dep {
    /// Registry lookup name (e.g. `requests`, `lodash`, `serde`).
    pub name: String,
    /// Display name; may carry extra coordinates (e.g. `group:name` for Maven).
    pub display: String,
    /// Known current version (installed, locked or pinned). `None` when only
    /// an unpinned requirement is declared.
    pub version: Option<String>,
    /// Declared requirement/spec, e.g. `^2.0.0`, `>=1.4`, `~=2.2`.
    pub spec: Option<String>,
    /// Direct dependency (`false` = transitive/indirect).
    pub direct: bool,
    /// Extra info, e.g. dependency kind.
    pub detail: Option<String>,
    /// OSV package name override (Maven needs `group:name`, not just `name`).
    pub osv_name: String,
}

impl Dep {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            display: name.clone(),
            osv_name: name.clone(),
            name,
            version: None,
            spec: None,
            direct: true,
            detail: None,
        }
    }
}

/// One outdated dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutdatedDep {
    pub name: String,
    pub current: String,
    pub latest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Set when an even newer release exists but is unusable (e.g. an
    /// Android library needing a newer compileSdk than the project has).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<BlockedUpdate>,
    /// Lookup-failure reason when `latest` comes from stale cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<String>,
    /// Release dates (`YYYY-MM-DD`) of the two versions, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_released: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_released: Option<String>,
    /// Days between the two releases, when both dates are known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_behind: Option<i64>,
}

/// A newer release that exists but cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct BlockedUpdate {
    pub latest: String,
    pub min_compile_sdk: u32,
}

/// An update that is entirely unavailable: the current version is already
/// the newest usable one, but a newer release exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedDep {
    pub name: String,
    pub current: String,
    pub latest: String,
    pub min_compile_sdk: u32,
    /// Release dates (`YYYY-MM-DD`) of the two versions, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_released: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_released: Option<String>,
    /// Days between the two releases, when both dates are known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_behind: Option<i64>,
}

/// Newest release info from the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LatestInfo {
    /// Newest usable release (honoring caps such as compileSdk).
    pub latest: String,
    /// Newer-but-unusable release, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<BlockedUpdate>,
    /// Set when usability could not be verified (transient failure): `latest`
    /// is the newest release, assumed usable. Never cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unverified: Option<String>,
}

impl LatestInfo {
    pub fn simple(latest: String) -> Self {
        Self {
            latest,
            blocked: None,
            unverified: None,
        }
    }
}

/// Outcome status of a single ecosystem check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The check ran to completion (possibly with findings).
    Ok,
    /// Nothing to check (no dependencies found).
    Skipped,
    /// The check failed with an error.
    Error,
}

/// One thing that could not be checked, with the reason why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub name: String,
    pub check: GapCheck,
    pub reason: String,
}

/// What kind of dependency-metadata notice this is. Grows with each new
/// analysis (ghost dependencies, toolchain drift, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NoticeCheck {
    Licenses,
    Yanked,
    Eol,
    Bloat,
    #[serde(rename = "license-change")]
    LicenseChange,
    Ghost,
    Drift,
    Secrets,
    Crypto,
    #[serde(rename = "dead-code")]
    DeadCode,
}

/// A dependency-metadata finding: license violation, yanked pin,
/// end-of-life framework. Dependency-level (name) or source-level
/// (file/line) depending on the analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    pub check: NoticeCheck,
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GapCheck {
    Outdated,
    Vulns,
    Lint,
}

/// One notice per package locked at more than one version: every
/// extra copy is installed (and, for compiled languages, built and
/// shipped) separately. Versions arrive sorted; callers dedup.
pub(crate) fn bloat_notices(locked: &HashMap<String, Vec<String>>) -> Vec<Notice> {
    let mut names: Vec<&String> = locked
        .iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, _)| name)
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let versions = &locked[name];
            Notice {
                check: NoticeCheck::Bloat,
                name: name.clone(),
                message: format!(
                    "{} locked versions: {}",
                    versions.len(),
                    versions.join(", ")
                ),
                file: None,
                line: None,
            }
        })
        .collect()
}

/// Dependency inventory plus the dependencies that could not even be
/// inventoried (path-only deps, dynamic versions, ...) and notes about
/// dependencies deliberately skipped (first-party workspace specs, ...).
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub deps: Vec<Dep>,
    pub gaps: Vec<Gap>,
    pub notes: Vec<String>,
}

/// Cached value plus the lookup-failure reason when it came from stale
/// cache (`None` = fresh from the registry).
pub type Fresh<T> = (T, Option<String>);

/// Version-resolution outcome plus stale reason when the version came
/// from stale cache.
type Resolved = (Result<Option<String>, String>, Option<String>);

/// Enriched dependency: (dep, resolve outcome, latest lookup or skip-marker).
type Enriched = (
    Dep,
    Option<Resolved>,
    Option<Result<Fresh<LatestInfo>, String>>,
);

/// Full outcome of auditing one ecosystem in a project directory.
#[derive(Debug, Clone, Serialize)]
pub struct CheckOutcome {
    /// Stable id: python, node, rust, go, android.
    pub id: &'static str,
    /// Human display name.
    pub display: &'static str,
    pub status: Status,
    pub outdated: Vec<OutdatedDep>,
    /// Updates that exist but cannot be used (newer SDK needed, ...).
    #[serde(default)]
    pub blocked: Vec<BlockedDep>,
    pub vulnerabilities: Vec<FoundVuln>,
    /// Outdated language/toolchain pins (gradle wrapper, node engines, ...).
    #[serde(default)]
    pub tools: Vec<OutdatedDep>,
    /// Things that could not be checked, with reasons.
    #[serde(default)]
    pub gaps: Vec<Gap>,
    /// Linter findings for the project's own sources.
    #[serde(default)]
    pub lint: Vec<crate::lint::LintFinding>,
    /// Dependency-metadata notices: licenses, yanked pins, EOL frameworks.
    #[serde(default)]
    pub notices: Vec<Notice>,
    /// Shell command that applies the outdated updates, if the ecosystem
    /// has a stock updater.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_command: Option<String>,
    /// Total number of dependencies examined.
    pub checked: usize,
    /// Warnings / skip reason / error text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CheckOutcome {
    pub fn error(id: &'static str, display: &'static str, err: impl Into<String>) -> Self {
        Self {
            id,
            display,
            status: Status::Error,
            outdated: Vec::new(),
            blocked: Vec::new(),
            vulnerabilities: Vec::new(),
            tools: Vec::new(),
            gaps: Vec::new(),
            lint: Vec::new(),
            notices: Vec::new(),
            update_command: None,
            checked: 0,
            message: Some(err.into()),
        }
    }
}

/// Context shared by all checkers: user policy knobs.
#[derive(Clone)]
pub struct Ctx {
    pub verbose: bool,
    /// Include transitive/indirect dependencies in the outdated check.
    /// (Vulnerability checks always cover every known dependency.)
    pub deep: bool,
    pub check_outdated: bool,
    pub check_vulns: bool,
    pub cache: Arc<Cache>,
    /// Newest Android compileSdk the project can build against: newer
    /// library releases that require a higher one are reported as blocked
    /// rather than outdated. `None` disables SDK gating.
    pub android_sdk_cap: Option<u32>,
    /// Run linters on the project's own sources.
    pub lint: bool,
    /// Config-file search order across the project / depaudit / global tiers.
    pub lint_config_order: [crate::lint::Tier; 3],
    /// Run dependency-metadata notices (licenses, yanked, EOL). Part of
    /// the full audit only: any `--*-only` flag restricts to its check.
    pub check_notices: bool,
    /// License policy from `[licenses] deny`.
    pub license_policy: crate::licenses::Policy,
}

/// Interface every language ecosystem implements.
pub trait EcosystemChecker: Sync {
    fn id(&self) -> &'static str;
    fn display(&self) -> &'static str;
    /// OSV ecosystem name: PyPI, npm, crates.io, Go, Maven.
    fn osv_ecosystem(&self) -> &'static str;
    /// Whether `root` looks like a project of this ecosystem (marker files).
    fn detect(&self, root: &Path) -> bool;
    /// Inventory the project's dependencies from its files, plus the
    /// dependencies that could not be inventoried and why.
    fn enumerate(&self, root: &Path) -> Result<Inventory, String>;
    /// Newest usable release from the registry, or the reason it cannot be
    /// determined (not published, private, network failure, ...). Usability
    /// honors policy caps (e.g. Android compileSdk); newer-but-unusable
    /// releases ride along in [`LatestInfo::blocked`].
    fn fetch_latest(&self, ctx: &Ctx, dep: &Dep) -> Result<LatestInfo, String>;
    /// Resolve an unpinned requirement to the version a fresh install would
    /// pick today (used for both checks when no installed/locked version is
    /// known). `Ok(None)` means unresolvable, `Err` carries the failure
    /// reason. The default cannot resolve.
    fn resolve_version(&self, _dep: &Dep) -> Result<Option<String>, String> {
        Ok(None)
    }
    /// Decide whether `dep` is outdated given `latest`; `None` means fresh.
    fn outdated(&self, dep: &Dep, latest: &str) -> Option<OutdatedDep>;

    /// Release dates (`YYYY-MM-DD`) of the current and newest releases.
    /// Best-effort annotations: failures yield `None`, never gaps.
    fn release_dates(
        &self,
        _ctx: &Ctx,
        _name: &str,
        _current: &str,
        _latest: &str,
    ) -> (Option<String>, Option<String>) {
        (None, None)
    }

    /// Shell command that applies the `outdated` updates, run from `root`.
    /// The default ecosystem has no stock updater command.
    fn update_command(&self, _root: &Path, _outdated: &[OutdatedDep]) -> Option<String> {
        None
    }

    /// Language/toolchain pins found in project files (gradle wrapper, node
    /// engines, `requires-python`, ...). The default ecosystem has none.
    fn enumerate_tools(&self, _root: &Path) -> Vec<ToolPin> {
        Vec::new()
    }

    /// Lint the project's own sources. Runs after the vulnerability phase
    /// so findings that repeat a reported vulnerability can be suppressed.
    /// The default ecosystem has no linters.
    fn lint(&self, _ctx: &Ctx, _root: &Path, _vulns: &[FoundVuln]) -> crate::lint::LintOutcome {
        crate::lint::LintOutcome::default()
    }

    /// Fill release dates on outdated lines, resolved in parallel.
    /// `keys` holds the registry key per line, in the same order.
    fn attach_dates(&self, ctx: &Ctx, keys: &[String], outdated: &mut [OutdatedDep]) {
        let dates: Vec<(Option<String>, Option<String>)> = std::thread::scope(|s| {
            let handles: Vec<_> = keys
                .iter()
                .zip(outdated.iter())
                .map(|(key, line)| {
                    s.spawn(|| self.release_dates(ctx, key, &line.current, &line.latest))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or((None, None)))
                .collect()
        });
        for (line, (current, latest)) in outdated.iter_mut().zip(dates) {
            fill_dates(
                &mut line.current_released,
                &mut line.latest_released,
                &mut line.days_behind,
                current,
                latest,
            );
        }
    }

    /// Fill release dates on blocked lines, resolved in parallel.
    fn attach_blocked_dates(&self, ctx: &Ctx, keys: &[String], blocked: &mut [BlockedDep]) {
        let dates: Vec<(Option<String>, Option<String>)> = std::thread::scope(|s| {
            let handles: Vec<_> = keys
                .iter()
                .zip(blocked.iter())
                .map(|(key, line)| {
                    s.spawn(|| self.release_dates(ctx, key, &line.current, &line.latest))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or((None, None)))
                .collect()
        });
        for (line, (current, latest)) in blocked.iter_mut().zip(dates) {
            fill_dates(
                &mut line.current_released,
                &mut line.latest_released,
                &mut line.days_behind,
                current,
                latest,
            );
        }
    }

    /// SPDX licenses of one used (name, version): empty when unknown.
    /// A published version's license never changes, so implementations
    /// cache forever.
    fn dep_licenses(&self, _ctx: &Ctx, _name: &str, _version: &str) -> Vec<String> {
        Vec::new()
    }

    /// Dependency-metadata notices for one used version. The default
    /// covers licenses; ecosystems add yanked pins and framework EOL.
    fn dep_notice(&self, ctx: &Ctx, name: &str, version: &str) -> Vec<Notice> {
        crate::licenses::license_notices(
            &ctx.license_policy,
            name,
            version,
            &self.dep_licenses(ctx, name, version),
        )
    }

    /// Project-level notices from lockfiles and sources (duplicate
    /// versions, phantom imports). Local-only: no network, no cache.
    /// `inventory` is the enumerated dependency set for direct /
    /// transitive membership tests.
    fn project_notices(&self, _ctx: &Ctx, _root: &Path, _inventory: &[Dep]) -> Vec<Notice> {
        Vec::new()
    }

    /// Relicensing notice when the newest release's license set differs
    /// from the used version's. One extra license lookup per outdated
    /// dependency, forever-cached like every other resolution.
    fn license_change_notice(
        &self,
        ctx: &Ctx,
        name: &str,
        used: &str,
        latest: &str,
    ) -> Option<Notice> {
        if used == latest {
            return None;
        }
        let before = self.dep_licenses(ctx, name, used);
        let after = self.dep_licenses(ctx, name, latest);
        crate::licenses::license_change(name, latest, &before, &after)
    }

    /// Run the audit: outdated via the registry, vulns via OSV.
    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome {
        let started = crate::progress::start();
        let inventory = match self.enumerate(root) {
            Ok(inv) => inv,
            Err(e) => {
                crate::progress::skipped(self.id(), &e);
                return CheckOutcome::error(self.id(), self.display(), e);
            }
        };
        let deps = inventory.deps;
        let mut gaps = inventory.gaps;
        let inventory_notes = inventory.notes;
        if ctx.verbose {
            eprintln!("[{}] enumerated {} dependencies", self.id(), deps.len());
        }
        let tools = if ctx.check_outdated {
            self.enumerate_tools(root)
        } else {
            Vec::new()
        };
        // A dependency-less project (stdlib-only Go, ...) still has
        // lintable sources, so linting alone defeats the skip.
        if deps.is_empty() && tools.is_empty() && !ctx.lint {
            crate::progress::skipped(self.id(), "no dependencies found");
            return CheckOutcome {
                id: self.id(),
                display: self.display(),
                status: Status::Skipped,
                outdated: Vec::new(),
                blocked: Vec::new(),
                vulnerabilities: Vec::new(),
                tools: Vec::new(),
                gaps,
                lint: Vec::new(),
                notices: Vec::new(),
                update_command: None,
                checked: 0,
                message: Some("no dependencies found".to_string()),
            };
        }

        crate::progress::checking(self.id(), deps.len());
        let mut outdated = Vec::new();
        let mut outdated_keys: Vec<String> = Vec::new();
        let mut blocked = Vec::new();
        let mut blocked_keys: Vec<String> = Vec::new();
        let mut vulnerabilities = Vec::new();
        let mut notes = inventory_notes;
        let mut license_changes = Vec::new();

        // Enrich every dep (resolve unknown versions, fetch latest) in parallel.
        let enriched: Vec<Enriched> = std::thread::scope(|s| {
            let handles: Vec<_> = deps
                .iter()
                .map(|d| {
                    s.spawn(|| {
                        let mut dep = d.clone();
                        let mut resolve_outcome = None;
                        if dep.version.is_none() {
                            match self.cached_resolve(ctx, &dep) {
                                Ok((resolved, stale)) => {
                                    dep.version = resolved.or(dep.version);
                                    resolve_outcome = Some((Ok(dep.version.clone()), stale));
                                }
                                Err(e) => resolve_outcome = Some((Err(e), None)),
                            }
                        }
                        let latest = if ctx.check_outdated && (ctx.deep || dep.direct) {
                            Some(self.cached_latest(ctx, &dep))
                        } else {
                            None
                        };
                        (dep, resolve_outcome, latest)
                    })
                })
                .collect();
            handles
                .into_iter()
                .enumerate()
                .map(|(i, h)| {
                    h.join().unwrap_or_else(|_| {
                        gaps.push(Gap {
                            name: deps[i].display.clone(),
                            check: GapCheck::Outdated,
                            reason: "internal worker failure".to_string(),
                        });
                        (deps[i].clone(), None, None)
                    })
                })
                .collect()
        });

        // Stale version resolutions are flagged once, up front: they feed
        // both the outdated and the vulnerability checks below.
        let mut stale_used = 0;
        for (dep, resolve_outcome, _) in &enriched {
            if let Some((_, Some(reason))) = resolve_outcome {
                stale_used += 1;
                gaps.push(Gap {
                    name: dep.display.clone(),
                    check: GapCheck::Outdated,
                    reason: format!("using cached version resolution ({reason})"),
                });
                if ctx.verbose {
                    eprintln!(
                        "[{}] {}: using stale cached version ({reason})",
                        self.id(),
                        dep.display
                    );
                }
            }
        }

        if ctx.check_outdated {
            let mut skipped_transitive = 0;
            for (dep, _, latest) in &enriched {
                if !(ctx.deep || dep.direct) {
                    skipped_transitive += 1;
                    continue;
                }
                match latest {
                    Some(Ok((info, stale))) => {
                        if let Some(reason) = &info.unverified {
                            gaps.push(Gap {
                                name: dep.display.clone(),
                                check: GapCheck::Outdated,
                                reason: reason.clone(),
                            });
                        }
                        if let Some(reason) = stale {
                            stale_used += 1;
                            if ctx.verbose {
                                eprintln!(
                                    "[{}] {}: using stale cached latest ({reason})",
                                    self.id(),
                                    dep.display
                                );
                            }
                        }
                        match self.outdated(dep, &info.latest) {
                            Some(mut o) => {
                                o.blocked = info.blocked.clone();
                                o.stale = stale.clone();
                                outdated.push(o);
                                outdated_keys.push(dep.name.clone());
                            }
                            None => {
                                if let Some(b) = &info.blocked {
                                    blocked.push(BlockedDep {
                                        name: dep.display.clone(),
                                        current: dep
                                            .version
                                            .clone()
                                            .or_else(|| dep.spec.clone())
                                            .unwrap_or_default(),
                                        latest: b.latest.clone(),
                                        min_compile_sdk: b.min_compile_sdk,
                                        current_released: None,
                                        latest_released: None,
                                        days_behind: None,
                                    });
                                    blocked_keys.push(dep.name.clone());
                                }
                            }
                        }
                    }
                    Some(Err(reason)) => gaps.push(Gap {
                        name: dep.display.clone(),
                        check: GapCheck::Outdated,
                        reason: reason.clone(),
                    }),
                    // Outdated check disabled: nothing to do.
                    None => {}
                }
            }
            // Sort lines with their registry keys attached, then resolve
            // release dates in parallel (only for lines actually shown).
            let mut paired: Vec<_> = outdated.into_iter().zip(outdated_keys).collect();
            paired.sort_by(|a, b| a.0.name.cmp(&b.0.name));
            let (sorted, keys): (Vec<OutdatedDep>, Vec<String>) = paired.into_iter().unzip();
            outdated = sorted;
            let mut bpaired: Vec<_> = blocked.into_iter().zip(blocked_keys).collect();
            bpaired.sort_by(|a, b| a.0.name.cmp(&b.0.name));
            let (bsorted, bkeys): (Vec<BlockedDep>, Vec<String>) = bpaired.into_iter().unzip();
            blocked = bsorted;
            self.attach_dates(ctx, &keys, &mut outdated);
            self.attach_blocked_dates(ctx, &bkeys, &mut blocked);
            // Relicensed upstreams: used vs newest reachable release.
            // `keys` aligns with `outdated` from the sort above.
            if ctx.check_notices {
                for (line, key) in outdated.iter().zip(keys.iter()) {
                    if let Some(n) =
                        self.license_change_notice(ctx, key, &line.current, &line.latest)
                    {
                        license_changes.push(n);
                    }
                }
            }
            if skipped_transitive > 0 {
                notes.push(if skipped_transitive == 1 {
                    "1 transitive dependency not checked for outdatedness (use --deep)"
                        .to_string()
                } else {
                    format!(
                        "{skipped_transitive} transitive dependencies not checked for outdatedness (use --deep)"
                    )
                });
            }
        }
        // Stale note is pushed after the tools section below, which also counts.

        if ctx.check_vulns {
            let queries: Vec<(String, String, String)> = enriched
                .iter()
                .filter_map(|(d, _, _)| {
                    d.version.as_ref().map(|v| {
                        (
                            self.osv_ecosystem().to_string(),
                            d.osv_name.clone(),
                            v.clone(),
                        )
                    })
                })
                .collect();
            // Anything still versionless cannot be queried.
            for (dep, resolve_outcome, _) in &enriched {
                if dep.version.is_none() {
                    let resolve_err = resolve_outcome.as_ref().and_then(|(r, _)| r.as_ref().err());
                    let reason = resolve_err.cloned().unwrap_or_else(|| match &dep.spec {
                        Some(spec) => {
                            format!("no installed, locked, or pinned version (declared: '{spec}')")
                        }
                        None => "no installed, locked, or pinned version".to_string(),
                    });
                    gaps.push(Gap {
                        name: dep.display.clone(),
                        check: GapCheck::Vulns,
                        reason,
                    });
                }
            }
            // Serve cached triples (including cached-clean ones) locally.
            let mut by_dep = std::collections::HashMap::new();
            let mut missing = Vec::new();
            for q in &queries {
                let key = osv_cache_key(q);
                match ctx.cache.get::<Vec<FoundVuln>>(&key, TTL_VULNS_SECS) {
                    Some(vulns) => {
                        if !vulns.is_empty() {
                            by_dep.insert(q.clone(), vulns);
                        }
                    }
                    None => missing.push(q.clone()),
                }
            }
            if ctx.verbose {
                eprintln!(
                    "[{}] querying OSV for {} versions ({} cached)",
                    self.id(),
                    missing.len(),
                    queries.len() - missing.len()
                );
            }
            if !missing.is_empty() {
                match osv::query_batch(&missing) {
                    Ok(outcome) => {
                        for q in &missing {
                            let vulns = outcome.by_dep.get(q).cloned().unwrap_or_default();
                            ctx.cache.set(&osv_cache_key(q), &vulns);
                            if !vulns.is_empty() {
                                by_dep.insert(q.clone(), vulns);
                            }
                        }
                        if outcome.detail_failures > 0 {
                            notes.push(format!(
                                "{} advisories shown without details (fetch failed)",
                                outcome.detail_failures
                            ));
                        }
                    }
                    Err(e) => {
                        // Offline or throttled: serve last-known results.
                        let mut stale_n = 0;
                        for q in &missing {
                            if let Some(vulns) =
                                ctx.cache.get_stale::<Vec<FoundVuln>>(&osv_cache_key(q))
                            {
                                if !vulns.is_empty() {
                                    by_dep.insert(q.clone(), vulns);
                                }
                                stale_n += 1;
                            }
                        }
                        notes.push(if stale_n > 0 {
                            format!(
                                "OSV unreachable ({}); {stale_n} results from stale cache",
                                crate::http::short_error(&e, 120)
                            )
                        } else {
                            format!("vulnerability check failed: {e:#}")
                        });
                    }
                }
            }
            for ((_, name, _), mut vulns) in by_dep {
                // Show the project's display name, not the registry key.
                if let Some(dep) = deps.iter().find(|d| d.osv_name == name) {
                    for v in &mut vulns {
                        v.name.clone_from(&dep.display);
                    }
                }
                vulnerabilities.extend(vulns);
            }
            vulnerabilities.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        }

        // Licenses, yanked pins, framework EOL: every dependency with a
        // known version, direct and transitive alike.
        let mut notices = Vec::new();
        if ctx.check_notices {
            let targets: Vec<(String, String)> = enriched
                .iter()
                .filter_map(|(d, _, _)| d.version.as_ref().map(|v| (d.name.clone(), v.clone())))
                .collect();
            let found: Vec<Vec<Notice>> = std::thread::scope(|s| {
                let handles: Vec<_> = targets
                    .iter()
                    .map(|(name, version)| s.spawn(|| self.dep_notice(ctx, name, version)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap_or_default())
                    .collect()
            });
            for mut n in found {
                notices.append(&mut n);
            }
            notices.append(&mut license_changes);
            let inv: Vec<Dep> = enriched.iter().map(|(d, _, _)| d.clone()).collect();
            notices.append(&mut self.project_notices(ctx, root, &inv));
            notices.sort_by(|a, b| (&a.check, &a.name).cmp(&(&b.check, &b.name)));
        }

        let mut tool_findings = Vec::new();
        if ctx.check_outdated && !tools.is_empty() {
            let statuses: Vec<Result<toolchains::ToolStatus, String>> = std::thread::scope(|s| {
                tools
                    .iter()
                    .map(|pin| {
                        s.spawn(|| {
                            let current = pin
                                .version
                                .clone()
                                .or_else(|| pin.spec.clone())
                                .ok_or_else(|| "no version or requirement declared".to_string())?;
                            toolchains::tool_status(&ctx.cache, pin.tool, &current)
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err("internal worker failure".to_string()))
                    })
                    .collect()
            });
            for (pin, status) in tools.iter().zip(statuses) {
                let current = pin.version.clone().or_else(|| pin.spec.clone());
                let status = match (current, status) {
                    (Some(current), Ok(status)) => (current, status),
                    (_current, result) => {
                        let reason = match result {
                            Err(e) => e,
                            Ok(_) => "no version or requirement declared".to_string(),
                        };
                        gaps.push(Gap {
                            name: pin.display.clone(),
                            check: GapCheck::Outdated,
                            reason,
                        });
                        continue;
                    }
                };
                let (current, status) = status;
                let baseline = pin
                    .version
                    .clone()
                    .or_else(|| {
                        pin.spec
                            .as_ref()
                            .and_then(|s| toolchains::spec_min_version(s))
                    })
                    .unwrap_or_else(|| current.clone());
                if crate::version::compare(&baseline, &status.latest) == std::cmp::Ordering::Less {
                    let detail = status.eol.map(|since| match since {
                        Some(date) => format!("end-of-life since {date}"),
                        None => "end-of-life".to_string(),
                    });
                    if let Some(reason) = &status.stale {
                        stale_used += 1;
                        if ctx.verbose {
                            eprintln!(
                                "[{}] {}: using stale cached latest ({reason})",
                                self.id(),
                                pin.display
                            );
                        }
                    }
                    tool_findings.push(OutdatedDep {
                        name: pin.display.clone(),
                        current,
                        latest: status.latest,
                        detail,
                        blocked: None,
                        stale: status.stale,
                        current_released: None,
                        latest_released: None,
                        days_behind: None,
                    });
                }
            }
            tool_findings.sort_by(|a, b| a.name.cmp(&b.name));
        }

        let mut lint_findings = Vec::new();
        if ctx.lint {
            crate::progress::linting(self.id());
            let outcome = self.lint(ctx, root, &vulnerabilities);
            lint_findings = outcome.findings;
            gaps.extend(outcome.gaps);
            notes.extend(outcome.notes);
        }

        if stale_used > 0 {
            notes.push(if stale_used == 1 {
                "1 lookup served from stale cache".to_string()
            } else {
                format!("{stale_used} lookups served from stale cache")
            });
        }
        gaps.sort_by(|a, b| (&a.name, &a.check).cmp(&(&b.name, &b.check)));
        let update_command = if outdated.is_empty() {
            None
        } else {
            self.update_command(root, &outdated)
        };
        let outcome = CheckOutcome {
            id: self.id(),
            display: self.display(),
            status: Status::Ok,
            outdated,
            blocked,
            vulnerabilities,
            tools: tool_findings,
            gaps,
            lint: lint_findings,
            notices,
            update_command,
            checked: deps.len(),
            message: if notes.is_empty() {
                None
            } else {
                Some(notes.join("; "))
            },
        };
        crate::progress::finished(
            self.id(),
            outcome.outdated.len(),
            outcome.vulnerabilities.len(),
            outcome.notices.len(),
            outcome.lint.len(),
            outcome.gaps.len(),
            started,
        );
        outcome
    }

    /// Latest release from cache-or-registry. On lookup failure the
    /// last-known value is served with the failure reason, so offline and
    /// rate-limited runs degrade instead of gaping. (Misses are never cached.)
    fn cached_latest(&self, ctx: &Ctx, dep: &Dep) -> Result<Fresh<LatestInfo>, String> {
        let key = self.latest_cache_key(ctx, dep);
        if let Some(cached) = ctx.cache.get(&key, ctx.cache.versions_ttl()) {
            return Ok((cached, None));
        }
        match self.fetch_latest(ctx, dep) {
            // Unverified results (transient failure during usability checks)
            // are served but never cached: the next run retries them.
            Ok(info) => {
                if info.unverified.is_none() {
                    ctx.cache.set(&key, &info);
                }
                Ok((info, None))
            }
            Err(e) => match ctx.cache.get_stale(&key) {
                Some(stale) => Ok((stale, Some(e))),
                None => Err(e),
            },
        }
    }

    /// Cache key for the latest-release lookup. Ecosystems whose answer
    /// depends on policy knobs (Android's SDK cap) must qualify it.
    fn latest_cache_key(&self, _ctx: &Ctx, dep: &Dep) -> String {
        format!("v1:latest:{}:{}", self.id(), dep.name)
    }

    /// Fresh-install resolution with a version-TTL cache (misses are never cached).
    fn cached_resolve(&self, ctx: &Ctx, dep: &Dep) -> Result<Fresh<Option<String>>, String> {
        let Some(spec) = dep.spec.as_ref() else {
            return self.resolve_version(dep).map(|v| (v, None));
        };
        let key = format!("v1:resolved:{}:{}:{spec}", self.id(), dep.name);
        if let Some(cached) = ctx.cache.get(&key, ctx.cache.versions_ttl()) {
            return Ok((Some(cached), None));
        }
        match self.resolve_version(dep) {
            Ok(Some(resolved)) => {
                ctx.cache.set(&key, &resolved);
                Ok((Some(resolved), None))
            }
            Ok(None) => Ok((None, None)),
            Err(e) => match ctx.cache.get_stale(&key) {
                Some(stale) => Ok((Some(stale), Some(e))),
                None => Err(e),
            },
        }
    }
}

fn osv_cache_key(q: &(String, String, String)) -> String {
    format!("v1:osv:{}:{}:{}", q.0, q.1, q.2)
}

/// All supported ecosystems, in stable report order.
pub fn all_checkers() -> Vec<Box<dyn EcosystemChecker>> {
    vec![
        Box::new(crate::python::Python),
        Box::new(crate::node::Node),
        Box::new(crate::rustlang::RustLang),
        Box::new(crate::golang::GoLang),
        Box::new(crate::android::Android),
    ]
}

/// Resolve a user-supplied ecosystem id (with `js` accepted as an alias).
pub fn canonical_id(input: &str) -> Option<&'static str> {
    match input.trim().to_lowercase().as_str() {
        "python" | "py" => Some("python"),
        "node" | "js" | "javascript" | "typescript" | "ts" => Some("node"),
        "rust" | "rs" => Some("rust"),
        "go" | "golang" => Some("go"),
        "android" | "gradle" | "kotlin" => Some("android"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFail;

    impl EcosystemChecker for MockFail {
        fn id(&self) -> &'static str {
            "mock"
        }

        fn display(&self) -> &'static str {
            "Mock"
        }

        fn detect(&self, _root: &Path) -> bool {
            false
        }

        fn osv_ecosystem(&self) -> &'static str {
            "mock"
        }

        fn enumerate(&self, _root: &Path) -> Result<Inventory, String> {
            Ok(Inventory::default())
        }

        fn fetch_latest(&self, _ctx: &Ctx, _dep: &Dep) -> Result<LatestInfo, String> {
            Err("boom".to_string())
        }

        fn outdated(&self, _dep: &Dep, _latest: &str) -> Option<OutdatedDep> {
            None
        }
    }

    fn test_ctx() -> Ctx {
        Ctx {
            verbose: false,
            deep: false,
            check_outdated: true,
            check_vulns: true,
            cache: std::sync::Arc::new(Cache::for_test()),
            android_sdk_cap: None,
            lint: false,
            lint_config_order: crate::lint::DEFAULT_ORDER,
            check_notices: false,
            license_policy: crate::licenses::Policy::default(),
        }
    }

    #[test]
    fn cached_latest_uses_stale_on_failure() {
        let checker = MockFail;
        let ctx = test_ctx();
        let dep = Dep::new("foo");
        // Nothing cached and fetch fails: plain error.
        assert_eq!(checker.cached_latest(&ctx, &dep), Err("boom".to_string()));
        // Plant a fresh entry: served without calling fetch.
        let info = LatestInfo::simple("2.0".to_string());
        ctx.cache.set("v1:latest:mock:foo", &info);
        assert_eq!(checker.cached_latest(&ctx, &dep), Ok((info.clone(), None)));
        // Expire it: fetch fails, stale served with the reason.
        ctx.cache.set_versions_ttl(0);
        assert_eq!(
            checker.cached_latest(&ctx, &dep),
            Ok((info, Some("boom".to_string())))
        );
    }

    #[test]
    fn attach_dates_fills_both_lines_and_days() {
        struct MockDates;
        impl EcosystemChecker for MockDates {
            fn id(&self) -> &'static str {
                "mock"
            }
            fn display(&self) -> &'static str {
                "Mock"
            }
            fn detect(&self, _root: &Path) -> bool {
                false
            }
            fn osv_ecosystem(&self) -> &'static str {
                "mock"
            }
            fn enumerate(&self, _root: &Path) -> Result<Inventory, String> {
                Ok(Inventory::default())
            }
            fn fetch_latest(&self, _ctx: &Ctx, _dep: &Dep) -> Result<LatestInfo, String> {
                Err("boom".to_string())
            }
            fn outdated(&self, _dep: &Dep, _latest: &str) -> Option<OutdatedDep> {
                None
            }
            fn release_dates(
                &self,
                _ctx: &Ctx,
                name: &str,
                _current: &str,
                _latest: &str,
            ) -> (Option<String>, Option<String>) {
                match name {
                    "dated" => (
                        Some("2025-11-02".to_string()),
                        Some("2026-04-18".to_string()),
                    ),
                    // One-sided dates leave days unknown.
                    _ => (None, Some("2026-04-18".to_string())),
                }
            }
        }
        let checker = MockDates;
        let ctx = test_ctx();
        let keys = ["dated".to_string(), "partial".to_string()];
        let mut outdated = vec![
            OutdatedDep {
                name: "dated".to_string(),
                current: "1.0".to_string(),
                latest: "2.0".to_string(),
                detail: None,
                blocked: None,
                stale: None,
                current_released: None,
                latest_released: None,
                days_behind: None,
            },
            OutdatedDep {
                name: "partial".to_string(),
                current: "1.0".to_string(),
                latest: "2.0".to_string(),
                detail: None,
                blocked: None,
                stale: None,
                current_released: None,
                latest_released: None,
                days_behind: None,
            },
        ];
        checker.attach_dates(&ctx, &keys, &mut outdated);
        assert_eq!(outdated[0].current_released.as_deref(), Some("2025-11-02"));
        assert_eq!(outdated[0].latest_released.as_deref(), Some("2026-04-18"));
        assert_eq!(outdated[0].days_behind, Some(167));
        assert_eq!(outdated[1].current_released, None);
        assert_eq!(outdated[1].days_behind, None);

        let mut blocked = vec![BlockedDep {
            name: "dated".to_string(),
            current: "1.0".to_string(),
            latest: "2.0".to_string(),
            min_compile_sdk: 37,
            current_released: None,
            latest_released: None,
            days_behind: None,
        }];
        checker.attach_blocked_dates(&ctx, &keys[..1], &mut blocked);
        assert_eq!(blocked[0].days_behind, Some(167));
    }

    #[test]
    fn cached_resolve_uses_stale_on_failure() {
        struct MockResolveFail;
        impl EcosystemChecker for MockResolveFail {
            fn id(&self) -> &'static str {
                "mock"
            }

            fn display(&self) -> &'static str {
                "Mock"
            }

            fn detect(&self, _root: &Path) -> bool {
                false
            }

            fn osv_ecosystem(&self) -> &'static str {
                "mock"
            }

            fn enumerate(&self, _root: &Path) -> Result<Inventory, String> {
                Ok(Inventory::default())
            }

            fn fetch_latest(&self, _ctx: &Ctx, _dep: &Dep) -> Result<LatestInfo, String> {
                Err("boom".to_string())
            }

            fn resolve_version(&self, _dep: &Dep) -> Result<Option<String>, String> {
                Err("boom".to_string())
            }

            fn outdated(&self, _dep: &Dep, _latest: &str) -> Option<OutdatedDep> {
                None
            }
        }

        let checker = MockResolveFail;
        let ctx = test_ctx();
        let mut dep = Dep::new("foo");
        dep.spec = Some("^1".to_string());
        assert_eq!(checker.cached_resolve(&ctx, &dep), Err("boom".to_string()));
        ctx.cache.set("v1:resolved:mock:foo:^1", &"1.5".to_string());
        ctx.cache.set_versions_ttl(0);
        assert_eq!(
            checker.cached_resolve(&ctx, &dep),
            Ok((Some("1.5".to_string()), Some("boom".to_string())))
        );
    }
}
