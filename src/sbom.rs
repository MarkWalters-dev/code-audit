//! CycloneDX SBOM emission to stdout.
//!
//! Reuses the audit itself: dependency enumeration, cached license
//! lookups, and the OSV findings already collected. Components are
//! deduplicated by purl across projects; versionless dependencies are
//! skipped with a stderr count (stdout stays pure SBOM for pipelines).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use crate::cache::Cache;
use crate::ecosystem::{CheckOutcome, Ctx, EcosystemChecker};

/// Minimal context for resolution/license lookups during SBOM assembly.
/// Licenses ignore policy here: the SBOM lists everything it finds.
fn sbom_ctx(cache: &Arc<Cache>) -> Ctx {
    Ctx {
        verbose: false,
        deep: false,
        check_outdated: false,
        check_vulns: false,
        cache: cache.clone(),
        android_sdk_cap: None,
        lint: false,
        lint_config_order: crate::lint::DEFAULT_ORDER,
        check_notices: false,
        license_policy: crate::licenses::Policy::default(),
    }
}

pub fn print(
    cache: &Arc<Cache>,
    checkers: &[Box<dyn EcosystemChecker>],
    reports: &[(String, Vec<CheckOutcome>)],
    root: &str,
) {
    let doc = build(cache, checkers, reports, root);
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
    );
}

fn build(
    cache: &Arc<Cache>,
    checkers: &[Box<dyn EcosystemChecker>],
    reports: &[(String, Vec<CheckOutcome>)],
    root: &str,
) -> serde_json::Value {
    let ctx = sbom_ctx(cache);
    let mut components = Vec::new();
    let mut seen = HashSet::new();
    let mut vulnerabilities = Vec::new();
    let mut skipped = 0;
    for (proj_str, outcomes) in reports {
        let proj_root = Path::new(proj_str);
        for outcome in outcomes {
            let Some(checker) = checkers.iter().find(|c| c.id() == outcome.id) else {
                continue;
            };
            let inventory = match checker.enumerate(proj_root) {
                Ok(inv) => inv,
                Err(_) => continue,
            };
            for dep in &inventory.deps {
                let Some(version) = dep
                    .version
                    .clone()
                    .or_else(|| checker.resolve_version(dep).ok().flatten())
                else {
                    skipped += 1;
                    continue;
                };
                let purl = purl(outcome.id, &dep.name, &version);
                if !seen.insert(purl.clone()) {
                    continue;
                }
                let licenses: Vec<serde_json::Value> = checker
                    .dep_licenses(&ctx, &dep.name, &version)
                    .into_iter()
                    .map(|id| serde_json::json!({"license": spdx_or_name(&id)}))
                    .collect();
                components.push(serde_json::json!({
                    "bom-ref": purl,
                    "type": "library",
                    "name": dep.name,
                    "version": version,
                    "licenses": licenses,
                    "purl": purl,
                    "properties": [
                        {"name": "depaudit:direct", "value": dep.direct.to_string()}
                    ],
                }));
            }
            for vuln in &outcome.vulnerabilities {
                let url = format!("https://osv.dev/vulnerability/{}", vuln.id);
                let id = vuln
                    .aliases
                    .iter()
                    .find(|a| a.starts_with("CVE-"))
                    .cloned()
                    .unwrap_or_else(|| vuln.id.clone());
                let mut versions =
                    vec![serde_json::json!({"version": vuln.version, "status": "affected"})];
                if let Some(fixed) = vuln.fixed.as_deref().filter(|f| !f.is_empty()) {
                    versions.push(serde_json::json!({"version": fixed, "status": "unaffected"}));
                }
                let mut entry = serde_json::json!({
                    "bom-ref": format!("{}-{}", vuln.id, vuln.name),
                    "id": id,
                    "source": {"name": "OSV", "url": url},
                    "description": vuln.summary,
                    "advisories": vuln.aliases.iter().map(|a| {
                        serde_json::json!({"url": format!("https://osv.dev/vulnerability/{a}")})
                    }).collect::<Vec<_>>(),
                    "affects": [{"ref": purl(outcome.id, &vuln.name, &vuln.version), "versions": versions}],
                });
                if let Some(rating) = severity_rating(vuln.severity.as_deref(), &url) {
                    entry["ratings"] = serde_json::json!([rating]);
                }
                vulnerabilities.push(entry);
            }
        }
    }
    if skipped > 0 {
        eprintln!("depaudit: SBOM skipped {skipped} versionless dependencies");
    }
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": rfc3339_now(),
            "tools": {"components": [
                {"type": "application", "name": "depaudit", "version": env!("CARGO_PKG_VERSION")}
            ]},
            "component": {"bom-ref": root, "type": "application", "name": root},
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    })
}

/// CycloneDX rating from OSV's best severity: either `"CVSS_V3 7.4"`
/// or a bare database_specific label (`"HIGH"`). Unparseable
/// severities yield no rating rather than a wrong one.
fn severity_rating(severity: Option<&str>, url: &str) -> Option<serde_json::Value> {
    let raw = severity?;
    if let Some((kind, score)) = raw.split_once(' ') {
        let method = match kind {
            "CVSS_V2" => "CVSSv2",
            "CVSS_V3" => "CVSSv3",
            "CVSS_V4" => "CVSSv4",
            _ => return None,
        };
        let score: f64 = score.parse().ok()?;
        return Some(serde_json::json!({
            "source": {"name": "OSV", "url": url},
            "score": score,
            "severity": cvss_label(score),
            "method": method,
        }));
    }
    let severity = match raw {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        "MEDIUM" | "MODERATE" => "medium",
        "LOW" => "low",
        _ => return None,
    };
    Some(serde_json::json!({
        "source": {"name": "OSV", "url": url},
        "severity": severity,
    }))
}

/// CVSS v3 qualitative severity rating scale.
fn cvss_label(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

/// SPDX ids serialize as `{"id": ...}`; anything else (custom tokens)
/// becomes `{"name": ...}` per the spec.
fn spdx_or_name(id: &str) -> serde_json::Value {
    if is_spdx_id(id) {
        serde_json::json!({"id": id})
    } else {
        serde_json::json!({"name": id})
    }
}

fn is_spdx_id(id: &str) -> bool {
    // SPDX ids never contain whitespace; custom tokens and prose do not
    // survive normalization as ids (see licenses::normalize_spdx).
    !id.is_empty() && !id.chars().any(|c| c.is_whitespace()) && id.len() <= 64
}

/// Package URL for a dependency. Best-effort rendering of the purl spec
/// for the five ecosystems (scope, case, and Go escaping handled).
pub(crate) fn purl(eco: &str, name: &str, version: &str) -> String {
    match eco {
        "python" => {
            let norm = name.to_lowercase().replace(['-', '_', '.'], "-");
            format!("pkg:pypi/{norm}@{version}")
        }
        "node" => {
            let path = name.replace('/', "%2f");
            let path = path
                .strip_prefix('@')
                .map(|s| format!("%40{s}"))
                .unwrap_or(path);
            format!("pkg:npm/{path}@{version}")
        }
        "rust" => format!("pkg:cargo/{name}@{version}"),
        "go" => {
            let escaped: String = name
                .chars()
                .flat_map(|c| {
                    if c.is_ascii_uppercase() {
                        vec!['!', c.to_ascii_lowercase()]
                    } else {
                        vec![c]
                    }
                })
                .collect();
            format!("pkg:golang/{escaped}@{version}")
        }
        "android" => match name.split_once(':') {
            Some((group, artifact)) => format!("pkg:maven/{group}/{artifact}@{version}"),
            None => format!("pkg:maven/{name}@{version}"),
        },
        _ => format!("pkg:generic/{name}@{version}"),
    }
}

fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = secs / 86400;
    let clock = secs % 86400;
    // Reuse the audit's own civil-date math for the calendar half.
    let date = crate::toolchains::today_string_from_days(day as i64);
    format!(
        "{date}T{:02}:{:02}:{:02}Z",
        clock / 3600,
        (clock % 3600) / 60,
        clock % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_purls() {
        assert_eq!(
            purl("python", "python_dateutil", "2.9.0"),
            "pkg:pypi/python-dateutil@2.9.0"
        );
        assert_eq!(purl("node", "is-odd", "3.0.1"), "pkg:npm/is-odd@3.0.1");
        assert_eq!(
            purl("node", "@angular/core", "17.0.0"),
            "pkg:npm/%40angular%2fcore@17.0.0"
        );
        assert_eq!(purl("rust", "serde", "1.0.229"), "pkg:cargo/serde@1.0.229");
        assert_eq!(
            purl("go", "github.com/BurntSushi/toml", "v1.0.0"),
            "pkg:golang/github.com/!burnt!sushi/toml@v1.0.0"
        );
        assert_eq!(
            purl("android", "junit:junit", "4.13.2"),
            "pkg:maven/junit/junit@4.13.2"
        );
    }

    #[test]
    fn timestamps_are_rfc3339() {
        let stamp = rfc3339_now();
        assert!(
            stamp.len() == 20 && stamp.ends_with('Z') && stamp.contains('T'),
            "{stamp}"
        );
    }

    #[test]
    fn ratings_map_cvss_scales() {
        let rating = severity_rating(Some("CVSS_V3 9.8"), "https://osv.dev/x").unwrap();
        assert_eq!(rating["method"], "CVSSv3");
        assert_eq!(rating["severity"], "critical");
        assert_eq!(rating["score"], 9.8);
        let rating = severity_rating(Some("CVSS_V4 5.0"), "https://osv.dev/x").unwrap();
        assert_eq!(rating["method"], "CVSSv4");
        assert_eq!(rating["severity"], "medium");
        let rating = severity_rating(Some("HIGH"), "https://osv.dev/x").unwrap();
        assert_eq!(rating["severity"], "high");
        assert!(rating.get("score").is_none());
        let rating = severity_rating(Some("MODERATE"), "https://osv.dev/x").unwrap();
        assert_eq!(rating["severity"], "medium");
        assert!(severity_rating(None, "https://osv.dev/x").is_none());
        assert!(severity_rating(Some("UNKNOWN"), "https://osv.dev/x").is_none());
        assert!(severity_rating(Some("CVSS_V3 nope"), "https://osv.dev/x").is_none());
    }
}
