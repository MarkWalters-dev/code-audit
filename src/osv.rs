//! Vulnerability lookup via the OSV API (https://osv.dev), the same database
//! that powers osv-scanner: NVD/CVE, GHSA, RustSec, Go vuln DB, PyPA, etc.
//! Free, keyless, batched: one HTTP request per ~100 dependencies.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::http;

/// A confirmed vulnerability in one dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundVuln {
    pub name: String,
    pub version: String,
    /// OSV id, e.g. GHSA-xxxx-yyyy-zzzz.
    pub id: String,
    /// Aliases, usually including the CVE id.
    pub aliases: Vec<String>,
    pub summary: String,
    /// Best severity, e.g. "CVSS_V3 7.4".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Fixed version, when the advisory names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    /// Suggested replacements from the advisory's Alternatives section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<Alternative>,
}

/// A suggested replacement crate with its newest stable release, when known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alternative {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
}

/// Outcome of [`query_batch`]: findings plus the number of advisories whose
/// full record could not be fetched (reported as id-only entries).
pub struct BatchOutcome {
    pub by_dep: HashMap<(String, String, String), Vec<FoundVuln>>,
    pub detail_failures: usize,
}

/// Query vulnerabilities for `(ecosystem, name, version)` triples.
/// Triples with no findings are absent from the map. Batch-call failure is
/// an `Err` (caller decides how to report it); per-vulnerability detail
/// failures degrade to id-only entries counted in `detail_failures`.
pub fn query_batch(deps: &[(String, String, String)]) -> anyhow::Result<BatchOutcome> {
    // Phase 1: batched queries yield vulnerability ids per triple.
    let mut ids_by_dep: HashMap<(String, String, String), Vec<String>> = HashMap::new();
    for chunk in deps.chunks(100) {
        let req = BatchRequest {
            queries: chunk
                .iter()
                .map(|(ecosystem, name, version)| Query {
                    package: Package {
                        name: name.clone(),
                        ecosystem: ecosystem.clone(),
                    },
                    version: version.clone(),
                })
                .collect(),
        };
        let resp: BatchResponse = http::post_json_retry("https://api.osv.dev/v1/querybatch", &req)?;
        for (i, result) in resp.results.into_iter().enumerate() {
            let Some(key) = chunk.get(i) else { continue };
            let ids: Vec<String> = result.vulns.into_iter().map(|v| v.id).collect();
            if !ids.is_empty() {
                ids_by_dep.insert(key.clone(), ids);
            }
        }
    }
    if ids_by_dep.is_empty() {
        return Ok(BatchOutcome {
            by_dep: HashMap::new(),
            detail_failures: 0,
        });
    }
    // Phase 2: full records, one GET per unique id, in parallel.
    let mut unique: Vec<String> = ids_by_dep.values().flatten().cloned().collect();
    unique.sort();
    unique.dedup();
    let mut full: HashMap<String, OsvVuln> = HashMap::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = unique.iter().map(|id| s.spawn(|| fetch_vuln(id))).collect();
        for (id, handle) in unique.iter().zip(handles) {
            if let Ok(Some(vuln)) = handle.join() {
                full.insert(id.clone(), vuln);
            }
        }
    });
    // Phase 3: assemble per-triple results.
    let mut out: HashMap<(String, String, String), Vec<FoundVuln>> = HashMap::new();
    let mut detail_failures = 0;
    for (key, ids) in ids_by_dep {
        let vulns: Vec<FoundVuln> = ids
            .into_iter()
            .map(|id| match full.remove(&id) {
                Some(v) => v.into_found(&key.1, &key.2, |n| crate::rustlang::crates_latest(n).ok()),
                None => {
                    detail_failures += 1;
                    FoundVuln {
                        name: key.1.clone(),
                        version: key.2.clone(),
                        summary: id.clone(),
                        id,
                        aliases: Vec::new(),
                        severity: None,
                        fixed: None,
                        alternatives: Vec::new(),
                    }
                }
            })
            .collect();
        out.insert(key, vulns);
    }
    // Deterministic order inside each entry.
    for vulns in out.values_mut() {
        vulns.sort_by(|a, b| a.id.cmp(&b.id));
    }
    Ok(BatchOutcome {
        by_dep: out,
        detail_failures,
    })
}

/// Fetch one full record, retrying transient failures (notably 429s when many
/// advisories resolve at once). Returns `None` when all attempts fail.
fn fetch_vuln(id: &str) -> Option<OsvVuln> {
    let url = format!("https://api.osv.dev/v1/vulns/{id}");
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(250 * (1 << (attempt - 1))));
        }
        match http::get_json::<OsvVuln>(&url) {
            Ok(v) => return Some(v),
            Err(e) => {
                if http::is_final(&e) {
                    return None;
                }
            }
        }
    }
    None
}

#[derive(Debug, Serialize)]
struct BatchRequest {
    queries: Vec<Query>,
}

#[derive(Debug, Serialize)]
struct Query {
    package: Package,
    version: String,
}

#[derive(Debug, Serialize)]
struct Package {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<QueryResult>,
}

#[derive(Debug, Deserialize, Default)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

/// Batch responses carry only references; full records come from /v1/vulns/{id}.
#[derive(Debug, Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<DbSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct DbSpecific {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Debug, Deserialize, Default)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize, Default)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

impl OsvVuln {
    fn into_found(
        self,
        name: &str,
        version: &str,
        resolve_latest: impl Fn(&str) -> Option<String>,
    ) -> FoundVuln {
        let summary = self
            .summary
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.details
                    .as_ref()
                    .map(|d| d.lines().next().unwrap_or("").trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| self.id.clone());
        let alternatives = self
            .details
            .as_deref()
            .map(parse_alternatives)
            .unwrap_or_default()
            .into_iter()
            .map(|alt| Alternative {
                latest: resolve_latest(&alt),
                name: alt,
            })
            .collect();
        // Scores are usually CVSS vectors ("CVSS:3.1/..."), occasionally plain
        // numbers; database_specific.severity carries the qualitative rating.
        let severity = self
            .severity
            .iter()
            .filter_map(|s| s.score.parse::<f32>().ok().map(|n| (n, s)))
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, s)| format!("{} {}", s.kind, s.score))
            .or_else(|| {
                self.database_specific
                    .and_then(|d| d.severity)
                    .map(|r| r.to_uppercase())
            });
        let fixed = self
            .affected
            .iter()
            .flat_map(|a| &a.ranges)
            .flat_map(|r| &r.events)
            .find_map(|e| e.fixed.clone());
        FoundVuln {
            name: name.to_string(),
            version: version.to_string(),
            id: self.id,
            aliases: self.aliases,
            summary,
            severity,
            fixed,
            alternatives,
        }
    }
}

/// Replacement crates named by an advisory. First choice is RustSec's
/// Alternatives section (`crates.io/crates/<name>` links until the next
/// heading); unmaintained advisories without one fall back to suggestion
/// lines ("take a look at ... instead") mentioning crates.io or GitHub.
/// Capped and deduplicated; names are verified against crates.io by the
/// caller, so bad guesses just resolve to no version.
fn parse_alternatives(details: &str) -> Vec<String> {
    let section = parse_alternatives_section(details);
    if !section.is_empty() {
        return section;
    }
    let lower = details.to_lowercase();
    if lower.contains("unmaintained") || lower.contains("no longer maintained") {
        return parse_suggested_links(details);
    }
    Vec::new()
}

fn parse_alternatives_section(details: &str) -> Vec<String> {
    const PREFIX: &str = "crates.io/crates/";
    let mut in_section = false;
    let mut out = Vec::new();
    for line in details.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            in_section = is_alternatives_heading(trimmed);
            continue;
        }
        if !in_section {
            continue;
        }
        for (i, _) in trimmed.match_indices(PREFIX) {
            let name: String = trimmed[i + PREFIX.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
                if out.len() >= 5 {
                    return out;
                }
            }
        }
    }
    out
}

/// Matches `## Alternatives`, `## Alternative(s)`, `### alternatives`, ...
fn is_alternatives_heading(line: &str) -> bool {
    let alpha: String = line
        .trim_start_matches('#')
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    alpha.eq_ignore_ascii_case("alternatives") || alpha.eq_ignore_ascii_case("alternative")
}

/// Link targets on suggestion-flavored lines: crates.io names come from the
/// URL, GitHub names from the link text. Only used for unmaintained
/// advisories (see [`parse_alternatives`]).
fn parse_suggested_links(details: &str) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "instead",
        "take a look",
        "consider",
        "migrate",
        "switch to",
        "replacement",
        "alternative",
        "recommend",
    ];
    let mut out = Vec::new();
    for line in details.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if !MARKERS.iter().any(|m| trimmed.to_lowercase().contains(m)) {
            continue;
        }
        for name in crates_links_in(trimmed) {
            if !out.contains(&name) {
                out.push(name);
                if out.len() >= 5 {
                    return out;
                }
            }
        }
        for name in github_link_texts(trimmed) {
            if !out.contains(&name) {
                out.push(name);
                if out.len() >= 5 {
                    return out;
                }
            }
        }
    }
    out
}

fn crates_links_in(line: &str) -> Vec<String> {
    const PREFIX: &str = "crates.io/crates/";
    line.match_indices(PREFIX)
        .filter_map(|(i, _)| {
            let name: String = line[i + PREFIX.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if name.is_empty() { None } else { Some(name) }
        })
        .collect()
}

/// Link texts of `[text](https://github.com/...)` links whose text looks
/// like a crate name.
fn github_link_texts(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('[') {
        rest = &rest[open + 1..];
        let (Some(close), Some(paren)) = (rest.find(']'), rest.find("](https://github.com/"))
        else {
            continue;
        };
        if close != paren {
            continue;
        }
        let text: String = rest[..close].chars().filter(|c| *c != '`').collect();
        if !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            out.push(text);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_batch_response() {
        let resp: BatchResponse = serde_json::from_str(
            r#"{"results": [{"vulns": [{"id": "GHSA-4hjh-wcwx-xvwj", "modified": "2024-01-01T00:00:00Z"}]}, {}]}"#,
        )
        .unwrap();
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].vulns.len(), 1);
        assert_eq!(resp.results[0].vulns[0].id, "GHSA-4hjh-wcwx-xvwj");
        assert!(resp.results[1].vulns.is_empty());
    }

    #[test]
    fn parses_full_record() {
        let vuln: OsvVuln = serde_json::from_str(
            r#"{
                "id": "GHSA-4hjh-wcwx-xvwj",
                "summary": "Prototype Pollution in lodash",
                "aliases": ["CVE-2020-8203"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                "database_specific": {"severity": "high"},
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
            }"#,
        )
        .unwrap();
        let found = vuln.into_found("lodash", "4.17.20", |_| None);
        assert_eq!(found.id, "GHSA-4hjh-wcwx-xvwj");
        assert_eq!(found.aliases, vec!["CVE-2020-8203".to_string()]);
        assert_eq!(found.severity.as_deref(), Some("HIGH"));
        assert_eq!(found.fixed.as_deref(), Some("4.17.21"));
        assert_eq!(found.summary, "Prototype Pollution in lodash");
    }

    #[test]
    fn prefers_numeric_severity_score() {
        let vuln: OsvVuln = serde_json::from_str(
            r#"{
                "id": "GHSA-x",
                "severity": [{"type": "CVSS_V3", "score": "7.4"}]
            }"#,
        )
        .unwrap();
        let found = vuln.into_found("x", "1.0", |_| None);
        assert_eq!(found.severity.as_deref(), Some("CVSS_V3 7.4"));
    }

    #[test]
    fn falls_back_to_details_first_line() {
        let v = OsvVuln {
            id: "GHSA-x".to_string(),
            summary: None,
            details: Some("First line.\nSecond line.".to_string()),
            aliases: Vec::new(),
            severity: Vec::new(),
            database_specific: None,
            affected: Vec::new(),
        };
        let found = v.into_found("x", "1.0", |_| None);
        assert_eq!(found.summary, "First line.");
        assert_eq!(found.severity, None);
        assert_eq!(found.fixed, None);
    }

    #[test]
    fn parses_alternatives_section() {
        let details = "The repo was archived.\n\n## Alternatives\n\nConsider one of:\n\n\
             - [saphyr](https://crates.io/crates/saphyr) \
             ([serde-saphyr](https://crates.io/crates/serde-saphyr) for serde users)\n\
             - [saphyr](https://crates.io/crates/saphyr) again\n\
             - [leftpad](https://registry.npmjs.org/leftpad) elsewhere\n\n\
             ## References\n\n- [old](https://crates.io/crates/ignored)\n";
        assert_eq!(
            parse_alternatives(details),
            vec!["saphyr".to_string(), "serde-saphyr".to_string()]
        );
        assert!(parse_alternatives("no section here").is_empty());
        assert!(parse_alternatives("## Alternatives\nno links\n").is_empty());
    }

    #[test]
    fn parses_alternative_heading_variants() {
        assert_eq!(
            parse_alternatives(
                "## Alternative(s)\n- [`skrifa`](https://crates.io/crates/skrifa)\n"
            ),
            vec!["skrifa".to_string()]
        );
        assert_eq!(
            parse_alternatives("### alternatives\n- [a](https://crates.io/crates/a-crate)\n"),
            vec!["a-crate".to_string()]
        );
    }

    #[test]
    fn falls_back_to_suggestion_lines_when_unmaintained() {
        // Real RUSTSEC-2025-0057 shape: no section, GitHub link in prose.
        let fxhash = "The fxhash crate is no longer maintained.\n\n\
             Please take a look at [rustc-hash](https://github.com/rust-lang/rustc-hash) instead.\n";
        assert_eq!(parse_alternatives(fxhash), vec!["rustc-hash".to_string()]);
        // Same shape but maintained: no fallback.
        let maintained =
            "A bug was fixed.\n\nPlease take a look at [x](https://github.com/o/x) instead.\n";
        assert!(parse_alternatives(maintained).is_empty());
        // Non-crate-looking link text is ignored.
        let prose =
            "Crate is unmaintained.\nConsider [Some Thing](https://github.com/o/repo) instead.\n";
        assert!(parse_alternatives(prose).is_empty());
    }

    #[test]
    fn into_found_resolves_alternatives() {
        let v = OsvVuln {
            id: "RUSTSEC-2024-0449".to_string(),
            summary: Some("unsafe-libyaml is unmaintained".to_string()),
            details: Some(
                "## Alternatives\n- [saphyr](https://crates.io/crates/saphyr)\n".to_string(),
            ),
            aliases: Vec::new(),
            severity: Vec::new(),
            database_specific: None,
            affected: Vec::new(),
        };
        let found = v.into_found("unsafe-libyaml", "0.2.11", |n| {
            assert_eq!(n, "saphyr");
            Some("0.5.0".to_string())
        });
        assert_eq!(
            found.alternatives,
            vec![Alternative {
                name: "saphyr".to_string(),
                latest: Some("0.5.0".to_string()),
            }]
        );
    }
}
