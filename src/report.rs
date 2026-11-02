//! Human and JSON report rendering.

use serde::Serialize;

use crate::ecosystem::{CheckOutcome, Status};

#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    root: &'a str,
    projects: Vec<JsonProject<'a>>,
    summary: JsonSummary,
}

#[derive(Debug, Serialize)]
struct JsonProject<'a> {
    root: &'a str,
    ecosystems: &'a [CheckOutcome],
    summary: JsonSummary,
}

#[derive(Debug, Serialize)]
struct JsonSummary {
    ecosystems: usize,
    ok: usize,
    outdated_deps: usize,
    vulnerabilities: usize,
    outdated_tools: usize,
    blocked: usize,
    lint_findings: usize,
    notices: usize,
    gaps: usize,
    skipped: usize,
    errors: usize,
}

impl JsonSummary {
    fn from_counts(counts: &SummaryCounts, ecosystems: usize) -> Self {
        Self {
            ecosystems,
            ok: counts.ok,
            outdated_deps: counts.outdated,
            vulnerabilities: counts.vulns,
            outdated_tools: counts.tools,
            blocked: counts.blocked,
            lint_findings: counts.lint,
            notices: counts.notices,
            gaps: counts.gaps,
            skipped: counts.skipped,
            errors: counts.errors,
        }
    }
}

#[derive(Debug, Default)]
pub struct SummaryCounts {
    pub ok: usize,
    pub outdated: usize,
    pub vulns: usize,
    pub tools: usize,
    pub blocked: usize,
    pub lint: usize,
    pub notices: usize,
    pub gaps: usize,
    pub skipped: usize,
    pub errors: usize,
}

impl std::ops::Add for SummaryCounts {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            ok: self.ok + rhs.ok,
            outdated: self.outdated + rhs.outdated,
            vulns: self.vulns + rhs.vulns,
            tools: self.tools + rhs.tools,
            blocked: self.blocked + rhs.blocked,
            lint: self.lint + rhs.lint,
            notices: self.notices + rhs.notices,
            gaps: self.gaps + rhs.gaps,
            skipped: self.skipped + rhs.skipped,
            errors: self.errors + rhs.errors,
        }
    }
}

pub fn summary_counts(outcomes: &[CheckOutcome]) -> SummaryCounts {
    let mut counts = SummaryCounts::default();
    for o in outcomes {
        match o.status {
            Status::Ok => {
                counts.ok += 1;
                counts.outdated += o.outdated.len();
                counts.vulns += o.vulnerabilities.len();
                counts.tools += o.tools.len();
                counts.blocked += o.blocked.len();
                counts.lint += o.lint.len();
                counts.notices += o.notices.len();
                counts.gaps += o.gaps.len();
            }
            Status::Skipped => counts.skipped += 1,
            Status::Error => counts.errors += 1,
        }
    }
    counts
}

pub fn print_json(root: &str, projects: &[(String, Vec<CheckOutcome>)]) {
    let mut total = SummaryCounts::default();
    let mut rendered = Vec::new();
    for (proj_root, outcomes) in projects {
        let counts = summary_counts(outcomes);
        rendered.push(JsonProject {
            root: proj_root,
            ecosystems: outcomes,
            summary: JsonSummary::from_counts(&counts, outcomes.len()),
        });
        total = total + counts;
    }
    let report = JsonReport {
        root,
        projects: rendered,
        summary: JsonSummary::from_counts(&total, projects.iter().map(|(_, o)| o.len()).sum()),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

pub fn print_human(projects: &[(String, Vec<CheckOutcome>)]) {
    for (i, (root, outcomes)) in projects.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print_project(root, outcomes);
    }
    if projects.len() > 1 {
        let total = projects
            .iter()
            .map(|(_, o)| summary_counts(o))
            .fold(SummaryCounts::default(), |a, b| a + b);
        println!();
        println!(
            "Total across {} projects: {} outdated, {} vulnerabilities, {} tools outdated, {} blocked, {} notices, {} lint findings, {} unchecked ({} ok, {} skipped, {} errors)",
            projects.len(),
            total.outdated,
            total.vulns,
            total.tools,
            total.blocked,
            total.notices,
            total.lint,
            total.gaps,
            total.ok,
            total.skipped,
            total.errors
        );
    }
}

fn print_project(root: &str, outcomes: &[CheckOutcome]) {
    println!("depaudit: {root}");
    println!();
    for o in outcomes {
        match o.status {
            Status::Ok => {
                println!(
                    "[{}] {}: {} outdated, {} vulnerabilities, {} tools outdated, {} blocked, {} notices, {} lint findings, {} unchecked ({} checked)",
                    o.id,
                    o.display,
                    o.outdated.len(),
                    o.vulnerabilities.len(),
                    o.tools.len(),
                    o.blocked.len(),
                    o.notices.len(),
                    o.lint.len(),
                    o.gaps.len(),
                    o.checked,
                );
                if !o.outdated.is_empty() {
                    println!("  outdated:");
                    for d in &o.outdated {
                        let mut line = format!(
                            "    {}  {} -> {}",
                            d.name,
                            ver(&d.current, &d.current_released),
                            ver(&d.latest, &d.latest_released)
                        );
                        if let Some(days) = days_note(&d.days_behind) {
                            line.push_str(&format!("  {days}"));
                        }
                        let mut notes = Vec::new();
                        if let Some(detail) = &d.detail {
                            notes.push(detail.clone());
                        }
                        if let Some(b) = &d.blocked {
                            notes.push(format!(
                                "latest {} needs compileSdk {}",
                                b.latest, b.min_compile_sdk
                            ));
                        }
                        if let Some(reason) = &d.stale {
                            notes.push(format!("stale cache: {reason}"));
                        }
                        if !notes.is_empty() {
                            line.push_str(&format!("  ({})", notes.join("; ")));
                        }
                        println!("{line}");
                    }
                }
                if let Some(cmd) = &o.update_command {
                    println!("  update: {cmd}");
                }
                if !o.blocked.is_empty() {
                    println!("  blocked (need newer compileSdk):");
                    for b in &o.blocked {
                        let mut line = format!(
                            "    {}  {}  (latest {} needs compileSdk {})",
                            b.name,
                            ver(&b.current, &b.current_released),
                            ver(&b.latest, &b.latest_released),
                            b.min_compile_sdk
                        );
                        if let Some(days) = days_note(&b.days_behind) {
                            line.push_str(&format!("  {days}"));
                        }
                        println!("{line}");
                    }
                }
                if !o.vulnerabilities.is_empty() {
                    println!("  vulnerabilities:");
                    for v in &o.vulnerabilities {
                        let id = preferred_id(v);
                        let mut header = format!("    {} {}  {id}", v.name, v.version);
                        if let Some(sev) = &v.severity {
                            header.push_str(&format!("  ({sev})"));
                        }
                        if let Some(fixed) = &v.fixed {
                            header.push_str(&format!("  fixed in {fixed}"));
                        }
                        println!("{header}");
                        println!("      {}", truncate(&v.summary, 160));
                        if !v.alternatives.is_empty() {
                            let list = v
                                .alternatives
                                .iter()
                                .map(|a| match &a.latest {
                                    Some(latest) => format!("{} {latest}", a.name),
                                    None => a.name.clone(),
                                })
                                .collect::<Vec<_>>()
                                .join(", ");
                            println!("      alternatives: {list}");
                        }
                    }
                }
                if !o.tools.is_empty() {
                    println!("  tools:");
                    for d in &o.tools {
                        match &d.detail {
                            Some(detail) => {
                                println!(
                                    "    {}  {} -> {}  ({detail})",
                                    d.name, d.current, d.latest
                                )
                            }
                            None => println!("    {}  {} -> {}", d.name, d.current, d.latest),
                        }
                    }
                }
                if !o.notices.is_empty() {
                    println!("  notices:");
                    for n in &o.notices {
                        println!("    {}", notice_line(n));
                    }
                }
                if !o.lint.is_empty() {
                    println!("  lint:");
                    for f in &o.lint {
                        println!("    {}", lint_line(f));
                    }
                }
                if !o.gaps.is_empty() {
                    println!("  could not check:");
                    for g in &o.gaps {
                        let check = match g.check {
                            crate::ecosystem::GapCheck::Outdated => "outdated",
                            crate::ecosystem::GapCheck::Vulns => "vulns",
                            crate::ecosystem::GapCheck::Lint => "lint",
                        };
                        println!("    {} ({check}): {}", g.name, g.reason);
                    }
                }
                if let Some(msg) = &o.message {
                    println!("  note: {msg}");
                }
            }
            Status::Skipped => {
                println!("[{}] {}: skipped", o.id, o.display);
                if let Some(msg) = &o.message {
                    println!("  {msg}");
                }
            }
            Status::Error => {
                println!("[{}] {}: ERROR", o.id, o.display);
                if let Some(msg) = &o.message {
                    println!("  {msg}");
                }
            }
        }
        println!();
    }
    let counts = summary_counts(outcomes);
    println!(
        "Summary: {} outdated, {} vulnerabilities, {} tools outdated, {} blocked, {} notices, {} lint findings, {} unchecked across {} ecosystem(s) ({} ok, {} skipped, {} errors)",
        counts.outdated,
        counts.vulns,
        counts.tools,
        counts.blocked,
        counts.notices,
        counts.lint,
        counts.gaps,
        outcomes.len(),
        counts.ok,
        counts.skipped,
        counts.errors
    );
}

/// One lint finding: `src/a.py:12  [F401] message  (ruff)`, with the
/// column when known, every merged rule and source, and an `[error]` /
/// `[info]` marker (warnings are unmarked).
fn lint_line(f: &crate::lint::LintFinding) -> String {
    let mut line = f.file.clone();
    if let Some(n) = f.line {
        line.push_str(&format!(":{n}"));
        if let Some(c) = f.column {
            line.push_str(&format!(":{c}"));
        }
    }
    line.push_str("  ");
    if !f.rules.is_empty() {
        line.push_str(&format!("[{}] ", f.rules.join(", ")));
    }
    line.push_str(&truncate(&f.message, 160));
    line.push_str(&format!("  ({})", f.sources.join(", ")));
    match f.severity {
        crate::lint::Severity::Error => line.push_str("  [error]"),
        crate::lint::Severity::Info => line.push_str("  [info]"),
        crate::lint::Severity::Warning => {}
    }
    line
}

/// One notice: `django  3.2 is end-of-life since 2024-04-01  (eol)`,
/// or `file:line  message  (check)` for source-level analyses.
fn notice_line(n: &crate::ecosystem::Notice) -> String {
    let subject = match (&n.file, n.line) {
        (Some(f), Some(l)) => format!("{f}:{l}"),
        (Some(f), None) => f.clone(),
        _ => n.name.clone(),
    };
    let check = match n.check {
        crate::ecosystem::NoticeCheck::Licenses => "licenses",
        crate::ecosystem::NoticeCheck::Yanked => "yanked",
        crate::ecosystem::NoticeCheck::Eol => "eol",
        crate::ecosystem::NoticeCheck::Bloat => "bloat",
        crate::ecosystem::NoticeCheck::LicenseChange => "license-change",
        crate::ecosystem::NoticeCheck::Ghost => "ghost",
        crate::ecosystem::NoticeCheck::Drift => "drift",
        crate::ecosystem::NoticeCheck::Secrets => "secrets",
        crate::ecosystem::NoticeCheck::Crypto => "crypto",
        crate::ecosystem::NoticeCheck::DeadCode => "dead-code",
    };
    format!("{subject}  {}  ({check})", truncate(&n.message, 200))
}

/// One version with its release date: `1.0.229(2026-07-18)`, or bare when
/// the date is unknown.
fn ver(version: &str, date: &Option<String>) -> String {
    match date {
        Some(d) => format!("{version}({d})"),
        None => version.to_string(),
    }
}

/// Trailing day gap between the two releases: `(167d)`.
fn days_note(days: &Option<i64>) -> Option<String> {
    days.map(|d| format!("({d}d)"))
}

/// Prefer a CVE alias for display, else the OSV id.
fn preferred_id(v: &crate::osv::FoundVuln) -> String {
    if let Some(cve) = v.aliases.iter().find(|a| a.starts_with("CVE-")) {
        if v.aliases.len() > 1 || cve != &v.id {
            return format!("{cve} ({})", v.id);
        }
        return cve.clone();
    }
    if v.aliases.is_empty() {
        v.id.clone()
    } else {
        format!("{} ({})", v.id, v.aliases.join(", "))
    }
}

fn truncate(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let cut: String = flat.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn versions_carry_their_own_dates() {
        assert_eq!(
            ver("1.0.229", &some("2026-07-18")),
            "1.0.229(2026-07-18)".to_string()
        );
        assert_eq!(ver("1.0.229", &None), "1.0.229".to_string());
        assert_eq!(days_note(&Some(167)), Some("(167d)".to_string()));
        assert_eq!(days_note(&None), None);
    }

    #[test]
    fn lint_lines_show_rules_sources_and_errors() {
        use crate::lint::{LintFinding, Severity};
        let finding = LintFinding {
            file: "src/a.py".to_string(),
            line: Some(12),
            column: Some(8),
            message: "`os` imported but unused".to_string(),
            rules: vec!["F401".to_string()],
            sources: vec!["ruff".to_string()],
            severity: Severity::Warning,
        };
        assert_eq!(
            lint_line(&finding),
            "src/a.py:12:8  [F401] `os` imported but unused  (ruff)"
        );
        let merged = LintFinding {
            file: "a.kt".to_string(),
            line: Some(3),
            column: None,
            message: "missing newline".to_string(),
            rules: vec!["final-newline".to_string(), "NoNewline".to_string()],
            sources: vec!["ktlint".to_string(), "detekt".to_string()],
            severity: Severity::Error,
        };
        assert_eq!(
            lint_line(&merged),
            "a.kt:3  [final-newline, NoNewline] missing newline  (ktlint, detekt)  [error]"
        );
    }

    #[test]
    fn notice_lines_show_subject_message_and_check() {
        use crate::ecosystem::{Notice, NoticeCheck};
        let dep = Notice {
            check: NoticeCheck::Yanked,
            name: "serde".to_string(),
            message: "1.0.100 is yanked on crates.io".to_string(),
            file: None,
            line: None,
        };
        assert_eq!(
            notice_line(&dep),
            "serde  1.0.100 is yanked on crates.io  (yanked)"
        );
        let src = Notice {
            check: NoticeCheck::Licenses,
            name: String::new(),
            message: "license could not be determined".to_string(),
            file: Some("a.py".to_string()),
            line: Some(3),
        };
        assert_eq!(
            notice_line(&src),
            "a.py:3  license could not be determined  (licenses)"
        );
    }
}
