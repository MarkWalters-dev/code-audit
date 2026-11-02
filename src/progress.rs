//! Run progress on stderr: what depaudit is doing right now. Long
//! audits (cold caches, big monorepos, JVM linters) otherwise sit silent
//! for minutes, which reads as hung. Everything here goes to stderr so
//! `--json` and `--sbom` stdout stay machine-clean; `--quiet` silences it.
//!
//! Lines are plain text, one `eprintln!` each (no cursor control), so they
//! degrade gracefully into logs and CI output. Parallel ecosystem checks
//! may interleave lines; each line is complete on its own.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static QUIET: AtomicBool = AtomicBool::new(false);

/// Silence all progress output (`--quiet`).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

fn silent() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Started timing the whole run.
pub fn start() -> Instant {
    Instant::now()
}

/// Discovery finished: N projects to audit.
pub fn discovered(projects: usize) {
    if silent() {
        return;
    }
    match projects {
        0 => eprintln!("depaudit: no projects found"),
        1 => eprintln!("depaudit: 1 project found"),
        n => eprintln!("depaudit: {n} projects found"),
    }
}

/// Starting project i of n.
pub fn project(i: usize, n: usize, path: &str) {
    if silent() {
        return;
    }
    if n > 1 {
        eprintln!("depaudit: [{i}/{n}] {path}");
    } else {
        eprintln!("depaudit: {path}");
    }
}

/// An ecosystem check starting, with its dependency count.
pub fn checking(id: &str, deps: usize) {
    if silent() {
        return;
    }
    match deps {
        1 => eprintln!("[{id}] checking 1 dependency..."),
        n => eprintln!("[{id}] checking {n} dependencies..."),
    }
}

/// An ecosystem check skipped or failed before doing work.
pub fn skipped(id: &str, reason: &str) {
    if silent() {
        return;
    }
    eprintln!("[{id}] skipped ({reason})");
}

/// Lint phase starting for an ecosystem.
pub fn linting(id: &str) {
    if silent() {
        return;
    }
    eprintln!("[{id}] linting...");
}

/// A single linter starting (slow ones also announce completion).
pub fn linter(id: &str, tool: &str) {
    if silent() {
        return;
    }
    eprintln!("[{id}] linting with {tool}...");
}

/// An ecosystem check finished, with its finding counts.
#[allow(clippy::too_many_arguments)]
pub fn finished(
    id: &str,
    outdated: usize,
    vulns: usize,
    notices: usize,
    lint: usize,
    gaps: usize,
    started: Instant,
) {
    if silent() {
        return;
    }
    eprintln!(
        "[{id}] done in {:.1}s: {outdated} outdated, {vulns} vulnerabilities, {notices} notices, {lint} lint findings, {gaps} unchecked",
        started.elapsed().as_secs_f32(),
    );
}

/// Freeform progress line (installs, slow tools). Callers include
/// their own `depaudit: ` prefix.
pub fn note(msg: &str) {
    if silent() {
        return;
    }
    eprintln!("{msg}");
}

/// Whole run finished.
pub fn done(started: Instant) {
    if silent() {
        return;
    }
    let secs = started.elapsed().as_secs_f32();
    if secs >= 1.0 {
        eprintln!("depaudit: done in {secs:.1}s");
    } else {
        eprintln!("depaudit: done");
    }
}
