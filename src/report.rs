//! Human and JSON report rendering.

use serde::Serialize;

use crate::ecosystem::{CheckOutcome, Status};

#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    root: &'a str,
    ecosystems: &'a [CheckOutcome],
    summary: JsonSummary,
}

#[derive(Debug, Serialize)]
struct JsonSummary {
    ecosystems: usize,
    ok: usize,
    outdated_deps: usize,
    skipped: usize,
    errors: usize,
}

pub fn summary_counts(outcomes: &[CheckOutcome]) -> (usize, usize, usize, usize) {
    let mut ok = 0;
    let mut outdated = 0;
    let mut skipped = 0;
    let mut errors = 0;
    for o in outcomes {
        match o.status {
            Status::Ok => {
                ok += 1;
                outdated += o.outdated.len();
            }
            Status::Skipped => skipped += 1,
            Status::Error => errors += 1,
        }
    }
    (ok, outdated, skipped, errors)
}

pub fn print_json(root: &str, outcomes: &[CheckOutcome]) {
    let (ok, outdated_deps, skipped, errors) = summary_counts(outcomes);
    let report = JsonReport {
        root,
        ecosystems: outcomes,
        summary: JsonSummary {
            ecosystems: outcomes.len(),
            ok,
            outdated_deps,
            skipped,
            errors,
        },
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

pub fn print_human(root: &str, outcomes: &[CheckOutcome]) {
    println!("freshdeps: {root}");
    println!();
    for o in outcomes {
        match o.status {
            Status::Ok => {
                if o.outdated.is_empty() {
                    match o.checked {
                        Some(n) => println!(
                            "[{}] {}: up to date ({} checked, tool: {})",
                            o.id, o.display, n, o.tool
                        ),
                        None => println!("[{}] {}: up to date (tool: {})", o.id, o.display, o.tool),
                    }
                } else {
                    println!(
                        "[{}] {}: {} outdated (tool: {})",
                        o.id,
                        o.display,
                        o.outdated.len(),
                        o.tool
                    );
                    for d in &o.outdated {
                        match &d.detail {
                            Some(detail) => {
                                println!("  {}  {} -> {}  ({detail})", d.name, d.current, d.latest)
                            }
                            None => println!("  {}  {} -> {}", d.name, d.current, d.latest),
                        }
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
    let (ok, outdated, skipped, errors) = summary_counts(outcomes);
    println!(
        "Summary: {outdated} outdated across {} ecosystem(s) ({ok} ok, {skipped} skipped, {errors} errors)",
        outcomes.len()
    );
}
