mod android;
mod cli;
mod ecosystem;
mod exec;
mod golang;
mod install;
mod node;
mod python;
mod report;
mod rustlang;
mod version;

use std::path::PathBuf;

use clap::Parser;

use crate::ecosystem::{Ctx, all_checkers, canonical_id};
use crate::install::InstallPolicy;

fn main() {
    let args = cli::Args::parse();
    std::process::exit(run(args));
}

fn run(args: cli::Args) -> i32 {
    let root = PathBuf::from(&args.path);
    if !root.is_dir() {
        eprintln!("freshdeps: {} is not a directory", root.display());
        return 2;
    }
    let root_display = root.canonicalize().unwrap_or(root.clone());
    let root_str = root_display.to_string_lossy().into_owned();

    let only: Vec<&str> = match resolve_ids(&args.only, "--only") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let exclude: Vec<&str> = match resolve_ids(&args.exclude, "--exclude") {
        Ok(v) => v,
        Err(code) => return code,
    };

    let install_policy = if args.no_install {
        InstallPolicy::Never
    } else if args.yes {
        InstallPolicy::Auto
    } else {
        InstallPolicy::Prompt
    };
    let ctx = Ctx {
        install_policy,
        verbose: args.verbose,
        deep: args.deep,
    };

    let checkers = all_checkers();
    let mut selected: Vec<&dyn ecosystem::EcosystemChecker> = checkers
        .iter()
        .map(|c| c.as_ref())
        .filter(|c| {
            (only.is_empty() || only.contains(&c.id()))
                && !exclude.contains(&c.id())
                && c.detect(&root)
        })
        .collect();
    // Keep registry order for a stable report.
    selected.sort_by_key(|c| checker_order(c.id()));

    if selected.is_empty() {
        if only.is_empty() && exclude.is_empty() {
            eprintln!(
                "freshdeps: no supported project detected in {root_str} (looked for Python, JavaScript, Rust, Go, Android markers)"
            );
        } else {
            eprintln!("freshdeps: no selected ecosystem detected in {root_str}");
        }
        return 2;
    }

    // Ecosystems are independent (separate tools, separate files): check in parallel.
    let mut outcomes = std::thread::scope(|s| {
        let handles: Vec<_> = selected
            .iter()
            .map(|c| s.spawn(|| c.check(&ctx, &root)))
            .collect();
        handles.into_iter().map(|h| h.join()).collect::<Vec<_>>()
    })
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap_or_default();
    outcomes.sort_by_key(|o| checker_order(o.id));

    if args.json {
        report::print_json(&root_str, &outcomes);
    } else {
        report::print_human(&root_str, &outcomes);
    }

    if args.fail_on_outdated {
        let (_, outdated, _, _) = report::summary_counts(&outcomes);
        if outdated > 0 {
            return 1;
        }
    }
    0
}

fn checker_order(id: &str) -> usize {
    match id {
        "python" => 0,
        "node" => 1,
        "rust" => 2,
        "go" => 3,
        "android" => 4,
        _ => 99,
    }
}

fn resolve_ids(raw: &[String], flag: &str) -> Result<Vec<&'static str>, i32> {
    let mut out = Vec::new();
    for item in raw {
        match canonical_id(item) {
            Some(id) => {
                if !out.contains(&id) {
                    out.push(id);
                }
            }
            None => {
                eprintln!(
                    "freshdeps: unknown ecosystem `{item}` in {flag} (expected: python, node, rust, go, android)"
                );
                return Err(2);
            }
        }
    }
    Ok(out)
}
