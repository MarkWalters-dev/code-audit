mod android;
mod cache;
mod cli;
mod config;
mod dates;
mod deadcode;
mod discover;
mod ecosystem;
mod ghost;
mod golang;
mod http;
mod licenses;
mod lint;
mod node;
mod osv;
mod progress;
mod python;
mod report;
mod rustlang;
mod sbom;
mod secrets;
mod toolchains;
mod version;

use std::path::PathBuf;

use clap::Parser;

use crate::ecosystem::{Ctx, all_checkers, canonical_id};

fn main() {
    let args = cli::Args::parse();
    std::process::exit(run(args));
}

fn run(args: cli::Args) -> i32 {
    let root = PathBuf::from(&args.path);
    if !root.is_dir() {
        eprintln!("depaudit: {} is not a directory", root.display());
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

    http::set_verbose(args.verbose);
    progress::set_quiet(args.quiet);
    let started = progress::start();
    let cache = match cache::Cache::load(!args.no_cache, cache::TTL_VERSIONS_SECS) {
        Ok(cache) => std::sync::Arc::new(cache),
        // Foreign or unreadable cache format: exit, never corrupt it.
        Err(e) => {
            eprintln!("depaudit: {e}");
            return cache::EXIT_CACHE_MISMATCH;
        }
    };
    if args.clear_cache {
        cache.clear();
    }

    let checkers = all_checkers();
    let projects = discover::discover_projects(&root, &|dir| {
        checkers
            .iter()
            .filter(|c| (only.is_empty() || only.contains(&c.id())) && !exclude.contains(&c.id()))
            .filter(|c| c.detect(dir))
            .map(|c| c.id())
            .collect()
    });
    if projects.is_empty() {
        if only.is_empty() && exclude.is_empty() {
            eprintln!(
                "depaudit: no supported project detected in {root_str} or its subdirectories (looked for Python, JavaScript, Rust, Go, Android markers)"
            );
        } else {
            eprintln!(
                "depaudit: no selected ecosystem detected in {root_str} or its subdirectories"
            );
        }
        return 2;
    }

    let mut reports: Vec<(String, Vec<ecosystem::CheckOutcome>)> = Vec::new();
    progress::discovered(projects.len());
    for (i, proj) in projects.iter().enumerate() {
        let proj_str = proj
            .root
            .canonicalize()
            .unwrap_or(proj.root.clone())
            .to_string_lossy()
            .into_owned();
        progress::project(i + 1, projects.len(), &proj_str);
        let file_config = match config::load(&proj.root) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("depaudit: {e}");
                return 2;
            }
        };
        cache.set_versions_ttl(
            file_config
                .cache
                .versions_ttl_hours
                .map(|h| h.saturating_mul(3600))
                .unwrap_or(cache::TTL_VERSIONS_SECS),
        );
        // Precedence: CLI flag, config file, auto-detected compileSdk.
        let (sdk_cap, sdk_source): (Option<u32>, Option<&str>) = {
            if let Some(v) = args.max_compile_sdk {
                (Some(v), Some("--max-compile-sdk"))
            } else if let Some(v) = file_config.android.max_compile_sdk {
                (Some(v), Some("depaudit.toml"))
            } else if let Some(v) = android::detect_compile_sdk(&proj.root) {
                (Some(v), Some("auto-detected compileSdk"))
            } else {
                (None, None)
            }
        };
        let lint_config_order = match &file_config.lint.config_order {
            None => lint::DEFAULT_ORDER,
            Some(order) => match lint::parse_order(order) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!(
                        "depaudit: {}: {e}",
                        proj.root.join("depaudit.toml").display()
                    );
                    return 2;
                }
            },
        };
        let ctx = Ctx {
            verbose: args.verbose,
            deep: args.deep,
            check_outdated: (!args.vulns_only && !args.lint_only) || args.sbom,
            check_vulns: (!args.outdated_only && !args.lint_only) || args.sbom,
            cache: cache.clone(),
            android_sdk_cap: sdk_cap,
            lint: !args.no_lint && !args.sbom && file_config.lint.enabled != Some(false),
            lint_config_order,
            check_notices: (!args.outdated_only && !args.vulns_only && !args.lint_only
                || args.sbom)
                && file_config.licenses.enabled != Some(false),
            license_policy: licenses::Policy::from_config(file_config.licenses.deny.clone()),
        };
        let mut selected: Vec<&dyn ecosystem::EcosystemChecker> = checkers
            .iter()
            .map(|c| c.as_ref())
            .filter(|c| proj.ecosystems.contains(&c.id()))
            .collect();
        // Keep registry order for a stable report.
        selected.sort_by_key(|c| checker_order(c.id()));

        if args.verbose && selected.iter().any(|c| c.id() == "android") {
            match (sdk_cap, sdk_source) {
                (Some(cap), Some(source)) => {
                    eprintln!("[android] compileSdk cap: {cap} ({source})");
                }
                _ => eprintln!("[android] no compileSdk cap"),
            }
        }

        // Ecosystems are independent: audit in parallel.
        let mut outcomes = std::thread::scope(|s| {
            let handles: Vec<_> = selected
                .iter()
                .map(|c| s.spawn(|| c.check(&ctx, &proj.root)))
                .collect();
            handles.into_iter().map(|h| h.join()).collect::<Vec<_>>()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
        outcomes.sort_by_key(|o| checker_order(o.id));
        // Project-level notices (toolchain drift, secrets, zombie
        // assets): attached to the first ecosystem outcome so they render
        // in its `notices:` section.
        if ctx.check_notices {
            let mut extra = toolchains::drift_notices(&proj.root);
            extra.extend(secrets::scan_project(&proj.root));
            extra.extend(deadcode::zombie_assets(&proj.root));
            if !extra.is_empty()
                && let Some(first) = outcomes.first_mut()
            {
                first.notices.append(&mut extra);
                first
                    .notices
                    .sort_by(|a, b| (&a.check, &a.name).cmp(&(&b.check, &b.name)));
            }
        }
        reports.push((proj_str, outcomes));
    }

    if args.sbom {
        sbom::print(&cache, &checkers, &reports, &root_str);
    } else if args.json {
        report::print_json(&root_str, &reports);
    } else {
        report::print_human(&reports);
    }
    cache.save();
    if args.verbose && !args.no_cache {
        let (hits, misses) = cache.stats();
        eprintln!(
            "cache: {hits} hits, {misses} misses, {} stale ({})",
            cache.stale_count(),
            cache.path().display()
        );
    }

    progress::done(started);
    if args.fail_on_outdated || args.fail_on_vulns {
        let counts = reports
            .iter()
            .map(|(_, o)| report::summary_counts(o))
            .fold(report::SummaryCounts::default(), |a, b| a + b);
        if (args.fail_on_outdated && counts.outdated + counts.tools > 0)
            || (args.fail_on_vulns && counts.vulns > 0)
        {
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
                    "depaudit: unknown ecosystem `{item}` in {flag} (expected: python, node, rust, go, android)"
                );
                return Err(2);
            }
        }
    }
    Ok(out)
}
