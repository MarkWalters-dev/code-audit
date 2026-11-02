//! Rust ecosystem: `cargo-outdated` over Cargo.toml.
//!
//! Installs via `cargo install cargo-outdated` when missing. Defaults to root
//! (direct) dependencies; `--deep` checks the full dependency tree.

use std::path::Path;

use serde::Deserialize;

use crate::ecosystem::{CheckOutcome, Ctx, EcosystemChecker, OutdatedDep};
use crate::{exec, install};

pub struct RustLang;

impl EcosystemChecker for RustLang {
    fn id(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("Cargo.toml").is_file()
    }

    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome {
        let cargo = match exec::resolve_tool("cargo") {
            Some(c) => c,
            None => {
                return CheckOutcome::error(
                    "rust",
                    "Rust",
                    "cargo-outdated",
                    "cargo is not installed; install the Rust toolchain from https://rustup.rs/ and re-run.",
                );
            }
        };
        if !has_cargo_outdated(&cargo, root, ctx.verbose) {
            let cmdline = "cargo install cargo-outdated";
            if !install::wants_install(ctx.install_policy, "cargo-outdated", cmdline) {
                return CheckOutcome::skipped(
                    "rust",
                    "Rust",
                    "cargo-outdated",
                    install::skipped_msg("cargo-outdated", cmdline),
                );
            }
            let ok = install::run_install(
                &cargo,
                &["install".to_string(), "cargo-outdated".to_string()],
                root,
                ctx.verbose,
            );
            match ok {
                Ok(true) => {}
                _ => {
                    return CheckOutcome::error(
                        "rust",
                        "Rust",
                        "cargo-outdated",
                        "`cargo install cargo-outdated` failed; see output above.",
                    );
                }
            }
        }

        let manifest = root.join("Cargo.toml");
        let mut args = vec![
            "outdated".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--manifest-path".to_string(),
            manifest.to_string_lossy().into_owned(),
        ];
        if manifest_is_workspace(&manifest) {
            args.push("--workspace".to_string());
        } else if !ctx.deep {
            args.push("--root-deps-only".to_string());
        }
        match exec::run(&cargo, &args, root, &Default::default(), ctx.verbose) {
            Ok(out) if out.success => match parse_outdated_json(&out.stdout) {
                Ok(deps) => CheckOutcome::ok("rust", "Rust", "cargo-outdated", deps),
                Err(e) => CheckOutcome::error(
                    "rust",
                    "Rust",
                    "cargo-outdated",
                    format!(
                        "could not parse cargo-outdated output: {e}. stderr: {}",
                        first_lines(&out.stderr, 3)
                    ),
                ),
            },
            Ok(out) => CheckOutcome::error(
                "rust",
                "Rust",
                "cargo-outdated",
                format!(
                    "cargo-outdated exited with code {:?}: {}",
                    out.code,
                    first_lines(&out.stderr, 5)
                ),
            ),
            Err(e) => CheckOutcome::error("rust", "Rust", "cargo-outdated", format!("{e:#}")),
        }
    }
}

fn has_cargo_outdated(cargo: &str, cwd: &Path, verbose: bool) -> bool {
    if exec::resolve_tool("cargo-outdated").is_some() {
        return true;
    }
    matches!(
        exec::run(
            cargo,
            &["outdated".to_string(), "--version".to_string()],
            cwd,
            &Default::default(),
            verbose,
        ),
        Ok(o) if o.success
    )
}

fn manifest_is_workspace(manifest: &Path) -> bool {
    std::fs::read_to_string(manifest)
        .map(|s| s.lines().any(|l| l.trim() == "[workspace]"))
        .unwrap_or(false)
}

#[derive(Debug, Deserialize)]
struct OutdatedReport {
    #[allow(dead_code)]
    crate_name: Option<String>,
    dependencies: Vec<OutdatedEntry>,
}

#[derive(Debug, Deserialize)]
struct OutdatedEntry {
    name: String,
    project: String,
    compat: String,
    latest: String,
    kind: String,
}

fn parse_outdated_json(stdout: &str) -> Result<Vec<OutdatedDep>, String> {
    let report: OutdatedReport =
        serde_json::from_str(stdout).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(report
        .dependencies
        .into_iter()
        .filter(|d| d.latest != "---" && d.latest != d.project)
        .map(|d| {
            let mut detail = format!("kind: {}", d.kind.to_lowercase());
            if d.compat != "---" && d.compat != d.project && d.compat != d.latest {
                detail.push_str(&format!(", compatible: {}", d.compat));
            }
            OutdatedDep {
                name: d.name,
                current: d.project,
                latest: d.latest,
                detail: Some(detail),
            }
        })
        .collect())
}

fn first_lines(s: &str, n: usize) -> String {
    s.lines().take(n).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_outdated_report() {
        let json = r#"{"crate_name":"rustproj","dependencies":[
            {"name":"serde","project":"1.0.100","compat":"---","latest":"1.0.229","kind":"Normal","platform":null},
            {"name":"fresh","project":"2.0.0","compat":"2.0.0","latest":"2.0.0","kind":"Normal","platform":null}
        ]}"#;
        let deps = parse_outdated_json(json).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].current, "1.0.100");
        assert_eq!(deps[0].latest, "1.0.229");
    }
}
