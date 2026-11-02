//! JavaScript/TypeScript ecosystem: `npm-check-updates` (ncu) over package.json.
//!
//! Install preference follows the package manager in use: pnpm first
//! (`pnpm add -g npm-check-updates`), then npm. When installation is declined
//! or impossible, a one-shot `pnpm dlx` / `npx` run is used instead so the
//! check still works without touching global state.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::ecosystem::{CheckOutcome, Ctx, EcosystemChecker, OutdatedDep};
use crate::{exec, install};

pub struct Node;

impl EcosystemChecker for Node {
    fn id(&self) -> &'static str {
        "node"
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("package.json").is_file()
    }

    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome {
        let manifest = match read_manifest(root) {
            Ok(m) => m,
            Err(e) => {
                return CheckOutcome::error("node", "JavaScript", "npm-check-updates", e);
            }
        };
        let declared = manifest.all_specs();
        if declared.is_empty() {
            let mut outcome =
                CheckOutcome::ok("node", "JavaScript", "npm-check-updates", Vec::new());
            outcome.checked = Some(0);
            return outcome;
        }

        let invocation = match ensure_ncu(ctx, root) {
            Ok(inv) => inv,
            Err(reason) => {
                return CheckOutcome::skipped("node", "JavaScript", "npm-check-updates", reason);
            }
        };
        let mut args = invocation.args;
        args.push("--jsonUpgraded".to_string());
        match exec::run(
            &invocation.program,
            &args,
            root,
            &Default::default(),
            ctx.verbose,
        ) {
            Ok(out) if out.success => match parse_json_upgraded(&out.stdout) {
                Ok(upgrades) => {
                    let outdated: Vec<OutdatedDep> = upgrades
                        .into_iter()
                        .map(|(name, latest)| {
                            let current = declared
                                .get(&name)
                                .cloned()
                                .unwrap_or_else(|| "?".to_string());
                            OutdatedDep {
                                name,
                                current,
                                latest,
                                detail: None,
                            }
                        })
                        .collect();
                    let mut outcome =
                        CheckOutcome::ok("node", "JavaScript", "npm-check-updates", outdated);
                    outcome.checked = Some(declared.len());
                    outcome
                }
                Err(e) => CheckOutcome::error(
                    "node",
                    "JavaScript",
                    "npm-check-updates",
                    format!(
                        "could not parse ncu output: {e}. stderr: {}",
                        first_lines(&out.stderr, 3)
                    ),
                ),
            },
            Ok(out) => CheckOutcome::error(
                "node",
                "JavaScript",
                "npm-check-updates",
                format!(
                    "ncu exited with code {:?}: {}",
                    out.code,
                    first_lines(&out.stderr, 5)
                ),
            ),
            Err(e) => {
                CheckOutcome::error("node", "JavaScript", "npm-check-updates", format!("{e:#}"))
            }
        }
    }
}

struct Invocation {
    program: String,
    args: Vec<String>,
}

/// Ensure `ncu` is runnable: installed binary first, else global install via
/// pnpm/npm when allowed, else a one-shot dlx/npx invocation.
fn ensure_ncu(ctx: &Ctx, root: &Path) -> Result<Invocation, String> {
    if let Some(ncu) = exec::resolve_tool("ncu") {
        return Ok(Invocation {
            program: ncu,
            args: Vec::new(),
        });
    }
    let pnpm = exec::resolve_tool("pnpm");
    let npm = exec::resolve_tool("npm");

    // Preferred: global install via pnpm, then npm.
    let install_via = if pnpm.is_some() {
        pnpm.clone().map(|p| {
            (
                p,
                vec![
                    "add".to_string(),
                    "-g".to_string(),
                    "npm-check-updates".to_string(),
                ],
            )
        })
    } else {
        None
    }
    .or_else(|| {
        npm.clone().map(|p| {
            (
                p,
                vec![
                    "install".to_string(),
                    "-g".to_string(),
                    "npm-check-updates".to_string(),
                ],
            )
        })
    });

    if let Some((program, args)) = install_via {
        let cmdline = if pnpm.is_some() {
            "pnpm add -g npm-check-updates".to_string()
        } else {
            "npm install -g npm-check-updates".to_string()
        };
        if install::wants_install(ctx.install_policy, "npm-check-updates", &cmdline) {
            let ok = install::run_install(&program, &args, root, ctx.verbose)
                .map_err(|e| format!("{e:#}"))?;
            if ok && let Some(ncu) = install::resolve_after_install("ncu") {
                return Ok(Invocation {
                    program: ncu,
                    args: Vec::new(),
                });
            }
            if ctx.verbose {
                eprintln!("global ncu install failed; falling back to one-shot dlx/npx");
            }
        } else if ctx.verbose {
            eprintln!("ncu install declined; falling back to one-shot dlx/npx");
        }
    }

    // One-shot fallback: no global state touched.
    if let Some(pnpm) = pnpm {
        return Ok(Invocation {
            program: pnpm,
            args: vec!["dlx".to_string(), "npm-check-updates".to_string()],
        });
    }
    if npm.is_some() {
        let npx = exec::resolve_tool("npx").unwrap_or_else(|| "npx".to_string());
        return Ok(Invocation {
            program: npx,
            args: vec!["-y".to_string(), "npm-check-updates".to_string()],
        });
    }
    Err("no ncu binary and no pnpm/npm/npx to run it with. Install Node.js (https://nodejs.org/) and re-run.".to_string())
}

#[derive(Debug, Default, Deserialize)]
struct Manifest {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies: HashMap<String, String>,
    #[serde(rename = "peerDependencies", default)]
    peer_dependencies: HashMap<String, String>,
    #[serde(rename = "optionalDependencies", default)]
    optional_dependencies: HashMap<String, String>,
}

impl Manifest {
    fn all_specs(&self) -> HashMap<String, String> {
        let mut all = HashMap::new();
        for map in [
            &self.dependencies,
            &self.dev_dependencies,
            &self.peer_dependencies,
            &self.optional_dependencies,
        ] {
            for (k, v) in map {
                all.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        all
    }
}

fn read_manifest(root: &Path) -> Result<Manifest, String> {
    let raw = std::fs::read_to_string(root.join("package.json"))
        .map_err(|e| format!("cannot read package.json: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid package.json: {e}"))
}

/// Parse `ncu --jsonUpgraded`: `{"dep": "newVersion", ...}`. ncu prints pure
/// JSON to stdout; be tolerant of stray log lines by slicing to the braces.
fn parse_json_upgraded(stdout: &str) -> Result<Vec<(String, String)>, String> {
    let start = stdout
        .find('{')
        .ok_or_else(|| "empty ncu output".to_string())?;
    let end = stdout
        .rfind('}')
        .ok_or_else(|| "empty ncu output".to_string())?;
    let map: HashMap<String, String> =
        serde_json::from_str(&stdout[start..=end]).map_err(|e| format!("invalid JSON: {e}"))?;
    let mut upgrades: Vec<(String, String)> = map.into_iter().collect();
    upgrades.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(upgrades)
}

fn first_lines(s: &str, n: usize) -> String {
    s.lines().take(n).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_upgraded() {
        let upgrades = parse_json_upgraded("{\n  \"is-odd\": \"3.0.1\"\n}\n").unwrap();
        assert_eq!(upgrades, vec![("is-odd".to_string(), "3.0.1".to_string())]);
        assert!(parse_json_upgraded("{}\n").unwrap().is_empty());
    }

    #[test]
    fn manifest_specs_merge() {
        let m: Manifest = serde_json::from_str(
            r#"{"dependencies":{"a":"^1.0.0"},"devDependencies":{"b":"2.0.0"}}"#,
        )
        .unwrap();
        let specs = m.all_specs();
        assert_eq!(specs.get("a").unwrap(), "^1.0.0");
        assert_eq!(specs.get("b").unwrap(), "2.0.0");
    }
}
