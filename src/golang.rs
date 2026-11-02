//! Go ecosystem: the toolchain's own `go list -u -m -json all`.
//!
//! No third-party app is needed; the check only requires the Go toolchain.
//! Direct dependencies are reported by default, indirect ones with `--deep`.

use std::path::Path;

use serde::Deserialize;

use crate::ecosystem::{CheckOutcome, Ctx, EcosystemChecker, OutdatedDep};
use crate::exec;

pub struct GoLang;

impl EcosystemChecker for GoLang {
    fn id(&self) -> &'static str {
        "go"
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("go.mod").is_file()
    }

    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome {
        let go = match exec::resolve_tool("go") {
            Some(g) => g,
            None => {
                return CheckOutcome::error(
                    "go",
                    "Go",
                    "go list",
                    "the Go toolchain is not installed; install it from https://go.dev/dl/ and re-run.",
                );
            }
        };
        let args = vec![
            "list".to_string(),
            "-u".to_string(),
            "-m".to_string(),
            "-json".to_string(),
            "all".to_string(),
        ];
        match exec::run(&go, &args, root, &Default::default(), ctx.verbose) {
            Ok(out) if out.success => match parse_go_list(&out.stdout, ctx.deep) {
                Ok((deps, checked)) => {
                    let mut outcome = CheckOutcome::ok("go", "Go", "go list -u -m", deps);
                    outcome.checked = Some(checked);
                    outcome
                }
                Err(e) => CheckOutcome::error("go", "Go", "go list -u -m", e),
            },
            Ok(out) => CheckOutcome::error(
                "go",
                "Go",
                "go list -u -m",
                format!(
                    "go list exited with code {:?}: {}",
                    out.code,
                    first_lines(&out.stderr, 5)
                ),
            ),
            Err(e) => CheckOutcome::error("go", "Go", "go list -u -m", format!("{e:#}")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GoModule {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "Main")]
    main: Option<bool>,
    #[serde(rename = "Indirect")]
    indirect: Option<bool>,
    #[serde(rename = "Update")]
    update: Option<GoUpdate>,
}

#[derive(Debug, Deserialize)]
struct GoUpdate {
    #[serde(rename = "Version")]
    version: String,
}

/// Parse the concatenated-JSON stream of `go list -m -json`.
/// Returns (outdated deps, number of modules examined).
fn parse_go_list(stdout: &str, deep: bool) -> Result<(Vec<OutdatedDep>, usize), String> {
    let stream = serde_json::Deserializer::from_str(stdout).into_iter::<GoModule>();
    let mut outdated = Vec::new();
    let mut checked = 0;
    for module in stream {
        let m = module.map_err(|e| format!("invalid JSON in go list output: {e}"))?;
        if m.main == Some(true) {
            continue;
        }
        let Some(current) = m.version else {
            continue;
        };
        let indirect = m.indirect == Some(true);
        if indirect && !deep {
            continue;
        }
        checked += 1;
        if let Some(update) = m.update
            && update.version != current
        {
            outdated.push(OutdatedDep {
                name: m.path,
                current,
                latest: update.version,
                detail: indirect.then_some("indirect".to_string()),
            });
        }
    }
    outdated.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((outdated, checked))
}

fn first_lines(s: &str, n: usize) -> String {
    s.lines().take(n).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"Path":"example.com/probe","Main":true,"GoVersion":"1.27.3"}
{"Path":"github.com/fatih/color","Version":"v1.13.0","Update":{"Path":"github.com/fatih/color","Version":"v1.19.0"}}
{"Path":"github.com/mattn/go-colorable","Version":"v0.1.9","Update":{"Path":"github.com/mattn/go-colorable","Version":"v0.1.16"},"Indirect":true}
{"Path":"github.com/fresh/dep","Version":"v2.0.0"}
"#;

    #[test]
    fn direct_only_by_default() {
        let (deps, checked) = parse_go_list(SAMPLE, false).unwrap();
        assert_eq!(checked, 2);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/fatih/color");
        assert_eq!(deps[0].current, "v1.13.0");
        assert_eq!(deps[0].latest, "v1.19.0");
        assert_eq!(deps[0].detail, None);
    }

    #[test]
    fn deep_includes_indirect() {
        let (deps, checked) = parse_go_list(SAMPLE, true).unwrap();
        assert_eq!(checked, 3);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[1].detail.as_deref(), Some("indirect"));
    }
}
