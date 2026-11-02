//! Python ecosystem: check the project's environment for outdated packages.
//!
//! Strategy, in order:
//! 1. `uv pip list --outdated` against the project's interpreter (JSON, fast).
//! 2. `<interpreter> -m pip list --outdated` (JSON).
//! 3. `pip-review` installed via `uv tool install pip-review`, pointed at the
//!    project's site-packages with `--path` (pip-review checks its own
//!    interpreter's environment, so it needs the redirect).

use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;

use crate::ecosystem::{CheckOutcome, Ctx, EcosystemChecker, OutdatedDep};
use crate::{exec, install};

pub struct Python;

impl EcosystemChecker for Python {
    fn id(&self) -> &'static str {
        "python"
    }

    fn detect(&self, root: &Path) -> bool {
        const MARKERS: &[&str] = &[
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
            "pdm.lock",
        ];
        if root.join(".venv").is_dir() {
            return true;
        }
        if MARKERS.iter().any(|m| root.join(m).is_file()) {
            return true;
        }
        // requirements.txt, requirements-dev.txt, requirements.in, ...
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.starts_with("requirements")
                        && (lower.ends_with(".txt") || lower.ends_with(".in"))
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome {
        let interp = find_interpreter(root);
        let in_project_env =
            root.join(".venv").is_dir() || std::env::var_os("VIRTUAL_ENV").is_some();
        let ambient_note = match &interp {
            Some(p) if !in_project_env => Some(format!(
                "no project virtualenv (.venv/VIRTUAL_ENV) found; reporting for ambient interpreter {}",
                p.display()
            )),
            _ => None,
        };

        // Strategy 1: uv pip list against the project's interpreter.
        if let (Some(uv), Some(py)) = (find_uv(), interp.clone()) {
            let args = vec![
                "pip".to_string(),
                "list".to_string(),
                "--python".to_string(),
                py.to_string_lossy().into_owned(),
                "--outdated".to_string(),
                "--format".to_string(),
                "json".to_string(),
            ];
            match exec::run(&uv, &args, root, &Default::default(), ctx.verbose) {
                Ok(out) if out.success => match parse_pip_list_json(&out.stdout) {
                    Ok(deps) => {
                        let mut outcome = CheckOutcome::ok("python", "Python", "uv pip list", deps);
                        outcome.message = ambient_note;
                        return outcome;
                    }
                    Err(e) => {
                        if ctx.verbose {
                            eprintln!(
                                "uv pip list output did not parse ({e}); trying next strategy"
                            );
                        }
                    }
                },
                Ok(out) => {
                    if ctx.verbose {
                        eprintln!(
                            "uv pip list failed (code {:?}): {}",
                            out.code,
                            out.stderr.trim()
                        );
                    }
                }
                Err(e) => {
                    if ctx.verbose {
                        eprintln!("uv pip list error: {e:#}");
                    }
                }
            }
        }

        // Strategy 2: the interpreter's own pip.
        if let Some(py) = interp.clone() {
            let py_str = py.to_string_lossy().into_owned();
            let probe = exec::run(
                &py_str,
                &["-m".to_string(), "pip".to_string(), "--version".to_string()],
                root,
                &Default::default(),
                ctx.verbose,
            );
            let has_pip = matches!(probe, Ok(o) if o.success);
            if has_pip {
                let args = vec![
                    "-m".to_string(),
                    "pip".to_string(),
                    "list".to_string(),
                    "--outdated".to_string(),
                    "--format=json".to_string(),
                ];
                match exec::run(&py_str, &args, root, &Default::default(), ctx.verbose) {
                    Ok(out) if out.success => match parse_pip_list_json(&out.stdout) {
                        Ok(deps) => {
                            let mut outcome =
                                CheckOutcome::ok("python", "Python", "pip list --outdated", deps);
                            outcome.message = ambient_note;
                            return outcome;
                        }
                        Err(e) => {
                            return CheckOutcome::error(
                                "python",
                                "Python",
                                "pip list --outdated",
                                format!("could not parse pip output: {e}"),
                            );
                        }
                    },
                    Ok(out) => {
                        return CheckOutcome::error(
                            "python",
                            "Python",
                            "pip list --outdated",
                            format!(
                                "pip exited with code {:?}: {}",
                                out.code,
                                first_lines(&out.stderr, 5)
                            ),
                        );
                    }
                    Err(e) => {
                        return CheckOutcome::error(
                            "python",
                            "Python",
                            "pip list --outdated",
                            format!("{e:#}"),
                        );
                    }
                }
            }
        }

        // Strategy 3: pip-review managed via `uv tool`.
        let Some(py) = interp else {
            return CheckOutcome::error(
                "python",
                "Python",
                "none",
                "no Python interpreter found (looked for .venv, VIRTUAL_ENV, python3, python).",
            );
        };
        match ensure_pip_review(ctx, root) {
            Ok(tool) => {
                let mut args = Vec::new();
                if let Some(site) = site_packages(&py.to_string_lossy(), root, ctx.verbose) {
                    args.push("--path".to_string());
                    args.push(site);
                } else if ctx.verbose {
                    eprintln!(
                        "could not determine site-packages; pip-review will check its own environment"
                    );
                }
                match exec::run(&tool, &args, root, &Default::default(), ctx.verbose) {
                    Ok(out) if out.success => {
                        let mut outcome = CheckOutcome::ok(
                            "python",
                            "Python",
                            "pip-review (uv tool)",
                            parse_pip_review(&out.stdout),
                        );
                        outcome.message = ambient_note;
                        outcome
                    }
                    Ok(out) => CheckOutcome::error(
                        "python",
                        "Python",
                        "pip-review (uv tool)",
                        format!(
                            "pip-review exited with code {:?}: {}",
                            out.code,
                            first_lines(&out.stderr, 5)
                        ),
                    ),
                    Err(e) => CheckOutcome::error(
                        "python",
                        "Python",
                        "pip-review (uv tool)",
                        format!("{e:#}"),
                    ),
                }
            }
            Err(reason) => {
                CheckOutcome::skipped("python", "Python", "pip-review (uv tool)", reason)
            }
        }
    }
}

/// Locate the interpreter to inspect: project's `.venv` first, then
/// `VIRTUAL_ENV`, then `python3`/`python` on PATH.
fn find_interpreter(root: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    let venv_py = root.join(".venv").join("Scripts").join("python.exe");
    #[cfg(not(windows))]
    let venv_py = root.join(".venv").join("bin").join("python");
    if venv_py.is_file() {
        return Some(venv_py);
    }
    if let Some(venv) = std::env::var_os("VIRTUAL_ENV") {
        let venv = PathBuf::from(venv);
        #[cfg(windows)]
        let candidate = venv.join("Scripts").join("python.exe");
        #[cfg(not(windows))]
        let candidate = venv.join("bin").join("python");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    exec::which("python3").or_else(|| exec::which("python"))
}

/// Ask the interpreter for its site-packages directory (for `pip-review --path`).
fn site_packages(python: &str, cwd: &Path, verbose: bool) -> Option<String> {
    let out = exec::run(
        python,
        &[
            "-c".to_string(),
            "import sysconfig; print(sysconfig.get_path('purelib'))".to_string(),
        ],
        cwd,
        &Default::default(),
        verbose,
    )
    .ok()?;
    if !out.success {
        return None;
    }
    let dir = out.stdout.trim().to_string();
    if dir.is_empty() || !Path::new(&dir).is_dir() {
        return None;
    }
    Some(dir)
}

/// Locate the `uv` binary, including its default install dir (`~/.local/bin`)
/// which may not be on PATH right after a fresh install.
fn find_uv() -> Option<String> {
    if let Some(uv) = exec::resolve_tool("uv") {
        return Some(uv);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))?;
    let candidate = home.join(".local").join("bin").join("uv");
    candidate
        .is_file()
        .then(|| candidate.to_string_lossy().into_owned())
}

/// Ensure `pip-review` is available via `uv tool`, bootstrapping `uv` itself
/// first when necessary. Returns the command to invoke, or a skip reason.
fn ensure_pip_review(ctx: &Ctx, root: &Path) -> Result<String, String> {
    if let Some(tool) = exec::resolve_tool("pip-review") {
        return Ok(tool);
    }
    if find_uv().is_none() {
        ensure_uv(ctx, root)?;
    }
    let uv = find_uv().ok_or_else(|| "uv is not available".to_string())?;
    let cmdline = "uv tool install pip-review";
    if !install::wants_install(ctx.install_policy, "pip-review", cmdline) {
        return Err(install::skipped_msg("pip-review", cmdline));
    }
    let ok = install::run_install(
        &uv,
        &[
            "tool".to_string(),
            "install".to_string(),
            "pip-review".to_string(),
        ],
        root,
        ctx.verbose,
    )
    .map_err(|e| format!("{e:#}"))?;
    if !ok {
        return Err("`uv tool install pip-review` failed; see output above.".to_string());
    }
    install::resolve_after_install("pip-review")
        .ok_or_else(|| "pip-review installed but not found afterwards.".to_string())
}

/// Bootstrap the `uv` binary itself via the official installer (unix only;
/// other platforms get manual instructions since `uv tool` cannot exist yet).
fn ensure_uv(ctx: &Ctx, root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let cmdline = "curl -LsSf https://astral.sh/uv/install.sh | sh";
        if !install::wants_install(ctx.install_policy, "uv", cmdline) {
            return Err(install::skipped_msg("uv", cmdline));
        }
        if exec::which("curl").is_none() {
            return Err(
                "need curl to install uv; install uv manually from https://docs.astral.sh/uv/"
                    .to_string(),
            );
        }
        let script = exec::run(
            "curl",
            &[
                "-LsSf".to_string(),
                "https://astral.sh/uv/install.sh".to_string(),
            ],
            root,
            &Default::default(),
            ctx.verbose,
        )
        .map_err(|e| format!("{e:#}"))?;
        if !script.success {
            return Err(format!(
                "downloading the uv installer failed: {}",
                first_lines(&script.stderr, 3)
            ));
        }
        let mut child = std::process::Command::new("sh")
            .arg("-s")
            .arg("--")
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to run sh: {e}"))?;
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(script.stdout.as_bytes());
        }
        let status = child
            .wait()
            .map_err(|e| format!("uv installer failed: {e}"))?;
        if !status.success() {
            return Err("uv installer failed; see output above.".to_string());
        }
        find_uv()
            .map(|_| ())
            .ok_or_else(|| "uv installed but not found afterwards.".to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, root);
        Err(
            "uv is not installed; install it from https://docs.astral.sh/uv/ and re-run."
                .to_string(),
        )
    }
}

#[derive(Debug, Deserialize)]
struct PipListEntry {
    name: String,
    version: String,
    latest_version: String,
}

/// Parse `pip list --outdated --format=json` / `uv pip list --format json`.
fn parse_pip_list_json(stdout: &str) -> Result<Vec<OutdatedDep>, String> {
    let entries: Vec<PipListEntry> =
        serde_json::from_str(stdout).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(entries
        .into_iter()
        .map(|e| OutdatedDep {
            name: e.name,
            current: e.version,
            latest: e.latest_version,
            detail: None,
        })
        .collect())
}

/// Parse `pip-review` output lines: `six==1.17.0 is available (you have 1.15.0)`.
fn parse_pip_review(stdout: &str) -> Vec<OutdatedDep> {
    let re = Regex::new(r"^(\S+)==(\S+) is available \(you have ([^)]+)\)").unwrap();
    stdout
        .lines()
        .filter_map(|line| {
            let caps = re.captures(line.trim())?;
            Some(OutdatedDep {
                name: caps[1].to_string(),
                current: caps[3].to_string(),
                latest: caps[2].to_string(),
                detail: None,
            })
        })
        .collect()
}

fn first_lines(s: &str, n: usize) -> String {
    s.lines().take(n).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pip_list_json() {
        let json = r#"[{"name":"six","version":"1.15.0","latest_version":"1.17.0","latest_filetype":"wheel"}]"#;
        let deps = parse_pip_list_json(json).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "six");
        assert_eq!(deps[0].current, "1.15.0");
        assert_eq!(deps[0].latest, "1.17.0");
    }

    #[test]
    fn parses_pip_review_lines() {
        let out = "six==1.17.0 is available (you have 1.15.0)\nrequests==2.32.0 is available (you have 2.28.0)\n";
        let deps = parse_pip_review(out);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "six");
        assert_eq!(deps[0].current, "1.15.0");
        assert_eq!(deps[0].latest, "1.17.0");
    }

    #[test]
    fn detects_python_markers() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!Python.detect(dir.path()));
        std::fs::write(dir.path().join("requirements.txt"), "six\n").unwrap();
        assert!(Python.detect(dir.path()));
        std::fs::remove_file(dir.path().join("requirements.txt")).unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "[project]\n").unwrap();
        assert!(Python.detect(dir.path()));
    }
}
