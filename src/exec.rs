//! Subprocess execution and executable lookup helpers.

use anyhow::{Context, Result};
use std::collections::HashMap;
#[cfg(windows)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Captured result of a child process. A non-zero exit is *not* an error here;
/// callers decide via [`CmdOutput::success`].
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Run `program args...` with `cwd` as working directory and `env` additions.
/// `verbose` echoes the exact command (with cwd) to stderr before running.
pub fn run(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &HashMap<String, String>,
    verbose: bool,
) -> Result<CmdOutput> {
    if verbose {
        eprintln!("+ (cd {}) {} {}", cwd.display(), program, args.join(" "));
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd
        .output()
        .with_context(|| format!("failed to execute `{program}`"))?;
    Ok(CmdOutput {
        success: out.status.success(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Find `name` on PATH (honoring Windows PATHEXT). Returns the absolute path.
pub fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let direct = PathBuf::from(name);
    if direct.components().count() > 1 && is_executable_file(&direct) {
        return Some(direct);
    }
    #[cfg(windows)]
    let extensions: Vec<OsString> = {
        let pathext = std::env::var_os("PATHEXT").unwrap_or_else(|| ".EXE;.BAT;.CMD".into());
        std::env::split_paths(&pathext.to_string_lossy().replace(';', ":"))
            .map(|e| e.as_os_str().to_os_string())
            .collect()
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            if candidate.extension().is_none() {
                for ext in &extensions {
                    let mut with_ext = candidate.as_os_str().to_os_string();
                    with_ext.push(ext);
                    let with_ext = PathBuf::from(with_ext);
                    if is_executable_file(&with_ext) {
                        return Some(with_ext);
                    }
                }
            }
        }
    }
    None
}

fn is_executable_file(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Extra bin directories that installers use but that may be missing from PATH:
/// `~/.local/bin` (uv tool shims), pnpm's global bin, `~/.cargo/bin`.
pub fn known_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from));
    if let Some(home) = home {
        dirs.push(home.join(".local").join("bin"));
        dirs.push(home.join(".cargo").join("bin"));
        dirs.push(home.join(".local").join("share").join("pnpm"));
        #[cfg(windows)]
        dirs.push(home.join("AppData").join("Roaming").join("npm"));
    }
    // Ask pnpm itself where its global bin is (cheap, best-effort).
    if let Some(pnpm) = which("pnpm")
        && let Ok(out) = Command::new(pnpm).arg("bin").arg("-g").output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let dir = PathBuf::from(s.trim());
        if dir.is_dir() && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs.into_iter().filter(|d| d.is_dir()).collect()
}

/// Look for `name` on PATH first, then in [`known_bin_dirs`].
/// Returns a path/command string usable to invoke the tool.
pub fn resolve_tool(name: &str) -> Option<String> {
    if let Some(p) = which(name) {
        return Some(p.to_string_lossy().into_owned());
    }
    for dir in known_bin_dirs() {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
        }
        #[cfg(windows)]
        for ext in ["exe", "cmd", "bat", "ps1"] {
            let candidate = dir.join(format!("{name}.{ext}"));
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}
