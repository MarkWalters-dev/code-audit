//! "Install the checker app if missing" flow shared by all ecosystems.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::Result;

use crate::exec;

/// What to do when an underlying checker tool is not installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPolicy {
    /// Install without asking.
    Auto,
    /// Ask on an interactive terminal, otherwise skip.
    Prompt,
    /// Never install; report the ecosystem as skipped.
    Never,
}

/// Decide whether to proceed with installing `tool` via `command_line`.
/// Prints the prompt (when interactive) and returns true when installation
/// should be attempted.
pub fn wants_install(policy: InstallPolicy, tool: &str, command_line: &str) -> bool {
    match policy {
        InstallPolicy::Auto => {
            eprintln!("{tool} not found; installing with: {command_line}");
            true
        }
        InstallPolicy::Never => false,
        InstallPolicy::Prompt => {
            if !std::io::stdin().is_terminal() {
                return false;
            }
            eprint!("{tool} not found. Install it with `{command_line}`? [Y/n] ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(_) => {
                    let answer = line.trim().to_lowercase();
                    answer.is_empty() || answer == "y" || answer == "yes"
                }
                Err(_) => false,
            }
        }
    }
}

/// Run an install command (`program` + `args`), streaming its output to stderr
/// so slow installs (compiles, downloads) don't look hung. Returns true when
/// the install command exited successfully.
pub fn run_install(program: &str, args: &[String], cwd: &Path, verbose: bool) -> Result<bool> {
    if verbose {
        eprintln!("+ (cd {}) {} {}", cwd.display(), program, args.join(" "));
    }
    let mut child = std::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to execute `{program}`: {e}"))?;
    let status = child.wait()?;
    Ok(status.success())
}

/// Standard "not installed" skip message used when no install is attempted.
pub fn skipped_msg(tool: &str, command_line: &str) -> String {
    format!(
        "{tool} is not installed and was not installed. Install it with `{command_line}` or re-run with `--yes` to install automatically."
    )
}

/// Re-resolve `tool` after an install attempt (fresh installs may land in bin
/// dirs that are not on PATH, e.g. `~/.local/bin` for `uv tool` shims).
pub fn resolve_after_install(tool: &str) -> Option<String> {
    exec::resolve_tool(tool)
}
