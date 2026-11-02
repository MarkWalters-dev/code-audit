//! Command-line interface definition.

use clap::Parser;

/// Check whether a project's dependencies are the latest versions.
///
/// Detects the project type(s) in PATH (Python, JavaScript, Rust, Go, Android)
/// and runs each ecosystem's own outdated-checker, installing it first when
/// missing and allowed.
#[derive(Debug, Parser)]
#[command(name = "freshdeps", version, about, long_about = None)]
pub struct Args {
    /// Project directory to check.
    #[arg(default_value = ".")]
    pub path: String,

    /// Only check these ecosystems (comma-separated):
    /// python, node, rust, go, android.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub only: Vec<String>,

    /// Skip these ecosystems (comma-separated).
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub exclude: Vec<String>,

    /// Install missing checker tools without asking.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Never install missing checker tools; skip those ecosystems instead.
    #[arg(long, conflicts_with = "yes")]
    pub no_install: bool,

    /// Also check transitive/indirect dependencies where supported.
    #[arg(long)]
    pub deep: bool,

    /// Print the full machine-readable report as JSON.
    #[arg(long)]
    pub json: bool,

    /// Exit with status 1 when any outdated dependency is found.
    #[arg(long)]
    pub fail_on_outdated: bool,

    /// Print every external command before running it.
    #[arg(short, long)]
    pub verbose: bool,
}
