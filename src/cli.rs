//! Command-line interface definition.

use clap::Parser;

/// Audit a project's dependencies for outdated and vulnerable libraries.
///
/// Detects the project type(s) in PATH (Python, JavaScript, Rust, Go, Android)
/// and checks each dependency against its registry (latest release) and the
/// OSV vulnerability database, then runs each ecosystem's linters.
#[derive(Debug, Parser)]
#[command(name = "depaudit", version, about, long_about = None)]
pub struct Args {
    /// Project directory to audit.
    #[arg(default_value = ".")]
    pub path: String,

    /// Only audit these ecosystems (comma-separated):
    /// python, node, rust, go, android.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub only: Vec<String>,

    /// Skip these ecosystems (comma-separated).
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub exclude: Vec<String>,

    /// Only check for outdated dependencies.
    #[arg(long, conflicts_with_all = ["vulns_only", "lint_only"])]
    pub outdated_only: bool,

    /// Only check for vulnerabilities.
    #[arg(long, conflicts_with_all = ["outdated_only", "lint_only"])]
    pub vulns_only: bool,

    /// Only run linters.
    #[arg(long, conflicts_with_all = ["outdated_only", "vulns_only", "no_lint"])]
    pub lint_only: bool,

    /// Skip linters.
    #[arg(long, conflicts_with = "lint_only")]
    pub no_lint: bool,

    /// Print a CycloneDX SBOM (JSON) to stdout instead of the audit report.
    #[arg(
        long,
        conflicts_with_all = ["outdated_only", "vulns_only", "lint_only"]
    )]
    pub sbom: bool,

    /// Also check transitive/indirect dependencies for outdatedness.
    /// (Vulnerabilities always cover every known dependency.)
    #[arg(long)]
    pub deep: bool,

    /// Print the full machine-readable report as JSON.
    #[arg(long)]
    pub json: bool,

    /// Exit with status 1 when any outdated dependency is found.
    #[arg(long)]
    pub fail_on_outdated: bool,

    /// Exit with status 1 when any vulnerability is found.
    #[arg(long)]
    pub fail_on_vulns: bool,

    /// Cap Android updates to releases needing at most this compileSdk.
    /// Overrides depaudit.toml and auto-detection.
    #[arg(long)]
    pub max_compile_sdk: Option<u32>,

    /// Bypass the disk cache (version lookups are cached 24h, vulns 6h).
    #[arg(long)]
    pub no_cache: bool,

    /// Clear the disk cache before auditing.
    #[arg(long)]
    pub clear_cache: bool,

    /// Print extra progress information.
    #[arg(short, long)]
    pub verbose: bool,

    /// Silence progress output (reports still print).
    #[arg(short, long)]
    pub quiet: bool,
}
