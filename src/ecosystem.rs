//! Shared types for ecosystem checkers and the checker registry.

use serde::Serialize;
use std::path::Path;

use crate::install::InstallPolicy;

/// One outdated dependency found by an ecosystem checker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutdatedDep {
    pub name: String,
    pub current: String,
    pub latest: String,
    /// Optional extra info, e.g. dependency kind or "indirect".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Outcome status of a single ecosystem check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The check ran to completion (possibly with outdated deps found).
    Ok,
    /// The check was skipped (usually: checker tool missing, install declined).
    Skipped,
    /// The check failed with an error.
    Error,
}

/// Full outcome of checking one ecosystem in a project directory.
#[derive(Debug, Clone, Serialize)]
pub struct CheckOutcome {
    /// Stable id: python, node, rust, go, android.
    pub id: &'static str,
    /// Human display name.
    pub display: &'static str,
    pub status: Status,
    /// The underlying tool/command that produced the result.
    pub tool: String,
    /// Outdated dependencies (empty when everything is fresh).
    pub outdated: Vec<OutdatedDep>,
    /// Total number of dependencies examined, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<usize>,
    /// Warning, skip reason or error text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CheckOutcome {
    pub fn ok(
        id: &'static str,
        display: &'static str,
        tool: impl Into<String>,
        outdated: Vec<OutdatedDep>,
    ) -> Self {
        Self {
            id,
            display,
            status: Status::Ok,
            tool: tool.into(),
            outdated,
            checked: None,
            message: None,
        }
    }

    pub fn skipped(
        id: &'static str,
        display: &'static str,
        tool: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id,
            display,
            status: Status::Skipped,
            tool: tool.into(),
            outdated: Vec::new(),
            checked: None,
            message: Some(reason.into()),
        }
    }

    pub fn error(
        id: &'static str,
        display: &'static str,
        tool: impl Into<String>,
        err: impl Into<String>,
    ) -> Self {
        Self {
            id,
            display,
            status: Status::Error,
            tool: tool.into(),
            outdated: Vec::new(),
            checked: None,
            message: Some(err.into()),
        }
    }
}

/// Context shared by all checkers: user policy knobs.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub install_policy: InstallPolicy,
    pub verbose: bool,
    /// Include transitive/indirect dependencies where the underlying tool supports it.
    pub deep: bool,
}

/// Interface every language ecosystem implements.
pub trait EcosystemChecker: Sync {
    fn id(&self) -> &'static str;
    /// Whether `root` looks like a project of this ecosystem (marker files).
    fn detect(&self, root: &Path) -> bool;
    /// Run the outdated check (installing the underlying tool if needed/allowed).
    fn check(&self, ctx: &Ctx, root: &Path) -> CheckOutcome;
}

/// All supported ecosystems, in stable report order.
pub fn all_checkers() -> Vec<Box<dyn EcosystemChecker>> {
    vec![
        Box::new(crate::python::Python),
        Box::new(crate::node::Node),
        Box::new(crate::rustlang::RustLang),
        Box::new(crate::golang::GoLang),
        Box::new(crate::android::Android),
    ]
}

/// Resolve a user-supplied ecosystem id (with `js` accepted as an alias).
pub fn canonical_id(input: &str) -> Option<&'static str> {
    match input.trim().to_lowercase().as_str() {
        "python" | "py" => Some("python"),
        "node" | "js" | "javascript" | "typescript" | "ts" => Some("node"),
        "rust" | "rs" => Some("rust"),
        "go" | "golang" => Some("go"),
        "android" | "gradle" | "kotlin" => Some("android"),
        _ => None,
    }
}
