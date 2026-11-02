//! Recursive project discovery: find every project directory under the CLI
//! root so callers never have to guess which subfolder holds the markers.
//!
//! Dependency, build-output and VCS directories are pruned (`node_modules`,
//! `target`, `.venv`, ...), as are hidden directories and symlinked paths
//! (cycle safety). A nested directory only counts for ecosystems not already
//! detected in an ancestor project: Gradle modules (`app/`), Cargo workspace
//! members and the like belong to the parent project, while genuinely
//! different stacks (a `frontend/` under a Python root) are audited too.

use std::path::{Path, PathBuf};

pub struct Project {
    pub root: PathBuf,
    /// Ecosystem ids detected here, minus ones already detected in an
    /// ancestor project directory.
    pub ecosystems: Vec<&'static str>,
}

/// Find project directories under `root` (which is always examined itself).
/// `detect` maps a directory to the ecosystem ids detected there, after
/// `--only`/`--exclude` filtering. Results are sorted with the CLI root first.
pub fn discover_projects(root: &Path, detect: &dyn Fn(&Path) -> Vec<&'static str>) -> Vec<Project> {
    let mut out = Vec::new();
    // (directory, ecosystem ids detected in ancestor projects)
    let mut stack: Vec<(PathBuf, Vec<&'static str>)> = vec![(root.to_path_buf(), Vec::new())];
    while let Some((dir, inherited)) = stack.pop() {
        let detected = detect(&dir);
        let fresh: Vec<&'static str> = detected
            .iter()
            .filter(|id| !inherited.contains(id))
            .copied()
            .collect();
        let mut pass_down = inherited;
        if !fresh.is_empty() {
            out.push(Project {
                root: dir.clone(),
                ecosystems: fresh.clone(),
            });
            pass_down.extend(fresh.iter().copied());
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut kids: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| {
                e.file_type().is_ok_and(|t| t.is_dir())
                    && !skip_dir_name(&e.file_name().to_string_lossy())
            })
            .map(|e| e.path())
            .collect();
        kids.sort();
        for kid in kids {
            stack.push((kid, pass_down.clone()));
        }
    }
    out.sort_by(|a, b| a.root.cmp(&b.root));
    out
}

/// Directory names that never contain an independent project.
/// Shared with the lint source walkers so linters skip the same trees.
pub(crate) fn skip_dir_name(name: &str) -> bool {
    if name.starts_with('.') {
        return true;
    }
    if name.ends_with(".egg-info") {
        return true;
    }
    matches!(
        name,
        "node_modules"
            | "target"
            | "venv"
            | "__pycache__"
            | "build"
            | "dist"
            | "vendor"
            | "_build"
            | "out"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Detection stub: the directory name selects the ecosystem.
    fn detect_by_name(dir: &Path) -> Vec<&'static str> {
        match dir.file_name().and_then(|n| n.to_str()) {
            Some("py") | Some("backend") => vec!["python"],
            Some("js") | Some("frontend") => vec!["node"],
            _ => vec![],
        }
    }

    fn mkdirs(root: &Path, rel: &[&str]) {
        for r in rel {
            std::fs::create_dir_all(root.join(r)).unwrap();
        }
    }

    #[test]
    fn finds_nested_project_when_root_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        mkdirs(dir.path(), &["apps/py"]);
        let found = discover_projects(dir.path(), &detect_by_name);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, dir.path().join("apps/py"));
        assert_eq!(found[0].ecosystems, vec!["python"]);
    }

    #[test]
    fn root_and_different_nested_stack_both_found() {
        let dir = tempfile::tempdir().unwrap();
        mkdirs(dir.path(), &["frontend"]);
        let found = discover_projects(dir.path(), &|d| {
            if d == dir.path() {
                vec!["python"]
            } else {
                detect_by_name(d)
            }
        });
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].root, dir.path().to_path_buf());
        assert_eq!(found[1].root, dir.path().join("frontend"));
        assert_eq!(found[1].ecosystems, vec!["node"]);
    }

    #[test]
    fn same_ecosystem_nesting_is_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        mkdirs(dir.path(), &["backend"]);
        let found = discover_projects(dir.path(), &|d| {
            if d == dir.path() {
                vec!["python"]
            } else {
                detect_by_name(d)
            }
        });
        // backend/ is python under a python root: belongs to the parent.
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, dir.path().to_path_buf());
    }

    #[test]
    fn dependency_and_hidden_dirs_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        mkdirs(
            dir.path(),
            &[
                "node_modules/py",
                "target/py",
                ".venv/py",
                "venv/py",
                ".hidden/py",
                "build/py",
                "dist/py",
                "vendor/py",
                "real/py",
            ],
        );
        let found = discover_projects(dir.path(), &detect_by_name);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, dir.path().join("real/py"));
    }

    #[test]
    fn cli_root_is_examined_even_when_ignored_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("build");
        std::fs::create_dir_all(&root).unwrap();
        let found = discover_projects(&root, &|d| {
            if d == root { vec!["go"] } else { vec![] }
        });
        assert_eq!(found.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_dirs_do_not_loop() {
        let dir = tempfile::tempdir().unwrap();
        mkdirs(dir.path(), &["sub"]);
        std::os::unix::fs::symlink(dir.path(), dir.path().join("sub/loop")).unwrap();
        let found = discover_projects(dir.path(), &detect_by_name);
        assert!(found.is_empty());
    }
}
