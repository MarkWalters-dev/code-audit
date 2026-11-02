//! Project config file: `depaudit.toml` in the audited root.
//!
//! ```toml
//! [android]
//! max_compile_sdk = 36
//! ```
//!
//! Unknown keys are ignored so newer config files keep working with older
//! releases. A file that exists but fails to parse is a hard error: silently
//! continuing with different settings could suggest unusable updates.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub android: AndroidConfig,
    pub cache: CacheConfig,
    pub lint: LintConfig,
    pub licenses: LicenseConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AndroidConfig {
    /// Newest compileSdk the project can build against. Library releases
    /// that require a higher one are reported as blocked, not outdated.
    pub max_compile_sdk: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Hours that version lookups stay fresh (default 24). Expired entries
    /// are kept regardless and served, flagged, when lookups fail.
    pub versions_ttl_hours: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LintConfig {
    /// Run linters as part of the audit (default true).
    pub enabled: Option<bool>,
    /// Config-file search order across the three tiers: project (the audited
    /// directory), depaudit (`~/.config/depaudit/lint/`), global
    /// (`/etc/depaudit/lint/`). Must name each tier exactly once; the first
    /// tier holding a linter's config file wins.
    pub config_order: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LicenseConfig {
    /// Run license/yanked/EOL notices as part of the audit (default true).
    pub enabled: Option<bool>,
    /// Denied SPDX ids; family prefixes match (`GPL` catches every GPL
    /// variant). Dependencies whose license matches are reported.
    pub deny: Option<Vec<String>>,
}

pub fn load(root: &Path) -> Result<FileConfig, String> {
    let path = root.join("depaudit.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileConfig::default()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    toml::from_str::<FileConfig>(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, body: &str) {
        std::fs::write(dir.path().join("depaudit.toml"), body).unwrap();
    }

    #[test]
    fn missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.android.max_compile_sdk, None);
    }

    #[test]
    fn parses_max_compile_sdk() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "[android]\nmax_compile_sdk = 36\n");
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.android.max_compile_sdk, Some(36));
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "[android\nmax_compile_sdk = nope\n");
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn parses_cache_ttl() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "[cache]\nversions_ttl_hours = 48\n");
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.cache.versions_ttl_hours, Some(48));
        assert_eq!(cfg.android.max_compile_sdk, None);
    }

    #[test]
    fn parses_lint_section() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir,
            "[lint]\nenabled = false\nconfig_order = [\"depaudit\", \"project\", \"global\"]\n",
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.lint.enabled, Some(false));
        assert_eq!(
            cfg.lint.config_order.unwrap().join(","),
            "depaudit,project,global"
        );
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir,
            "[android]\nmax_compile_sdk = 35\nfuture_key = true\n[other]\nx = 1\n",
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.android.max_compile_sdk, Some(35));
    }
}
