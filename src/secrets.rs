//! Hardcoded-secret and cryptographic-hygiene scanning: known token
//! patterns (AWS, GitHub, Slack, private keys, ...), high-entropy
//! strings that look like generated credentials, deprecated hash and
//! cipher use (MD5, SHA-1, DES, ECB, RC4), and TLS-verification
//! disables. Runs once per project over text sources; lockfiles (hash
//! soup by design) and oversized files are excluded. Local-only: no
//! network, no cache.
//!
//! Findings are heuristic by nature. Patterns favor precision over
//! recall: every rule below exists because its false-positive rate
//! proved tolerable on real repositories, and the entropy fallback
//! skips hex digests and UUIDs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use crate::ecosystem::{Notice, NoticeCheck};
use crate::ghost::walk_sources;

/// Source and config extensions worth scanning.
const SECRET_EXTS: &[&str] = &[
    "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "rb", "php", "sh", "bash", "zsh",
    "env", "json", "yaml", "yml", "toml", "ini", "cfg", "conf", "xml", "html", "htm", "java", "kt",
    "kts", "go", "rs", "c", "h", "cpp", "hpp", "cs", "swift", "tf", "ps1", "pl",
];

/// Lockfiles and registries: hashes by design, never scan them.
const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "Cargo.lock",
    "go.sum",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile.lock",
    "composer.lock",
    "Gemfile.lock",
    "Package.resolved",
    "pubspec.lock",
    "flake.lock",
    "sources.json",
];

struct Rule {
    kind: &'static str,
    check: NoticeCheck,
    pattern: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
        let secret = NoticeCheck::Secrets;
        let crypto = NoticeCheck::Crypto;
        vec![
            // -- Secrets: known token shapes -------------------------------
            rule("AWS access key ID", secret, r"\bAKIA[0-9A-Z]{16}\b"),
            rule(
                "GitHub token",
                secret,
                r"\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
            ),
            rule("GitLab token", secret, r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
            rule("Slack token", secret, r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
            rule(
                "private key",
                secret,
                r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY",
            ),
            rule("Stripe live key", secret, r"\bsk_live_[A-Za-z0-9]{10,}\b"),
            rule(
                "SendGrid key",
                secret,
                r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{20,}\b",
            ),
            rule("Twilio key", secret, r"\bSK[0-9a-fA-F]{32}\b"),
            rule("npm token", secret, r"\bnpm_[A-Za-z0-9]{20,}\b"),
            rule("PyPI token", secret, r"\bpypi-[A-Za-z0-9_-]{40,}\b"),
            rule("Google API key", secret, r"\bAIza[0-9A-Za-z_-]{35}\b"),
            // -- Crypto: deprecated primitives ------------------------------
            rule(
                "deprecated crypto: MD5",
                crypto,
                r#"(?i)\bmd5\s*\(|hashlib\.md5|getInstance\s*\(\s*['"]MD5['"]|createHash\s*\(\s*['"]md5['"]"#,
            ),
            rule(
                "deprecated crypto: SHA-1",
                crypto,
                r#"(?i)\bsha-?1\s*\(|hashlib\.sha1|getInstance\s*\(\s*['"]SHA-?1['"]|createHash\s*\(\s*['"]sha1['"]|\bsha1\s*\.\s*(New|Sum)"#,
            ),
            rule(
                "deprecated crypto: DES",
                crypto,
                r"(?i)DES/ECB|DESede|TripleDES|Cipher[^;]*DES[^;]*\)",
            ),
            rule("deprecated crypto: ECB mode", crypto, r"\bECB\b"),
            rule("deprecated crypto: RC4", crypto, r"(?i)\brc4\b|ARC4"),
            rule(
                "deprecated crypto: createCipher",
                crypto,
                r"\.createCipher\s*\(",
            ),
            // -- Crypto: TLS verification disables --------------------------
            rule(
                "TLS verification disabled",
                crypto,
                r#"verify\s*=\s*False|CERT_NONE|VERIFY_NONE|InsecureSkipVerify\s*:\s*true|_create_unverified_context|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0"#,
            ),
        ]
    });
    &RULES
}

fn rule(kind: &'static str, check: NoticeCheck, pattern: &'static str) -> Rule {
    Rule {
        kind,
        check,
        pattern,
    }
}

/// Assignment-shaped credentials: `password = "..."`, `api_key: '...'`.
/// Placeholders (`xxx`, `changeme`, ...) are excluded by value. The
/// set carries the same pattern as a prefilter; captures need the
/// real regex, run only on prefilter hits.
const ASSIGN_PATTERN: &str = r#"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['"]([^'"]{4,})['"]"#;
static ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(ASSIGN_PATTERN).unwrap());

/// One-pass prefilter over all rule patterns plus the assignment shape:
/// a single scan per line reports which rules matched, replacing one
/// pass per rule. Built from `rules()` so indices always align with
/// rule order; index `rules().len()` is the assignment prefilter.
fn rule_set() -> &'static RegexSet {
    static SET: LazyLock<RegexSet> = LazyLock::new(|| {
        RegexSet::new(
            rules()
                .iter()
                .map(|r| r.pattern)
                .chain(std::iter::once(ASSIGN_PATTERN)),
        )
        .unwrap()
    });
    &SET
}

/// Candidate generated tokens for the entropy fallback.
static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_-]{20,}").unwrap());

/// Placeholder credential values that are never findings.
const PLACEHOLDERS: &[&str] = &[
    "xxx",
    "xxxx",
    "test",
    "testing",
    "example",
    "changeme",
    "change-me",
    "password",
    "secret",
    "apikey",
    "api-key",
    "yourkey",
    "your-key",
    "todo",
    "none",
    "null",
    "undefined",
    "***",
    "ppp",
    "1234",
    "12345",
];

/// Minimum Shannon entropy (bits/char) for the high-entropy fallback.
const ENTROPY_BITS: f64 = 4.5;

/// Scan the project for secrets and crypto issues. One notice per
/// (file, line, check); files are deduplicated by scan order.
/// `done` holds files already scanned by an ancestor project (nested
/// projects share subtrees): they are skipped, and every scanned file
/// is recorded so descendants skip them too.
pub fn scan_project(root: &Path, done: &mut HashSet<PathBuf>) -> Vec<Notice> {
    let files = walk_sources(root, SECRET_EXTS);
    if files.len() > 500 {
        crate::progress::note(&format!(
            "depaudit: scanning {} files for secrets...",
            files.len()
        ));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in &files {
        // Already covered by an ancestor project's scan.
        if !done.insert(path.clone()) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if SKIP_FILES.contains(&name) || name.ends_with(".lockb") || name.ends_with(".min.js") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let display = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());
        for (idx, line) in text.lines().enumerate() {
            let line_no = idx as u32 + 1;
            for found in scan_line(line) {
                if seen.insert((display.clone(), line_no, found.check)) {
                    out.push(Notice {
                        check: found.check,
                        name: display.clone(),
                        message: found.message,
                        file: Some(display.clone()),
                        line: Some(line_no),
                    });
                }
            }
        }
    }
    out.sort_by_key(|a| (a.file.clone(), a.line));
    out
}

struct Finding {
    check: NoticeCheck,
    message: String,
}

/// All findings on one line: known patterns, credential assignments,
/// then the entropy fallback (only when nothing else matched, so one
/// token yields one notice).
fn scan_line(line: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let assign_idx = rules().len();
    let mut assign_hit = false;
    for idx in rule_set().matches(line) {
        if idx == assign_idx {
            assign_hit = true;
            continue;
        }
        let rule = &rules()[idx];
        // `ARC4` also matches `arc4random` (a fine CSPRNG): exclude it.
        if rule.kind.ends_with("RC4") && line.to_lowercase().contains("arc4random") {
            continue;
        }
        let message = match rule.check {
            NoticeCheck::Secrets => format!("possible secret: {}", rule.kind),
            _ => rule.kind.to_string(),
        };
        out.push(Finding {
            check: rule.check,
            message,
        });
    }
    if assign_hit && let Some(caps) = ASSIGN_RE.captures(line) {
        let value = caps.get(2).unwrap().as_str();
        // Real credentials never contain whitespace; prose does.
        if !value.chars().any(|c| c.is_whitespace()) && !is_placeholder(value) {
            out.push(Finding {
                check: NoticeCheck::Secrets,
                message: format!(
                    "possible secret: hardcoded {}",
                    caps.get(1).unwrap().as_str().to_lowercase()
                ),
            });
        }
    }
    if out.is_empty() {
        for token in TOKEN_RE.find_iter(line).map(|m| m.as_str()) {
            if looks_generated(token) {
                out.push(Finding {
                    check: NoticeCheck::Secrets,
                    message: format!(
                        "possible secret: high-entropy string ({} chars)",
                        token.len()
                    ),
                });
                break;
            }
        }
    }
    out
}

/// Placeholder or obviously-fake credential value.
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    if PLACEHOLDERS
        .iter()
        .any(|p| lower == *p || lower.contains(p))
    {
        return true;
    }
    // `***`, `xxx...`, single-char runs.
    let mut chars = lower.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => true,
    }
}

/// Well-known encoding alphabets: maximum entropy, never credentials.
const ALPHABETS: &[&str] = &[
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
];

/// Generated-looking token: enough entropy, not a hex digest, UUID,
/// `key=value` flag blob, or encoding alphabet.
fn looks_generated(token: &str) -> bool {
    if token.len() < 20 || token.len() > 256 {
        return false;
    }
    // Base64 pads with trailing `=` only; `=` mid-token means `flag=value`.
    if token.trim_end_matches('=').contains('=') {
        return false;
    }
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return false; // content hash, not a credential
    }
    if is_uuid(token) {
        return false;
    }
    if ALPHABETS
        .iter()
        .any(|a| a.contains(token) || token.contains(a))
    {
        return false;
    }
    shannon_entropy(token) >= ENTROPY_BITS
}

fn is_uuid(token: &str) -> bool {
    // 8-4-4-4-12 hex with dashes at 8/13/18/23; no allocation.
    token.len() == 36
        && token.as_bytes()[8] == b'-'
        && token.as_bytes()[13] == b'-'
        && token.as_bytes()[18] == b'-'
        && token.as_bytes()[23] == b'-'
        && token
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit())
}

fn shannon_entropy(token: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in token.bytes() {
        counts[b as usize] += 1;
    }
    let len = token.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(line: &str) -> Vec<NoticeCheck> {
        scan_line(line).iter().map(|f| f.check).collect()
    }

    #[test]
    fn known_tokens_flag() {
        assert_eq!(
            kinds("key = \"AKIAIOSFODNN7EXAMPLE\""),
            vec![NoticeCheck::Secrets]
        );
        assert_eq!(
            kinds("token = \"ghp_abcdefghij1234567890\""),
            vec![NoticeCheck::Secrets]
        );
        assert_eq!(
            kinds("t = \"xoxb-123456789012-abcdefghij\""),
            vec![NoticeCheck::Secrets]
        );
        assert_eq!(
            kinds("-----BEGIN RSA PRIVATE KEY-----"),
            vec![NoticeCheck::Secrets]
        );
    }

    #[test]
    fn assignments_flag_unless_placeholder() {
        assert_eq!(
            kinds("password = \"s3cr3t-value-99\""),
            vec![NoticeCheck::Secrets]
        );
        assert!(kinds("password = \"\"").is_empty());
        assert!(kinds("password = \"changeme\"").is_empty());
        assert!(kinds("api_key = \"xxx\"").is_empty());
    }

    #[test]
    fn entropy_flags_generated_skips_digests() {
        assert_eq!(
            kinds("token = \"xK9mP2vL8qR4tW6yN1zA7bC3eF5dH0\""),
            vec![NoticeCheck::Secrets]
        );
        // sha256 hex, UUID, prose: silent.
        assert!(
            kinds("sha = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"")
                .is_empty()
        );
        assert!(kinds("id = \"123e4567-e89b-12d3-a456-426614174000\"").is_empty());
        assert!(kinds("# just a comment about nothing important here").is_empty());
        // CLI flag blobs, encoding alphabets, prose assignments: silent.
        assert!(
            kinds("\"build\": \"NODE_OPTIONS=--max-old-space-size=6144 vite build\"").is_empty()
        );
        assert!(
            kinds(
                "const a = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\";"
            )
            .is_empty()
        );
        assert!(kinds("secret: \"Credentials and keys are not allowed here.\"").is_empty());
    }

    #[test]
    fn crypto_primitives_flag() {
        assert_eq!(
            kinds("hashlib.md5(data).hexdigest()"),
            vec![NoticeCheck::Crypto]
        );
        assert_eq!(
            kinds("Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"),
            vec![NoticeCheck::Crypto]
        );
        assert_eq!(
            kinds("requests.get(url, verify=False)"),
            vec![NoticeCheck::Crypto]
        );
        assert!(kinds("seed = arc4random()").is_empty());
        assert!(kinds("hashlib.sha256(data)").is_empty());
    }

    #[test]
    fn lockfiles_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            "{\"resolved\": \"https://example.com/AKIAIOSFODNN7EXAMPLE\"}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("app.py"), "x = \"AKIAIOSFODNN7EXAMPLE\"\n").unwrap();
        let notices = scan_project(dir.path(), &mut HashSet::new());
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].file.as_deref(), Some("app.py"));
    }
}
