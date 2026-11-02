//! Shared HTTP helper: one agent with a proper User-Agent and timeouts.
//!
//! Some registries (notably crates.io) reject requests without a User-Agent.

use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result};

pub const USER_AGENT: &str = "depaudit/0.1";

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable per-retry diagnostics on stderr (wired to `-v`).
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

static AGENT: OnceLock<ureq::Agent> = OnceLock::new();

/// Shared agent so all requests reuse pooled connections.
fn agent() -> ureq::Agent {
    AGENT
        .get_or_init(|| {
            ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(20)))
                .build()
                .into()
        })
        .clone()
}

/// Cap concurrent registry requests process-wide. Dep audits fan out to one
/// thread per dependency; uncapped bursts get connections dropped (notably
/// by Google's frontends), which then costs timeouts and retry backoffs.
const MAX_CONCURRENT_REQUESTS: usize = 6;

struct Limiter {
    tx: std::sync::mpsc::SyncSender<()>,
    rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

static LIMITER: OnceLock<Limiter> = OnceLock::new();

fn limiter() -> &'static Limiter {
    LIMITER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_CONCURRENT_REQUESTS);
        for _ in 0..MAX_CONCURRENT_REQUESTS {
            tx.send(()).unwrap();
        }
        Limiter {
            tx,
            rx: std::sync::Mutex::new(rx),
        }
    })
}

/// One lane of the global request budget; released on drop.
struct Slot;

fn acquire_slot() -> Slot {
    limiter().rx.lock().unwrap().recv().unwrap();
    Slot
}

impl Drop for Slot {
    fn drop(&mut self) {
        let _ = limiter().tx.send(());
    }
}

pub fn get_text(url: &str) -> Result<String> {
    let _slot = acquire_slot();
    let start = std::time::Instant::now();
    let result = get_text_inner(url);
    log_slow("GET", url, &start);
    result
}

fn get_text_inner(url: &str) -> Result<String> {
    let mut resp = agent()
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {url}: HTTP {}", resp.status());
    }
    resp.body_mut()
        .read_to_string()
        .with_context(|| format!("reading body of {url}"))
}

pub fn get_bytes(url: &str) -> Result<Vec<u8>> {
    let _slot = acquire_slot();
    let start = std::time::Instant::now();
    let result = get_bytes_inner(url);
    log_slow("GET", url, &start);
    result
}

fn get_bytes_inner(url: &str) -> Result<Vec<u8>> {
    let mut resp = agent()
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {url}: HTTP {}", resp.status());
    }
    let mut buf = Vec::new();
    resp.body_mut()
        .as_reader()
        .read_to_end(&mut buf)
        .with_context(|| format!("reading body of {url}"))?;
    Ok(buf)
}

/// At `-v`, log any request slower than a second: hangs hide in totals.
fn log_slow(method: &str, url: &str, start: &std::time::Instant) {
    if VERBOSE.load(Ordering::Relaxed) {
        let elapsed = start.elapsed();
        if elapsed.as_secs() >= 1 {
            eprintln!(
                "[http] slow {} {url}: {:.1}s",
                method,
                elapsed.as_secs_f32()
            );
        }
    }
}

/// GET with retries for transient failures (dropped connections, 429s,
/// 5xx) when many requests fire at once. Client errors other than 429 fail
/// immediately. Same policy as the OSV detail fetches.
pub fn get_text_retry(url: &str) -> Result<String> {
    with_retry(url, get_text)
}

/// Same retry policy for binary responses (AAR downloads).
pub fn get_bytes_retry(url: &str) -> Result<Vec<u8>> {
    with_retry(url, get_bytes)
}

/// Same retry policy for JSON responses (registry lookups).
pub fn get_json_retry<T: serde::de::DeserializeOwned>(url: &str) -> Result<T> {
    with_retry(url, get_json::<T>)
}

/// Same retry policy for idempotent JSON POSTs (OSV batch queries).
pub fn post_json_retry<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T> {
    with_retry(url, |u| post_json(u, body))
}

/// HEAD a URL and return its `Last-Modified` header, if any. Maven
/// publishes no per-version date API, so artifact dates come from the
/// file metadata of the versioned POM.
pub fn head_last_modified_retry(url: &str) -> Result<Option<String>> {
    with_retry(url, head_last_modified)
}

fn head_last_modified(url: &str) -> Result<Option<String>> {
    let _slot = acquire_slot();
    let start = std::time::Instant::now();
    let result = head_last_modified_inner(url);
    log_slow("HEAD", url, &start);
    result
}

fn head_last_modified_inner(url: &str) -> Result<Option<String>> {
    let resp = agent()
        .head(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("HEAD {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("HEAD {url}: HTTP {}", resp.status());
    }
    Ok(resp
        .headers()
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string))
}

fn with_retry<T>(url: &str, fetch: impl Fn(&str) -> Result<T>) -> Result<T> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(250 * (1 << (attempt - 1))));
        }
        match fetch(url) {
            Ok(body) => return Ok(body),
            Err(e) => {
                if is_final(&e) {
                    return Err(e);
                }
                if VERBOSE.load(Ordering::Relaxed) {
                    eprintln!(
                        "[http] attempt {}/4 failed for {url}: {}",
                        attempt + 1,
                        short_error(&e, 160)
                    );
                }
                last = Some(e);
            }
        }
    }
    Err(last.expect("retry loop always makes an attempt"))
}

/// Client errors other than 429 are not worth retrying.
pub fn is_final(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        matches!(cause.downcast_ref::<ureq::Error>(), Some(ureq::Error::StatusCode(code)) if *code != 429 && (400..500).contains(code))
    })
}

pub fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T> {
    let _slot = acquire_slot();
    let mut resp = agent()
        .get(url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json")
        .call()
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {url}: HTTP {}", resp.status());
    }
    resp.body_mut()
        .read_json::<T>()
        .with_context(|| format!("decoding JSON from {url}"))
}

/// Whether an HTTP failure was a 404 (unknown package/module) as opposed to
/// a network or server problem. Used to give precise "could not check" reasons.
pub fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ureq::Error>(),
            Some(ureq::Error::StatusCode(404))
        )
    })
}

/// First line of an error, truncated, for gap reasons. The method+URL
/// prefix is redundant (callers name the source) and would eat the budget,
/// so it is stripped; DNS failures get plain words.
pub fn short_error(e: &anyhow::Error, max: usize) -> String {
    let mut flat: String = format!("{e:#}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for method in ["GET ", "POST ", "HEAD "] {
        if let Some(rest) = flat.strip_prefix(method)
            && let Some(pos) = rest.find(": ")
        {
            flat = rest[pos + 2..].to_string();
            break;
        }
    }
    flat = flat
        .replace(
            "failed to lookup address information: Temporary failure in name resolution",
            "temporary DNS resolution failure",
        )
        .replace(
            "failed to lookup address information",
            "DNS resolution failed",
        );
    if flat.chars().count() <= max {
        return flat;
    }
    flat.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

pub fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T> {
    let _slot = acquire_slot();
    let mut resp = agent()
        .post(url)
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/json")
        .send_json(body)
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("POST {url}: HTTP {}", resp.status());
    }
    resp.body_mut()
        .read_json::<T>()
        .with_context(|| format!("decoding JSON from {url}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_error_strips_url_and_clarifies_dns() {
        let dns = anyhow::anyhow!(
            "GET https://crates.io/api/v1/crates/lab: \
             io: failed to lookup address information: Temporary failure in name resolution"
        );
        assert_eq!(
            short_error(&dns, 100),
            "io: temporary DNS resolution failure"
        );
        let http = anyhow::anyhow!("GET https://x.io/y: HTTP 500");
        assert_eq!(short_error(&http, 100), "HTTP 500");
    }
}
