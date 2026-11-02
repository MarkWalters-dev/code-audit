//! Disk cache for registry/version lookups and OSV results.
//!
//! SQLite key/value store (`cache.db` under the platform cache dir):
//! string keys to `{fetched_at, payload}` rows, payload as JSON text.
//! Every write commits immediately (write-through), so a killed run keeps
//! its progress, and concurrent audits share through SQLite's locking
//! instead of last-writer-wins clobbering each other.
//!
//! Only successful lookups are cached — misses and transient failures
//! always re-fetch. Version data lives 24h by default (configurable),
//! vulnerability data 6h. Entries are never deleted on expiry (only
//! `--clear-cache` removes them): when a lookup fails transiently —
//! offline, rate-limited, DNS hiccup — the last-known value is served
//! instead, flagged as stale.
//!
//! Two data shapes, each where it fits:
//!
//! - `entries`: volatile lookup cache (latest versions, OSV, EOL, ...).
//!   Schemaless keys with TTLs and stale fallback; rows churn constantly,
//!   so a key/value table is the honest shape (the same shape memcached
//!   and Redis use for the same reason).
//! - `licenses` + `package_licenses`: durable per-version license log.
//!   Published releases never change license, so this is append-only
//!   history, normalized (one lookup table, integer references) for
//!   license-change detection across runs.
//!
//! Format gating: the database's `PRAGMA user_version` must equal
//! [`CACHE_FORMAT_VERSION`] when opened and again inside every write
//! transaction (after taking the write lock, so a concurrent migrator
//! cannot slip between the check and the write). Older databases are
//! upgraded by directed migrations (see [`migrate`]), each writing a
//! `cache.db.bak.<from>` snapshot first via `VACUUM INTO` (WAL-safe).
//! Anything newer than this binary exits with an error instead of
//! risking corruption: SQLite errors alone cannot catch this, since a
//! newer schema may accept our SQL while giving the rows a different
//! meaning. The legacy JSON file (format 1) is imported once with its
//! fetch times intact; the JSON is never deleted, only renamed aside
//! (see [`migrate_legacy_json`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

/// Default TTL for latest/resolved/EOL version data (24h).
/// Overridable per project via `[cache] versions_ttl_hours`.
pub const TTL_VERSIONS_SECS: u64 = 24 * 3600;
/// TTL for vulnerability data: advisories only grow, but stay fresher.
pub const TTL_VULNS_SECS: u64 = 6 * 3600;
/// TTL for immutable per-release metadata (release dates, AAR manifests,
/// POMs): effectively forever, since published artifacts never change.
pub const TTL_FOREVER_SECS: u64 = 10 * 365 * 24 * 3600;

/// Cache format this binary reads and writes (`PRAGMA user_version`).
/// Format 1 was the legacy JSON file, imported once on first open;
/// format 2 added nothing but the SQLite store; format 3 adds the
/// normalized license log (imported from the v2 license keys).
pub const CACHE_FORMAT_VERSION: u32 = 3;

/// Process exit code for a cache format mismatch (see `run()` in main).
pub const EXIT_CACHE_MISMATCH: i32 = 3;

pub struct Cache {
    path: PathBuf,
    conn: Mutex<Connection>,
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
    warned_write: AtomicBool,
    enabled: bool,
    /// TTL for version data; set per project from `[cache] versions_ttl_hours`.
    versions_ttl: AtomicU64,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("path", &self.path)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl Cache {
    /// Open the cache, migrating a legacy JSON file if this is the first
    /// run. Fails when the database carries a foreign format version or
    /// is unreadable — the caller exits instead of touching it.
    pub fn load(enabled: bool, versions_ttl: u64) -> Result<Self, String> {
        Self::open_at(&cache_file(), enabled, versions_ttl)
    }

    pub(crate) fn open_at(path: &Path, enabled: bool, versions_ttl: u64) -> Result<Self, String> {
        if !enabled {
            // Bypass: in-memory database, never touches (or migrates) disk.
            let conn = Connection::open_in_memory().map_err(|e| format!("in-memory cache: {e}"))?;
            init_db(&conn)?;
            return Ok(Self::new(path.to_path_buf(), conn, false, versions_ttl));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        // Migrate the legacy JSON file exactly once: only when no database
        // exists yet, so a later run can never resurrect stale data.
        if !path.is_file()
            && let Some(count) = migrate_legacy_json(path)?
        {
            eprintln!(
                "depaudit: migrated {count} cache entries from {} (original preserved as {}.migrated)",
                path.with_extension("json").display(),
                path.with_extension("json").display(),
            );
        }
        let mut conn =
            Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        configure(&conn)?;
        gate_or_init(&mut conn, path)?;
        Ok(Self::new(path.to_path_buf(), conn, true, versions_ttl))
    }

    fn new(path: PathBuf, conn: Connection, enabled: bool, versions_ttl: u64) -> Self {
        Self {
            path,
            conn: Mutex::new(conn),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale: AtomicU64::new(0),
            warned_write: AtomicBool::new(false),
            enabled,
            versions_ttl: AtomicU64::new(versions_ttl),
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// TTL for version data (default 24h, see `[cache] versions_ttl_hours`).
    pub fn versions_ttl(&self) -> u64 {
        self.versions_ttl.load(Ordering::Relaxed)
    }

    pub fn set_versions_ttl(&self, ttl: u64) {
        self.versions_ttl.store(ttl, Ordering::Relaxed);
    }

    /// Look up `key`, returning `None` on miss, expiry or type mismatch.
    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str, ttl_secs: u64) -> Option<T> {
        if !self.enabled {
            return None;
        }
        let conn = self.conn.lock().unwrap();
        let (payload, fetched_at): (String, i64) = conn
            .query_row(
                "SELECT payload, fetched_at FROM entries WHERE key = ?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok()?;
        let age = unix_now().saturating_sub(fetched_at.try_into().unwrap_or(0));
        if age < ttl_secs {
            match serde_json::from_str(&payload) {
                Ok(value) => {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    Some(value)
                }
                Err(_) => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Last-known value for `key` regardless of TTL, for serving stale on
    /// lookup failure. Counts separately from hits/misses.
    pub fn get_stale<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        if !self.enabled {
            return None;
        }
        let conn = self.conn.lock().unwrap();
        let payload: String = conn
            .query_row(
                "SELECT payload FROM entries WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok()?;
        match serde_json::from_str(&payload) {
            Ok(value) => {
                self.stale.fetch_add(1, Ordering::Relaxed);
                Some(value)
            }
            Err(_) => None,
        }
    }

    /// Store a successful lookup result, committed immediately.
    pub fn set<T: Serialize>(&self, key: &str, value: &T) {
        if !self.enabled {
            return;
        }
        let Ok(payload) = serde_json::to_string(value) else {
            return;
        };
        let mut conn = self.conn.lock().unwrap();
        // BEGIN IMMEDIATE takes the write lock first; the format check
        // inside it then cannot race a concurrent migrator.
        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(e) => {
                self.warn_write(&e);
                return;
            }
        };
        match tx.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0)) {
            Ok(CACHE_FORMAT_VERSION) => {}
            Ok(found) => fatal_version_mismatch(&self.path, found),
            Err(e) => {
                self.warn_write(&e);
                return;
            }
        }
        let stored_at = unix_now() as i64;
        let updated = tx.execute(
            "INSERT OR REPLACE INTO entries (key, fetched_at, payload) VALUES (?1, ?2, ?3)",
            params![key, stored_at, payload],
        );
        if let Err(e) = updated {
            self.warn_write(&e);
            return;
        }
        if let Err(e) = tx.commit() {
            self.warn_write(&e);
        }
    }

    /// Resolved licenses for one used version: `Some` (even empty)
    /// means resolved, so unknown stays unknown without refetching.
    /// Reads the normalized log first, then the legacy empty-marker row
    /// in `entries` — that order also lets a corrected resolution
    /// supersede a stale marker without deleting anything.
    pub fn license_resolution(
        &self,
        cache_key: &str,
        eco: &str,
        name: &str,
        version: &str,
    ) -> Option<Vec<String>> {
        if !self.enabled {
            return None;
        }
        let conn = self.conn.lock().unwrap();
        let logged: Vec<String> = conn
            .prepare(
                "SELECT l.spdx FROM package_licenses p
                 JOIN licenses l ON l.id = p.license_id
                 WHERE p.eco = ?1 AND p.name = ?2 AND p.version = ?3
                 ORDER BY l.spdx",
            )
            .ok()?
            .query_map(params![eco, name, version], |row| row.get(0))
            .ok()?
            .collect::<Result<_, _>>()
            .unwrap_or_default();
        if !logged.is_empty() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(logged);
        }
        let payload: String = conn
            .query_row(
                "SELECT payload FROM entries WHERE key = ?1",
                params![cache_key],
                |row| row.get(0),
            )
            .ok()?;
        match serde_json::from_str(&payload) {
            Ok(ids) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(ids)
            }
            Err(_) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Store a license resolution: known ids go to the normalized log
    /// (forever history), an empty set to the cache as the
    /// resolved-unknown marker. Same gated immediate transaction as `set`.
    pub fn store_license_resolution(
        &self,
        cache_key: &str,
        eco: &str,
        name: &str,
        version: &str,
        licenses: &[String],
    ) {
        if !self.enabled {
            return;
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(e) => {
                self.warn_write(&e);
                return;
            }
        };
        match tx.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0)) {
            Ok(CACHE_FORMAT_VERSION) => {}
            Ok(found) => fatal_version_mismatch(&self.path, found),
            Err(e) => {
                self.warn_write(&e);
                return;
            }
        }
        let stored_at = unix_now() as i64;
        let updated = if licenses.is_empty() {
            tx.execute(
                "INSERT OR REPLACE INTO entries (key, fetched_at, payload) VALUES (?1, ?2, '[]')",
                params![cache_key, stored_at],
            )
            .map(|_| ())
            .map_err(|e| format!("store license marker: {e}"))
        } else {
            licenses
                .iter()
                .try_for_each(|id| log_license_row(&tx, eco, name, version, id, stored_at))
        };
        if let Err(e) = updated {
            eprintln!(
                "depaudit: warning: license log write to {} failed ({e}); continuing",
                self.path.display()
            );
            return;
        }
        if let Err(e) = tx.commit() {
            self.warn_write(&e);
        }
    }

    /// One stderr warning per run when writes fail (disk full, read-only
    /// file, ...): the audit continues, it just cannot cache anything new.
    fn warn_write(&self, e: &rusqlite::Error) {
        if !self.warned_write.swap(true, Ordering::Relaxed) {
            eprintln!(
                "depaudit: warning: cache write to {} failed ({e}); continuing without caching new entries",
                self.path.display()
            );
        }
    }

    /// Checkpoint the write-ahead log so it stays small across runs.
    /// All entries are already committed by `set()`; this only tidies.
    pub fn save(&self) {
        if !self.enabled {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
    }

    /// Drop everything: volatile entries and the license log alike.
    /// Ungated by design: explicit user intent via `--clear-cache`, which
    /// also removes an unmigrated legacy JSON file so the next run cannot
    /// migrate supposedly cleared data back. `*.migrated` / `*.corrupt` /
    /// `*.bak.*` backups are left alone.
    pub fn clear(&self) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute_batch(
            "DELETE FROM entries; DELETE FROM package_licenses; DELETE FROM licenses;
             PRAGMA wal_checkpoint(TRUNCATE)",
        );
        let _ = std::fs::remove_file(legacy_json_path(&self.path));
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    pub fn stale_count(&self) -> u64 {
        self.stale.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        Self::new(PathBuf::from(":memory:"), conn, true, TTL_VERSIONS_SECS)
    }

    /// Plant one row with an explicit fetch time, for expiry tests.
    #[cfg(test)]
    fn plant(&self, key: &str, fetched_at: u64, payload: serde_json::Value) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO entries (key, fetched_at, payload) VALUES (?1, ?2, ?3)",
            params![key, fetched_at as i64, payload.to_string()],
        )
        .unwrap();
    }
}

/// Refuse to write a foreign-format database: exit, never corrupt.
fn fatal_version_mismatch(path: &Path, found: u32) -> ! {
    eprintln!(
        "depaudit: refusing to write {}: cache format version {found}, this depaudit writes version {CACHE_FORMAT_VERSION}. Run the matching depaudit version; --clear-cache starts a fresh cache (deletes cached data)",
        path.display()
    );
    std::process::exit(EXIT_CACHE_MISMATCH);
}

/// Locking and durability pragmas. The busy timeout lets parallel audits
/// share the database; the rest are best-effort speedups — correctness
/// never depends on them.
fn configure(conn: &Connection) -> Result<(), String> {
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| format!("configure cache: {e}"))?;
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(None, "synchronous", "NORMAL");
    Ok(())
}

/// Full current schema: volatile key/value cache plus the normalized
/// license log. Fresh installs and in-memory/test databases start here.
fn init_db(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(SCHEMA_V3)
        .map_err(|e| format!("create cache schema: {e}"))?;
    conn.pragma_update(None, "user_version", CACHE_FORMAT_VERSION)
        .map_err(|e| format!("stamp cache version: {e}"))?;
    Ok(())
}

/// Current schema (format 3). `package_licenses` is append-only history:
/// one row per (ecosystem, package, version, license) with the first
/// observation time. Its primary key prefixes (eco, name), so per-package
/// history reads are indexed with no extra index.
const SCHEMA_V3: &str = "
CREATE TABLE IF NOT EXISTS entries (
  key TEXT PRIMARY KEY,
  fetched_at INTEGER NOT NULL,
  payload TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY,
  spdx TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS package_licenses (
  eco TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  license_id INTEGER NOT NULL REFERENCES licenses(id),
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (eco, name, version, license_id)
) WITHOUT ROWID;";

/// Accept the database only if it carries our format version, initializing
/// a fresh/empty file. Older databases migrate forward (backup first);
/// newer-than-binary or corrupt ones are an error for the caller to exit
/// on — the file is never modified on that path.
fn gate_or_init(conn: &mut Connection, path: &Path) -> Result<(), String> {
    let version: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| {
            format!(
                "read {}: {e}; if the file is corrupt, back it up and use --clear-cache to start fresh",
                path.display()
            )
        })?;
    if version == CACHE_FORMAT_VERSION {
        return Ok(());
    }
    if version == 0 && !has_entries_table(conn)? {
        return init_db(conn);
    }
    if version < CACHE_FORMAT_VERSION {
        return migrate(conn, path, version);
    }
    Err(format!(
        "cache format mismatch: {} is version {version}, this depaudit reads/writes version {CACHE_FORMAT_VERSION}. Run the matching depaudit version; --clear-cache starts a fresh cache (deletes cached data)",
        path.display()
    ))
}

/// Directed upgrade `from` -> [`CACHE_FORMAT_VERSION`], one ordered step
/// per version. A `VACUUM INTO` snapshot (`cache.db.bak.<from>`) lands
/// before anything is touched — it reads a consistent image even in WAL
/// mode, and an existing snapshot is left alone (a concurrent run may
/// have taken it). The migration itself runs in an immediate transaction
/// with the version re-checked inside, so concurrent upgraders serialize
/// and losers observe the winner's result.
fn migrate(conn: &mut Connection, path: &Path, from: u32) -> Result<(), String> {
    let backup = path.with_extension(format!("db.bak.{from}"));
    if !backup.is_file() {
        conn.execute(
            "VACUUM INTO ?1",
            params![backup.to_string_lossy().to_string()],
        )
        .map_err(|e| format!("back up {} to {}: {e}", path.display(), backup.display()))?;
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("migrate cache: {e}"))?;
    let current: u32 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| format!("migrate cache: {e}"))?;
    if current == CACHE_FORMAT_VERSION {
        return Ok(()); // Lost the race; the winner already migrated.
    }
    if current != from {
        return Err(format!(
            "migrate cache: expected version {from}, found {current}; refusing to migrate an unexpected state"
        ));
    }
    if current == 2 {
        migrate_2_to_3(&tx)?;
    }
    tx.pragma_update(None, "user_version", CACHE_FORMAT_VERSION)
        .map_err(|e| format!("stamp cache version: {e}"))?;
    tx.commit().map_err(|e| format!("migrate cache: {e}"))?;
    eprintln!(
        "depaudit: migrated cache {} v{from} -> v{CACHE_FORMAT_VERSION} (pre-migration snapshot at {})",
        path.display(),
        backup.display()
    );
    Ok(())
}

/// Format 3: normalized license log, backfilled from the v2 license keys
/// (`v1:license:<eco>:<name>:<version>` -> JSON id list), keeping each
/// row's original fetch time as its observation time. Cache-only rows
/// are untouched: `:latest` approximations are crate-level, not
/// per-version history, and empty resolutions stay in `entries` as the
/// resolved-unknown marker. The backfill is idempotent (re-running a
/// half-finished migration inserts nothing twice).
fn migrate_2_to_3(tx: &rusqlite::Transaction) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS licenses (
           id INTEGER PRIMARY KEY,
           spdx TEXT NOT NULL UNIQUE
         );
         CREATE TABLE IF NOT EXISTS package_licenses (
           eco TEXT NOT NULL,
           name TEXT NOT NULL,
           version TEXT NOT NULL,
           license_id INTEGER NOT NULL REFERENCES licenses(id),
           observed_at INTEGER NOT NULL,
           PRIMARY KEY (eco, name, version, license_id)
         ) WITHOUT ROWID;",
    )
    .map_err(|e| format!("migrate cache: {e}"))?;
    let mut select = tx
        .prepare("SELECT key, fetched_at, payload FROM entries WHERE key LIKE 'v1:license:%'")
        .map_err(|e| format!("migrate cache: {e}"))?;
    let rows: Vec<(String, i64, String)> = select
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| format!("migrate cache: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("migrate cache: {e}"))?;
    for (key, fetched_at, payload) in &rows {
        let Some((raw_eco, name, version)) = split_license_key(key) else {
            continue;
        };
        if version == "latest" {
            continue;
        }
        // Canonical log tags are checker ids; v2 Android keys say `maven`.
        let eco = if raw_eco == "maven" {
            "android"
        } else {
            raw_eco
        };
        let Ok(ids) = serde_json::from_str::<Vec<String>>(payload) else {
            continue;
        };
        for id in &ids {
            log_license_row(tx, eco, name, version, id, *fetched_at)?;
        }
    }
    Ok(())
}

/// `v1:license:<eco>:<name>:<version>` -> parts. Names may contain `:`
/// (Maven `group:artifact`, Go module paths), so the ecosystem is the
/// first segment and the version the last.
fn split_license_key(key: &str) -> Option<(&str, &str, &str)> {
    let rest = key.strip_prefix("v1:license:")?;
    let (eco, rest) = rest.split_once(':')?;
    let (name, version) = rest.rsplit_once(':')?;
    if eco.is_empty() || name.is_empty() || version.is_empty() {
        return None;
    }
    Some((eco, name, version))
}

/// One idempotent history row: lookup id first (inserting the SPDX text
/// when unseen), then the package row keyed on first observation.
fn log_license_row(
    tx: &rusqlite::Transaction,
    eco: &str,
    name: &str,
    version: &str,
    spdx: &str,
    observed_at: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT OR IGNORE INTO licenses (spdx) VALUES (?1)",
        params![spdx],
    )
    .map_err(|e| format!("log license: {e}"))?;
    let id: i64 = tx
        .query_row(
            "SELECT id FROM licenses WHERE spdx = ?1",
            params![spdx],
            |row| row.get(0),
        )
        .map_err(|e| format!("log license: {e}"))?;
    tx.execute(
        "INSERT OR IGNORE INTO package_licenses (eco, name, version, license_id, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![eco, name, version, id, observed_at],
    )
    .map_err(|e| format!("log license: {e}"))?;
    Ok(())
}

fn has_entries_table(conn: &Connection) -> Result<bool, String> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'entries'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("inspect cache schema: {e}"))?;
    Ok(count > 0)
}

/// Legacy JSON layout (format 1), read-only: used once to import.
#[derive(Deserialize)]
struct LegacyEntry {
    fetched_at: u64,
    payload: serde_json::Value,
}

#[derive(Deserialize)]
struct LegacyStore {
    v: u32,
    entries: HashMap<String, LegacyEntry>,
}

fn legacy_json_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("json")
}

/// Import a legacy `cache.json` (format 1) into a fresh database, keeping
/// every entry's original fetch time so TTLs survive the move. The JSON
/// file is never deleted: renamed to `cache.json.migrated` on success
/// (`.corrupt` / `.unmigrated` when it cannot be imported, with a warning,
/// and the run proceeds with an empty cache). Returns the imported entry
/// count, or `None` when no JSON file exists. Concurrent first runs are
/// safe: the import is idempotent and the rename is atomic.
fn migrate_legacy_json(db_path: &Path) -> Result<Option<usize>, String> {
    let json_path = legacy_json_path(db_path);
    let text = match std::fs::read_to_string(&json_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", json_path.display())),
    };
    let store: LegacyStore = match serde_json::from_str(&text) {
        Ok(store) => store,
        Err(e) => {
            let kept = json_path.with_extension("json.corrupt");
            let _ = std::fs::rename(&json_path, &kept);
            eprintln!(
                "depaudit: warning: {} is not valid cache JSON ({e}); preserved as {} and starting with an empty cache",
                json_path.display(),
                kept.display()
            );
            return Ok(Some(0));
        }
    };
    if store.v != 1 {
        let kept = json_path.with_extension("json.unmigrated");
        let _ = std::fs::rename(&json_path, &kept);
        eprintln!(
            "depaudit: warning: {} is JSON cache version {}, which this depaudit does not import; preserved as {} and starting with an empty cache",
            json_path.display(),
            store.v,
            kept.display()
        );
        return Ok(Some(0));
    }
    let mut conn =
        Connection::open(db_path).map_err(|e| format!("create {}: {e}", db_path.display()))?;
    init_db(&conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("migrate cache: {e}"))?;
    for (key, entry) in &store.entries {
        tx.execute(
            "INSERT OR REPLACE INTO entries (key, fetched_at, payload) VALUES (?1, ?2, ?3)",
            params![key, entry.fetched_at as i64, entry.payload.to_string()],
        )
        .map_err(|e| format!("migrate cache: {e}"))?;
    }
    tx.commit().map_err(|e| format!("migrate cache: {e}"))?;
    drop(conn);
    let count = store.entries.len();
    // Ignore rename failures: a concurrent first run may have won the race.
    let kept = json_path.with_extension("json.migrated");
    let _ = std::fs::rename(&json_path, &kept);
    Ok(Some(count))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_file() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            return dir.join("depaudit").join("cache.db");
        }
        if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            return home.join(".cache").join("depaudit").join("cache.db");
        }
        return PathBuf::from("depaudit-cache.db");
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            return home
                .join("Library")
                .join("Caches")
                .join("depaudit")
                .join("cache.db");
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(dir) = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
            return dir.join("depaudit").join("cache.db");
        }
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            return home.join(".cache").join("depaudit").join("cache.db");
        }
    }
    #[allow(unreachable_code)]
    PathBuf::from("depaudit-cache.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cache() -> Cache {
        Cache::for_test()
    }

    #[test]
    fn roundtrip_and_expiry() {
        let cache = test_cache();
        cache.set("k", &"v1".to_string());
        assert_eq!(cache.get::<String>("k", 60), Some("v1".to_string()));
        // TTL 0 expires immediately.
        assert_eq!(cache.get::<String>("k", 0), None);
        // Type mismatch is a miss.
        assert_eq!(cache.get::<u64>("k", 60), None);
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 2);
    }

    #[test]
    fn stale_entries_miss() {
        let cache = test_cache();
        cache.plant(
            "old",
            unix_now().saturating_sub(3600),
            serde_json::json!("v"),
        );
        assert_eq!(cache.get::<String>("old", 60), None);
        assert_eq!(cache.get::<String>("old", 7200), Some("v".to_string()));
    }

    #[test]
    fn disabled_cache_is_transparent() {
        let mut cache = test_cache();
        cache.enabled = false;
        cache.set("k", &"v1".to_string());
        assert_eq!(cache.get::<String>("k", 60), None);
    }

    #[test]
    fn stale_fallback_ignores_ttl() {
        let cache = test_cache();
        cache.set("k", &"v1".to_string());
        // Fresh for normal reads, expired for a zero TTL, always stale-able.
        assert_eq!(cache.get::<String>("k", 60), Some("v1".to_string()));
        assert_eq!(cache.get::<String>("k", 0), None);
        assert_eq!(cache.get_stale::<String>("k"), Some("v1".to_string()));
        assert_eq!(cache.stale_count(), 1);
        assert_eq!(cache.get_stale::<String>("missing"), None);
        assert_eq!(cache.stale_count(), 1);
    }

    #[test]
    fn expired_entries_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        {
            let cache = Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap();
            cache.set("k", &"v1".to_string());
            // Age the entry past any TTL without deleting it. Writes commit
            // immediately, so dropping the cache loses nothing.
            cache.plant("k", 1, serde_json::json!("v1"));
        }
        let reloaded = Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap();
        assert_eq!(reloaded.get::<String>("k", 60), None);
        assert_eq!(reloaded.get_stale::<String>("k"), Some("v1".to_string()));
        // ... and a refresh replaces the entry in place.
        reloaded.set("k", &"v2".to_string());
        assert_eq!(reloaded.get::<String>("k", 60), Some("v2".to_string()));
    }

    #[test]
    fn legacy_json_migrates_without_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.db");
        let json_path = dir.path().join("cache.json");
        let fresh_at = unix_now();
        std::fs::write(
            &json_path,
            serde_json::json!({
                "v": 1,
                "entries": {
                    "fresh": {"fetched_at": fresh_at, "payload": "new"},
                    "old": {"fetched_at": 1, "payload": "ancient"}
                }
            })
            .to_string(),
        )
        .unwrap();
        let cache = Cache::open_at(&db_path, true, TTL_VERSIONS_SECS).unwrap();
        // Fetch times survive the move: TTLs keep working, stale stays stale.
        assert_eq!(cache.get::<String>("fresh", 60), Some("new".to_string()));
        assert_eq!(cache.get::<String>("old", 60), None);
        assert_eq!(
            cache.get_stale::<String>("old"),
            Some("ancient".to_string())
        );
        // The JSON is preserved aside, never deleted ...
        assert!(!json_path.is_file());
        let kept = dir.path().join("cache.json.migrated");
        assert!(kept.is_file());
        // ... and a second open does not re-migrate.
        drop(cache);
        let again = Cache::open_at(&db_path, true, TTL_VERSIONS_SECS).unwrap();
        assert_eq!(again.get::<String>("fresh", 60), Some("new".to_string()));
        assert!(dir.path().read_dir().unwrap().count() >= 2);
    }

    #[test]
    fn foreign_format_version_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        drop(Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap());
        // Simulate a newer depaudit's database.
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99u32).unwrap();
        drop(conn);
        let err = Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap_err();
        assert!(err.contains("version 99"), "{err}");
        assert!(
            err.contains(&format!("version {CACHE_FORMAT_VERSION}")),
            "{err}"
        );
        // The foreign file is untouched.
        let conn = Connection::open(&path).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 99);
    }

    #[test]
    fn corrupt_db_errors_without_deleting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        std::fs::write(&path, b"definitely not sqlite").unwrap();
        let err = Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap_err();
        assert!(err.contains("--clear-cache"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"definitely not sqlite");
    }

    #[test]
    fn license_log_roundtrip_and_unknown_marker() {
        let cache = test_cache();
        let mit = vec!["MIT".to_string()];
        assert_eq!(
            cache.license_resolution("v1:license:python:six:1.15.0", "python", "six", "1.15.0"),
            None
        );
        cache.store_license_resolution(
            "v1:license:python:six:1.15.0",
            "python",
            "six",
            "1.15.0",
            &mit,
        );
        assert_eq!(
            cache.license_resolution("v1:license:python:six:1.15.0", "python", "six", "1.15.0"),
            Some(mit)
        );
        // Unknown resolutions are remembered without a log row.
        cache.store_license_resolution("v1:license:node:odd:1.0.0", "node", "odd", "1.0.0", &[]);
        assert_eq!(
            cache.license_resolution("v1:license:node:odd:1.0.0", "node", "odd", "1.0.0"),
            Some(Vec::new())
        );
        // Lookup table deduplicates: MIT stored once.
        let conn = cache.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM licenses", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn v2_migration_backs_up_and_imports_licenses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE entries (
                   key TEXT PRIMARY KEY,
                   fetched_at INTEGER NOT NULL,
                   payload TEXT NOT NULL
                 ) WITHOUT ROWID;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO entries (key, fetched_at, payload) VALUES
                 ('v1:license:python:six:1.15.0', 1000, '[\"MIT\"]'),
                 ('v1:license:maven:junit:junit:4.13.1', 2000, '[\"EPL-1.0\"]'),
                 ('v1:license:rust:regex:latest', 3000, '[\"MIT\"]'),
                 ('v1:license:node:odd:1.0.0', 4000, '[]'),
                 ('v1:latest:python:six', 5000, '{\"latest\":\"1.17.0\"}')",
                [],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 2).unwrap();
        }
        let cache = Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap();
        // Snapshot of the v2 database exists; the live db is stamped v3.
        assert!(dir.path().join("cache.db.bak.2").is_file());
        {
            let conn = cache.conn.lock().unwrap();
            let version: u32 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, CACHE_FORMAT_VERSION);
        }
        // Known licenses imported with original fetch times; maven tag
        // canonicalized to the android checker id.
        assert_eq!(
            cache.license_resolution("v1:license:python:six:1.15.0", "python", "six", "1.15.0"),
            Some(vec!["MIT".to_string()])
        );
        assert_eq!(
            cache.license_resolution(
                "v1:license:maven:junit:junit:4.13.1",
                "android",
                "junit:junit",
                "4.13.1"
            ),
            Some(vec!["EPL-1.0".to_string()])
        );
        {
            let conn = cache.conn.lock().unwrap();
            let observed: i64 = conn
                .query_row(
                    "SELECT observed_at FROM package_licenses
                     WHERE eco = 'android' AND name = 'junit:junit'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(observed, 2000);
        }
        // Crate-level approximations stay cache-only; empties stay markers.
        assert_eq!(
            cache.license_resolution("v1:license:rust:regex:latest", "rust", "regex", "latest"),
            Some(vec!["MIT".to_string()])
        );
        assert_eq!(
            cache.license_resolution("v1:license:node:odd:1.0.0", "node", "odd", "1.0.0"),
            Some(Vec::new())
        );
        // Non-license rows untouched.
        assert!(
            cache
                .get_stale::<serde_json::Value>("v1:latest:python:six")
                .is_some()
        );
    }

    #[test]
    fn newer_database_still_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V3).unwrap();
            conn.pragma_update(None, "user_version", CACHE_FORMAT_VERSION + 1)
                .unwrap();
        }
        let err = Cache::open_at(&path, true, TTL_VERSIONS_SECS).unwrap_err();
        assert!(err.contains("format mismatch"), "{err}");
        assert!(!dir.path().join("cache.db.bak.4").is_file());
    }

    #[test]
    fn unreadable_legacy_json_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.db");
        let json_path = dir.path().join("cache.json");
        std::fs::write(&json_path, b"{oops").unwrap();
        let cache = Cache::open_at(&db_path, true, TTL_VERSIONS_SECS).unwrap();
        assert_eq!(cache.get_stale::<String>("anything"), None);
        assert!(!json_path.is_file());
        assert_eq!(
            std::fs::read(dir.path().join("cache.json.corrupt")).unwrap(),
            b"{oops"
        );
    }
}
