# depaudit

One command to audit a project's dependencies for **outdated** and
**vulnerable** libraries — across Python, JavaScript/TypeScript, Rust, Go and
Android projects.

`depaudit` is a single static binary with zero runtime dependencies: no
`npm-check-updates`, `cargo-outdated`, `osv-scanner`, `trivy` or language
toolchains required. It parses your project files directly, resolves the
latest releases from each ecosystem's registry, checks every known version
against the [OSV vulnerability database](https://osv.dev) (the same data
behind osv-scanner: NVD/CVE, GHSA, RustSec, Go vuln DB, PyPA, ...), and
checks the language/toolchain versions your project pins.

## Install

Requires the Rust toolchain (https://rustup.rs/):

```sh
cargo install --path .
```

Or build and run directly (always use `--release` outside development —
the local scans are regex-heavy and debug builds run several times slower):

```sh
cargo build --release
./target/release/depaudit /path/to/project
```

## Usage

```sh
depaudit [PATH] [OPTIONS]

Options:
      --only <a,b>       Only audit these ecosystems: python, node, rust, go, android
      --exclude <c>      Skip these ecosystems
      --outdated-only    Only check for outdated dependencies
      --vulns-only       Only check for vulnerabilities
      --lint-only        Only run linters
      --no-lint          Skip linters
      --sbom             CycloneDX SBOM (JSON) to stdout instead of the report
      --deep             Include transitive/indirect deps in the outdated check
                         (vulnerabilities always cover every known dependency)
      --json             Machine-readable report
      --fail-on-outdated Exit 1 when any outdated dependency is found
      --fail-on-vulns    Exit 1 when any vulnerability is found
      --max-compile-sdk N  Cap Android updates to releases needing at most this compileSdk
      --no-cache         Bypass the disk cache
      --clear-cache      Clear the disk cache before auditing
  -v, --verbose          Print extra progress information
  -q, --quiet            Silence progress output (reports still print)
```

Progress goes to stderr (`depaudit: checking …`, per-linter
announcements, `depaudit: done in …`), so stdout stays clean for
`--json` / `--sbom` piping; `-q` silences it.

Examples:

```sh
depaudit                                   # audit the current directory
depaudit ~/projects/app --fail-on-vulns    # CI gate on vulnerabilities
depaudit --only python,rust --vulns-only   # targeted audit
depaudit --json > report.json
```

Exit codes: `0` audit completed, `1` findings with a `--fail-on-*` flag,
`2` usage error or nothing detected, `3` cache format mismatch.

## Discovery

`PATH` is searched recursively: every directory containing project markers
is audited, so monorepos and nested projects just work without pointing at
each one. Each project gets its own report section (plus a `Total` line when
there are several); JSON nests per-project reports under `projects` with a
combined `summary`.

Skipped while walking: hidden directories, symlinked paths, and dependency
/ build-output directories (`node_modules`, `target`, `venv`/`.venv`,
`__pycache__`, `build`, `dist`, `vendor`, `_build`, `out`, `*.egg-info`).
A nested directory only counts for ecosystems not already detected in an
ancestor project, so Gradle modules (`app/`) and Cargo workspace members
are audited once at the top instead of twice.

## How each ecosystem is checked

| Ecosystem | Inventory from | Latest from | Current version when ambiguous |
|---|---|---|---|
| Python | installed `dist-info` (`.venv`/`VIRTUAL_ENV`), else `uv/poetry/pdm.lock`, else `requirements*.txt`, `pyproject.toml`, `Pipfile` | PyPI JSON API | unpinned specs resolve to what `pip install` would pick |
| JavaScript | `package.json` + `node_modules`, lockfiles (`package-lock` → `pnpm-lock` → `bun.lock` → `yarn.lock`) | npm registry `/latest` | exact specs count as versions; ranges resolve by satisfaction |
| Rust | `Cargo.toml` (workspace-aware) + `Cargo.lock` | crates.io API | requirements resolve to newest matching non-yanked release |
| Go | `go.mod` requires (+ `replace`, `GOPRIVATE` honored) | Go module proxy `@v/list` | always pinned in `go.mod` |
| Android | `libs.versions.toml`, `build.gradle(.kts)`, known plugin ids | Maven Central + Google Maven | always pinned (dynamic versions skipped) |

Outdated rule: a dependency is outdated when a newer **stable** release
exists (pre-releases only count when you already use one). Without a
lockfile or installed environment, checks reflect what a fresh install
would resolve to today. For Python, direct means a graph root in the
installed environment or lockfile, ignoring the project's own editable
install and `extra`-gated requirements.

By default only direct dependencies are checked for outdatedness;
`--deep` includes transitive ones. Runs that skip transitives say so in
a `note:` line. (Vulnerabilities always cover every known dependency.)

Vulnerabilities come from OSV (`/v1/querybatch` + `/v1/vulns`), one batched
request per ecosystem plus one fetch per unique advisory (retried with
backoff). Every known version — direct and transitive — is checked.
When an advisory names replacements (RustSec's `Alternatives` section, or
prose suggestions in unmaintained advisories), each is shown with its newest
stable release:

```text
    unsafe-libyaml 0.2.11  RUSTSEC-2024-0449
      unsafe-libyaml is unmaintained
      alternatives: saphyr 0.3.3, serde-saphyr 2.0.0
```

All registry reads are retried with backoff (4 attempts; non-429 client
errors fail fast) behind a 6-request concurrency cap, so burst
throttling and transient DNS failures ride through instead of becoming
`could not check` gaps.

JavaScript lockfiles resolve in order `package-lock.json` →
`pnpm-lock.yaml` (nearest up, importer-aware, so workspace members pin
correctly) → `bun.lock` (JSONC, workspace-aware) → `yarn.lock` (v1 and
berry). `catalog:` / `catalog:<name>` specs resolve through
`pnpm-workspace.yaml` and the workspace root `package.json`; `patch:`
suffixed versions compare by their base version. First-party
`workspace:*` / `link:` / `file:` specs are skipped with a note, not
flagged as gaps. `bun.lockb` is binary with no stable spec and is never
parsed — when it is the only lockfile that is named as a gap.

## Sample output

```text
depaudit: /tmp/vuln

[python] Python: 1 outdated, 20 vulnerabilities, 0 tools outdated, 0 blocked, 0 unchecked (1 checked)
  outdated:
    urllib3  1.26.5(2021-05-26) -> 2.8.0(2026-09-15)  (1938d)
  update: pip install -U urllib3==2.8.0
  vulnerabilities:
    urllib3 1.26.5  CVE-2023-43804 (GHSA-v845-jxx5-vc9f)  (HIGH)  fixed in 2.0.6
      `Cookie` HTTP header isn't stripped on cross-origin redirects
    ...

Summary: 1 outdated, 20 vulnerabilities, 0 tools outdated, 0 blocked, 0 unchecked across 1 ecosystem(s) (1 ok, 0 skipped, 0 errors)
```

## Updating

Every ecosystem with outdated dependencies prints a copy-pasteable `update:`
command (also in JSON as `update_command`), run from the project root:

| Ecosystem | Command | Notes |
|---|---|---|
| Python | `pip install -U pkg==ver ...` (`uv pip install` with `uv.lock`) | Upgrades the environment; pin files need manual edits |
| JavaScript | `npm install` / `pnpm update` / `yarn up|upgrade` | Picked from the lockfile (berry vs classic via `.yarnrc.yml`) |
| Rust | `cargo upgrade --incompatible --pinned -p pkg ...` | Needs cargo-edit (`cargo install cargo-edit`); bumps `Cargo.toml` requirements including majors |
| Go | `go get mod@ver ...` | Updates `go.mod` |
| Android | — | Gradle has no stock updater; edit the version catalog / build files |

## Toolchain checks

Each ecosystem also reports outdated language/tool pins in a `tools:`
section (counted by `--fail-on-outdated`):

| Ecosystem | Pins read |
|---|---|
| Python | `requires-python`, `.python-version`, `python_requires`, `.tool-versions`/`mise` |
| JavaScript | `engines`, `packageManager`, `volta`, `.nvmrc`, `.node-version`, `.tool-versions`/`mise` (node, npm, pnpm, yarn, bun) |
| Rust | `rust-version` (MSRV), `rust-toolchain.toml`, `.tool-versions`/`mise` |
| Go | `go` / `toolchain` directives, `.tool-versions`/`mise` |
| Android | Gradle wrapper, Kotlin plugin version (`id(...)`, `kotlin("...")`, catalog), `.tool-versions`/`mise` |

Latest releases come from endoflife.date (Python, Node LTS, Go), the npm
registry (npm, pnpm, yarn incl. berry), GitHub releases (Bun), the Rust
channel manifest, the Gradle version service, and Maven metadata (Kotlin).
For Python, Node and Go the report also flags end-of-life releases, e.g.
`node (engines) >=18 -> 26.13.0 (end-of-life since 2025-04-30)`.
(Vite, AGP and similar are regular dependencies and show up as libraries.)

Separately, **drift** notices compare toolchain pin files against the
host's active binaries: `.nvmrc` / `.node-version` vs `node`,
`.python-version` vs `python3`, `go.mod` vs `go`, `rust-toolchain.toml`
vs `rustc`. Only numeric pins are compared (`stable` / `lts/*` stay
silent, as do missing host binaries), e.g.
`.nvmrc pins node 18, host node is 26.12.1  (drift)`.

## Unchecked dependencies (gaps)

`depaudit` never silently drops a dependency. Anything that cannot be
compared or queried is listed by name in a `could not check:` section,
with a reason, and counted as _unchecked_ in the ecosystem line and the
summary:

```text
[rust] Rust: 1 outdated, 0 vulnerabilities, 7 unchecked (2 checked)
  could not check:
    local (outdated): path dependency has no published version
    no-such-crate-xyz (outdated): not found on crates.io
    weird (vulns): no installed, locked, or pinned version (declared: '>=99')
```

In JSON each ecosystem has a `gaps` array (`{name, check, reason}`,
where `check` is `outdated`, `vulns` or `tool`) and the summary has a
`gaps` count. Common reasons:

| Reason | Ecosystem | Fix |
|---|---|---|
| `path dependency has no published version` | Rust | Remove it or publish the crate |
| `git dependency has no published version` | Rust | Switch to a crates.io version |
| `replaced by local path ...` | Go | Replace the path with a versioned require, or vendor it |
| `matched by GOPRIVATE/GONOSUMDB; skipped` | Go | Unset for public modules, or audit privately |
| `GOPROXY=off` | Go | Set `GOPROXY` to a reachable proxy |
| `dynamic version '1.+' cannot be compared` | Android | Pin an exact version |
| `no matching libs.versions.toml entry` | Android | Add the accessor to the version catalog |
| `install_requires needs execution; ...` | Python | Mirror deps in `requirements.txt` or `pyproject.toml` |
| `no installed, locked, or pinned version` | Python/Node/Rust | Install, lock, or pin the dependency |
| `not found on ...` | any | Check the spelling or the registry |
| `... request failed: ...` | any | Transient network/registry error (retried automatically); re-run if it persists |
| `SDK compatibility unverified: ...` | Android | AAR/POM fetch failed; the newest release is shown assuming it fits — re-run to verify |

## Android SDK compatibility

New Android library releases often require a newer `compileSdk` than your
project has (e.g. `core-ktx 1.19.x` needs compileSdk 37). `depaudit` reads
each candidate release's `minCompileSdk` from its AAR metadata — including
transitive dependencies via their POMs — and reports newer-but-unusable
releases as **blocked** instead of outdated:

```text
[android] Android: 1 outdated, 0 vulnerabilities, 0 tools outdated, 2 blocked, 0 unchecked (15 checked)
  outdated:
    androidx.compose:compose-bom  2026.01.01 -> 2026.09.00
  blocked (need newer compileSdk):
    androidx.core:core-ktx  1.18.0  (latest 1.19.1 needs compileSdk 37)
```

When a newer-but-compatible release exists between your version and the
blocked newest, it is still offered:
`core-ktx 1.18.0 -> 1.18.5 (latest 1.19.1 needs compileSdk 37)`.
In JSON, blocked-only updates appear in the ecosystem's `blocked` array and
partially blocked ones carry a `blocked` object on the outdated entry; the
summary counts them as `blocked`. Blocked updates never trigger
`--fail-on-outdated` (there is nothing actionable to update).

The cap is resolved as: `--max-compile-sdk N` flag, then `depaudit.toml`,
then the `compileSdk` literal auto-detected from your `build.gradle(.kts)`
files (strictest module wins). Pure-JVM artifacts (JAR/POM) and AARs without
metadata declare no requirement and are never blocked.

Limitations: only literal `compileSdk = 36` / `compileSdkVersion 36`
declarations are detected (version-catalog references are not resolved);
transitive requirements resolve literal POM versions only (BOM-managed
versions, ranges, and parent-POM properties are skipped).

## Configuration

Optional `depaudit.toml` in the audited project root:

```toml
[android]
max_compile_sdk = 36

[cache]
versions_ttl_hours = 24

[lint]
enabled = true
# Config-file search order across the three tiers (each named once).
config_order = ["project", "depaudit", "global"]

[licenses]
enabled = true
# Deny whole families ("GPL") or exact ids ("AGPL-3.0-only").
deny = []
```

Unknown keys are ignored; a file that fails to parse is an error.

## Caching

Registry lookups are cached in a SQLite database for 24h by default
(tunable per project, see below) and OSV results for 6h
(`~/.cache/depaudit/cache.db` on Linux), so repeat audits run in
milliseconds with no network. Immutable per-release metadata (release
dates, Android AAR requirements, POMs) is cached effectively forever. Only
successful lookups are cached. `--no-cache` bypasses it, `--clear-cache`
wipes it, and `-v` prints hit/miss/stale stats.

Every write commits immediately, and concurrent audits share the database
through SQLite's locking — a killed run keeps its progress and parallel
runs can no longer clobber each other's entries. The database carries a
format version that is checked on open and inside every write transaction.
Older databases migrate forward automatically, one directed step per
version, with a `cache.db.bak.<from>` snapshot taken first — migrate,
never delete. A database *newer* than the binary exits with an error
(exit code 3) instead of risking corruption, so an old binary can never
damage a newer cache. Run the matching depaudit version, or `--clear-cache`
to start fresh. A legacy `cache.json` from earlier versions is imported
once automatically (the original is preserved as `cache.json.migrated`,
never deleted).

Next to the volatile lookup cache, the database keeps a normalized,
append-only license log (`licenses` + `package_licenses`, one row per
package version and SPDX id) with first-observation times — the same
lookup table / integer-reference shape as any well-designed history
table. That log powers the `license-change` notices: without per-version
history, a relicense between your pinned version and the newest release
would be invisible.

Expired entries are never deleted: when a lookup fails — offline,
rate-limited, DNS hiccup — the last-known value is served instead, flagged
per line (`stale cache: ...`), counted in a `note:`, and listed per
dependency with `-v`. Vulnerability queries degrade the same way. This
makes fully-offline audits work from cache.

Outdated lines also show each version's release date and how many days
apart they are (`1.26.5(2021-05-26) -> 2.8.0(2026-09-15)  (1938d)`), so you
can tell a stale-by-years dependency from a stale-by-days one at a glance.
Dates come from PyPI file uploads, the npm `time` map, crates.io
`created_at`, Go proxy `.info` documents, and Maven POM `Last-Modified`
headers; a published version's date never changes, so these entries are
cached forever. A date that cannot be determined is simply omitted — never
a gap.

## Linting

Each ecosystem's sources are linted after the dependency checks
(`--no-lint` skips this, `--lint-only` runs just this):

- Python: `ruff check`
- JavaScript: the repo's own `eslint` when the repo configures it,
  otherwise `biome lint`
- Rust: `cargo clippy`
- Go: `golangci-lint run`, falling back to `go vet` when golangci-lint
  cannot be installed or run
- Android: `./gradlew lint`, `ktlint`, and `detekt` (detekt only runs
  when a config exists in some tier)

Missing linters are installed globally on first use: ruff via
`uv tool install`, clippy via `rustup component add`, golangci-lint via
`go install ...@latest`, biome via `pnpm add -g`, ktlint/detekt via
GitHub-release downloads into `~/.local/bin`. When the installer itself
is missing (no `uv`, `pnpm`, `go`, `rustup`) or there is no Java runtime
for the JVM linters, that is reported as a gap with instructions instead
of failing obscurely. Repository-owned tools are never installed or
modified: a configured-but-missing eslint is a gap telling you to run
your package manager's install, and Gradle comes from the project's own
wrapper.

Linter configs resolve across three tiers — the audited project, your
depaudit dir (`~/.config/depaudit/lint/`), and the system-global dir
(`/etc/depaudit/lint/`) — in `[lint] config_order` (default
`project, depaudit, global`). The first tier holding a linter's config
wins and is passed explicitly, so a preferred tier always beats the
linter's own auto-discovery. Recognized files: `ruff.toml` /
`.ruff.toml` / `pyproject.toml` (with `[tool.ruff]`), `.golangci.*`,
`biome.json(c)`, `.editorconfig` (ktlint), `detekt.yml` / `detekt.yaml`,
`eslint.config.js`. Clippy (`[lints]` in `Cargo.toml`), Android lint
(`lint.xml` / Gradle DSL) and `go vet` only honor project-native
configuration.

Gradle lint never downloads a stale distribution: when the wrapper is
older than the latest stable Gradle, lint is skipped with an
update-first message naming the exact
`./gradlew wrapper --gradle-version X` command, and re-running after the
update does the lint.

Findings from several linters on the same file/line with the same message
are merged into one entry naming every source, and a lint finding that
only repeats an already-reported vulnerability (matched by CVE/GHSA-style
ids) is suppressed — both with a count in the notes, never silently.
Slow linters announce themselves on stderr; cold builds get generous
timeouts (15 min for clippy/golangci-lint/detekt, 30 min for Gradle) and
partial build caches still speed up the next run.

```text
[python] Python: 0 outdated, 0 vulnerabilities, 0 tools outdated, 0 blocked, 2 lint findings, 0 unchecked (0 checked)
  lint:
    bad.py:1:8  [F401] `os` imported but unused  (ruff)
    bad.py:2:8  [F401] `sys` imported but unused  (ruff)
```

## Notices: licenses, yanked, end-of-life, and more

Every audited dependency also gets metadata checks, reported as
`notices:` lines (and a `notices` count in the header). The
project-level checks (secrets, crypto, dead code, drift, zombie assets)
run once per project with no network and no cache:

- **licenses**: each dependency's SPDX license is resolved and matched
  against `[licenses] deny`. Family prefixes match (`GPL` denies
  `GPL-3.0-only`), `-only`/`-or-later` suffixes fold together, and a
  dependency whose license cannot be determined is always surfaced.
- **yanked**: versions retracted upstream (PyPI yank, crates.io yank,
  npm deprecation) are flagged with the registry's reason when given.
- **eol**: framework dependencies with endoflife.date coverage
  (Django, React, Angular, Vue, Next.js, Nuxt) warn once their release
  cycle passes end-of-life.
- **bloat**: packages locked at more than one version (Rust `Cargo.lock`,
  npm `package-lock.json` at every nesting depth, pnpm/yarn/bun
  workspace merges), each copy installed — and for compiled languages,
  built and shipped — separately.
- **license-change**: the newest release carries a different license set
  than the used version (upstream relicensed). Both ends must be known;
  unknown on either side stays silent.
- **ghost**: source files importing packages no manifest declares —
  phantom dependencies that work today only via a transitive pull-in
  (the notice says when the import is present transitively). Stdlib,
  builtins, relative imports, and first-party modules are excluded;
  Python import aliases (`yaml` → `pyyaml`, `PIL` → `pillow`) resolve
  through a built-in map, and Kotlin uses a conservative token-overlap
  heuristic since packages do not name their artifact.
- **secrets**: hardcoded tokens (AWS, GitHub, Slack, Google, private
  keys, …) via known-shape rules plus an entropy fallback for assigned
  string literals. Precision over recall: lockfiles, alphabets, and
  prose-looking strings are filtered out.
- **crypto**: deprecated primitives in source — MD5, SHA-1, DES, ECB
  mode, RC4, `createCipher` — and TLS-verification disables.
- **dead-code**: source files nothing imports and media/font assets
  nothing references (zombie assets). Framework entries are honored:
  file routers (`pages/`, `routes/`, expo `app/`), stories, fixtures,
  tests, `scripts/`, shebang CLIs, `package.json` `bin`/script targets,
  manifest entries, tsconfig aliases, Metro platform variants
  (`.ios`/`.android`/`.native`), and references from JSON/HTML
  (`app.json` plugins, `index.html` entry scripts). When in doubt a
  file is called live — a notice is a prompt to look, not proof.

License sources are the registries themselves, never guesses: PyPI
version documents (classifiers + `license` + yank flag), npm version
metadata, the unpacked `Cargo.toml` in the local cargo registry with a
per-version crates.io fallback, Go module cache / proxy zips, and Maven
POM `<licenses>` with parent-POM inheritance. Published releases are
immutable, so resolved licenses cache forever; yanked state re-checks
on the version TTL.

`--sbom` prints a CycloneDX 1.6 document to stdout instead of the
report: one component per dependency (purl, SPDX licenses,
direct/transitive marker) plus the OSV vulnerabilities with severity
ratings and fixed versions.

```text
[rust] Rust: 1 outdated, 0 vulnerabilities, 0 tools outdated, 0 blocked, 1 notices, 0 lint findings, 0 unchecked (1 checked)
  notices:
    regex  1.12.0 is yanked on crates.io  (yanked)
```

## Limitations

- Private registries and authenticated indexes are not queried (Go modules
  matched by `GOPRIVATE`/`GONOSUMDB` are skipped rather than leaked).
- `bun.lockb` is binary with no stable spec and is never parsed (named as
  a gap when it is the only lockfile); everything else resolves versions
  from `package-lock.json`, `pnpm-lock.yaml` (workspace-aware, `catalog:`
  specs resolved), `bun.lock`, or `yarn.lock`, in that order.
- Fresh audits need network access to the public registries and OSV;
  repeat audits degrade to stale cache per dependency when offline
  (see Caching), and the project-level checks (drift, secrets, crypto,
  dead code, ghost) never need the network at all.

## Development

```sh
cargo test
cargo clippy --all-targets
cargo fmt --check
```

## Release

```sh
# 1. Set the version in Cargo.toml ([package] version).
# 2. Commit everything; releases build from a clean tree.
scripts/release.sh
```

The release version is the `Cargo.toml` base version plus the commit
count as a build number (`0.0.1` at 5 commits → `0.0.1.5`). The build
number lives only in the tarball name, the tag, and the package
manager: cargo files are never touched, so the binary reports the
base version.

The script runs the gates above (clippy with warnings denied),
archives a pristine `HEAD` tree, vendors every crates.io dependency
into it (168 crates plus a relocatable `.cargo/config.toml`), and
writes a versioned source tarball plus a sha256 file to `dist/` (e.g.
`depaudit-0.0.1.5.tar.gz`). The tarball layout is the conventional
`depaudit-<version>/` top dir with stable entry order, root ownership,
and `HEAD` commit mtimes. Before succeeding, the script extracts the
tarball and builds it fully offline (`cargo build --frozen` with an
empty `CARGO_HOME` and no network), then checks `--version` — so
whatever it produces is proven self-contained. It then prints the
tag/push commands. Pass `--allow-dirty` for test builds from an
uncommitted tree (the archive still reflects `HEAD`).

Upload the tarball to a GitHub release and point the ebuild's `SRC_URI`
at it. No `CRATES` list is needed: the build is a plain offline cargo
invocation, e.g. `cargo build --release --frozen` followed by
`dobin target/release/depaudit`.

## License

MIT — see [LICENSE](LICENSE).
