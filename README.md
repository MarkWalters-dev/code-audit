# freshdeps

One command to answer "are my project's dependencies the latest versions?" —
across Python, JavaScript/TypeScript, Rust, Go and Android projects.

`freshdeps` detects which kind(s) of project live in a directory and runs each
ecosystem's own outdated-checker for you, installing the checker first when it
is missing and you allow it.

## Install

Requires the Rust toolchain (https://rustup.rs/):

```sh
cargo install --path .
```

Or build and run directly:

```sh
cargo build
./target/debug/freshdeps /path/to/project
```

## Usage

```sh
freshdeps [PATH] [OPTIONS]

Options:
      --only <a,b>       Only check these ecosystems: python, node, rust, go, android
      --exclude <c>      Skip these ecosystems
  -y, --yes              Install missing checker tools without asking
      --no-install       Never install missing checkers; skip those ecosystems
      --deep             Include transitive/indirect dependencies where supported
      --json             Machine-readable report
      --fail-on-outdated Exit 1 when any outdated dependency is found
  -v, --verbose          Print every external command before running it
```

Examples:

```sh
freshdeps                  # check the current directory
freshdeps ~/projects/app   # check another project
freshdeps --only python,rust --fail-on-outdated   # CI-friendly subset
freshdeps --json > report.json
```

Exit codes: `0` check completed, `1` outdated deps found (only with
`--fail-on-outdated`), `2` usage error or nothing detected.

## Which tools it calls

| Ecosystem | Detected by | Checker | Installed with (when missing) |
|---|---|---|---|
| Python | `requirements*.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, `*.lock`, `.venv` | `uv pip list --outdated`, else `pip list --outdated`, else `pip-review` | `uv tool install pip-review` |
| JavaScript | `package.json` | `ncu` (npm-check-updates) | `pnpm add -g npm-check-updates` (else `npm install -g`, else one-shot `pnpm dlx`/`npx`) |
| Rust | `Cargo.toml` | `cargo-outdated` | `cargo install cargo-outdated` |
| Go | `go.mod` | `go list -u -m` (built into the toolchain) | not auto-installed; install from https://go.dev/dl/ |
| Android | `*.gradle(.kts)`, `gradle/libs.versions.toml` | `gradle dependencyUpdates` when the versions plugin is applied, else Maven metadata lookup | n/a (uses the project's Gradle wrapper / network) |

Install behavior: with `-y`/`--yes` missing tools are installed
non-interactively; otherwise you are asked on an interactive terminal; with
`--no-install` (or a "no") the ecosystem is reported as `skipped` with the
manual install command. Fresh installs are also found when their bin directory
is not on `PATH` (`~/.local/bin`, pnpm's global bin, `~/.cargo/bin`).

## Notes per ecosystem

- **Python** checks the project's environment: `<project>/.venv` first, then
  `$VIRTUAL_ENV`, then the ambient interpreter. Without a project virtualenv
  the report covers the ambient interpreter and says so. Create one with
  `uv venv && uv pip install -r requirements.txt` for project-accurate results.
- **JavaScript** reads version specs from `package.json` and resolves the
  latest from the npm registry; no `node_modules` install needed.
- **Rust** checks direct dependencies by default (`--deep` walks the whole
  tree) and passes `--workspace` for workspace roots automatically.
- **Go** reports direct modules by default (`--deep` adds indirect ones).
- **Android** never modifies your build: the `gradle-versions-plugin` is only
  *used* when already applied. Without it, pinned versions from
  `libs.versions.toml`, `build.gradle(.kts)` dependency strings
  (`group:name:version`), and known plugin ids (AGP, Kotlin, …) are compared
  against Maven Central and Google Maven. Pre-release versions are ignored
  unless the declared version is itself a pre-release.

## Sample output

```text
freshdeps: /tmp/mono

[python] Python: 1 outdated (tool: uv pip list)
  six  1.15.0 -> 1.17.0

[node] JavaScript: 1 outdated (tool: npm-check-updates)
  is-odd  2.0.0 -> 3.0.1

Summary: 2 outdated across 2 ecosystem(s) (2 ok, 0 skipped, 0 errors)
```

## Development

```sh
cargo test
cargo clippy --all-targets
cargo fmt --check
```

## License

MIT — see [LICENSE](LICENSE).
