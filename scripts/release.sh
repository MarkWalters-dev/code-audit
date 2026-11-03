#!/usr/bin/env bash
# Build a versioned, checksummed release tarball for depaudit.
#
# Usage:
#   scripts/release.sh [--allow-dirty]
#
# Runs the full gate suite (fmt, clippy with warnings denied, tests),
# builds with --locked --release, and writes
#   dist/depaudit-<version>-<target>.tar.gz (+ .sha256)
# The tarball is extracted to a temp dir and its binary smoke-tested
# (`--version` must match Cargo.toml) before the script succeeds.
#
# Set the version in Cargo.toml first. Tagging and pushing are left to
# you; the script prints the exact commands at the end.
set -euo pipefail

ALLOW_DIRTY=0
if [[ "${1:-}" == "--allow-dirty" ]]; then
    ALLOW_DIRTY=1
fi

cd "$(dirname "$0")/.."

VERSION="$(awk '/^\[package\]/{p=1} p && /^version *= *"/{gsub(/"/, "", $3); print $3; exit}' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
    echo "release: cannot parse version from Cargo.toml" >&2
    exit 1
fi
TARGET="$(rustc -vV | awk '/^host:/{print $2}')"
if [[ -z "$TARGET" ]]; then
    echo "release: cannot determine target triple" >&2
    exit 1
fi

if [[ "$ALLOW_DIRTY" -eq 0 ]] && { ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; }; then
    echo "release: working tree is dirty; commit first or pass --allow-dirty" >&2
    exit 1
fi

echo "release: depaudit $VERSION for $TARGET"
echo "release: gates (fmt, clippy, tests)..."
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --quiet

echo "release: building..."
cargo build --locked --release --quiet

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/depaudit-$VERSION"
cp target/release/depaudit LICENSE README.md "$STAGE/depaudit-$VERSION/"

mkdir -p dist
TARBALL="dist/depaudit-$VERSION-$TARGET.tar.gz"
tar -czf "$TARBALL" -C "$STAGE" "depaudit-$VERSION"
sha256sum "$TARBALL" | awk '{print $1}' > "$TARBALL.sha256"

echo "release: smoke-testing tarball..."
SMOKE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$SMOKE"' EXIT
tar -xzf "$TARBALL" -C "$SMOKE"
GOT="$("$SMOKE/depaudit-$VERSION/depaudit" --version)"
if [[ "$GOT" != "depaudit $VERSION" ]]; then
    echo "release: smoke test failed: got '$GOT', want 'depaudit $VERSION'" >&2
    exit 1
fi

echo "release: ok: $TARBALL"
echo "release: sha256: $(cat "$TARBALL.sha256")"
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
    echo "release: note: tag v$VERSION already exists; bump Cargo.toml for a new release" >&2
else
    echo "release: next:"
    echo "  git tag v$VERSION"
    echo "  git push github v$VERSION   # and/or: git push origin v$VERSION"
fi
