#!/usr/bin/env bash
# Build a Gentoo-ready vendored SOURCE tarball for depaudit.
#
# Usage:
#   scripts/package.sh [--allow-dirty]
#
# Runs the gates (fmt, clippy with warnings denied, tests), archives a
# pristine HEAD tree, vendors every crates.io dependency into it, and
# writes
#   dist/depaudit-<version>.tar.gz (+ .sha256)
# Upload the tarball to a GitHub release and point the ebuild's SRC_URI
# at it. The tree builds fully offline (`cargo build --release
# --frozen` with an empty CARGO_HOME) with no CRATES list needed in the
# ebuild — the script proves it by doing exactly that from the
# extracted tarball before succeeding.
#
# The release version is the Cargo.toml base version plus the commit
# count as a build number (e.g. base 0.0.1 at 5 commits -> 0.0.1.5).
# The build number lives only in the tarball name, the tag, and the
# package manager: cargo files are never touched, so the binary
# reports the base version. Tagging and pushing are left to you; the
# script prints the exact commands at the end.
set -euo pipefail

ALLOW_DIRTY=0
if [[ "${1:-}" == "--allow-dirty" ]]; then
    ALLOW_DIRTY=1
fi

cd "$(dirname "$0")/.."

BASE_VERSION="$(awk '/^\[package\]/{p=1} p && /^version *= *"/{gsub(/"/, "", $3); print $3; exit}' Cargo.toml)"
if [[ -z "$BASE_VERSION" ]]; then
    echo "package: cannot parse version from Cargo.toml" >&2
    exit 1
fi
BUILD="$(git rev-list --count HEAD)"
VERSION="$BASE_VERSION.$BUILD"

if [[ "$ALLOW_DIRTY" -eq 0 ]] && { ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; }; then
    echo "package: working tree is dirty; commit first or pass --allow-dirty" >&2
    exit 1
fi
if [[ "$ALLOW_DIRTY" -eq 1 ]]; then
    echo "package: warning: archiving HEAD; uncommitted changes are excluded" >&2
fi

echo "package: depaudit $VERSION source tarball (base $BASE_VERSION, build $BUILD)"
echo "package: gates (fmt, clippy, tests)..."
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --quiet

echo "package: archiving HEAD..."
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/depaudit-$VERSION"
git archive HEAD | tar -x -C "$STAGE/depaudit-$VERSION"


echo "package: vendoring dependencies..."
mkdir -p "$STAGE/depaudit-$VERSION/.cargo"
# Run from inside the staged tree with a relative vendor dir so the
# recorded `directory = "vendor"` stays valid after unpacking anywhere.
(
    cd "$STAGE/depaudit-$VERSION"
    cargo vendor vendor > .cargo/config.toml
)
if ! grep -q '^directory = "vendor"$' "$STAGE/depaudit-$VERSION/.cargo/config.toml"; then
    echo "package: vendor config is not relocatable:" >&2
    cat "$STAGE/depaudit-$VERSION/.cargo/config.toml" >&2
    exit 1
fi
NCRATES="$(find "$STAGE/depaudit-$VERSION/vendor" -mindepth 1 -maxdepth 1 | wc -l)"
echo "package: vendored $NCRATES crates"

# Stable tarball: sorted entries, root ownership, HEAD commit mtime.
EPOCH="$(git log -1 --format=%ct HEAD)"
mkdir -p dist
TARBALL="dist/depaudit-$VERSION.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" \
    -czf "$TARBALL" -C "$STAGE" "depaudit-$VERSION"
sha256sum "$TARBALL" | awk '{print $1}' > "$TARBALL.sha256"

echo "package: verifying offline build from tarball..."
VERIFY="$(mktemp -d)"
EMPTY_CARGO_HOME="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$VERIFY" "$EMPTY_CARGO_HOME"' EXIT
tar -xzf "$TARBALL" -C "$VERIFY"
# Drop the stage first: the verify build must prove the tarball is
# self-contained, not accidentally reuse staged files.
rm -rf "$STAGE"
(
    cd "$VERIFY/depaudit-$VERSION"
    CARGO_HOME="$EMPTY_CARGO_HOME" CARGO_NET_OFFLINE=true cargo build --frozen --quiet
)
GOT="$("$VERIFY/depaudit-$VERSION/target/debug/depaudit" --version)"
if [[ "$GOT" != "depaudit $BASE_VERSION" ]]; then
    echo "package: verify failed: got '$GOT', want 'depaudit $BASE_VERSION'" >&2
    exit 1
fi

echo "package: ok: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "package: sha256: $(cat "$TARBALL.sha256")"
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
    echo "package: note: tag v$VERSION already exists; bump Cargo.toml for a new release" >&2
else
    echo "package: next:"
    echo "  git tag v$VERSION"
    echo "  git push github v$VERSION   # and/or: git push origin v$VERSION"
fi
