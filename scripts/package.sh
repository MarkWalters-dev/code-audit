#!/usr/bin/env bash
# Build a Gentoo-ready vendored SOURCE tarball for depaudit.
#
# Usage:
#   scripts/package.sh [--allow-dirty] [--binary]
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
# With --binary, it additionally builds an optimized release binary
# from that same staged tree and writes
#   dist/depaudit-<version>-<platform>.tar.gz (+ .sha256)
# e.g. depaudit-0.0.1.6-linux-x86_64.tar.gz. Same GitHub release,
# second asset, for users without a Rust toolchain.
#
# The release version is the Cargo.toml base version plus the commit
# count as a build number (e.g. base 0.0.1 at 5 commits -> 0.0.1.5).
# The build number lives only in the tarball name, the tag, and the
# package manager: cargo files are never touched, so the binary
# reports the base version. Tagging and pushing are left to you; the
# script prints the exact commands at the end.
set -euo pipefail

ALLOW_DIRTY=0
WITH_BINARY=0
for arg in "$@"; do
    case "$arg" in
        --allow-dirty) ALLOW_DIRTY=1 ;;
        --binary) WITH_BINARY=1 ;;
        *) echo "package: unknown flag $arg" >&2; exit 1 ;;
    esac
done

cd "$(dirname "$0")/.."

BASE_VERSION="$(awk '/^\[package\]/{p=1} p && /^version *= *"/{gsub(/"/, "", $3); print $3; exit}' Cargo.toml)"
if [[ -z "$BASE_VERSION" ]]; then
    echo "package: cannot parse version from Cargo.toml" >&2
    exit 1
fi
BUILD="$(git rev-list --count HEAD)"
VERSION="$BASE_VERSION.$BUILD"

# Canonical triple -> short platform name for asset filenames.
# `unknown` is just the conventional vendor slot for Linux triples;
# the short form drops it. Unmapped triples pass through unchanged.
short_target() {
    case "$1" in
        x86_64-unknown-linux-gnu) echo linux-x86_64 ;;
        aarch64-unknown-linux-gnu) echo linux-aarch64 ;;
        x86_64-apple-darwin) echo macos-x86_64 ;;
        aarch64-apple-darwin) echo macos-aarch64 ;;
        x86_64-pc-windows-msvc) echo windows-x86_64 ;;
        *) echo "$1" ;;
    esac
}

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

# Optimized binary from the same staged tree, so it always matches
# the tarball sources exactly (the staged cargo config forces
# vendored deps; --frozen forbids lockfile drift).
BINTARBALL=""
if [[ "$WITH_BINARY" -eq 1 ]]; then
    PLATFORM="$(short_target "$(rustc -vV | awk '/^host:/{print $2}')")"
    echo "package: building release binary ($PLATFORM)..."
    (
        cd "$STAGE/depaudit-$VERSION"
        cargo build --release --frozen
    )
    BINNAME="depaudit-$VERSION-$PLATFORM"
    mkdir -p "$STAGE/$BINNAME"
    cp "$STAGE/depaudit-$VERSION/target/release/depaudit" \
        "$STAGE/depaudit-$VERSION/README.md" \
        "$STAGE/depaudit-$VERSION/LICENSE" \
        "$STAGE/$BINNAME/"
    # The release build must not leak into the source tarball.
    rm -rf "$STAGE/depaudit-$VERSION/target"
fi

# Stable tarball: sorted entries, root ownership, HEAD commit mtime.
EPOCH="$(git log -1 --format=%ct HEAD)"
mkdir -p dist
TARBALL="dist/depaudit-$VERSION.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" \
    -czf "$TARBALL" -C "$STAGE" "depaudit-$VERSION"
sha256sum "$TARBALL" | awk '{print $1}' > "$TARBALL.sha256"

if [[ "$WITH_BINARY" -eq 1 ]]; then
    BINTARBALL="dist/$BINNAME.tar.gz"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" \
        -czf "$BINTARBALL" -C "$STAGE" "$BINNAME"
    sha256sum "$BINTARBALL" | awk '{print $1}' > "$BINTARBALL.sha256"
    GOT_BIN="$("$STAGE/$BINNAME/depaudit" --version)"
    if [[ "$GOT_BIN" != "depaudit $BASE_VERSION" ]]; then
        echo "package: binary verify failed: got '$GOT_BIN', want 'depaudit $BASE_VERSION'" >&2
        exit 1
    fi
fi

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
if [[ -n "$BINTARBALL" ]]; then
    echo "package: ok: $BINTARBALL ($(du -h "$BINTARBALL" | cut -f1))"
    echo "package: sha256: $(cat "$BINTARBALL.sha256")"
fi
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
    echo "package: note: tag v$VERSION already exists; bump Cargo.toml for a new release" >&2
else
    echo "package: next:"
    echo "  git tag v$VERSION"
    echo "  git push github v$VERSION   # and/or: git push origin v$VERSION"
fi
