#!/usr/bin/env bash
# build.sh — a THROWAWAY validation build of the dev-container image.
#
# This never produces a production image. CI builds and publishes those, and
# neither component builds them (00-OBJECTIVE.md, Boundaries); what this makes
# is a validation candidate, which is the only kind of build a component is
# allowed to perform.
#
# B1 in full: the build is a throwaway and the tree it builds from is a
# throwaway with it. A tree is cut fresh from the repository, used, and torn
# down — nothing ever builds from a live tree. Teardown is total and covers the
# signal paths, so an interrupted run leaves no tree, no image and no container
# behind.
#
# Usage:
#   ./build.sh            build a validation candidate and tear it down
#   ./build.sh --keep     leave the image behind for inspection (still no tree)
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

TAG="nox-validation:$(date -u +%Y%m%d-%H%M%S)-$$"
TREE=""

# ── Teardown, registered before anything is created ──────────────────────────
# The trap covers EXIT and the signal paths alike, because a build killed by a
# hangup leaks exactly as much as one that fails.
teardown() {
    local rc=$?
    [ -n "$TREE" ] && [ -d "$TREE" ] && rm -rf "$TREE"
    if [ "$KEEP" = 0 ] && podman image exists "$TAG" 2>/dev/null; then
        podman rmi -f "$TAG" >/dev/null 2>&1 || true
    fi
    return $rc
}
trap teardown EXIT HUP INT QUIT TERM

command -v podman >/dev/null 2>&1 || { echo "build: podman is required" >&2; exit 1; }
command -v git    >/dev/null 2>&1 || { echo "build: git is required" >&2; exit 1; }

# ── The throwaway tree ───────────────────────────────────────────────────────
# Cut from the repository's committed state rather than the working tree, so a
# validation candidate always corresponds to something that exists in git.
TREE=$(mktemp -d -t nox-build-XXXXXXXX)
echo ">> cutting a throwaway tree at $TREE"
git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$TREE" \
    || { echo "build: cannot cut a tree from HEAD" >&2; exit 1; }

# ── The build ────────────────────────────────────────────────────────────────
# Context is the tree root, because the Containerfile copies from both
# dev-container/ and shared/ and a narrower context would not see the latter.
echo ">> building $TAG"
podman build \
    --file "$TREE/dev-container/Containerfile" \
    --tag "$TAG" \
    "$TREE" \
    || { echo "build: image build failed" >&2; exit 1; }

echo ">> built $TAG"

# ── What the container can prove about itself (tier 1) ───────────────────────
# Only what runs here belongs here. Anything needing PID 1 or boot-level
# behaviour is the host's to validate, per the objective's two tiers.
echo ">> tier-1 checks"
podman run --rm --entrypoint /bin/bash "$TAG" -c '
set -e
for c in git gh tmux podman distrobox python3 openssl; do
    command -v "$c" >/dev/null || { echo "missing: $c"; exit 1; }
done
[ -f /usr/share/dev-pair/claudebox/distrobox.ini ] || { echo "missing the box manifest"; exit 1; }
[ -x /usr/bin/pair-gh-app-token ] || { echo "the App-token minter is not executable"; exit 1; }
[ -x /usr/bin/nox-session ] || { echo "the entrypoint is not executable"; exit 1; }
id core >/dev/null || { echo "no session user"; exit 1; }
echo "tier-1: working set present, box manifest present, entrypoint executable"
' || { echo "build: tier-1 checks failed" >&2; exit 1; }

if [ "$KEEP" = 1 ]; then
    echo ">> kept: $TAG (the tree is gone; remove the image with: podman rmi $TAG)"
else
    echo ">> validation candidate torn down — nothing durable was left behind"
fi
