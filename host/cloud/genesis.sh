#!/usr/bin/env bash
# dev-pair — CLOUD GENESIS (FR-PROV-1): turn a stock Fedora cloud image on any provider
# into a converged dev-pair host. Remote, channel-proof, no local act: the operator runs
# one command over the provider's initial SSH access (or pastes it into the provider's
# user-data/console), and everything after is this repository.
#
# What it does, in order:
#   1. Verifies the environment FACTS (P2 — onboarded by verifying, never by assuming).
#   2. Installs git (the one bootstrap dependency a stock image may lack).
#   3. Clones this repository as the control clone at /opt/dev-pair (or fast-forwards an
#      existing one — genesis is re-run-safe).
#   4. Hands over to the core converger. The tailnet join is the one remaining genesis
#      act: supply TS_AUTHKEY=tskey-... for an unattended join, or answer the browser
#      link the converger prints.
#
# Env (all optional): DEVPAIR_USER (core) DEVPAIR_HOSTNAME (box) DEVPAIR_KEYS_USER
# (oso-gato) TS_AUTHKEY TS_ACCEPT_ROUTES TS_EXIT_NODE SELINUX_TARGET.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "genesis.sh must run as root (the provider's initial SSH user usually is)." >&2; exit 1; }

REPO="${DEVPAIR_REPO:-https://github.com/oso-gato/dev-pair}"
CLONE="${DEVPAIR_CLONE:-/opt/dev-pair}"
BRANCH="${DEVPAIR_BRANCH:-main}"

echo "== dev-pair cloud genesis: verifying environment facts (P2) =="
. /etc/os-release
[ "${ID:-}" = fedora ] || { echo "FATAL: cloud genesis targets a stock Fedora image (found ID='${ID:-?}')." >&2; exit 1; }
echo ">> Fedora ${VERSION_ID:-?} / $(uname -m) / kernel $(uname -r) — facts verified against the live machine"

command -v git >/dev/null 2>&1 || dnf -y --setopt=install_weak_deps=False install git

if [ -d "$CLONE/.git" ]; then
    echo ">> control clone exists at $CLONE — fast-forwarding to origin/$BRANCH"
    git -C "$CLONE" fetch --quiet origin "$BRANCH"
    git -C "$CLONE" merge --ff-only "origin/$BRANCH"
else
    echo ">> cloning $REPO -> $CLONE (the control clone; tip of merged $BRANCH is the spec of record)"
    git clone --depth 50 --branch "$BRANCH" "$REPO" "$CLONE"
fi

echo "== facts verified; handing over to the core converger =="
exec bash "$CLONE/host/core/converge.sh"
