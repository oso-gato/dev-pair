#!/usr/bin/env bash
# 30-tailnet — the private network every non-public service sits behind.
#
# The objective's first security outcome is a minimal public surface: hardened
# SSH is the only public door and everything else is reachable only from the
# tailnet. This unit admits Tailscale at L2 and makes sure the daemon is there
# to enforce that; the join itself needs an auth key, so day zero performs it.
#
# Sourced by converge.sh.

log_unit "tailnet"

# L2: the vendor's own repository, both signature checks on. Tailscale signs
# its metadata, so repo_gpgcheck is 1 rather than 0.
#
# The fingerprint is deliberately not pinned here, and that is a recorded gap
# rather than an oversight: this repository's last verified position on
# Tailscale is the donor's own .repo file (trail 2026-07-11), which pins no
# fingerprint either, and inventing one would be worse than declaring none.
# prov_l2_repo pins whatever key it first fetches to disk and verifies every
# later fetch against it, so tampering after admission fails closed. Pin the
# fingerprint here the first time a session with upstream reach can verify it.
prov_l2_repo tailscale-stable "Tailscale stable" \
    "https://pkgs.tailscale.com/stable/fedora/\$basearch" \
    "https://pkgs.tailscale.com/stable/fedora/repo.gpg" \
    1

prov_l2_install tailscale-stable "the tailnet is the private network boundary (objective, Security 1)" \
    tailscale

fs_enable_unit tailscaled.service

# Report the join state without performing it. A converge run holds no auth key
# — the key is a credential and reaches the host only through day zero — so
# this unit tells the operator where things stand rather than pretending.
if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
    log_ok "joined the tailnet as ${TAILNET_HOSTNAME}"
else
    log_warn "not joined to the tailnet yet — day zero performs the join, or run: sudo tailscale up ${TAILSCALE_ARGS[*]}"
fi
