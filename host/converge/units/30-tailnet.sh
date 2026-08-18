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

# L2, admitted as the vendor's OWN definition pinned by checksum.
#
# PINNED VENDOR ASSET. The pin lives HERE and is bumped here only, after a live
# re-check against upstream (C5):
#   curl -fsSL https://pkgs.tailscale.com/stable/fedora/tailscale.repo | sha256sum
#
# This supersedes the hand-written definition this unit carried first, and it
# closes most of the gap recorded in docs/decisions/000027: a transcribed .repo
# cannot detect a changed upstream definition, while this stops the run on one.
# The value is the estate's own, verified by fedora-dev and carried forward with
# its provenance rather than re-derived from memory (docs/decisions/000031).
#
# It is not a signing-key fingerprint pin, and the disclosure says so. What it
# guarantees is that the definition — its baseurl and its gpgkey URL — is the
# vendor's own and unchanged since the pin. A substituted key served at that URL
# is a narrower residual gap, still bounded by TLS and by gpgcheck on every
# package fetch thereafter.
TAILSCALE_REPO_URL=https://pkgs.tailscale.com/stable/fedora/tailscale.repo
TAILSCALE_REPO_SHA256=87206259fb7032fb4147eabccf4ffdb0b4d850d0519ef4c6991cf8c4d100ac13

prov_l2_vendor_repo tailscale-stable "$TAILSCALE_REPO_URL" "$TAILSCALE_REPO_SHA256"

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
