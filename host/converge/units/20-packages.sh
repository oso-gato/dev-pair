#!/usr/bin/env bash
# 20-packages — the host's package set, admitted through the ladder.
#
# Everything here is L1: Fedora's own repositories, which is the strongest
# provenance any of these artifacts admits, so settling lower would be the
# defect C4 names. `install_weak_deps=False` rides on every installation
# through prov_l1_install, per the bylaw's minimalism flag.
#
# Each group carries the justification C3 requires — nothing enters a built
# tree without one — and the most specific leaf package beats any convenience
# metapackage, which is why there is no @group anywhere below.
#
# Sourced by converge.sh.

log_unit "packages"

prov_l1_install "container runtime — every application runs in a container (C7)" \
    podman

prov_l1_install "the disposable agent layer's runtime (C8)" \
    distrobox flatpak-session-helper

prov_l1_install "the ticket bus is the durable hand-off, so both components need a git and a GitHub client" \
    git gh

prov_l1_install "sessions survive disconnection — tmux holds the session, mosh survives the roam" \
    tmux mosh

prov_l1_install "the App-token minter parses JSON and the converger parses declarations" \
    python3

prov_l1_install "SELinux labels have to be correctable in place, not only reported" \
    policycoreutils-python-utils

prov_l1_install "moving work between the host and the dev-container's volume" \
    rsync

# Deliberately absent, and recorded so the absence reads as a decision rather
# than an oversight (C3: dropping a capability is a recorded trade-off):
#   cockpit and its subpackages — a web console is not on this ticket's
#     acceptance, and a dashboard nobody has asked for is footprint without a
#     capability decision behind it.
#   firewalld — the access boundary here is the network layer, not a host
#     packet filter: the only public door is SSH and everything else is
#     tailnet-only, so firewalld would guard a boundary that is already closed.
#   libvirt, qemu and the GPU stack — the VPS track has neither virtualization
#     nor a GPU (registry: erebus), and validation needing them routes to the
#     bare-metal track by C9 rather than being simulated here.
log_ok "cockpit, firewalld and the virtualization stack deliberately absent on this track"
