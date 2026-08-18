#!/bin/bash
# claudebox-init — post-assemble bridges and policy (C8).
#
# Runs on the component AFTER `distrobox assemble`, and applies everything that
# cannot live in a distrobox.ini hook: assemble double-evaluates hooks, so
# quotes and redirections detonate there. Everything here goes over the
# quote-safe `distrobox enter -- sudo` channel instead.
#
# The agent's own installation comes first, then three bridges:
#   0. the agent itself, from Anthropic's repository, admitted only after its
#      signing key matches a pinned fingerprint;
#   1. the host's rootless podman socket, so in-box podman drives the
#      component's own containers rather than a nested runtime;
#   2. the managed settings, read-only to the in-box user;
#   3. the GitHub App installation token, re-read every shell so the ~hourly
#      refresh is picked up live.
#
# Shared by host and dev-container alike — SRC is the only thing that differs,
# and it is passed in rather than hardcoded.
set -euo pipefail

BOX=claudebox
SRC="${CLAUDEBOX_SHARE:-/usr/share/dev-pair/claudebox}"
TOKEN_PATH="${PAIR_TOKEN_PATH:-/run/dev-pair/gh-token}"

[ -d "$SRC" ] || { echo "claudebox-init: $SRC not found" >&2; exit 1; }

# ── (0) The agent itself ─────────────────────────────────────────────────────
# This used to be a distrobox.ini pre_init hook whose repository definition
# named a REMOTE gpgkey, which `dnf -y` auto-imports — so the fingerprint in
# the manifest was a comment rather than a control. The work moved here, where
# a comparison can be written, and the script is piped in over the same
# stdin channel the managed settings use. A key that does not match the pin
# stops the box build rather than producing a box that looks finished.
distrobox enter "$BOX" -- sudo sh -c 'cat > /tmp/claudebox-agent-repo.sh' \
    < "$SRC/claudebox-agent-repo.sh"
distrobox enter "$BOX" -- sudo sh /tmp/claudebox-agent-repo.sh
distrobox enter "$BOX" -- sudo rm -f /tmp/claudebox-agent-repo.sh

# ── (1) Host podman bridge ───────────────────────────────────────────────────
# The box's /run/user/<uid> IS the host's, bind-mounted by distrobox with
# init=0, so pointing CONTAINER_HOST at it reaches the host's rootless socket.
# shellcheck disable=SC2016  # the inner $ is written literally, for the in-box shell to expand
distrobox enter "$BOX" -- sudo sh -c \
  'printf "export CONTAINER_HOST=unix:///run/user/%s/podman/podman.sock\n" "$(id -u '"$USER"')" > /etc/profile.d/dev-pair-container-host.sh' \
  || distrobox enter "$BOX" -- sudo sh -c \
  "printf 'export CONTAINER_HOST=unix:///run/user/\$(id -u)/podman/podman.sock\n' > /etc/profile.d/dev-pair-container-host.sh"

# ── (2) Managed settings ─────────────────────────────────────────────────────
# $SRC is a path on the COMPONENT. Inside the box, /usr is the toolbox's own
# filesystem, so an in-box `cp $SRC/...` cannot see it. Pipe the file in over
# stdin instead: the redirection is evaluated component-side where $SRC is
# valid, and cat writes it in-box.
distrobox enter "$BOX" -- sudo mkdir -p /etc/claude-code
distrobox enter "$BOX" -- sudo sh -c 'cat > /etc/claude-code/managed-settings.json' < "$SRC/managed-settings.json"
distrobox enter "$BOX" -- sudo chmod 0644 /etc/claude-code/managed-settings.json

# ── (3) GitHub App token bridge ──────────────────────────────────────────────
# The component mints a short-lived installation token to tmpfs; this exports
# it as GH_TOKEN in every in-box shell, so in-box gh and git act as the pair's
# own App identity and never as a personal token. Re-read per shell so the
# refresh is picked up without a box restart. No-ops cleanly when the App is
# not configured, leaving a box with no GitHub authority rather than a broken
# one. The redirection is component-side, matching the settings pipe above.
distrobox enter "$BOX" -- sudo sh -c 'cat > /etc/profile.d/dev-pair-gh-token.sh' <<EOF
# dev-pair: bridge the component-minted GitHub App token as GH_TOKEN (C6/C8)
for _t in /run/host${TOKEN_PATH} ${TOKEN_PATH}; do
  if [ -r "\$_t" ]; then
    GH_TOKEN="\$(cat "\$_t" 2>/dev/null)" && export GH_TOKEN GITHUB_TOKEN="\$GH_TOKEN"
    break
  fi
done
unset _t
EOF
distrobox enter "$BOX" -- sudo chmod 0644 /etc/profile.d/dev-pair-gh-token.sh

echo "claudebox-init: agent installed, podman bridge, managed settings and GitHub App token applied."
