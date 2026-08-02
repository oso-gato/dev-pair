#!/usr/bin/env bash
# dev-pair — the ROOTLESS layer of the converge verb, run AS the operating user (handed
# off from converge.sh). Only what genuinely belongs to the user: the authorized-keys
# trust root and the rootless container socket.
set -euo pipefail

# ---- authorized keys: the maintainer's published key set is the single trust root ------
# (FR-SEC-2). ALL keys on github.com/<user>.keys are authorized verbatim — access is
# granted and revoked by managing the account's keys, never by distributing credentials.
# Defensive: a failed or empty fetch never wipes existing keys; only well-formed public
# keys land (ssh-keygen -lf validates each line).
GH_USER="${DEVPAIR_KEYS_USER:-oso-gato}"
SSH_DIR="$HOME/.ssh"
AK="$SSH_DIR/authorized_keys"
NEW="$SSH_DIR/.authorized_keys.new"

install -d -m 700 "$SSH_DIR"
raw="$(mktemp)"; trap 'rm -f "$raw" "$NEW"' EXIT

if ! curl -fsSL --retry 3 "https://github.com/${GH_USER}.keys" -o "$raw" || [ ! -s "$raw" ]; then
    echo "WARN: fetch of github.com/${GH_USER}.keys failed or empty — authorized_keys left unchanged" >&2
else
    : > "$NEW"; chmod 600 "$NEW"
    n=0
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        printf '%s\n' "$key" | ssh-keygen -lf /dev/stdin >/dev/null 2>&1 || continue
        printf '%s\n' "$key" >> "$NEW"
        n=$((n + 1))
    done < "$raw"
    if [ "$n" -lt 1 ]; then
        echo "WARN: no valid keys at github.com/${GH_USER}.keys — authorized_keys left unchanged" >&2
    else
        # rename WITHIN ~/.ssh — keeps the ssh_home_t SELinux label (never mv from /tmp).
        mv -f "$NEW" "$AK"
        command -v restorecon >/dev/null 2>&1 && restorecon -F "$AK" 2>/dev/null || true
        echo "ssh keys: authorized $n key(s) from github.com/${GH_USER}.keys (single trust root)"
    fi
fi

# ---- rootless podman socket ------------------------------------------------------------
# The dev-container and app workloads talk to the user's rootless podman through this
# socket. Linger (enabled by converge.sh) keeps the user manager up across logouts.
systemctl --user enable --now podman.socket 2>/dev/null \
    || echo "WARN: could not enable user podman.socket (user manager not up? converge.sh re-runs this)" >&2

echo ">> rootless layer complete for $(id -un)."
