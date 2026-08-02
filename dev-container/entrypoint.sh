#!/bin/bash
# dev-pair dev-container — PID 1 (root). Bring-up order, then a pgrep watchdog:
#   home volume -> runtime dir -> uid-map caps -> ssh host keys -> authorized_keys ->
#   sshd -> tailscaled (+ join) -> standing GitHub credential -> rootless podman socket.
# The agent-layer machinery (box assemble, daily tick, resume) is build-order step 4;
# the loop services (merge authority, watchers) are steps 5–6. Neither is stubbed here —
# an unproven actuator never ships (P3).
set -eu

# Graceful shutdown: propagate SIGTERM to the process group so sshd closes cleanly and
# tailscaled deregisters, rather than getting SIGKILLed after podman-stop's timeout.
trap 'kill -TERM 0 2>/dev/null; exit 0' TERM INT

# ---- home volume may be empty on first run ----------------------------------------------
if [ ! -e /home/core/.bashrc ]; then
    cp -rT /etc/skel /home/core
fi
chown -R core:core /home/core

# ---- rootless podman needs a runtime dir (no systemd/PAM session manager) ---------------
install -d -m 0700 -o core -g core /run/user/1000

# ---- defensive: restore newuidmap/newgidmap caps if the overlay stripped them -----------
for bin in /usr/bin/newuidmap /usr/bin/newgidmap; do
    [ -x "$bin" ] || continue
    if ! getcap "$bin" | grep -q "cap_set"; then
        case "$bin" in
            */newuidmap) setcap cap_setuid+ep "$bin" ;;
            */newgidmap) setcap cap_setgid+ep "$bin" ;;
        esac
        echo "[caps] restored on $bin"
    fi
done

# ---- persistent ssh host keys on the root-owned state volume ----------------------------
install -d -m 0700 /var/lib/devpair/hostkeys
if [ ! -f /var/lib/devpair/hostkeys/ssh_host_ed25519_key ]; then
    ssh-keygen -t ed25519 -N "" -f /var/lib/devpair/hostkeys/ssh_host_ed25519_key
fi
mkdir -p /run/sshd

# ---- authorized_keys: the maintainer's published key set is the single trust root -------
# (FR-SEC-2). Fetch ALL keys on the GitHub account each boot, validate each line, cache
# on the home volume. GitHub briefly unreachable + cache exists -> keep the cache;
# unreachable + no cache -> public ssh stays closed (Tailscale SSH remains the path in).
KEYS_USER="${DEVPAIR_KEYS_USER:-oso-gato}"
runuser -u core -- env KEYS_USER="$KEYS_USER" bash -c '
    set -u
    mkdir -p ~/.ssh; chmod 0700 ~/.ssh
    raw=$(mktemp); new=$(mktemp)
    if curl -fsSL --max-time 10 "https://github.com/${KEYS_USER}.keys" -o "$raw" && [ -s "$raw" ]; then
        n=0
        while IFS= read -r key; do
            [ -n "$key" ] || continue
            printf "%s\n" "$key" | ssh-keygen -lf /dev/stdin >/dev/null 2>&1 || continue
            printf "%s\n" "$key" >> "$new"; n=$((n + 1))
        done < "$raw"
        if [ "$n" -ge 1 ]; then
            mv "$new" ~/.ssh/authorized_keys; chmod 0600 ~/.ssh/authorized_keys
            echo "[ssh-keys] authorized $n key(s) from github.com/${KEYS_USER}.keys (single trust root)"
        else
            rm -f "$new"; echo "[ssh-keys] WARNING: no valid keys at source; keeping any cached file"
        fi
    else
        rm -f "$new"
        [ -s ~/.ssh/authorized_keys ] \
            && echo "[ssh-keys] GitHub unreachable; keeping cached authorized_keys" \
            || echo "[ssh-keys] WARNING: GitHub unreachable AND no cache — public ssh closed until next sync"
    fi
    rm -f "$raw"
'

# ---- sshd (container :22; the Quadlet publishes host :4444; mosh rides the same door) ---
/usr/sbin/sshd

# ---- tailscaled + join -------------------------------------------------------------------
/usr/sbin/tailscaled --state=/var/lib/devpair/tailscaled.state \
    --socket=/var/run/tailscale/tailscaled.sock &
for _ in $(seq 1 30); do
    tailscale status >/dev/null 2>&1 && break
    [ -S /var/run/tailscale/tailscaled.sock ] && break
    sleep 1
done
# The unattended join key arrives as a MOUNTED SECRET FILE (/run/secrets/ts-authkey) —
# never an env var: an env var is re-materialised onto the argv of every `distrobox
# enter` / `podman exec` (world-readable via /proc/<pid>/cmdline). The key reaches
# tailscale via its --auth-key=file: prefix, so it never lands on tailscale's argv
# either. Node name = the container hostname; uname -n, NOT $(hostname) — the image
# ships no `hostname` binary (fleet-measured empty-substitution bug).
_ts_keyfile=/run/secrets/ts-authkey
if [ -r "$_ts_keyfile" ]; then
    until tailscale up --ssh --auth-key="file:$_ts_keyfile" --hostname="$(uname -n)"; do
        echo "[tailscale] up failed, retrying in 5s"; sleep 5
    done
    echo "==== TAILNET JOINED ===="
else
    (
        until tailscale up --ssh --hostname="$(uname -n)" 2>&1 | sed 's/^/[tailscale] /'; do
            sleep 5
        done
        echo "==== TAILNET JOINED ===="
    ) &
    echo "=================================================================="
    echo " ACTION REQUIRED: open the login.tailscale.com URL in the logs"
    echo " (podman logs -f dev-container). One-time per state volume."
    echo "=================================================================="
fi

# ---- standing GitHub credential (the pair's own App identity — FR-WORK-6) ---------------
# Mints <=1h installation tokens from the App key (mounted secret, runtime only — never a
# layer), wired to core's git store helper + gh hosts.yml; refreshed every 40 min. No
# credential -> boots unauthenticated (fail-safe; a persisted gh login on the home volume
# is used as-is). GH_TOKEN static fallback for development only.
if [ -n "${GH_APP_ID:-}" ] && { [ -n "${GH_APP_PRIVATE_KEY:-}" ] || [ -r "${GH_APP_PRIVATE_KEY_FILE:-/run/secrets/gh_app_key}" ]; }; then
    if runuser -u core -- env HOME=/home/core \
            GH_APP_ID="${GH_APP_ID}" \
            GH_APP_INSTALLATION_ID="${GH_APP_INSTALLATION_ID:-}" \
            GH_APP_PRIVATE_KEY="${GH_APP_PRIVATE_KEY:-}" \
            GH_APP_PRIVATE_KEY_FILE="${GH_APP_PRIVATE_KEY_FILE:-/run/secrets/gh_app_key}" \
            bash /usr/local/bin/gh-app-auth.sh install; then
        echo "[gh-auth] standing App credential provisioned (pair identity)"
        runuser -u core -- env HOME=/home/core \
            GH_APP_ID="${GH_APP_ID}" \
            GH_APP_INSTALLATION_ID="${GH_APP_INSTALLATION_ID:-}" \
            GH_APP_PRIVATE_KEY="${GH_APP_PRIVATE_KEY:-}" \
            GH_APP_PRIVATE_KEY_FILE="${GH_APP_PRIVATE_KEY_FILE:-/run/secrets/gh_app_key}" \
            bash -c 'while sleep 2400; do bash /usr/local/bin/gh-app-auth.sh install >/dev/null 2>&1 || true; done' &
    else
        echo "[gh-auth] App credential provisioning FAILED — continuing unauthenticated" >&2
    fi
elif [ -n "${GH_TOKEN:-}" ]; then
    runuser -u core -- env HOME=/home/core GH_TOKEN="${GH_TOKEN}" bash -c '
        mkdir -p ~/.config/gh
        [ -f ~/.config/gh/config.yml ] || printf "version: 1\ngit_protocol: https\n" > ~/.config/gh/config.yml
        printf "github.com:\n    users:\n        x-access-token:\n            oauth_token: %s\n    git_protocol: https\n    oauth_token: %s\n    user: x-access-token\n" "$GH_TOKEN" "$GH_TOKEN" > ~/.config/gh/hosts.yml
        chmod 600 ~/.config/gh/hosts.yml
        git config --global credential.helper store
        printf "https://x-access-token:%s@github.com\n" "$GH_TOKEN" > ~/.git-credentials
        chmod 600 ~/.git-credentials' \
        && echo "[gh-auth] provisioned from static GH_TOKEN (development fallback)" \
        || echo "[gh-auth] GH_TOKEN provisioning failed — continuing unauthenticated" >&2
else
    echo "[gh-auth] no standing credential supplied — running unauthenticated (fail-safe)"
fi

# ---- supervised: rootless podman API socket (the agent layer's engine target) -----------
# The socket's parent dir must exist first: `podman system service` does NOT mkdir it.
install -d -m 0700 -o core -g core /run/user/1000/podman
runuser -u core -- podman system service --time=0 \
    unix:///run/user/1000/podman/podman.sock &
podman_sock_pid=$!

echo "dev-container up: ssh :22 (tailnet) + published public ssh/mosh (key-only), $(podman --version)"

# ---- watchdog: exit on a core-service death; the outer --restart heals (P10) -------------
while sleep 30; do
    pgrep -x tailscaled        >/dev/null 2>&1 || { echo "tailscaled died";    exit 1; }
    pgrep -x sshd              >/dev/null 2>&1 || { echo "sshd died";          exit 1; }
    kill -0 "$podman_sock_pid" 2>/dev/null     || { echo "podman socket died"; exit 1; }
done
