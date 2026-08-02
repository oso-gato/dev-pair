#!/bin/bash
# dev-pair dev-container — base-image install. Mined from the fleet's proven install.sh,
# pruned to the decided capabilities. Official sources only (P1): Fedora repos (L1) +
# Tailscale's own dnf repo (L2, pinned by sha256 — fail-closed: a changed upstream file
# STOPS the build rather than silently redefining the vendor repo).
set -euo pipefail

DNF="dnf -y --setopt=install_weak_deps=False"

# ---- vendor dnf repo: pinned fetch (the one pinned-fetch contract, P1) ----------------
: "${TAILSCALE_REPO_SHA256:?not set — the Containerfile ARG carries the pin}"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
curl -fsSL https://pkgs.tailscale.com/stable/fedora/tailscale.repo -o "$tmp"
actual="$(sha256sum "$tmp" | cut -d' ' -f1)"
[ "$actual" = "$TAILSCALE_REPO_SHA256" ] || {
    echo "install.sh: tailscale.repo sha256 MISMATCH (got $actual, want $TAILSCALE_REPO_SHA256)" >&2
    echo "  A changed vendor repo definition is exactly what the pin exists to fail on." >&2
    echo "  Remedy: live re-check the file (P2), then bump ARG TAILSCALE_REPO_SHA256." >&2
    exit 1
}
# Structural check too (one home: host/core/lib.sh's verify_tailscale_repo, inlined here
# because the host lib is not in this build context — the pin above is the stronger check).
grep -q '^\[tailscale-stable\]' "$tmp" && grep -q '^gpgcheck=1' "$tmp" \
    && grep -q '^repo_gpgcheck=1' "$tmp" \
    || { echo "install.sh: tailscale.repo failed structural verification" >&2; exit 1; }
install -m0644 "$tmp" /etc/yum.repos.d/tailscale.repo

# ---- base packages (P3 minimal leaf; install_weak_deps=False is load-bearing) ---------
#   Engine + storage:    podman shadow-utils fuse-overlayfs passt nftables
#   Login + persistence: openssh-server mosh tmux tailscale
#   Agent layer:         distrobox inotify-tools
#   The bus:             gh, python3-jsonschema (contract validation)
#   Plumbing:            sudo procps-ng glibc-langpack-en openssl git-core
#   Break-glass:         nano
$DNF install \
    podman shadow-utils fuse-overlayfs passt nftables \
    openssh-server mosh tmux tailscale \
    distrobox inotify-tools \
    gh python3-jsonschema \
    sudo procps-ng glibc-langpack-en openssl git-core nano

# ---- defensive: restore file caps on newuidmap/newgidmap -------------------------------
# shadow-utils' scriptlet sets these, but security.capability xattrs don't always survive
# layer commits in every podman storage configuration — without them, nested rootless
# podman fails "newuidmap: write to uid_map failed". Set in OUR layer; entrypoint
# re-verifies at runtime as a second defense.
setcap cap_setuid+ep /usr/bin/newuidmap
setcap cap_setgid+ep /usr/bin/newgidmap

# ---- user core (password NEVER in a layer — key-only door) -----------------------------
useradd -m -u 1000 -s /bin/bash core
usermod -aG wheel core
# Inner subordinate IDs must fit inside the outer rootless 65536-ID map.
echo "core:10000:55000" > /etc/subuid
echo "core:10000:55000" > /etc/subgid

# ---- nested rootless podman (no systemd inside) ----------------------------------------
# journald log-driver without the journald events backend breaks `podman logs --follow`
# (the first `distrobox enter` does exactly that); k8s-file logs + file events make
# first-enter clean. fuse-overlayfs for nested overlay storage.
install -d -m 0755 /etc/containers
cat > /etc/containers/containers.conf <<'EOF'
[containers]
log_driver = "k8s-file"

[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
EOF
cat > /etc/containers/storage.conf <<'EOF'
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev,fsync=0"
EOF
cat > /etc/containers/registries.conf <<'EOF'
unqualified-search-registries = ["registry.fedoraproject.org", "docker.io"]
EOF
# No systemd/PAM session manager: provide XDG_RUNTIME_DIR for rootless podman.
cat > /etc/profile.d/xdg-runtime.sh <<'EOF'
if [ "$(id -u)" = "1000" ]; then
    export XDG_RUNTIME_DIR=/run/user/1000
fi
EOF

# ---- surface the tailnet join on remote logins until joined ----------------------------
# A fresh state volume has no persisted identity; the one-time browser join has to be
# visible somewhere. Prints the live login URL on interactive logins until Running;
# silent thereafter. Runs BEFORE the tmux attach below (sorts first by filename).
cat > /etc/profile.d/zz-tailscale-login.sh <<'EOF'
case $- in *i*) ;; *) return ;; esac
[ -t 0 ] || return
command -v tailscale >/dev/null 2>&1 || return
_ts_state=$(tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState": *"\([^"]*\)".*/\1/p')
if [ -n "$_ts_state" ] && [ "$_ts_state" != "Running" ]; then
    _ts_url=$(tailscale status --json 2>/dev/null | sed -n 's/.*"AuthURL": *"\([^"]*\)".*/\1/p')
    printf '\n  Tailscale is not connected (state: %s).\n' "$_ts_state"
    [ -n "$_ts_url" ] && printf '  Join the tailnet (one-time): %s\n\n' "$_ts_url"
fi
unset _ts_state _ts_url 2>/dev/null || true
EOF

# ---- session persistence (FR-SEC-3 — the proven tmux session-group mechanism) -----------
# Each login gets its OWN session in the shared "main" GROUP: windows (the work) shared,
# geometry independent per client (the fleet-measured multi-client resize race). The
# per-connection session self-destroys on disconnect; work persists in the detached base.
cat > /etc/profile.d/zz-tmux-attach.sh <<'EOF'
case $- in *i*) ;; *) return ;; esac
if [ -z "${TMUX:-}" ] && command -v tmux >/dev/null && { [ -n "${SSH_TTY:-}" ] || [ -t 0 ]; }; then
    tmux has-session -t main 2>/dev/null || tmux new-session -d -s main 2>/dev/null || true
    exec tmux new-session -t main -s "c$$" \; set-option destroy-unattached on
fi
EOF
# Multi-device geometry policy (verified against tmux source + a live multi-client
# harness by the fleet): window-size=latest follows the last-typing device; idle larger
# devices blank-letterbox (fill-character ' '), never the `·`-garble; aggressive-resize
# gives devices on DIFFERENT tabs their own size; full repaint on attach/resize.
# prefix+g cycles latest -> smallest -> largest for co-viewing.
cat > /etc/tmux.conf <<'EOF'
set -g default-terminal "tmux-256color"
set -g window-size latest
setw -g aggressive-resize on
setw -g fill-character ' '
set-hook -g client-attached 'refresh-client'
set-hook -g client-resized  'refresh-client'
set -g @coview latest

bind-key g {
  if-shell -F '#{==:#{@coview},latest}' {
    set -g window-size smallest
    set -g @coview smallest
    display-message 'co-view: SMALLEST - every device sees the whole session'
  } {
    if-shell -F '#{==:#{@coview},smallest}' {
      set -g window-size largest
      set -g @coview largest
      display-message 'co-view: LARGEST - biggest screen wins; smaller devices crop'
    } {
      set -g window-size latest
      set -g @coview latest
      display-message 'co-view: LATEST - the device you last typed on wins'
    }
  }
  refresh-client -S
}
EOF

# ---- sshd: the dev-container's own public door, key-only (FR-SEC-1/2) -------------------
# Host keys live on the ROOT-OWNED state volume (NOT under core's home — core owns that
# tree and could swap keys); generated by the entrypoint at runtime. Public ssh is
# published by the Quadlet (host :4444 -> container :22); mosh rides the same door.
# authorized_keys sync from the maintainer's published GitHub keys at every start,
# cached on the home volume so a brief GitHub outage never locks the operator out.
install -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-devpair.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
PermitRootLogin no
AllowUsers core
HostKey /var/lib/devpair/hostkeys/ssh_host_ed25519_key
EOF
rm -f /etc/ssh/ssh_host_*_key*   # never ship host keys in a published image

# No fail2ban / rsyslog (fleet-proven): a key-only door has no password to brute-force,
# and with no journald in this image the jail saw zero events — a control with no purpose.

dnf clean all
rm -rf /var/cache/dnf
# /var/cache/libdnf5 may be a build-time bind-mount (a persistent package cache): removing
# a mountpoint fails EBUSY and wiping it would destroy the cache — skip it then.
grep -q ' /var/cache/libdnf5 ' /proc/self/mounts || rm -rf /var/cache/libdnf5
