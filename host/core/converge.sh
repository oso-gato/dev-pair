#!/usr/bin/env bash
# dev-pair — the CONVERGE verb (FR-PROV-1, FR-PROV-4; P4).
#
# The host's idempotent applier: every host mutation is declared here and flows the
# merge-and-deploy path. Run as root, re-run-safe from any historical version; ad-hoc
# drift vanishes on the next apply. Fail-loud, never silently partial.
#
# Privilege layers (proven in the fleet): this script is the SYSTEM layer — only what
# genuinely needs root. The rootless layer is converge-user.sh, run AS the operating
# user via the hand-off at the end.
#
# Rebuilt from the fleet's setup-host.sh under P1–P11: the tailscale.repo fetch is
# structurally verified (gpgcheck=1 AND repo_gpgcheck=1, vendor key on the vendor host —
# live fact-checked 2026-08-03), the footprint is pruned to the decided capabilities,
# and every gate left standing passes the warrant test.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "converge.sh is the SYSTEM layer and must run as root." >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
PHASE() { printf '\n==== %s ====\n' "$*"; }

U="${DEVPAIR_USER:-core}"
H="${DEVPAIR_HOSTNAME:-box}"
KEYS_USER="${DEVPAIR_KEYS_USER:-oso-gato}"
dp_valid_user "$U" || { echo "FATAL: invalid DEVPAIR_USER '$U' (a-z 0-9 _ -)" >&2; exit 1; }
dp_valid_hostname "$H" || { echo "FATAL: invalid DEVPAIR_HOSTNAME '$H' (RFC-1123, max 63)" >&2; exit 1; }

# ---- preflight: environment facts (P2 — verified, never assumed) ---------------------
PHASE "facts (P2 verify-before-adopt)"
. /etc/os-release
[ "${ID:-}" = fedora ] || { echo "FATAL: this converger targets Fedora (found ID='${ID:-?}'). A new OS is an adapter addition, never a silent proceed." >&2; exit 1; }
echo ">> Fedora ${VERSION_ID:-?} on $(uname -m), kernel $(uname -r)"

PHASE "hostname"
hostnamectl set-hostname "$H"
# Cloud-init would revert the name every boot; preserve_hostname is the one documented key
# that disables both its set- and update-hostname modules. Drop-in, never vendor-file edit.
install -d -m0755 /etc/cloud/cloud.cfg.d
printf '#cloud-config\npreserve_hostname: true\n' > /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg
chmod 0644 /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg
restorecon /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg 2>/dev/null || true

# ---- packages (P1 provenance: Fedora L1 + Tailscale L2; P3 minimal leaf) -------------
PHASE "packages"
# The Tailscale vendor repo (L2: vendor's own dnf repo). The .repo file itself is fetched
# through the one pinned-fetch contract: official URL only, STRUCTURALLY verified before
# it goes live — it must declare gpgcheck=1 AND repo_gpgcheck=1 with the signing key on
# the vendor's own host (live fact-check 2026-08-03; the check lives in lib.sh). Written
# to a dot-name dnf ignores, verified, then atomically renamed, so a partial fetch never
# poisons dnf.
new=/etc/yum.repos.d/.tailscale.repo.new
if curl -fsSL https://pkgs.tailscale.com/stable/fedora/tailscale.repo -o "$new" \
   && verify_tailscale_repo "$new"; then
    mv -f "$new" /etc/yum.repos.d/tailscale.repo
    restorecon /etc/yum.repos.d/tailscale.repo 2>/dev/null || true
elif [ -s /etc/yum.repos.d/tailscale.repo ] && verify_tailscale_repo /etc/yum.repos.d/tailscale.repo; then
    rm -f "$new"; echo ">> tailscale.repo fetch failed or failed verification; existing copy verified, keeping it" >&2
else
    rm -f "$new"; echo "FATAL: tailscale.repo failed verification and no verified copy exists (fail-closed, P1)" >&2; exit 1
fi

# The decided capability set, minimal leaf (P3; install_weak_deps=False is load-bearing —
# never drop it). Recorded exclusions from the fleet's list: flatpak-session-helper (no
# capability serves it here), fastfetch (cosmetic), cockpit-networkmanager +
# cockpit-selinux (dashboard conveniences — host network and SELinux are repo-converged,
# never hand-managed; capability trade-off, recorded), fail2ban (a key-only door has no
# password to brute-force — fleet-proven).
dnf -y --setopt=install_weak_deps=False install \
    podman distrobox git tmux mosh openssh-server tailscale \
    dnf5-plugin-automatic \
    cockpit cockpit-podman cockpit-files

# ---- operating user (no blanket NOPASSWD — a real trust boundary, converged now) -----
PHASE "operating user '$U'"
# useradd allocates the subuid/subgid ranges rootless podman needs. wheel membership lets
# a human admin escalate WITH a password. The scoped agent sudoers allowlist ships with
# the verb that needs it (P3: no unproven gating) — increment 6.
id "$U" >/dev/null 2>&1 || useradd -m -G wheel "$U"
# Converge away cloud-init's blanket NOPASSWD for $U if the provider image granted it —
# sudoers is a permissive union, so the broad rule must be actively stripped, not assumed
# absent. Only $U's lines are touched; other admins' stanzas stay.
ci=/etc/sudoers.d/90-cloud-init-users
if [ -f "$ci" ] && grep -qE "^[[:space:]]*${U}[[:space:]].*NOPASSWD" "$ci"; then
    grep -vE "^[[:space:]]*${U}[[:space:]].*NOPASSWD" "$ci" > "${ci}.new" || true
    chmod 0440 "${ci}.new"
    if ! visudo -cf "${ci}.new" >/dev/null 2>&1; then
        rm -f "${ci}.new"; echo "WARN: could not safely strip '$U' NOPASSWD from $ci; left as-is" >&2
    elif [ -s "${ci}.new" ]; then
        mv -f "${ci}.new" "$ci"; restorecon "$ci" 2>/dev/null || true
        echo ">> stripped cloud-init's blanket NOPASSWD for '$U'"
    else
        rm -f "${ci}.new" "$ci"
        echo ">> removed cloud-init's blanket NOPASSWD ($ci held only '$U')"
    fi
fi
loginctl enable-linger "$U"
uid="$(id -u "$U")"
systemctl start "user@${uid}.service" 2>/dev/null || true

# ---- sshd: the one public door, key-only (FR-SEC-1, FR-SEC-2) ------------------------
PHASE "sshd: key-only door"
# Explicit, not assumed: the door's posture is declared here, validated with sshd -t
# BEFORE it goes live, and read back by validate.sh (the G2 seam). Root stays reachable
# by KEY ONLY (prohibit-password) as the provider-console-independent recovery path —
# still key-only, satisfying FR-SEC-2.
install -d -m0755 /etc/ssh/sshd_config.d
tee /etc/ssh/sshd_config.d/50-devpair.conf >/dev/null <<'EOS'
# dev-pair: the public door is key-only, without exception on any shell path (FR-SEC-2).
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOS
chmod 0644 /etc/ssh/sshd_config.d/50-devpair.conf
# Host keys normally exist from the image's first boot (cloud-init/sshd-keygen); an image
# whose first boot never generated them must not wedge the converger — generate on demand
# (a no-op where keys already exist), then validate BEFORE the drop-in goes live.
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
sshd -t || { echo "FATAL: sshd config invalid after applying 50-devpair.conf" >&2; exit 1; }
systemctl enable --now sshd
systemctl reload sshd 2>/dev/null || systemctl restart sshd

# ---- system services -----------------------------------------------------------------
PHASE "services"
# Cockpit is tailnet-only by construction: bind its socket to loopback BEFORE it can ever
# start (the vendor default listens on all interfaces — on a firewall-less Fedora Cloud
# that is a public dashboard). The empty ListenStream= resets the vendor default; the
# re-bind is the only listener. Sole ingress: the tailnet serve proxy below.
install -d /etc/systemd/system/cockpit.socket.d
tee /etc/systemd/system/cockpit.socket.d/listen.conf >/dev/null <<'EOS'
[Socket]
ListenStream=
ListenStream=127.0.0.1:9090
EOS
# Host OS clock (FR-REF-5): dnf5-automatic applies ALL updates (Fedora security metadata
# is incomplete — upgrade_type=security is unreliable, RH BZ#1770125), NEVER auto-reboots
# (a reboot is a decision the refresh machinery owns). Monthly, on the 15th.
tee /etc/dnf/automatic.conf >/dev/null <<'EOS'
[commands]
upgrade_type = default
download_updates = yes
apply_updates = yes
reboot = never
random_sleep = 0

[emitters]
emit_via = stdio
EOS
install -d /etc/systemd/system/dnf5-automatic.timer.d
tee /etc/systemd/system/dnf5-automatic.timer.d/schedule.conf >/dev/null <<'EOS'
[Timer]
OnCalendar=
OnCalendar=*-*-15 06:00
EOS
# Reboot NOTIFIER (never reboots): surfaces "reboot recommended" as a login motd when
# applied updates haven't taken effect. Re-checked after boot and daily.
install -d /etc/motd.d
tee /etc/systemd/system/reboot-needed-notify.service >/dev/null <<'EOS'
[Unit]
Description=Surface "reboot recommended" after package updates (NEVER reboots)
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'dnf -q needs-restarting >/dev/null 2>&1 && rm -f /etc/motd.d/15-reboot-needed || echo "** A reboot is recommended to finish applying updates (kernel/libraries); reboot at your convenience. **" > /etc/motd.d/15-reboot-needed'
EOS
tee /etc/systemd/system/reboot-needed-notify.timer >/dev/null <<'EOS'
[Unit]
Description=Check whether a reboot is recommended (after boot + daily)
[Timer]
OnBootSec=2min
OnCalendar=*-*-* 07:00
Persistent=true
[Install]
WantedBy=timers.target
EOS
systemctl daemon-reload
systemctl enable --now cockpit.socket tailscaled dnf5-automatic.timer reboot-needed-notify.timer
systemctl restart cockpit.socket

# ---- SELinux: one-time no-wait convergence to enforcing ------------------------------
# A fresh Fedora Cloud boots SELinux-DISABLED; enforcing on an unlabeled fs can wedge the
# boot. The one brick-safe path (fleet-proven, already the simplified form): relabel in
# PERMISSIVE, then a fire-once unit flips to enforcing LIVE on the post-relabel boot and
# self-disarms. Never downgrades an enforcing host. Opt out: SELINUX_TARGET=permissive.
PHASE "SELinux convergence"
selc=/etc/selinux/config
seldir=/var/lib/dev-pair
selarmed="$seldir/selinux-enforce-armed"
seltarget="${SELINUX_TARGET:-enforcing}"
install -d -m0755 "$seldir"
install -m0755 "$HERE/selinux-enforce-once.sh" /usr/local/sbin/selinux-enforce-once
restorecon /usr/local/sbin/selinux-enforce-once 2>/dev/null || true
tee /etc/systemd/system/selinux-enforce-once.service >/dev/null <<EOS
[Unit]
Description=dev-pair: one-time SELinux permissive->enforcing flip (no-wait, self-disarming)
ConditionSecurity=selinux
ConditionPathExists=$selarmed
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/selinux-enforce-once
[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
_sel_set(){ if grep -qE '^SELINUX=' "$selc"; then sed -i "s/^SELINUX=.*/SELINUX=$1/" "$selc"; else printf 'SELINUX=%s\n' "$1" >> "$selc"; fi; restorecon "$selc" 2>/dev/null || true; }
_sel_unarm(){ rm -f "$selarmed"; systemctl disable selinux-enforce-once.service >/dev/null 2>&1 || true; }
selcur=$(getenforce 2>/dev/null || true)
if [ ! -f "$selc" ] || [ -z "$selcur" ]; then
    echo ">> no getenforce/$selc (container or SELinux-less userspace) — skipping SELinux config."
elif grep -qE '(^| )selinux=0( |$)' /proc/cmdline 2>/dev/null; then
    _sel_unarm
    echo ">> WARNING: 'selinux=0' on the kernel cmdline overrides $selc — SELinux cannot enable; NOT armed." >&2
elif [ "$seltarget" != enforcing ]; then
    [ "$selcur" = Disabled ] && { [ -e /.autorelabel ] || touch /.autorelabel; }
    _sel_set permissive; _sel_unarm
    echo ">> SELINUX_TARGET=$seltarget -> permissive only; enforcing NOT armed (was $selcur)."
elif [ "$selcur" = Enforcing ]; then
    _sel_set enforcing; _sel_unarm
    echo ">> SELinux already enforcing — nothing to converge."
elif [ "$selcur" = Permissive ]; then
    _sel_set enforcing; setenforce 1 2>/dev/null || true; _sel_unarm
    echo ">> SELinux was permissive (labeled) -> flipped to ENFORCING live."
else
    _sel_set permissive
    [ -e /.autorelabel ] || touch /.autorelabel
    : > "$selarmed"
    systemctl enable selinux-enforce-once.service >/dev/null 2>&1 || true
    echo ">> SELinux ARMED — no-wait convergence to ENFORCING (was $selcur):"
    echo ">>   REBOOT -> relabel in permissive (auto-reboots) -> next boot flips to ENFORCING live."
fi

# ---- tailscale: the private network (FR-SEC-1) ----------------------------------------
PHASE "tailscale"
# Routing posture ON BY DEFAULT, as the fleet proved useful: accept-routes (reach the home
# LAN), advertise-exit-node (offer the VPS's public IP as an exit). Override per run with
# TS_ACCEPT_ROUTES=0 / TS_EXIT_NODE=0. The join is a GENESIS act (one human/browser or one
# auth key, once); convergence re-asserts prefs on an already-joined node and warns loudly
# — never fails — on an unjoined one (P10: converge must stay re-runnable).
ACCEPT_ROUTES="$(ts_bool "${TS_ACCEPT_ROUTES:-}")"; ADVERTISE_EXIT="$(ts_bool "${TS_EXIT_NODE:-}")"
if [ "$ADVERTISE_EXIT" = true ]; then
    install -d -m0755 /etc/sysctl.d
    printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' > /etc/sysctl.d/99-tailscale.conf
    sysctl -p /etc/sysctl.d/99-tailscale.conf >/dev/null 2>&1 || true
fi
ts_up=(--ssh)
[ "$ACCEPT_ROUTES" = true ] && ts_up+=(--accept-routes)
[ "$ADVERTISE_EXIT" = true ] && ts_up+=(--advertise-exit-node)
if ! tailscale status >/dev/null 2>&1; then
    if [ -n "${TS_AUTHKEY:-}" ]; then
        # The key never lands on argv (readable via /proc/<pid>/cmdline): tailscale's
        # stable --auth-key=file: prefix reads it from a 0600 file, removed after the join.
        _tskf="$(mktemp)"; chmod 600 "$_tskf"; printf '%s' "$TS_AUTHKEY" > "$_tskf"
        tailscale up "${ts_up[@]}" --auth-key="file:$_tskf"; rc=$?
        rm -f "$_tskf"
        [ "$rc" = 0 ] || { echo "FATAL: tailscale unattended join failed" >&2; exit 1; }
    else
        echo ">> WARNING: node not joined and no TS_AUTHKEY — the tailnet join is a genesis act." >&2
        echo ">>   Complete it: 'tailscale up ${ts_up[*]}' (browser link), or re-run with TS_AUTHKEY=tskey-..." >&2
    fi
else
    # Already joined: re-assert prefs idempotently (covers drift), and if advertising as an
    # exit node, VERIFY it reached the control plane — local prefs alone are a false
    # positive on a logged-out node (fleet-measured).
    tailscale set --accept-routes="$ACCEPT_ROUTES" --advertise-exit-node="$ADVERTISE_EXIT" || true
    if [ "$ADVERTISE_EXIT" = true ]; then
        if tailscale status --json 2>/dev/null | grep -q '"BackendState":[[:space:]]*"Running"' \
           && tailscale debug prefs 2>/dev/null | grep -Eq '0\.0\.0\.0/0|::/0'; then
            echo ">> Tailscale: running, advertising as exit node."
        else
            echo ">> WARNING: BackendState != Running or exit-node route not advertised." >&2
        fi
    fi
fi
# Publish Cockpit on the tailnet (TLS :443 -> 127.0.0.1:9090). The serve only works once
# MagicDNS + HTTPS Certificates are enabled, so the helper retries under systemd
# (Restart=on-failure owns the retry — no bash sleep-loop) and settles on first success.
install -m0755 "$HERE/cockpit-tailnet-serve.sh" /usr/local/sbin/cockpit-tailnet-serve
tee /etc/systemd/system/cockpit-tailnet-serve.service >/dev/null <<'EOS'
[Unit]
Description=Publish Cockpit on the tailnet (tailscale serve :443 -> 127.0.0.1:9090) + matching cockpit.conf
After=tailscaled.service cockpit.socket network-online.target
Wants=tailscaled.service
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cockpit-tailnet-serve
Restart=on-failure
RestartSec=60s
[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
systemctl enable cockpit-tailnet-serve.service
systemctl start --no-block cockpit-tailnet-serve.service 2>/dev/null || true

# ---- session persistence (FR-SEC-3 — mechanism chosen in DESIGN B.7) ------------------
PHASE "session persistence"
# Every ssh/mosh login gets its OWN session in ONE shared "main" tmux GROUP: windows (the
# work) are shared across every client, each connection's geometry stays independent (the
# fleet-measured multi-client resize race). The per-connection session self-destroys on
# disconnect; work persists in the detached base. Long-term persistence is the default
# state — nothing reaps idle sessions.
tee /etc/profile.d/zz-tmux-attach.sh >/dev/null <<'EOS'
# ssh/mosh logins each get their own session in the shared "main" group.
case $- in *i*) ;; *) return ;; esac
if [ -z "${TMUX:-}" ] && command -v tmux >/dev/null && { [ -n "${SSH_TTY:-}" ] || [ -t 0 ]; }; then
    tmux has-session -t main 2>/dev/null || tmux new-session -d -s main 2>/dev/null || true
    exec tmux new-session -t main -s "c$$" \; set-option destroy-unattached on
fi
EOS
tee /etc/tmux.conf >/dev/null <<'EOS'
set -g default-terminal "tmux-256color"
set -g window-size latest
setw -g aggressive-resize on
setw -g fill-character ' '
set-hook -g client-attached 'refresh-client'
set-hook -g client-resized  'refresh-client'
EOS

# ---- control clone ownership ----------------------------------------------------------
# The repo this converger runs from is the control clone (/opt/dev-pair on a provisioned
# host). It must be $U-owned: the self-refresh absorber (increment 6) fast-forwards it as
# $U, and on a root-owned clone that verb is a permanent fail-closed no-op (fleet incident
# 2026-07-17: merged host code silently never went live). Fail-LOUD, never fatal.
PHASE "control clone"
CLONE="$(cd "$HERE/../.." && pwd)"
if [ -d "$CLONE/.git" ]; then
    if chown -R "$U:$U" "$CLONE"; then
        git config --global --add safe.directory "$CLONE" 2>/dev/null || true
        echo ">> control clone $CLONE is now $U-writable."
    else
        echo ">> WARN: could not chown control clone $CLONE to $U — self-refresh will stay a fail-closed no-op." >&2
    fi
else
    echo ">> NOTE: $CLONE is not a git clone — no self-refresh source (running from an archive?)." >&2
fi

# ---- hand off to the rootless layer ----------------------------------------------------
PHASE "rootless layer (as '$U')"
uid="$(id -u "$U")"
for _ in $(seq 1 100); do [ -S "/run/user/${uid}/bus" ] && break; sleep 0.1; done
[ -S "/run/user/${uid}/bus" ] || echo ">> WARN: user D-Bus not up for '$U' — rootless layer may need a re-run after first login." >&2
su - "$U" -c "DEVPAIR_KEYS_USER='$KEYS_USER' bash '$HERE/converge-user.sh'"

echo ">> CONVERGE COMPLETE — host state declared and applied. Verify with: host/core/validate.sh"
