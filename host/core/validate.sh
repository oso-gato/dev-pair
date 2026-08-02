#!/usr/bin/env bash
# dev-pair — the VALIDATE verb (v1): the host's live acceptance read-back, and the G2
# seam for host refreshes. Every check reads the LIVE artifact — effective daemon config,
# listening sockets, unit state — never a config file's testimony. Exit 1 if any check
# FAILs. SKIP/WARN marks a legitimately-incomplete state (e.g. tailnet join pending
# genesis) so a standing red never trains the loop to ignore alarms (P3).
set -uo pipefail
U="${DEVPAIR_USER:-core}"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
warn() { printf 'WARN  %s\n' "$1"; }

# ---- the door: key-only, effective config (FR-SEC-1, FR-SEC-2) -------------------------
if command -v sshd >/dev/null 2>&1; then
    eff="$(sshd -T 2>/dev/null || true)"
    [ -n "$eff" ] || { eff="$(runuser -u root -- sshd -T 2>/dev/null || sudo sshd -T 2>/dev/null || true)"; }
    chk() { printf '%s\n' "$eff" | grep -q "^$1 $2\$"; }
    if [ -z "$eff" ]; then
        warn "sshd -T unreadable (needs root) — effective-config checks skipped"
    else
        chk passwordauthentication no   && pass "sshd: PasswordAuthentication no (effective)"   || fail "sshd: PasswordAuthentication is NOT 'no' (effective)"
        chk pubkeyauthentication yes    && pass "sshd: PubkeyAuthentication yes (effective)"    || fail "sshd: PubkeyAuthentication is NOT 'yes' (effective)"
        chk permitrootlogin prohibit-password \
            && pass "sshd: PermitRootLogin prohibit-password (effective, key-only recovery path)" \
            || fail "sshd: PermitRootLogin is NOT 'prohibit-password' (effective)"
    fi
    systemctl is-active --quiet sshd && pass "sshd: active" || fail "sshd: not active"
else
    fail "openssh-server not installed"
fi

# ---- public surface: only the sanctioned doors listen publicly --------------------------
# TCP: 22 (ssh) is the only public listener; cockpit must be loopback-only. UDP: mosh-server
# (60000-61000) appears only while a session runs — a sanctioned door (FR-SEC-1).
if command -v ss >/dev/null 2>&1; then
    bad="$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|::1|\[::1\])' \
           | grep -vE ':(22)$' || true)"
    [ -z "$bad" ] && pass "surface: no public TCP listeners besides ssh" \
                  || fail "surface: unexpected public TCP listener(s): $(printf '%s' "$bad" | tr '\n' ' ')"
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE '^(127\.0\.0\.1|\[::1\]):9090$' \
        && pass "cockpit: bound to loopback only" \
        || warn "cockpit: not listening on 127.0.0.1:9090 (socket inactive or unbound)"
else
    warn "ss not available — surface checks skipped"
fi

# ---- the platform capabilities -----------------------------------------------------------
for pkg in podman distrobox tmux mosh tailscale git; do
    rpm -q "$pkg" >/dev/null 2>&1 && pass "package: $pkg" || fail "package missing: $pkg"
done

systemctl is-active --quiet tailscaled && pass "tailscaled: active" || fail "tailscaled: not active"
if tailscale status >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | grep -q '"BackendState":[[:space:]]*"Running"' \
        && pass "tailscale: joined and Running" \
        || warn "tailscale: up but BackendState != Running"
else
    warn "tailscale: NOT JOINED — a legitimate pre-genesis state; converge warns, genesis joins"
fi

# ---- session persistence (FR-SEC-3) -------------------------------------------------------
[ -f /etc/profile.d/zz-tmux-attach.sh ] && pass "persistence: tmux login drop-in installed" \
                                        || fail "persistence: /etc/profile.d/zz-tmux-attach.sh missing"
[ -f /etc/tmux.conf ] && pass "persistence: /etc/tmux.conf installed" \
                      || fail "persistence: /etc/tmux.conf missing"

# ---- the operating user ------------------------------------------------------------------
if id "$U" >/dev/null 2>&1; then
    pass "user: '$U' exists"
    [ "$(loginctl show-user "$U" -p Linger --value 2>/dev/null)" = yes ] \
        && pass "user: linger enabled for '$U'" \
        || fail "user: linger NOT enabled for '$U' (rootless layer dies at logout)"
else
    fail "user: '$U' missing"
fi

# ---- host clock + updates -----------------------------------------------------------------
systemctl is-enabled --quiet dnf5-automatic.timer 2>/dev/null \
    && pass "updates: dnf5-automatic.timer enabled (host OS clock)" \
    || fail "updates: dnf5-automatic.timer not enabled"

# ---- SELinux: enforcing, converging, or honestly exempt -----------------------------------
selcur="$(getenforce 2>/dev/null || true)"
case "$selcur" in
    Enforcing)  pass "SELinux: enforcing" ;;
    Permissive) [ -f /var/lib/dev-pair/selinux-enforce-armed ] \
                    && warn "SELinux: permissive, convergence ARMED (relabel boot pending)" \
                    || fail "SELinux: permissive and convergence NOT armed" ;;
    Disabled)   [ -f /var/lib/dev-pair/selinux-enforce-armed ] \
                    && warn "SELinux: disabled, convergence ARMED (relabel boot pending)" \
                    || warn "SELinux: disabled (container or selinux=0 — convergence skipped by design)" ;;
    *)          warn "SELinux: state unknown (no getenforce — container?)" ;;
esac

echo
if [ "$fails" -gt 0 ]; then
    echo "VALIDATE: $fails check(s) FAILED — the live host does not match the declared state."
    exit 1
fi
echo "VALIDATE: all checks passed (warnings, if any, name legitimate incomplete states)."
