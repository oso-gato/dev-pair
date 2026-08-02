#!/usr/bin/env bash
# dev-pair — one-time SELinux permissive->enforcing flip (NO-WAIT, self-disarming).
# Fleet-proven, carried verbatim except the state dir. Installed by converge.sh to
# /usr/local/sbin/selinux-enforce-once; run by selinux-enforce-once.service on the first
# boot that reaches multi-user.target AFTER the permissive relabel — by then the fs is
# labeled, so flipping to enforcing is brick-safe. Flips LIVE (no third reboot), makes it
# durable in config, self-disarms.
set -uo pipefail
seldir=/var/lib/dev-pair; selc=/etc/selinux/config; armed="$seldir/selinux-enforce-armed"
[ -f "$armed" ] || exit 0

# Flip only once actually PERMISSIVE — i.e. the relabel boot has run (fs now labeled). The
# unit's ConditionSecurity=selinux fences the kernel-disabled boot; this double-checks the
# running mode so we never setenforce against an unlabeled fs.
if [ "$(getenforce 2>/dev/null)" = Permissive ]; then
    if grep -qE '^SELINUX=' "$selc"; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' "$selc"
    else printf 'SELINUX=enforcing\n' >> "$selc"; fi
    restorecon "$selc" 2>/dev/null || true
    setenforce 1 2>/dev/null || true
    logger -t selinux-enforce-once "flipped to ENFORCING (live) on a labeled fs; disarming" 2>/dev/null || true
fi

rm -f "$armed"
systemctl disable selinux-enforce-once.service >/dev/null 2>&1 || true
