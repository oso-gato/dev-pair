#!/usr/bin/env bash
# 10-identity — the administrative user, the trust root, and root's retirement.
#
# C7 fixes the identity: on every host the estate operates, the first
# administrative user outside root is `core`, root never authenticates remotely
# after genesis, and escalation is by sudo. This unit is that sentence made
# real, and it is re-applied on every converge so drift cannot reopen a door.
#
# What this unit does NOT do is set the password. The hash is a declaration
# whose one home is the vault (C6), and day zero is what carries it here. This
# unit enforces the shape; day zero supplies the secret.
#
# Sourced by converge.sh, with log.sh and fs.sh already loaded.

log_unit "identity"

# ── The administrative user ──────────────────────────────────────────────────
if id -u "$ADMIN_USER" >/dev/null 2>&1; then
    log_ok "user ${ADMIN_USER} exists"
else
    useradd --create-home --shell /bin/bash --groups wheel "$ADMIN_USER" \
        || log_die "cannot create ${ADMIN_USER}"
    log_changed "created ${ADMIN_USER}"
fi

if id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx wheel; then
    log_ok "${ADMIN_USER} is in wheel"
else
    usermod -aG wheel "$ADMIN_USER" || log_die "cannot add ${ADMIN_USER} to wheel"
    log_changed "added ${ADMIN_USER} to wheel"
fi

# ── The trust root ───────────────────────────────────────────────────────────
# Run the sync as the user itself, so the keys land in its own authorized_keys
# with its own ownership. It is failure-safe by design: a failed or empty fetch
# leaves the existing keys alone and says so. Read its actual output rather than
# assuming success, or a converge run would report a change that never happened.
_sync_out=$(runuser -u "$ADMIN_USER" -- env "TRUST_ROOT_USER=$TRUST_ROOT_USER" \
            "$BIN_DIR/pair-keys-sync" 2>&1) || true
case "$_sync_out" in
    *"already current"*) log_ok "authorized_keys current from the trust root" ;;
    *"authorized "*)     log_changed "synced authorized_keys from github.com/${TRUST_ROOT_USER}.keys" ;;
    *)                   log_warn "trust-root sync did not complete; existing keys left untouched — ${_sync_out}" ;;
esac

# ── Shell access policy ──────────────────────────────────────────────────────
# The test has to come after the install and the install has to be reversible,
# because sshd includes every drop-in in this directory the instant it lands.
# Validating the repository's copy first would prove nothing about what sshd
# will actually read, and an invalid drop-in left on disk survives the running
# daemon and takes the next reboot's sshd down with it — a host that comes back
# with no public door. So the incumbent is kept aside, the new file is
# installed, the live configuration is tested, and a failure puts the incumbent
# back before this unit dies. That restoration is the C11 recovery, and dying
# without it would be the human summons C11 forbids.
#
# The copy is kept outside sshd_config.d, because a spare copy inside it would
# itself be a live drop-in. Both the incumbent's hash and its copy are taken
# inside one existence test, because the converger runs under pipefail and a
# sha256sum of a file that is not there yet fails the whole pipeline — which on
# a first apply aborted converge here rather than installing anything.
_sshd_conf=/etc/ssh/sshd_config.d/40-dev-pair.conf
_sshd_before=""
_sshd_backup=""
if [ -f "$_sshd_conf" ]; then
    _sshd_before=$(sha256sum "$_sshd_conf" | awk '{print $1}')
    _sshd_backup=$(mktemp) || log_die "cannot stage a copy of ${_sshd_conf}"
    cp -p "$_sshd_conf" "$_sshd_backup" || log_die "cannot copy ${_sshd_conf} aside"
fi

fs_install "$REPO_ROOT/host/sysroot/etc/ssh/sshd_config.d/40-dev-pair.conf" \
           "$_sshd_conf" 0644
_sshd_after=$(sha256sum "$_sshd_conf" | awk '{print $1}')

if [ "$_sshd_before" != "$_sshd_after" ]; then
    if sshd -t; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd \
            || log_die "cannot reload sshd"
        log_changed "sshd reloaded under the keys-only policy"
    else
        if [ -n "$_sshd_backup" ]; then
            install -m 0644 -o root -g root "$_sshd_backup" "$_sshd_conf" \
                || log_die "the new sshd configuration does not parse AND the previous one cannot be put back — ${_sshd_conf} is invalid on disk and must be repaired from the provider's console before this host reboots; the previous drop-in is still readable at ${_sshd_backup}"
            _sshd_restored="the previous drop-in is back in place"
        else
            rm -f "$_sshd_conf"
            _sshd_restored="the new drop-in was removed and there was no previous one"
        fi
        rm -f "$_sshd_backup"
        sshd -t || log_die "the new sshd configuration does not parse, and the configuration restored under it does not parse either — sshd is broken beyond this unit's recovery and must be repaired from the provider's console before this host reboots"
        log_die "the new sshd configuration does not parse — nothing reloaded, ${_sshd_restored}"
    fi
fi
if [ -n "$_sshd_backup" ]; then
    rm -f "$_sshd_backup"
fi

# Land an interactive login in the durable session, on this component as well
# as in the dev-container. Both are reached by ssh and by mosh, and on both the
# work has to outlive the connection.
fs_install "$REPO_ROOT/shared/profile.d/zz-tmux-attach.sh" \
           /etc/profile.d/zz-tmux-attach.sh 0644

# The geometry half of the same answer. The profile above puts each login in
# its own client-scoped session so windows are shared and size is not; this
# settles what happens when two devices do land on the same window. It is
# byte-identical to the dev-container's copy because the rule belongs to the
# platform rather than to either component, and the self-test holds the two
# together so a difference reads as drift instead of as a decision.
fs_install "$REPO_ROOT/host/sysroot/etc/tmux.conf" /etc/tmux.conf 0644

# ── Root retires, but only once someone else can get in ──────────────────────
# Remote root is already refused by the sshd policy above. Locking the password
# closes the console path day zero itself came in through, which is the whole
# point of "root's only act, ever".
#
# Recovery before power (C11): locking root while the administrative user is
# not yet usable would strand the host with no way in and no self-heal path,
# which is the definition of a human summons. So the lock is gated on proof
# that the replacement works — the user exists, can escalate, and has a key to
# arrive on. Failing that, this unit leaves root alone and says why.
_admin_ready=1
_admin_home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
id -u "$ADMIN_USER" >/dev/null 2>&1 || _admin_ready=0
id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx wheel || _admin_ready=0
[ -s "${_admin_home}/.ssh/authorized_keys" ] || _admin_ready=0
# A usable password is what makes sudo work; `L`, `NP` and an empty field all
# mean the administrative user cannot escalate.
passwd -S "$ADMIN_USER" 2>/dev/null | awk '{print $2}' | grep -qx 'P' || _admin_ready=0

if [ "$_admin_ready" = 0 ]; then
    # Say which situation this actually is. "Root is not retired" was printed
    # without reading root's state, and on a host converged once and later
    # degraded it was simply false — root was locked and the operator was told
    # otherwise. Which of the two it is decides whether there is still a way in.
    if passwd -S root 2>/dev/null | awk '{print $2}' | grep -qE '^(L|LK)$'; then
        log_warn "root is ALREADY locked and ${ADMIN_USER} is not usable (needs wheel, an authorized key, and a password) — the provider's console is the only way in. Day zero completes this; re-run converge afterwards."
    else
        log_warn "root NOT retired — ${ADMIN_USER} is not yet usable (needs wheel, an authorized key, and a password). Day zero completes this; re-run converge afterwards."
    fi
elif passwd -S root 2>/dev/null | awk '{print $2}' | grep -qE '^(L|LK)$'; then
    log_ok "root password locked"
else
    passwd -l root >/dev/null 2>&1 || log_die "cannot lock the root password"
    log_changed "root password locked — ${ADMIN_USER} verified usable first"
fi

# ── Closing every other door ─────────────────────────────────────────────────
# Everything below removes a way in, and all of it is now gated on the same
# proof that gates root's retirement. The gate used to cover the root lock
# alone: on a host where `core` was NOT usable, this unit printed that core
# could not escalate and then cleared root's authorized_keys, deleted the
# provider's sudo rule, locked its users and stripped any remaining NOPASSWD
# rule — narrating the lockout while causing it. That is the human summons C11
# forbids, produced by the unit whose own comment claims to avoid it.
#
# A converged host takes the else branch every time, so this costs nothing in
# the steady state and only holds the doors open while something is wrong.
if [ "$_admin_ready" = 0 ]; then
    log_warn "every other way in is left alone until ${ADMIN_USER} is usable — root's keys, the provider's users and its sudo rules are untouched on purpose"
else
    if [ -s /root/.ssh/authorized_keys ]; then
        : > /root/.ssh/authorized_keys
        log_changed "cleared root's authorized_keys"
    else
        log_ok "root holds no authorized keys"
    fi

    # ── No second administrator ──────────────────────────────────────────────────
    # The provider's template leaves its own cloud-init user with passwordless
    # sudo. That is a second administrative identity, which C7 does not allow, and
    # a NOPASSWD rule for it would also defeat the sudo-by-password rule the
    # objective's Security outcome 2 states. Lock the account rather than delete
    # it — a delete with live processes is messy, and locked is sufficient.
    for stale in /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/90-cloud-init; do
        if [ -f "$stale" ]; then
            rm -f "$stale"
            log_changed "removed the provider's passwordless sudo rule ($stale)"
        fi
    done

    for other in fedora cloud-user ec2-user admin; do
        id -u "$other" >/dev/null 2>&1 || continue
        [ "$other" = "$ADMIN_USER" ] && continue
        if passwd -S "$other" 2>/dev/null | awk '{print $2}' | grep -qE '^(L|LK)$'; then
            log_ok "provider user ${other} already locked"
        else
            passwd -l "$other" >/dev/null 2>&1 || log_warn "cannot lock ${other}"
            log_changed "locked the provider's user ${other} — ${ADMIN_USER} is the one administrator (C7)"
        fi
        if id -nG "$other" | tr ' ' '\n' | grep -qx wheel; then
            gpasswd -d "$other" wheel >/dev/null 2>&1 || log_warn "cannot remove ${other} from wheel"
            log_changed "removed ${other} from wheel"
        fi
    done

    # ── Sudo requires the password ───────────────────────────────────────────────
    # Steady state is stock %wheel with a password. Anything granting NOPASSWD to
    # wheel would silently undo the objective's Security outcome 2, so it goes.
    if grep -rlsE '^[^#]*%wheel.*NOPASSWD' /etc/sudoers.d/ >/dev/null 2>&1; then
        while IFS= read -r f; do
            rm -f "$f"
            log_changed "removed a passwordless sudo rule for wheel ($f)"
        done < <(grep -rlsE '^[^#]*%wheel.*NOPASSWD' /etc/sudoers.d/)
    else
        log_ok "sudo requires a password for wheel"
    fi
fi
