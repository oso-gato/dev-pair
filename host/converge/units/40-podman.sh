#!/usr/bin/env bash
# 40-podman — rootless containers for the administrative user.
#
# Both things this host runs — the agent box and the dev-container — are
# rootless containers owned by the administrative user, which is C6's least
# privilege applied to the runtime rather than only to identities. This unit
# makes that possible and makes it survive a reboot with nobody logged in.
#
# Sourced by converge.sh.

log_unit "podman"

# Subordinate ID ranges: without these, a rootless container has no user
# namespace to map into and podman fails in a way that reads as a permissions
# bug rather than a missing declaration.
if grep -q "^${ADMIN_USER}:" /etc/subuid && grep -q "^${ADMIN_USER}:" /etc/subgid; then
    log_ok "subordinate id ranges present for ${ADMIN_USER}"
else
    usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$ADMIN_USER" \
        || log_die "cannot assign subordinate id ranges to ${ADMIN_USER}"
    log_changed "assigned subordinate id ranges to ${ADMIN_USER}"
fi

# Linger: the user manager has to run at boot without a login, or the
# dev-container and the box's daily timer would only exist while somebody was
# connected — which would make "sessions survive" false the first time nobody
# was.
if loginctl show-user "$ADMIN_USER" -p Linger --value 2>/dev/null | grep -qx yes; then
    log_ok "linger enabled for ${ADMIN_USER}"
else
    loginctl enable-linger "$ADMIN_USER" || log_die "cannot enable linger for ${ADMIN_USER}"
    log_changed "enabled linger for ${ADMIN_USER} — the user manager now runs at boot"
fi

# The rootless API socket the agent box bridges to. Enabled globally so it
# exists for the administrative user's manager without a per-session step.
fs_enable_user_unit podman.socket

# The durable state directories, split by owner so the dev-container running as
# the administrative user cannot reach the host component's own App key.
fs_ensure_dir "$PAIR_STATE_DIR"       0755 root:root
fs_ensure_dir "$PAIR_SECRETS_DIR"     0700 root:root
fs_ensure_dir "$PAIR_ADMIN_STATE"     0700 "${ADMIN_USER}:${ADMIN_USER}"
fs_ensure_dir "$PAIR_DEV_SECRETS_DIR" 0700 "${ADMIN_USER}:${ADMIN_USER}"
fs_ensure_dir "$PAIR_WORK_DIR"        0755 "${ADMIN_USER}:${ADMIN_USER}"
