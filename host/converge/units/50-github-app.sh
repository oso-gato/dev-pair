#!/usr/bin/env bash
# 50-github-app — the pair's GitHub authority, minted short and held on tmpfs.
#
# Each pair works under its own dedicated App identities, never shared
# (00-OBJECTIVE.md; ADR 000012). The host component's App carries no merge
# permission and the dev-container's does, so the host-never-merges boundary is
# enforced by GitHub rather than by our own restraint.
#
# The private keys are credentials and reach the host only through day zero.
# This unit installs the minter and its schedule, so a host that has the keys
# always holds a fresh token and a host that does not simply holds none.
#
# Sourced by converge.sh.

log_unit "github app"

# The minter is shared: both components mint their own token from their own
# App, so it lives in shared/ and neither component owns a copy.
# BIN_DIR and UNIT_DIR are adapter facts because /usr is read-only on the
# bare-metal track's bootc host — the image owns it and it changes only by
# rebase. This unit runs on both tracks, so it must not assume it can write there.
fs_install "$REPO_ROOT/shared/bin/pair-gh-app-token"       "$BIN_DIR/pair-gh-app-token" 0755
fs_install "$REPO_ROOT/host/sysroot/usr/bin/pair-gh-renew" "$BIN_DIR/pair-gh-renew"     0755

fs_render "$REPO_ROOT/host/sysroot/usr/lib/systemd/system/pair-gh-app-token.service.tpl" \
          "$UNIT_DIR/pair-gh-app-token.service" 0644 BIN_DIR PAIR_SECRETS_DIR ADMIN_USER
fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/system/pair-gh-app-token.timer" \
           "$UNIT_DIR/pair-gh-app-token.timer" 0644

systemctl daemon-reload
fs_enable_unit pair-gh-app-token.timer

# Report whether the capability is actually armed. C3's activation-proof is the
# standard here: an installed minter with no credentials is not a working
# GitHub authority, and saying so beats reporting green.
#
# Presence alone was never that proof. A zero-byte or truncated key satisfies a
# file test, so this unit reported credentials in green while the minter died
# on the very same file at the next timer fire — the activation-proof above was
# aspiration rather than fact. The probe therefore asks openssl whether the
# file is a usable private key, which is the question the minter asks of it.
#
# Only the exit status is read and both streams go to /dev/null, because a
# credential's own bytes must never reach a terminal or the journal (C6). An
# absent openssl fails the probe and is reported the same way, and that is
# correct rather than a false alarm: the minter cannot mint without it either.
_app_key_usable() {
    [ -s "$1" ] && openssl pkey -in "$1" -noout >/dev/null 2>&1
}

if _app_key_usable "$PAIR_SECRETS_DIR/github-app/private-key.pem"; then
    log_ok "host App credentials present and usable (${HOST_APP_NAME}, App ${HOST_APP_ID})"
else
    log_warn "host App credentials absent or unusable — day zero installs them from the vault; the box will have no GitHub authority until it does"
fi

if _app_key_usable "$PAIR_DEV_SECRETS_DIR/${DEV_CONTAINER_NAME}-github-app/private-key.pem"; then
    log_ok "dev-container App credentials present and usable (${DEV_APP_NAME}, App ${DEV_APP_ID})"
else
    log_warn "dev-container App credentials absent or unusable — day zero installs them from the vault"
fi
