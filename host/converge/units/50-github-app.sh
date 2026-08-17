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
fs_install "$REPO_ROOT/shared/bin/pair-gh-app-token"       /usr/bin/pair-gh-app-token 0755
fs_install "$REPO_ROOT/host/sysroot/usr/bin/pair-gh-renew" /usr/bin/pair-gh-renew     0755

fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/system/pair-gh-app-token.service" \
           /usr/lib/systemd/system/pair-gh-app-token.service 0644
fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/system/pair-gh-app-token.timer" \
           /usr/lib/systemd/system/pair-gh-app-token.timer 0644

systemctl daemon-reload
fs_enable_unit pair-gh-app-token.timer

# Report whether the capability is actually armed. C3's activation-proof is the
# standard here: an installed minter with no credentials is not a working
# GitHub authority, and saying so beats reporting green.
if [ -f "$PAIR_SECRETS_DIR/github-app/private-key.pem" ]; then
    log_ok "host App credentials present (${HOST_APP_NAME}, App ${HOST_APP_ID})"
else
    log_warn "host App credentials absent — day zero installs them from the vault; the box will have no GitHub authority until it does"
fi

if [ -f "$PAIR_DEV_SECRETS_DIR/nox-github-app/private-key.pem" ]; then
    log_ok "dev-container App credentials present (${DEV_APP_NAME}, App ${DEV_APP_ID})"
else
    log_warn "dev-container App credentials absent — day zero installs them from the vault"
fi
