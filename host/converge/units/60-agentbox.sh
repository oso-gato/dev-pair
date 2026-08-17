#!/usr/bin/env bash
# 60-agentbox — the disposable agent layer on the host component (C8).
#
# The component is stable and the agent tooling is not, so the box absorbs the
# churn the component refuses. One box, one agent: claudebox is Claude Code,
# and a second agent would be a second box beside it rather than a package
# added to this one.
#
# The manifest is shared with the dev-container, because C8 pairs boxes by
# agent across a pair's components. That is why it comes from shared/ and not
# from host/.
#
# Sourced by converge.sh.

log_unit "agent box"

# The shared box definition, installed where both the rebuild unit and
# claudebox-init.sh expect it.
fs_install "$REPO_ROOT/shared/claudebox/distrobox.ini" \
           /usr/share/dev-pair/claudebox/distrobox.ini 0644
fs_install "$REPO_ROOT/shared/claudebox/managed-settings.json" \
           /usr/share/dev-pair/claudebox/managed-settings.json 0644
fs_install "$REPO_ROOT/shared/claudebox/claudebox-init.sh" \
           /usr/share/dev-pair/claudebox/claudebox-init.sh 0755

# The operator commands, shared with the dev-container for the same reason the
# manifest is: both components run a box and drive it the same way.
fs_install "$REPO_ROOT/shared/claudebox/claude"            "$BIN_DIR/claude"            0755
fs_install "$REPO_ROOT/shared/claudebox/claudebox-rebuild" "$BIN_DIR/claudebox-rebuild" 0755
fs_install "$REPO_ROOT/shared/claudebox/claudebox-daily"   "$BIN_DIR/claudebox-daily"   0755

# The rebuild machinery, in the user manager because the box is the user's.
fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/user/claudebox-rebuild-run.service" \
           /usr/lib/systemd/user/claudebox-rebuild-run.service 0644
fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/user/claudebox-rebuild-daily.service" \
           /usr/lib/systemd/user/claudebox-rebuild-daily.service 0644
fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/user/claudebox-rebuild-daily.timer" \
           /usr/lib/systemd/user/claudebox-rebuild-daily.timer 0644

systemctl daemon-reload
fs_enable_user_unit claudebox-rebuild-daily.timer

# The box itself is not built here. The daily timer's OnStartupSec creates it
# on the first boot after this converge, and `claude` builds it on demand if a
# session comes first — so there is no path where the operator has to build it
# by hand, and no path where a converge run blocks for five minutes building a
# layer it is about to replace nightly anyway.
if runuser -u "$ADMIN_USER" -- podman container exists claudebox 2>/dev/null; then
    log_ok "claudebox exists — the daily rebuild keeps it current"
else
    log_ok "claudebox not built yet — the rebuild timer creates it, or the claude wrapper does on first use"
fi
