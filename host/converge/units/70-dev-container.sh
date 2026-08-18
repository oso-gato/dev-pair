#!/usr/bin/env bash
# 70-dev-container — the pair's dev-container, launched by the host from outside.
#
# Two boundaries meet here and both are the objective's own. Neither component
# builds production images, so the host PULLS what CI built and never builds it
# locally. And the dev-container never rebuilds itself — the host launches and
# relaunches it from outside (B4), which is why this unit lives on the host and
# has no counterpart inside the container.
#
# One image serves every lineage. What differs between pairs is the instance
# name and the App identity, and those are adapter facts rather than a second
# definition — an addition, never a fork.
#
# Sourced by converge.sh.

log_unit "dev-container"

# Rendered per pair from the one template.
fs_render "$REPO_ROOT/host/sysroot/etc/containers/systemd/users/dev-container.container.tpl" \
          "/etc/containers/systemd/users/${DEV_CONTAINER_NAME}.container" 0644 \
          PAIR_NAME DEV_CONTAINER_NAME DEV_CONTAINER_IMAGE \
          DEV_SSH_PORT DEV_MOSH_PORTS DEV_TAILNET_HOSTNAME TRUST_ROOT_USER

# The enter command takes its container from its own invocation name, so it is
# installed as `nox` on erebus and `moros` on strix from the same source file.
fs_install "$REPO_ROOT/host/sysroot/usr/bin/pair-enter" "$BIN_DIR/${DEV_CONTAINER_NAME}" 0755

# The volumes the Quadlet mounts have to exist and be owned before the unit
# starts, or podman creates them root-owned and the rootless container cannot
# write its host keys or its tailnet state.
fs_ensure_dir "$PAIR_ADMIN_STATE/${DEV_CONTAINER_NAME}-sshd-keys"      0700 "${ADMIN_USER}:${ADMIN_USER}"
fs_ensure_dir "$PAIR_ADMIN_STATE/${DEV_CONTAINER_NAME}-tailscale-state" 0700 "${ADMIN_USER}:${ADMIN_USER}"
fs_ensure_dir "$PAIR_DEV_SECRETS_DIR/${DEV_CONTAINER_NAME}-tailscale"   0700 "${ADMIN_USER}:${ADMIN_USER}"

# Pull what CI built. An image already present at the same digest is not pulled
# again, so a converged host reports no change here.
_admin_uid=$(id -u "$ADMIN_USER")
_as_admin=(runuser -u "$ADMIN_USER" -- env "XDG_RUNTIME_DIR=/run/user/${_admin_uid}"
           "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${_admin_uid}/bus")

_local_digest=$("${_as_admin[@]}" podman image inspect -f '{{.Digest}}' "$DEV_CONTAINER_IMAGE" 2>/dev/null || true)
if "${_as_admin[@]}" podman pull --quiet "$DEV_CONTAINER_IMAGE" >/dev/null 2>&1; then
    _new_digest=$("${_as_admin[@]}" podman image inspect -f '{{.Digest}}' "$DEV_CONTAINER_IMAGE" 2>/dev/null || true)
    if [ "$_local_digest" = "$_new_digest" ]; then
        log_ok "${DEV_CONTAINER_NAME} image current (${_new_digest})"
    else
        log_changed "pulled ${DEV_CONTAINER_IMAGE} (${_new_digest})"
    fi
    prov_disclose "image:${DEV_CONTAINER_NAME}" "L1" "$DEV_CONTAINER_IMAGE" "CI-built; the host never builds production images"
else
    log_die "cannot pull ${DEV_CONTAINER_IMAGE}. CI publishes it from dev-container/Containerfile on merge to main; the host is otherwise converged, so re-run converge once the image is published."
fi

# Hand the generated service to the user manager. Reloading is what turns a
# newly rendered .container file into a unit, and starting it is what makes
# "a running dev container" true rather than merely declared.
"${_as_admin[@]}" systemctl --user daemon-reload 2>/dev/null || true

if "${_as_admin[@]}" systemctl --user is-active --quiet "${DEV_CONTAINER_NAME}.service" 2>/dev/null; then
    log_ok "${DEV_CONTAINER_NAME} running"
else
    "${_as_admin[@]}" systemctl --user start "${DEV_CONTAINER_NAME}.service" 2>/dev/null \
        || log_die "cannot start ${DEV_CONTAINER_NAME} — inspect: journalctl --user -u ${DEV_CONTAINER_NAME}"
    log_changed "started ${DEV_CONTAINER_NAME}"
fi
