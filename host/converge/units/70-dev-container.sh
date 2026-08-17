#!/usr/bin/env bash
# 70-dev-container — nox, launched by the host from outside.
#
# Two boundaries meet here and both are the objective's own. Neither component
# builds production images, so the host PULLS what CI built and never builds it
# locally. And the dev-container never rebuilds itself — the host launches and
# relaunches it from outside (B4), which is why this unit lives on the host and
# has no counterpart inside nox.
#
# Sourced by converge.sh.

log_unit "dev-container"

NOX_IMAGE="ghcr.io/oso-gato/${DEV_CONTAINER_NAME}:44"

# The Quadlet definition, in the all-users rootless path so the administrative
# user's manager generates a service from it at boot.
fs_install "$REPO_ROOT/host/sysroot/etc/containers/systemd/users/nox.container" \
           "/etc/containers/systemd/users/${DEV_CONTAINER_NAME}.container" 0644
fs_install "$REPO_ROOT/host/sysroot/usr/bin/nox" /usr/bin/nox 0755

# Pull what CI built. An image already present at the same digest is not pulled
# again, so a converged host reports no change here.
_local_digest=$(runuser -u "$ADMIN_USER" -- podman image inspect -f '{{.Digest}}' "$NOX_IMAGE" 2>/dev/null || true)
if runuser -u "$ADMIN_USER" -- podman pull --quiet "$NOX_IMAGE" >/dev/null 2>&1; then
    _new_digest=$(runuser -u "$ADMIN_USER" -- podman image inspect -f '{{.Digest}}' "$NOX_IMAGE" 2>/dev/null || true)
    if [ "$_local_digest" = "$_new_digest" ]; then
        log_ok "${DEV_CONTAINER_NAME} image current (${_new_digest})"
    else
        log_changed "pulled ${NOX_IMAGE} (${_new_digest})"
    fi
    prov_disclose "image:${DEV_CONTAINER_NAME}" "L1" "$NOX_IMAGE" "CI-built; the host never builds production images"
else
    log_die "cannot pull ${NOX_IMAGE}. CI publishes it from dev-container/Containerfile on merge to main; the host is otherwise converged, so re-run converge once the image is published."
fi

# Hand the generated service to the user manager. Reloading is what turns a
# newly installed .container file into a unit, and starting it is what makes
# acceptance 1's "a running dev container" true rather than merely declared.
runuser -u "$ADMIN_USER" -- env "XDG_RUNTIME_DIR=/run/user/$(id -u "$ADMIN_USER")" \
    systemctl --user daemon-reload 2>/dev/null || true

if runuser -u "$ADMIN_USER" -- env "XDG_RUNTIME_DIR=/run/user/$(id -u "$ADMIN_USER")" \
        systemctl --user is-active --quiet "${DEV_CONTAINER_NAME}.service" 2>/dev/null; then
    log_ok "${DEV_CONTAINER_NAME} running"
else
    runuser -u "$ADMIN_USER" -- env "XDG_RUNTIME_DIR=/run/user/$(id -u "$ADMIN_USER")" \
        systemctl --user start "${DEV_CONTAINER_NAME}.service" 2>/dev/null \
        || log_die "cannot start ${DEV_CONTAINER_NAME} — inspect: journalctl --user -u ${DEV_CONTAINER_NAME}"
    log_changed "started ${DEV_CONTAINER_NAME}"
fi
