#!/usr/bin/env bash
# 70-dev-container — the pair's dev-container, launched by the host from outside.
#
# Two boundaries meet here and both are the objective's own. Neither component
# builds production images, so the host PULLS what CI built and never builds it
# locally. And the dev-container never rebuilds itself — launching it is the
# host's own act from outside, which is why this unit lives on the host and has
# no counterpart inside the container.
#
# What this unit does NOT do is relaunch it. It pulls the image and starts the
# service only when the service is not already running, so a pull that brings a
# new digest leaves the old container running and says so and nothing more.
# This header claimed the relaunch for a while, and a document asserting
# behaviour the code does not have is the stale map C1 makes a blocking
# finding, so it now states what the code does. Renewal proper is a separate
# ticket, for the reasons the drift warning below gives.
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

# Everything below reaches the administrative user's own manager through that
# runtime directory, and on a first apply it is not necessarily there yet:
# 40-podman enables linger earlier in this same run, and systemd starts the
# user manager asynchronously afterwards. Racing it makes this unit die on the
# first converge of a fresh host and succeed on the second, which is a
# converger that is not re-run-safe in the direction that matters.
#
# So wait for the manager to answer, and bound the wait. An unbounded wait
# would turn a linger that never took into an apply that hangs with no operator
# near it, and a bound that fails without saying why is the gate with no
# recovery C11 forbids — hence the reason and the next step in the message.
#
# The probe is a round trip any live manager satisfies rather than
# `is-system-running`, which reports failure for a merely degraded manager that
# would nonetheless run the container perfectly well.
_admin_bus="/run/user/${_admin_uid}/bus"
_bus_wait=60
_waited=0
_manager_ready=0
while [ "$_waited" -le "$_bus_wait" ]; do
    if [ -S "$_admin_bus" ] \
       && "${_as_admin[@]}" systemctl --user show --property=Version >/dev/null 2>&1; then
        _manager_ready=1
        break
    fi
    sleep 1
    _waited=$((_waited + 1))
done

if [ "$_manager_ready" = 0 ]; then
    log_die "the user manager for ${ADMIN_USER} did not answer within ${_bus_wait}s, and ${_admin_bus} is what every step below needs. Linger is enabled by 40-podman in this same run, so check it with 'loginctl show-user ${ADMIN_USER} -p Linger' and 'systemctl status user@${_admin_uid}.service', then re-run converge."
elif [ "$_waited" -gt 0 ]; then
    log_ok "user manager for ${ADMIN_USER} answered after ${_waited}s"
fi

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

    # A pull that brought a new digest does not replace what is already
    # running, and this is where that difference becomes visible instead of
    # silent. Report it, name both digests so the operator can see which is
    # which, and stop there.
    #
    # Restarting here would destroy every live session and everything in the
    # container's own /home/core, which the Quadlet does not put on a volume —
    # and B4's renewal is precisely the promise that the session set comes
    # back, so a restart that cannot restore it breaks the rule it appears to
    # serve. It would also be AutoUpdate=registry reimplemented in shell, which
    # the Quadlet template refuses outright on C7 grounds: a deployed artifact
    # does not replace itself out of band. Real renewal — put the home on a
    # volume, capture the live session set, replace the container, restore the
    # sessions onto it — is a separate ticket, and that home volume and that
    # capture-and-restore step are the work it has to do.
    _running_digest=$("${_as_admin[@]}" podman container inspect \
                      -f '{{.ImageDigest}}' "$DEV_CONTAINER_NAME" 2>/dev/null || true)
    if [ -n "$_running_digest" ] && [ "$_running_digest" != "$_new_digest" ]; then
        log_warn "${DEV_CONTAINER_NAME} is running an image the pull has moved past — running ${_running_digest}, pulled ${_new_digest}. Nothing was restarted on purpose: the restart would take the live sessions and the container's /home/core with it, and renewal that restores them (B4) is a separate ticket."
    fi
else
    "${_as_admin[@]}" systemctl --user start "${DEV_CONTAINER_NAME}.service" 2>/dev/null \
        || log_die "cannot start ${DEV_CONTAINER_NAME} — inspect: journalctl --user -u ${DEV_CONTAINER_NAME}"
    log_changed "started ${DEV_CONTAINER_NAME}"
fi
