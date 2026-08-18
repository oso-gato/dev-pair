# The pair's dev-container, as a rootless Quadlet unit.
#
# A TEMPLATE, rendered per pair by the converger: one definition serves every
# lineage, and the adapter supplies the names and ports. A second copy per pair
# would be the fork the bylaw forbids.
#
# The host builds nothing here: CI builds the production image and the host
# pulls it (00-OBJECTIVE.md, Boundaries). The host launches and relaunches this
# container from outside, and the dev-container never rebuilds itself (B4).
#
# Deliberately NO AutoUpdate=. An image that replaced itself from the registry
# would be a mutable out-of-band change to a deployed artifact, which C7
# forbids outright; renewal flows the merge-and-deploy path instead.
[Unit]
Description=@@DEV_CONTAINER_NAME@@ — the @@PAIR_NAME@@ pair's dev-container
After=network-online.target
Wants=network-online.target

[Container]
Image=@@DEV_CONTAINER_IMAGE@@
ContainerName=@@DEV_CONTAINER_NAME@@
# A stable in-container hostname. Without it podman falls back to the truncated
# container ID, which regenerates on every recreate — giving the tailnet a new
# machine name each cycle.
HostName=@@DEV_CONTAINER_NAME@@

# ── This component's own public doors (00-OBJECTIVE.md, Security 1) ──────────
# The objective names hardened SSH/MOSH on BOTH components of every pair as the
# only public doors. This component therefore publishes its own rather than
# hiding behind the host's.
#
# SSH is published on a different host port because the host's own sshd already
# holds 22 on the same public address; the container keeps 22 internally.
#
# The mosh range is mapped 1:1 and MUST stay that way: mosh-server tells the
# client which port it chose, so a rewritten port breaks the handshake. It
# starts above 61000 deliberately — mosh's default range is 60000-61000, which
# the host's own mosh uses, and an overlapping publish would collide with it.
PublishPort=@@DEV_SSH_PORT@@:22
PublishPort=@@DEV_MOSH_PORTS@@:@@DEV_MOSH_PORTS@@/udp

# ── What the nested agent box needs (docs/decisions/000029) ──────────────────
# SYS_ADMIN: `distrobox enter` calls sethostname() to name the inner box.
#   Podman's default seccomp gates that behind CAP_SYS_ADMIN and seccomp is NOT
#   namespace-aware, so without it the first box assemble dies with
#   "crun: sethostname: Operation not permitted". Deliberate — removing it
#   breaks the agent box. The full default seccomp profile stays active.
# NET_ADMIN + /dev/net/tun: tailscaled programs its own interface and firewall
#   rules, because this component is its own tailnet node (000030).
# /dev/fuse: fuse-overlayfs, the storage driver nested rootless podman uses.
#
# Bounded by the rootless user namespace, not by host root: this container is
# launched by an unprivileged user, so these capabilities are held inside that
# namespace and confer nothing on the host.
AddCapability=NET_ADMIN SYS_ADMIN
AddDevice=/dev/net/tun
AddDevice=/dev/fuse

# SELinux label separation is INTENTIONALLY OFF, and this is the one real
# security relaxation in the pair. Nested rootless podman plus fuse-overlayfs
# plus the passed devices cannot run under container_t confinement — SELinux
# denies the overlay mount and the device access — so the agent box does not
# assemble with it on. Reviewed trade-off, not an oversight to harden away:
# the blast radius is bounded by rootless execution and the user namespace, and
# the HOST stays enforcing throughout. See docs/decisions/000029 before
# changing this, and do not copy it to another workload without the same
# analysis.
SecurityLabelDisable=true

# ── Durable state, all of it outside the layer (C8) ──────────────────────────
Volume=%h/dev-pair/work:/work:Z
# The component's own App identity — the one that carries merge permission,
# which the host's does not. Read-only, never baked into the image.
Volume=%h/.dev-pair/secrets/@@DEV_CONTAINER_NAME@@-github-app:/run/secrets/github-app:ro,Z
# The tailnet auth key, read once at join. Read-only; the joined state below is
# what persists, so the key is not needed again.
Volume=%h/.dev-pair/secrets/@@DEV_CONTAINER_NAME@@-tailscale:/run/secrets/tailscale:ro,Z
# sshd host keys, so a relaunch does not trip every client's host-key check.
Volume=%h/.dev-pair/@@DEV_CONTAINER_NAME@@-sshd-keys:/etc/ssh/keys:Z
# Tailnet state, so a relaunch rejoins as the same node rather than burning a
# fresh machine entry each restart.
Volume=%h/.dev-pair/@@DEV_CONTAINER_NAME@@-tailscale-state:/var/lib/tailscale:Z

Environment=PAIR_APP_DIR=/run/secrets/github-app
Environment=PAIR_TOKEN_PATH=/run/dev-pair/gh-token
Environment=PAIR_TSKEY_PATH=/run/secrets/tailscale/authkey
Environment=PAIR_NAME=@@PAIR_NAME@@
Environment=DEV_CONTAINER_NAME=@@DEV_CONTAINER_NAME@@
Environment=TAILNET_HOSTNAME=@@DEV_TAILNET_HOSTNAME@@
Environment=TRUST_ROOT_USER=@@TRUST_ROOT_USER@@
Timezone=local

[Service]
Restart=always
TimeoutStartSec=900

[Install]
WantedBy=default.target
