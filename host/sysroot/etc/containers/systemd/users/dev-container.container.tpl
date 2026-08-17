# The pair's dev-container, as a rootless Quadlet unit.
#
# A TEMPLATE, rendered per pair by the converger: one definition serves every
# lineage, and the adapter supplies the names. A second copy per pair would be
# the fork the bylaw forbids, and the differences between pairs are facts, not
# structure.
#
# The host builds nothing here: CI builds the production image and the host
# pulls it (00-OBJECTIVE.md, Boundaries). The host launches and relaunches this
# container from outside, and the dev-container never rebuilds itself (B4).
#
# Deliberately NO AutoUpdate=. An image that replaced itself from the registry
# would be a mutable out-of-band change to a deployed artifact, which C7
# forbids outright; renewal flows the merge-and-deploy path instead.
#
# Rootless, under the administrative user, so the container holds the minimal
# authority its capability requires (C6).
[Unit]
Description=@@DEV_CONTAINER_NAME@@ — the @@PAIR_NAME@@ pair's dev-container
After=network-online.target
Wants=network-online.target

[Container]
Image=@@DEV_CONTAINER_IMAGE@@
ContainerName=@@DEV_CONTAINER_NAME@@
# Durable state lives outside every layer (C8), so a relaunch loses no work.
Volume=%h/dev-pair/work:/work:Z
# The dev-container's own App identity — separate from the host's, and the one
# that carries merge permission. Read-only, and never baked into the image.
Volume=%h/.dev-pair/secrets/@@DEV_CONTAINER_NAME@@-github-app:/run/secrets/github-app:ro,Z
Environment=PAIR_APP_DIR=/run/secrets/github-app
Environment=PAIR_TOKEN_PATH=/run/dev-pair/gh-token
Environment=PAIR_NAME=@@PAIR_NAME@@
Environment=DEV_CONTAINER_NAME=@@DEV_CONTAINER_NAME@@
# No published ports: the dev-container is reachable over the tailnet through
# the host, never from the public internet (00-OBJECTIVE.md, Security 1).
Timezone=local

[Service]
Restart=always
TimeoutStartSec=900

[Install]
WantedBy=default.target
