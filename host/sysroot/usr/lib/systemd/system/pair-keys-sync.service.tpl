# Runtime SSH-key re-sync from the single trust root (C6).
#
# The maintainer's published key set at github.com/<user>.keys governs who can
# log in, so rotating a key there propagates here without a reinstall and
# without a converge run. Runs as the administrative user against its own
# authorized_keys, and is failure-safe: the script never wipes existing keys on
# a failed or empty fetch.
[Unit]
Description=dev-pair authorized_keys sync from the trust root
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=@@ADMIN_USER@@
Group=@@ADMIN_USER@@
Environment=TRUST_ROOT_USER=@@TRUST_ROOT_USER@@
ExecStart=@@BIN_DIR@@/pair-keys-sync
