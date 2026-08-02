#!/usr/bin/env bash
# dev-pair — publish Cockpit on the tailnet, and make Cockpit work behind that proxy.
# Fleet-proven, carried verbatim. Run by cockpit-tailnet-serve.service (installed to
# /usr/local/sbin by converge.sh).
#
# ONE attempt per run — the systemd MANAGER owns the retry, not a bash sleep-loop
# (Restart=on-failure + RestartSec=60s + StartLimitIntervalSec=0 on the unit). A clean
# exit 0 stops the retry on first success; serve config persists in tailscaled.
#
# Two halves, BOTH required for genuinely-tailnet-only Cockpit (cockpit.socket is
# loopback-bound by converge.sh, so this proxy is the only ingress):
#   1. `tailscale serve` publishes https://<node>.<tailnet>.ts.net/ -> http://127.0.0.1:9090,
#      TLS-terminated at the tailnet edge. It fails until the tailnet has MagicDNS + HTTPS
#      Certificates enabled (admin console: DNS > MagicDNS, then HTTPS Certificates).
#   2. cockpit-ws behind that proxy would reject the login WebSocket as cross-origin, so
#      the node's MagicDNS origin is allow-listed in /etc/cockpit/cockpit.conf — knowable
#      only once the node is up and named, which is exactly here.
set -euo pipefail

if ! timeout 20 tailscale serve --bg --https=443 http://127.0.0.1:9090; then
    echo "cockpit-serve: tailnet not ready — enable MagicDNS + HTTPS Certificates in the admin console; exiting non-zero so systemd retries" >&2
    exit 1
fi

fqdn="$(tailscale status --json 2>/dev/null \
        | python3 -c 'import sys,json; print((json.load(sys.stdin).get("Self") or {}).get("DNSName","").rstrip("."))' 2>/dev/null || true)"
if [ -n "$fqdn" ]; then
    # AllowUnencrypted=true is SAFE here: the bind is loopback-only, traffic is encrypted
    # edge-to-edge by Tailscale (WireGuard) and TLS-terminated at the node — no plaintext
    # byte leaves the host. Origins is the load-bearing line.
    install -D -m0644 /dev/stdin /etc/cockpit/cockpit.conf <<EOF
[WebService]
Origins = https://${fqdn} wss://${fqdn}
ProtocolHeader = X-Forwarded-Proto
AllowUnencrypted = true
EOF
    systemctl try-restart cockpit || true
    echo "cockpit-serve: published at https://${fqdn}/ (Origins set; cockpit restarted)"
else
    echo "cockpit-serve: serve applied, but could not resolve the node's MagicDNS name — is MagicDNS enabled on the tailnet?" >&2
fi
