#!/usr/bin/env bash
# dev-pair — the converge verb's live test: run the REAL converger twice inside a real
# Fedora 44 systemd container, then run the REAL validate. No mocks: dnf installs the
# genuine package set, systemctl starts the genuine units, sshd -t validates the genuine
# drop-in (P8 — the suite must drive the execution boundary, and a re-run must be a
# no-op, proving idempotency).
#
# What this proves: converge.sh applies cleanly from scratch on Fedora 44, is
# re-run-safe, and leaves a host whose live state passes validate.sh's read-back.
# What it cannot prove (recorded, P3 honesty): the tailnet join (no auth in a test),
# the SELinux relabel path (no SELinux in a container), and multi-client tmux geometry —
# those activate on first VPS genesis and are changelog-recorded there.
#
# Run: bash host/core/test_converge_container.sh   (needs podman)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
IMG=localhost/devpair-test-systemd:44
NAME=devpair-converge-test

echo "== building the systemd test harness image (fedora:44 + systemd) =="
podman build -q -t "$IMG" -f "$HERE/test/Containerfile.systemd" "$HERE/test" >/dev/null

podman rm -f "$NAME" >/dev/null 2>&1 || true
echo "== starting the throwaway Fedora 44 systemd container =="
podman run -d --name "$NAME" --systemd=always --privileged \
    -v "$REPO_ROOT:/repo:ro" "$IMG" >/dev/null
trap 'podman rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
    state="$(podman exec "$NAME" systemctl is-system-running 2>/dev/null || true)"
    case "$state" in running|degraded) break ;; esac
    sleep 2
done
echo ">> systemd state: ${state:-unknown}"

# podman bind-mounts /etc/hostname into every container, and systemd-hostnamed cannot
# rewrite a mount point (EBUSY) — a container artifact, not a converger defect. Unmount
# it (privileged) to reveal the image's regular file so the REAL hostnamectl path runs,
# exactly as it will on any real image. /etc/hosts and resolv.conf stay: the converger
# never touches them (nss-myhostname resolves the local name).
podman exec "$NAME" umount /etc/hostname

echo "== CONVERGE run 1 (from scratch) =="
podman exec "$NAME" bash -c 'bash /repo/host/core/converge.sh < /dev/null'

echo "== CONVERGE run 2 (idempotency: re-run from the converged state must be a no-op-safe apply) =="
podman exec "$NAME" bash -c 'bash /repo/host/core/converge.sh < /dev/null'

echo "== VALIDATE (live read-back) =="
podman exec "$NAME" bash /repo/host/core/validate.sh

echo "== CONTAINER TEST PASS =="
