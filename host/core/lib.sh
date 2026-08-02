#!/usr/bin/env bash
# dev-pair host core — pure helper functions, the ONE home (P9) for logic shared by
# converge.sh and the test suite. Sourced, never executed directly. No I/O beyond the
# file each function is handed; every check is fail-closed.

# verify_tailscale_repo <file> — the pinned-fetch contract's structural check for the
# Tailscale vendor repo (P1 L2). Refuses anything missing the repo section, package OR
# repo-metadata signature enforcement, or with content addressed off the vendor's host.
# Live fact-checked against the vendor file 2026-08-03.
verify_tailscale_repo() {
    local f="$1"
    [ -f "$f" ] || return 1
    grep -q '^\[tailscale-stable\]' "$f" \
        && grep -q '^gpgcheck=1' "$f" \
        && grep -q '^repo_gpgcheck=1' "$f" \
        && grep -q '^gpgkey=https://pkgs\.tailscale\.com/' "$f" \
        && grep -q '^baseurl=https://pkgs\.tailscale\.com/' "$f"
}

# ts_bool — fleet routing-posture parser: default TRUE; only explicit 0/false/no/off is off.
ts_bool() { case "${1:-}" in 0|false|FALSE|no|off) echo false;; *) echo true;; esac; }

# dp_valid_user / dp_valid_hostname — input validation BEFORE a name reaches useradd,
# sudoers rewriting, or hostnamectl. A crafted name must never become a sudoers line
# that still passes visudo (fleet lesson).
dp_valid_user() { case "$1" in (''|*[!a-z0-9_-]*) return 1 ;; esac; return 0; }
dp_valid_hostname() {
    case "$1" in (''|-*|*-|*[!a-z0-9-]*) return 1 ;; esac
    [ "${#1}" -le 63 ] || return 1
    return 0
}
