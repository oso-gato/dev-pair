#!/usr/bin/env bash
# Unit tests for host/core/lib.sh — the converger's pure decision functions.
# Every refuse row is a mutation row (P8): it proves the check binds — weakening the
# function (e.g. dropping the repo_gpgcheck requirement) turns a row green and fails
# the suite. Drives the real functions, no mocks.
#
# Run: bash host/core/test_lib.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

fails=0
ok()  { echo "ok: $1"; }
bad() { echo "FAIL: $1"; fails=$((fails + 1)); }

expect_true()  { if "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1 — expected ACCEPT, got refuse"; fi; }
expect_false() { if "$2" "$3" 2>/dev/null; then bad "$1 — expected REFUSE, got accept"; else ok "$1"; fi; }

# ---- verify_tailscale_repo: the genuine vendor content (live fact-check 2026-08-03) ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
GOOD="$tmp/good.repo"
cat > "$GOOD" <<'EOF'
[tailscale-stable]
name=Tailscale stable
baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch
enabled=1
type=rpm
repo_gpgcheck=1
gpgcheck=1
gpgkey=https://pkgs.tailscale.com/stable/fedora/repo.gpg
EOF

expect_true  "vendor repo content accepted" verify_tailscale_repo "$GOOD"

# Mutation rows — each breaks exactly one requirement of the pinned-fetch contract (P1).
mut() { # <name> <sed-expr> — write a mutated copy of GOOD
    local out="$tmp/$1.repo"
    sed "$2" "$GOOD" > "$out"
    printf '%s' "$out"
}
expect_false "missing repo section refused"      verify_tailscale_repo "$(mut nosection 's/^\[tailscale-stable\]/[other]/')"
expect_false "gpgcheck=0 refused"                verify_tailscale_repo "$(mut nogpg 's/^gpgcheck=1/gpgcheck=0/')"
expect_false "repo_gpgcheck dropped refused"     verify_tailscale_repo "$(mut norepogpg '/^repo_gpgcheck=1/d')"
expect_false "key off vendor host refused"       verify_tailscale_repo "$(mut evilkey 's|^gpgkey=https://pkgs\.tailscale\.com/|gpgkey=https://evil.tld/|')"
expect_false "baseurl off vendor host refused"   verify_tailscale_repo "$(mut evilurl 's|^baseurl=https://pkgs\.tailscale\.com/|baseurl=https://mirror.evil.tld/|')"
expect_false "missing file refused"              verify_tailscale_repo "$tmp/does-not-exist.repo"

# ---- ts_bool: default-true, explicit-off only -------------------------------------------
[ "$(ts_bool '')"    = true ]  && ok "ts_bool: unset defaults true"  || bad "ts_bool: unset should default true"
[ "$(ts_bool 1)"     = true ]  && ok "ts_bool: 1 is true"            || bad "ts_bool: 1 should be true"
[ "$(ts_bool 0)"     = false ] && ok "ts_bool: 0 is false"           || bad "ts_bool: 0 should be false"
[ "$(ts_bool off)"   = false ] && ok "ts_bool: off is false"         || bad "ts_bool: off should be false"
[ "$(ts_bool FALSE)" = false ] && ok "ts_bool: FALSE is false"       || bad "ts_bool: FALSE should be false"
[ "$(ts_bool yes)"   = true ]  && ok "ts_bool: yes is true"          || bad "ts_bool: yes should be true"

# ---- dp_valid_user / dp_valid_hostname: injection-shaped names refused -------------------
expect_true  "plain user accepted"            dp_valid_user "core"
expect_true  "user with dash/underscore ok"   dp_valid_user "ops-user_1"
expect_false "empty user refused"             dp_valid_user ""
expect_false "sudoers-injection refused"      dp_valid_user "core ALL=(ALL) NOPASSWD:ALL"
expect_false "uppercase user refused"         dp_valid_user "Core"
expect_true  "plain hostname accepted"        dp_valid_hostname "box"
expect_true  "hyphenated hostname accepted"   dp_valid_hostname "dev-pair-1"
expect_false "empty hostname refused"         dp_valid_hostname ""
expect_false "leading hyphen refused"         dp_valid_hostname "-box"
expect_false "trailing hyphen refused"        dp_valid_hostname "box-"
expect_false "dot in hostname refused"        dp_valid_hostname "box.example"
expect_false "overlong hostname refused"      dp_valid_hostname "$(printf 'a%.0s' $(seq 1 64))"

echo
if [ "$fails" -gt 0 ]; then
    echo "LIB TESTS FAILED — $fails row(s)"
    exit 1
fi
echo "ALL LIB TESTS PASS (accept + mutation-refuse rows)"
