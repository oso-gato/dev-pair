#!/usr/bin/env bash
# Unit tests for dp-session — the session-isolation enforcement (FR-WORK-1, P6).
# Drives REAL git in throwaway tmpdirs (the real execution boundary — P8), no mocks.
# Every refuse row is a mutation row: weakening the namespace check (e.g. accepting any
# branch) turns a row green and fails the suite.
#
# Run: bash dev-container/test_session.sh   (needs git; no network — clones are local)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DP_SESSION="$HERE/bin/dp-session"
[ -x "$DP_SESSION" ] || DP_SESSION="bash $DP_SESSION"

fails=0
ok()  { echo "ok: $1"; }
bad() { echo "FAIL: $1"; fails=$((fails + 1)); }

# A scratch HOME per run: session state is namespaced under it.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP/home"; mkdir -p "$HOME"

# A local "origin" to clone (real git, no network).
ORIGIN="$TMP/origin"
git init -q --bare "$ORIGIN"
seed="$TMP/seed"; git init -q "$seed"
git -C "$seed" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init
git -C "$seed" branch -M main
git -C "$seed" push -q "file://$ORIGIN" main
git -C "$ORIGIN" symbolic-ref HEAD refs/heads/main

# The pure functions, exercised through the script (sourced definitions are not
# exported; use the verbs as the interface — they ARE the production path).

# --- new: creates a namespaced tree on a session-namespaced branch ---
REPO=oso-gato/dev-pair   # the namespace name; the SOURCE is the local bare origin
out=$($DP_SESSION new alpha "$REPO" "file://$ORIGIN" 2>&1) || bad "new: clone failed — $out"
tree="$HOME/.local/share/devpair/sessions/alpha/oso-gato__dev-pair"
if [ -d "$tree/.git" ]; then
    br="$(git -C "$tree" rev-parse --abbrev-ref HEAD)"
    [ "$br" = "session/alpha/main" ] && ok "new: tree on session/alpha/main" || bad "new: branch is '$br', want session/alpha/main"
else
    bad "new: no tree created at $tree"
fi
tree="$($DP_SESSION path alpha "$REPO")"

# --- verify: the pre-commit/pre-push guard (the load-bearing check) ---
$DP_SESSION verify alpha "$tree" >/dev/null \
    && ok "verify: own tree on own branch accepted" \
    || bad "verify: own tree on own branch must be accepted"

git -C "$tree" checkout -q -b main2
if $DP_SESSION verify alpha "$tree" >/dev/null 2>&1; then
    bad "verify: branch outside session namespace must be REFUSED"
else
    ok "verify: non-namespaced branch refused"
fi
git -C "$tree" checkout -q session/alpha/main

if $DP_SESSION verify alpha "$HOME" >/dev/null 2>&1; then
    bad "verify: path outside the session namespace must be REFUSED"
else
    ok "verify: path outside namespace refused"
fi

# Another session's tree is out of scope for alpha even on a well-formed branch.
$DP_SESSION new beta "$REPO" "file://$ORIGIN" >/dev/null 2>&1
btree="$($DP_SESSION path beta "$REPO")"
if $DP_SESSION verify alpha "$btree" >/dev/null 2>&1; then
    bad "verify: another session's tree must be REFUSED for alpha"
else
    ok "verify: another session's tree refused (isolation by scope)"
fi
$DP_SESSION verify beta "$btree" >/dev/null \
    && ok "verify: beta's tree accepted for beta" \
    || bad "verify: beta's own tree must be accepted for beta"

# Traversal-shaped and hostile session names never reach the filesystem.
for s in "" ".." "../x" "a/b" "a b"; do
    if $DP_SESSION new "$s" "$REPO" "file://$ORIGIN" >/dev/null 2>&1; then
        bad "session name '$s' must be REFUSED"
    else
        ok "session name '$s' refused"
    fi
done

echo
if [ "$fails" -gt 0 ]; then
    echo "SESSION TESTS FAILED — $fails row(s)"
    exit 1
fi
echo "ALL SESSION TESTS PASS (real git, namespaced trees, mutation-refuse rows)"
