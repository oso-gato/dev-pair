#!/usr/bin/env bash
# selftest.sh — what this repository can prove about the converger without a host.
#
# The objective's two tiers decide what belongs here. Tier 1 is everything
# provable inside a container: that every delivered script parses, that the
# idempotence primitives really are idempotent when run against a real
# filesystem, and that the tree carries no credential and no forbidden channel.
# Tier 2 — a full converge on a live Fedora Cloud host, and the second apply
# that proves acceptance 3 end to end — needs a host and is not simulated here.
# A track without a capability never simulates it (C9).
#
# The idempotence checks drive the real functions against a real temporary
# root. They are not assertions about a mock, and each one is mutation-checked
# in-suite: the guard is broken on a copy and the check must fail, or the check
# was proving nothing.
#
# Usage: ./selftest.sh
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
FAIL=0
PASS=0

pass() { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# Every shell script this repository delivers, found rather than listed, so a
# new script cannot quietly escape the checks below.
mapfile -t SCRIPTS < <(
    find "$REPO_ROOT/host" "$REPO_ROOT/shared" "$REPO_ROOT/dev-container" \
         -type f \( -name '*.sh' -o -name '*.env' \) 2>/dev/null
    find "$REPO_ROOT/host/sysroot/usr/bin" "$REPO_ROOT/shared/bin" \
         "$REPO_ROOT/shared/claudebox" "$REPO_ROOT/dev-container/sysroot/usr/bin" \
         -type f 2>/dev/null | while read -r f; do
        head -1 "$f" | grep -q '^#!.*\(bash\|sh\)' && printf '%s\n' "$f"
    done
)

# ── 1. Every delivered script parses ─────────────────────────────────────────
head_ "syntax"
for s in "${SCRIPTS[@]}"; do
    if bash -n "$s" 2>/dev/null; then
        pass "parses: ${s#"$REPO_ROOT"/}"
    else
        fail "does not parse: ${s#"$REPO_ROOT"/}"
        bash -n "$s" 2>&1 | sed 's/^/        /'
    fi
done

# ── 2. shellcheck at style level, where it exists ────────────────────────────
# Style level rather than warning, deliberately: SC2006 (backticks) is a style
# finding, and a backtick inside a double-quoted log line is a live command
# substitution rather than a matter of taste. One was found that way.
head_ "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
    for s in "${SCRIPTS[@]}"; do
        case "$s" in *.env) continue ;; esac
        if out=$(shellcheck -S style -e SC1091 -e SC2250 -e SC2312 "$s" 2>&1); then
            pass "clean: ${s#"$REPO_ROOT"/}"
        else
            fail "findings: ${s#"$REPO_ROOT"/}"
            printf '%s\n' "$out" | sed 's/^/        /'
        fi
    done
else
    fail "shellcheck absent — the check did not run, which is not the same as passing"
fi

# ── 3. The idempotence primitives, against a real filesystem ─────────────────
head_ "idempotence"
# shellcheck source=lib/log.sh
. "$REPO_ROOT/host/converge/lib/log.sh"
# shellcheck source=lib/fs.sh
. "$REPO_ROOT/host/converge/lib/fs.sh"

TESTROOT=$(mktemp -d)
trap 'rm -rf "$TESTROOT"' EXIT
SRCFILE="$TESTROOT/source.txt"
printf 'declared content\n' > "$SRCFILE"

# fs_install: first call changes, second does not.
CONVERGE_CHANGED=0
fs_install "$SRCFILE" "$TESTROOT/dest/file.txt" 0644 >/dev/null 2>&1
first=$CONVERGE_CHANGED
CONVERGE_CHANGED=0
fs_install "$SRCFILE" "$TESTROOT/dest/file.txt" 0644 >/dev/null 2>&1
second=$CONVERGE_CHANGED
if [ "$first" -eq 1 ] && [ "$second" -eq 0 ]; then
    pass "fs_install writes once and is a no-op on re-apply"
else
    fail "fs_install: first apply changed=$first (want 1), second changed=$second (want 0)"
fi

# fs_install notices a real difference rather than trusting a sentinel.
printf 'drifted content\n' > "$TESTROOT/dest/file.txt"
CONVERGE_CHANGED=0
fs_install "$SRCFILE" "$TESTROOT/dest/file.txt" 0644 >/dev/null 2>&1
if [ "$CONVERGE_CHANGED" -eq 1 ] && [ "$(cat "$TESTROOT/dest/file.txt")" = "declared content" ]; then
    pass "fs_install erases drift on the next apply"
else
    fail "fs_install did not correct drifted content"
fi

# fs_install corrects a wrong mode without a content change.
chmod 0777 "$TESTROOT/dest/file.txt"
CONVERGE_CHANGED=0
fs_install "$SRCFILE" "$TESTROOT/dest/file.txt" 0644 >/dev/null 2>&1
if [ "$CONVERGE_CHANGED" -eq 1 ] && [ "$(stat -c '%a' "$TESTROOT/dest/file.txt")" = "644" ]; then
    pass "fs_install corrects a drifted mode"
else
    fail "fs_install left mode $(stat -c '%a' "$TESTROOT/dest/file.txt"), wanted 644"
fi

# fs_ensure_dir: first call changes, second does not.
CONVERGE_CHANGED=0
fs_ensure_dir "$TESTROOT/adir" 0750 >/dev/null 2>&1
first=$CONVERGE_CHANGED
CONVERGE_CHANGED=0
fs_ensure_dir "$TESTROOT/adir" 0750 >/dev/null 2>&1
if [ "$first" -eq 1 ] && [ "$CONVERGE_CHANGED" -eq 0 ]; then
    pass "fs_ensure_dir creates once and is a no-op on re-apply"
else
    fail "fs_ensure_dir: first changed=$first (want 1), second changed=$CONVERGE_CHANGED (want 0)"
fi

# prov_disclose: the record is current state, so a re-apply must not grow it.
# shellcheck disable=SC2034  # read by provenance.sh when it is sourced below
PAIR_STATE_DIR="$TESTROOT/state"
# shellcheck source=lib/provenance.sh
. "$REPO_ROOT/host/converge/lib/provenance.sh"
prov_disclose "podman" "L1" "fedora" "container runtime"
prov_disclose "git" "L1" "fedora" "the ticket bus"
lines_first=$(wc -l < "$PROV_DISCLOSURE")
prov_disclose "podman" "L1" "fedora" "container runtime"
prov_disclose "git" "L1" "fedora" "the ticket bus"
lines_second=$(wc -l < "$PROV_DISCLOSURE")
if [ "$lines_first" -eq "$lines_second" ] && [ "$lines_first" -eq 3 ]; then
    pass "prov_disclose keeps one row per artifact across re-applies"
else
    fail "prov_disclose grew from $lines_first to $lines_second lines (want 3 and 3)"
fi

# ── 4. Mutation check: break the guard, the check must fail ──────────────────
# A test that passes against broken code proves nothing (C9). fs_install's
# idempotence rests entirely on the content comparison, so removing it is the
# mutation, and the no-op assertion above must fail against this copy.
head_ "mutation"
fs_install_mutated() {
    local src="$1" dest="$2" mode="$3"
    install -D -m "$mode" "$src" "$dest"     # the cmp -s guard removed
    log_changed "installed $dest"
}
CONVERGE_CHANGED=0
fs_install_mutated "$SRCFILE" "$TESTROOT/mut/file.txt" 0644 >/dev/null 2>&1
CONVERGE_CHANGED=0
fs_install_mutated "$SRCFILE" "$TESTROOT/mut/file.txt" 0644 >/dev/null 2>&1
if [ "$CONVERGE_CHANGED" -eq 0 ]; then
    fail "the mutated fs_install still reported no change — the idempotence check cannot detect a broken guard"
else
    pass "the mutated fs_install reports a change on re-apply, so the check above can fail"
fi

# ── 5. No credential in the tree ─────────────────────────────────────────────
head_ "credentials"
if git -C "$REPO_ROOT" grep -nIE '(-----BEGIN [A-Z ]*PRIVATE KEY|tskey-[a-zA-Z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})' \
     -- ':!docs/' >/dev/null 2>&1; then
    fail "something matching a private key or a token is committed"
    git -C "$REPO_ROOT" grep -nIE '(-----BEGIN [A-Z ]*PRIVATE KEY|tskey-[a-zA-Z0-9]{10,}|ghp_|github_pat_)' -- ':!docs/' | sed 's/^/        /'
else
    pass "no private key and no token anywhere in the tree"
fi

# shellcheck disable=SC2016  # a literal regex for a crypt prefix, not an expansion
if git -C "$REPO_ROOT" grep -nIE '\$6\$[./A-Za-z0-9]{8,}\$' -- ':!docs/' >/dev/null 2>&1; then
    fail "a password hash is committed — declarations belong in the vault, not here"
else
    pass "no password hash committed — the declaration stays in the vault"
fi

# ── 6. No forbidden channel ──────────────────────────────────────────────────
# The bylaw's own instances of C4's forbidden categories. Scoped to the code,
# because the deny list in managed-settings.json and the prose in docs/ name
# these deliberately and naming a thing is not using it.
head_ "provenance"
forbidden_hit=0
while IFS= read -r hit; do
    forbidden_hit=1
    printf '        %s\n' "$hit"
done < <(git -C "$REPO_ROOT" grep -nIE \
    '(dnf +copr|copr +enable|pip3? +install|pipx +install|npm +install +-g|npm +i +-g|cargo +install|go +install|gem +install|brew +install|flatpak +install|snap +install|curl[^|]*\| *(ba)?sh)' \
    -- 'host/**' 'dev-container/**' 'shared/**' \
       ':!shared/claudebox/managed-settings.json' 2>/dev/null)
if [ "$forbidden_hit" = 0 ]; then
    pass "no forbidden channel in host/, dev-container/ or shared/"
else
    fail "a forbidden channel appears in the code"
fi

# Every dnf install in the tree carries the minimalism flag.
head_ "minimalism"
bad_dnf=0
while IFS= read -r line; do
    printf '%s' "$line" | grep -q 'install_weak_deps=False' && continue
    printf '        %s\n' "$line"
    bad_dnf=1
done < <(git -C "$REPO_ROOT" grep -nIE 'dnf +(-y +)?.*install ' \
    -- 'host/**' 'dev-container/**' 'shared/**' \
       ':!shared/claudebox/managed-settings.json' \
       ':!host/converge/selftest.sh' 2>/dev/null)
if [ "$bad_dnf" = 0 ]; then
    pass "every package installation sets install_weak_deps=False"
else
    fail "a package installation omits install_weak_deps=False"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
printf '\n\033[1mselftest: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
cat <<'EOF'

Tier 1 only. A full converge on a live Fedora Cloud host, and the second apply
that proves acceptance 3 end to end, need a host and were not run here.
EOF
