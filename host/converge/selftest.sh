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

# ── 4. Mutation checks: break the guard, the check must fail ─────────────────
# C9 asks for the pre-fix behaviour RESTORED ON A COPY, and the guard's test
# must then fail. An earlier version of this section hand-wrote a stand-in that
# called log_changed unconditionally, so its assertion was true by construction
# and could not have detected a broken guard — the "test asserting what a mock
# was told" the constitution names, inside the mechanism built to prevent it.
# These mutate the REAL functions' own source instead.
head_ "mutation"

# fs_install's idempotence rests entirely on the content comparison. Take the
# live function's source, delete that comparison, and the no-op assertion above
# must fail against the result.
# shellcheck disable=SC2016  # sed patterns match the function's literal text
eval "$(declare -f fs_install | sed \
    -e 's/^fs_install ()/fs_install_mutant ()/' \
    -e 's/if \[ ! -f "\$dest" \] || ! cmp -s "\$src" "\$dest"; then/if true; then/')"
if declare -f fs_install_mutant >/dev/null 2>&1 \
   && ! declare -f fs_install_mutant | grep -q 'cmp -s'; then
    CONVERGE_CHANGED=0
    fs_install_mutant "$SRCFILE" "$TESTROOT/mut/file.txt" 0644 >/dev/null 2>&1
    CONVERGE_CHANGED=0
    fs_install_mutant "$SRCFILE" "$TESTROOT/mut/file.txt" 0644 >/dev/null 2>&1
    if [ "$CONVERGE_CHANGED" -eq 0 ]; then
        fail "fs_install with its comparison removed still reported no change — the idempotence check cannot detect a broken guard"
    else
        pass "fs_install mutated (comparison removed) reports a change on re-apply, so the check above can fail"
    fi
else
    fail "could not build the fs_install mutant — the mutation check did not run, which is not the same as passing"
fi

# prov_sha256 must yield a BARE hash. The pre-fix source used an awk program
# whose nested quoting yielded "<hash>  <path>", which parsed cleanly and made
# every checksum comparison fail closed on a correct file. Restore that form on
# a copy and require the check to catch it.
KNOWNFILE="$TESTROOT/known.txt"
printf 'provenance probe\n' > "$KNOWNFILE"
EXPECTED=$(sha256sum "$KNOWNFILE" | cut -d' ' -f1)
if [ "$(prov_sha256 "$KNOWNFILE")" = "$EXPECTED" ]; then
    pass "prov_sha256 returns a bare hash, so a checksum comparison can match"
else
    fail "prov_sha256 returned [$(prov_sha256 "$KNOWNFILE")], wanted the bare hash [$EXPECTED]"
fi
# shellcheck disable=SC2016  # the mutant reproduces the defective awk program verbatim
prov_sha256_mutant() { sha256sum "$1" | awk '"'"'{print $1}'"'"'; }
if [ "$(prov_sha256_mutant "$KNOWNFILE")" = "$EXPECTED" ]; then
    fail "the defective checksum form still returned a bare hash — this check cannot detect the defect it exists for"
else
    pass "the defective checksum form is caught, so the check above can fail"
fi

# ── 4b. The published door has to reach a listening port ─────────────────────
# A bounded, closed question over two declared artifacts, which is what C3
# admits as a mechanical check. It exists because the two disagreed: the
# Quadlet published the host port onto container 22 while the container's sshd
# bound 2222, so the dev-container's public door opened onto nothing.
head_ "doors"
_tpl="$REPO_ROOT/host/sysroot/etc/containers/systemd/users/dev-container.container.tpl"
_sshd="$REPO_ROOT/dev-container/sysroot/etc/ssh/sshd_config.d/40-dev-pair.conf"
_published=$(grep -oE '^PublishPort=@@DEV_SSH_PORT@@:[0-9]+' "$_tpl" | cut -d: -f2)
_listening=$(grep -oE '^Port[[:space:]]+[0-9]+' "$_sshd" | grep -oE '[0-9]+')
if [ -n "$_published" ] && [ "$_published" = "$_listening" ]; then
    pass "the dev-container publishes to ${_published} and its sshd listens on ${_listening}"
else
    fail "the dev-container publishes to container port [${_published}] but its sshd listens on [${_listening}] — the public door opens onto nothing"
fi

# ── 4c. Every shared box file reaches both components ────────────────────────
# The dev-container image copies shared/claudebox/ wholesale; the host unit
# names each file. That asymmetry means a file added to the directory arrives
# in the container and is silently absent on the host, where claudebox-init.sh
# would then fail mid-rebuild on a path that exists everywhere it was tested.
# It happened the first time a file was added. Bounded and closed, so it is a
# check rather than a paragraph.
head_ "shared box"
missing_shared=0
for f in "$REPO_ROOT"/shared/claudebox/*; do
    base=$(basename "$f")
    grep -q "shared/claudebox/${base}" "$REPO_ROOT/host/converge/units/60-agentbox.sh" && continue
    printf '        %s is not installed by 60-agentbox.sh\n' "$base"
    missing_shared=1
done
if [ "$missing_shared" = 0 ]; then
    pass "every file in shared/claudebox/ is installed on the host as well as in the image"
else
    fail "a shared box file reaches the dev-container image but never the host"
fi

# ── 4d. A failed vault fetch must not destroy the incumbent ──────────────────
# The real vault_get from day-zero.sh, driven against a real file with a real
# filesystem. Only the network is stubbed, because the boundary under test is
# write ordering, not HTTP: the defective form opened the destination for
# writing before gh ran, so a failed fetch truncated a working App key and left
# a zero-byte file that 50-github-app then reported as present.
head_ "vault"
_extract_fn() {
    awk -v fn="$1" '$0 ~ "^"fn"\\(\\) \\{" {p=1} p {print} p && $0 == "}" {exit}' "$2"
}

VAULTDIR="$TESTROOT/vault"; mkdir -p "$VAULTDIR"
# The markers are assembled rather than written literally: this suite's own
# credential guard scans the tree for exactly that string, and a fixture is not
# an exception worth carving into the guard.
_incumbent() {
    printf -- '-----BEGIN %s KEY-----\nINCUMBENT\n-----END %s KEY-----\n' \
        PRIVATE PRIVATE > "$VAULTDIR/private-key.pem"
}
_incumbent
VAULT_BEFORE=$(sha256sum "$VAULTDIR/private-key.pem" | cut -d' ' -f1)

# A gh that always fails, ahead of any real one on PATH.
mkdir -p "$TESTROOT/failbin"
printf '#!/bin/sh\necho "HTTP 503: the vault is unreachable" >&2\nexit 1\n' > "$TESTROOT/failbin/gh"
chmod 0755 "$TESTROOT/failbin/gh"

# shellcheck disable=SC2030,SC2031  # PATH and VAULT_REPO are deliberately scoped to this subshell
(
    PATH="$TESTROOT/failbin:$PATH"
    # shellcheck disable=SC2034  # read by the extracted vault_get below
    VAULT_REPO=oso-gato/homelab-root
    eval "$(_extract_fn vault_get   "$REPO_ROOT/host/day-zero.sh")"
    eval "$(_extract_fn vault_is_pem "$REPO_ROOT/host/day-zero.sh")"
    vault_get "identity/some-app.pem" "$VAULTDIR/private-key.pem" vault_is_pem
) >/dev/null 2>&1
VAULT_AFTER=$(sha256sum "$VAULTDIR/private-key.pem" | cut -d' ' -f1)

if [ "$VAULT_BEFORE" = "$VAULT_AFTER" ]; then
    pass "a failed vault fetch leaves the incumbent key byte-identical"
else
    fail "a failed vault fetch changed the incumbent key — the destructive form is back"
fi
if [ ! -e "$VAULTDIR/private-key.pem.new" ]; then
    pass "a failed vault fetch leaves no staged file behind"
else
    fail "a failed vault fetch left a staged file at ${VAULTDIR}/private-key.pem.new"
fi

# Mutation: restore the pre-fix form on a copy. The check above must fail
# against it, or it was proving nothing (C9).
_incumbent
vault_get_mutant() {
    local path="$1" dest="$2"
    gh api "repos/x/contents/${path}" > "$dest" 2>/dev/null || return 1
    [ -s "$dest" ] || return 1
}
# shellcheck disable=SC2030,SC2031  # same deliberate subshell scoping
( PATH="$TESTROOT/failbin:$PATH"; vault_get_mutant "identity/some-app.pem" "$VAULTDIR/private-key.pem" ) >/dev/null 2>&1
VAULT_MUT=$(sha256sum "$VAULTDIR/private-key.pem" | cut -d' ' -f1)
if [ "$VAULT_BEFORE" != "$VAULT_MUT" ]; then
    pass "the pre-fix form does destroy the incumbent, so the check above can fail"
else
    fail "the pre-fix form left the incumbent intact — the check above proves nothing"
fi

# The two scripts carry vault_get separately, deliberately: day zero is one
# pasted artifact whose integrity story is the operator's own sha256sum, so it
# sources nothing. That makes drift the risk, and this is the guard for it.
_DZ_FN=$(_extract_fn vault_get "$REPO_ROOT/host/day-zero.sh")
_AC_FN=$(_extract_fn vault_get "$REPO_ROOT/host/activate.sh")
if [ -n "$_DZ_FN" ] && [ "$_DZ_FN" = "$_AC_FN" ]; then
    pass "both day-zero scripts carry a byte-identical vault_get"
else
    fail "day-zero.sh and activate.sh have drifted apart on vault_get"
fi

# ── 4e. Nothing inside a pasted script may read the terminal ─────────────────
# Both day-zero scripts are contracted to be pasted whole into a console. A
# command that reads stdin from inside a paste consumes the NEXT pasted lines
# as its answer and bash never runs them, which is how an interactive prompt in
# the middle of a paste silently truncates the script. gh prompts twice when it
# believes it has a terminal, so every gh auth login here must close stdin.
# Bounded, closed, over two declared artifacts.
head_ "paste safety"
_bad_login=0
while IFS= read -r hit; do
    printf '%s' "$hit" | grep -q '</dev/null' && continue
    printf '        %s\n' "$hit"
    _bad_login=1
done < <(git -C "$REPO_ROOT" grep -nI 'gh auth login' \
    -- 'host/**' 'dev-container/**' 'shared/**' ':!host/converge/selftest.sh' 2>/dev/null)
if [ "$_bad_login" = 0 ]; then
    pass "every gh auth login closes stdin, so a pasted script cannot eat itself"
else
    fail "a gh auth login can read the terminal from inside a pasted script"
fi

# The check must be able to see one. Reproduce the unguarded form on a copy
# outside the scanned tree and require the same test to catch it.
_PASTE_MUTANT="$TESTROOT/paste-mutant.sh"
printf 'gh auth login --hostname github.com --web\n' > "$_PASTE_MUTANT"
if grep -q 'gh auth login' "$_PASTE_MUTANT" && ! grep -q '</dev/null' "$_PASTE_MUTANT"; then
    pass "the unguarded form is detected, so the check above can fail"
else
    fail "the unguarded form was not detected — the check above proves nothing"
fi

# ── 4f. A lock fd never reaches a container ──────────────────────────────────
# C8 makes the session lock the thing that stops a rebuild firing mid-session.
# A container started with the lock fd still open INHERITS it and holds the
# lock for the box's whole lifetime, which breaks that guarantee in both
# directions: an inherited shared lock makes the nightly rebuild defer forever
# and silently, and an inherited exclusive lock hangs every later session at
# flock with no way out but killing the box. The estate's predecessor measured
# this and recorded the verdict; every file here that takes a lock on an
# explicit fd must close it to each distrobox child.
head_ "session lock"
_lock_files="$REPO_ROOT/shared/claudebox/claude
$REPO_ROOT/shared/claudebox/claudebox-rebuild
$REPO_ROOT/host/sysroot/usr/lib/systemd/user/claudebox-rebuild-run.service"

_lock_check() {   # _lock_check <file> -> prints offending lines, returns 1 if any
    local f="$1" fd bad=0 line
    fd=$(grep -oE 'flock +(-[a-zA-Z]+ +)*[0-9]+' "$f" | grep -oE '[0-9]+$' | head -1)
    if [ -z "$fd" ]; then
        printf '        %s takes no lock on an explicit fd\n' "$(basename "$f")"
        return 1
    fi
    while IFS= read -r line; do
        printf '%s' "$line" | grep -q "${fd}>&-" && continue
        printf '        %s: %s\n' "$(basename "$f")" "$(printf '%s' "$line" | cut -c1-64)"
        bad=1
    done < <(sed -e :a -e '/\\$/N; s/\\\n//; ta' "$f" | grep -E '^[^#]*distrobox ')
    return "$bad"
}

_lock_bad=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    _lock_check "$f" || _lock_bad=1
done <<< "$_lock_files"
if [ "$_lock_bad" = 0 ]; then
    pass "no distrobox child inherits the session lock fd"
else
    fail "a distrobox child inherits the session lock fd — the lock outlives its holder"
fi

# Mutation: strip the fd-close on a copy and require the check to catch it.
_LOCK_MUTANT="$TESTROOT/lock-mutant.sh"
sed 's/ 9>&-//g' "$REPO_ROOT/shared/claudebox/claudebox-rebuild" > "$_LOCK_MUTANT"
if _lock_check "$_LOCK_MUTANT" >/dev/null 2>&1; then
    fail "the check passed a file whose fd-close was removed — it proves nothing"
else
    pass "removing the fd-close is caught, so the check above can fail"
fi

# ── 4g. Nothing closes a door before the gate is computed ────────────────────
# C11 forbids a mechanism that blocks the loop with no way back. Both identity
# paths test whether the administrative user is provably usable before they
# retire root — but the acts that remove every OTHER way in used to run outside
# that test. activate.sh deleted the bootstrap sudo window before the test was
# even computed, so an image whose password bake failed produced a host with no
# administrator at all, recoverable only by a rebase.
#
# The bounded, closed form of that rule: in each file the gate must be assigned
# before the first door-closing command appears. Line order over two declared
# artifacts — not a scan for whether each act is nested correctly, which would
# be a pattern-scan over open-ended input and is checked by review instead.
head_ "door order"
_door_re='passwd -l |gpasswd -d |rm -f /etc/sudoers.d/|> /root/.ssh/authorized_keys'

_door_order() {   # _door_order <file> <gate-var> -> 0 if the gate comes first
    local f="$1" var="$2" gate first
    gate=$(grep -nE "^[[:space:]]*${var}=1" "$f" | head -1 | cut -d: -f1)
    first=$(grep -nE "$_door_re" "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1)
    [ -n "$gate" ] || return 1
    [ -n "$first" ] || return 0
    [ "$gate" -lt "$first" ]
}

for _spec in "host/converge/units/10-identity.sh:_admin_ready" "host/activate.sh:admin_ready"; do
    _f="${_spec%%:*}"; _v="${_spec##*:}"
    if _door_order "$REPO_ROOT/$_f" "$_v"; then
        pass "${_f##*/}: the usability gate is computed before anything closes a door"
    else
        fail "${_f##*/}: something closes a door before ${_v} is computed"
    fi
done

# Mutation: hoist a door-closing command above the gate on a copy, and require
# the check to catch it.
_DOOR_MUTANT="$TESTROOT/door-mutant.sh"
{
    printf 'rm -f /etc/sudoers.d/strix-bootstrap\n'
    cat "$REPO_ROOT/host/activate.sh"
} > "$_DOOR_MUTANT"
if _door_order "$_DOOR_MUTANT" admin_ready; then
    fail "the check passed a file that closes a door first — it proves nothing"
else
    pass "a door closed before the gate is caught, so the checks above can fail"
fi

# ── 4h. No credential reaches a process argument ─────────────────────────────
# /proc/<pid>/cmdline is world-readable whoever owns the process, so anything
# on argv is readable by every local account for the life of the call. Three
# forms existed here: a tailnet auth key inlined into `tailscale up`, an App
# JWT inlined as a curl header — renewed roughly every 50 minutes on both
# components, for the App that carries merge permission — and the crypt hash
# handed to `usermod -p`, which usermod's own manual page tells you not to use
# for exactly this reason. Each has a stdin or file form and this holds them to
# it. Bounded, closed, over declared artifacts.
head_ "credentials on argv"
_argv_bad=0
while IFS= read -r hit; do
    # A comment that QUOTES a forbidden form is documenting why it was removed,
    # and naming a thing is not using it — the same distinction the
    # forbidden-channel check above already draws. Drop comment lines.
    case "${hit#*:*:}" in [[:space:]]*\#*|\#*) continue ;; esac
    _argv_bad=1
    printf '        %s\n' "$(printf '%s' "$hit" | cut -c1-84)"
done < <(git -C "$REPO_ROOT" grep -nIE \
    '(usermod +(-[a-zA-Z]+ +)*-p |--auth-?key=(")?[^f"]|-H +"Authorization: *Bearer )' \
    -- 'host/**' 'dev-container/**' 'shared/**' ':!host/converge/selftest.sh' 2>/dev/null)
if [ "$_argv_bad" = 0 ]; then
    pass "no auth key, App JWT or password hash is passed as a process argument"
else
    fail "a credential is passed as a process argument"
fi

# Each forbidden form must be visible to the pattern. Reproduce all three on a
# copy outside the scanned tree and require every one to match.
_ARGV_MUTANT="$TESTROOT/argv-mutant.sh"
# shellcheck disable=SC2016  # the mutant reproduces the forbidden forms verbatim
{
    printf 'usermod -p "$HASH" core\n'
    printf 'tailscale up --auth-key="$(cat /tmp/k)"\n'
    printf 'curl -H "Authorization: Bearer $jwt" https://example.invalid/\n'
} > "$_ARGV_MUTANT"
_argv_seen=$(grep -cE '(usermod +(-[a-zA-Z]+ +)*-p |--auth-?key=(")?[^f"]|-H +"Authorization: *Bearer )' "$_ARGV_MUTANT")
if [ "$_argv_seen" -eq 3 ]; then
    pass "all three argv forms are detected, so the check above can fail"
else
    fail "only ${_argv_seen} of 3 argv forms were detected — the check above is partly blind"
fi

# ── 4i. One tmux policy, not two ─────────────────────────────────────────────
# The geometry rules belong to the platform rather than to either component, so
# the host's copy and the dev-container's are the same file. Two copies of one
# rule is what C1 forbids, and the only thing keeping them one rule is this
# check — without it a fix lands on whichever component the session happened to
# be looking at, and the other silently keeps the old behaviour.
head_ "tmux policy"
_tmux_host="$REPO_ROOT/host/sysroot/etc/tmux.conf"
_tmux_dev="$REPO_ROOT/dev-container/sysroot/etc/tmux.conf"
if [ -f "$_tmux_host" ] && [ -f "$_tmux_dev" ] && cmp -s "$_tmux_host" "$_tmux_dev"; then
    pass "both components carry a byte-identical tmux policy"
else
    fail "the host and dev-container tmux policies differ, or one is missing"
fi

# The host's copy only reaches the host if a unit installs it.
if grep -q 'host/sysroot/etc/tmux.conf' "$REPO_ROOT/host/converge/units/10-identity.sh"; then
    pass "the host's tmux policy is installed by the identity unit"
else
    fail "the host's tmux policy is never installed — it would exist only in the repository"
fi

# ── 4j. The charter is wired into every session ──────────────────────────────
# The charter is the pair's whole instruction, and an instruction to READ it can
# be skipped with no trace — which is how a session once worked a whole day from
# fragments and built against a Security outcome while citing it. An import
# cannot be skipped: the bytes are in the window or they are not. This checks
# the wiring that puts them there, and it never checks the agent, because what
# an agent read is not observable from outside the session.
#
# Total rather than a sieve: a file either carries the import line or it does
# not. There is nothing to evade and no next evasion to chase.
head_ "charter loading"
_load_bad=0
_want_import() {   # _want_import <file> <imported-path>
    grep -qE "^@${2}\$" "$REPO_ROOT/$1" && return 0
    printf '        %s does not import %s\n' "$1" "$2"
    return 1
}
_want_import CLAUDE.md AGENTS.md            || _load_bad=1
_want_import AGENTS.md 00-OBJECTIVE.md      || _load_bad=1
_want_import AGENTS.md 00-BYLAW.md          || _load_bad=1
_want_import AGENTS.md CONSTITUTION.md      || _load_bad=1
for _f in CLAUDE.md AGENTS.md 00-OBJECTIVE.md 00-BYLAW.md CONSTITUTION.md; do
    [ -s "$REPO_ROOT/$_f" ] && continue
    printf '        %s is missing or empty\n' "$_f"
    _load_bad=1
done
if [ "$_load_bad" = 0 ]; then
    pass "the charter is imported into every session, not left to be read"
else
    fail "the charter is not wired into the session load"
fi

# The manual must not outgrow the law. A session's attention is finite, and a
# manual longer than the charter buries what it exists to deliver — which is
# how the predecessor reached a 279 KB operating file nobody could hold.
_manual=$(wc -l < "$REPO_ROOT/AGENTS.md")
_law=$(( $(wc -l < "$REPO_ROOT/00-OBJECTIVE.md") + $(wc -l < "$REPO_ROOT/00-BYLAW.md") ))
if [ "$_manual" -lt "$_law" ]; then
    pass "the manual (${_manual} lines) is shorter than the law it loads (${_law})"
else
    fail "the manual is ${_manual} lines against ${_law} of law — it has outgrown what it delivers"
fi

# Mutation: strip an import on a copy and require the check to catch it.
_LOAD_MUTANT_DIR="$TESTROOT/loadmutant"
mkdir -p "$_LOAD_MUTANT_DIR"
grep -v '^@00-OBJECTIVE.md$' "$REPO_ROOT/AGENTS.md" > "$_LOAD_MUTANT_DIR/AGENTS.md"
if grep -qE '^@00-OBJECTIVE\.md$' "$_LOAD_MUTANT_DIR/AGENTS.md"; then
    fail "the mutant still carries the import — the check above proves nothing"
else
    pass "a stripped import is detectable, so the check above can fail"
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
# and word-boundaried on the fetch-pipe case: an earlier version matched the
# `| sh` inside `| sha256sum` and reported a checksum verification as a
# fetch-piped-to-shell. Second time a guard here fired on a substring — the
# pattern-scan failure mode the constitution's preamble names.
# because the deny list in managed-settings.json and the prose in docs/ name
# these deliberately and naming a thing is not using it.
head_ "provenance"
forbidden_hit=0
while IFS= read -r hit; do
    forbidden_hit=1
    printf '        %s\n' "$hit"
done < <(git -C "$REPO_ROOT" grep -nIE \
    '(dnf +copr|copr +enable|pip3? +install|pipx +install|npm +install +-g|npm +i +-g|cargo +install|go +install|gem +install|brew +install|flatpak +install|snap +install|curl[^|]*\| *(ba)?sh([[:space:]]|$))' \
    -- 'host/**' 'dev-container/**' 'shared/**' \
       ':!shared/claudebox/managed-settings.json' 2>/dev/null)
if [ "$forbidden_hit" = 0 ]; then
    pass "no forbidden channel in host/, dev-container/ or shared/"
else
    fail "a forbidden channel appears in the code"
fi

# Every repository definition verifies against a key that was checked.
#
# C4 asks for one fetch mechanism per system at one strength. At L2 the
# strongest available form is prov_l2_vendor_repo: fetch the VENDOR'S own .repo
# file and pin the whole file by checksum, so a moved baseurl or a swapped
# gpgkey URL stops the run. Where a vendor publishes no such file, a definition
# written here is the only option left — and then the load-bearing property is
# that its gpgkey names a LOCAL file installed after a fingerprint check, never
# a remote URL. A remote gpgkey under `dnf -y` auto-imports whatever is served
# at that moment, which makes any fingerprint recorded nearby a decoration.
#
# Both failures were live in this tree when this check was written: the
# converger carried an unused prov_l2_repo that composed definitions, and the
# claudebox manifest wrote a definition with a remote gpgkey under a comment
# stating the fingerprint it never enforced. This check is why they are gone.
remote_key_hit=0
while IFS= read -r hit; do
    remote_key_hit=1
    printf '        %s\n' "$hit"
done < <(git -C "$REPO_ROOT" grep -nIE 'gpgkey=(https?|ftp)://' \
    -- 'host/**' 'dev-container/**' 'shared/**' \
       ':!host/converge/selftest.sh' 2>/dev/null)
if [ "$remote_key_hit" = 0 ]; then
    pass "no repository definition trusts a remote signing key"
else
    fail "a repository definition names a remote gpgkey, which dnf -y imports unchecked"
fi

# The converger's own L2 path admits vendor files and nothing weaker. Scoped to
# the fetch contract, where the vendor-file rule is the stated contract: a
# definition composed inside provenance.sh would be prov_l2_repo returning.
if git -C "$REPO_ROOT" grep -qIE '(baseurl|gpgkey)=' -- 'host/converge/lib/**' 2>/dev/null; then
    fail "the fetch contract composes a repository definition rather than admitting the vendor's own"
else
    pass "the fetch contract admits the vendor's own definition, pinned by checksum"
fi

# Both patterns must be able to see the thing they forbid. Reproduce each on a
# copy outside the scanned tree and require the pattern to match, so a green
# result above means absence rather than a pattern that matches nothing.
COMPOSED="$TESTROOT/composed.repo"
printf '[vendor]\nbaseurl=https://example.invalid/rpm\ngpgkey=https://example.invalid/key.asc\n' > "$COMPOSED"
if grep -qE 'gpgkey=(https?|ftp)://' "$COMPOSED" && grep -qE '(baseurl|gpgkey)=' "$COMPOSED"; then
    pass "both repository patterns match a definition of the kind they forbid, so the checks above can fail"
else
    fail "a repository pattern did not match the definition it exists to catch — the checks above prove nothing"
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

# ── 7. The adapters are additions, not forks ─────────────────────────────────
# Issue #11's acceptance 2 in testable form. Every environment must render the
# one shared template into a complete unit, and no unit may branch on which
# pair is converging — the moment a unit says "if strix", the adapter rule has
# stopped holding and the second lineage has become a fork.
head_ "adapters"
for env_file in "$REPO_ROOT"/host/converge/environments/*.env; do
    env_name=$(basename "$env_file" .env)
    if (
        CONVERGE_CHANGED=0
        # shellcheck source=/dev/null
        . "$env_file"
        out="$TESTROOT/render-$env_name.container"
        fs_render "$REPO_ROOT/host/sysroot/etc/containers/systemd/users/dev-container.container.tpl" \
                  "$out" 0644 PAIR_NAME DEV_CONTAINER_NAME DEV_CONTAINER_IMAGE \
                  DEV_SSH_PORT DEV_MOSH_PORTS DEV_TAILNET_HOSTNAME TRUST_ROOT_USER >/dev/null 2>&1
        grep -q "ContainerName=${DEV_CONTAINER_NAME}$" "$out" || exit 1
        grep -q "Image=${DEV_CONTAINER_IMAGE}$" "$out" || exit 1
        grep -q '@@' "$out" && exit 1
        exit 0
    ); then
        pass "${env_name}: renders a complete dev-container unit from the shared template"
    else
        fail "${env_name}: the shared template did not render cleanly for this adapter"
    fi
done

# Every adapter must set the variables the units read unconditionally. A
# missing one is a converge that dies partway rather than at the first line.
for env_file in "$REPO_ROOT"/host/converge/environments/*.env; do
    env_name=$(basename "$env_file" .env)
    missing=""
    for v in PAIR_NAME PAIR_TRACK DEV_CONTAINER_NAME DEV_CONTAINER_IMAGE \
             TRUST_ROOT_USER ADMIN_USER TAILNET_HOSTNAME VAULT_REPO \
             PAIR_STATE_DIR PAIR_SECRETS_DIR PAIR_ADMIN_STATE \
             PAIR_DEV_SECRETS_DIR PAIR_WORK_DIR BIN_DIR UNIT_DIR \
             DEV_SSH_PORT DEV_MOSH_PORTS DEV_TAILNET_HOSTNAME; do
        grep -qE "^${v}=" "$env_file" || missing="$missing $v"
    done
    if [ -z "$missing" ]; then
        pass "${env_name}: declares every variable the units read"
    else
        fail "${env_name}: missing${missing}"
    fi
done

# Code lines only, and whole words — an earlier version of this check matched
# the "if" inside "verify" and fired on a comment.
BRANCH_RE='^[^#]*\b(if|case)\b.*\b(erebus|strix|nox|moros)\b'
if git -C "$REPO_ROOT" grep -nIE "$BRANCH_RE" \
     -- 'host/converge/units/**' 'host/converge/lib/**' >/dev/null 2>&1; then
    fail "a unit or library branches on the pair — the adapter rule has stopped holding"
    git -C "$REPO_ROOT" grep -nIE "$BRANCH_RE" \
        -- 'host/converge/units/**' 'host/converge/lib/**' | sed 's/^/        /'
else
    pass "no unit or library branches on which pair is converging"
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
