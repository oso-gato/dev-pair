#!/usr/bin/env bash
# log.sh — the output discipline every converger unit shares.
#
# The converger's normal case is a re-run, so its output has to make "nothing
# to do" as legible as "changed something". Units report through these three
# and nothing else, and the difference between them is what tells the operator
# whether an apply was a no-op.
#
# Sourced, never executed.

# Colour only when stdout is a terminal — the converger runs from a console
# paste, from a systemd unit, and from a pipe, and only the first wants escapes.
if [ -t 1 ]; then
    _C_RESET=$'\033[0m'; _C_DIM=$'\033[2m'; _C_BOLD=$'\033[1m'
    _C_RED=$'\033[31m'; _C_YELLOW=$'\033[33m'; _C_GREEN=$'\033[32m'
else
    _C_RESET=''; _C_DIM=''; _C_BOLD=''
    _C_RED=''; _C_YELLOW=''; _C_GREEN=''
fi

# Counters the entry point reads back to summarise the run.
CONVERGE_CHANGED=0
CONVERGE_UNCHANGED=0

# log_unit — announce the unit now running.
log_unit() { printf '%s\n' "${_C_BOLD}── $* ──${_C_RESET}"; }

# log_changed — this apply altered live state. Every call is a real difference
# the unit acted on, which is what makes a second apply's silence meaningful.
log_changed() {
    CONVERGE_CHANGED=$((CONVERGE_CHANGED + 1))
    printf '%s\n' "${_C_GREEN}[changed]${_C_RESET} $*"
    command -v logger >/dev/null 2>&1 && logger -t converge -p info "changed: $*" || true
}

# log_ok — the declaration already held; nothing was done.
log_ok() {
    CONVERGE_UNCHANGED=$((CONVERGE_UNCHANGED + 1))
    printf '%s\n' "${_C_DIM}[ok]${_C_RESET}      $*"
}

# log_warn — something is off but the run continues. Never used for a failed
# admission: an artifact that will not verify stops the run through log_die.
log_warn() {
    printf '%s\n' "${_C_YELLOW}[warn]${_C_RESET}    $*" >&2
    command -v logger >/dev/null 2>&1 && logger -t converge -p warning "$*" || true
}

# log_die — fail closed. The converger stops rather than leave the host in a
# state no declaration describes.
log_die() {
    printf '%s\n' "${_C_RED}[fail]${_C_RESET}    $*" >&2
    command -v logger >/dev/null 2>&1 && logger -t converge -p err "$*" || true
    exit 1
}

# log_summary — the line an operator reads to know whether the apply was a
# no-op. Acceptance 3 is exactly this reporting zero changes on a second run.
log_summary() {
    printf '\n%s\n' "${_C_BOLD}converge: ${CONVERGE_CHANGED} changed, ${CONVERGE_UNCHANGED} already correct${_C_RESET}"
}
