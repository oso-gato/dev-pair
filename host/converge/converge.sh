#!/usr/bin/env bash
# converge.sh — the idempotent converger, and the host's only deploy mechanism.
#
# The VPS track's sanctioned deploy mechanism (00-BYLAW.md): every mutation the
# host carries is declared in this repository, any historical version re-runs
# safely, and ad-hoc drift vanishes on the next apply. Re-running is the normal
# case, not the recovery case.
#
# Idempotence is a property of each unit rather than of a guard around this
# script. Every unit reads live state, compares it against the declaration, and
# acts only on the difference — so a second apply reports zero changes because
# there is nothing to change, which is what acceptance 3 asks for.
#
# Usage:
#   sudo ./converge.sh                      converge for the default environment
#   sudo ./converge.sh --env strix          converge for another environment
#   sudo ./converge.sh --only 60-agentbox   run one unit
#   sudo ./converge.sh --list               show the units and stop
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONVERGE_DIR="$REPO_ROOT/host/converge"
ENVIRONMENT="${CONVERGE_ENV:-erebus}"
ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --env)  ENVIRONMENT="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        --list) find "$CONVERGE_DIR/units" -name '*.sh' -printf '%f\n' | sed 's/\.sh$//' | sort; exit 0 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "converge: unknown argument $1" >&2; exit 2 ;;
    esac
done

# shellcheck source=lib/log.sh
. "$CONVERGE_DIR/lib/log.sh"

[ "$(id -u)" -eq 0 ] || log_die "converge must run as root: sudo $0"

ENV_FILE="$CONVERGE_DIR/environments/${ENVIRONMENT}.env"
[ -f "$ENV_FILE" ] || log_die "no adapter for environment '${ENVIRONMENT}' at ${ENV_FILE}"
# shellcheck source=environments/erebus.env
. "$ENV_FILE"

# shellcheck source=lib/fs.sh
. "$CONVERGE_DIR/lib/fs.sh"
# shellcheck source=lib/provenance.sh
. "$CONVERGE_DIR/lib/provenance.sh"

printf '%s\n\n' "converge: ${PAIR_NAME} (${PAIR_TRACK} track) from ${REPO_ROOT}"

# The preamble belongs to the track whose deploy mechanism this is. On the VPS
# track the converger owns the host's OS state, so it installs its own fetch
# tooling and the trust-root sync ahead of the ordered units. On the bare-metal
# track the image owns all of that and arrives by rebase, so touching it here
# would put two mechanisms in charge of one fact — and installing a package on
# an image-immutable host is the out-of-band change C7 forbids outright.
if [ -z "${CONVERGE_UNITS:-}" ]; then
    prov_bootstrap

    # The trust-root sync has to exist before the identity unit runs it, and it
    # is the one file installed ahead of the ordered units for that reason.
    fs_install "$REPO_ROOT/shared/bin/pair-keys-sync" "$BIN_DIR/pair-keys-sync" 0755
    fs_render "$REPO_ROOT/host/sysroot/usr/lib/systemd/system/pair-keys-sync.service.tpl" \
              "$UNIT_DIR/pair-keys-sync.service" 0644 BIN_DIR ADMIN_USER TRUST_ROOT_USER
    fs_install "$REPO_ROOT/host/sysroot/usr/lib/systemd/system/pair-keys-sync.timer" \
               "$UNIT_DIR/pair-keys-sync.timer" 0644
    systemctl daemon-reload
    fs_enable_unit pair-keys-sync.timer
else
    log_ok "preamble skipped — ${PAIR_TRACK} track: the image owns the host's OS state"
fi

# Units run in filename order, and the numbering IS the dependency declaration:
# identity before packages because a host with no administrator is not one we
# want installing software, packages before the tailnet because the vendor
# repository needs the fetch tooling, podman before the box and the box before
# the dev-container. Nothing here is parallel, because every step genuinely
# depends on the one above it (C12: order only by dependency).
#
# Which units apply is a track fact the adapter declares. The VPS track's
# sanctioned deploy mechanism is this converger, so it runs all of them; the
# bare-metal track's is image rebase, so it runs only what the image does not
# already carry. An unset list means every unit.
for unit in "$CONVERGE_DIR"/units/*.sh; do
    name=$(basename "$unit" .sh)
    if [ -n "$ONLY" ]; then
        [ "$ONLY" = "$name" ] || continue
    elif [ -n "${CONVERGE_UNITS:-}" ]; then
        case " $CONVERGE_UNITS " in
            *" $name "*) : ;;
            *) continue ;;
        esac
    fi
    echo
    # shellcheck source=/dev/null
    . "$unit"
done

log_summary

if [ "$CONVERGE_CHANGED" -eq 0 ]; then
    echo "converge: the host already matched its declaration — nothing was done."
fi
