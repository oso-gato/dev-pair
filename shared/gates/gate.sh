#!/usr/bin/env bash
# One-command repo-state gate: P2 structure, P4 channels, P6 secrets, shellcheck.
# CI, the host, and the dev-container all run exactly this script — one home,
# one definition. Runs every scan and aggregates, so one red never hides another.
# The shell-lint sweep excludes the test fixtures (violations by design); a
# missing linter is a failure, never a skip — a gate that skips is theatrical.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
gates="shared/gates"

rc=0
"$gates/scan_structure.sh" || rc=1
"$gates/scan_channels.sh" || rc=1
"$gates/scan_secrets.sh" || rc=1

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "gate: shellcheck not present — failing closed" >&2
  rc=1
else
  git ls-files '*.sh' | grep -v '^shared/gates/test/fixtures/' | xargs shellcheck || rc=1
fi

if [ "$rc" -eq 0 ]; then
  echo "gate: green"
else
  echo "gate: red" >&2
fi
exit "$rc"
