#!/usr/bin/env bash
# PR-context gate: locked documents, specs-completeness, frozen-at-ship.
# Args: BASE_SHA HEAD_SHA BRANCH. Diffs three-dot — the PR's own changes since
# the merge base, never the base branch's drift.
# Not covered (adversarial review): whether the spec content matches the code.
set -euo pipefail
base="$1"; head="$2"; branch="$3"

fail=0
say() { echo "specs-gate: $*" >&2; fail=1; }

changed=$(git diff --name-only "$base...$head")

while IFS= read -r f; do
  case "$f" in
    00-OBJECTIVE.md|00-BYLAW.md|CONSTITUTION.md)
      say "'$f' is maintainer-merge-only — a locked document never lands through the loop" ;;
  esac
done <<< "$changed"

if grep -qE '^(host|dev-container|shared|\.github)/' <<< "$changed"; then
  if ! [[ "$branch" =~ ^[0-9]+- ]]; then
    say "component change on branch '$branch' — ticket branches are <NNN-slug>"
  elif ! { git cat-file -e "$head:docs/specs/$branch/spec.md" 2>/dev/null \
        && git cat-file -e "$head:docs/specs/$branch/plan.md" 2>/dev/null \
        && git cat-file -e "$head:docs/specs/$branch/tasks.md" 2>/dev/null; }; then
    say "component change without a complete docs/specs/$branch/ (spec.md, plan.md, tasks.md)"
  fi
fi

while IFS= read -r d; do
  [ -z "$d" ] && continue
  [ "$d" = "$branch" ] && continue
  say "edits docs/specs/$d — another ticket's record, frozen at ship; a change is a new ticket"
done < <(grep -E '^docs/specs/' <<< "$changed" | awk -F/ '{print $3}' | sort -u || true)

exit "$fail"
