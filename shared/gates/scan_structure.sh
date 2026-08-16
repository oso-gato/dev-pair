#!/usr/bin/env bash
# P2 structure scan: the standing skeleton, mechanically.
# Fails on: a root entry outside the standing inventory; an uppercase character
# in any directory name; an uppercase working file below root (Containerfile is
# the one tool-contract exception); a docs/ child that is neither decisions/,
# specs/, nor an asset recorded in ARCHITECTURE.md; a file directly under docs/;
# any .md inside a component tree (component folders hold code and scripts only).
# Not covered (adversarial review): whether ARCHITECTURE.md reflects the code.
set -euo pipefail
cd "${1:-.}"

fail=0
say() { echo "structure: $*" >&2; fail=1; }

allowed_root_files=" 00-OBJECTIVE.md 00-BYLAW.md CONSTITUTION.md AGENTS.md ARCHITECTURE.md CHANGELOG.md README.md "
allowed_root_dirs=" docs host dev-container shared .github "

while IFS= read -r entry; do
  if [ -d "$entry" ]; then
    case "$allowed_root_dirs" in
      *" $entry "*) ;;
      *) say "root directory '$entry' is not in the standing skeleton" ;;
    esac
  else
    case "$allowed_root_files" in
      *" $entry "*) ;;
      *) say "root file '$entry' is not a standing surface" ;;
    esac
  fi
done < <(git ls-files | awk -F/ '{print $1}' | sort -u)

while IFS= read -r dir; do
  case "$dir" in
    *[A-Z]*) say "directory '$dir' violates the lowercase grammar" ;;
  esac
done < <(git ls-files | awk -F/ 'NF>1 {for (i=1; i<NF; i++) print $i}' | sort -u)

while IFS= read -r path; do
  base="${path##*/}"
  case "$path" in */*) ;; *) continue ;; esac
  [ "$base" = "Containerfile" ] && continue
  case "$base" in
    *[A-Z]*) say "file '$path' violates the below-root lowercase grammar" ;;
  esac
done < <(git ls-files)

while IFS= read -r child; do
  case "$child" in
    decisions|specs) ;;
    *)
      if ! grep -q "docs/$child" ARCHITECTURE.md 2>/dev/null; then
        say "docs/$child is not a documentation asset recorded in ARCHITECTURE.md"
      fi
      ;;
  esac
done < <(git ls-files docs | awk -F/ 'NF>2 {print $2}' | sort -u)

while IFS= read -r loose; do
  say "file '$loose' sits directly under docs/ — docs holds only its records and recorded assets"
done < <(git ls-files docs | awk -F/ 'NF==2 {print $0}')

while IFS= read -r doc; do
  say "documentation '$doc' inside a component tree — component folders hold code and scripts only"
done < <(git ls-files host dev-container shared | grep '\.md$' || true)

exit "$fail"
