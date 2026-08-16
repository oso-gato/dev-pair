#!/usr/bin/env bash
# P6 secret scan: credential shapes, mechanically, over the whole tracked tree.
# Fails on: private-key blocks, GitHub tokens and PATs, tailnet keys, AWS access
# keys, sha512crypt hashes. The pattern texts cannot match themselves, so this
# file needs no exclusion; the test fixtures are excluded (real-shaped dummies,
# proven by the tests instead).
# Not covered (adversarial review): high-entropy strings without a known shape,
# secrets in binary blobs, credentials named innocently in prose.
set -euo pipefail
cd "${1:-.}"

fixtures="shared/gates/test/fixtures/"

# The single quotes are the point: literal regex text, never expanded.
# shellcheck disable=SC2016
patterns=(
  'BEGIN [A-Z ]*PRIVATE KEY'
  '\bgh[opsu]_[A-Za-z0-9]{16,}'
  '\bgithub_pat_[A-Za-z0-9_]{20,}'
  '\btskey-[a-z]+-[A-Za-z0-9]+'
  '\bAKIA[0-9A-Z]{16}\b'
  '\$6\$[A-Za-z0-9./]{4,}\$[A-Za-z0-9./]{8,}'
)

fail=0
while IFS= read -r file; do
  case "$file" in "$fixtures"*) continue ;; esac
  for p in "${patterns[@]}"; do
    if grep -nE "$p" "$file" /dev/null; then
      echo "secrets: credential-shaped content in '$file' — rotate it; git never forgets (P6)" >&2
      fail=1
    fi
  done
done < <(git ls-files)

exit "$fail"
