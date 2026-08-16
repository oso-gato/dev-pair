#!/usr/bin/env bash
# P4 channel scan: the bylaw's forbidden channels, mechanically, over the
# component trees and .github. Fails on: curl/wget piped to a shell; COPR;
# flatpak; snap install; global npm/pip/gem/cargo installs; tar extraction
# into system paths. Excludes exactly two paths, stated here: this file (its
# pattern list would match itself) and the test fixtures (violations by design,
# proven by the tests instead).
# Not covered (adversarial review): mirror and aggregator binaries, obfuscated
# fetch-and-execute, provenance grades within sanctioned channels.
set -euo pipefail
cd "${1:-.}"

self="shared/gates/scan_channels.sh"
fixtures="shared/gates/test/fixtures/"

patterns=(
  '(curl|wget)[^|;&]*\|[[:space:]]*(ba|z|da)?sh'
  '\bcopr\b'
  '\bflatpak\b'
  '\bsnap[[:space:]]+install\b'
  '\bnpm[[:space:]]+(install|i)[[:space:]]+.*(-g\b|--global\b)'
  '\bpip3?[[:space:]]+install\b'
  '\bgem[[:space:]]+install\b'
  '\bcargo[[:space:]]+install\b'
  '\btar[[:space:]]+[^;|&]*-C[[:space:]]*/usr'
)

fail=0
while IFS= read -r file; do
  [ "$file" = "$self" ] && continue
  case "$file" in "$fixtures"*) continue ;; esac
  for p in "${patterns[@]}"; do
    if grep -nE "$p" "$file" /dev/null; then
      echo "channels: forbidden channel in '$file' (pattern: $p)" >&2
      fail=1
    fi
  done
done < <(git ls-files host dev-container shared .github)

exit "$fail"
