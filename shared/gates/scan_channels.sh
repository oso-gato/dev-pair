#!/usr/bin/env bash
# P4 channel scan: the bylaw's forbidden channels, mechanically, over the
# component trees and .github. Fails on: curl/wget piped to a shell — directly
# or through a wrapper like sudo or env; COPR; flatpak; snap install; global
# npm (-g, --global, --location=global), pip, gem, cargo installs; tar
# extraction into a system path (-C or --directory into /usr /bin /lib /opt
# /etc /sbin). Excludes exactly two paths, stated here: this file (its pattern
# list would match itself) and the whole test tree `shared/gates/test/` (the
# fixtures and the harness both embed violation strings by design, proven by
# the tests instead).
# Not covered (adversarial review): mirror and aggregator binaries, obfuscated
# fetch-and-execute, case-variant CLI names, provenance grades within
# sanctioned channels.
set -euo pipefail
cd "${1:-.}"

self="shared/gates/scan_channels.sh"
testdir="shared/gates/test/"

patterns=(
  '(curl|wget)[^|;&]*\|.*\b(ba|z|da|k)?sh\b'
  '\bcopr\b'
  '\bflatpak\b'
  '\bsnap[[:space:]]+install\b'
  '\bnpm[[:space:]]+(install|i)\b[^;|&]*(-g\b|--global\b|--location[= ]global\b)'
  '\bpip3?[[:space:]]+install\b'
  '\bgem[[:space:]]+install\b'
  '\bcargo[[:space:]]+install\b'
  '\btar[[:space:]]+[^;|&]*(-C[[:space:]]*|--directory[= ])/(usr|bin|lib|opt|etc|sbin)'
)

fail=0
while IFS= read -r file; do
  [ "$file" = "$self" ] && continue
  case "$file" in "$testdir"*) continue ;; esac
  for p in "${patterns[@]}"; do
    while IFS= read -r m; do
      echo "channels: forbidden channel in $file: $m" >&2
      fail=1
    done < <(grep -nE "$p" "$file" 2>/dev/null)
  done
done < <(git ls-files host dev-container shared .github)

exit "$fail"
