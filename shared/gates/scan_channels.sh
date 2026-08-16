#!/usr/bin/env bash
# P4 channel scan: the bylaw's forbidden channels, mechanically, over the
# component trees and .github. Fails on: curl/wget piped to a shell — directly
# or through a wrapper like sudo or env; COPR; flatpak; snap install; global
# npm (-g, --global, --location=global), pip, gem, cargo installs; tar
# extraction into a system path (-C or --directory into /usr /bin /lib /opt
# /etc /sbin). Excludes exactly two paths, stated here: this file (its pattern
# list would match itself) and `shared/gates/test/fixtures/` (violation strings
# by design, proven by the tests instead). The test harness itself is NOT
# excluded — it holds no literal violation string, sourcing its payloads from
# the fixtures — so a real violation added anywhere under test/ outside
# fixtures/ is still caught.
# Not covered (adversarial review): mirror and aggregator binaries, obfuscated
# fetch-and-execute, case-variant CLI names, provenance grades within
# sanctioned channels.
set -euo pipefail
cd "${1:-.}"

self="shared/gates/scan_channels.sh"
fixtures="shared/gates/test/fixtures/"

patterns=(
  # curl/wget piped to a shell that is the command immediately after the pipe,
  # optionally behind wrappers (sudo, env, …). Anchored so a benign pipeline
  # that merely mentions a shell name or a .sh path later (| tee x.sh,
  # | grep bash-completion, | ssh host) does not false-positive.
  '(curl|wget)[^|;&]*\|[[:space:]]*((sudo|env|command|exec|nice|nohup|time)[[:space:]]+([A-Za-z0-9_=/.:-]+[[:space:]]+)*)*\b(ba|z|da|k)?sh\b'
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
  case "$file" in "$fixtures"*) continue ;; esac
  for p in "${patterns[@]}"; do
    while IFS= read -r m; do
      echo "channels: forbidden channel in $file: $m" >&2
      fail=1
    done < <(grep -nE "$p" "$file" 2>/dev/null)
  done
done < <(git ls-files host dev-container shared .github)

exit "$fail"
