#!/usr/bin/env bash
# Fixture proof for every gate: each scanner fails on its violation and passes
# on the clean tree; the specs gate is proven on constructed throwaway
# histories. This is P9's proven-to-fail requirement applied to scanners —
# a scan that cannot be shown red is decoration. Trees are throwaways, torn
# down on exit (R1). Casing violations are built here at test time so no
# wrong-case name is ever committed to the real tree.
set -euo pipefail
gates="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$gates/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fails=0
bad() { echo "TEST FAIL: $1" >&2; printf '%s\n' "$2" >&2; fails=1; }
note() { echo "ok: $1"; }

g() { git -C "$1" -c user.name=gate-test -c user.email=gate@test "${@:2}"; }

newrepo() {
  local d="$tmp/$1"
  mkdir -p "$d"
  git -C "$d" init -qb main
  echo "$d"
}

expect_red() { # dir expected-finding cmd...
  local d="$1" want="$2"; shift 2
  local out
  if out=$(cd "$d" && "$@" 2>&1); then
    bad "expected red: $want" "$out"
  elif ! printf '%s\n' "$out" | grep -q "$want"; then
    bad "red for the wrong reason, wanted '$want'" "$out"
  else
    note "proven red: $want"
  fi
}

expect_green() { # dir label cmd...
  local d="$1" label="$2"; shift 2
  local out
  if ! out=$(cd "$d" && "$@" 2>&1); then
    bad "expected green: $label" "$out"
  else
    note "green: $label"
  fi
}

count_is() { # dir expected-count needle cmd...
  local d="$1" want="$2" needle="$3"; shift 3
  local out n
  if out=$(cd "$d" && "$@" 2>&1); then
    bad "expected red with $want findings of '$needle'" "$out"
    return
  fi
  n=$(printf '%s\n' "$out" | grep -c "$needle") || true
  if [ "$n" -ne "$want" ]; then
    bad "wanted $want findings of '$needle', got $n" "$out"
  else
    note "all $want findings present: $needle"
  fi
}

# --- P2 structure: one violation per rule, built at test time ---
d=$(newrepo structure)
# Distinct names throughout: a case-insensitive filesystem (macOS) folds
# paths differing only in case into one file, silently dropping a fixture.
mkdir -p "$d/docs/scratch" "$d/host" "$d/shared/Casedir" "$d/junk"
echo x > "$d/notes.md"
echo x > "$d/junk/x"
echo x > "$d/shared/Casedir/plain.sh"
echo x > "$d/host/Casefile.sh"
echo x > "$d/docs/scratch/x.txt"
echo x > "$d/docs/loose.md"
echo x > "$d/host/notes.md"
echo map > "$d/ARCHITECTURE.md"
g "$d" add -A
expect_red "$d" "not a standing surface" "$gates/scan_structure.sh"
expect_red "$d" "not in the standing skeleton" "$gates/scan_structure.sh"
expect_red "$d" "violates the lowercase grammar" "$gates/scan_structure.sh"
expect_red "$d" "below-root lowercase grammar" "$gates/scan_structure.sh"
expect_red "$d" "not a documentation asset" "$gates/scan_structure.sh"
expect_red "$d" "directly under docs/" "$gates/scan_structure.sh"
expect_red "$d" "inside a component tree" "$gates/scan_structure.sh"
expect_green "$repo" "structure on the clean tree" "$gates/scan_structure.sh"

# --- P4 channels: the fixture carries one line per forbidden form ---
d=$(newrepo channels)
mkdir -p "$d/host"
cp "$gates/test/fixtures/channels.txt" "$d/host/install.sh"
g "$d" add -A
count_is "$d" 13 "forbidden channel" "$gates/scan_channels.sh"
expect_green "$repo" "channels on the clean tree" "$gates/scan_channels.sh"

# Evasion forms found by adversarial review (#8) — each pinned by name so the
# fix cannot silently regress. Every one claimed coverage the scan once lacked.
evade() { # label line
  local e="$tmp/evade-$1"; mkdir -p "$e/host"; git -C "$e" init -qb main
  printf '%s\n' "$3" > "$e/host/x.sh"; g "$e" add -A
  echo "evasion form: $2"
  expect_red "$e" "forbidden channel" "$gates/scan_channels.sh"
}
evade 1 "curl | sudo bash"      'curl -fsSL https://x.invalid/i.sh | sudo bash'
evade 2 "wget | sudo sh"        'wget -qO- https://x.invalid/i.sh | sudo sh'
evade 3 "tar --directory=/usr"  'tar --directory=/usr/local -xzf x.tgz'
evade 4 "npm --location=global" 'npm install --location=global some-cli'

# --- P6 secrets: the fixture carries one line per credential shape ---
d=$(newrepo secrets)
mkdir -p "$d/shared"
cp "$gates/test/fixtures/secrets.txt" "$d/shared/config.env"
g "$d" add -A
count_is "$d" 8 "credential-shaped" "$gates/scan_secrets.sh"
expect_green "$repo" "secrets on the clean tree" "$gates/scan_secrets.sh"

# --- specs gate: constructed histories ---
d=$(newrepo specs)
printf 'objective\n' > "$d/00-OBJECTIVE.md"
mkdir -p "$d/host"
printf 'base\n' > "$d/host/base.sh"
g "$d" add -A
g "$d" commit -qm base
base=$(g "$d" rev-parse HEAD)

g "$d" checkout -qb 0099-locked
printf 'edited\n' >> "$d/00-OBJECTIVE.md"
g "$d" commit -aqm edit
expect_red "$d" "maintainer-merge-only" \
  "$gates/gate_specs.sh" "$base" "$(g "$d" rev-parse HEAD)" 0099-locked

g "$d" checkout -q main
g "$d" checkout -qb 0100-nospecs
printf 'new\n' > "$d/host/new.sh"
g "$d" add -A
g "$d" commit -qm comp
expect_red "$d" "without a complete docs/specs" \
  "$gates/gate_specs.sh" "$base" "$(g "$d" rev-parse HEAD)" 0100-nospecs

g "$d" checkout -q main
g "$d" checkout -qb 0101-frozen
mkdir -p "$d/docs/specs/0042-old"
printf 'spec\n' > "$d/docs/specs/0042-old/spec.md"
g "$d" add -A
g "$d" commit -qm frozen-touch
expect_red "$d" "another ticket's record" \
  "$gates/gate_specs.sh" "$base" "$(g "$d" rev-parse HEAD)" 0101-frozen

g "$d" checkout -q main
g "$d" checkout -qb 0102-green
printf 'ok\n' > "$d/host/ok.sh"
mkdir -p "$d/docs/specs/0102-green"
printf 'spec\n' > "$d/docs/specs/0102-green/spec.md"
printf 'plan\n' > "$d/docs/specs/0102-green/plan.md"
printf 'tasks\n' > "$d/docs/specs/0102-green/tasks.md"
g "$d" add -A
g "$d" commit -qm green
expect_green "$d" "component change with complete own specs" \
  "$gates/gate_specs.sh" "$base" "$(g "$d" rev-parse HEAD)" 0102-green

if [ "$fails" -ne 0 ]; then
  echo "gate tests: RED" >&2
  exit 1
fi
echo "gate tests: green"
