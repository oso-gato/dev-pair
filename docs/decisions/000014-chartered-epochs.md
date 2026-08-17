# 000014 — Chartered epochs: the named, protected baseline

- status: accepted
- date: 2026-08-17

## Problem

The fedora-dev and fedora-bootstrap era proved agents can wreck a repository badly enough that the maintainer needs a way back — and a non-programmer maintainer cannot be expected to remember commit hashes or version numbers. The confirmed pre-build state (pure law, nothing built) had no durable, named, mess-proof anchor.

## Decision

1. The confirmed 00-charter state is locked as two tags, per the floating-name-plus-immutable-epochs pattern: the dated epoch `chartered-YYYY-MM-DD`, never moved or deleted, and the floating `chartered`, always pointing at the newest epoch, moving only on a new maintainer confirmation of the 00-charter.
2. A GitHub Release wraps the epoch — a clickable object on the repo's front page and a tarball snapshot that exists outside git history entirely.
3. A tag-protection ruleset armours both: epochs immutable to everyone; the floating name movable by the maintainer alone.
4. Restoration is by name, never by number. Revert is the default — the mess stays visible as record, then is undone; reset, which erases, is a maintainer-only act.
5. The law is universal (C11 amendment); the mechanics are a genesis step, so every future repo is born with its anchor before its first line of code.
6. The tag is named `chartered`, not `charter`: the 00-charter is the artifact pair; `chartered` is the state its confirmation produced — one word, one meaning.

## Options considered

- Tagging homelab-root too — rejected by maintainer ruling: the estate root is not a built repo; it is the living registry and credential vault, whose facts must keep moving, and whose protection is privacy plus maintainer-merge-only law, not frozen baselines.
- A single movable `chartered` tag with no dated epochs — rejected: advancing the name would orphan every prior baseline.
- Branch-based checkpoints — rejected: branches invite commits; a baseline is a point, not a line.

## Consequences

Dev-pair's HEAD at this commit becomes `chartered-2026-08-17` and `chartered`. AGENTS.md (and the genesis template) carry the recovery line, so no session needs git knowledge to find the way back. Restoring to `chartered` discards nothing from history under the revert default — the record of the mess survives its own undoing.
