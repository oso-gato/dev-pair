# 000015 — C12: parallel by independence

- status: accepted
- date: 2026-08-17

## Problem

The maintainer directed a standing rule: parallelise autonomous work wherever tasks are independent, serialise only where dependencies force order, and never let speed buy past quality. The placement question was live: conduct rules had precedent in AGENTS.md (the writing style, 000005), but AGENTS.md is agent-maintained — any session can edit it without maintainer confirmation. A rule protecting quality against speed deserves a lock.

## Decision

1. The law is universal constitution **C12 — PARALLEL BY INDEPENDENCE**, in its own closing group: work planned so independent tasks fan out and dependencies alone impose order; `tasks.md` declares the dependencies so the plan shows what may run concurrently; every parallel result passes the same gates as if it had run alone; needless serialisation is a reviewable defect.
2. AGENTS.md — dev-pair's and the genesis template — carries the session-loaded operational echo with a (C12) pointer, on the B4 pattern: law locked in one home, echo where every session starts.

## Options considered

- AGENTS.md only (the style precedent) — rejected on the lock-level argument: agent-editable surfaces hold standing practice, not standing law; the maintainer's word was "law".
- A bylaw rule — rejected: nothing repo-specific about it; it binds every repo's sessions.

## Consequences

The analyze gate and any review can now check a decomposition against C12 mechanically: dependencies declared, independence honoured, gates unweakened. The constitution takes its fourth amendment of the day.
