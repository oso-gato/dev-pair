# 0003 — Adopt Spec Kit's per-ticket method; root lock renamed OBJECTIVE.md

- status: accepted
- date: 2026-08-16

## Problem

The repo-level lock had been named `spec.md` "per Spec Kit convention" — but in Spec Kit, `spec.md` is always per-feature (`specs/<NNN-slug>/spec.md`); the kit has no repo-level spec at all. Adopting the kit's per-ticket flow would have created two files named `spec.md` with different authority: one locked, one working.

## Decision

1. The root lock is `OBJECTIVE.md` — a name the kit doesn't claim, uppercase per P13 (no tool consumer). Same for every project the pair builds.
2. Per-ticket work adopts Spec Kit verbatim: `specs/<NNN-slug>/spec.md`, `plan.md`, `tasks.md`; NNN is the GitHub issue number. Stages: specify → plan → tasks → analyze → implement.
3. Deviation, deliberate: the kit's `/clarify` (mid-flow human questioning) folds into the one initiation session — the objective's single-interaction law forbids a mid-loop human summons (P10).
4. `specs/` folders merge to main and are kept, kit-faithful, frozen at ship; a change to the feature is a new ticket.
5. Division against `decisions/`: a decision stays in `plan.md` while ticket-scoped; it graduates to an ADR when it binds beyond its ticket, and the plan points to it.

## The road wrongly travelled

Recorded per P9. The root lock was first renamed to `spec.md` on the mistaken claim that this matched the kit; an interim proposal then renamed the kit's own artifacts (`requirements.md`) to dodge the self-inflicted collision. Both reversed here. A second misreading — that the throwaway doctrine forbade keeping merged `specs/` folders — was corrected by scoping P5 to build state on the pair's components; repository content is governed by P9 and P13, and the objective's immutability clause gained "on the pair's components" to close the ambiguity.

## Consequences

P5 gained an explicit scope paragraph. P9's surface list and P13's skeleton admit `specs/`. AGENTS.md carries the working method. "Spec" now means exactly one thing in any repo of the platform: a per-ticket specification.
