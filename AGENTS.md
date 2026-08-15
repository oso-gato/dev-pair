# AGENTS.md — operating manual for agents in this repository

Read this first, every session.

## The pair is three parts

1. **The GitHub ticket bus** — issues and PRs. Every hand-off between components travels here; nothing durable lives only in a container or a layer.
2. **The host** — operates the platform, validates what the container cannot (tier-2), opens PRs only. It never merges.
3. **The dev-container** — develops and validates (tier-1); the sole merge authority — except `OBJECTIVE.md` and `constitution.md`, which are maintainer-merge-only.

## Standing law

- [OBJECTIVE.md](OBJECTIVE.md) — WHY, locked. [constitution.md](constitution.md) — HOW, locked. Read both before structural work.
- [ARCHITECTURE.md](ARCHITECTURE.md) — the current-state map. Update it in the same change that alters a fact; a stale map is a blocking finding (P9).
- [decisions/](decisions/) — record every non-obvious decision as an ADR: problem, options, choice, fate. Reverse by superseding record, never by edit.
- [CHANGELOG.md](CHANGELOG.md) — notable changes and incident narrative.

## Self-renewal — never forget this

A maintainer-instructed improvement merges → the host brings itself to the merged state → the host rebuilds and relaunches the dev-container from outside → every session is restored. The dev-container never rebuilds itself — it requests renewal, its own or the host's, through the ticket bus. (constitution P12.)

## Working method

Per work unit (one ticket), the loop runs **specify → plan → tasks → analyze → implement**:

1. `specs/<NNN-slug>/spec.md` — what this ticket must do; NNN is the GitHub issue number. (For a whole project, the locked `OBJECTIVE.md` plays this role.)
2. `specs/<NNN-slug>/plan.md` — the design that serves it.
3. `specs/<NNN-slug>/tasks.md` — the decomposition to iterate through.
4. Analyze — a read-only consistency check across spec, plan, and tasks before implementing.
5. Implement, validate, iterate — two tiers, per the objective.

Clarification happens once, in the project's initiation session — never as a mid-loop human summons (P10). Spec folders merge to main and are frozen at ship; a change to the feature is a new ticket. A decision stays in `plan.md` while it binds only its ticket; the moment it binds future tickets it graduates to `decisions/` and the plan points to it.

## Ticket routing

Every ticket carries two stamps: its **pair** (the lineage, named by host: `erebus`, `strix`) and its **agent** (`claudebox` = Claude Code, `kimibox` = Kimi Code). Pick up a ticket only when both stamps match your box. (P11.)

## Session conduct

- Author and build only in your session's isolated, namespaced worktree; re-verify branch ownership before every commit and push (P6).
- Builds are throwaways cut from throwaway trees — never from a live tree (P5).
- No mutable out-of-band change to any deployed artifact, host or container (P4).
- No mechanism without a real outcome it changes; no test that asserts a mock; no gate without recovery (preamble, P3, P8, P10).
