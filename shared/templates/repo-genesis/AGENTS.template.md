# AGENTS.md — operating manual for agents in this repository

Read this first, every session.

## Governance

- [OBJECTIVE.md](OBJECTIVE.md) — WHY, locked, maintainer-merge-only.
- [CONSTITUTION.md](CONSTITUTION.md) — the universal law, by reference; load it at session start via its fetch line.
- [BYLAW.md](BYLAW.md) — this repo's build principles and instantiations, locked, subordinate to the constitution.
- [ARCHITECTURE.md](ARCHITECTURE.md) — current-state map; update it in the same change that alters a fact.
- [docs/decisions/](docs/decisions/) — ADRs for decisions that bind beyond one ticket; append-only, superseded not edited.
- [CHANGELOG.md](CHANGELOG.md) — notable changes and incidents.

## Working method

Per ticket: **specify → plan → tasks → analyze → implement.** `docs/specs/<NNN-slug>/spec.md`, `plan.md`, `tasks.md` — NNN is the GitHub issue number; folders merge to main and are frozen at ship; a change is a new ticket. Clarification happens only at initiation — never a mid-loop human summons. A decision stays in `plan.md` while ticket-scoped; it graduates to `docs/decisions/` when it binds future tickets.

## Build & test

{{commands, as they come into existence — keep current}}

## Boundaries

{{repo-specific never-touch list}}
