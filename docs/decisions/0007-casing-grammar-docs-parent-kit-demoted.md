# 0007 — Casing grammar; docs/ records parent; Spec Kit demoted to donor

- status: accepted (amends 0002, 0003, 0004)
- date: 2026-08-16

## Problem

Two prior decisions rested on GitHub Spec Kit being a potential tool consumer: lowercase `constitution.md` / root `specs/` (its layout), and the CLI door held open (ADR 0004). The maintainer supplied the fact only he could: he does not drive CLIs — he vibe-codes through agents, and the pair *is* the workflow the kit scaffolds for humans. The kit will never run here.

## Decision

1. Spec Kit is demoted from consumer to **donor**: its templates and stage discipline are harvested and pinned (VENDORED.md stands); its CLI, slash commands, and path expectations bind nothing. The specify → plan → tasks → analyze → implement method is unchanged — it is the estate's own law now.
2. Casing becomes a grammar: **every root file uppercase, every directory lowercase** — component folders (`host/`, `dev-container/`, `shared/`) included; working files below root (per-ticket `spec.md`, `plan.md`, `tasks.md`) lowercase. `constitution.md` → `CONSTITUTION.md` everywhere, including the universal home (`principles/CONSTITUTION.md`). `AGENTS.md` remains the one tool contract.
3. The two record directories move under one parent: `docs/decisions/` (the MADR-standard home) and `docs/specs/`. Root is now uniformly: uppercase governance files + `docs/` + the component tree.

## Options considered

- Keep root `specs/` for future CLI compatibility — rejected: the consumer is now known never to arrive; a contract with a counterparty that will never call is dead law.
- Uppercase the per-ticket files too — rejected: the uppercase rule is a root convention; below root, lowercase working files read as working files.

## Consequences

All live surfaces updated (P1 list, P2 skeleton and casing law, AGENTS.md, README, ARCHITECTURE.md, BYLAW R1, genesis manual and templates, the fetch line). Frozen records keep their epoch's paths. This supersedes ADR 0002's tool-contract casing rationale for the kit's files, ADR 0003's "exact layout" clause, and ADR 0004's open CLI door.
