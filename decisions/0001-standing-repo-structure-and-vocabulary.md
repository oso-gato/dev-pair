# 0001 — Standing repo structure and vocabulary

- status: accepted
- date: 2026-08-16

## Problem

The rebuilt repository needed a documentation structure agents reliably load, and a vocabulary without collisions. Measured failures: past agents forgot the pair's three-part architecture and its renewal chain; "lineage" meant three different things (vendor tooling, host heritage, bootc build).

## Decision

1. Documentation surfaces, exactly: README, `spec.md`, `constitution.md`, `AGENTS.md` (session-loaded operating manual), `ARCHITECTURE.md` (current-state map), `decisions/` (ADRs), `CHANGELOG.md`. Nothing else accretes (P9).
2. Naming follows GitHub Spec Kit convention: `spec.md`, `constitution.md`.
3. Vocabulary: **lineage** = a dev pair, named by its host (`erebus`, `strix`). Each agent box runs one **agent** (claudebox → Claude Code, kimibox → Kimi Code). The self-improvement chain is **self-renewal** (P12). **Admission manifest** replaces "lineage manifest".
4. Tickets carry two stamps — pair and agent — so wrong-pair and wrong-agent pickup are both impossible.

## Options considered

- `ARCHITECTURE.md` vs `DESIGN.md` — ARCHITECTURE.md chosen (industry convention).
- A bespoke "runtime law" document — rejected: its role is `AGENTS.md` under the open standard; a fourth locked document failed minimalism (P3).
- `docs/adr/` nesting — rejected: the surfaces above are the whole documentation inventory; root `decisions/` is shallower.
- "make" / "master agent" for the vendor dimension — rejected for plain **agent**.

## Consequences

Every session loads AGENTS.md, so the three-part architecture and renewal chain cannot be forgotten. The spec needed six matching edits (agent-layer paragraph, erebus rename, ship-gate wording, multi-box law, strix wording, file rename). The universal/repo-specific split of the constitution remains open; classifications so far: P4, P8, P10, P11 universal · P5, P6, P7, P12 pair-specific · P1–P3, P9 pending.
