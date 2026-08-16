# 0002 — Structure into law; filename casing as tool contracts

- status: accepted
- date: 2026-08-16

## Problem

The standing repo skeleton existed only in conversation and, partially, in the README — law living in a chat transcript. Separately, the mixed filename casing (`spec.md`/`constitution.md` lowercase; `AGENTS.md`/`ARCHITECTURE.md`/`CHANGELOG.md`/`README.md` uppercase) looked arbitrary and was questioned.

## Decision

1. The full skeleton is law: constitution P13 — documentation surfaces invariant; the component tree adapts to runtime shape (single artifact · host + container · container swarm); `shared/` only with two or more components; no fourth place.
2. Casing is a per-consumer contract, not a style. `spec.md` and `constitution.md` match GitHub Spec Kit; `AGENTS.md` matches the agents.md standard — the hosts run case-sensitive filesystems, so a wrong-case name is an undiscovered file. README, ARCHITECTURE, and CHANGELOG have no tool consumer; they keep the classic uppercase root convention.

## Options considered

- Uppercasing `SPEC.md`/`CONSTITUTION.md` for visual uniformity — rejected: breaks Spec Kit matching on case-sensitive filesystems.
- Lowercasing everything — rejected: breaks `AGENTS.md` discovery by agent CLIs; gains nothing that matters.

## Consequences

README's layout law shrank to this repo's instantiation plus a pointer to P13. Future repos start from P13's skeleton with the shape decided at initiation.
