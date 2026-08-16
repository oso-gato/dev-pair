# 0006 — BYLAW.md surface; "constitution" made univocal

- status: accepted
- date: 2026-08-16

## Problem

"Constitution" meant two different documents — the universal law in the estate root, and each repo's pull-plus-repo-specifics — the same one-word-two-meanings disease as the earlier spec.md collision. Repo-specific principles (R-numbered) had no home of their own.

## Decision

1. "Constitution" means exactly one thing estate-wide: the universal law. Each repo's `constitution.md` is only that law's presence — the by-reference statement and a session-start fetch line, nothing else. The reference mechanism is thereby swappable (pointer → submodule → vendored copy) without touching any other surface.
2. Repo-specific principles and instantiations live in `BYLAW.md` — singular, matching OBJECTIVE.md; uppercase, no tool consumer. The term is governance's own: bylaws are local rules subordinate to a constitution, valid only where they do not conflict. Always present in the skeleton; "None" is a valid, stated entry.
3. The universal constitution's P1 surface list and P2 skeleton admit the new surface — the first post-confirmation amendment, made as a new maintainer confirmation.

## Options considered

- Repo-specific principles into OBJECTIVE.md — rejected: breaks the WHY/HOW boundary both documents legislate; no best-practice support (specs never carry engineering law).
- Constitution as a git submodule — parked, not rejected: submodules mount whole repositories only (no single-file submodule), so it requires either extracting the principles into a dedicated repo or accepting a whole-tree mount of the private root (trust-root included) into every authorized recursive clone. The thin-pointer constitution.md keeps this door open at zero cost.
- `build_principles.md` as the name — rejected for `BYLAW.md`: the governance term encodes the subordination hierarchy the literal name doesn't.

## Consequences

Dev-pair's R1–R4 and instantiations moved verbatim to BYLAW.md. Genesis gained a BYLAW template and a thinner constitution template. Live surfaces updated (AGENTS.md, README, ARCHITECTURE.md, genesis manual). BYLAW.md joins the maintainer-merge-only set.
