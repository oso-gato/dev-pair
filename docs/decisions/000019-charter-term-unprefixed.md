# 000019 — The charter, unprefixed

- status: accepted
- date: 2026-08-17

## Problem

The collective term for the two initiation artifacts was coined as "00-charter", carrying the files' sort prefix into running prose. The prefix earns its place in filenames — it sorts the artifacts first and wears their provenance (000008) — but in prose it is noise: the term reads as a filename fragment rather than a name, and the objective's own boundary clauses fell back to the vaguer "the `00-` artifacts" instead of using the term at all.

## Decision

Maintainer-instructed. The term is **charter**, bare, and it refers to exactly one thing: the two initiation artifacts — `00-OBJECTIVE.md` and `00-BYLAW.md` — collectively, as confirmed. Filenames keep the `00-` prefix; only the prose term drops it. The "the `00-` artifacts" circumlocutions are replaced by the term, so every reference to the pair of files now goes through one name.

## Options considered

- Keep "00-charter" — rejected by the maintainer: the prefix is a sort mechanism, not part of the name.
- Rename the files to match the bare term — not considered seriously; the initiation prefix (000008) does real work in the tree and the term change costs nothing.

## Consequences

Live surfaces swept in the same change, in both repositories: here, the objective (definition and every reference, including the two boundary clauses), the bylaw's Authority, and AGENTS.md; in `homelab-root`, universal C11 with its amendment trail, the genesis manual, and the AGENTS and BYLAW templates — so every future repository is born with the bare term. Frozen records (the changelog's earlier entries, ADR 000014) keep the coined "00-charter", the same term under this record's equivalence.
