# 0005 — Constitution split: universal P1–P11 and repo-specific R1–R4

- status: accepted
- date: 2026-08-16

## Problem

One constitution braided two kinds of law: universal principles binding every repository in the estate, and this pair's own mechanisms and instantiations. New repos could not pull the universal set without dragging pair machinery along, and the ordering was historical accretion, not merit.

## Decision

1. The universal constitution lives at `principles/constitution.md` in the estate's root repository — P1–P11, applied by reference from every repo's `constitution.md`, never re-dictated. Bare P-numbers estate-wide refer to it.
2. This repository's constitution reduces to the pull, four repo-specific principles (R1–R4), and the instantiations it owns (the Fedora provenance ladder and forbidden channels; the weak-deps flag; the two host lineages and their deploy mechanisms). The lineage bullet also corrects the bare-metal machine to the Minisforum MS-S1 MAX, registry-consistent.
3. Ordering is zero-base, merit-only: remember → embody → justify → source → verify → withhold trust → run immutable → except the agent → prove → verify independently → recover. Every cross-reference points backward; a linear read meets no concept before its definition.
4. Two principles were added on audit: P6 (least privilege, secrets at runtime only) and P10 (distrust made structural, elevated from this repo's objective — the objective's bullets now carry pointers). One extension: P11 gains the restore-proven clause for durable state.
5. Audited and rejected, on the record: observability as a standalone principle (one clause folded into P10); a universal bounded-storage principle (stays in R1 until a second repo needs it); licensing/compliance (no consumer in a single-maintainer private estate); style law (lives in AGENTS.md and templates).

## Number mapping (pre-split → post-split)

P1→P4 (kernel; ladder and forbidden list → instantiation) · P2→P5 · P3→P3 (flag → instantiation) · P4→P7 (doctrine; lineages → instantiation) · P5→R1 · P6→R2 · P7→R3 · P8→P9 · P9→P1 · P10→P11 · P11→P8 · P12→R4 · P13→P2. New without predecessor: P6, P10. Frozen records (ADRs 0001–0004, specs/, changelog history) cite their epoch's numbers; read them through this mapping.

## Retired provenance note (was the constitution's closing memoir)

Mapping to the fleet's BP1–BP9, preserved here per P1's memoir rule: P1=BP1 (strengthened: one fetch contract; repo-metadata signatures) · P2=BP2 (strengthened: environment/release re-verification; adoption trail) · P3=BP3 (extended: gates-are-features, activation-proof, no-standing-red) · P4=BP4 (amended: container immutability made explicit; two host lineages named) · P5=BP5 (recast as the pair's build-and-validation mechanism) · P6=BP6 (strengthened: harness sites named) · P7=BP7 (rescoped as the pair's own protocol) · P8=BP8 (extended: mutation-proven; merge gate) · P9=BP9 (recast: one home + decision record; vendoring clause re-homed to the layout law) · P10, P11, P12, P13 = new in the 2026-08 review (recovery, agent layer, self-renewal, standing structure). All numbers in this paragraph are the pre-split epoch's.

## Consequences

New repos pull exactly the universal law via the genesis template, which now links the real home. Live surfaces renumbered (AGENTS.md, README, genesis templates, ARCHITECTURE.md, the objective's pointers). The two constitutions and the objective remain DRAFT pending maintainer confirmation — confirmation now covers three documents.
