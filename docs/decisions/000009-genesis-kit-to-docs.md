# 0009 — Genesis kit moves to docs/; component folders hold code only

- status: accepted (amends 0004's template home)
- date: 2026-08-16

## Problem

The genesis kit lived at `shared/templates/repo-genesis/` on the rationale "both components use it." That conflated two kinds of use: what runs or is machine-consumed at runtime (code, scripts, the R3 contracts) versus what an agent reads and copies at repo-creation time (a manual and its templates). Reference material was wearing a component's address.

## Decision

1. The genesis kit lives at `docs/repo-genesis/` — permanently and unconditionally. It is a placeholder folder-and-file structure for every new repo the pair creates: documentation, not machinery.
2. The boundary sharpens into scannable law (P1): **component folders hold code and scripts only; anything read-and-copied is documentation.** `shared/` in every shape is contracts and code both sides genuinely use — never templates.
3. P1 gains the governed valve: beyond the two records, `docs/` holds only documentation assets the repository owns, each a named subfolder recorded in `ARCHITECTURE.md`.

## The road not travelled

A "when genesis becomes a script, co-locate templates with the tool" trigger was proposed and withdrawn on self-examination: the co-location convention applies to distributed packages, and nothing in the estate is distributed — a future script would read from the documented home, and relocating templates beside it would move documentation authority into a component folder, violating rule 2. Honest projection: a genesis script likely never exists at all — automating what agents already do reliably fails P3's gate test.

## Consequences

`shared/` is empty until the R3 contracts return with the component tree. AGENTS.md and ARCHITECTURE.md pointers updated; universal P1 amended (fourth amendment). Frozen records keep the old path.
