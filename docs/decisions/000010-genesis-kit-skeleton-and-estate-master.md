# 0010 — Genesis kit: skeleton mirror, master in the estate root, no committed mirror

- status: accepted (amends 0009's location; completes 0004's genesis home)
- date: 2026-08-16

## Problem

Three defects, maintainer-caught. The kit's flat interior contradicted the `docs/` structure it teaches (drift from ticket #6, which predates ADRs 0007/0009). The per-ticket templates lived only in this repo, so future repos would have to reach back here for their own working method. And the kit had no permanent estate home — with master-versus-mirror undecided.

## Decision

1. **Skeleton mirror.** The kit's templates live in `skeleton/`, a literal mirror of the output tree — including `docs/decisions/0000-adr.template.md` and `docs/specs/` ticket templates, so every repo is born self-sufficient (the MADR convention: the template beside the records it shapes). Instantiation is copy, strip `.template`, fill — no mapping table.
2. **Master: the estate root**, at `genesis/` — the kit is universal P2's instantiable form and belongs beside the law it instantiates, as the estate root's fourth section. Kit changes are amendment-work, maintainer-merge-only, not loop tickets.
3. **No committed mirror anywhere.** Access ≠ residence: the pair reaches the estate root by authentication, as the constitution's fetch line proves each session. At each genesis the kit is fetched fresh into a throwaway tree, used, and torn down (R1's discipline applied to templates). A committed mirror would force P1's bad pair: a sync checker (machinery managing machinery — P3 refuses) or drift.

## Roads not travelled

- `shapes/` placeholder trees (single/pair/swarm holding only READMEs) — killed by P1 (a second home for what the manual's diagrams already state) and P3 (copied empty directories evaporate at first commit; no outcome changed). Shapes stay documented once, in the manual.
- A genesis script with co-located templates — withdrawn in 0009; co-location serves distributed packages, and nothing in the estate is distributed.

## Consequences

`docs/repo-genesis/` removed from this repo (its git history remains here as the kit's build record); AGENTS.md carries the fetch-fresh pointer; the estate root README gains the fourth section. Frozen records keep old paths.
