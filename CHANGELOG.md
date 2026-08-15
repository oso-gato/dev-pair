# Changelog

Curated notable changes and incident narrative. Newest first.

## 2026-08-16

- P1–P3 rewritten under maintainer review, completing the P1–P13 pass: kernels separated from OS instantiations (P1 ladder, P3 weak-deps flag); P2 now names its live exemplars (the vendoring trail, the environment registry).
- Repo-genesis template set shipped (ticket #6, the method's first exercise): `shared/templates/repo-genesis/` — standing-surface templates, the three-shape manual, Spec Kit ticket templates vendored at v0.16.4. See decisions/0004.
- Spec Kit per-ticket method adopted (specify → plan → tasks → analyze → implement; `specs/<NNN-slug>/`, kept on main, frozen at ship); root lock renamed `spec.md` → `OBJECTIVE.md` to end the name collision; P5 scoped to build state; clarify folded into the initiation session. See decisions/0003.
- P13 added: the standing repo structure (skeleton tree, shape adaptation, filename-casing contracts) made law; README layout law now points at it. See decisions/0002.
- Governing documents renamed to Spec Kit convention: `spec.md` (was `00-OBJECTIVES.md`), `constitution.md` (was `00-BUILDPRINCIPLE.md`). Spec now opens with the twofold objective.
- Constitution finalised under maintainer review: P4–P11 rewritten, P12 (self-renewal) added, no-theatrical-machinery rationale added to the preamble.
- Vocabulary fixed: lineage = a dev pair named by its host (`erebus`, `strix`); each agent box runs one agent; tickets stamped pair + agent; "admission manifest" replaces "lineage manifest".
- Standing documentation surfaces adopted: `AGENTS.md`, `ARCHITECTURE.md`, `decisions/`, `CHANGELOG.md`. See decisions/0001.

## 2026-08-15

- Repository reset to the two governing documents; README added.
