# Changelog

Curated notable changes and incident narrative. Newest first.

## 2026-08-17

- Epoch timestamps set to Hong Kong time, UTC+8 (000017); the UTC-named epoch grandfathered.
- Epoch names timestamped to the minute, UTC (chartered-YYYY-MM-DD-HHMM); pre-grammar names grandfathered. See docs/decisions/000016.
- C12 (parallel by independence) added to the universal constitution, with the session-loaded echo in AGENTS.md and the genesis template: independent tasks fan out, dependencies alone impose order, parallel results pass the same gates. See docs/decisions/000015.
- Chartered epochs adopted (C11 amendment): the confirmed pre-build state locked as the protected dated epoch `chartered-2026-08-17` with the floating `chartered` atop it — restore by name, never by number; revert default, reset maintainer-only; every future repo born with its anchor via the genesis step. See docs/decisions/000014.
- Citation letters renamed: P→C and R→B, numerals unchanged (P≡C, R≡B); record numbering widened to six digits for decisions and specs, existing files renamed with contents untouched — the measured burn rate on the prior fleet justified the width. See docs/decisions/000013.
- The credential vault decided (maintainer, overruling the agent's recommendation — on record): live credentials rest only in the private estate root; universal P6 amended with the scoped exception; the trust root fixed as all published `oso-gato` SSH keys, consumed live, with a dated snapshot in the vault. See docs/decisions/0011.
- 00-charter amended: the no-root outcome added to Security outcome 2 (the admin is `core`, sudo-by-password, root never authenticates remotely after genesis); both lineages gained their day-zero contracts in the bylaw — the VPS's one pasted script that builds and retires root, bare metal's activation-only act injecting just the live credentials.

## 2026-08-16

- AGENTS.md restructured zero-base into session-lifecycle order (load → orient → work → route → renew → charter → record → write → conduct → build); the silence policy added to the working method, Build & test added honestly empty; the genesis AGENTS template aligned, with the pair-only sections (self-renewal, chartering) deliberately absent.
- Objective amended: the **00-charter** coined (the two initiation artifacts as one term); Delivery added to the workflow (a report, never a request); the silence and halt policies stated; the After-ship rule added (in-scope tickets flow, scope changes amend the 00-charter first); "no second interaction" sharpened to "no second approval".
- Objective rewritten under maintainer confirmation, ~45% shorter: post-split re-dictation of P3/P7/P8/P10 removed, environment facts moved to registry pointers, the pair aligned to three parts, both `00-` initiation artifacts named in the workflow, meta-sections merged into one Authority. No outcome dropped.
- Universal constitution shortened ~25%, expression-only (fifth amendment): the P1/P2 surface duplication removed, the stale vendoring-trail pointer fixed to the Provenance note, the amendment trail compacted; no rule changed.
- Genesis kit restructured to a literal `skeleton/` mirror (per-repo ADR and ticket templates included — every repo born self-sufficient) and re-homed to the estate root's `genesis/` as master; no repo keeps a committed copy — throwaway fetch at each genesis. See docs/decisions/0010.
- Genesis kit moved `shared/templates/` → `docs/repo-genesis/`; component folders now hold code and scripts only, with P1's docs/ asset valve admitting repo-owned documentation. See docs/decisions/0009.
- `00-` initiation prefix adopted: `00-OBJECTIVE.md` and `00-BYLAW.md` — the two artifacts co-created with the maintainer in the initiation session — sort first and wear their provenance; constitution stays pulled, the rest agent-generated. See docs/decisions/0008.
- Casing grammar adopted (root files uppercase, directories lowercase): `CONSTITUTION.md` everywhere including the universal home; records moved under `docs/` (`docs/decisions/`, `docs/specs/`); Spec Kit demoted from consumer to donor — the maintainer does not drive CLIs. See docs/decisions/0007.
- BYLAW.md introduced: repo-specific principles (R1–R4) and instantiations moved out of constitution.md, which is now purely the universal law's by-reference presence with a session-start fetch line. "Constitution" is univocal estate-wide. First post-confirmation amendment of the universal constitution (surface admitted). See decisions/0006.
- Maintainer confirmation: the three governing documents (universal constitution, this repo's constitution, the objective) moved DRAFT → CONFIRMED 2026-08-16; preambles restructured from blockquotes into Authority / Conformance / Scope sections, with no-theatrical-machinery's standing made explicit.
- Constitution split: universal P1–P11 moved to the estate root's `principles/constitution.md`, merit-ordered zero-base, with two audited additions (P6 least-privilege, P10 distrust) and the restore-proven clause; this repo's constitution reduced to the pull + R1–R4 + instantiations. See decisions/0005 for the full number mapping.
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
