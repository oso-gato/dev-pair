# Changelog

Incident narrative and activation-proofs live here — memoir is not specification (P9).
Newest first.

## 2026-08-03 — Increment 1: shared/ grammars v1

Build-order step 1 of `DESIGN.md` Part C landed: the four bus grammars —
ticket-envelope, verdict, refresh-manifest, lineage-manifest — defined once,
versioned v1, in `shared/contracts/`, with seven valid example instances.

**Activation-proof (P3):** `shared/contracts/test_contracts.py` — 43 rows
(7 accept, 36 refuse) against the real JSON Schema validator, all passing.
Mutation-proven in fact (P8): removing `sha` from the verdict schema's required
set turned exactly the matching refuse-row red (`verdict unbound from sha
refused: instance was accepted`); the restored schema is green. Two lineage
manifests recorded against the P11 admission contract: claudebox (admitted, L2),
kimibox (admitted, L3 c2); one example non-admission recorded with its reason.

## 2026-08-02 — Repository founded

`00-OBJECTIVES.md` and `00-BUILDPRINCIPLE.md` committed as the governing pair;
layout law (`host/` · `dev-container/` · `shared/`) established with scoping
READMEs. Loop steps (a) and (b) landed as `DESIGN.md` (dev-owned): functional
requirements traced per objective clause, the zero-base architecture (one loop,
two empirical gates, three host verbs, one watcher per clock, one versioned
bus), and the nine-increment build order.
