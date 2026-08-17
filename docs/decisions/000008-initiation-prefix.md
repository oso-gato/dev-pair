# 0008 — The 00- prefix marks initiation-session artifacts

- status: accepted (amends 0007's grammar)
- date: 2026-08-16

## Problem

The root surfaces have three provenances — co-created by maintainer and agent in the one interactive initiation session (objective, bylaw), pulled from the estate (constitution), and agent-generated (AGENTS, ARCHITECTURE, CHANGELOG, README). The skeleton did not encode which was which.

## Decision

The `00-` prefix marks provenance: exactly the two initiation-session co-created artifacts — `00-OBJECTIVE.md` and `00-BYLAW.md` — for this repository and every future genesis. They sort first; the human-and-agent-made law is visible at a glance. The casing grammar extends: root files uppercase, the two initiation artifacts additionally `00-`-prefixed, directories lowercase.

## Options considered

- Prefixing the constitution too — rejected: it is pulled, not co-created; the prefix would lie about provenance.
- Encoding provenance only in the surface table — rejected: the filename is the surface every listing shows; the table is one more hop.

## Consequences

Renames in this repo and the genesis templates; universal P1 and P2 amended (third amendment). Frozen records keep their epoch's names.
