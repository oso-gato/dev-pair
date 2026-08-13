# The Dev Pair — SPECIFICATION

> **THE WHAT** — what the platform must do, and how well. Derived from `00-OBJECTIVE.md`,
> built under `00-BUILDPRINCIPLE.md`.
>
> **Status: NOT YET DERIVED.** This document is a placeholder. It is populated by the pair
> in step **(a)** of the loop, only after `00-OBJECTIVE.md` is confirmed by the maintainer.
>
> **Class: derived and checked (◐).** The pair authors it; the maintainer does not approve
> it clause by clause — OB-2 permits one human act, and that act is confirming the
> objective. What keeps this document honest is mechanism, not attendance:
>
> - **Traceability** — every clause cites the `OB-n` it serves. A clause with no live trace
>   is scope creep and fails the check.
> - **Coverage** — every `OB-n` resolves to at least one clause. An `OB-n` with none is a
>   gap and fails the check.
> - **Non-author verification** — a change here is a visible event on the ticket bus,
>   verified by a session that did not write it. Never a silent edit.
>
> This document **is** a conformance target: the ship gate (OB-29) verifies the built
> product against the objective first, then this specification, then the build principles.

---

## Intended shape

Two clause families, both in EARS notation so that conformance is a scan rather than a
judgment:

- **Functional requirements** — what the platform does. Event-driven:
  `WHEN <trigger> THE system SHALL <response>.`
- **Quality attributes** — how well, and under what conditions. Ubiquitous or state-driven,
  with **numeric thresholds**: `THE system SHALL <property> within <measurable bound>.`

Every clause carries its `OB-n` trace. A closing coverage section reconciles both
directions and is re-run on every amendment to the objective.

## Prerequisite

Derivation is blocked until `00-OBJECTIVE.md` is confirmed and its `OB-n` numbering is
final. Tracing to clause identifiers that may still move produces traces that silently rot.
