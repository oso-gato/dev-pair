# The Dev Pair — DESIGN

> **THE ARRANGEMENT** — how this system is put together, as it stands now. Serves
> `01-SPEC.md`, built under `00-BUILDPRINCIPLE.md`.
>
> **Status: NOT YET AUTHORED.** This document is a placeholder. It is populated by the pair
> in step **(b)** of the loop, after `01-SPEC.md` is derived.
>
> **Class: mutable-on-fact (○).** Dev-owned. It changes when facts change, through the
> loop's own merge path, without maintainer re-confirmation. It is **never a conformance
> target** — if this document and the objective or the specification disagree, **this
> document is defective.**

---

## Intended shape

This document holds the arrangement **as it currently stands**: component boundaries, what
talks to what, where state lives, and the mechanism choices that satisfy the specification's
quality attributes.

It does **not** hold:

- **Requirements** — those are `01-SPEC.md`.
- **Decision history** — why an arrangement was chosen, and what was rejected, belongs in
  `docs/adr/`. This document describes the present; ADRs record how it got here. An agent
  can regenerate this document from the code. It can never regenerate the rationale.
- **Build sequencing** — increments are tickets on the bus, not a section here.

## Prerequisite

Blocked until `01-SPEC.md` is derived. Architecting against an underived specification
produces an arrangement with nothing to be correct about.
