# Architecture decision records

Why the system is arranged the way `02-DESIGN.md` describes — and what was rejected.

**Append-only.** A decision is never edited after acceptance. It is superseded by a new
record that names the one it replaces. `02-DESIGN.md` is the present tense; this directory
is the past tense, and the past does not change.

**Class: mutable-on-fact (○)** in the sense that the pair may add records without maintainer
confirmation — but individual records, once accepted, are immutable.

## Why this directory exists

An agent can regenerate `02-DESIGN.md` from the code. It cannot regenerate the reasoning:
which options were considered, why the chosen one won, what was deliberately not built, and
what the trade-off cost. That reasoning is the expensive artifact, and it is the one most
easily lost when a snapshot document is rewritten.

## Format

One file per decision, `NNNN-kebab-case-title.md`, numbered in acceptance order.

```markdown
# NNNN — Title

- **Status:** proposed | accepted | superseded by NNNN
- **Date:** YYYY-MM-DD
- **Trace:** OB-n, and the 01-SPEC clauses affected

## Context
The forces in play. What made a decision necessary.

## Options considered
Each option, with its cost. An ADR with one option is a note, not a decision.

## Decision
What was chosen.

## Consequences
What this makes easy, what it makes hard, and what it forecloses.
```

Two record kinds carry their own conventions:

- **Exclusions** — deliberate non-construction ("no supervisory orchestrator"). Recorded so
  a future session does not rediscover and rebuild them. Revisitable on new facts.
- **Trade-offs** — where one objective clause was served at another's expense. The evaluation
  is the record; an undated trade-off is a defect.
