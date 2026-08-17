# 000024 — The five-stage method is the estate's own; Spec Kit is provenance only

- status: accepted
- date: 2026-08-17

## Problem

"Spec Kit" names two things that were separated a year of records ago, and the shared name keeps pulling them back together. One is the tool — a CLI with slash commands and path expectations, which the estate does not use. The other is the per-ticket method it donated, specify → plan → tasks → analyze → implement, which the estate does use and which is its own law.

The answer already existed and was unfindable. ADR 000003 is titled "Adopt Spec Kit's per-ticket method", so it reads as an adoption still in force. The demotion that retired the tool is the third clause of ADR 000007, whose title is "Casing grammar; docs/ records parent; Spec Kit demoted to donor" — a record about filename casing. An agent asking whether this estate uses Spec Kit must read a record about casing to learn that it does not, and must read an adoption record to learn what survived. One concept, two half-homes, and C1 requires one.

The cost was measured rather than assumed. The question consumed working time twice in a single day, and on the second occasion an audit agent was briefed on a compressed restatement of the maintainer's ruling, found that live law contradicted the compression, and reported a defect against an estate that had none.

## Decision

Maintainer-confirmed. The five-stage method — specify → plan → tasks → analyze → implement — is kept as the estate's feature-building method, and its records land under `docs/specs/<NNNNNN-slug>/`. The Spec Kit CLI and its slash commands are not used and bind nothing. The casing grammar stands: root files uppercase, directories lowercase, and folders carry the code and the documentation.

Nothing in live law changes, because live law already says this. `AGENTS.md`, the constitution, the charter and the map name no donor, and the method stands under its own description.

The decision this record adds is a naming rule. The method must not reacquire the donor's name in prose. "Spec Kit" is legitimate in exactly two places: the genesis kit's Provenance note, where it is a C5 adoption trail carrying release, sha and fetch date, and frozen records, which are never restyled. Anywhere else it is a defect, because it re-opens the ambiguity this record exists to close.

This record is the one home for the estate's relationship to Spec Kit. ADR 000003 keeps its adoption and ADR 000007 keeps its demotion; neither is superseded, and both are read through this one.

## Options considered

- **Write nothing, since live law is already correct** — rejected by the maintainer. The rule was already right and still cost time twice, which is the same shape ADR 000018 diagnosed: a rule that is correct but not findable loses to whatever a reader finds first.
- **Rename the stages so no donor name could ever attach** — rejected. The five words describe the work accurately, every prior record uses them, and renaming would churn the surfaces to solve a problem the naming rule solves with a sentence.
- **Retire the method along with the tool** — considered and rejected on the maintainer's ruling. The stage discipline is the part worth having, and it is what ADR 000007 deliberately kept when it discarded the CLI.

## Consequences

No live surface changes. The changelog records the confirmation and this record becomes the answer an agent finds when it asks the question. The three absorbed ticket templates stay in the genesis skeleton, and their Provenance note stays as written, because provenance is the one place the donor is properly named.
