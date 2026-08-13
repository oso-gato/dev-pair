# dev-pair — agent router

**What this repository is.** One autonomous development platform of two components: a
Fedora host and its dev-container, together one **dev pair**. The pair takes a confirmed
objective and ships a product from it with no second human act.

**Read this first, then the document your work touches. Never work from memory of a
governing document — fetch it fresh.**

## The document spine

| File | Holds | Class | Owner |
|---|---|---|---|
| `00-OBJECTIVE.md` | Why, outcomes, boundaries, this repo's constraints | ⬤ fixed | maintainer |
| `00-BUILDPRINCIPLE.md` | Universal construction law · vendored @ fleet v1 | ⬤ fixed | maintainer |
| `01-SPEC.md` | What the platform must do · traced to `OB-n` | ◐ derived, checked | pair |
| `02-DESIGN.md` | How it is arranged | ○ mutable-on-fact | pair |
| `docs/adr/` | Why it is arranged that way, and what was rejected | ○ append-only | pair |
| `CHANGELOG.md` | Incident narrative | ○ append-only | pair |

⬤ frozen — new maintainer confirmation only · ◐ re-derived, never hand-edited ·
○ changes freely on evidence

**Authority on conflict:** `00-BUILDPRINCIPLE.md` · `00-OBJECTIVE.md` > `01-SPEC.md` >
`02-DESIGN.md` > tickets > code. A lower document disagreeing with a higher one is
defective, not authoritative.

**The constitution layer** is `00-BUILDPRINCIPLE.md` (construction law) plus
`00-OBJECTIVE.md` §Boundaries and §Document authority (governance).

## Source tree

- `host/` — the mother platform
- `dev-container/` — the development container
- `shared/contracts/` — machine-readable grammars, versioned, one home each

## Tasks

GitHub Issues and pull requests are the tasks layer. There is no `tasks.md`. Work is
co-written to the bus so any session can be torn down and resumed from it.

## Standing rules

- `00-OBJECTIVE.md` and `00-BUILDPRINCIPLE.md` are maintainer-merge-only, enforced by
  `.github/CODEOWNERS`. Propose by PR; never merge.
- `00-BUILDPRINCIPLE.md` is a vendored copy. Do not edit it here — amend it at the fleet
  home and re-pin.
- Every `01-SPEC.md` clause cites the `OB-n` it serves. No trace is scope creep; an
  `OB-n` with no clause is a gap.
- One authoritative home per concept. Every other mention is a one-line pointer.
