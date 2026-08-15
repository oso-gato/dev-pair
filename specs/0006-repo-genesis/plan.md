# Implementation Plan: Repo-genesis template set

**Branch**: worked on main (bootstrap) | **Date**: 2026-08-16 | **Spec**: [spec.md](spec.md)

## Design

- Home: `shared/templates/repo-genesis/` — shared, because both components use it (the dev-container instantiates; the host validates against it).
- One manual (`README.md`) carries the procedure, the three shapes, and the surface table — single home, per P9.
- Standing-surface templates as `*.template.md` with `{{placeholder}}` convention; ticket templates keep Spec Kit's exact filenames (filename-contract rule, P13).
- Vendoring by API fetch from live upstream, pinned to release v0.16.4 / sha `bf88c9f9`, trail in `VENDORED.md` (P2).
- Decision binding beyond this ticket — the five-binding build-in design and the vendored-not-CLI choice — graduates to `decisions/0004` (the ADR graduation rule).

## Not in this ticket

Ticket-envelope stage/pair/agent stamps (P7 contracts) and the mechanical merge gate (P8 CI) — subsequent tickets; recorded in ADR 0004 consequences.
