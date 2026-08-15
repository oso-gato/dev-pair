# Feature Specification: Repo-genesis template set

**Feature Branch**: `0006-repo-genesis` (worked directly on main — pre-loop bootstrap; the merge gate does not yet exist)
**Created**: 2026-08-16
**Status**: Shipped (frozen)
**Ticket**: [#6](https://github.com/oso-gato/dev-pair/issues/6)

## What this must do

The pair must be able to start any new development repository mechanically after its one initiation session: instantiate the standing documentation surfaces (P13), the component tree for the declared runtime shape, and the per-ticket working method — with nothing left to memory.

## Functional requirements

1. A template exists for every standing surface (OBJECTIVE, constitution, AGENTS, ARCHITECTURE, CHANGELOG, README, ADR), each documenting its own format via placeholders.
2. The three runtime shapes are documented with their exact component trees: single artifact · host + container + shared · swarm + shared.
3. The per-ticket artifacts (spec, plan, tasks) are Spec Kit's own templates, vendored verbatim and version-pinned with an adoption trail (P1/P2).
4. A genesis procedure states the steps from confirmed objective to working repo, including what is locked, what starts empty, and where the first ticket begins.

## Acceptance

A new repo can be created by following `shared/templates/repo-genesis/README.md` alone, with no reference to conversation history.
