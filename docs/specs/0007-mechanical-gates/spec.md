# Feature Specification: Mechanical gates — CI merge gate and the P2/P4/P6 scans

**Feature Branch**: `0007-mechanical-gates`
**Created**: 2026-08-17
**Status**: Shipped (frozen)
**Ticket**: [#7](https://github.com/oso-gato/dev-pair/issues/7)

Epoch note: pre-loop bootstrap under the maintainer's standing instruction of 2026-08-17. Authored by the genesis agent (claudebox); merged after non-author adversarial review by an independent agent context (P10). The dev-container assumes sole merge authority when it rises.

## What this must do

ARCHITECTURE.md names the merge gate and the mechanical scans as promised by law but unbuilt — until they exist, every rule binds by discipline alone. This ticket gives the law mechanical existence at the merge boundary: no PR lands that violates the standing structure, adopts a forbidden channel, carries a secret, implements without its spec folder, edits a frozen record, or touches a locked document.

## Functional requirements

1. A CI gate runs on every pull request and its verdict gates the merge, bound to the exact head sha (P9).
2. P2 structure scan: the root inventory is exactly the standing surfaces plus `docs/`, the component trees, and `.github/`; the casing grammar holds; `docs/` children are only `decisions/`, `specs/`, and assets recorded in ARCHITECTURE.md; no `.md` inside a component tree (component folders hold code and scripts only).
3. P4 channel scan: the bylaw's forbidden channels fail mechanically — curl-pipe-sh, COPR, flatpak, snap, global language-package-manager installs, tar onto system paths.
4. P6 secret scan: private-key blocks, GitHub tokens, tailnet keys, AWS keys, and crypt hashes fail anywhere in the tree.
5. Specs gate: a PR touching a component tree carries a complete `docs/specs/<branch>/` (spec, plan, tasks); a PR never edits another ticket's specs folder; a PR never touches the locked documents (00-OBJECTIVE.md, 00-BYLAW.md, CONSTITUTION.md).
6. Every check lives once in `shared/gates/`, runnable identically by CI, the host, and the dev-container — one home, one definition.
7. Every scanner is fixture-proven: for each rule, a fixture violating it fails the scan, and the clean tree passes — P9's proven-to-fail requirement applied to scanners.
8. shellcheck runs over every tracked shell file and fails the gate on findings.

## Acceptance

A PR violating any rule above goes red on the live gate. This PR itself merges green under the gate it introduces. Branch protection on `main` requires the gate, strict to the head sha. Each scan's header states what it does not catch — judgment stays with adversarial review, and a scan never pretends coverage it lacks.

## Out of scope

The P7 out-of-band mutation scan (host runtime machinery — the host ticket). The ticket-envelope contract (a following ticket).
