# Implementation Plan: Mechanical gates

**Branch**: `0007-mechanical-gates` | **Date**: 2026-08-17 | **Spec**: [spec.md](spec.md)

## Design

- One home: all gate logic is plain bash in `shared/gates/` — git, grep, and the shell, no new runtime (P3). The workflow is a thin caller; host and dev-container run the identical scripts.
- `.github/` is a tool contract, the same standing as `AGENTS.md`'s casing: GitHub reads workflows only at that path. It joins the root inventory as a lowercase directory; this plan records the admission.
- Two entry points: `gate.sh` runs the repo-state scans (structure, channels, secrets, shellcheck) and needs no context; `gate_specs.sh BASE HEAD BRANCH` runs the PR-context checks (locked documents, specs-completeness, frozen-at-ship) over the three-dot diff — a PR's own changes, not the base branch's drift.
- Scans walk `git ls-files` only: untracked local noise never fails a gate, and what is not committed cannot ship.
- Fixtures under `shared/gates/test/fixtures/` hold real-shaped dummy violations; the repo sweep excludes exactly that path. `test_gates.sh` copies each fixture into a throwaway git repo (R1 discipline), asserts the scan fails there with the expected finding, then asserts the clean tree passes. The specs gate is tested against constructed throwaway histories: a locked-document edit, a component change without specs, a frozen-folder edit, and a green case.
- The channel scan excludes its own file — its pattern list would match itself; the exclusion is one named file, stated in its header. Secret patterns are written so their regex text cannot self-match; no exclusion needed.
- Branch protection on `main`: required status check `gate`, `strict: true` (head must be current with main at merge). `enforce_admins` stays off — the maintainer's locked-document amendments keep their sanctioned direct path; the gate red on a locked-document PR is the mechanism working, and the maintainer's bypass is the recorded exception (objective: maintainer-merge-only).
- Casing exception below root, exactly one name: `Containerfile` — podman's filename contract, the genesis manual's shape 1 precedent.

## Adoption trail (P4/P5)

- `actions/checkout` v7.0.1, pinned by commit sha `3d3c42e5aac5ba805825da76410c181273ba90b1`; existence and identity verified against live upstream via `gh api repos/actions/checkout/git/ref/tags/v7.0.1`, 2026-08-17. Strongest available provenance for a workflow step: full-sha pin.
- Runner `ubuntu-24.04` with its preinstalled shellcheck; presence checked fail-closed — the gate errors if shellcheck is absent rather than skipping (a gate that skips is theatrical machinery).

## Not in this ticket

The P7 drift scan (host runtime). Ticket-envelope validation (the contracts ticket). "ARCHITECTURE.md updated in the same change" — a judgment call, left to adversarial review, recorded here so nobody mistakes the gap for coverage.
