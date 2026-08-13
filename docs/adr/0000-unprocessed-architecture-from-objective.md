# 0000 — Unprocessed: architecture removed from the objective

- **Status:** holding file — not a decision record
- **Date:** 2026-08-13

## Why this file exists

The objective previously carried its own architecture: the loop mechanics, the capability
tracks' reasoning, and the component operating rules. That content is **how this system is
arranged**, not **why it must exist**, so it does not belong in a maintainer-fixed
objective — it was frozen at the wrong authority, and stated without the rejected options
that make a decision legible.

It is parked here verbatim rather than deleted, because `DESIGN.md` — which restated most
of it — is being thrown away with the rest of the pre-restart repository. Deleting from
both places at once would lose the thinking.

**This file is temporary.** Each item below becomes a proper ADR once `01-SPEC.md` and
`02-DESIGN.md` are derived, at which point this file is removed. It is deliberately named
`0000` so it sorts above real records and reads as unfinished.

## Parked — loop mechanics

- **Three decoupled clocks.** The host OS, the container image, and each agent box advance
  on independent cadences — the agent layer's being the fast, daily one — each advancing
  without costing live work, each verified by reading the live artifact back. None forces a
  rebuild of the others.
- **Multi-tenant development.** The dev-container runs an undefined number of isolated
  agent sessions, each on its own declared repository set, independently and exclusively.
  Isolation is **by scope, code-enforced**, not by identity. The host is the **single
  shared validator** for all of them. GitHub issues and pull requests are the first-class
  ticket bus; the dev-container never touches the host directly — it instructs the host's
  agent.
- **Two-tier validation.** A session proves whatever it can inside the dev-container and
  engages the host **only for the live validation the container cannot perform itself** —
  then iterates on the host's verdict until GREEN. Where the container cannot validate at
  all, that fallback is forced, not chosen. A validation needing full virtualization or a
  GPU routes to the bare-metal track.
- **Merged is not live — in both directions.** A merge is not a deployment. A merge
  **self-arms** the matching refresh with no human step, and the pair staggers it: each
  component refreshes the other **from outside**, and every refresh is **confirmed by
  reading the live artifact back against merged source, fail-closed.**
- **Minimal machinery.** The smallest mechanism set that advances the objective. Where a
  mechanism helps one clause while hurting another, the trade-off is **evaluated and
  recorded**, never defaulted.
- **Dogfooding.** Every change to this repository lands through the platform's own loop.

## Parked — capability-track reasoning

- A VPS host is itself virtualized, so full virtualization is commonly unavailable to it; a
  bare-metal host runs libvirt/KVM virtual machines directly. Certain testing requires full
  virtualization for best validation.
- Certain hosted apps require GPU acceleration. A bare-metal host's GPU is a **shared
  compute substrate** — shared to containers and virtual machines, never monopolised away
  from the host. The VPS track is assumed to have none.

*(The binding rule that survives — capability may be used where it exists, never required —
is retained in the objective as OB-12.)*

## Parked — provisioning classes

- **Cloud genesis:** remote, channel-proof, no local act, converging a stock Fedora cloud
  image via an idempotent converger.
- **Local genesis:** a custom **bootc** image — container-first, CoreOS-style, layered —
  built from the repository and deployed to the machine, kept current by image rebase with
  atomic rollback, permanent data preserved across reinstalls. Working lineage: the
  maintainer's `strix` bootc build (`strix-ms-s1-bootc`), succeeding the earlier declarative
  Fedora CoreOS era.
- The genesis path is a **Fedora core plus a per-environment provisioning adapter**;
  onboarding a new environment is an adapter addition, never a fork.
- The first host, named **box**, is the **genesis agent**: first a member of the dev pair,
  second a spinner-up of future containers as apps and services.
