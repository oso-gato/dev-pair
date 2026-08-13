# 0001 — Unprocessed: instance facts (the two live pairs)

- **Status:** holding file — not a decision record
- **Date:** 2026-08-13

## Why this file exists

The objective previously named its own hardware: *"currently Fedora 44 on Hostinger Plan
4"* in the host clause, and the `strix-ms-s1-bootc` build in the local-genesis clause.
Both were removed, correctly — OB-7 declares environment facts to be **inputs, never
baked-in assumptions**, and UNI-P2 declares that they **expire** and must be re-verified
per environment and per release. A specific provider plan frozen inside a
maintainer-fixed document is exactly the assumption those two clauses forbid: it cannot
rot loudly, only silently.

But the spine as restructured has **no artifact for instance facts at all**, so removing
them from the objective lost them. They are parked here until their real home exists.

## Their real home

**The environment adapter.** OB-15 structures genesis as a *Fedora core plus a
per-environment provisioning adapter*. A machine's identity, its plan or hardware, its
release, and its measured capabilities are that adapter's **verified facts** — recorded
with an adoption trail per UNI-P2: what was verified, against what, on what date, and when
it was last re-checked. They live in the source tree beside the adapter that consumes
them, not in a governing document.

When `host/` is rebuilt, each adapter carries its own facts record and this file is
deleted.

## Parked — the VPS track

| | |
|---|---|
| Provider | Hostinger |
| Plan | Plan 4 |
| OS at time of record | Fedora 44 |
| Virtualization | none assumed — the host is itself virtualized |
| GPU | none assumed |
| Genesis class | cloud genesis — stock Fedora cloud image, idempotent converger |
| Last live-verified | **unverified — re-check before use** |

## Parked — the bare-metal track

| | |
|---|---|
| Machine | Minisforum MS-S1 |
| Host name | `box` — the genesis agent |
| Image lineage | `strix` bootc build (`strix-ms-s1-bootc`) |
| Predecessor era | declarative Fedora CoreOS, superseded |
| Virtualization | libvirt/KVM, run directly |
| GPU | present — a **shared compute substrate** for containers and VMs, never monopolised away from the host |
| Genesis class | local genesis — custom bootc image + installer media, kept current by rebase with atomic rollback, permanent data preserved across reinstalls |
| CPU / memory / storage / GPU model | **not recorded — to be verified live, never assumed (UNI-P2)** |
| Last live-verified | **unverified — re-check before use** |

The hardware rows are deliberately blank rather than filled from memory or from a vendor
specification sheet. UNI-P2 admits an environment fact only when it has been checked
against the live machine, and a plausible-looking invented value is worse than an empty
field — it reads as verified.

## What stays in the objective

Only the rules that survive any machine:

- **OB-7** — Fedora and headlessness are the only constants; environment facts are inputs.
- **OB-12** — the two capability tracks differ in capability, never in contract; a
  capability may be **used** where it exists, and **no platform function may require it**.
- **OB-15** — onboarding a new environment is an **adapter addition, never a fork**.

Swapping Hostinger for another provider, or the MS-S1 for a different machine, must
therefore change an adapter and nothing else. If it would require amending the objective,
the objective has an instance fact hiding in it.
