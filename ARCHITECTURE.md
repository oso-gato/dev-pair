# ARCHITECTURE.md — current state

Agent-owned map of the system as built. Mutable-on-fact: updated in the same change that alters a fact. Never a conformance target — this map chases the code, not the reverse.

## Current state (2026-08-16)

This repository holds the governing documents, the documentation surfaces, and the first component content: the repo-genesis template set. The universal principles live in `oso-gato/homelab-root` under `principles/`; `CONSTITUTION.md` here carries only the pull, and `00-BYLAW.md` carries the R-numbered principles and the instantiations this repository owns. The rest of the component tree (`host/`, `dev-container/`, the remainder of `shared/`) is not yet rebuilt; it returns as code lands under the constitution.

## Pairs

- `erebus` — VPS pair (Hostinger KVM 4, stock Fedora Cloud, idempotent converger). Facts: homelab-root `environments/erebus.md`.
- `strix` — bare-metal pair (Minisforum MS-S1 MAX, `strix-ms-s1-bootc` image, rebase with rollback). Facts: homelab-root `environments/strix.md`.

## Components

- (none built yet — the component tree returns as code lands; component folders hold code and scripts only)

## Documentation assets (per universal P1's docs/ valve)

- `docs/repo-genesis/` — the genesis kit: the three-shape manual, standing-surface templates, and the vendored per-ticket templates (trail in its `VENDORED.md`). Shipped as ticket #6; moved from `shared/templates/` per docs/decisions/0009.
