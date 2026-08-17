# ARCHITECTURE.md — current state

Agent-owned map of the system as built. Mutable-on-fact: updated in the same change that alters a fact. Never a conformance target — this map chases the code, not the reverse.

## Current state (2026-08-16)

This repository holds the governing documents and the documentation surfaces. The confirmed pre-build baseline is the protected tag `chartered` (epochs `chartered-2026-08-17` and `chartered-2026-08-17-2`, each wrapped in a GitHub Release; the floating name at the latest); two active tag rulesets armour it — epochs immutable to everyone, the floating name maintainer-movable. The universal principles and the genesis kit live in `oso-gato/homelab-root` (`principles/`, `genesis/`); `CONSTITUTION.md` here carries only the pull, and `00-BYLAW.md` carries the B-numbered principles and the instantiations this repository owns. The component tree (`host/`, `dev-container/`, `shared/`) is not yet rebuilt; it returns as code lands under the constitution.

## Pairs

- `erebus` (host) + `nox` (dev-container) — the VPS pair (Hostinger KVM 4, stock Fedora Cloud, idempotent converger). Facts: homelab-root `environments/erebus.md`.
- `strix` (host) + `moros` (dev-container) — the bare-metal pair (Minisforum MS-S1 MAX, `strix-ms-s1-bootc` image, rebase with rollback). Facts: homelab-root `environments/strix.md`.

## Components

- (none built yet — the component tree returns as code lands; component folders hold code and scripts only)

## Promised by law, not yet built

The law names these mechanisms in normative present tense; none exists yet, so today every rule binds by agent discipline alone — do not rely on a gate to catch a violation:

- the CI merge gate (C9: specs-completeness, frozen-at-ship, C2 surface check)
- the ticket-envelope contract with pair + agent + stage stamps (B3, C8)
- the mechanical scans (C2 casing/structure, C4 forbidden channels, C7 out-of-band mutation)

## Documentation assets (per universal C1's docs/ valve)

- (none — the genesis kit's master lives in the estate root at `genesis/`; consumed by throwaway fetch, per docs/decisions/000010)
