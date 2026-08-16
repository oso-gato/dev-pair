# ARCHITECTURE.md — current state

Agent-owned map of the system as built. Mutable-on-fact: updated in the same change that alters a fact. Never a conformance target — this map chases the code, not the reverse.

## Current state (2026-08-17)

This repository holds the governing documents, the documentation surfaces, and the first component code: the mechanical gates. The universal principles and the genesis kit live in `oso-gato/homelab-root` (`principles/`, `genesis/`); `CONSTITUTION.md` here carries only the pull, and `00-BYLAW.md` carries the R-numbered principles and the instantiations this repository owns. `host/` and `dev-container/` are not yet rebuilt; they return as code lands under the constitution.

## Pairs

- `erebus` (host) + `nox` (dev-container) — the VPS pair (Hostinger KVM 4, stock Fedora Cloud, idempotent converger). Facts: homelab-root `environments/erebus.md`.
- `strix` (host) + `moros` (dev-container) — the bare-metal pair (Minisforum MS-S1 MAX, `strix-ms-s1-bootc` image, rebase with rollback). Facts: homelab-root `environments/strix.md`.

## Components

- `shared/gates/` — the mechanical gates, one home for CI, host, and dev-container alike (#7): `scan_structure.sh` (P2), `scan_channels.sh` (P4), `scan_secrets.sh` (P6), `gate_specs.sh` (locked documents, specs-completeness, frozen-at-ship), `gate.sh` (one-command runner incl. shellcheck), `test/` (fixture proofs).
- `.github/workflows/gate.yml` — the CI merge gate: a thin caller of `shared/gates/`, required on `main` as status check `gate` with `strict` head-sha binding (#7).

## Promised by law, not yet built

The law names these mechanisms in normative present tense; until each exists, its rule binds by agent discipline alone — do not rely on a gate to catch a violation:

- the ticket-envelope contract with pair + agent + stage stamps (R3, P8)
- the P7 out-of-band mutation scan (host runtime machinery — lands with the host component)

## Documentation assets (per universal P1's docs/ valve)

- (none — the genesis kit's master lives in the estate root at `genesis/`; consumed by throwaway fetch, per docs/decisions/0010)
