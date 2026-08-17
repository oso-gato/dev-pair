# ARCHITECTURE.md — current state

Agent-owned map of the system as built. Mutable-on-fact: updated in the same change that alters a fact. Never a conformance target — this map chases the code, not the reverse. It records only what exists: unbuilt work lives in issues, never here, because a list of absent mechanisms sitting in the current-state map reads as a build queue and gets built.

## Current state (2026-08-18)

This repository holds the governing documents and the documentation surfaces. The confirmed baseline is the protected tag `chartered` (epochs timestamped per C11 — the only epoch is `chartered-2026-08-18-0159` (Hong Kong time), where the floating tag points, wrapped in a Release); two active tag rulesets armour them — epochs immutable to everyone, the floating name maintainer-movable. The universal principles and the genesis kit live in `oso-gato/homelab-root` (`principles/`, `genesis/`); `CONSTITUTION.md` here carries the pull and its charter membership, and `00-BYLAW.md` carries the B-numbered principles and the instantiations this repository owns. The component tree (`host/`, `dev-container/`, `shared/`) is not yet rebuilt; it returns as code lands under the constitution.

## Pairs

- `erebus` (host) + `nox` (dev-container) — the VPS pair. Neither component is built; the host sits at its as-provisioned template. Facts: homelab-root `environments/erebus.md`.
- `strix` (host) + `moros` (dev-container) — the bare-metal pair. The host image is built and CI-built at `oso-gato/strix-ms-s1-bootc`; `moros` is not built, and the live machine state is unverified. Facts: homelab-root `environments/strix.md`.
- Identities for every pair rest in the estate vault, homelab-root `identity/`: the App registry `github-apps.md` (App and installation IDs, each PEM beside it), the tailnet auth key `tskey-auth-oso-2026-09-26-expiry.key` (tailnet `oso`, expiry in the name), and the `core` declaration `core-user.md` (userid; sudo hashes, main and alternative). Credential files are never read — homelab-root's `AGENTS.md` carries the vault discipline, and it binds this repository's agents too.

## Components

- (none built yet — the component tree returns as code lands; component folders hold code and scripts only)

## Documentation assets (per universal C1's docs/ valve)

- (none — the genesis kit's master lives in the estate root at `genesis/`; consumed by throwaway fetch, per docs/decisions/000010)
