# ARCHITECTURE.md — current state

Agent-owned map of the system as built. Mutable-on-fact: updated in the same change that alters a fact. Never a conformance target — this map chases the code, not the reverse. It records only what exists: unbuilt work lives in issues, never here, because a list of absent mechanisms sitting in the current-state map reads as a build queue and gets built.

## Current state (2026-08-18)

This repository holds the governing documents, the documentation surfaces, and both lineages' genesis paths as code. The confirmed baseline is the protected tag `chartered` (epochs timestamped per C11 — the only epoch is `chartered-2026-08-18-0159` (Hong Kong time), where the floating tag points, wrapped in a Release); two active tag rulesets armour them — epochs immutable to everyone, the floating name maintainer-movable. The universal principles and the genesis kit live in `oso-gato/homelab-root` (`principles/`, `genesis/`); `CONSTITUTION.md` here carries the pull and its charter membership, and `00-BYLAW.md` carries the B-numbered principles and the instantiations this repository owns.

The component tree exists in all three parts. Nothing here has been applied to a live host: the delivery boundary for issues #10 and #11 alike is the artifact the maintainer consumes, and the apply is his act.

## Pairs

- `erebus` (host) + `nox` (dev-container) — the VPS pair, and lineage 1. Its genesis path is built and unapplied: `host/day-zero.sh`, the converger, the agent box, and `nox` as an instance of the shared dev-container image. The host sits at its as-provisioned template until the maintainer pastes day zero. Facts: homelab-root `environments/erebus.md`.
- `strix` (host) + `moros` (dev-container) — the bare-metal pair, and lineage 2. The host image is built and CI-built at `oso-gato/strix-ms-s1-bootc`, which is also this repository's **donor**: patterns are read from it and adapted, never forked and never depended on at run time (docs/decisions/000027). Its activation path is built and unapplied — `host/activate.sh` and the `strix.env` adapter — and the live machine state is unverified. `moros` is an instance of the shared dev-container image rather than an image of its own. The pair's two GitHub Apps do not exist yet; the registry lists both as planned, and until they do the boxes hold no GitHub authority. Facts: homelab-root `environments/strix.md`.
- Identities for every pair rest in the estate vault, homelab-root `identity/`: the App registry `github-apps.md` (App and installation IDs, each PEM beside it), the tailnet auth key `tskey-auth-oso-2026-09-26-expiry.key` (tailnet `oso`, expiry in the name), and the `core` declaration `core-user.md` (userid; sudo hashes, main and alternative). Credential files are never read — homelab-root's `AGENTS.md` carries the vault discipline, and it binds this repository's agents too.

## Components

- `host/day-zero.sh` — the one pasted script for the VPS track. Credential-free, two phases around a single GitHub device-flow approval, and re-runnable. It installs the host from public sources, creates `core` from the trust root, then reads the vault for the `core` sudo hash, the tailnet auth key and the pair's App private keys (docs/decisions/000026).
- `host/activate.sh` — the bare-metal track's day zero. It installs nothing, because that track's host state arrives by image rebase and a package installed here would be the out-of-band change C7 forbids. It confirms what the image baked, takes the same single approval, reads the vault for the tailnet key and the App keys, and retires root under the same guard.
- `host/converge/` — the idempotent converger, the VPS track's sanctioned deploy mechanism. `converge.sh` is the entry point; `lib/` holds the output discipline, the idempotent filesystem operations and the one pinned-fetch contract; `units/` holds the seven ordered units, whose numbering is their dependency declaration; `environments/` holds one adapter per host, an addition rather than a fork. Which units apply is a track fact the adapter declares, so the bare-metal track runs only what its image does not already carry (docs/decisions/000028). `selftest.sh` is what the container can prove without a host.
- `host/sysroot/` — the files the converger installs: the keys-only `sshd` policy, the trust-root key sync and its timer, the App-token timer, the dev-container Quadlet template, and `pair-enter`, installed under the dev-container's own name.
- `shared/claudebox/` — the disposable agent layer (C8), shared because both components run one: the pinned manifest with self-update off, the managed settings, the post-assemble bridges, and the rebuild machinery whose session lock is what keeps a rebuild from ever interrupting live work.
- `shared/bin/pair-gh-app-token` — the App installation-token minter, shared because each component mints its own token from its own App. The host's App carries no merge permission and `nox`'s does.
- `dev-container/` — one image for every lineage, its throwaway validation build (B1), and `pair-session`, the session supervisor that is its PID 1. `nox` and `moros` are two instances of it, differing only in name and App identity. The production image is built by CI at `.github/workflows/build-dev-container.yml` and published to `ghcr.io/oso-gato/dev-container`; neither component builds it.

## Provenance, as admitted

The host's own record is `/var/lib/dev-pair/provenance.tsv`, written at apply time. What the repository declares: everything on the host is L1 from Fedora's own repositories except `tailscale`, which is L2 from the vendor's signed repository, and `claude-code`, which is L2 inside the agent box only and never on a component. There is no L3 artifact anywhere; `prov_l3_fetch` exists so the first one that needs it cannot be admitted without a checksum.

One gap is open and recorded: Tailscale's signing-key fingerprint is unpinned, because the estate's last verified position on it pins none and the session that built this could not reach the vendor to verify one (docs/decisions/000027).

## Documentation assets (per universal C1's docs/ valve)

- (none — the genesis kit's master lives in the estate root at `genesis/`; consumed by throwaway fetch, per docs/decisions/000010)
