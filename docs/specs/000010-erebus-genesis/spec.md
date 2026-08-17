# Feature Specification: Genesis of the erebus pair

**Feature Branch**: `claude/dev-pair-universal-constitution-4xtdos`
**Created**: 2026-08-17
**Status**: In progress
**Ticket**: [#10](https://github.com/oso-gato/dev-pair/issues/10)
**Pair**: erebus · **Agent**: claudebox

## What this must do

The platform has governing documents and no pair. This ticket delivers the erebus lineage as code, up to the moment the maintainer pastes day zero into the Hostinger console — the artifact he consumes, never applied by its author.

Erebus is lineage 1 and is built first because the VPS is the more stable surface: it is virtualised, it carries no GPU and no libvirt, and its failure modes are the smaller set. Strix follows in its own ticket because it carries more load and full virtualization. This ordering is a maintainer instruction, recorded here because it is a fact no repository held.

## Functional requirements

1. **Day zero is one pasteable script and holds no credential.** The maintainer pastes it into the root terminal Hostinger's out-of-band web console gives on a stock `Fedora Cloud 44` template. It runs to completion or fails loudly, and it never leaves the host half-converged without saying so.
2. **Identity arrives from the estate's trust root and vault, at run time.** The `core` user is created from the published key set at `github.com/oso-gato.keys`; the sudo hash, the tailnet auth key, and the pair's GitHub App credentials come from `oso-gato/homelab-root` → `identity/`. `dev-pair` is a public repository, so no declaration and no credential may be committed into it — the one home stays the vault.
3. **The human act is exactly one.** Day zero authorises once, through GitHub's device flow, and that approval is what unlocks the vault pull. No second prompt, no second approval, no summons later.
4. **Root retires inside day zero.** After `core` exists and holds the maintainer's keys, root can no longer authenticate remotely, and password authentication is off on every path. Escalation is by sudo, gated on the `core` password.
5. **The converger is the host's only deploy mechanism, and it is idempotent.** Every mutation the host carries is declared in this repository, applies re-run-safe, and erases ad-hoc drift on the next apply. Any historical version re-runs safely.
6. **Every package admission walks the ladder and discloses where it landed.** Fedora's own repositories first, the vendor's signed repository second, an official upstream artifact only where neither exists. No forbidden channel appears anywhere in the tree.
7. **The agent box is disposable and cannot self-update.** `claudebox` is a distrobox layer on the host, rebuilt rather than updated, with every durable thing — credentials, transcripts, configuration — outside the layer.
8. **`nox` is the second component and is built by the host, from outside.** It carries its own agent box, hosts the multi-tenant sessions, and holds the merge authority the host does not.
9. **Sessions survive disconnection.** A session left running survives a network roam, a device sleep, and a client restart, and resumes from any authorised device with its work intact.

## Acceptance

The ticket's own eight acceptance criteria stand unchanged, and this specification adds nothing to them. Criterion 1 is the delivery boundary: a maintainer can paste `host/day-zero.sh` into a stock Fedora Cloud 44 root terminal and reach a converged host with a running dev container, with no other manual step. The apply itself is his act and is out of scope.

## Out of scope, and why

Applying any of this to the live VPS, because that is the maintainer's act and this ticket makes the artifact it consumes.

The self-renewal chain (B4) and the ticket-envelope contract (B3), because both need two live components to talk to each other, and a producer-first contract is the bylaw's own UNSAFE case.

The strix pair, because it is lineage 2 and follows in its own ticket, drawing on `oso-gato/strix-ms-s1-bootc` as a donor.

`oso-gato/noir-strix-halo-fcos`, `oso-gato/fedora-dev` and `oso-gato/fedora-bootstrap` are out of scope entirely, by maintainer instruction. They are the prior fleet, and nothing here reads from them or cites them.
