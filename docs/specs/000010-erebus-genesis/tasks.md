# Tasks: Genesis of the erebus pair

Dependencies are marked so the independent work fans out and only the dependent work waits (C12). A task marked `after:` may not start until every task it names is done; everything else is concurrent.

## Foundation

- [ ] T1 — `host/converge/lib/log.sh`: the output discipline every unit shares.
- [ ] T2 — `host/converge/lib/provenance.sh`: the one pinned-fetch contract (C4), fail-closed, used by day zero and every unit alike.
- [ ] T3 — `host/converge/environments/erebus.env`: the per-environment adapter, holding only what differs between hosts.

## The shared agent box

- [ ] T4 — `shared/claudebox/distrobox.ini`: the pinned box manifest, self-update disabled by construction.
- [ ] T5 — `shared/claudebox/managed-settings.json`: managed policy, autoupdater off, package-discipline deny list.
- [ ] T6 — `shared/claudebox/claudebox-init.sh`: the post-assemble bridges — host podman socket, GitHub App token, managed settings.

## Converger units — `after: T1, T2, T3`

- [ ] T7 — `10-identity.sh`: `core`, the trust-root key sync, the sudo flip, keys-only `sshd`, root retired.
- [ ] T8 — `20-packages.sh`: the ladder walked, `install_weak_deps=False`, every admission disclosed.
- [ ] T9 — `30-tailnet.sh`: the L2 vendor repository and the tailnet join. `after: T8`
- [ ] T10 — `40-podman.sh`: rootless podman for `core`, linger, the user socket the box bridges to.
- [ ] T11 — `50-github-app.sh`: `pair-gh-app-token` and its timer, minting the short-lived installation token to tmpfs.
- [ ] T12 — `60-agentbox.sh`: `claudebox` on the host from `shared/claudebox/`, with the daily rebuild timer. `after: T4, T5, T6, T10`
- [ ] T13 — `70-dev-container.sh`: build and launch `nox` from outside. `after: T10, T14`

## The dev-container

- [ ] T14 — `dev-container/Containerfile`: the `nox` image, its own `claudebox`, sessions durable outside the layer.
- [ ] T15 — `dev-container/build.sh`: the throwaway build, torn down by an EXIT trap covering signal paths (B1).

## Assembly — `after: T7, T8, T9, T10, T11, T12, T13`

- [ ] T16 — `host/converge/converge.sh`: the entry point that orders the units and is safe to re-run.
- [ ] T17 — `host/day-zero.sh`: the one pasted script, credential-free, one device-flow approval, root retired at the end.

## Proof — `after: T16, T17`

- [ ] T18 — Re-run safety proven: a second apply changes nothing, asserted against the real scripts rather than a mock (C9, acceptance 3).
- [ ] T19 — Static proof of the credential and provenance claims: no secret in the tree, no forbidden channel anywhere (acceptance 2, 4).
- [ ] T20 — Shell correctness of every delivered script under `bash -n` and `shellcheck` where available.

## Records — `after: T18, T19, T20`

- [ ] T21 — ADR: day zero pulls identity from the vault after one device-flow authorization.
- [ ] T22 — ADR: `oso-gato/strix-ms-s1-bootc` is a donor, and the prior fleet is out of scope.
- [ ] T23 — `ARCHITECTURE.md` updated in the same change that lands the components.
- [ ] T24 — `AGENTS.md` Build & test section replaced with the real commands, as that section's own rule requires.
- [ ] T25 — `CHANGELOG.md` entry.
- [ ] T26 — Analyze pass across spec, plan and tasks before the ticket is offered as done.
