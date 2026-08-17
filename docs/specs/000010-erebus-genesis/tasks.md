# Tasks: Genesis of the erebus pair

Dependencies are marked so the independent work fans out and only the dependent work waits (C12). A task marked `after:` may not start until every task it names is done; everything else is concurrent.

## Foundation

- [x] T1 — `host/converge/lib/log.sh`: the output discipline every unit shares.
- [x] T2 — `host/converge/lib/provenance.sh`: the one pinned-fetch contract (C4), fail-closed, used by day zero and every unit alike.
- [x] T3 — `host/converge/environments/erebus.env`: the per-environment adapter, holding only what differs between hosts.

## The shared agent box

- [x] T4 — `shared/claudebox/distrobox.ini`: the pinned box manifest, self-update disabled by construction.
- [x] T5 — `shared/claudebox/managed-settings.json`: managed policy, autoupdater off, package-discipline deny list.
- [x] T6 — `shared/claudebox/claudebox-init.sh`: the post-assemble bridges — host podman socket, GitHub App token, managed settings.

## Converger units — `after: T1, T2, T3`

- [x] T7 — `10-identity.sh`: `core`, the trust-root key sync, the sudo flip, keys-only `sshd`, root retired.
- [x] T8 — `20-packages.sh`: the ladder walked, `install_weak_deps=False`, every admission disclosed.
- [x] T9 — `30-tailnet.sh`: the L2 vendor repository and the tailnet join. `after: T8`
- [x] T10 — `40-podman.sh`: rootless podman for `core`, linger, the user socket the box bridges to.
- [x] T11 — `50-github-app.sh`: `pair-gh-app-token` and its timer, minting the short-lived installation token to tmpfs.
- [x] T12 — `60-agentbox.sh`: `claudebox` on the host from `shared/claudebox/`, with the daily rebuild timer. `after: T4, T5, T6, T10`
- [x] T13 — `70-dev-container.sh`: pull the CI-built image and launch `nox` from outside. `after: T10, T14`

## The dev-container

- [x] T14 — `dev-container/Containerfile`: the `nox` image, its own `claudebox`, sessions durable outside the layer.
- [x] T15 — `dev-container/build.sh`: the throwaway build, torn down by an EXIT trap covering signal paths (B1).

## Assembly — `after: T7, T8, T9, T10, T11, T12, T13`

- [x] T16 — `host/converge/converge.sh`: the entry point that orders the units and is safe to re-run.
- [x] T17 — `host/day-zero.sh`: the one pasted script, credential-free, one device-flow approval, root retired at the end.

## Proof — `after: T16, T17`

- [x] T18 — Re-run safety proven: a second apply changes nothing, asserted against the real scripts rather than a mock (C9, acceptance 3).
- [x] T19 — Static proof of the credential and provenance claims: no secret in the tree, no forbidden channel anywhere (acceptance 2, 4).
- [x] T20 — Shell correctness of every delivered script under `bash -n` and `shellcheck` where available.

## Records — `after: T18, T19, T20`

- [x] T21 — ADR: day zero pulls identity from the vault after one device-flow authorization.
- [x] T22 — ADR: `oso-gato/strix-ms-s1-bootc` is a donor, and the prior fleet is out of scope.
- [x] T23 — `ARCHITECTURE.md` updated in the same change that lands the components.
- [x] T24 — `AGENTS.md` Build & test section replaced with the real commands, as that section's own rule requires.
- [x] T25 — `CHANGELOG.md` entry.
- [x] T26 — Analyze pass across spec, plan and tasks before the ticket is offered as done.

## What the analyze pass found

Two documents disagreed with the code and with the objective, and the code was the one that was right.

Requirement 8 in `spec.md` and the design section in `plan.md` both said the host builds the `nox` image. The objective's Boundaries say neither component builds production images and CI builds them, and `70-dev-container.sh` pulls rather than builds — so the implementation conformed and both documents did not. Both are corrected, and `tasks.md` T13's verb with them.

`plan.md` graded the Hostinger template L1. The registry records that Hostinger publishes no image source, checksum or build date, so the upstream artifact behind the catalogue label is unverified and L1 overstated it. The row now says what it is.

Nothing else diverged. Every functional requirement maps to delivered code, every task to a file, and the ticket's eight acceptance criteria are unchanged — with criterion 1's apply, and the end-to-end proof of criterion 3, standing as the maintainer's tier-2 act rather than as anything claimed here.
