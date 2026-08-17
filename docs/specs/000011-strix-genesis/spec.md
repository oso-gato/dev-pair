# Feature Specification: Genesis of the strix pair

**Feature Branch**: `claude/dev-pair-universal-constitution-4xtdos`
**Created**: 2026-08-18
**Status**: In progress
**Ticket**: [#11](https://github.com/oso-gato/dev-pair/issues/11)
**Pair**: strix · **Agent**: claudebox

## What this must do

Strix is lineage 2 and follows erebus, because the VPS is the more stable surface while strix carries more load and full virtualization. It is the smaller ticket, and the reason is a maintainer fact: `oso-gato/strix-ms-s1-bootc` is built, CI-built and working, and it is this repository's donor for the strix lineage. The host image exists and already carries every capability, so there is no host build here at all.

What is missing is everything on this side of that image — the environment adapter, the pair's second component, and the one act that turns a booted machine into a member of the pair.

## Functional requirements

1. **Activation installs nothing.** The bare-metal track's host state arrives by image rebase, so a package installed by the activation act would be a mutable out-of-band change to an image-immutable host. The script confirms what the image gave it and fails loudly if the image did not give it.
2. **No password is set.** On this track the administrative user, its keys and its sudo hash are baked from the trust root at image build, because declarations are records. Activation has nothing to apply and reads no hash.
3. **The one human act is the same act.** A single GitHub device-flow approval opens the estate vault for the two things an image may never hold — the tailnet auth key and the pair's GitHub App private keys. Same shape as day zero on the VPS track, because it is the same law.
4. **The adapter is an addition, never a fork.** Everything that differs between the two lineages lives in `strix.env` and nowhere else. No file erebus uses is copied, and no unit branches on which pair is converging.
5. **One dev-container image serves both pairs.** `moros` and `nox` are two instances of one definition, differing by name and App identity. A second Containerfile would be the fork the bylaw forbids.
6. **The tailnet join advertises the LAN.** Unlike erebus, this host has a network behind it, and the registry records that subnet.
7. **Root retires, but only once `core` is provably usable.** Locking root on a machine whose replacement administrator has not been confirmed would strand it with no way in — the human summons C11 forbids.
8. **Nothing is written to the donor.** `strix-ms-s1-bootc` is read and adapted, never forked and never depended on at run time.

## Acceptance

The ticket's own eight criteria stand unchanged.

Criterion 1 — reaching a joined, App-activated host with a running dev container from one command — carries a prerequisite this ticket cannot clear, stated here rather than discovered at apply time. The strix pair's two GitHub Apps do not exist: the estate registry lists `oso-gato-strix-claudebox` and `oso-gato-moros-claudebox` as planned for when this pair rises, and creating a GitHub App is an act on github.com that no artifact can perform. Until the maintainer creates them and puts their keys in the vault, activation completes and the host joins the tailnet and runs its dev-container, but both boxes hold no GitHub authority and every step that touches an App says so rather than reporting green.

## Out of scope, and why

Applying any of this to the live machine, because that is the maintainer's act.

Changing `oso-gato/strix-ms-s1-bootc`, because it is a donor rather than a dependency or a fork.

The self-renewal chain (B4) and the ticket-envelope contract (B3), for the same reason they are out of #10.

GPU capability inside `moros`. The bare-metal track has a GPU as shared substrate, but nothing has yet asked the dev-container to use one, and a capability added before a decision needs it is footprint without a justification — which C3 forbids. Adding it later is a device mapping in the rendered unit, not a new image.
