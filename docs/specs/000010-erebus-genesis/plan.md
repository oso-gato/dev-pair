# Implementation Plan: Genesis of the erebus pair

**Branch**: `claude/dev-pair-universal-constitution-4xtdos` | **Date**: 2026-08-17 | **Spec**: [spec.md](spec.md)

## Design

### Day zero splits at the one human act

Day zero cannot carry a credential and cannot ask twice, and those two constraints together fix its shape. It runs in two phases with the maintainer's single approval between them.

The first phase needs no authority at all. It installs the minimum from Fedora's own repositories, creates `core`, authorises the published key set from `github.com/oso-gato.keys`, hardens `sshd` to keys-only, and leaves the account password-locked. Everything here is public or local, so nothing gates it.

The second phase needs the vault. The script runs GitHub's device flow once, the maintainer approves the printed code, and the script then reads `oso-gato/homelab-root` → `identity/` for the three things an artifact may never hold — the `core` sudo hash, the tailnet auth key, and the erebus GitHub App credentials. It applies them, hands off to the converger, and retires root. The device-flow token lives in an ephemeral directory that the exit trap destroys, so a power loss mid-run strands nothing on disk.

This replaces the donor's own credential source. The donor pulls a `firstboot.yaml` from a separate private repository; the estate's vault is `homelab-root` → `identity/` by ADR 000011, and a second credential home would be exactly the duplication C1 forbids. The decision binds every future pair, so it graduates to `docs/decisions/`.

### The converger is units under one entry point

`host/converge/converge.sh` is the entry point and the only supported way to change the host. It sources one environment adapter, then runs numbered units in order, each idempotent on its own. Re-running the whole thing is the normal case, not the recovery case.

Idempotence is a property of each unit, never of a guard around it. A unit reads the live state, computes what the declaration requires, and acts only on the difference — so the second apply reports no change because there is no difference to act on, not because a sentinel told it to skip.

The per-environment adapter is `host/converge/environments/erebus.env`, and it holds only what differs between hosts. This is the bylaw's own rule that onboarding a new environment is an adapter addition and never a fork, so strix will add its own file beside erebus's rather than copy the tree.

### Provenance is enforced at the fetch, on the host

Every package on the host comes from Fedora's own repositories or from a vendor repository with both signature checks on. `install_weak_deps=False` is set on every installation, bootstrap paths included, per the bylaw's minimalism flag.

The verification runs where the network is — on the host, at apply time, fail-closed. This session could not reach `quay.io`, `pkgs.tailscale.com` or `downloads.claude.ai`; the environment's network policy answered 403 to all three. That is recorded honestly in the provenance trail rather than papered over with a check that did not happen, and the artifact is built so the maintainer's apply is itself the live check: a missing key, an unsigned repository or a failed signature installs nothing and stops the run.

### The agent box is shared code, because both components run one

C8 pairs boxes by agent across a pair's components, so `claudebox` exists on the host and on `nox` alike. The manifest, the post-assemble bridge and the managed settings are therefore genuinely shared, and they live in `shared/claudebox/` — the one case in this ticket that meets the bar for `shared/`.

Host-side operator scripts are pair-neutral and prefixed `pair-`, because `host/` serves both tracks and a per-pair copy would be the fork the bylaw forbids. Box scripts keep the `claudebox-` name C8 gives them.

### `nox` is built by CI and launched from outside

CI builds the `nox` image from `dev-container/Containerfile` and publishes it to `ghcr.io`; the host pulls that image and launches it. Neither component builds production images, which is the objective's own boundary, so `dev-container/build.sh` produces a throwaway validation candidate and nothing else.

The host launches and relaunches the container from outside, and the dev-container never rebuilds itself — B4's rule holding even before the self-renewal chain exists. Sessions survive disconnection because the durable state is the ticket bus and the mounted work volume, never the layer.

## Provenance, as adopted

| artifact | level | source | pinned | verified |
| --- | --- | --- | --- | --- |
| base OS | provider template, upstream unverified | Hostinger stock `Fedora Cloud 44` | template, as provisioned | maintainer 2026-08-17, registry |
| host packages | L1 | Fedora 44 repositories | release-pinned | at fetch, on the host |
| `tailscale` | L2 | `pkgs.tailscale.com/stable/fedora` | `gpgcheck=1` + `repo_gpgcheck=1` | donor trail 2026-07-11; not re-checkable this session |
| `claude-code` | L2 | `downloads.claude.ai/claude-code/rpm/latest` | `gpgcheck=1`, key `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE` | donor trail; not re-checkable this session |
| `fedora-toolbox:44` | L1 | `quay.io/fedora/fedora-toolbox` | tag `44`, never `latest` | donor trail; not re-checkable this session |
| trust root | — | `github.com/oso-gato.keys` | live, consumed at run time | C6 |

Every row whose verification reads "not re-checkable this session" is re-verified by the host at apply time, fail-closed. None is trusted on this session's word.

## Not in this ticket

The self-renewal chain (B4) and the ticket-envelope contract (B3), both out by the ticket's own scope.

Any mechanical conformance gate. C3 forbids a mechanism before the thing it serves, and issue #9 was withdrawn for exactly this.

## Decisions that graduate

Two bind beyond this ticket and become records — the vault-pull day zero, and the donor relationship with `oso-gato/strix-ms-s1-bootc` together with the prior fleet's exclusion.
