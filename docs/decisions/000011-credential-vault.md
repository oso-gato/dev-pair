# 0011 — The credential vault: live credentials rest in the estate root

- status: accepted
- date: 2026-08-17

## Problem

Day zero on both lineages needs live credentials — the tailnet auth key and the pair's GitHub App private key. Universal P6 forbade credentials in any repository, which left them homeless: held ad hoc by the maintainer, pasted at provisioning, easy to lose, and impossible for the loop to draw on repeatably.

## Decision

By maintainer decision, overruling the agent's recommendation: the estate root, private, is the **credential vault** — the single repository where live credentials may rest. P6 is amended with that scoped exception; every other repository, image, and build remains bound in full. The trust-root rule is also fixed in the same act: the maintainer's key set is *every* public SSH key published on the `oso-gato` GitHub account, consumed live from `github.com/oso-gato.keys` and never hardcoded — three keys today, any number tomorrow.

## Options considered

- Runtime-prompt only, nothing at rest — the agent's recommendation: the strongest posture, but every provisioning act then depends on the maintainer's presence and personal key custody, which the maintainer weighed and declined.
- An external secret manager — rejected: a standing service to run, trust, and recover, contrary to P3 for a single-maintainer estate.
- Encrypting at rest inside the vault (sops/age) — not adopted now; it remains open as an implementation hardening the maintainer can take later without amending law.

## Consequences

The vault must remain private forever — flipping it public would expose every resting credential at once, and rotation is the only recovery, because git never forgets. The App PEM carries the App's full authority, so vault access now equals loop authority. In exchange, day zero draws from exactly one place, and the trust root propagates key changes to every host on its next converge.
