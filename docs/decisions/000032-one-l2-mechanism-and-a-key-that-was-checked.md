# 000032 — One L2 mechanism, and every repository key checked before it is trusted

- status: accepted
- date: 2026-08-18
- supersedes: the composed-definition path in [000031](000031-fedora-dev-narrowed-to-a-consult.md), which recorded `prov_l2_repo` as the place a fingerprint pin would eventually land

## Problem

C4 asks for one fetch mechanism per system at one strength, and names the canonical violation: a definition fetched unverified on the most privileged component while pinned on another. This repository had two mechanisms at L2 and neither reading of that sentence was comfortable.

The converger carried `prov_l2_repo`, which composed a repository definition from arguments — an id, a name, a baseurl, a key URL — and wrote this repository's transcription of the vendor's file rather than the file. ADR 000031 then added `prov_l2_vendor_repo`, which fetches the vendor's own `.repo` and pins the whole file by checksum, and moved Tailscale onto it. The weaker function was left in place. Nothing called it, on either lineage, ever.

A transcription cannot detect the substitution it is exposed to, because the transcription is the thing the comparison is made against. A moved baseurl or a swapped signing-key URL passes silently. Leaving that function available was leaving the weaker mechanism there to be reached for, which is the condition C4 was written to prevent.

The second instance was worse and had gone unnoticed. The claudebox manifest wrote Anthropic's repository definition inside a `pre_init` hook, with `gpgkey` naming a remote URL. Under `dnf -y` that auto-imports whatever key the URL serves at the moment the box is assembled. The manifest recorded the expected fingerprint in a comment directly above, where a reader would reasonably take it for a control. It was never compared against anything.

## Decision

`prov_l2_repo` is deleted. `prov_l2_vendor_repo` is the one L2 mechanism: the vendor's own file, pinned by checksum, fail-closed on every path including a cache hit.

The claudebox repository work moves out of the manifest hook and into `shared/claudebox/claudebox-agent-repo.sh`, run by `claudebox-init.sh` over the quote-safe channel the manifest's own rule already reserved for work that needs redirection and comparison. The signing key is fetched, compared against the pinned fingerprint before anything is imported, installed locally on a match, and the definition names that local file. A substituted key now stops the box build instead of producing a box that looks finished. `claude-code` leaves `additional_packages` for the same reason: admission needs a comparison, and a hook cannot express one.

Both are held by the self-test rather than by prose. The blocking rule is the security property — no repository definition anywhere in `host/`, `dev-container/` or `shared/` may name a remote `gpgkey` — with a second check that the fetch contract itself composes nothing, which is `prov_l2_repo` returning. Both patterns are mutation-checked against a definition of the kind they forbid, so a green result means absence rather than a pattern that matches nothing.

## Options

**Keep `prov_l2_repo` for vendors publishing no `.repo` file.** Rejected. No vendor on either lineage needs it and none ever did, so it was scaffolding kept warm against a need nobody has had — the estate's own measured failure mode, which AGENTS.md names directly. A vendor that publishes no file is a case to grade against that real vendor when it arrives.

**Narrow the check so the claudebox site stops matching.** Rejected outright, and worth recording because it was available and quick. The check fired on its first run against real code. A gate tuned until it passes is a gate that proves nothing, which is the failure C3 and C9 exist to refuse.

**Leave the check failing and record the gap.** Rejected. The hazard it named — an unchecked key import — was fixable from this session without upstream reach, because the fingerprint was already in the tree and only needed to be made load-bearing. A recorded gap is for what cannot be closed, not for what can.

**Pin Anthropic's own `.repo` by checksum, matching Tailscale.** Not available. This session could not reach `downloads.claude.ai` at all, so it learned neither whether such a file is published nor what it contains. Inventing a pin would be a claim of verification that never happened (C5).

## Consequence

One L2 mechanism in the converger, and one admission path per non-Fedora repository, each verifying against something that was checked.

The residue is stated rather than rounded away. The claude-code definition is still this repository's own transcription against Anthropic's baseurl, so a substituted baseurl would not be detected — bounded by TLS at fetch and by `gpgcheck` against the pinned key on every package thereafter. That is the same shape of gap ADR 000031 closed for Tailscale, and it closes the same way: the first session that can reach the vendor pins the vendor's own file by checksum, or records that no such file exists.

Adding the script exposed a second asymmetry worth a check of its own. The dev-container image copies `shared/claudebox/` wholesale while the host's agent-box unit names each file, so a file added to that directory arrives in the container and is silently absent on the host — where `claudebox-init.sh` would then fail mid-rebuild on a path that exists everywhere it was tested. That is what happened here, on the first file added. The self-test now holds the unit's list against the directory.

The pinned fingerprint has one home, in the script that enforces it. It was previously a comment in the manifest, and a fact in two places where only one is enforced is the drift C1 forbids.
