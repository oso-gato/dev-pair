# 000028 — One dev-container image for every lineage, and the track decides which units apply

- status: accepted
- date: 2026-08-18

## Problem

Two questions arrived together when the second lineage was built, and each would have produced a fork if answered carelessly.

The first was what `moros` is. Issue #10 delivered `nox` as the erebus pair's dev-container, and named it accordingly all the way down: the published image was `ghcr.io/oso-gato/nox`, the entrypoint `nox-session`, the enter command `nox`, and the Quadlet a file with `nox` written through it. Building `moros` from that shape means copying four files and changing a word in each, and then maintaining both — which is precisely the fork the bylaw forbids when it says onboarding an environment is an adapter addition.

The second was whether the converger runs on strix at all. The bylaw gives each track exactly one sanctioned deploy mechanism: the idempotent converger for the VPS track, image rebase with atomic rollback for bare metal. Strix's host state is baked into `oso-gato/strix-ms-s1-bootc` and arrives by rebase. Running the full converger there would put two mechanisms in charge of the same facts, and its package-installing units would perform exactly the mutable out-of-band change to a deployed artifact that C7 forbids. Running none of it leaves `moros` with nothing to create it, because the donor image has no dev-container at all.

## Decision

**One dev-container image, instantiated per pair.** The image is `ghcr.io/oso-gato/dev-container`, built by CI from one Containerfile. `nox` and `moros` are two instances of it, and they differ in exactly two facts — their name and their App identity — both of which are adapter values. The Quadlet is a template the converger renders per pair, failing closed on an unset variable or a leftover placeholder rather than starting a container with a blank image name. The entrypoint is `pair-session`. The enter command is one source file, `pair-enter`, installed under the dev-container's own name and taking the container it drives from how it was invoked, so `nox` and `moros` are the same script.

The pair-specific names in #10's output are corrected in the same change that adds the second lineage, rather than left for this ticket to work around. A known-wrong name that ships is harder to remove than one that never did, and both tickets are on one unmerged branch.

**The track declares which units apply.** The adapter carries `CONVERGE_UNITS`. Unset means every unit, which is what the VPS track wants, because there the converger *is* the deploy mechanism. Strix names the two the image does not carry — the estate's pair-neutral App minter and the dev-container — and no others. The converger's preamble, which installs its own fetch tooling, is gated the same way and for the same reason.

This keeps each track's sanctioned mechanism sole owner of what it owns. The image owns strix's OS state; the converger owns erebus's; and the pair-level state that neither image nor provider supplies is owned by the converger on both, because it is the only thing that can own it.

## Options considered

- **A second Containerfile for `moros`.** Rejected. The two components have identical software roles; what differs is runtime configuration. A second image would have been two homes for one definition, and the first divergence between them would have been silent.
- **Keep `nox` as the image name and tag `moros` from it.** Rejected. It would leave one pair's name on an artifact both pairs depend on, which is the naming defect rather than a fix for it, and it would read as erebus owning strix's dev-container.
- **Run the full converger on strix and let its units no-op.** Rejected. The units would still install packages on an image-immutable host — the C7 violation is in the attempt, not in whether it changed anything — and two mechanisms declaring the same facts is the duplication C1 forbids however quietly they agree.
- **Run no converger on strix and put `moros` in the donor image.** Rejected. It would mean writing to a donor, which ADR 000027 rules out, and it would make the dev-container a property of the host image rather than of the pair — so a rebase would be needed to change a container.
- **Add GPU capability to the shared image now**, since the bare-metal track has one. Rejected. Nothing has yet asked the dev-container to use a GPU, and C3 is explicit that a capability enters on a recorded decision rather than because the hardware exists. When something needs it, it is a device mapping in the rendered unit, not a second image.

## Consequences

`strix.env` is the only file in the tree outside documentation that mentions strix, and the self-test proves it: it renders the shared template against every adapter, requires every adapter to declare the full variable set, and fails if any unit or library branches on a pair name. The bylaw's adapter rule is therefore a checked fact about this tree rather than an aspiration in it.

A third lineage is one adapter file. Nothing else changes.

The strix pair's two GitHub Apps do not exist — the registry lists both as planned — and no artifact can create one. The adapter carries their names with empty IDs, and activation treats an empty ID as a warned, non-fatal state: the host still joins the tailnet and still runs its dev-container, and the boxes hold no GitHub authority until the maintainer creates the Apps and re-runs. Making it fatal was rejected, because it would block two working outcomes on a prerequisite unrelated to either.

One check had to be repaired before it was trustworthy. The first version of the no-branching test matched the `if` inside `verify` and fired on a comment — a guard reporting a finding it could not justify, which is the failure the constitution's own preamble names. It is word-boundaried and skips comments now, and it is worth recording that the estate's measured failure mode showed up inside the mechanism written to prevent it.
