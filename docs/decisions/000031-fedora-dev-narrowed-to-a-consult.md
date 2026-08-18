# 000031 — `fedora-dev` narrowed from excluded to surgically consulted

- status: accepted
- date: 2026-08-18
- supersedes: the blanket exclusion in [000027](000027-strix-bootc-is-a-donor.md), in part

## Problem

ADR 000027 recorded the maintainer's instruction that the prior fleet — `noir-strix-halo-fcos`, `fedora-dev`, `fedora-bootstrap` — was out of scope entirely, not read and not cited. That exclusion was written to stop a refused pattern coming back, and it stands as the default.

Two questions then arose that the exclusion could not answer well. Whether a distrobox will assemble inside a rootless container, and how to publish a container's own SSH and mosh doors without colliding with the host's. Both are empirical, both were untested here, and the author said so — flagging the nested box as likely fragile or broken rather than claiming otherwise.

`fedora-dev` runs exactly that stack in production and publishes exactly those doors. Excluding it meant either shipping an untested guess or re-deriving, by trial on a live host, an answer that already existed.

## Decision

The exclusion is narrowed, by maintainer instruction, and the narrowing is deliberately small.

`fedora-dev` may be consulted **on named, already-working points**, when the alternative is guessing at something it has measured. It was consulted on exactly two: the nested agent box, and public port exposure for the dev-container. Nothing else in that repository was read for adoption, and the fleet's architecture — its watchers, its gates, its doctrine — remains out of scope and remains what C3's no-theatre clauses were written about.

The maintainer's framing is worth preserving, because it draws the line better than the original exclusion did. The consult was not outside the objective or the constitution; it was outside one instruction, and the instruction was his to narrow. The test he applied was whether the finding served something already intended rather than opening a new direction.

Three things came back, and all three were things this repository already meant to do.

**The nested box works, and needs five specific declarations.** Recorded in full at [000029](000029-the-nested-agent-box.md). One of them corrected a live defect: subordinate ID ranges here were sized to the host-side habit and could not fit inside the outer rootless map, so the first box assemble would have failed.

**The port scheme.** Recorded at [000030](000030-both-components-on-the-tailnet.md). SSH published on 4444 to 22, mosh one-to-one above 61000 to clear the host's default range.

**The vendor repository pinned by checksum.** This one closed a gap this repository had already opened and recorded. ADR 000027 and `ARCHITECTURE.md` both stated that Tailscale's signing key was unpinned and that the first session with upstream reach should pin it, and `prov_l2_repo` was built with an optional fingerprint parameter for exactly that purpose. The session could not reach the vendor, so the gap stood.

The mechanism found is not the one that was planned, and it is better. Pinning the sha256 of the vendor's own `.repo` file means fetching Tailscale's definition rather than transcribing it, and it fails closed when upstream changes — so a swapped `baseurl` or a swapped `gpgkey` URL stops the run instead of silently redefining where packages come from. A hand-written definition cannot detect either.

It is not the same guarantee as a key fingerprint pin, and the disclosure says so. A substituted key served at the pinned URL remains possible, bounded by TLS and by `gpgcheck` on every package fetch thereafter. The gap is narrowed substantially rather than closed, and the residue is stated rather than rounded away.

## Options considered

- **Keep the blanket exclusion and ship the untested nesting.** Rejected by the maintainer, and rightly: it would have shipped a known-doubtful mechanism to a live host to preserve a boundary that exists to prevent bad patterns, not good facts.
- **Keep the exclusion and re-derive both answers by trial on the VPS.** Rejected. C5 asks for verification against something live before adoption; a working implementation is exactly that, and trial-and-error on the maintainer's host is a worse instrument, not a purer one.
- **Reopen the fleet generally, since parts of it evidently work.** Rejected, and this is the boundary the narrowing protects. The fleet's audited failure was its architecture, not its device flags. Consulting it for a measured operating fact is not the same act as taking its shape back.
- **Adopt the checksum pin without recording that it fell outside the instruction.** Rejected. The scope of an instruction is part of the record, and quietly widening one is how an exclusion decays.

## Consequences

`prov_l2_vendor_repo` admits a vendor's own definition pinned by checksum, fail-closed on every path. `30-tailnet.sh` and the dev-container image both use it, with the pin and its re-check command stated at the point of use, so a bump is a deliberate act after a live verification (C5).

`ARCHITECTURE.md`'s open-gap line changes from an unpinned signing key to the narrower residue that remains.

**A bylaw sharpening is recommended, and it is the maintainer's to make.** C4 already requires the strongest provenance a source admits and calls settling lower a defect, so the constitution needs nothing: the checksum-pinned vendor definition is compliance with C4, not an amendment to it. But this repository's own Fedora instantiation of L2 describes the weaker form — a `.repo` with `gpgcheck=1` and `repo_gpgcheck=1` — which reads as licensing a hand-written definition and is what the author first built. The instantiation under-describes what C4 demands, and the objective needs no change at all, since package admission is a HOW rather than a WHY.

The consult also confirmed something worth keeping: the author's doubt about the nested box was correct in substance and wrong in conclusion. Saying "I have not tested this and think it may be broken" is what made the consult possible, and it is a better failure mode than confidence would have been.
