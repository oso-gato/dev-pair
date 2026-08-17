# 000027 — `strix-ms-s1-bootc` is a donor, and the prior fleet is out of scope

- status: accepted
- date: 2026-08-18

## Problem

The pair had to be built and three repositories outside this one had a claim on the work, with nothing on record saying what any of them was for.

`oso-gato/strix-ms-s1-bootc` is built, CI-built, and running the strix host. It already contains working answers to problems this ticket faces — a disposable `claudebox` layer, a GitHub App token minter, a trust-root key sync, a signed vendor repository, a keys-only `sshd` policy. The registry names it as strix's OS and `ARCHITECTURE.md` records that it exists, but neither says whether this repository may take from it, must depend on it, or should ignore it.

`oso-gato/noir-strix-halo-fcos`, `oso-gato/fedora-dev` and `oso-gato/fedora-bootstrap` are the prior fleet. Two of them were audited on 2026-08-17 and the audit is why C3 gained its no-sieves and no-mechanism-before-its-subject clauses — 6,164 lines of watchers over a 641-line loop, and a last recorded defect of a failed apply reporting green. They were never declared out of scope in writing, so their code remained quietly available to be copied by an agent that found it and assumed availability meant sanction.

## Decision

Both facts come from the maintainer and are recorded here because no repository held them.

**`strix-ms-s1-bootc` is a donor.** This repository reads it, takes patterns and code from it with attribution, and adapts them to the estate's current law. It is not forked, not vendored, and not depended on at run time: nothing this repository produces fetches from it, and nothing here breaks if it changes. The donor relationship is one-directional and ends at the copy — once a pattern lands here it is this repository's, and its future is decided here.

Two donations were taken and both were changed on the way in. The `claudebox` layer, its rebuild machinery and the session lock arrived close to verbatim, because C8 is the same law on both tracks and the donor's lock discipline already solved "never interrupt a live session" correctly. The App-token minter and the key sync arrived with their paths made pair-neutral and their credential source repointed at the estate vault, per ADR 000026. What did not come across is the donor's own credential repository, which predates the vault decision.

The donor also decides the strix ticket's shape. Strix is lineage 2, its host image is already built and working, and it therefore needs no host build at all — its remaining work is `moros`, its App identities, and the activation act. That is a different and much smaller ticket than erebus's, and it follows erebus rather than preceding it because the VPS is the more stable surface while strix carries more load and full virtualization.

**The prior fleet is out of scope entirely.** `noir-strix-halo-fcos`, `fedora-dev` and `fedora-bootstrap` are not read, not cited, and not copied from. Where the donor's own comments reference them, those references are not carried forward. This is a boundary rather than a judgement on the code: the estate has already extracted what it learned from that fleet, and it extracted it as law in C3 rather than as source to reuse.

## Options considered

- **Fork `strix-ms-s1-bootc` into this repository.** Rejected. The bylaw's own rule is that onboarding an environment is an adapter addition and never a fork, and a fork would give the strix host two homes competing to define it.
- **Depend on it at run time**, fetching its scripts during converge. Rejected. It would make a second repository load-bearing for every apply, and C4's one-fetch-contract point is that the privileged path must not reach for definitions it cannot verify. The donor is also a bare-metal artifact; making the VPS track depend on it would couple the two tracks the objective keeps separate.
- **Ignore it and write everything fresh.** Rejected. It is built and working, its patterns are already estate-verified, and rewriting a solved lock discipline from scratch would have been the more likely source of a defect, not the less.
- **Leave the prior fleet's status unstated**, on the grounds that nobody is using it. Rejected, and this is the option the record exists to close. Availability reads as sanction to the next agent, and the fleet's audit is recent enough that its code still looks current. Silence here is how a refused pattern comes back.

## Consequences

`ARCHITECTURE.md` records the donor relationship on the strix line, so the map says what the repository is for rather than only that it exists.

Provenance rows carried from the donor keep the donor's verification date rather than borrowing today's. The session that built erebus could not reach `quay.io`, `pkgs.tailscale.com` or `downloads.claude.ai` — the environment's network policy answered 403 — so no donor-verified fact was re-checked live, and the trail says so. The artifact verifies at fetch time on the host instead, fail-closed, which is where C4 puts admission anyway.

One gap is now explicit. Tailscale's signing-key fingerprint is unpinned, because the donor pins none and this session could not verify one. The fetch contract pins whatever key it first sees and verifies every later fetch against it, so tampering after admission fails closed, but the first fetch rests on TLS alone. The first session with upstream reach should pin it.
