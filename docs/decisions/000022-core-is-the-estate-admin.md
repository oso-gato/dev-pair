# 000022 — `core` is the estate's administrative identity

- status: accepted
- date: 2026-08-17

## Problem

The CoreOS convention was law in one repository and habit everywhere else. Universal C7 declared the estate *"container-first, Fedora CoreOS-style throughout"* but named no user. The administrative identity `core` appeared only in this repository's Security outcome 2 and in the bylaw's bare-metal instantiation, and the `core` declaration itself rests in the estate vault at `identity/core-user.md`. A repository chartered tomorrow would inherit the CoreOS style and not the identity that makes it concrete.

The gap surfaced while verifying the erebus OS record. The two lineages begin from different delivered identities — upstream Fedora Cloud Base locks root and creates a `fedora` user, while the VPS lineage's day zero begins at a root shell reached through the provider's own web console — and they were being reconciled by each lineage's day-zero contract rather than by a stated rule.

## Decision

Maintainer-instructed. On every host the estate operates, whatever its lineage or image, the first administrative user outside root is `core`. Root never authenticates remotely after genesis, and escalation is by sudo. A provider's out-of-band console is not remote authentication, so a root shell reached there is where day zero begins rather than an exception to the rule — the VPS lineage's pasted script creates `core` and retires root, the bare-metal lineage bakes `core` from the trust root at image build, and both arrive at the same identity by different paths.

It lands in C7, which already carries the CoreOS-style declaration, as the convention taken literally at the identity. C6 keeps what it already owns: the identity declaration is a record rather than a secret, its home is the trust root, and scope is minimal per capability. This repository's Security outcome 2 drops what has become re-dictation and keeps only what is scoped to the pair — the escalation password that exists for escalation only and never authenticates a remote shell.

## Options considered

- **C6 rather than C7** — considered seriously and declined. C6 owns identity in general, so the placement is arguable. C7 wins because the rule is not about scope or secrecy; it is the CoreOS convention taken literally, and C7 is where that convention is declared. Naming the user beside "Fedora CoreOS-style throughout" makes the two read as one decision.
- **Leave it scoped to this repository** — rejected: the next chartered repository would inherit the style without the identity, which is the shape that produces divergence across lineages.
- **Bind it per repository rather than per host** — rejected: a repository shipping a single container has no administrative user, so the rule is scoped to hosts the estate operates and binds nothing that has no host.

## Consequences

C7 gains the clause and the Authority trail records it. This repository's Security outcome 2 becomes a pointer plus its own scoped outcome. The bylaw's two lineage contracts already produce `core` and need no change — they are now instantiations of a stated universal rather than the only place the rule exists.
