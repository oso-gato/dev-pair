# BUILD PRINCIPLES — v1

> **THE HOW WE BUILD** — how every artifact is constructed, whatever it does.
>
> **Universal.** These principles bind **every project the pair develops**, not this
> repository alone. They are vendored from a single fleet home and pinned by version. **Do
> not edit this file in place** — amend it at the fleet home, publish a new version, and
> re-pin the projects that adopt it. A CI check enforces byte identity with the pinned
> version.
>
> **Status: DRAFT — pending maintainer confirmation.** Confirmed with a project's objective
> and sharing its authority: fixed thereafter, amendment is a new maintainer confirmation,
> maintainer-merge-only.
>
> **Scope.** In: uniform construction constraints binding every artifact built under them —
> host configuration, container images, workload images, and every throwaway build and
> throwaway tree alike, whatever the artifact does. Out: intent and outcomes (the
> objective's), per-project requirements (`01-SPEC.md`), per-project construction
> constraints (that project's objective §Constraints), and the system's arrangement
> (`02-DESIGN.md`).
>
> **They are capabilities, not implementations:** a requirement says what a thing must
> *do*; a build principle says how anything built must be *made*.
>
> **The aim:** that anything built under these principles is built the one proven way —
> minimal, provenanced, disposable, verified — without construction law being re-decided
> per artifact, per project, or per session.
>
> **Success and acceptance:** a change conforms when it passes every principle that applies
> to it — by mechanical scan where a scan exists, by adversarial review where judgment is
> required. **A principle that cannot be checked cannot bind:** each must be enforceable in
> fact, or it is defective.
>
> **Identifiers.** `UNI-P<n>`. A project-specific construction constraint is never given a
> `UNI-P` number — it belongs to that project's objective.

---

## UNI-P1 — PROVENANCE

Every artifact entering **any** tree built under these principles is admitted
**fail-closed and version-pinned at the strongest level it admits** of a three-level
hierarchy: **L1** the distribution's own repos; **L2** the vendor's own package or repo
definition with signature verification enabled (and repo-metadata signatures where the
vendor publishes them); **L3** last-resort official-upstream binary, provenance-graded
(**c1** GPG signature > **c2** published checksum > **c3** resolve-log) and disclosed per
artifact. Descending to a lower level a higher one would satisfy is a defect. Forbidden
outright and enforced by mechanical scan: third-party community repos, language package
managers onto PATH, tarballs onto PATH, curl-pipe-sh, mirror/aggregator binaries, and
unsandboxed universal-package formats. Disposability grants no exemption. **One
pinned-fetch contract serves the whole platform** — every component fetches pinned
artifacts through the same mechanism with the same strength; provenance is a constant,
never a per-component achievement. (A repo definition fetched unverified on the most
privileged component while pinned on another is the canonical violation.)

## UNI-P2 — VERIFY-BEFORE-ADOPT

Before adopting or bumping **any** source, version, or artifact, its existence and identity
are **fact-checked against the live upstream** — not asserted from memory or a stale pin —
and a **risky install** (a version-mismatched vendor package, a new repo definition, an L3
binary) is **exercised in a scratch throwaway before it is wired into a real build file**.
Every adoption leaves a recorded trail: artifact, level/grade, pin, adoption date, last
live-check date. **Environment and release-specific facts** (provider console behavior,
image vintage, hardware, virtualization capability, GPU availability, network shape,
package splits) expire: they are re-verified against the live environment **per environment
and per release**. A new environment is onboarded by **verifying its facts**, never by
assuming them, and never by forking. A source adopted without a live fact-check, or a risky
install wired in unproven, is a reviewable defect.

## UNI-P3 — CAPABILITY-RELATIVE MINIMALISM

Every package and artifact is installed at the **minimal leaf footprint for its decided
capability**: nothing enters any built tree without a **recorded justification**; weak
dependencies are disabled on **every** package installation, including bootstrap paths that
would otherwise inherit an upstream default; the most specific leaf package is chosen over
any convenience metapackage; the irreducible hard-dependency closure of a chosen capability
is accepted and disclosed, not fought. Minimality is **capability-relative** — between
equal-capability options prefer the smaller, higher-provenance one; **dropping a capability
to shrink the footprint is a recorded capability trade-off, never a minimalism win.**

Minimalism binds machinery as well as packages — see **UNI-P8**.

## UNI-P4 — ISOLATED WORKING TREE

Every authoring or build action runs in a **fresh, per-session-namespaced working tree that
never mutates the immutable live tree, a shared clone, or another session's tree**. All
mutable local state (worktree roots, locks, markers, scratch) is namespaced per session.
The checked-out branch is **re-verified to belong to the session's own namespace before
EVERY commit and EVERY push** — at the authoring sites and at the harness's own commit/push
sites alike, the harness being the most important case. The `cd` into an isolated tree is a
**fail-closed guard**, never a prefix: a failed enter runs no mutating step in the caller's
directory. A mutating action outside an isolated tree, or a commit/push without branch
re-verification, is UNSAFE.

## UNI-P5 — TEST-QUALITY / MUTATION-PROVEN

Every behavioral change ships a test that **drives the real execution boundary** (the actual
engine, git, kernel, or process semantics under test — not a stub asserting what a mock was
told) and is **proven to fail against the pre-change code**; a test that passes against the
unfixed code is a defect. Guards are **mutation-checked in-suite**: the pre-fix behavior is
mechanically restored on a copy and the row must fail. **Production-only lines** — the paths
no test seam substitutes — must be covered by a real-body test or by the live acceptance
gate, and the suite must contain **no line whose production invocation has never been
executed** (the measured lesson: an untested production invocation fails silently at scale).
Where the behavior under test needs a capability the primary environment lacks, it runs on
an environment that has it — **validation never simulates what another available environment
can prove.** **The suite gates**: tests run at the merge boundary bound to the exact head
sha — a test culture that cannot stop a merge is decoration, not proof. A permanently-failing
test or probe is fixed or removed, never tolerated (UNI-P8's no-standing-red).

## UNI-P6 — DOCUMENT ARCHITECTURE

**Every repository built under these principles carries the same spine, in the same
places, with the same ownership.**

| Path | Holds | Class |
|---|---|---|
| `AGENTS.md` | Router. Points at everything; states no law. Not a rung. | mutable |
| `README.md` | Human orientation. No law. Not a rung. | mutable |
| `00-OBJECTIVE.md` | Why, outcomes, boundaries, this repo's constraints | **fixed** |
| `00-BUILDPRINCIPLE.md` | This document, vendored and pinned | **fixed** |
| `01-SPEC.md` | What the product must do, traced to `OB-n` | derived, checked |
| `02-DESIGN.md` | How it is arranged | mutable |
| `docs/adr/` | Why it is arranged that way, and what was rejected. Append-only. | mutable |
| `CHANGELOG.md` | Incident narrative. Append-only. | mutable |
| `.github/CODEOWNERS` | Ownership of the fixed documents, enforced | **fixed** |

**A number means the file is a rung on the derivation chain, in order. No number means it
is not one.** Authority on conflict follows the same order: build principles and objective
first, then specification, then design, then tickets, then code. A lower document
disagreeing with a higher one is defective, not authoritative.

**Ownership is enforced, not asserted.** `CODEOWNERS` plus branch protection is what makes
maintainer-merge-only true; a filename convention is not a gate.

**Source layout below the spine is per-project** and is declared in that project's
objective — never here.

**One authoritative home per concept; every other mention is a one-line pointer or
deleted.** Shared content is **vendored from one home**, never copied by hand; where bytes
must be identical, a mechanical check enforces identity — and the preferred fix for
duplication is de-duplication, not another checker. Evidence and benchmarks live only in
the principle they prove. Incident narrative belongs to the changelog: **memoir is not
specification.** A document asserting behavior the code does not have is UNTRUE and a
blocking finding.

## UNI-P7 — RECOVERY-BEFORE-POWER

**No mechanism may block the loop without carrying a bounded, automatic recovery.** A gate
that is unavailable, stalled, or erroring must retry, fail over, or degrade under a recorded
policy — and surface to the maintainer only after its bounded attempts fail. **Detection may
only be added together with recovery**: a change introducing a blocking gate with no
self-heal path is UNSAFE, because a fail-closed gate with no recovery is a human summons,
and the single-interaction law forbids those. Every autonomous mutation is reversible —
merge (revert), deploy (rollback), refresh (re-converge), closure (reopen) — and each
recovery path is proven by a test (UNI-P5), not by a standing drill framework that itself
needs managing.

## UNI-P8 — GATES ARE FEATURES

Every gate, check, watcher and probe built under these principles **is itself a feature,
and is justified like one** — security machinery is not exempt. A mechanism is warranted
only if it **(a) guards a real trust boundary, (b) reads an artifact rather than an
opinion, and (c) is wired to a decision it can change.** A check that can change no outcome
is telemetry and lives in the log, not in a gate. Machinery exists to move the objective's
artifacts — **never to manage other machinery**: a component whose only consumer is another
component's failure mode is the same component. **Activation-proof:** no actuator is
declared built until its **first measured live success** is recorded — a merged, unproven
mechanism is scaffolding, and a permanently-red probe is deleted or fixed, never tolerated
(a standing red trains the loop to ignore alarms, which is worse than no alarm).

---

## Provenance note

Consolidated from the fleet's `fedora-dev/00-BUILDPRINCIPLE.md` (BP1–BP9), the host-side
instantiation drafted for `fedora-bootstrap`, and the zero-base architectural review of the
pair (2026-08-02).

UNI-P1=BP1 (strengthened: one fetch contract; repo-metadata signatures) · UNI-P2=BP2
(strengthened: environment/release re-verification; adoption trail) · UNI-P3=BP3 · UNI-P4=BP6
(strengthened: harness sites named) · UNI-P5=BP8 (extended: the suite gates;
production-only-line rule) · UNI-P6=BP9 (extended: the document spine made universal and
mechanically checkable; vendoring preferred over parity checkers;
memoir-is-not-specification) · UNI-P7=new (codified from the measured gate-without-recovery
incidents) · UNI-P8=new (split out of BP3's minimalism doctrine: gates-are-features,
activation-proof, no-standing-red).

**Descoped to project objectives.** BP4 (immutable host / containerise-everything), BP5
(throwaway builds and cache invariant), BP7 (atomic contracts), and the disposable
agent-layer discipline were previously carried here as repo-specific principles. They
describe one product's construction, not universal law, and now live in that project's
objective §Constraints. Removing them from this document is what makes it genuinely
portable.
