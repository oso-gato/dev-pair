# The Dev Pair — BUILD PRINCIPLES (construction spec of record)

> **THE HOW WE BUILD** — how every artifact is constructed, whatever it does.
>
> **Status: DRAFT — pending maintainer confirmation.** Confirmed with the objective
> (`00-OBJECTIVES.md`) and sharing its authority: fixed thereafter, amendment is a new
> maintainer confirmation, MAINTAINER-MERGE-ONLY. These principles serve the twofold
> objective — the autonomous dev-pair loop workflow first, the mother platform second —
> and must never contradict it. They are **capabilities, not implementations**: a
> functional requirement says what a thing must *do*; a build principle says how anything
> the platform builds must be *made*.
>
> **Scope.** In: uniform construction constraints binding **every artifact the platform
> builds** — the host configuration, the dev-container image, workload images, and every
> throwaway build and throwaway tree alike — whatever the artifact does. Out: intent and
> outcomes (the objective's), per-project requirements (each project's own locked spec),
> and the system's arrangement (the design's).
>
> **The aim:** that anything built under these principles is built the one proven way —
> minimal, provenanced, disposable, verified — without construction law being re-decided
> per artifact or per session.
>
> **Success and acceptance:** a change conforms when it passes every principle that
> applies to it — by mechanical scan where a scan exists, by adversarial review where
> judgment is required. A principle that cannot be checked cannot bind: each must be
> enforceable in fact, or it is defective.
>
> Consolidated from the fleet's `fedora-dev/00-BUILDPRINCIPLE.md` (BP1–BP9), the host-side
> instantiation drafted for `fedora-bootstrap`, the zero-base architectural review of the
> pair, and the twofold-objective restatement (2026-08-02). A mapping note closes this
> document.

## P1 — PROVENANCE

Every artifact entering **any** tree the platform builds — host, dev-container, workloads,
and every throwaway alike — is admitted **fail-closed and version-pinned at the strongest
level it admits** of a three-level hierarchy: **L1** Fedora's own dnf repos; **L2** the
vendor's own RPM or dnf `.repo` with `gpgcheck=1` (and repo-metadata signatures where the
vendor publishes them); **L3** last-resort official-upstream binary, provenance-graded
(**c1** GPG signature > **c2** published checksum > **c3** resolve-log) and disclosed per
artifact. Descending to a lower level a higher one would satisfy is a defect. Forbidden
outright and enforced by mechanical scan: COPR/third-party repos, language package managers
onto PATH, tarballs onto PATH, curl-pipe-sh, mirror/aggregator binaries, flatpak, snap.
Disposability grants no exemption. **One pinned-fetch contract serves the whole platform** —
host and dev-container fetch pinned artifacts through the same mechanism with the same
strength; provenance is a platform constant, never a per-component achievement. (A repo
definition fetched unverified on the most privileged component while pinned on another is
the canonical violation.)

## P2 — VERIFY-BEFORE-ADOPT

Before adopting or bumping **any** source, version, or artifact, its existence and identity
are **fact-checked against the live upstream** — not asserted from memory or a stale pin —
and a **risky install** (a version-mismatched vendor RPM, a new `.repo`, an L3 binary) is
**exercised in a scratch throwaway before it is wired into a real build file**. Every
adoption leaves a recorded trail: artifact, level/grade, pin, adoption date, last
live-check date. **Provisioning-environment and release-specific facts** (provider console
behavior, cloud-image vintage, hardware, virtualization capability, GPU availability,
network shape, package splits) expire: they are re-verified against the live environment
**per provisioning environment and per Fedora release**, because the host is
environment-agnostic by objective. A new environment — a new cloud provider, a local
bare-metal machine — is onboarded by **verifying its facts**, never by assuming them, and
never by forking the platform. A source adopted without a live fact-check, or a risky
install wired in unproven, is a reviewable defect.

## P3 — CAPABILITY-RELATIVE MINIMALISM

Every package and artifact is installed at the **minimal leaf footprint for its decided
capability**: nothing enters any built tree without a **recorded justification**;
`install_weak_deps=False` applies to **every** package installation on the platform,
including bootstrap paths that would otherwise inherit an upstream default; the most
specific leaf package is chosen over any convenience metapackage; the irreducible
hard-dependency closure of a chosen capability is accepted and disclosed, not fought.
Minimality is **capability-relative** — between equal-capability options prefer the smaller,
higher-provenance one; **dropping a capability to shrink the footprint is a recorded
capability trade-off, never a minimalism win.**

**Gates are features.** The same discipline binds every gate, check, watcher, and probe the
platform builds — security machinery is not exempt from justification. A mechanism is
warranted only if it **(a) guards a real trust boundary, (b) reads an artifact rather than
an opinion, and (c) is wired to a decision it can change.** A check that can change no
outcome is telemetry and lives in the log, not in a gate. Machinery exists to move the
objective's artifacts — **never to manage other machinery**: a component whose only consumer
is another component's failure mode is the same component. **Activation-proof:** no
actuator is declared built until its **first measured live success** is recorded — a merged,
unproven mechanism is scaffolding, and a permanently-red probe is deleted or fixed, never
tolerated (a standing red trains the loop to ignore alarms, which is worse than no alarm).

## P4 — IMMUTABLE HOST / CONTAINERISE-EVERYTHING

The platform runs as an immutable host with **every application in a container** (and,
where a workload genuinely requires it, in a virtual machine — a recorded capability
decision per the objective). The invariant: **no mutable out-of-band host change; every
host change is reproducible from this repository and flows the merge-and-deploy path.**
Two deploy mechanisms are sanctioned, chosen per provisioning class: the **idempotent
converger** (cloud genesis — applied autonomously by the self-refresh actuators or
manually by the operator, every mutation declared in the repository, re-run-safe from any
historical version, ad-hoc drift vanishing on the next apply by design) and the **bootc
image build/rebase** (local genesis — a container-first, CoreOS-style layered image built
from this repository, rebased onto the machine with atomic rollback). Moving any
environment from converger to image-rebase is a design decision, not a conformance gap.
**The host artifact is environment-agnostic**: the genesis path is structured as a
**Fedora core plus a per-environment provisioning adapter** — the **cloud adapter**
converges a stock Fedora cloud image via the idempotent converger; the **local adapter**
builds a custom bootc image **and its installer media** from this repository, installs the
machine from the image, and keeps it current by **image rebase with atomic rollback**,
with the machine's permanent data preserved across reinstalls; onboarding a new
environment is an **adapter addition, never a fork**. A mechanical check fails any change
that mutates the live host outside the merge-and-deploy path.

## P5 — THE THROWAWAY PRINCIPLE & CHURN

Every build a throwaway, and the tree it built from a
throwaway with it. Teardown (EXIT-trap, including
signal paths) covers every throwaway tree, image, and run container; an orphan sweeper
reaps crash/kill leaks and is itself scheduled and proven. The durable inputs — a small,
**declared registry** of caches — hold **re-downloadable inputs only, never build output,
never an image layer** (the zero-byte re-download standard across iterations). The
invariant on every cache: **bounded by a hard ceiling under a scheduled, self-verifying
actuator**, so storage can never grow without limit; the eviction policy and numeric
ceilings are design facts owned per component, recorded in the design, not here.
Containerfiles are structured **heavy/stable-early, churn-late**; `--no-cache`/prune is
reserved for the periodic clean rebuild, never used during churn.

## P6 — ISOLATED WORKING TREE

Every authoring or build action runs in a **fresh, per-session-namespaced working tree that
never mutates the immutable live tree, a shared clone, or another session's tree**. All
mutable local state (worktree roots, locks, markers, scratch) is namespaced per session.
The checked-out branch is **re-verified to belong to the session's own namespace before
EVERY commit and EVERY push** — at the authoring sites and at the harness's own commit/push
sites alike, the harness being the most important case. The `cd` into an isolated tree is a
**fail-closed guard**, never a prefix: a failed enter runs no mutating step in the caller's
directory. A mutating action outside an isolated tree, or a commit/push without branch
re-verification, is UNSAFE.

## P7 — ATOMIC CONTRACTS / RUNTIME COMPATIBILITY

This repository holds **both sides of every contract** the platform uses — the ticket-bus
grammar, the verdict formats, the refresh manifests — so a contract change lands
**atomically, producer and consumer in one change**, and every machine-readable grammar is
**defined once, in `shared/`, and versioned** — one home per contract, per the
repository's `host/` · `dev-container/` · `shared/` layout. What remains is the **runtime
stagger**: components run mixed versions across a refresh window, so every consumer
**fail-safe refuses an unrecognized shape** rather than mis-parsing it, and every new
producer emission is **gated off until the consumer that understands it is confirmed
live**. A producer-first emission that can strand or wedge a not-yet-upgraded counterpart
is UNSAFE.

## P8 — TEST-QUALITY / MUTATION-PROVEN

Every behavioral change ships a test that **drives the real execution boundary** (the actual
engine, git, kernel, or process semantics under test — not a stub asserting what a mock was
told) and is **proven to fail against the pre-change code**; a test that passes against the
unfixed code is a defect. Guards are **mutation-checked in-suite**: the pre-fix behavior is
mechanically restored on a copy and the row must fail. **Production-only lines** — the paths
no test seam substitutes — must be covered by a real-body test or by the live acceptance
gate, and the suite must contain **no line whose production invocation has never been
executed** (the measured lesson: an untested production invocation fails silently at
scale). Where the behavior under test needs full
virtualization or a GPU, it runs on the **bare-metal capability track** — validation
never simulates on the VPS track what the bare-metal track can prove. **The suite gates**: tests run at the merge boundary bound to the exact head sha — a
test culture that cannot stop a merge is decoration, not proof. A permanently-failing test
or probe is fixed or removed, never tolerated (P3's no-standing-red).

## P9 — DOCUMENTATION-DRY

**One authoritative home per concept; every other mention is a one-line pointer or
deleted.** The document spine is the objective, these principles, the runtime law, and the
changelog — nothing else accretes. Shared content between components is **vendored from one
home** (`shared/`), never copied by hand; where bytes must be identical, a mechanical check
enforces identity — and the preferred fix for duplication is de-duplication, not another
checker. Evidence and benchmarks live only in the principle they prove. Incident narrative
belongs to the changelog: **memoir is not specification**. A document asserting behavior the
code does not have is UNTRUE and a blocking finding.

## P10 — RECOVERY-BEFORE-POWER

**No mechanism may block the loop without carrying a bounded, automatic recovery.** A gate
that is unavailable, stalled, or erroring must retry, fail over, or degrade under a recorded
policy — and surface to the maintainer only after its bounded attempts fail. **Detection may
only be added together with recovery**: a change introducing a blocking gate with no
self-heal path is UNSAFE, because a fail-closed gate with no recovery is a human summons,
and the objective's single-interaction law forbids those. Every autonomous mutation is
reversible — merge (revert), deploy (rollback), refresh (re-converge), closure (reopen) —
and each recovery path is proven by a test (P8), not by a standing drill framework that
itself needs managing.

## P11 — DISPOSABLE AGENT LAYER (REBUILD, NEVER UPDATE)

The agent tooling lives in a **disposable layer — an agent box** — that is **rebuilt,
never updated in place**: currency flows only through a rebuild from the official
channel, admitted per P1. The tool's **own self-update is disabled** by construction — a
self-installed binary would shadow the managed one, survive the rebuild on a persistent
volume, and strand the layer stale while appearing current. The rebuild cadence is
**fast** (daily, tracking the vendor's releases) and **never costs live work**: the
standing rule is **interrupt → rebuild → restart → resume** — every session **resumed to
active work and verified** — and where a refresh class cannot yet resume reliably,
**live sessions block it until all sessions have quit**; deferral is the fallback for
unproven resume, never the steady state, and an on-demand path is always available.
**Everything durable** — credentials, transcripts, configuration —
lives on persistent volumes **outside the disposable layer**, never in it, so a rebuild
loses nothing and a stale layer never accumulates. The component beneath stays stable
precisely because the layer above absorbs the churn.

**Lineage admission is a contract, not a name.** The layer carries **two built
lineages** — the claudebox (Claude Code) and the kimibox (Kimi Code) — and **admits anything
further** (DeepSeek, Codex, Gemini, GLM, and their successors) when — and only when — it
satisfies the contract: **official provenance at the strongest level the vendor admits**
(P1; a lineage whose only source is a forbidden channel is inadmissible until a
compliant one exists), **headless non-interactive autonomous operation**, **self-update
disabled by construction**, **state held outside the layer**, and the loop's
**policy/permissions interface**. Each admitted lineage is recorded as a **lineage
manifest**; a lineage that fails the contract is a recorded non-admission, never a
silent waiver. **One box instance runs one lineage**, chosen at provisioning; a box never
carries more than one lineage (P3).

**Resume is part of the refresh, not an afterthought.** A layer rebuild or a component
refresh **captures the live session set before it tears anything down and restores every
session afterwards** — all of them, every tenant — and the resume is **verified against
work, not presence**: each restored session **actively working again** — a session that
comes back and sits idle, waiting for a nudge, is **not resumed**; it is a stalled
session and the refresh is not done. A refresh that cannot resume
its sessions **does not fire**. Resume is possible by construction because the work's
durable state is the ticket bus: sessions re-derive from what is co-written to GitHub,
never from container or layer state.

---

## Mapping to the fleet's BP1–BP9 (provenance note)

P1=BP1 (strengthened: one fetch contract; repo-metadata signatures) · P2=BP2 (strengthened:
environment/release re-verification incl. virtualization + GPU availability; adoption
trail) · P3=BP3 (extended: gates-are-features, activation-proof, no-standing-red — the
zero-base minimalism doctrine) · P4=BP4 (amended: two sanctioned mechanisms per
provisioning class — cloud converger, local bootc image; environment-adapter genesis;
VM-as-recorded-capability) · P5=BP5 (amended and renamed to the objective's throwaway
principle: cache invariant; bounded input registry) · P6=BP6 (strengthened: harness sites
named) · P7=BP7 (rescoped: atomic contracts in one repo + runtime stagger; versioning made
standing) · P8=BP8 (extended: the suite gates; production-only-line rule; the bare-metal capability
track for full-virtualization/GPU validation) · P9=BP9 (extended: vendoring
preferred over parity checkers; memoir-is-not-specification) · P10=new (codified from the
measured gate-without-recovery incidents) · P11=new (the agent-layer discipline —
rebuild-not-update, auto-resume with deferral as fallback, state-outside-layer,
multi-lineage admission contract — codified from the fleet's daily-rebuild
implementation).
