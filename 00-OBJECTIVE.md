# The Dev Pair — OBJECTIVE (spec of record)

> **THE WHY and THE HOW WE BUILD.** The objective and the build principles that govern the
> work, in one document — they are confirmed together, once, in a single session, and share
> one authority. **Status: DRAFT — pending maintainer confirmation.** Once confirmed this is
> fixed: amendment is a new maintainer confirmation, never a silent edit.
>
> **Identifiers.** **OB-<n>** objective clauses · **UNI-P<n>** universal build principles
> (bind every project the pair develops) · **REPO-P<n>** repo-specific build principles
> (bind this repository's own platform).

# Part O — Objective

## The highest objective — twofold

### 1. The autonomous dev-pair loop workflow

The primary objective is to **create, maintain, and develop an autonomous
development-loop workflow apparatus as a pair**: a host and its **dev-container** —
together, one **dev pair**. For any development task or project, the
workflow is:

- **OB-1 · Initiation — exactly one interactive session at the very beginning.** The maintainer
  states the objective and the intended outcome, and sets the scope and the boundaries.
- **OB-2 · Confirmation — the dev pair confirms the objective in that chat session.** The pair
  **co-creates the confirmed objective with the maintainer from that discussion** —
  sharpening and expanding his statement, settling it together — and the maintainer
  confirms it, **with the build principles that will govern the work captured explicitly
  in that same session** (applied by reference, never re-dictated). That confirmation is
  the **one and only** human act the
  workflow requires.
- **OB-3 · Execution — then autonomous, to ship.** The confirmed objective is **locked as
  `00-OBJECTIVE.md` at the root of the repository being worked on** (the per-project spec
  of record, distinct from this platform objective), and from it the dev pair
  autonomously: **(a)** builds the functional requirements, **(b)** architects the
  design that serves them, **(c)** builds, validates, and iterates in a live environment —
  recovering automatically from failure, until the product ships. Humans approve goals,
  never deployments; there is no second interaction.
- **OB-4 · Immutability — the throwaway principle.** The workflow operates on **throwaway builds
  and the throwaway trees they build from**. This *is* the immutability principle of the
  host and the dev-container for the life of the work: every build is thrown away, every tree it
  built from is thrown away with it, and nothing durable accumulates except what the
  confirmed objective names — until the product is shipped.

### 2. The host as mother platform

**OB-5** — In addition to its role in the dev pair, the host serves as a **mother platform**: it
hosts other containers as apps and services for whatever the maintainer needs — media
servers, cloud drives, and any other kind — each app its own container pulled from a
registry, and, where a workload genuinely requires it, a virtual machine as a recorded
capability decision. This function never outranks the pair: **a host is always deployed
as a dev pair foremost and first.**

### Everything else is secondary

**OB-6** — Any other clause in this document — access, security, mechanics, roles — describes **how**
the two primaries are realized. Secondary clauses must never contradict the primaries; on
conflict, the twofold objective wins and the secondary clause is defective.

## The platform

This repository builds and operates the apparatus: one autonomous development platform of
two components, specified, versioned, and evolved together in this single source of truth:

- **OB-7 · The host** — a Fedora system (the latest stable Fedora release) turned by this
  repository's genesis path into an immutable, container-as-app mother platform,
  **environment-agnostic by construction**: a cloud VPS from any provider (currently
  Fedora 44 on Hostinger Plan 4) or a locally hosted bare-metal machine. The only
  constants are Fedora and headlessness. Provisioning-environment facts — provider
  consoles, cloud images, hardware, virtualization capability, GPU availability, network
  shape — are inputs, never baked-in assumptions.
- **OB-8 · The dev-container** — a containerised development environment running on that host.
  It is **highly stable by design**: it changes deliberately — through this repository's
  merge-and-deploy path — never incidentally, and it carries the maintainer's work,
  credentials, and sessions across every refresh.
- **OB-9 · The agent layer — the claudebox and its lineages.** On both the host and the
  dev-container, the agent runs inside a **disposable Distrobox layer**; the component
  and its box together form that component's **agent box**. **Two lineages are built
  now** — the **claudebox** (Claude Code) and the **kimibox** (Kimi Code) — with the
  **provision that the layer can carry anything**: further lineages (DeepSeek, Codex,
  Gemini, GLM, and their successors) are admitted as each meets the platform's lineage
  contract (official provenance, headless autonomous operation, rebuild-not-update,
  state outside the layer). **One box instance runs one
  lineage, chosen at provisioning** (default: claudebox) — the lineage is a provisioning
  parameter of the component, never a fork of the platform. This layering is what lets the host and the
  dev-container stay **relatively stable** while the agent stays **always current**: each
  box tracks its vendor's releases on a **daily refresh cycle**, and a refresh **never
  costs live work**: the standing rule is **interrupt → rebuild → restart → resume** —
  every session **resumed to active work: kick-started and working, never merely present,
  never waiting for a nudge — and verified** — and where a refresh class cannot yet resume
  reliably, **live sessions block it until they quit**; deferral is the fallback for
  unproven resume, never the steady state. Everything durable — credentials, transcripts,
  configuration — lives outside the disposable layer, so a rebuild loses nothing. And when
  either **component** refreshes to match the merged repository, its agent boxes **resume
  every session to active work** — all of them, every tenant — because the sessions' work
  is co-written to GitHub and never lives only in the layer.

**OB-10** — The two components are **one system**: one lifecycle, one specification, one repository,
organised as **`host/`** (the mother platform), **`dev-container/`** (the development container),
and **`shared/`** (what both sides use) — every file has exactly one home. The runtime
boundary between host and dev-container is real; no other boundary is manufactured.

**OB-11 · One repository, many pairs.** The platform is **replicable**: this repository is
instance-agnostic, and each deployment of it is one **pair** — one host plus its dev-container.
Provisioning has two classes: **cloud genesis** (remote, channel-proof, no local act) and
**local genesis** (a custom **bootc** image — container-first, CoreOS-style, layered —
built from this repository and deployed to the machine; after first boot, convergence is
identical; its working lineage is the maintainer's **`strix` bootc build**
(`strix-ms-s1-bootc`), succeeding the earlier declarative Fedora CoreOS era). After
genesis, every pair is managed the same way, by the same loop, against this same
specification; instance-specific facts are inputs to a pair, never branches of it.
**A host is always deployed as a dev pair foremost and first**: whatever else a host will
eventually do, it comes up first as a pair — host plus dev-container — and only then takes on
application workloads. The first host, named **box**, is the **genesis agent**: its first
function is as a member of the dev pair; its second is to spin up any future containers
as apps and services. **Authority is per-pair**: each pair's dev-container is the sole merger of
its own work, and each pair's host is the single shared validator of its own sessions.
Pairs are peers — they share this specification, the build principles, and the
App-installation scope rule, and nothing else by default; **each pair works under its own
dedicated GitHub App identities, never shared across pairs.**

## The two capability tracks — VPS and bare-metal pairs

The **primary difference** between a VPS-hosted pair and a bare-metal pair is
**virtualization and GPU access**. It defines **two tracks of capability** the platform
validates and serves on — the **VPS track** (host + dev-container on a cloud VPS) and the
**bare-metal track** (host + dev-container on local bare metal):

- **OB-12 · Virtualization.** A VPS host is itself a virtualized environment, so full
  virtualization is commonly unavailable to it; a bare-metal host runs **libvirt/KVM
  virtual machines** directly. Certain aspects of testing **require full virtualization
  for the best validation** — so validation that needs full virtualization runs on the
  **bare-metal track**, and the VPS track never simulates what it cannot run.
- **OB-13 · GPU acceleration.** Certain apps and services hosted on the host require GPU
  acceleration. A bare-metal host's GPU is a **shared compute substrate** for them —
  shared to containers and virtual machines, never monopolised away from the host —
  while the VPS track is assumed to have none.

**OB-14** — The tracks differ in capability, never in contract: same specification, same loop, same
roles, same gates, same access model. A host's GPU or virtualization capability may be
**used** where it exists; no platform function may **require** it, because the VPS track
has none.

## Standing roles of the two components

- **OB-15 · The host** — genesis (cold-start, per the provisioning class: **cloud genesis** from a
  stock Fedora cloud image on any provider, or **local genesis** on a bare-metal machine
  by deploying a custom bootc image (container-first, CoreOS-style) built from this
  repository; re-run-safe, idempotent, fail-loud); **operate +
  maintain** the platform (deploy, refresh, roll back, create and remove containers; keep
  the host sound); **host applications** — spin up and run containers as apps and services
  for whatever the maintainer needs, per the twofold objective; **live-diagnose + develop
  fixes → open PRs only**. It never merges, never builds production images (CI does), and
  never applies an unmerged change. When this repository merges, the host **refreshes
  itself** — bounded, idempotent, health-gated, rolled back on failure, proven live by
  read-back — with no standing human tap.
- **OB-16 · The dev-container** — **develop + validate (tier-1)** features and images; the
  platform's **sole merge authority** under its empirical gates; home of the multi-tenant
  sessions. It is refreshed **from outside, by the host**, to the latest merged image.

## How the loop works (mechanics — secondary to the twofold objective)

The platform is built by **dogfooding**: every change to this repository lands through the
platform's own loop. The loop's mechanics:

- **OB-17 · Immutable host, containerise-everything.** The host OS is immutable and every
  application — the dev-container, the agent tooling, all workloads — runs in a container.
- **OB-18 · Three decoupled clocks.** The host OS, the dev-container image, and each **agent
  box** in the agent layer each advance on their own cadence — the agent layer's being
  the fast, daily one — each advancing **without costing live work** (auto-resume by
  default, deferral as fallback), each verified by reading the live artifact back. None
  forces a rebuild of the others.
- **OB-19 · Multi-tenant development.** The dev-container runs an undefined number of isolated
  agent sessions, each on its own declared repository set, independently and exclusively.
  Isolation is **by scope, code-enforced**, not by identity. No session reads, touches, or
  iterates another session's work. The host is the **single shared validator** for all of
  them. GitHub issues and pull requests are the first-class ticket bus; the dev-container
  never touches the host directly — it instructs the host's agent.
- **OB-20 · Two-tier validation.** A session proves whatever it can **inside the dev-container** and
  engages the host **only for the live validation the container cannot perform itself** —
  then iterates on the host's verdict until it is GREEN. Where the container cannot validate
  at all, that fallback is forced, not chosen. The two tiers are the model on **both**
  capability tracks; a validation that needs full virtualization or a GPU is routed to the
  bare-metal track — which is part of what that track exists for.
- **OB-21 · Merged is not live — in both directions.** A merge is not a deployment. A merge to
  this repository **self-arms** the matching refresh with no human step, and the pair
  staggers it: each component refreshes the other **from outside** (neither
  rebuilds the agent doing the work), and every refresh is **confirmed by reading the live
  artifact back against merged source, fail-closed** — not done until verified live on the
  target.
- **OB-22 · Distrust, made structural.** No outcome is accepted on testimony — not an agent's word,
  not a reviewer persuaded by prose, not a proxy mistaken for the artifact. Each gating
  outcome is **proven against the live artifact at check-time, by a non-author**. Liveness is
  monitored by freshness, never assumed; the **absence of a completion signal is a failure
  to surface**, never evidence of progress — and a gate that can only stall is a human
  summons, which this objective forbids.
- **OB-23 · Minimal machinery.** The platform builds the smallest mechanism set that advances this
  objective. A feature — **including any gate, check, or watcher** — is built only if it
  advances the objective; where a mechanism helps one clause while hurting another, the
  trade-off is **evaluated and recorded**, never defaulted.
- **OB-24 · The ship gate.** Nothing ships on its builder's own word. A product ships only after an
  **independent, adversarial review** verifies the built product against the confirmed
  spec — the objective first, then the requirements, then the build principles; reviewer
  and author are drawn from **different agent lineages** where the platform's lineages
  allow, so independence means a different checker, not just a different context. If the
  review does not pass, the product goes back into the loop, not out the door.

## Access and security objectives (secondary — must not contradict the twofold objective)

1. **OB-25 · Secure public access with minimal surface.** Every service is locked behind
   private networks **by default**. The only doors exposed to the public internet are
   **secure-shell access (SSH/MOSH-type), hardened** — on **both** the host and the
   dev-container, of every pair. Everything else — desktops, consoles, dashboards, admin
   interfaces — is reachable only from private networks: the tailnet everywhere, and the
   local LAN on a locally hosted pair, bounded at the network layer.
2. **OB-26 · Key-based authentication, without exception on any shell path.** Every public door
   authenticates **by SSH keys only**, on **both** components of every pair; and no
   password ever authenticates remote **shell** access anywhere in the platform, public or
   private. The maintainer's published key set is the **single trust root**: access is
   granted and revoked by managing keys, never by distributing or rotating credentials.
   Consoles and dashboards — reachable only on private networks per clause 1 — may use
   their own hardened, per-service authentication, never a shared or default credential.
3. **OB-27 · Session persistence, as an outcome.** Interactive sessions must **survive frequent
   disconnections** — network roams, device sleeps, client restarts — and **persist
   long-term**: a session left running for weeks is resumed exactly where it was, from any
   authorized device, with no loss of running state, transcript, or work context. This
   objective names the **outcome only**; the mechanism is chosen by the design against
   current best practice and may change without amending this document.

## Boundaries

- **OB-28** — The host never merges; the dev-container merges — **except the confirmed spec**, which
  only the maintainer merges.
- **OB-29** — Neither component builds production images; CI builds them. The host builds only
  throwaway validation candidates.
- **OB-30** — No unmerged change is ever applied to either component. Proposing is never applying.
- **OB-31** — The platform operates on **the repositories its GitHub App is installed on** — the
  maintainer's live install choice, private repositories included — and **never widens its
  own reach**.
- **OB-32** — No secrets in the repository or in image layers; credentials enter at runtime only.
- **OB-33** — **Headless is binding.** Nothing in the platform may assume a physical display or a
  local seat — on any host, cloud or bare-metal, after genesis. A host's GPU or
  virtualization capability, where it exists, may be used; no platform function may
  require it. A change that needs a display or a seat is a defect.

## Document authority

**OB-34** — This objective and the build principles are **confirmed once and fixed**; amendment is a new
maintainer confirmation, maintainer-merge-only. The design is dev-owned and
mutable-on-fact. The document spine of this repository is exactly: **this document (the
objective and the build principles), the design, and the changelog** — one authoritative home per
concept; every other mention points or is deleted. Memoir is not specification.

**OB-35 · Why the objective is scoped and the principles are universal.** The objective is **scoped** — this
platform objective here, and each project's locked `00-OBJECTIVE.md` in its own
repository — while the build principles are **universal**, binding everything the platform
builds. They are confirmed **together, once, in a single session**; thereafter a project's
one initiation session **co-creates that project's objective AND explicitly captures the
build principles that govern the work** — the platform's principles applied by reference,
plus any project-specific construction constraint decided in that session — so nothing
about how the work will be built is left implicit or assumed. The principles are
**captured, never re-dictated** — a re-dictation is a fork. One session, two parts,
nothing assumed.

# Part P — Build principles

> **THE HOW WE BUILD** — how every artifact is constructed, whatever it does.
>
> **Status: DRAFT — pending maintainer confirmation.** Confirmed with the objective
> (Part O) and sharing its authority: fixed thereafter, amendment is a new
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

## UNI-P — Universal principles (bind every project the pair develops)

### UNI-P1 — PROVENANCE

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

### UNI-P2 — VERIFY-BEFORE-ADOPT

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

### UNI-P3 — CAPABILITY-RELATIVE MINIMALISM

Every package and artifact is installed at the **minimal leaf footprint for its decided
capability**: nothing enters any built tree without a **recorded justification**;
`install_weak_deps=False` applies to **every** package installation on the platform,
including bootstrap paths that would otherwise inherit an upstream default; the most
specific leaf package is chosen over any convenience metapackage; the irreducible
hard-dependency closure of a chosen capability is accepted and disclosed, not fought.
Minimality is **capability-relative** — between equal-capability options prefer the smaller,
higher-provenance one; **dropping a capability to shrink the footprint is a recorded
capability trade-off, never a minimalism win.**

Minimalism binds machinery as well as packages — see **UNI-P8**.

### UNI-P4 — ISOLATED WORKING TREE

Every authoring or build action runs in a **fresh, per-session-namespaced working tree that
never mutates the immutable live tree, a shared clone, or another session's tree**. All
mutable local state (worktree roots, locks, markers, scratch) is namespaced per session.
The checked-out branch is **re-verified to belong to the session's own namespace before
EVERY commit and EVERY push** — at the authoring sites and at the harness's own commit/push
sites alike, the harness being the most important case. The `cd` into an isolated tree is a
**fail-closed guard**, never a prefix: a failed enter runs no mutating step in the caller's
directory. A mutating action outside an isolated tree, or a commit/push without branch
re-verification, is UNSAFE.

### UNI-P5 — TEST-QUALITY / MUTATION-PROVEN

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
or probe is fixed or removed, never tolerated (UNI-P3's no-standing-red).

### UNI-P6 — DOCUMENTATION-DRY

**One authoritative home per concept; every other mention is a one-line pointer or
deleted.** The document spine is this document, the design, and the
changelog — nothing else accretes. Shared content between components is **vendored from one
home** (`shared/`), never copied by hand; where bytes must be identical, a mechanical check
enforces identity — and the preferred fix for duplication is de-duplication, not another
checker. Evidence and benchmarks live only in the principle they prove. Incident narrative
belongs to the changelog: **memoir is not specification**. A document asserting behavior the
code does not have is UNTRUE and a blocking finding.

### UNI-P7 — RECOVERY-BEFORE-POWER

**No mechanism may block the loop without carrying a bounded, automatic recovery.** A gate
that is unavailable, stalled, or erroring must retry, fail over, or degrade under a recorded
policy — and surface to the maintainer only after its bounded attempts fail. **Detection may
only be added together with recovery**: a change introducing a blocking gate with no
self-heal path is UNSAFE, because a fail-closed gate with no recovery is a human summons,
and the objective's single-interaction law forbids those. Every autonomous mutation is
reversible — merge (revert), deploy (rollback), refresh (re-converge), closure (reopen) —
and each recovery path is proven by a test (UNI-P5), not by a standing drill framework that
itself needs managing.

### UNI-P8 — GATES ARE FEATURES

Every gate, check, watcher and probe the platform builds **is itself a feature, and is justified like one**: the same discipline binds every gate, check, watcher, and probe the
platform builds — security machinery is not exempt from justification. A mechanism is
warranted only if it **(a) guards a real trust boundary, (b) reads an artifact rather than
an opinion, and (c) is wired to a decision it can change.** A check that can change no
outcome is telemetry and lives in the log, not in a gate. Machinery exists to move the
objective's artifacts — **never to manage other machinery**: a component whose only consumer
is another component's failure mode is the same component. **Activation-proof:** no
actuator is declared built until its **first measured live success** is recorded — a merged,
unproven mechanism is scaffolding, and a permanently-red probe is deleted or fixed, never
tolerated (a standing red trains the loop to ignore alarms, which is worse than no alarm).

## REPO-P — Repo-specific principles (bind this repository's own platform)

### REPO-P1 — IMMUTABLE HOST / CONTAINERISE-EVERYTHING

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

### REPO-P2 — THE THROWAWAY PRINCIPLE & CHURN

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

### REPO-P3 — ATOMIC CONTRACTS / RUNTIME COMPATIBILITY

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

### REPO-P4 — DISPOSABLE AGENT LAYER (REBUILD, NEVER UPDATE)

The agent tooling lives in a **disposable layer — an agent box** — that is **rebuilt,
never updated in place**: currency flows only through a rebuild from the official
channel, admitted per UNI-P1. The tool's **own self-update is disabled** by construction — a
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
(UNI-P1; a lineage whose only source is a forbidden channel is inadmissible until a
compliant one exists), **headless non-interactive autonomous operation**, **self-update
disabled by construction**, **state held outside the layer**, and the loop's
**policy/permissions interface**. Each admitted lineage is recorded as a **lineage
manifest**; a lineage that fails the contract is a recorded non-admission, never a
silent waiver. **One box instance runs one lineage**, chosen at provisioning; a box never
carries more than one lineage (UNI-P3).

**Resume is part of the refresh, not an afterthought.** A layer rebuild or a component
refresh **captures the live session set before it tears anything down and restores every
session afterwards** — all of them, every tenant — and the resume is **verified against
work, not presence**: each restored session **actively working again** — a session that
comes back and sits idle, waiting for a nudge, is **not resumed**; it is a stalled
session and the refresh is not done. A refresh that cannot resume
its sessions **does not fire**. Resume is possible by construction because the work's
durable state is the ticket bus: sessions re-derive from what is co-written to GitHub,
never from container or layer state.

## Mapping to the fleet's BP1–BP9 (provenance note)

UNI-P1=BP1 (strengthened: one fetch contract; repo-metadata signatures) · UNI-P2=BP2 (strengthened:
environment/release re-verification incl. virtualization + GPU availability; adoption
trail) · UNI-P3=BP3 (extended: gates-are-features, activation-proof, no-standing-red — the
zero-base minimalism doctrine) · REPO-P1=BP4 (amended: two sanctioned mechanisms per
provisioning class — cloud converger, local bootc image; environment-adapter genesis;
VM-as-recorded-capability) · REPO-P2=BP5 (amended and renamed to the objective's throwaway
principle: cache invariant; bounded input registry) · UNI-P4=BP6 (strengthened: harness sites
named) · REPO-P3=BP7 (rescoped: atomic contracts in one repo + runtime stagger; versioning made
standing) · UNI-P5=BP8 (extended: the suite gates; production-only-line rule; the bare-metal capability
track for full-virtualization/GPU validation) · UNI-P6=BP9 (extended: vendoring
preferred over parity checkers; memoir-is-not-specification) · UNI-P7=new (codified from the
measured gate-without-recovery incidents) · REPO-P4=new (the agent-layer discipline —
rebuild-not-update, auto-resume with deferral as fallback, state-outside-layer,
multi-lineage admission contract — codified from the fleet's daily-rebuild
implementation).
