# The Dev Pair — OBJECTIVE (spec of record)

> **THE WHY** — the highest objective of the host + dev-container pair, stated once, durable.
>
> **Status: DRAFT — pending maintainer confirmation.** Once confirmed, this document is fixed:
> amendment is a new maintainer confirmation, never a silent edit, and any change to it is
> MAINTAINER-MERGE-ONLY. The build principles (`00-BUILDPRINCIPLE.md`) share that authority.
> The design is dev-owned and mutable-on-fact; it serves this objective and is never a
> conformance target.
>
> **Identifiers.** Clauses here are **O-<area>-<n>** and are cited by requirements. The four
> schemes across the spine are **O** objective · **P** principle · **R** requirement · **D** design.
> Every R cites the O it serves; an O cited by no R and discharged by no P is a gap.
>
> **What belongs in this document:** the WHY and the WHAT — the intent, the outcomes the
> platform must produce, and the boundaries it must never cross. Never the HOW: how
> anything is built belongs to the build principles; how this system is arranged belongs
> to the design.

## The highest objective — twofold

### 1. The autonomous dev-pair loop workflow

The primary objective is to **create, maintain, and develop an autonomous
development-loop workflow apparatus as a pair**: a host and its **dev-container** —
together, one **dev pair**. For any development task or project, the
workflow is:

- **O-LOOP-1 · Initiation — exactly one interactive session at the very beginning.** The maintainer
  states the objective and the intended outcome, and sets the scope and the boundaries.
- **O-LOOP-2 · Confirmation — the dev pair confirms the objective in that chat session.** The pair
  **co-creates the confirmed objective with the maintainer from that discussion** —
  sharpening and expanding his statement, settling it together — and the maintainer
  confirms it, **with the build principles that will govern the work captured explicitly
  in that same session** (applied by reference, never re-dictated). That confirmation is
  the **one and only** human act the
  workflow requires.
- **O-LOOP-3 · Execution — then autonomous, to ship.** The confirmed objective is **locked as
  `00-OBJECTIVE.md` at the root of the repository being worked on** (the per-project spec
  of record, distinct from this platform objective), and from it the dev pair
  autonomously: **(a)** builds the functional requirements, **(b)** architects the
  design that serves them, **(c)** builds, validates, and iterates in a live environment —
  recovering automatically from failure, until the product ships. Humans approve goals,
  never deployments; there is no second interaction.
- **O-LOOP-4 · Immutability — the throwaway principle.** The workflow operates on **throwaway builds
  and the throwaway trees they build from**. This *is* the immutability principle of the
  host and the dev-container for the life of the work: every build is thrown away, every tree it
  built from is thrown away with it, and nothing durable accumulates except what the
  confirmed objective names — until the product is shipped.

### 2. The host as mother platform

**O-HOST-1** — In addition to its role in the dev pair, the host serves as a **mother platform**: it
hosts other containers as apps and services for whatever the maintainer needs — media
servers, cloud drives, and any other kind — each app its own container pulled from a
registry, and, where a workload genuinely requires it, a virtual machine as a recorded
capability decision. This function never outranks the pair: **a host is always deployed
as a dev pair foremost and first.**

### Everything else is secondary

**O-PRIME-1** — Any other clause in this document — access, security, mechanics, roles — describes **how**
the two primaries are realized. Secondary clauses must never contradict the primaries; on
conflict, the twofold objective wins and the secondary clause is defective.

## The platform

This repository builds and operates the apparatus: one autonomous development platform of
two components, specified, versioned, and evolved together in this single source of truth:

- **O-PLAT-1 · The host** — a Fedora system (the latest stable Fedora release) turned by this
  repository's genesis path into an immutable, container-as-app mother platform,
  **environment-agnostic by construction**: a cloud VPS from any provider (currently
  Fedora 44 on Hostinger Plan 4) or a locally hosted bare-metal machine. The only
  constants are Fedora and headlessness. Provisioning-environment facts — provider
  consoles, cloud images, hardware, virtualization capability, GPU availability, network
  shape — are inputs, never baked-in assumptions.
- **O-PLAT-2 · The dev-container** — a containerised development environment running on that host.
  It is **highly stable by design**: it changes deliberately — through this repository's
  merge-and-deploy path — never incidentally, and it carries the maintainer's work,
  credentials, and sessions across every refresh.
- **O-PLAT-3 · The agent layer — the claudebox and its lineages.** On both the host and the
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

**O-PLAT-4** — The two components are **one system**: one lifecycle, one specification, one repository,
organised as **`host/`** (the mother platform), **`dev-container/`** (the development container),
and **`shared/`** (what both sides use) — every file has exactly one home. The runtime
boundary between host and dev-container is real; no other boundary is manufactured.

**O-PLAT-5 · One repository, many pairs.** The platform is **replicable**: this repository is
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

- **O-TRACK-1 · Virtualization.** A VPS host is itself a virtualized environment, so full
  virtualization is commonly unavailable to it; a bare-metal host runs **libvirt/KVM
  virtual machines** directly. Certain aspects of testing **require full virtualization
  for the best validation** — so validation that needs full virtualization runs on the
  **bare-metal track**, and the VPS track never simulates what it cannot run.
- **O-TRACK-2 · GPU acceleration.** Certain apps and services hosted on the host require GPU
  acceleration. A bare-metal host's GPU is a **shared compute substrate** for them —
  shared to containers and virtual machines, never monopolised away from the host —
  while the VPS track is assumed to have none.

**O-TRACK-3** — The tracks differ in capability, never in contract: same specification, same loop, same
roles, same gates, same access model. A host's GPU or virtualization capability may be
**used** where it exists; no platform function may **require** it, because the VPS track
has none.

## Standing roles of the two components

- **O-ROLE-1 · The host** — genesis (cold-start, per the provisioning class: **cloud genesis** from a
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
- **O-ROLE-2 · The dev-container** — **develop + validate (tier-1)** features and images; the
  platform's **sole merge authority** under its empirical gates; home of the multi-tenant
  sessions. It is refreshed **from outside, by the host**, to the latest merged image.

## How the loop works (mechanics — secondary to the twofold objective)

The platform is built by **dogfooding**: every change to this repository lands through the
platform's own loop. The loop's mechanics:

- **O-MECH-1 · Immutable host, containerise-everything.** The host OS is immutable and every
  application — the dev-container, the agent tooling, all workloads — runs in a container.
- **O-MECH-2 · Three decoupled clocks.** The host OS, the dev-container image, and each **agent
  box** in the agent layer each advance on their own cadence — the agent layer's being
  the fast, daily one — each advancing **without costing live work** (auto-resume by
  default, deferral as fallback), each verified by reading the live artifact back. None
  forces a rebuild of the others.
- **O-MECH-3 · Multi-tenant development.** The dev-container runs an undefined number of isolated
  agent sessions, each on its own declared repository set, independently and exclusively.
  Isolation is **by scope, code-enforced**, not by identity. No session reads, touches, or
  iterates another session's work. The host is the **single shared validator** for all of
  them. GitHub issues and pull requests are the first-class ticket bus; the dev-container
  never touches the host directly — it instructs the host's agent.
- **O-MECH-4 · Two-tier validation.** A session proves whatever it can **inside the dev-container** and
  engages the host **only for the live validation the container cannot perform itself** —
  then iterates on the host's verdict until it is GREEN. Where the container cannot validate
  at all, that fallback is forced, not chosen. The two tiers are the model on **both**
  capability tracks; a validation that needs full virtualization or a GPU is routed to the
  bare-metal track — which is part of what that track exists for.
- **O-MECH-5 · Merged is not live — in both directions.** A merge is not a deployment. A merge to
  this repository **self-arms** the matching refresh with no human step, and the pair
  staggers it: each component refreshes the other **from outside** (neither
  rebuilds the agent doing the work), and every refresh is **confirmed by reading the live
  artifact back against merged source, fail-closed** — not done until verified live on the
  target.
- **O-MECH-6 · Distrust, made structural.** No outcome is accepted on testimony — not an agent's word,
  not a reviewer persuaded by prose, not a proxy mistaken for the artifact. Each gating
  outcome is **proven against the live artifact at check-time, by a non-author**. Liveness is
  monitored by freshness, never assumed; the **absence of a completion signal is a failure
  to surface**, never evidence of progress — and a gate that can only stall is a human
  summons, which this objective forbids.
- **O-MECH-7 · Minimal machinery.** The platform builds the smallest mechanism set that advances this
  objective. A feature — **including any gate, check, or watcher** — is built only if it
  advances the objective; where a mechanism helps one clause while hurting another, the
  trade-off is **evaluated and recorded**, never defaulted.
- **O-MECH-8 · The ship gate.** Nothing ships on its builder's own word. A product ships only after an
  **independent, adversarial review** verifies the built product against the confirmed
  spec — the objective first, then the requirements, then the build principles; reviewer
  and author are drawn from **different agent lineages** where the platform's lineages
  allow, so independence means a different checker, not just a different context. If the
  review does not pass, the product goes back into the loop, not out the door.

## Access and security objectives (secondary — must not contradict the twofold objective)

1. **O-SEC-1 · Secure public access with minimal surface.** Every service is locked behind
   private networks **by default**. The only doors exposed to the public internet are
   **secure-shell access (SSH/MOSH-type), hardened** — on **both** the host and the
   dev-container, of every pair. Everything else — desktops, consoles, dashboards, admin
   interfaces — is reachable only from private networks: the tailnet everywhere, and the
   local LAN on a locally hosted pair, bounded at the network layer.
2. **O-SEC-2 · Key-based authentication, without exception on any shell path.** Every public door
   authenticates **by SSH keys only**, on **both** components of every pair; and no
   password ever authenticates remote **shell** access anywhere in the platform, public or
   private. The maintainer's published key set is the **single trust root**: access is
   granted and revoked by managing keys, never by distributing or rotating credentials.
   Consoles and dashboards — reachable only on private networks per clause 1 — may use
   their own hardened, per-service authentication, never a shared or default credential.
3. **O-SEC-3 · Session persistence, as an outcome.** Interactive sessions must **survive frequent
   disconnections** — network roams, device sleeps, client restarts — and **persist
   long-term**: a session left running for weeks is resumed exactly where it was, from any
   authorized device, with no loss of running state, transcript, or work context. This
   objective names the **outcome only**; the mechanism is chosen by the design against
   current best practice and may change without amending this document.

## Boundaries

- **O-BND-1** — The host never merges; the dev-container merges — **except the confirmed spec**, which
  only the maintainer merges.
- **O-BND-2** — Neither component builds production images; CI builds them. The host builds only
  throwaway validation candidates.
- **O-BND-3** — No unmerged change is ever applied to either component. Proposing is never applying.
- **O-BND-4** — The platform operates on **the repositories its GitHub App is installed on** — the
  maintainer's live install choice, private repositories included — and **never widens its
  own reach**.
- **O-BND-5** — No secrets in the repository or in image layers; credentials enter at runtime only.
- **O-BND-6** — **Headless is binding.** Nothing in the platform may assume a physical display or a
  local seat — on any host, cloud or bare-metal, after genesis. A host's GPU or
  virtualization capability, where it exists, may be used; no platform function may
  require it. A change that needs a display or a seat is a defect.

## Document authority

**O-DOC-1** — This objective and the build principles are **confirmed once and fixed**; amendment is a new
maintainer confirmation, maintainer-merge-only. The design is dev-owned and
mutable-on-fact. The document spine of this repository is exactly: **the objective, the
build principles, the runtime law, and the changelog** — one authoritative home per
concept; every other mention points or is deleted. Memoir is not specification.

**O-DOC-2 · Why objective and principles are two documents.** The objective is **scoped** — this
platform objective here, and each project's locked `00-OBJECTIVE.md` in its own
repository — while the build principles are **universal**, binding everything the platform
builds. They are confirmed **together, once, in a single session**; thereafter a project's
one initiation session **co-creates that project's objective AND explicitly captures the
build principles that govern the work** — the platform's principles applied by reference,
plus any project-specific construction constraint decided in that session — so nothing
about how the work will be built is left implicit or assumed. The principles are
**captured, never re-dictated** — a re-dictation is a fork. One session, two documents,
nothing assumed.
