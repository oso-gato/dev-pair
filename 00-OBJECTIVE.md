# The Dev Pair — OBJECTIVE

> **THE WHY** — the intent, the outcomes this platform must produce, and the boundaries it
> must never cross. Stated once, durable.
>
> **Status: DRAFT — pending maintainer confirmation.** Once confirmed this document is
> fixed: amendment is a new maintainer confirmation, never a silent edit, and every change
> is maintainer-merge-only (enforced by `.github/CODEOWNERS`).
>
> **Governed by** `00-BUILDPRINCIPLE.md` **v1**, vendored — universal construction law,
> applied by reference, never re-dictated here.
>
> **What belongs in this document:** the WHY, the WHAT, and the boundaries — including
> this repository's own construction constraints. **Never the HOW.** How anything the pair
> builds must be *made* belongs to the build principles. How *this system* is arranged
> belongs to `02-DESIGN.md`, and why it is arranged that way to `docs/adr/`.
>
> **Identifiers.** `OB-<n>`, flat and contiguous. Every `01-SPEC.md` clause cites the
> `OB-n` it serves; an `OB-n` with no requirement is a gap.

---

## 1 · The highest objective — twofold

### 1.1 The autonomous dev-pair loop workflow

The primary objective is to **create, maintain, and develop an autonomous
development-loop workflow apparatus as a pair**: a host and its **dev-container** —
together, one **dev pair**. For any development task or project, the workflow is:

- **OB-1 · Initiation — exactly one interactive session at the very beginning.** The
  maintainer states the objective and the intended outcome, and sets the scope and the
  boundaries.

- **OB-2 · Confirmation — the dev pair confirms the objective in that chat session.** The
  pair **co-creates the confirmed objective with the maintainer from that discussion** —
  sharpening and expanding his statement, settling it together — and the maintainer
  confirms it, **with the build principles that will govern the work captured explicitly
  in that same session** (applied by reference, never re-dictated). That confirmation is
  the **one and only** human act the workflow requires.

- **OB-3 · Execution — then autonomous, to ship.** The confirmed objective is **locked as
  `00-OBJECTIVE.md` at the root of the repository being worked on**, and from it the dev
  pair autonomously: **(a)** derives the specification, **(b)** architects the design that
  serves it, **(c)** builds, validates, and iterates in a live environment — recovering
  automatically from failure, until the product ships. Humans approve goals, never
  deployments; there is no second interaction.

- **OB-4 · Immutability — the throwaway principle.** The workflow operates on **throwaway
  builds and the throwaway trees they build from**: every build is thrown away, every tree
  it built from is thrown away with it, and nothing durable accumulates except what the
  confirmed objective names — until the product is shipped.

### 1.2 The host as mother platform

**OB-5** — In addition to its role in the dev pair, the host serves as a **mother
platform**: it hosts other containers as apps and services for whatever the maintainer
needs — media servers, cloud drives, and any other kind — each app its own container
pulled from a registry, and, where a workload genuinely requires it, a virtual machine as
a recorded capability decision. This function never outranks the pair: **a host is always
deployed as a dev pair foremost and first.**

### 1.3 Supremacy

**OB-6** — Any other clause in this document describes **how** the two primaries are
realized. Secondary clauses must never contradict the primaries; on conflict, the twofold
objective wins and the secondary clause is defective.

---

## 2 · What the platform is

**OB-7 · The host** — a Fedora system (the latest stable Fedora release) turned by this
repository's genesis path into an immutable, container-as-app mother platform,
**environment-agnostic by construction**: a cloud VPS from any provider, or a locally
hosted bare-metal machine. The only constants are Fedora and headlessness.
Provisioning-environment facts — provider consoles, cloud images, hardware, virtualization
capability, GPU availability, network shape — are inputs, never baked-in assumptions.

**OB-8 · The dev-container** — a containerised development environment running on that
host. It is **highly stable by design**: it changes deliberately, through this
repository's merge-and-deploy path, never incidentally, and it carries the maintainer's
work, credentials, and sessions across every refresh.

**OB-9 · The agent layer** — on both components the agent runs inside a **disposable
layer**; the component and its layer together form that component's **agent box**. The
layer is what lets the components stay **relatively stable** while the agent stays
**always current**. Everything durable — credentials, transcripts, configuration — lives
outside it, so a rebuild loses nothing. Two lineages are built now, the **claudebox**
(Claude Code) and the **kimibox** (Kimi Code), with the provision that the layer can carry
anything admitted under the lineage contract of OB-18. Lineage is a provisioning parameter
of a component, **never a fork of the platform**.

**OB-10 · One system, one repository.** The two components are one lifecycle, one
specification, one repository, organised as **`host/`** (the mother platform),
**`dev-container/`** (the development container), and **`shared/`** (what both sides use)
— every file has exactly one home. The runtime boundary between host and dev-container is
real; **no other boundary is manufactured.**

**OB-11 · One repository, many pairs.** The platform is **replicable**: this repository is
instance-agnostic, and each deployment of it is one **pair**. After genesis, every pair is
managed the same way, by the same loop, against this same specification; instance-specific
facts are inputs to a pair, never branches of it. **Authority is per-pair**: each pair's
dev-container is the sole merger of its own work, and each pair's host is the single
shared validator of its own sessions. Pairs are peers — they share this specification, the
build principles, and the App-installation scope rule, and nothing else by default; **each
pair works under its own dedicated GitHub App identities, never shared across pairs.**

**OB-12 · Two capability tracks.** A VPS-hosted pair and a bare-metal pair differ in
**virtualization and GPU access**, and that difference defines two tracks the platform
validates and serves on. Validation that requires full virtualization or a GPU runs on the
**bare-metal track**; the VPS track never simulates what it cannot run. The tracks differ
in capability, never in contract: same specification, same loop, same roles, same gates,
same access model. A capability may be **used** where it exists; **no platform function
may require it.**

---

## 3 · Standing roles

**OB-13 · The host** — genesis (cold-start, re-run-safe, idempotent, fail-loud);
**operate + maintain** the platform (deploy, refresh, roll back, create and remove
containers; keep the host sound); **host applications** per OB-5; **live-diagnose +
develop fixes → open PRs only.** It never merges, never builds production images, and
never applies an unmerged change. When this repository merges, the host **refreshes
itself**, with no standing human tap.

**OB-14 · The dev-container** — **develop + validate** features and images; the platform's
**sole merge authority** under its empirical gates; home of the multi-tenant sessions. It
is refreshed **from outside, by the host**, to the latest merged image.

---

## 4 · Constraints on this platform

Construction constraints specific to this repository. Universal construction law is not
restated here — it is `00-BUILDPRINCIPLE.md`, applied by reference.

**OB-15 · Immutable host, containerise everything.** The host OS is immutable and every
application — the dev-container, the agent tooling, all workloads — runs in a container,
or, where a workload genuinely requires it, in a virtual machine as a recorded capability
decision. The invariant: **no mutable out-of-band host change; every host change is
reproducible from this repository and flows the merge-and-deploy path.** The host artifact
is environment-agnostic — onboarding a new environment is an **adapter addition, never a
fork.**

**OB-16 · Throwaway builds and throwaway trees.** Every build is a throwaway and the tree
it built from is a throwaway with it. Durable inputs are a small **declared registry** of
caches holding **re-downloadable inputs only** — never build output, never an image layer
— each bounded by a hard ceiling under a scheduled, self-verifying actuator, so storage
can never grow without limit.

**OB-17 · Atomic contracts.** This repository holds **both sides of every contract** the
platform uses, so a contract change lands **atomically, producer and consumer in one
change**. Every machine-readable grammar is **defined once, in `shared/`, and versioned**.
Because components run mixed versions across a refresh window, every consumer **fail-safe
refuses an unrecognized shape**, and every new producer emission is **gated off until the
consumer that understands it is confirmed live.**

**OB-18 · Disposable agent layer — rebuild, never update.** The agent layer is **rebuilt,
never updated in place**; currency flows only through a rebuild from the official channel.
The tool's own self-update is **disabled by construction**. The cadence is **fast**, and a
rebuild **never costs live work**: the standing rule is **interrupt → rebuild → restart →
resume** — every session **resumed to active work and verified**, never merely present. A
refresh that cannot resume its sessions **does not fire**; deferral is the fallback for an
unproven resume class, never the steady state. A lineage is admitted only on the
**contract**: official provenance at the strongest level the vendor admits, headless
autonomous operation, self-update disabled by construction, state held outside the layer,
and the loop's policy/permissions interface. Each admission or non-admission is recorded;
a silent waiver is a defect. **One box instance runs one lineage.**

---

## 5 · Access and security

**OB-19 · Secure public access with minimal surface.** Every service is locked behind
private networks **by default**. The only doors exposed to the public internet are
**secure-shell access (SSH/MOSH-type), hardened** — on both components of every pair.
Everything else — desktops, consoles, dashboards, admin interfaces — is reachable only
from private networks, bounded at the network layer.

**OB-20 · Key-based authentication, without exception on any shell path.** Every public
door authenticates **by SSH keys only**, on both components of every pair; no password
ever authenticates remote **shell** access anywhere in the platform, public or private.
The maintainer's published key set is the **single trust root**: access is granted and
revoked by managing keys, never by distributing or rotating credentials. Private-network
consoles may use their own hardened, per-service authentication, never a shared or default
credential.

**OB-21 · Session persistence, as an outcome.** Interactive sessions must **survive
frequent disconnections** — network roams, device sleeps, client restarts — and **persist
long-term**: a session left running for weeks is resumed exactly where it was, from any
authorized device, with no loss of running state, transcript, or work context. This clause
names the **outcome only**; the mechanism is the design's choice and may change without
amending this document.

---

## 6 · Boundaries

- **OB-22** — The host never merges; the dev-container merges — **except this document and
  the build principles**, which only the maintainer merges.
- **OB-23** — Neither component builds production images; CI builds them. The host builds
  only throwaway validation candidates.
- **OB-24** — No unmerged change is ever applied to either component. **Proposing is never
  applying.**
- **OB-25** — The platform operates on **the repositories its GitHub App is installed on**
  — the maintainer's live install choice, private repositories included — and **never
  widens its own reach.**
- **OB-26** — No secrets in the repository or in image layers; credentials enter at
  runtime only.
- **OB-27** — **Headless is binding.** Nothing may assume a physical display or a local
  seat, on any host, after genesis. A change that needs a display or a seat is a defect.
- **OB-28** — **No outcome is accepted on testimony.** Not an agent's word, not a reviewer
  persuaded by prose, not a proxy mistaken for the artifact. Each gating outcome is
  **proven against the live artifact at check-time, by a non-author.** The **absence of a
  completion signal is a failure to surface**, never evidence of progress.
- **OB-29** — **Nothing ships on its builder's own word.** A product ships only after an
  **independent, adversarial review** verifies the built product against the confirmed
  spec — this document first, then the specification, then the build principles — with
  reviewer and author drawn from **different agent lineages** where the platform's
  lineages allow. If the review does not pass, the product goes back into the loop, not
  out the door.
- **OB-30** — **No standing human tap.** A gate that can only stall is a human summons,
  which this objective forbids. Every blocking mechanism carries a bounded, automatic
  recovery and surfaces to the maintainer only after its bounded attempts fail.

---

## 7 · Document authority

**OB-31 · Spine and ownership.** The document spine of this repository is exactly:
`00-OBJECTIVE.md`, `00-BUILDPRINCIPLE.md`, `01-SPEC.md`, `02-DESIGN.md`, `docs/adr/`, and
`CHANGELOG.md` — one authoritative home per concept; every other mention points or is
deleted. Authority on conflict runs in that order. This document and the build principles
are **confirmed once and fixed**, maintainer-merge-only. `01-SPEC.md` is **derived and
checked** — re-derived from this document, never hand-edited, with traceability and
coverage enforced mechanically and every change verified by a non-author. `02-DESIGN.md`
and `docs/adr/` are **dev-owned and mutable-on-fact** and are never conformance targets.
**Memoir is not specification.**

**OB-32 · Why the objective is scoped and the principles are universal.** This objective
is **scoped** — one per repository, this one no more special than any other the pair
develops. The build principles are **universal**, binding everything the platform builds,
and are therefore vendored from a single fleet home and pinned by version. They are
confirmed **together, once, in a single session**; thereafter a project's one initiation
session **co-creates that project's objective AND explicitly captures the build principles
that govern the work** — applied by reference, plus any project-specific construction
constraint decided in that session, recorded in that project's own §Constraints. The
principles are **captured, never re-dictated** — a re-dictation is a fork. One session,
two documents, nothing assumed.
